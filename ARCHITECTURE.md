# SilentConnect System Design & Architecture Specification

> **Document Classification**: Diátaxis Explanation & System Design  
> **Status**: Authoritative Production Specification (Release v5.0 Active-Active Turso Mesh)  
> **Verification Status**: 100% Verified against Codebase (`128 unit tests passing`, `0 security leaks`)  
> **Target Scope**: Geo-Distributed Active-Active Mesh Architecture, Ingress Multiplexing, and Data Plane  
> **Related Documentation**: [README.md](README.md) • [README_RU.md](README_RU.md) • [DEPLOYMENT.md](DEPLOYMENT.md) • [AMNEZIA_SLOTS.md](AMNEZIA_SLOTS.md) • [WHITELIST_SPEC.md](WHITELIST_SPEC.md)

---

## 1. System Philosophy & High-Level Architecture

**SilentConnect** is an enterprise-grade, geo-distributed **Active-Active Mesh** platform engineered to deliver resilient, high-throughput network tunneling and subscription lifecycle automation. The platform is designed from the ground up to operate reliably across adversarial network conditions, including Deep Packet Inspection (DPI), state-level censorship, protocol throttling, and complete datacenter-level network partitions.

### 1.1. Core Architectural Tenets

1. **Shared-Nothing Multi-Node Mesh**:  
   Traditional VPN subscription setups rely on a single monolithic master node that controls edge servers via brittle SSH tunnels or cron-based file copies (`scp`/`rsync`). SilentConnect eliminates all cross-server runtime dependencies. Every node (`Node-1`, `Node-2`, `Node-3`, `Node-N`) is an autonomous transit peer capable of serving client connections, terminating ingress traffic, and executing local business logic independently.

2. **Global Authoritative Primary with Local NVMe Replicas**:  
   Cluster state is synchronized across nodes using **Turso Cloud (libSQL)** as the global authoritative primary. Rather than making blocking network round-trips to a remote database on every client request, each node maintains an embedded replica directly on local NVMe storage (`libsql_replica.py`). Reads execute with sub-0.02ms latency directly from the local file system, while transactional writes commit through to Turso Cloud atomically.

3. **Autonomous Local Pull Reconciliation**:  
   Control plane state and data plane state are decoupled. Nodes do not receive push commands over external SSH. Instead, each node runs an autonomous local pull daemon (`xui_reconciler.py`) that synchronizes state from the local Turso replica into running 3X-UI / Xray Core memory via local REST APIs. Configuration changes take effect hot in memory without restarting Xray or interrupting active client sessions.

4. **Single-Socket Front Demultiplexing**:  
   To blend into standard web traffic and evade active DPI probing, every node runs a single unified TCP port `443` listener managed by `xray-dokodemo-door`. Incoming TCP streams are inspected at the TLS ClientHello level: Reality camouflage connections are forwarded directly to Xray's VLESS Reality Inbound, while legitimate web and subscription domains are routed to a local Caddy reverse proxy.

5. **Direct DNS-Only Ingress**:  
   All public endpoints connect via **Cloudflare DNS-Only (⚪ grey cloud)** direct A-records pointing straight to node public IP addresses. Cloudflare Proxy (🟠 orange cloud) is strictly prohibited due to nationwide TSPU filtering and lack of arbitrary TCP/UDP routing. No intermediate gateways or external proxies exist in the data path.

---

## 2. Distributed State Layer: Turso libSQL & Local NVMe Replicas

At the foundation of SilentConnect's active-active mesh is a hybrid database architecture managed by `vpn_shop/libsql_replica.py`.

```mermaid
flowchart TD
    subgraph Clients["Clients and Edge Ingress Layer"]
        CLI["VPN Clients\n(Streisand / Happ / Sing-box / Amnezia)"]
        WEB["Web and Telegram Users"]
        DNS["Cloudflare DNS-Only A-Records\n(SHOP / SUB / EDGE Domains)"]
    end

    subgraph Mesh["Active-Active Multi-Node Cluster Mesh"]
        subgraph N1["Node-1 (Core Hub - 1 Gbps)"]
            MUX1["xray-dokodemo-door (:443 Mux)"]
            CAD1["Caddy TLS Proxy (:4430)"]
            WEB1["vpn-shop-web (:3090 Active Storefront)"]
            BOT1["vpn_shop.bot (Systemd Daemon)"]
            REC1["xui_reconciler.py (Pull Daemon)"]
            DB1[("Local NVMe Replica\nvpn_shop_replica_*.db")]
        end

        subgraph N2["Node-2 (Transit Mesh Peer - 10 Gbps)"]
            MUX2["xray-dokodemo-door (:443 Mux)"]
            CAD2["Caddy TLS Proxy (:4430)"]
            WEB2["vpn-shop-web (:3090 Standby API)"]
            REC2["xui_reconciler.py (Pull Daemon)"]
            DB2[("Local NVMe Replica\nvpn_shop_replica_*.db")]
        end

        subgraph N3["Node-3 (Edge Transit Peer - 1 Gbps)"]
            MUX3["xray-dokodemo-door (:443 Mux)"]
            CAD3["Caddy TLS Proxy (:4430)"]
            WEB3["vpn-shop-web (:3090 Standby API)"]
            REC3["xui_reconciler.py (Pull Daemon)"]
            DB3[("Local NVMe Replica\nvpn_shop_replica_*.db")]
        end
    end

    subgraph Storage["Authoritative State Layer"]
        TURSO[("Turso Cloud Primary (libSQL)\nAuthoritative Mesh DB")]
    end

    WEB --> DNS
    CLI --> DNS
    DNS --> MUX1
    DNS --> MUX2
    DNS --> MUX3

    MUX1 --> CAD1
    CAD1 --> WEB1
    WEB1 --> DB1

    MUX2 --> CAD2
    CAD2 --> WEB2
    WEB2 --> DB2

    MUX3 --> CAD3
    CAD3 --> WEB3
    WEB3 --> DB3

    DB1 <-->|"WAL replication (sync_if_stale 2.0s)"| TURSO
    DB2 <-->|"WAL replication (sync_if_stale 2.0s)"| TURSO
    DB3 <-->|"WAL replication (sync_if_stale 2.0s)"| TURSO
```

### 2.1. The Concurrency and Latency Dilemma

In a distributed multi-node VPN network, the database must satisfy two conflicting requirements:
- **Ultra-low latency reads (< 0.1 ms)**: Every inbound connection handshake or subscription retrieval queries user validity, data limits, and expiration timestamps. Making a remote HTTP/TLS call to a cloud database on every handshake introduces 50–200 ms of latency, severely degrading user experience and client connection speed.
- **Strict write consistency**: When a user purchases a subscription or extends their plan via the web storefront or Telegram bot, the update must immediately replicate across all nodes so that any node can validate the user without split-brain anomalies.

### 2.2. Implementation Architecture: `LibsqlReplicaManager`

SilentConnect resolves this dilemma via `LibsqlReplicaManager` and `LibsqlConnectionProxy` (`vpn_shop/libsql_replica.py`):

1. **Embedded NVMe Replicas**:  
   Each node maintains a local SQLite database replica file on local NVMe storage. Embedded replicas are created using the `libsql` driver:
   ```python
   libsql.connect(self._path, sync_url=self._sync_url, auth_token=self._auth_token)
   ```
2. **Sub-0.02ms Read Path (`_get_ro_conn`)**:  
   Read operations do not touch the network or the synchronous write lock. Instead, `LibsqlReplicaManager` provides thread-local standard `sqlite3` connections opened directly to the local NVMe replica file in read-only mode:
   ```python
   uri = f"file:{self._path}?mode=ro"
   conn = sqlite3.connect(uri, uri=True, timeout=15.0, check_same_thread=False)
   conn.row_factory = sqlite3.Row
   conn.execute("PRAGMA query_only = ON;")
   ```
   This architecture enables typical query execution times under **0.02 ms**, entirely decoupled from external network latency.

3. **Dual-Lock Hierarchy & Non-Blocking Staleness Check (`sync_if_stale`)**:  
   Synchronization is governed by two dedicated locks:
   - `self._sync_lock = threading.Lock()`: Guards network synchronization with Turso Cloud.
   - `self._exec_lock = threading.RLock()`: Guards SQL execution on the embedded connection.

   The default staleness threshold is 2.0 seconds (`TURSO_SYNC_INTERVAL=2.0`). When `sync_if_stale()` is invoked:
   ```python
   now = time.monotonic()
   if now - self._last_sync_at >= self._sync_interval:
       if self._sync_lock.acquire(blocking=False):
           try:
               if time.monotonic() - self._last_sync_at >= self._sync_interval:
                   if self._exec_lock.acquire(blocking=False):
                       try:
                           self._conn.sync()
                           self._last_sync_at = time.monotonic()
                       finally:
                           self._exec_lock.release()
           finally:
               self._sync_lock.release()
   ```
   Because both locks are acquired with `blocking=False`, concurrent read queries **never block** waiting for network I/O. If another thread is actively pulling WAL frames from Turso Cloud, incoming reads seamlessly execute against the local NVMe replica.

4. **Atomic Write-Through Commits (`force_sync`)**:  
   When a write transaction (`INSERT`, `UPDATE`, `DELETE`, `REPLACE`) executes through `LibsqlConnectionProxy`, the proxy sets an internal flag `self._wrote = True`. When the transaction commits, `commit()` automatically triggers `self._mgr.force_sync()`, committing the WAL frame to Turso Cloud under `_sync_lock`. This guarantees immediate consistency across the cluster.

5. **Process Isolation for Replica Files**:  
   To prevent operating system file lock contention (`sqlite3.OperationalError: database is locked`) when multiple services run on the same node, `vpn_shop/store.py` assigns an isolated replica database file to each daemon process:
   - Telegram Bot Daemon: `vpn_shop_replica_bot.db`
   - Web Storefront & API: `vpn_shop_replica_web.db`
   - SubJSON Service: `vpn_shop_replica_subjson.db`
   - 3X-UI Reconciler: `vpn_shop_replica_xui_reconcile.db`

6. **SQLite PRAGMA Interception**:  
   `LibsqlConnectionProxy` intercepts PRAGMA calls before execution. Informational PRAGMAs (`TABLE_INFO`, `INDEX_LIST`, `INTEGRITY_CHECK`) are safely directed to the local read-only handle. Engine configuration PRAGMAs unsupported by the remote libSQL server (`busy_timeout`, `journal_mode`) return empty cursors, preventing driver rejections.

---

## 3. Ingress Architecture: TCP 443 Front Multiplexing & Caddy Routing

In censorship-heavy environments, binding port 443 exclusively to standard web services or exposing non-standard ports for VPN traffic invites immediate DPI fingerprinting and firewall throttling. SilentConnect solves this by multiplexing all inbound TCP 443 traffic through a single ingress gateway.

```mermaid
sequenceDiagram
    autonumber
    actor Client as "Client / Browser"
    participant Mux as "xray-dokodemo-door (:443)"
    participant Xray as "Xray Reality Inbound (:23385)"
    participant Caddy as "Caddy TLS Proxy (:4430)"
    participant Shop as "Web Shop (:3090)"
    participant Sub as "SubJSON Service (:3088)"

    Client->>Mux: TCP SYN + ClientHello (Port 443)
    Note over Mux: Sniffs SNI in TLS handshake

    alt SNI matches Reality Camouflage Domain
        Mux->>Xray: Forward TCP raw stream to 127.0.0.1:23385
        Xray->>Xray: Authenticate Reality Key & Vision Flow
        Xray-->>Client: Establish stealth VLESS tunnel
    else SNI matches Service Domain (SHOP_DOMAIN / SUB_DOMAIN)
        Mux->>Caddy: Forward TCP stream to 127.0.0.1:4430
        Caddy->>Caddy: Terminate TLS via Let's Encrypt / ZeroSSL
        alt Path matches /order/* or /api/* or /
            Caddy->>Shop: HTTP Reverse Proxy to 127.0.0.1:3090
            Shop-->>Client: Web Storefront / API Response
        else Path matches /my-secret-sub/* or /singbox/*
            Caddy->>Sub: HTTP Reverse Proxy to 127.0.0.1:3088
            Sub-->>Client: Dynamic Subscription Payload
        end
    end
```

### 3.1. Front Multiplexer: `xray-dokodemo-door`

On every node, the public TCP port `443` socket is owned by `xray-dokodemo-door`. The multiplexer does not terminate TLS; instead, it sniffs the `Server Name Indication` (SNI) field in the client's `ClientHello` packet and applies layer-4 routing rules:

```json
{
  "log": { "loglevel": "warning", "access": "none" },
  "inbounds": [
    {
      "port": 443,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1",
        "port": 4430,
        "network": "tcp",
        "followRedirect": false
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "to-xray-reality",
      "settings": { "redirect": "127.0.0.1:23385" }
    },
    {
      "protocol": "freedom",
      "tag": "to-caddy-web",
      "settings": { "redirect": "127.0.0.1:4430" }
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "domain": ["<REALITY_SNI_1>", "<REALITY_SNI_2>", "<REALITY_SNI_3>"],
        "outboundTag": "to-xray-reality"
      },
      {
        "type": "field",
        "network": "tcp",
        "outboundTag": "to-caddy-web"
      }
    ]
  }
}
```

### 3.2. Routing Paths

1. **Reality SNI Camouflage**:  
   When the sniffed SNI matches a configured Reality camouflage domain (e.g., `sber.ru`, `ozon.ru`), `dokodemo-door` transparently redirects the raw TCP stream to `127.0.0.1:23385` (Xray VLESS Reality Vision Inbound). Xray verifies the TLS handshake against the Reality private key and establishes the tunnel. If an active DPI probe attempts an unauthorized handshake, Xray proxies the connection to the legitimate camouflage site.

2. **Service & Web Domains**:  
   When the sniffed SNI matches service hostnames (`<SHOP_DOMAIN>`, `<SUB_DOMAIN>`, `<EDGE_DOMAIN>`, `<NODE1_DOMAIN>`) or non-TLS HTTP traffic, the stream routes to `127.0.0.1:4430`, where Caddy terminates TLS.

### 3.3. Caddy Reverse Proxy Architecture (`:4430`)

Caddy operates behind the multiplexer on internal port `4430` (`https_port 4430`, `http_port 80`), managing automated ACME certificates via Let's Encrypt / ZeroSSL and distributing traffic to backend daemons:
- **WebSocket Gateway (`127.0.0.1:10010`)**: Path prefix `/sc-ws-path*` reverse proxies to Xray WebSocket fallback for restrictive corporate proxies.
- **Web Storefront & API (`127.0.0.1:3090`)**: Paths `/`, `/order/*`, `/api/*`, `/cabinet/*`, `/legal/*`, `/about`, `/contact`, and `/assets/*` route to `vpn-shop-web.service`.
- **SubJSON Subscription Service (`127.0.0.1:3088`)**: Subscription paths (`/my-secret-sub/*`, `/singbox/*`, `/happ/*`, `/clash/*`, `/wireguard/*`) route to `subjson.service`.

### 3.4. Direct Cloudflare DNS-Only (⚪ Grey Cloud) Ingress Policy

- All DNS records for `<SHOP_DOMAIN>`, `<SUB_DOMAIN>`, `<EDGE_DOMAIN>`, `<NODE1_DOMAIN>`, `<NODE2_DOMAIN>`, and `<NODE3_DOMAIN>` are configured strictly in **Cloudflare DNS-Only (⚪ grey cloud)** mode.
- **Why Cloudflare Proxied (🟠 Orange Cloud) is strictly prohibited**:
  1. TSPU systems in Russia actively block and throttle Cloudflare CDN edge IP ranges. Enabling proxy mode causes complete connectivity failure for users inside Russia.
  2. Cloudflare CDN only supports standard HTTP/HTTPS. It cannot forward UDP VPN protocols (Hysteria 2 UDP 38443, port hopping 30000:40000, AmneziaWG UDP 44121/49752) or raw TCP VLESS Reality connections.
- **Why Intermediate Gateways are omitted**:  
  Legacy architectures that evaluated external cloud proxies or third-party API gateways are completely eliminated. In production, intermediate gateways introduce latency, single-point-of-failure risks, and protocol limitations. Direct Cloudflare DNS-Only A-records provide direct, zero-overhead connectivity straight to physical node endpoints.

---

## 4. Autonomous Node Reconciler & Dual Circuit Breakers

The synchronization between the authoritative Turso database and the local server daemons (3X-UI, Xray Core, and AmneziaWG) is managed by `vpn_shop/xui_reconciler.py`.

```mermaid
stateDiagram-v2
    [*] --> Idle: Daemon Start / Loop Finished
    Idle --> SyncReplica: 15s Timer Expired OR SIGUSR1 Signal
    
    SyncReplica --> FetchProfiles: sync_if_stale() / force_sync()
    FetchProfiles --> CheckProfiles: Load Profiles from Local Turso Replica
    
    CheckProfiles --> ZeroProfilesBreaker: Profile Count == 0
    ZeroProfilesBreaker --> AbortSync: Trip Breaker (Log Warning)
    AbortSync --> Idle: Retain Existing Inbounds Untouched
    
    CheckProfiles --> EvaluateDiff: Profile Count > 0
    EvaluateDiff --> AlignInMemory: Compute Inbound Diff (Xray 3X-UI)
    
    AlignInMemory --> AlignSQLite: Add / Update / Disable via REST API
    AlignSQLite --> ReconcileAWG: Update clients, settings, traffics
    
    ReconcileAWG --> CheckAWGSlots: Fetch AWG Active Slots
    CheckAWGSlots --> AWGZeroSlotsBreaker: Active Slots == 0
    AWGZeroSlotsBreaker --> AbortAWG: Trip Breaker (ReconciliationAbortedError)
    
    CheckAWGSlots --> CheckMassDeletion: Active Slots > 0
    CheckMassDeletion --> AWGMassDeletionBreaker: Deletions > 30% or > 10 peers
    AWGMassDeletionBreaker --> AbortAWG: Trip Breaker (Mass Deletion Blocked)
    
    CheckMassDeletion --> ApplyAWGChanges: Deletion Safety Threshold OK
    ApplyAWGChanges --> SyncAWGTraffic: Kernel Peer Add / Remove (awg0)
    AbortAWG --> SyncAWGTraffic: Kernel Peers Preserved Untouched
    
    SyncAWGTraffic --> Idle: Monotonic Deltas Pushed to Ledger
```

### 4.1. Reconciler Operational Lifecycle

- **Autonomous Pull Model**:  
  `XuiReconciler.run_daemon()` executes a polling loop every 15.0 seconds (`interval_seconds=15.0`). Each node pulls directly from its local Turso replica, evaluating active client subscriptions against the local 3X-UI inbounds.
- **Instant Wake via `SIGUSR1` (< 100 ms)**:  
  When an order is completed or a profile is created in the web storefront or Telegram bot, waiting 15 seconds for polling would degrade user experience. The initiating process calls `notify_local_reconciler()`, which reads `/tmp/silentconnect_xui_reconcile.pid` and sends `signal.SIGUSR1` to the reconciler process. The daemon catches the signal, immediately wakes from `time.sleep()`, and completes reconciliation in under **100 ms**.
- **Process Concurrency Lock**:  
  To prevent overlapping reconciliation runs from scheduled polls and incoming `SIGUSR1` signals, the reconciler acquires an exclusive, non-blocking file lock on `/tmp/silentconnect_xui_reconcile.lock` via `fcntl.flock(fileno, LOCK_EX | LOCK_NB)`.
- **Zero-Downtime Hot In-Memory Alignment**:  
  Client mutations (adding new users, modifying expiry timestamps, toggling enable state, setting IP limits) are dispatched to 3X-UI via its local REST API (`xui_api.py: add_client, update_client, delete_client`). 3X-UI applies changes hot into running Xray Core memory via gRPC without restarting the Xray process. Active user sessions are never terminated or dropped during reconciliation.
- **Deep SQLite Cache Alignment (`_align_local_xui_sqlite`)**:  
  To support services that query 3X-UI's underlying database directly (such as `subjson-service` and Hysteria 2 HTTP authentication), the reconciler directly updates local SQLite tables (`/etc/x-ui/x-ui.db`):
  1. `clients` table (enable, expiry_time, sub_id, limit_ip, updated_at).
  2. `inbounds.settings` JSON clients array.
  3. `client_traffics` table (`INSERT ... ON CONFLICT(email) DO UPDATE`).
  4. `client_inbounds` table (3X-UI v2.4+ multi-inbound mapping).

### 4.2. Dual Circuit Breakers

To guarantee high availability and protect client connectivity during database network partitions, upstream provider outages, or replica corruption, the reconciler enforces two independent circuit breakers:

#### 1. Zero-Profiles Circuit Breaker (`xui_reconciler.py:175-180`)
If a temporary network partition between the node and Turso Cloud causes the local replica to return an empty profile list, a naive reconciler would interpret this as an instruction to delete all clients from Xray Core.  
The Zero-Profiles Circuit Breaker prevents this:
```python
profiles = self._load_shop_profiles()
if not profiles:
    LOGGER.warning("Turso returned 0 profiles; aborting reconciliation (circuit breaker)")
    return {"ok": True, "skipped": "zero_profiles_circuit_breaker"}
```
If 0 profiles are returned, reconciliation immediately aborts. Existing in-memory clients and kernel peers remain untouched, guaranteeing that users stay connected even during total control plane partition.

#### 2. AmneziaWG Mass-Deletion Circuit Breaker (`awg_manager.py:1173-1186`)
In AmneziaWG peer synchronization, an erroneous batch command or partial data corruption could attempt to purge active wireguard keys. The reconciler evaluates the deletion ratio before applying changes to the kernel:
```python
num_manageable = len(current_by_pubkey)
num_to_remove = len(to_remove)
if num_manageable > 0 and num_to_remove > 0:
    ratio = num_to_remove / num_manageable
    if ((ratio > 0.30 and num_to_remove > 3) or num_to_remove > 10) and not force_mass_delete:
        msg = (
            f"Mass deletion circuit breaker triggered for {code.upper()}: "
            f"attempting to remove {num_to_remove}/{num_manageable} peers ({ratio:.1%}). "
            "Operation aborted to prevent accidental outage. Pass force_mass_delete=True to override."
        )
        LOGGER.error("[%s] %s", code.upper(), msg)
        raise ReconciliationAbortedError(msg)
```
If a synchronization attempt would delete more than 30% of peers (with >3 peers) or more than 10 total peers, the operation is blocked and logged as an error unless an explicit override flag is supplied.

---

## 5. Complete Socket, Port & Protocol Matrix

The following table provides the authoritative specification of all listening sockets, transport protocols, port redirections, and daemon bindings across the SilentConnect cluster.

| # | Protocol / Service | Transport Layer | Public Port | Internal Target | Bound Daemon | Security, Obfuscation & Purpose |
|:---|:---|:---|:---|:---|:---|:---|
| **1** | **Front Multiplexer** | TCP | `443` | `127.0.0.1:443` | `xray-dokodemo-door` | Layer-4 SNI demux sniffing `["http", "tls"]`. Routes Reality to :23385, service domains to :4430. |
| **2** | **Caddy Ingress Proxy** | TCP | — *(Internal)* | `127.0.0.1:4430` | `caddy` | Let's Encrypt / ZeroSSL TLS termination. Proxies to Web Shop (:3090) and SubJSON (:3088). |
| **3** | **VLESS Reality Vision** | TCP | `443` *(via demux)* | `127.0.0.1:23385` | `xray` (3X-UI) | Primary stealth protocol. Flow: `xtls-rprx-vision`, uTLS Chrome/Edge fingerprint. |
| **4** | **VLESS Reality gRPC** | TCP | `29443` | `0.0.0.0:29443` | `xray` (3X-UI) | Direct high-latency resilient gRPC stream (`serviceName: grpc-maxru`). Fallback for unstable cellular networks. |
| **5** | **VLESS Reality XHTTP** | TCP | `8443` | `0.0.0.0:8443` | `xray` (3X-UI) | HTTP/2 / XHTTP packet-up streaming (`/xh-7m-path`). Bypasses restrictive corporate firewalls. |
| **6** | **Hysteria 2 Core** | UDP | `38443` | `0.0.0.0:38443` | `hysteria-server` | High-speed QUIC protocol. Mandatory `gecko` obfuscation (`64-1400` bytes). Auth via `:3088/internal/hysteria-auth`. |
| **7** | **Hysteria 2 Port Hopping** | UDP | `30000:40000` | Redirect `38443` | `iptables` NAT | Dynamic UDP port hopping via `PREROUTING -j REDIRECT`. Evades ISP UDP flow-rate throttling. |
| **8** | **Hysteria 2 Direct 443** | UDP | `443` | Redirect `38443` | `iptables` NAT | Direct QUIC port 443 redirect via `PREROUTING -j REDIRECT`. Blends with standard HTTP/3 traffic. |
| **9** | **AmneziaWG (Node-1 & Node-2)** | UDP | `44121` | `172.17.0.2:44121` | Docker `amnezia-awg2` | Obfuscated WireGuard 3.1. Parameters: `Jc=5, Jmin=10, Jmax=50, S1-S4=12, H1=1, H2=2, H3=3, H4=4`. |
| **10** | **AmneziaWG (Node-3)** | UDP | `49752` | `172.17.0.2:49752` | Docker `amnezia-awg2` | Node-3 custom obfuscation profile: `Jc=5, Jmin=10, Jmax=50, S1=51, S2=30, S3=34, S4=12, H1=1, H2=2, H3=3, H4=4`. |
| **11** | **SubJSON Subscription Service** | TCP | — *(Internal)* | `127.0.0.1:3088` | `subjson.service` | Dynamic multi-format subscription generator (Sing-box, Clash Meta, Happ, V2Ray, WireGuard). |
| **12** | **VPN Shop Web** | TCP | — *(Internal)* | `127.0.0.1:3090` | `vpn-shop-web.service` | Web storefront, payment processing, user cabinet, node healthcheck, and RPC bridge. |
| **13** | **3X-UI Admin API** | TCP | — *(Internal)* | `127.0.0.1:2053` | `x-ui.service` | Local REST API bound to localhost. Managed by `xui_reconciler.py`. Blocked from external access via UFW. |
| **14** | **WebSocket Gateway** | TCP | — *(Internal)* | `127.0.0.1:10010` | `xray-ws443` | VLESS over TLS WebSocket fallback behind Caddy for restrictive HTTPS-only environments. |

---

## 6. Service Distribution & Multi-Node Topology

Physical geographical locations are completely abstracted into modular topological roles. Every node in the mesh operates symmetrically with identical base capabilities, while specific ingress hostnames and transactional fulfillment duties are assigned per topological role.

### 6.1. Modular Topological Roles

| Specification | Node-1 (Core Hub) | Node-2 (Transit Mesh Peer) | Node-3 (Edge Transit Peer) | Node-N (Modular Expansion Peer) |
|:---|:---|:---|:---|:---|
| **Topological Role** | Control Plane Origin & Core Hub | High-Throughput Transit Mesh Peer | Edge Transit Mesh Peer | Generic Expansion Peer |
| **Network Uplink** | 1 Gbps | **10 Gbps** | 1 Gbps | 1–10 Gbps |
| **Turso libSQL Engine** | Embedded Replica + Active Sync | Embedded Replica + Active Sync | Embedded Replica + Active Sync | Embedded Replica + Active Sync |
| **Public Storefront (`<SHOP_DOMAIN>`)**| **Active Primary Storefront** | Standby Mirror | Standby Mirror | Standby Mirror |
| **Web Service Mode (`:3090`)** | `DIGISELLER_ENABLED=true` | `DIGISELLER_ENABLED=false` | `DIGISELLER_ENABLED=false` | `DIGISELLER_ENABLED=false` |
| **Telegram Bot Daemon** | **Active Systemd Daemon** | Dormant / Hot Standby | Dormant / Hot Standby | Dormant / Hot Standby |
| **SubJSON Service (`:3088`)** | Active | Active | Active | Active |
| **3X-UI Reconciler Daemon** | Active (15s pull + `SIGUSR1`) | Active (15s pull + `SIGUSR1`) | Active (15s pull + `SIGUSR1`) | Active (15s pull + `SIGUSR1`) |
| **Port 443 Multiplexer** | Active (`dokodemo-door`) | Active (`dokodemo-door`) | Active (`dokodemo-door`) | Active (`dokodemo-door`) |
| **VLESS Reality (Vision, gRPC, XHTTP)** | Active | Active | Active | Active |
| **Hysteria 2 (UDP 38443, Gecko)** | Active | Active | Active | Active |
| **AmneziaWG Port** | `UDP 44121` (Subnet `10.8.1.0/24`)| `UDP 44121` (Subnet `10.8.3.0/24`)| `UDP 49752` (Subnet `10.8.2.0/24`)| Allocated UDP (Subnet `10.8.N.0/24`) |
| **OpenFlux Dedicated Sandbox** | Active Docker Worker Pool | Active Docker Worker Pool | *Omitted* (CDN Captcha Rule) | Optional |

### 6.2. Distribution of Service `:3090` (`vpn-shop-web.service`)

The Python web daemon `vpn-shop-web.service` runs on all nodes across the cluster (`web.py`), but with distinct functional roles:

#### Node-1 (Active Primary Storefront)
- Direct target of the public Cloudflare DNS A-record for `<SHOP_DOMAIN>`.
- Serves customer traffic: web catalog, shopping cart, promo code redemption, Cloudflare Turnstile bot validation, customer personal cabinet, and SBP / bank card payments.
- **Digiseller Fulfillment (`DIGISELLER_ENABLED=true`)**: Active fulfillment processor receiving Digiseller / Plati.market webhooks, executing fail-closed purchase validation (`/api/purchase/info/{invoice_id}`), creating customer profiles, and delivering goods.

#### Node-2 & Node-3 (Standby Mode)
- Deployed with `DIGISELLER_ENABLED=false` and without Telegram bot polling.
- Rather than idling, these instances actively handle distributed mesh traffic:
  1. `GET /healthz`: Responds with HTTP 200 `{"status":"ok"}` for external monitors and mesh healthcheckers.
  2. `POST /api/bridge`: Secure HMAC-SHA256 authenticated RPC endpoint (`verify_and_dispatch_bridge`) executing local server actions (AmneziaWG slot creation, WireGuard key allocation, local serverless actions).
  3. `GET /order/*` & `GET /order/*/status`: Direct access for localized customer order status queries.
  4. `POST /api/payment/platega/callback` & `/api/payment/digiseller/callback`: Secondary payment callback endpoints ensuring zero missed webhooks if ingress traffic is rerouted across mesh peers.
  5. `GET /api/internal/cluster/health`: Cluster health and Dead Man's Switch status exporter for `cluster_watchdog.py`.
  6. `GET /sub/awg/<sub_id>/slot/<slot_index>/config`: On-demand client WireGuard configuration generation.
  7. `POST /sub/awg/<sub_id>/slot/<slot_index>/switch_country`: Seamless node switching for AmneziaWG slots.

---

## 7. Telegram Bot Architecture: Production Systemd Daemon vs TGCloud Prototype

The codebase contains two distinct implementations of the Telegram Bot interface, which fulfill different operational roles:

### 7.1. Authoritative Production Engine: `vpn-shop-silentconnect.service`

- **Implementation**: Native Python 3 daemon (`vpn_shop/bot.py`, `vpn_shop/__main__.py`).
- **Systemd Service**: Managed as a standard systemd service `vpn-shop-silentconnect.service` on Node-1:
  ```ini
  [Unit]
  Description=VPN Shop Bot - SilentConnect
  After=network-online.target x-ui.service subjson.service
  Wants=network-online.target

  [Service]
  Type=simple
  WorkingDirectory=/root/vpn-shop
  EnvironmentFile=/root/vpn-shop/.env.silentconnect
  ExecStart=/usr/bin/python3 -m vpn_shop --env-file .env.silentconnect run-bot
  Restart=always
  RestartSec=3
  User=root
  ```
- **Operational Characteristics**:
  - Executes a robust long-polling loop against the Telegram Bot API (`bot.py: run_forever()`).
  - Connects directly to the local Turso libSQL embedded replica (`vpn_shop_replica_bot.db`), ensuring sub-millisecond database queries.
  - Manages client onboarding, catalog browsing, promo redemptions, subscription delivery, and payment callback confirmations.
  - Holds the distributed lease worker (`cluster_leases`) to execute cluster-wide maintenance tasks.

### 7.2. Experimental Serverless Prototype: `tgcloud` (`github_export/tgcloud/`)

- **Implementation**: JavaScript / Node.js serverless application (`tgcloud/lib/bot.js`, `tgcloud/lib/store.js`, `tgcloud.jsonc`).
- **Target Platform**: Designed as an evaluation prototype for serverless deployment on platforms such as Cloudflare Workers, Vercel, or Telegram Cloud.
- **Operational Characteristics**:
  - Communicates with Turso Cloud via HTTP REST API (`tursoUrl`, `tursoToken`).
  - Coordinates physical node actions via the secure HMAC-SHA256 authenticated RPC bridge (`POST /api/bridge`).
- **Classification**: Explicitly documented as an **experimental evaluation prototype**. It is not used in production and does not replace the authoritative systemd daemon.

### 7.3. Runtime Fallback: `SERVERLESS_MODE`

To ensure stability during operational experiments, the Python daemon `ShopBot.run_forever()` implements automatic conflict detection. If an external serverless webhook or testing instance starts polling the Telegram Bot API with the same token, Telegram returns `HTTP 409 Conflict`.  
When `bot.py` encounters this condition, it does not crash or enter an aggressive restart loop; instead, it automatically transitions to `SERVERLESS_MODE`:
- Halts Telegram `getUpdates` polling to prevent API conflicts.
- Continues running in the background as an authoritative periodic lease worker, executing subscription expirations, trial cleanups, and Digiseller reconciliations via Turso distributed locks.

---

## 8. Censorship Circumvention Subsystems

### 8.1. OpenFlux White-Lists Container Sandbox (v0.3.0)

Under active ISP "White-Lists" enforcement (where all international IP traffic and standard VPN protocols are blocked at the border), SilentConnect deploys **OpenFlux**, a specialized bypass subsystem (`vpn_shop/openflux_manager.py`).

```mermaid
flowchart TD
    User["User Client (OpenFlux App)"]
    Doc["Mail.ru Cloud Collaborative Doc\n(docs.datacloudmail.ru)"]
    
    subgraph Sandbox["Isolated Docker Sandbox Container"]
        Worker["openflux-worker-UID\n(php:8.2-cli-alpine)"]
        Limits["Limits: 64MB RAM, 0.5 CPU\nVolume: /opt/openflux:ro"]
    end
    
    Target["Internet Destination"]

    User <-->|"WSS / Base64 Document Cursor"| Doc
    Doc <-->|"WSS / Engine.IO v4 Stream"| Worker
    Worker <-->|"Direct Internet Outbound"| Target
```

1. **Protocol Mechanism**:  
   Instead of opening direct TCP/UDP sockets between the client and the node, OpenFlux establishes a bidirectional data stream using collaborative cloud document cursors (`docs.datacloudmail.ru`). Data frames are encoded into Base64 strings and exchanged over Engine.IO v4 / WebSocket connections, blending into permitted cloud office traffic.

2. **Container Sandbox Isolation**:  
   Each active OpenFlux slot is provisioned as an isolated Docker container on the host:
   ```bash
   docker run -d --name openflux-worker-<uid> --restart unless-stopped \
     --memory=64m \
     --cpus=0.5 \
     -v /opt/openflux:/opt/openflux:ro \
     php:8.2-cli-alpine \
     sh -c 'while true; do php -d memory_limit=48M /opt/openflux/runner.php "$1"; sleep 1; done' _ '<PUBLIC_DOC_URL>'
   ```
   - **Base Image**: Lightweight `php:8.2-cli-alpine` to minimize memory footprint.
   - **Memory Capping**: Hard host limit `--memory=64m` with PHP process limit `memory_limit=48M`.
   - **CPU Quota**: `--cpus=0.5` prevents runaway CPU utilization.
   - **Read-Only Volume**: `/opt/openflux` is mounted `:ro` to prevent container tampering.

3. **Two-Phase Zero-Downtime Migration**:  
   When a user migrates their OpenFlux slot between nodes:
   - **Phase 1 (Prepare)**: `start_server_switch()` spins up a parallel worker container (`openflux-worker-<uid>-pending`) on the target node while preserving the active worker on the source node. The system records `pending_started_at = now()` with a 5-minute timeout window (`MIGRATION_TIMEOUT_SECONDS = 300`).
   - **Phase 2 (Confirm)**: `confirm_server_switch()` marks the target node active in Turso, renames the container, and tears down the old container and remote document.
   - **Watchdog Cleanup**: If 300 seconds elapse without user confirmation, `cleanup_expired_migrations()` automatically destroys the pending container, purges the temporary document, and restores the original node to active status without dropped service.

4. **Technical Justification for Node-3 Omission**:  
   OpenFlux workers are deployed **exclusively on Node-1 and Node-2**. Node-3 is intentionally excluded:
   - Outbound connections from Node-3 IP prefixes to Mail.ru Cloud WebSocket endpoints are actively intercepted by upstream CDN routers with `TCP RST` resets (`errno 104`) or `HTTP/2 PROTOCOL_ERROR`.
   - Access to document endpoints from Node-3 datacenter CIDRs triggers mandatory anti-bot captchas (`X-Captcha-Required: 1`), breaking automated headless CLI runners (`runner.php`).
   - Node-1 (1 Gbps) and Node-2 (10 Gbps) maintain 100% clean, uninhibited connectivity to cloud collaborative document endpoints.

### 8.2. AmneziaWG Dedicated Slots & Monotonic Quota Accounting

AmneziaWG provides obfuscated WireGuard connectivity across dedicated device slots (`vpn_shop/awg_manager.py`, `vpn_shop/awg_traffic.py`):

1. **Dedicated Slot Subnet Addressing**:  
   Each node manages an isolated `/24` subnet:
   - **Node-1**: Subnet `10.8.1.0/24`, Gateway: `10.8.1.1`, Endpoint Port: `44121/udp`
   - **Node-2**: Subnet `10.8.3.0/24`, Gateway: `10.8.3.1`, Endpoint Port: `44121/udp`
   - **Node-3**: Subnet `10.8.2.0/24`, Gateway: `10.8.2.1`, Endpoint Port: `49752/udp`
   - **Reserved Host IPs**: Addresses `.1, .2, .3, .4, .6` are reserved on every subnet for gateway routing, diagnostic loops, and internal DNS.

2. **Monotonic Counter State Tracking (`CounterStateTracker`)**:  
   WireGuard byte counters exposed by `awg show awg0 transfer` reset to zero whenever the network interface is reloaded or the host restarts. To prevent counter corruption or loss of tracked usage:
   - `CounterStateTracker` persists baseline and rolling counter snapshots in `/dev/shm/awg_last_counters.json` (falling back to `/tmp/awg_last_counters.json`).
   - If `curr_rx < prev_rx`, the tracker detects a kernel interface reset and records `delta_rx = curr_rx`, ensuring non-negative monotonic delta accumulation across 30-day billing cycles.

3. **Soft-Disable Guarantee (VLESS & Hysteria Unmetered)**:  
   AmneziaWG enforces tiered 30-day data limits: 250 GB (3 devices), 500 GB (6 devices), 1000 GB (9 devices).  
   When a user exhausts their AmneziaWG monthly quota:
   - The user's WireGuard public keys are removed from the Linux kernel (`awg set awg0 peer <key> remove`) and disabled in the `awg_slots` table.
   - **VLESS Reality (TCP Vision, gRPC, XHTTP) and Hysteria 2 remain 100% UNMETERED and FULLY ACTIVE** in 3X-UI.
   - The customer never suffers a complete loss of internet access; primary stealth protocols remain fully operational.

4. **Packet Obfuscation Matrix**:
   - **Node-1 & Node-2**: `Jc=5, Jmin=10, Jmax=50, S1=12, S2=12, S3=12, S4=12, H1=1, H2=2, H3=3, H4=4`
   - **Node-3**: `Jc=5, Jmin=10, Jmax=50, S1=51, S2=30, S3=34, S4=12, H1=1, H2=2, H3=3, H4=4`

5. **BitTorrent DPI Protection**:  
   To prevent copyright infringement notices and network abuse, the container's iptables FORWARD chain enforces string-matching DPI blocks:
   - `iptables -I FORWARD 1 -p tcp -m string --string 'BitTorrent protocol' --algo bm -j REJECT --reject-with icmp-port-unreachable`
   - `iptables -I FORWARD 1 -p udp -m string --string 'd1:ad2:id20:' --algo bm -j REJECT --reject-with icmp-port-unreachable` (DHT announce)
   - `iptables -I FORWARD 1 -p udp -m string --string 'BT-SEARCH' --algo bm -j REJECT --reject-with icmp-port-unreachable` (LSD)

### 8.3. Hysteria 2 Protocol with Gecko Obfuscation

Hysteria 2 delivers high-throughput UDP tunneling using custom QUIC congestion control (BBR):
- **Mandatory Gecko Obfuscation**: Configured strictly with `obfs: type: gecko` and packet padding parameters `min_packet_size: 64, max_packet_size: 1400`. Legacy `salamander` obfuscation is blocked by Russian TSPU filters and is strictly forbidden across the cluster.
- **Dynamic Port Hopping**: While the core daemon listens on UDP port `38443`, iptables PREROUTING rules dynamically redirect incoming UDP traffic across ports `30000:40000` and port `443` into port `38443`. This evades ISP UDP rate-limiting and session throttling.
- **Dynamic HTTP Authentication**: Client credentials are authenticated against `subjson-service` via local HTTP webhook (`http://127.0.0.1:3088/internal/hysteria-auth`), ensuring instant synchronization with user subscription validity.

---

## 9. State Coordination, Distributed Mutexes & Failure Modes

### 9.1. Distributed Mutex via `cluster_leases`

To prevent race conditions, duplicate Telegram notifications, or redundant payment reconciliations across multiple active nodes, SilentConnect coordinates cluster tasks using distributed database leases in Turso libSQL (`Store.try_acquire_cluster_lease`):

```sql
INSERT INTO cluster_leases(lease_name, holder_node, expires_at, updated_at)
VALUES('periodic_tasks', ?, ?, ?)
ON CONFLICT(lease_name) DO UPDATE SET
    holder_node = excluded.holder_node,
    expires_at = excluded.expires_at,
    updated_at = excluded.updated_at
WHERE cluster_leases.expires_at <= ? OR cluster_leases.holder_node = ?;
```

Only the node holding the active lease executes cluster maintenance routines:
1. `reap_expired_subscriptions()`: Transitions lapsed subscriptions to `expired` status.
2. `cleanup_expired_test_profiles()`: Purges expired 24-hour and 7-day trial profiles.
3. `send_subscription_expiry_reminders()`: Dispatches expiry warnings at 24 hours and 1 hour before expiration.
4. `recover_stale_orders()`: Recovers orders stalled in the `provisioning` state.
5. `reconcile_digiseller_orders()`: Reconciles order delivery and dispute status against the Digiseller API.

### 9.2. Order Finite State Machine (FSM)

Order state transitions in `vpn_shop/store.py` are governed by a strict finite state machine with optimistic concurrency control (`version = version + 1`) and audit logging in `order_state_log`:

```mermaid
stateDiagram-v2
    [*] --> waiting_payment: Order Created (Paid)
    [*] --> auto_provision: 100 Percent Promo Code (0 RUB)
    
    waiting_payment --> provisioning: Payment Confirmed (CAS Claim)
    waiting_payment --> pending_provision: Queued for Background Worker
    waiting_payment --> cancelled: Cancelled by User or Admin
    waiting_payment --> expired: 6-Hour Payment Timeout
    
    auto_provision --> provisioning: Instant Auto-Provisioning
    pending_provision --> provisioning: Acquired by Worker
    
    provisioning --> delivered: Profile Created in X-UI and Turso
    provisioning --> failed: Provisioning Failure (Rollback)
    
    failed --> provisioning: Automated Retry / Recovery
    failed --> cancelled: Final Cancellation
    
    delivered --> cancelled: Refund / Chargeback Revocation
```

### 9.3. Fail-Closed Payment Integrations

1. **Platega.io (`vpn_shop/platega.py`)**:
   - Webhook headers `X-MerchantId` and `X-Secret` are verified using constant-time comparison (`secrets.compare_digest`).
   - Outbound status verification verifies transaction details via `GET /transaction/{id}` and enforces underpayment protection (`amount >= expected_rub - 0.5`).
2. **Digiseller / Plati.market (`vpn_shop/digiseller.py`)**:
   - Webhooks are verified using SHA-256 signatures (`secret;invoice;goods` and `HMAC-SHA256`).
   - **Fail-Closed Verification**: Before provisioning a subscription, the server queries `/api/purchase/info/{invoice_id}`, validating `invoice_state == 3`, valid `date_pay`, correct product ID, and minimum required payment amount.
   - **Refund Tombstones**: When a refund notification is received, access is immediately revoked (`revoke_profile_access`), and a tombstone entry `tombstone:refund:{invoice_id}` is written to `webhook_events`, preventing late webhooks from re-provisioning refunded goods.

### 9.4. Replay-Protected RPC Bridge (`/api/bridge`)

Secure cross-node and serverless RPC calls are executed via `POST /api/bridge` (`vpn_shop/bridge.py`):
- Every request is authenticated using `HMAC-SHA256` computed over `"{timestamp}.{raw_body}"` using `SERVERLESS_BRIDGE_SECRET`.
- Replay protection enforces a maximum clock skew window of 300 seconds (`MAX_CLOCK_SKEW_SECONDS = 300`).
- An in-memory replay cache (`_REPLAY_CACHE`) rejects duplicate signatures within the valid time window.

### 9.5. Disaster Recovery & Backup Strategy

- **Turso Cloud Point-in-Time Recovery**: The authoritative database in Turso Cloud maintains automated WAL history and point-in-time recovery capabilities. Every node maintains an independent physical SQLite replica on NVMe storage.
- **Automated Configuration Backups**: Scheduled backup jobs (`backup_to_gdrive.sh`) create encrypted archives of node configurations (`Caddyfile`, `x-ui.db`, `/etc/hysteria/`, `/opt/amnezia/awg/`), storing them in isolated Google Drive folders with 7-day and 30-day retention policies.
- **Cluster Watchdog Daemon (`cluster_watchdog.py`)**: Continuously monitors the health of `amnezia-awg2` containers across nodes, coordinates leader election via `/tmp/silentconnect_watchdog.leader.lock`, pings an external Dead Man's Switch (`WATCHDOG_HEARTBEAT_URL`), and exports cluster health via `GET /api/internal/cluster/health` (returning HTTP 503 if health cache exceeds 180 seconds).

---

## 10. Summary & Design Invariants

| Architectural Layer | Design Invariant | Primary Mechanism |
|:---|:---|:---|
| **Cluster Topology** | Active-Active Mesh with zero cross-node SSH runtime dependencies | Decentralized nodes (`Node-1`, `Node-2`, `Node-3`, `Node-N`) |
| **Database Reads** | Sub-0.02ms query latency; non-blocking concurrency | Local NVMe SQLite replica (`PRAGMA query_only = ON;`, `sync_if_stale`) |
| **Database Writes** | Immediate cluster-wide atomic consistency | Write-through commit via `force_sync()` to Turso Cloud |
| **Ingress Demultiplexing** | Stealth camouflage and legitimate web services on single port 443 | `xray-dokodemo-door` sniffing SNI to Reality (:23385) vs Caddy (:4430) |
| **DNS Ingress** | Direct node IP connection; 0 Cloudflare proxying, 0 external gateways | Cloudflare DNS-Only (⚪ grey cloud) direct A-records |
| **Node Reconciliation** | Zero-downtime hot in-memory updates without Xray Core restart | Autonomous pull daemon (`xui_reconciler.py`) with 3X-UI REST API |
| **Partition Defense** | Protection against catastrophic client deletion during database failure | Zero-Profiles and AWG Mass-Deletion circuit breakers |
| **Storefront Service** | Active storefront on Node-1; standby APIs on Node-2 & Node-3 | `vpn-shop-web.service (:3090)` (`DIGISELLER_ENABLED=false` on standby) |
| **Telegram Bot** | Authoritative production systemd daemon with prototype decoupling | `vpn_shop.bot` systemd daemon vs `tgcloud` evaluation prototype |
| **Censorship Bypass** | Multi-tiered resistance to DPI, IP blocking, and white-listing | VLESS Reality Vision, Hysteria 2 Gecko, AmneziaWG slots, OpenFlux |
| **WireGuard Quotas** | Soft-disable guarantee: VLESS and Hysteria 2 remain unmetered | Monotonic `CounterStateTracker` with AWG-only key deactivation |
