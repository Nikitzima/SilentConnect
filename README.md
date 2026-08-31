# SilentConnect: Enterprise Multi-Protocol VPN & Subscription Platform

[![Security Audit](https://img.shields.io/badge/Security_Audit-Zero_Leaks_Passed-10b981.svg?style=flat-square)](#automated-security--zero-leak-verification)
[![Python Version](https://img.shields.io/badge/Python-3.11+-3b82f6.svg?style=flat-square)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-64748b.svg?style=flat-square)](LICENSE)
[![Protocols](https://img.shields.io/badge/Protocols-VLESS_%7C_Reality_%7C_XHTTP_%7C_AmneziaWG_%7C_Hysteria2-8b5cf6.svg?style=flat-square)](#protocol-and-subscription-support)

**SilentConnect** is a high-availability, multi-protocol VPN subscription ecosystem and automation platform designed to withstand aggressive Deep Packet Inspection (DPI/TSPU), packet manipulation, and infrastructure outages. It seamlessly bridges Telegram bot sales automation, dynamic multi-format subscription generation, Xray/3X-UI panel provisioning, AmneziaWG obfuscated WireGuard mesh management, and multi-node active-passive disaster recovery with zero data loss.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Microservices & Components](#microservices--components)
3. [Disaster Recovery & Dual-Node Failover](#disaster-recovery--dual-node-failover)
4. [Protocol and Subscription Support](#protocol-and-subscription-support)
5. [Supported Platforms & Client Matrix](#supported-platforms--client-matrix)
6. [Telegram Bot & Administrative Workflows](#telegram-bot--administrative-workflows)
7. [Web Storefront & Self-Service Cabinet](#web-storefront--self-service-cabinet)
8. [Configuration & Environment Catalog](#configuration--environment-catalog)
9. [Deployment & Quickstart Guide](#deployment--quickstart-guide)
10. [Automated Security & Zero-Leak Verification](#automated-security--zero-leak-verification)

---

## Architecture Overview

SilentConnect operates on an active-passive, geo-distributed multi-node topology designed for high availability and instant failover:

```text
                                  [ Users & Clients ]
                                           │
                 ┌─────────────────────────┴─────────────────────────┐
                 │                                                   │
      (Web Browser / Checkout)                             (VPN Clients / Apps)
                 │                                                   │
      https://example.com                                 https://sub.example.com
                 │                                                   │
      [ Caddy v2 Reverse Proxy ]                          [ Caddy v2 Reverse Proxy ]
                 │                                                   │
      ┌──────────┴──────────┐                             ┌──────────┴──────────┐
      │                     │                             │                     │
[ VPN Shop Web ]    [ Static Assets ]             [ SubJSON Engine ]    [ Xray Inbounds ]
  (Port 3090)                                        (Port 3088)          (TCP / XHTTP / WS)
      │                                                   │                     │
      └─────────────────────┬─────────────────────────────┘                     │
                            │                                                   │
                     [ SQLite WAL DBs ] <───────────────────────────────────────┘
                     • vpn_shop.db (App State & Orders)
                     • x-ui.db (Inbounds & Client Keys)
                            │
              [ Continuous WAL Replication ]
                            │
                  (Litestream Engine)
                            │
            ┌───────────────┴───────────────┐
            │                               │
   [ Primary Node (NL Master) ]    [ Standby Node (FI Standby) ]
     Subnet: 10.8.1.0/24             Subnet: 10.8.2.0/24
```

### Key Architectural Highlights
- **Decoupled Control & Data Planes**: The billing and subscription systems operate independently from raw packet transit. Even if the web or bot services undergo maintenance, active VPN tunnels remain fully operational.
- **DPI Resistance**: Combines VLESS with XTLS-Reality camouflage against foreign SNIs (e.g., Apple, Google), HTTP/2 multiplexed streaming (XHTTP), and obfuscated AmneziaWG UDP with custom packet junk (`Jc`, `Jmin`, `Jmax`) and header transformations (`S1`-`S4`, `H1`-`H4`, `I1`-`I5`).
- **Unified Profile Model**: A single subscription link dynamically renders tailored configurations for Sing-box, Clash Meta, Happ, Streisand, or v2rayN based on User-Agent inspection and route selection.

---

## Microservices & Components

### 1. `vpn_shop.bot` (Telegram Bot Automation Engine)
- **Path**: `vpn-shop/vpn_shop/bot.py`
- **Description**: Zero-heavy-framework, high-reliability Telegram Bot daemon implementing deterministic state machines (FSM) for public onboarding, tariff selection, trial activations, promotional discounts, and payment confirmation workflows.
- **Key Modules**:
  - `ShopBot`: FSM controller managing session contexts, action guards, and interactive menus.
  - `Provisioner` (`provisioning.py`): Abstraction layer interfacing with 3X-UI REST API and SQLite databases.
  - `Catalog` (`catalog.py`): Multi-tier tariff matrix (3, 6, 9 concurrent devices across 1, 3, 6, 12 months).

### 2. `vpn_shop.web` (Storefront & Self-Service Cabinet)
- **Path**: `vpn-shop/vpn_shop/web.py`
- **Description**: Lightweight async web server running on port `3090` behind Caddy.
- **Features**:
  - Dark-mode responsive UI for desktop and mobile browsers.
  - Real-time SBP QR payment checkout with client-side status polling.
  - Cloudflare Turnstile human verification protecting checkout and cabinet link recovery.
  - Background expiration reminder worker dispatching transactional HTML emails via SMTP or Resend API.

### 3. `subjson-service` (Dynamic Subscription & Profile Delivery Engine)
- **Path**: `subjson-service/app.py`
- **Description**: High-throughput FastAPI engine running on port `3088` serving optimized client subscription formats and web setup wizards.
- **Features**:
  - Route handlers: `/singbox/{sub_id}`, `/clash/{sub_id}`, `/happ/{sub_id}`, `/v2ray/{sub_id}`.
  - Web Onboarding Wizard: `/{SECRET_SEGMENT}/import/{sub_id}` with OS platform auto-detection and 1-click app import buttons.
  - Standby Quiesce Locking: Authorizes `/internal-quiesce/*` requests during node maintenance to prevent split-brain database writes.
  - Token-Bucket Rate Limiter (`RATE_LIMIT_RPM=1200`).

### 4. `awg_manager` & `awg_reconcile` (AmneziaWG Multi-Node Mesh)
- **Path**: `vpn-shop/vpn_shop/awg_manager.py` & `vpn-shop/awg_reconcile.py`
- **Description**: Lifecycle manager for obfuscated AmneziaWG WireGuard containers across primary (NL) and standby (FI) servers.
- **Features**:
  - Dual-node container orchestration over local Docker or SSH ControlMaster sockets.
  - Monthly traffic quota enforcement (500GB cap per peer) with automatic suspension and restoration.
  - Dynamic AllowedIPs split-tunneling and automated iptables DPI rules blocking BitTorrent and DHT.

---

## Disaster Recovery & Dual-Node Failover

SilentConnect features an enterprise-grade Active-Passive disaster recovery architecture guaranteeing zero data loss and continuous data-plane availability during cloud infrastructure outages:

```text
       ┌─────────────────────────────────────────────────────────────┐
       │                   PRIMARY MASTER NODE (NL)                  │
       │  • Active Control Plane: vpn-shop-silentconnect, web (3090) │
       │  • Active Data Plane: xray-maxru, xray-ws443, amnezia-awg2   │
       │  • Sole Database Writer: vpn_shop.db & x-ui.db              │
       │  • Continuous WAL Streaming: Litestream -> FI SFTP Replica  │
       └──────────────────────────────┬──────────────────────────────┘
                                      │ Continuous WAL Replica
                                      ▼
       ┌─────────────────────────────────────────────────────────────┐
       │                   STANDBY PASSIVE NODE (FI)                 │
       │  • Passive Standby Posture: web & bot STOPPED & DISABLED    │
       │  • Restore-Only Configuration: Litestream daemon NOT running │
       │  • Active Data Plane: xray-maxru, xray-ws443, amnezia-awg2   │
       │  • Incoming SFTP Replica Store: /var/lib/litestream/        │
       └──────────────────────────────┬──────────────────────────────┘
                                      │
         [ Outage on Primary Master (NL) / Disaster Declared ]
                                      │
         (1) Manual Promotion Runbook: /usr/local/bin/promote_fi.sh
             • Acquires exclusive execution lock (flock)
             • Executes Litestream restore for vpn_shop.db & x-ui.db
             • Validates SQLite integrity via PRAGMA integrity_check
             • Starts & enables local bot and web services on Standby
             • Updates Cloudflare DNS A records to Standby IP (DNS-Only ⚪)
                                      │
                   [ Standby Node Serves Traffic & Orders ]
                                      │
                    [ Primary Master Restored Online ]
                                      │
         (2) Reconcile & Demotion Runbook: /usr/local/bin/demote_fi.sh
             • Acquires Quiesce Lock on Standby (freezes local writes)
             • Synchronizes Standby SQLite DBs to Primary staging
             • Executes 3-Way Merge Engine (failback_merge.py)
             • Switches Cloudflare DNS back to Master IP (DNS-Only ⚪)
             • Disables standby web/bot services to return to Passive Standby
             • Re-enables primary Litestream streaming
```

### Standby Posture & SQLite Isolation
To maintain strict data integrity and eliminate split-brain database corruption:
- **Zero Standby Writes**: `vpn-shop-web.service` and `vpn-shop-silentconnect.service` remain stopped and disabled on the standby node during normal operations.
- **Restore-Only Posture**: The background Litestream replication daemon is **strictly not running** on the standby node. Standby uses a restore-only configuration (`/etc/litestream.yml`) targeting the incoming SFTP replica path.
- **Data Plane Continuity**: Inbound proxy engines (`xray-maxru`, `xray-ws443`, `x-ui`) and AmneziaWG obfuscated WireGuard mesh containers (`amnezia-awg2`) remain continuously active on both nodes, ensuring client connectivity is never interrupted.

### 3-Way SQLite Conflict-Free Reconciliation (`scripts/failback_merge.py`)
- **Natural Business Keys**: Reconciles profiles, orders, and users by `public_id`, `xui_email`, and `subId` rather than auto-increment primary keys.
- **Foreign Key Remapping**: Automatically updates relational references across `orders`, `profiles`, `referrers`, and `promo_codes`.
- **Expiry Preservation**: Merges subscription expirations via `MAX(primary.expires_at, secondary.expires_at)`, guaranteeing renewals made on standby are never lost.
- **Traffic Counter Delta**: Aggregates byte transfer deltas from standby into primary metrics.

### Port 2053 & Firewall Security Architecture
- **Public Restriction**: Port `2053/tcp` (3X-UI administrative panel) is strictly blocked from the public internet by UFW firewall rules on both NL and FI nodes (`ufw deny 2053/tcp`).
- **Local-Only Access**: 3X-UI binds to `127.0.0.1:2053`. Administrative access is performed exclusively via secure SSH port forwarding:
  ```bash
  ssh -N -L 2053:127.0.0.1:2053 root@your-server-ip
  ```
- **Brute-Force Rate Limiting**: Port `22/tcp` (SSH) is hardened with UFW rate limiting (`ufw limit 22/tcp`), dropping aggressive connection bursts.

---

## Protocol and Subscription Support

SilentConnect dynamically generates format-compliant profiles for modern client applications:

| Format / Route | Engine / Protocol | Target Clients | Key Features |
|---|---|---|---|
| `/singbox/<sub_id>` | Sing-box 1.18+ JSON | Sing-box, Happ, Karing | `url-test` smart outbound auto-selection, GeoIP / GeoSite routing, DoH DNS |
| `/clash/<sub_id>` | Clash Meta / Mihomo YAML | Clash Verge Rev, Mihomo Party, Flclash | Mixed Tun mode, automatic latency fallback, rule-providers |
| `/happ/<sub_id>` | Happ Encrypted Bundle | Happ (iOS, Android, Windows, macOS, TV) | `Happ-User-Info` response headers, profile auto-update, in-app renewal deep-link |
| `/v2ray/<sub_id>` | Base64 Link Bundle | v2rayN, v2rayNG, Streisand, Shadowrocket | Raw VLESS Reality, XHTTP, and VMess links with SNI camouflage |

---

## Supported Platforms & Client Matrix

The web setup wizard (`/{SECRET_SEGMENT}/import/{sub_id}`) automatically identifies client operating systems and provides step-by-step setup guides:

| Operating System | Recommended Client | Alternative Clients | Features Supported |
|---|---|---|---|
| **iOS / iPadOS** | **Happ**, **Streisand** | V2RayTun, Sing-box, Shadowrocket | 1-Click Import, Reality TLS, Today Widget |
| **Android** | **Happ**, **v2rayNG** | NekoBox, Sing-box, Flclash | Auto-Reconnect, Per-App Split Tunneling |
| **Windows** | **Happ**, **v2rayN** | Clash Verge Rev, Mihomo Party | System Proxy, Tun Virtual Network Adapter |
| **macOS** | **Happ**, **Clash Verge Rev** | Mihomo Party, Sing-box | Apple Silicon Native, Menu Bar Controls |
| **Linux** | **Clash Verge Rev** | Mihomo CLI, Sing-box CLI, v2rayA | Systemd Daemon Service, Headless CLI |
| **Android TV** | **Happ (Android TV)** | v2rayNG (TV mode), NekoBox | Remote DPAD Navigation, Leanback UI |
| **Apple TV** | **Streisand**, **Sing-box** | Shadowrocket | tvOS Native VPN Profile Integration |

---

## Telegram Bot & Administrative Workflows

The Telegram bot provides an intuitive user journey backed by robust admin tooling:

### Customer Flow
1. **Terms Acceptance**: First-time users review and accept terms (`TERMS_VERSION`).
2. **Device Selection**: Choose concurrency tier (3, 6, or 9 simultaneous devices).
3. **Duration Selection**: Choose validity period (30, 90, 180, or 360 days).
4. **Free Trial**: First-time users can activate a 7-day complimentary trial with 1 click.
5. **Promotional Discounts**: Enter promo codes for fixed RUB discounts or percentage reductions.
6. **Payment & Delivery**: Pay via SBP transfer link and receive setup links instantly upon confirmation.

### Administrative Command Suite
- `/admin` or `/menu`: Interactive administrative control panel.
- `/status`: Real-time system diagnostics (CPU load, memory metrics from `/proc/meminfo`, TCP connections from `/proc/net/tcp`, DNS resolution probes, systemd service health).
- `/traffic`: Top 20 consumers ranked by bandwidth utilization.
- `/invite`: Mint single-use or multi-use 30-day invite tokens.
- `/promo`: Interactive wizard to create promo discount codes.
- `/referrals`: Review affiliate commission ledger and process pending payouts.
- `/test_tcp` / `/test_xhttp`: Issue temporary 24-hour debug profiles (auto-purged after 24h).
- `/personal_tcp` / `/personal_xhttp`: Generate permanent administrative profiles.
- `/warp <sub_id>`: Inspect or regenerate AmneziaWG peer configurations.

---

## Web Storefront & Self-Service Cabinet

- **Landing Page**: Modern cyberpunk-themed interface presenting value propositions, live tariff selectors, and instant SBP QR checkout.
- **Order Tracking**: Real-time polling script querying payment status every 5 seconds.
- **Self-Service Cabinet**: Customers enter their email address to receive secure, time-limited magic links to manage active profiles and renew subscriptions.
- **Bot Protection**: Integrated with Cloudflare Turnstile to prevent automated captcha abuse.

---

## Configuration & Environment Catalog

All services are configured via environment variables. See [`.env.example`](.env.example) for the complete catalog of 60+ parameters.

### Quick Parameter Reference

| Variable | Default Value | Description |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | `""` | Telegram Bot token from @BotFather. |
| `TELEGRAM_BOT_USERNAME` | `""` | Bot username for generating deep-links. |
| `SUBSCRIPTION_BASE_URL` | `https://sub.example.com/...` | Base URL for fetching client subscription profiles. |
| `XUI_PANEL_URL` | `https://127.0.0.1:2053/...` | 3X-UI panel API endpoint. |
| `XUI_USERNAME` / `XUI_PASSWORD` | `""` | 3X-UI administrative credentials. |
| `XUI_DB_PATH` | `/etc/x-ui/x-ui.db` | Local filesystem path to 3X-UI database. |
| `WEB_LISTEN_PORT` | `3090` | Listening port for web checkout server. |
| `LISTEN_PORT` | `3088` | Listening port for SubJSON subscription engine. |
| `SECRET_SEGMENT` | `my-secret-sub` | Obfuscated URL path segment shielding subscriptions. |
| `CF_API_TOKEN` | `""` | Cloudflare API Token (`Zone:DNS:Edit`) for automated failover. |
| `DOMAIN_MAIN` | `example.com` | Root domain for web storefront. |
| `DOMAIN_SUB` | `sub.example.com` | Subdomain for subscription services. |
| `DOMAIN_EDGE` | `edge.example.com` | Subdomain for VPN proxy endpoints. |

---

## Deployment & Quickstart Guide

### Prerequisites
- **Operating System**: Ubuntu 22.04 / 24.04 LTS or Debian 12 (x86_64).
- **Core Dependencies**: Python 3.11+, SQLite3, Caddy v2, Git, Docker, Systemd.
- **Cloudflare Account**: Configured DNS domain with an API Token (`Zone:DNS:Edit`).

### Step 1: Clone Repository & Setup Environment
```bash
# Clone the repository
git clone https://github.com/your-org/silentconnect.git /root/silentconnect
cd /root/silentconnect

# Copy master environment configuration
cp .env.example .env
nano .env

# Setup service environment overrides
cp vpn-shop/.env.example vpn-shop/.env
cp subjson-service/subjson.env.example subjson-service/subjson.env
```

### Step 2: Install 3X-UI & Configure Inbounds
```bash
# Install 3X-UI panel
bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh)

# Configure Inbounds via 3X-UI Web Panel:
# - Inbound 1: Protocol VLESS, Transport XHTTP, Security TLS (Port 28080 or 443)
# - Inbound 2: Protocol VLESS, Transport TCP, Security XTLS-Reality (Port 443)
```

### Step 3: Configure Caddy Reverse Proxy
```bash
# Copy and customize Caddyfile
cp scripts/Caddyfile.fi /etc/caddy/Caddyfile
nano /etc/caddy/Caddyfile

# Enable and restart Caddy
systemctl enable --now caddy
systemctl restart caddy
```

### Step 4: Install & Enable Systemd Services
```bash
# 1. Install SubJSON Service
cp subjson-service/subjson.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now subjson.service

# 2. Install VPN Shop Bot & Web Services
cp vpn-shop/vpn-shop-silentconnect.service.example /etc/systemd/system/vpn-shop-silentconnect.service
cp vpn-shop/vpn-shop-web.service.example /etc/systemd/system/vpn-shop-web.service
systemctl daemon-reload
systemctl enable --now vpn-shop-silentconnect.service vpn-shop-web.service
```

---

## Automated Security & Zero-Leak Verification

SilentConnect includes an automated security audit scanner script (`scripts/security_audit_scanner.py`) to guarantee zero residual credentials, private keys, production IPs, or binary database dumps exist before distribution.

### Running Security & Test Verification
```bash
# 1. Run Automated Security Audit Scanner (Strict Mode)
python scripts/security_audit_scanner.py --target-dir . --strict

# 2. Run Full Unit Test Suite (180+ Test Cases across 14 Suites)
python -m unittest discover -s tests -p "test_*.py"

# 3. Run Sub-service Unit Test Suites
python -m unittest discover -s vpn-shop -p "test_*.py"
python -m unittest discover -s subjson-service -p "test_*.py"
```

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for more details.
