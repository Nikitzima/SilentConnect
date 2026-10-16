# SilentConnect: Multi-Protocol VPN & Automated Subscription Platform

[![Security Audit](https://img.shields.io/badge/Security_Audit-Zero_Leaks_Passed-10b981.svg?style=flat-square)](#automated-security--zero-leak-verification)
[![Tests](https://img.shields.io/badge/Tests-444_passed_(9_skipped)-10b981.svg?style=flat-square)](#automated-security--zero-leak-verification)
[![Python Version](https://img.shields.io/badge/Python-3.11+-3b82f6.svg?style=flat-square)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-64748b.svg?style=flat-square)](LICENSE)
[![Protocols](https://img.shields.io/badge/Protocols-VLESS_%7C_Reality_%7C_XHTTP_%7C_Hysteria2_%7C_AmneziaWG_%7C_OpenFlux-8b5cf6.svg?style=flat-square)](#protocol-and-subscription-support)

**SilentConnect** is a high-availability, multi-protocol VPN subscription ecosystem and automation platform engineered to withstand aggressive Deep Packet Inspection (DPI/filtering), packet manipulation, and datacenter outages. It bridges Telegram bot sales automation, dynamic multi-format subscription delivery, Xray/3X-UI panel provisioning, an AmneziaWG device slots hub with quota accounting, and automated multi-node active-passive disaster recovery.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Production Node Inventory](#production-node-inventory)
3. [Microservices & Components](#microservices--components)
4. [Disaster Recovery & Edge Failover](#disaster-recovery--edge-failover)
5. [Protocol & Subscription Delivery](#protocol--subscription-delivery)
6. [Supported Platforms & Client Matrix](#supported-platforms--client-matrix)
7. [Telegram Bot & Administrative Workflows](#telegram-bot--administrative-workflows)
8. [Web Storefront & Self-Service Cabinet](#web-storefront--self-service-cabinet)
9. [Configuration & Environment Catalog](#configuration--environment-catalog)
10. [Deployment & Quickstart Guide](#deployment--quickstart-guide)
11. [Automated Security & Zero-Leak Verification](#automated-security--zero-leak-verification)
12. [In-Depth Documentation Index](#in-depth-documentation-index)

---

## Architecture Overview

SilentConnect operates on an active-passive, geo-distributed multi-node topology designed for resilience, strict data integrity, and fast recovery:

```text
                                      [ Users & Clients ]
                                               │
                 ┌─────────────────────────────┴───────────────────────────┐
                 │                                                         │
    [ HTTPS: Store & Subscriptions ]                          [ VPN Traffic (DPI Bypass) ]
                 │                                                         │
       https://<SUB_DOMAIN>                                       https://<EDGE_DOMAIN>
    (API Gateway / Edge Buffer)                                     (Direct A-Records)
                 │                                                         │
                 ▼                                                         │
┌──────────────────────────────────────────────┐                           │
│          NL MASTER (Primary Node)            │                           │
│                                              │                           │
│  [ Xray Dokodemo Multiplexer (Port 443) ]    │◄──────────────────────────┤
│         │                          │         │                           │
│  (SNI: Web / Sub)           (SNI: Reality)   │                           │
│         ▼                          ▼         │                           │
│    [ Caddy v2 ]             [ Xray Inbound ] │                           │
│   (TLS Term :4430)         (Vision / XHTTP)  │                           │
│    ├── Web Shop (:3090)     (gRPC 29443)     │                           │
│    └── SubJSON  (:3088)            │         │                           │
│         │                          │         │                           │
│         ▼                          │         │                           │
│  [ SQLite WAL Master DBs ] ◄───────┘         │                           │
│  • vpn_shop.db  • x-ui.db                    │                           │
│  • Telegram Bot (Active Daemon)              │                           │
│  • Hysteria 2 (:38443) & AWG (:44121)        │◄───────────────────┐      │
└──────────────────────┬───────────────────────┘                    │      │
                       │                                            │      │
         [ 3-Minute Automated Snapshot Push ]                       │      │
            (sync_primary_to_standbys.sh)                           │      │
                       │                                            │      │
        ┌──────────────┴──────────────┐                             │      │
        ▼                             ▼                             │      │
┌───────────────────────────┐ ┌───────────────────────────┐         │      │
│   PL STANDBY (10 Gbps)    │ │   FI STANDBY (Backup)     │         │      │
│                           │ │                           │         │      │
│ • SQLite Replica (Sync)   │ │ • SQLite Replica (Sync)   │         │      │
│ • SubJSON & Web (Standby) │ │ • SubJSON & Web (Standby) │         │      │
│ • Xray Reality (ACTIVE)   │ │ • Xray Reality (ACTIVE)   │◄────────┼──────┘
│ • Hysteria 2 & AWG ACTIVE │ │ • Hysteria 2 & AWG ACTIVE │         │
└─────────────┬─────────────┘ └─────────────┬─────────────┘         │
              ▲                             ▲                       │
              │                             │                       │
              └─────────────────────────────┴───────────────────────┘
                     [ Direct Client Transit Across All Nodes ]
                     (VLESS Reality, Hysteria 2, AmneziaWG)
```

### Key Architectural Highlights
- **Decoupled Control & Data Planes**: Billing, Telegram bot processing, and subscription rendering run independently from packet transit. Maintenance on web services never interrupts active VPN tunnels.
- **Advanced DPI Camouflage**: Combines VLESS with XTLS-Reality masquerade against foreign domains (`minClientVer: 0.0.0`), HTTP/2 multiplexed streaming (XHTTP), Hysteria 2 with `gecko` packet padding and port hopping (UDP 38443, redirected from 443 and 30000–40000), and AmneziaWG obfuscated WireGuard with custom junk parameters (`Jc/Jmin/Jmax/S1-S4/H1-H4`).
- **Emergency Edge Buffer (Vercel Anycast)**: Anycast edge reverse proxy routing web requests directly to available standbys with zero DNS propagation latency during network incidents.

---

## Production Node Inventory

| Node / Role | Region | Network Uplink | Services Hosted | Cluster Status |
|---|---|---|---|---|
| **NL Master** | Western Europe | 1 Gbps | • Telegram Bot (`vpn_shop.bot`)<br>• Web Shop (`:3090`)<br>• SubJSON (`:3088`)<br>• X-UI Reality / Hysteria 2 (`gecko`)<br>• AmneziaWG (`amnezia-awg2`)<br>• Cloud Stream Worker | **PRIMARY MASTER**<br>(Active master source for database replication) |
| **PL Standby** | Central Europe | **10 Gbps** | • Standby Web (`:3090`)<br>• SubJSON (`:3088`)<br>• X-UI Reality / Hysteria 2 (`gecko`)<br>• AmneziaWG (`amnezia-awg2`)<br>• Cloud Stream Worker | **STANDBY READY**<br>(Receives snapshot push every 3 minutes; failover ready) |
| **FI Standby** | Northern Europe | 1 Gbps | • Standby Web (`:3090`)<br>• SubJSON (`:3088`)<br>• X-UI Reality / Hysteria 2 (`gecko`)<br>• AmneziaWG (`amnezia-awg2`)<br>• HA Health Monitor | **STANDBY READY**<br>(Emergency secondary standby; receives snapshot push) |

---

## Microservices & Components

### 1. `vpn_shop.bot` (Telegram Automation Engine)
- **Path**: [`vpn-shop/vpn_shop/bot.py`](vpn-shop/vpn_shop/bot.py)
- **Description**: High-reliability Telegram bot daemon implementing deterministic finite state machines (FSM) for customer onboarding, tariff selection, promo code validation, affiliate tracking, and payment processing.
- **Key Modules**:
  - `ShopBot`: Core FSM controller managing session contexts, action guards, and interactive inline keyboards.
  - `Provisioner` ([`provisioning.py`](vpn-shop/vpn_shop/provisioning.py)): Abstraction layer synchronizing 3X-UI REST APIs and SQLite client state.
  - `Catalog` ([`catalog.py`](vpn-shop/vpn_shop/catalog.py)): Authoritative tariff engine (3, 6, 9 devices with multi-month discount rounding).

### 2. `vpn_shop.web` (Storefront & Self-Service Cabinet)
- **Path**: [`vpn-shop/vpn_shop/web.py`](vpn-shop/vpn_shop/web.py)
- **Description**: Asynchronous web engine running on port `3090` behind Caddy.
- **Features**:
  - Dark-mode responsive UI supporting desktop and mobile viewports.
  - Instant SBP QR code checkout with asynchronous status verification.
  - Device slots self-service hub: configuration download, live PNG QR codes, and inline slot renaming.
  - Cloudflare Turnstile human verification with automated fallback.

### 3. `subjson-service` (Dynamic Subscription & Profile Delivery)
- **Path**: [`subjson-service/app.py`](subjson-service/app.py)
- **Description**: High-throughput subscription engine running on port `3088`.
- **Features**:
  - Dynamic profile rendering: `/singbox/{sub_id}`, `/clash/{sub_id}`, `/happ/{sub_id}`, `/streisand/{sub_id}`.
  - Web Onboarding Wizard: `/{SECRET_SEGMENT}/import/{sub_id}` with platform detection and 1-click client import.
  - Token-Bucket rate limiting (`RATE_LIMIT_RPM=1200`) and LRU response caching.

### 4. `awg_manager` & Device Slots Hub (AmneziaWG Mesh)
- **Path**: [`vpn-shop/vpn_shop/awg_manager.py`](vpn-shop/vpn_shop/awg_manager.py) & [`vpn-shop/vpn_shop/awg_traffic.py`](vpn-shop/vpn_shop/awg_traffic.py)
- **Description**: Multi-device slot allocator and traffic accounting engine.
- **Features**:
  - Allocates dedicated peer slots per subscriber (3, 6, or 9 slots) across `10.8.1.0/24`, `10.8.2.0/24`, and `10.8.3.0/24`.
  - Enforces monthly bandwidth quotas (250 GB, 500 GB, 1000 GB per 30-day billing cycle UTC).
  - Soft-disables WireGuard slots when quota is exceeded, while keeping VLESS Reality unmetered and fully operational.

---

## Disaster Recovery & Edge Failover

```text
                 [ Outage on Primary Master ]
                              │
              (1) Run Orchestrator: switch_primary.py
                  • Preflight check & target validation
                  • Reconciles SQLite snapshots
                  • Promotes Standby node to Primary
                  • Switches Cloudflare DNS A records
                              │
                 [ Standby Serves Live Traffic ]
                              │
              (2) Living Edge Buffer (Vercel Anycast)
                  • Instant reverse proxy for web and subscriptions
                  • Eliminates client-side ISP DNS caching delays
```

- **Continuous Snapshot Replication**: `sync_primary_to_standbys.sh` runs every 3 minutes via cron, generating clean SQLite `.backup` snapshots of `vpn_shop.db` and pushing them alongside X-UI client keys to Poland and Finland.
- **Cluster Failover**: Modern cluster failover is orchestrated via `switch_primary.py` (supporting `--dry-run` and `--preflight`). Legacy standalone failover scripts (`promote_fi.sh` / `demote_fi.sh`) remain available on the FI standby node.
- **Emergency Reverse Proxy**: Documented in [`docs/EDGE_FAILOVER_ARCHITECTURE.md`](docs/EDGE_FAILOVER_ARCHITECTURE.md) and [`docs/HA_DISASTER_RECOVERY.md`](docs/HA_DISASTER_RECOVERY.md), providing zero-delay fallback through Anycast edge workers.

---

## Protocol & Subscription Delivery

| Protocol / Transport | Transport Layer | Server Ports | Client Profile Route | Key Capabilities |
|---|---|---|---|---|
| **VLESS Reality Vision** | TCP | `443` / `23385` | `/singbox/{id}`, `/happ/{id}` | Direct TLS masquerade (`minClientVer: 0.0.0`), Vision flow |
| **VLESS Reality XHTTP** | TCP | `8443` | `/singbox/{id}`, `/happ/{id}` | Multiplexed HTTP/2 streaming |
| **VLESS Reality gRPC** | TCP | `29443` | `/singbox/{id}`, `/happ/{id}` | gRPC transport for high-latency connections |
| **Hysteria 2** | UDP | `38443` (redirect 443, 30k–40k) | `/singbox/{id}`, `/streisand/{id}` | Mandatory `gecko` obfuscation, port hopping |
| **AmneziaWG** | UDP | `44121` / `49752` | `/sub/awg/{token}/slot/{idx}/config` | Obfuscated WireGuard headers, dedicated device slots |
| **Cloud Stream** | WSS | `443` | Custom document link | Document-collaboration transport for extreme network isolation |

---

## Supported Platforms & Client Matrix

The web onboarding wizard automatically detects the visitor's operating system:

| Platform | Recommended App | Alternative Apps | Integration Method |
|---|---|---|---|
| **Android** | **sing-box MT**, **Happ** | Clash Mi, v2rayNG | 1-Click Import button / subscription URL |
| **iOS / iPadOS** | **sing-box MT**, **Happ**, **Streisand** | Shadowrocket, Clash Mi | Universal link / 1-Click Deep Link |
| **Windows** | **Happ**, **sing-box MT** | Clash Meta, v2rayN | Native setup guide & profile import |
| **macOS** | **sing-box MT**, **Happ** | Clash Verge Rev | Apple Silicon native client import |
| **Linux / Routers** | **sing-box CLI**, **AmneziaWG** | Mihomo CLI, Keenetic AWG | Download `.conf` / JSON configuration |

---

## Telegram Bot & Administrative Workflows

### Public Commands
- `/start` — Main menu, subscription status, and customer onboarding.
- `/prices` — Tariff overview (3, 6, 9 devices across 1, 3, 6, 12 months).
- `/pay` — Create an order or renew an active subscription.
- `/cabinet` — Self-service links and connection wizard.
- `/help` — Step-by-step setup instructions by platform.
- `/faq` — Answers to common connection and billing questions.
- `/rules` — Service terms of use and privacy policy.
- `/support` — Customer support contact channel.

### Administrative Command Suite (`/admin`)
- **Server Health**: Real-time CPU, RAM, active sockets, and systemd service statuses.
- **Traffic Top**: Top bandwidth consumers across billing periods.
- **Profile Management**: Enable, soft-disable, or inspect user profiles by ID.
- **Affiliate Ledger**: Review referral balances and process affiliate payouts.
- **Invite & Promo Generator**: Mint multi-use promotional discount codes and invite tokens.
- **Payment Approvals**: One-click confirmation and cancellation of pending orders.

---

## Web Storefront & Self-Service Cabinet

- **Landing Page**: Modern cyberpunk interface featuring dynamic pricing cards and instant checkout.
- **Authoritative Tariff Matrix** (from `catalog.py`):
  - **3 devices**: 149 ₽ / month (250 GB AWG quota + unmetered VLESS)
  - **6 devices**: 199 ₽ / month (500 GB AWG quota + unmetered VLESS)
  - **9 devices**: 235 ₽ / month (1000 GB AWG quota + unmetered VLESS)
  - *Duration discounts*: -10% for 3 months, -20% for 6 months, -30% for 12 months (rounded to psychological 9-ending prices).
- **Device Slots Hub**: Dedicated slot management interface allowing customers to download individual `.conf` files, view live PNG QR codes, and rename devices.

---

## Configuration & Environment Catalog

All components are configured via environment variables. See [`.env.example`](.env.example) for defaults:

| Variable | Default Value | Description |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | `""` | Telegram Bot API token from @BotFather. |
| `TELEGRAM_BOT_USERNAME` | `""` | Bot username used to assemble deep-links. |
| `SUBSCRIPTION_BASE_URL` | `http://127.0.0.1:3088/sub/json` | Base URL used by the subscription engine. |
| `WEB_LISTEN_PORT` | `3090` | Port for the web storefront and checkout daemon. |
| `LISTEN_PORT` | `3088` | Port for the `subjson-service` FastAPI engine. |
| `SECRET_SEGMENT` | `my-secret-sub` | Obfuscated URL path prefix protecting subscription endpoints. |
| `XUI_PANEL_URL` | `https://127.0.0.1:2053/` | 3X-UI internal administrative API URL. |
| `XUI_DB_PATH` | `/etc/x-ui/x-ui.db` | Filesystem path to the primary 3X-UI SQLite database. |
| `MONTHLY_PRICE_3_DEVICES_RUB`| `149` | Base monthly price for 3 concurrent devices. |
| `MONTHLY_PRICE_6_DEVICES_RUB`| `199` | Base monthly price for 6 concurrent devices. |
| `MONTHLY_PRICE_9_DEVICES_RUB`| `235` | Base monthly price for 9 concurrent devices. |
| `CF_TURNSTILE_SITE_KEY` | `""` | Cloudflare Turnstile public site key. |
| `CF_TURNSTILE_SECRET_KEY` | `""` | Cloudflare Turnstile private validation secret. |
| `PLATEGA_MERCHANT_ID_WEB` | `""` | Platega.io merchant identifier for web checkout. |
| `PLATEGA_SECRET_WEB` | `""` | Platega.io webhook validation secret. |

---

## Deployment & Quickstart Guide

### Prerequisites
- **Operating System**: Ubuntu 24.04 LTS or Debian 13 (Trixie).
- **Runtimes**: Python 3.11+, Docker, Caddy v2, SQLite 3.35+.

### Running Services with Systemd
```bash
# 1. Enable and start SubJSON subscription engine
systemctl enable --now subjson.service

# 2. Enable and start Web Storefront & Telegram Bot
systemctl enable --now vpn-shop-web.service vpn-shop-silentconnect.service

# 3. Verify listening sockets
ss -tulpn | grep -E '3088|3090|443|38443|44121'
```

---

## Automated Security & Zero-Leak Verification

SilentConnect includes an automated security audit scanner and regression test suite enforced via a git pre-push hook:

```bash
# 1. Run strict zero-leak security audit scanner
python scripts/security_audit_scanner.py --strict

# Output:
# Files Scanned    : 190
# Violations Found : 0
# [PASS] AUDIT PASSED: Zero leaks, zero binaries, zero untracked secrets detected.

# 2. Run complete regression test suite
python -m unittest discover -s tests -p "test_*.py"

# Output:
# Ran 444 tests in 68.478s
# OK (skipped=9)
```

---

## In-Depth Documentation Index

For exhaustive architecture blueprints, disaster recovery runbooks, and protocol details, refer to:

- **[ARCHITECTURE.md](ARCHITECTURE.md)** — Comprehensive cluster topology, SQLite replication mechanics, port maps, and failover workflows.
- **[DEPLOYMENT.md](DEPLOYMENT.md)** — Step-by-step standby node provisioning on Debian 13, systemd unit catalog, iptables rules, and disaster recovery.
- **[AMNEZIA_SLOTS.md](AMNEZIA_SLOTS.md)** — AmneziaWG device slots hub, 250/500/1000 GB monthly quota accounting engine, and client configuration specs.
- **[WHITELIST_SPEC.md](WHITELIST_SPEC.md)** — Dedicated slot architecture for cloud document stream transport.
- **[docs/EDGE_FAILOVER_ARCHITECTURE.md](docs/EDGE_FAILOVER_ARCHITECTURE.md)** — Living Vercel Anycast edge reverse proxy design for instant failover.
- **[docs/HA_DISASTER_RECOVERY.md](docs/HA_DISASTER_RECOVERY.md)** — Historical disaster recovery drill report (01.09.2026) and edge buffer specification.

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.
