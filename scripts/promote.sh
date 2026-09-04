#!/usr/bin/env bash
# ==============================================================================
# promote.sh - Generalized Disaster Recovery Failover Promotion Script
# Supports both FI (Finland) and PL (Poland) standby nodes.
#
# Usage:
#   promote.sh --node fi    # Promote FI (legacy: promote_fi.sh still works)
#   promote.sh --node pl    # Promote PL (new)
#   promote.sh --node=pl    # Alternate syntax
#
# Promotion steps:
# 1. Acquires mutual exclusion flock (/var/run/promote_<node>.lock).
# 2. Restores x-ui.db and vpn_shop.db from Litestream WAL replicas.
# 3. Validates SQLite database integrity (PRAGMA integrity_check).
# 4. Saves baseline snapshots for failback delta tracking.
# 5. Starts vpn-shop-silentconnect.service and vpn-shop-web.service.
# 6. Switches Cloudflare DNS A records to standby node IP (DNS-Only ⚪).
# 7. Dispatches Telegram administrative notification.
# ==============================================================================

set -eo pipefail

# ---- Node Configuration ----
NODE=""  # 'fi' or 'pl'
while [[ $# -gt 0 ]]; do
    case "$1" in
        --node)
            NODE="${2:-}"
            shift 2
            ;;
        --node=*)
            NODE="${1#--node=}"
            shift
            ;;
        *)
            echo "[promote] Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

# Normalize to lowercase
NODE="${NODE,,}"

# Fall back to FI if no node specified (backward compatibility)
if [ -z "$NODE" ]; then
    NODE="fi"
fi

if [ "$NODE" != "fi" ] && [ "$NODE" != "pl" ]; then
    echo "[promote] ERROR: --node must be 'fi' or 'pl', got '$NODE'" >&2
    exit 1
fi

# Node-specific IP defaults (override via environment variables)
case "$NODE" in
    fi)
        LOCK_FILE="${LOCK_FILE:-/var/run/promote_fi.lock}"
        STATE_FILE="${STATE_FILE:-/var/run/cluster_state}"
        NODE_IP="${NODE_IP:-${FI_IP:-${FI_STANDBY_IP:-198.51.100.1}}}"
        STATE_VALUE="FI_PRIMARY"
        LITESTREAM_CONFIG="${LITESTREAM_CONFIG:-/etc/litestream.yml}"
        NODE_LABEL="FI"
        ;;
    pl)
        LOCK_FILE="${LOCK_FILE:-/var/run/promote_pl.lock}"
        STATE_FILE="${STATE_FILE:-/var/run/cluster_state}"
        NODE_IP="${NODE_IP:-${PL_IP:-${PL_STANDBY_IP:-2.56.125.177}}}"
        STATE_VALUE="PL_PRIMARY"
        LITESTREAM_CONFIG="${LITESTREAM_CONFIG:-/etc/litestream_pl.yml}"
        NODE_LABEL="PL"
        ;;
esac

# Acquire non-blocking flock
exec 200>"$LOCK_FILE"
if ! flock -n 200; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [promote_${NODE}] ERROR: Another promotion/demotion process is currently running." >&2
    exit 1
fi

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [promote_${NODE}] $*"
}

err() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [promote_${NODE}] ERROR: $*" >&2
}

# Check if already promoted
if [ -f "$STATE_FILE" ] && [ "$(cat "$STATE_FILE" 2>/dev/null)" = "$STATE_VALUE" ]; then
    log "Cluster is already in ${STATE_VALUE} state. Checking services..."
    systemctl is-active vpn-shop-silentconnect 2>/dev/null || systemctl start vpn-shop-silentconnect
    systemctl is-active vpn-shop-web 2>/dev/null || systemctl start vpn-shop-web
    exit 0
fi

log "=== STARTING DISASTER RECOVERY PROMOTION TO ${NODE_LABEL} (${NODE_IP}) ==="

# Load environment configuration
ENV_FILE="${ENV_FILE:-/root/vpn-shop/.env}"
if [ -f "$ENV_FILE" ]; then
    BOT_TOKEN=$(grep -E '^TELEGRAM_BOT_TOKEN=' "$ENV_FILE" 2>/dev/null | cut -d= -f2- | tr -d '"'\''' || true)
    ADMIN_ID=$(grep -E '^ADMIN_TELEGRAM_ID=' "$ENV_FILE" 2>/dev/null | cut -d= -f2- | tr -d '"'\''' || true)
fi

# 1. Restore SQLite databases from Litestream
log "Step 1: Restoring SQLite databases from Litestream replicas..."
mkdir -p /etc/x-ui /root/vpn-shop/data-silentconnect /var/lib/litestream

# Stop x-ui before restoring database
systemctl stop x-ui 2>/dev/null || true

# Try node-specific config, fall back to default litestream.yml
LITESTREAM_CFG="$LITESTREAM_CONFIG"
if [ ! -f "$LITESTREAM_CFG" ]; then
    LITESTREAM_CFG="/etc/litestream.yml"
fi

litestream restore -config "$LITESTREAM_CFG" -o /etc/x-ui/x-ui.db /etc/x-ui/x-ui.db || {
    err "Litestream restore of /etc/x-ui/x-ui.db failed"
    exit 1
}

litestream restore -config "$LITESTREAM_CFG" -o /root/vpn-shop/data-silentconnect/vpn_shop.db /root/vpn-shop/data-silentconnect/vpn_shop.db || {
    err "Litestream restore of /root/vpn-shop/data-silentconnect/vpn_shop.db failed"
    exit 1
}

# 2. Validate SQLite integrity
log "Step 2: Validating SQLite database integrity..."
XUI_CHECK=$(sqlite3 /etc/x-ui/x-ui.db "PRAGMA integrity_check;" 2>/dev/null || echo "failed")
if [ "$XUI_CHECK" != "ok" ]; then
    err "x-ui.db integrity check failed: $XUI_CHECK"
    exit 1
fi

VPN_CHECK=$(sqlite3 /root/vpn-shop/data-silentconnect/vpn_shop.db "PRAGMA integrity_check;" 2>/dev/null || echo "failed")
if [ "$VPN_CHECK" != "ok" ]; then
    err "vpn_shop.db integrity check failed: $VPN_CHECK"
    exit 1
fi
log "SQLite integrity verified: OK"

# 3. Save baseline snapshots for failback delta tracking
log "Step 3: Saving baseline snapshots in /var/lib/litestream/..."
cp -f /etc/x-ui/x-ui.db /var/lib/litestream/baseline_xui.db
cp -f /root/vpn-shop/data-silentconnect/vpn_shop.db /var/lib/litestream/baseline_vpn_shop.db

# 4. Restart proxy services and start vpn-shop services
log "Step 4: Activating proxy and vpn-shop services on ${NODE_LABEL}..."
systemctl restart x-ui caddy subjson

systemctl start vpn-shop-silentconnect.service
systemctl start vpn-shop-web.service

# Verify services are active
systemctl is-active vpn-shop-silentconnect >/dev/null || {
    err "vpn-shop-silentconnect failed to start"
    exit 1
}
systemctl is-active vpn-shop-web >/dev/null || {
    err "vpn-shop-web failed to start"
    exit 1
}
log "${NODE_LABEL} Services active: vpn-shop-silentconnect, vpn-shop-web, subjson, x-ui, caddy"

# 5. Switch Cloudflare DNS to standby node IP (DNS-Only ⚪)
log "Step 5: Switching Cloudflare DNS records to ${NODE_LABEL} IP (${NODE_IP})..."
if [ -x "/usr/local/bin/cf-failover-dns.sh" ]; then
    /usr/local/bin/cf-failover-dns.sh "promote-${NODE}"
else
    log "WARNING: /usr/local/bin/cf-failover-dns.sh not found or not executable"
fi

# 6. Update Cluster State
echo "$STATE_VALUE" > "$STATE_FILE"
log "Cluster state updated to $STATE_VALUE"

# 7. Telegram Notification
if [ -n "$BOT_TOKEN" ] && [ -n "$ADMIN_ID" ]; then
    MSG="🚨 <b>[FAILOVER ALERT]</b>%0A%0ASilentConnect has been <b>PROMOTED to ${NODE_LABEL} Standby (${NODE_IP})</b>.%0A%0A• SQLite DBs: Restored and verified.%0A• Services: Active.%0A• DNS: Switched to ${NODE_LABEL} (DNS-Only ⚪)."
    curl -s -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
        -d "chat_id=${ADMIN_ID}" \
        -d "text=${MSG}" \
        -d "parse_mode=HTML" >/dev/null 2>&1 || true
fi

log "=== PROMOTION TO ${STATE_VALUE} COMPLETED SUCCESSFULLY ==="
exit 0
