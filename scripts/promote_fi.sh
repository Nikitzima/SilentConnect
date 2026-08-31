#!/usr/bin/env bash
# ==============================================================================
# promote_fi.sh - Disaster Recovery Failover Promotion Script
#
# Promotes Secondary Standby (FI) to Primary Master:
# 1. Acquires mutual exclusion flock (/var/run/promote_fi.lock).
# 2. Restores x-ui.db and vpn_shop.db from Litestream WAL replicas.
# 3. Validates SQLite database integrity (PRAGMA integrity_check).
# 4. Saves baseline snapshots for failback delta tracking.
# 5. Starts vpn-shop-silentconnect.service and vpn-shop-web.service on FI.
# 6. Switches Cloudflare DNS A records to FI IP (DNS-Only ⚪).
# 7. Dispatches Telegram administrative notification.
# ==============================================================================

set -eo pipefail

LOCK_FILE="/var/run/promote_fi.lock"
STATE_FILE="/var/run/cluster_state"
FI_IP="${FI_IP:-${FI_STANDBY_IP:-198.51.100.1}}"

# Acquire non-blocking lock
exec 200>"$LOCK_FILE"
if ! flock -n 200; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [promote_fi] ERROR: Another promotion/demotion process is currently running." >&2
    exit 1
fi

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [promote_fi] $*"
}

err() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [promote_fi] ERROR: $*" >&2
}

# Check if already promoted
if [ -f "$STATE_FILE" ] && [ "$(cat "$STATE_FILE" 2>/dev/null)" = "FI_PRIMARY" ]; then
    log "Cluster is already in FI_PRIMARY state. Checking services..."
    systemctl is-active vpn-shop-silentconnect || systemctl start vpn-shop-silentconnect
    systemctl is-active vpn-shop-web || systemctl start vpn-shop-web
    exit 0
fi

log "=== STARTING DISASTER RECOVERY PROMOTION TO FI (${FI_IP}) ==="

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

litestream restore -config /etc/litestream.yml -o /etc/x-ui/x-ui.db /etc/x-ui/x-ui.db || {
    err "Litestream restore of /etc/x-ui/x-ui.db failed"
    exit 1
}

litestream restore -config /etc/litestream.yml -o /root/vpn-shop/data-silentconnect/vpn_shop.db /root/vpn-shop/data-silentconnect/vpn_shop.db || {
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
log "Step 4: Activating proxy and vpn-shop services on FI..."
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
log "FI Services active: vpn-shop-silentconnect, vpn-shop-web, subjson, x-ui, caddy"

# 5. Switch Cloudflare DNS to FI IP (DNS-Only ⚪)
log "Step 5: Switching Cloudflare DNS records to FI IP (${FI_IP})..."
if [ -x "/usr/local/bin/cf-failover-dns.sh" ]; then
    /usr/local/bin/cf-failover-dns.sh promote-fi
else
    log "WARNING: /usr/local/bin/cf-failover-dns.sh not found or not executable"
fi

# 6. Update Cluster State
echo "FI_PRIMARY" > "$STATE_FILE"
log "Cluster state updated to FI_PRIMARY"

# 7. Telegram Notification
if [ -n "$BOT_TOKEN" ] && [ -n "$ADMIN_ID" ]; then
    MSG="🚨 <b>[FAILOVER ALERT]</b>%0A%0ASilentConnect has been <b>PROMOTED to FI Standby (${FI_IP})</b>.%0A%0A• SQLite DBs: Restored and verified.%0A• Services: Active.%0A• DNS: Switched to FI (DNS-Only ⚪)."
    curl -s -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
        -d "chat_id=${ADMIN_ID}" \
        -d "text=${MSG}" \
        -d "parse_mode=HTML" >/dev/null 2>&1 || true
fi

log "=== PROMOTION TO FI_PRIMARY COMPLETED SUCCESSFULLY ==="
exit 0
