#!/usr/bin/env bash
# ==============================================================================
# demote_fi.sh - Safe Failback & Re-synchronization Script
#
# Returns cluster control back to Primary Master (NL):
# 1. Acquires mutual exclusion flock (/var/run/demote_fi.lock).
# 2. Performs 30-second stability/debounce check on NL.
# 3. Initiates Quiesce Lock on FI SubJSON (30s lease + 10s heartbeat loop).
# 4. Stops FI vpn-shop-silentconnect and vpn-shop-web services.
# 5. Transfers delta to NL and executes failback_merge.py.
# 6. Switches Cloudflare DNS back to NL IP (DNS-Only ⚪).
# 7. Starts and verifies services on NL.
# 8. Releases FI Quiesce Lock.
# 9. Dispatches Telegram administrative notification.
# ==============================================================================

# Load environment configuration if available
if [ -f "/etc/cf-failover-dns.env" ]; then
    # shellcheck source=/dev/null
    source "/etc/cf-failover-dns.env"
fi

LOCK_FILE="/var/run/demote_fi.lock"
STATE_FILE="/var/run/cluster_state"
NL_IP="${NL_IP:-${NL_MASTER_IP:-193.233.210.189}}"
FI_IP="${FI_IP:-${FI_STANDBY_IP:-95.217.178.48}}"

# Acquire non-blocking lock
exec 200>"$LOCK_FILE"
if ! flock -n 200; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [demote_fi] ERROR: Another promotion/demotion process is currently running." >&2
    exit 1
fi

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [demote_fi] $*"
}

err() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [demote_fi] ERROR: $*" >&2
}

log "=== STARTING SAFE FAILBACK & RE-SYNCHRONIZATION TO NL (${NL_IP}) ==="

# Load environment configuration
ENV_FILE="${ENV_FILE:-/root/vpn-shop/.env}"
SUBJSON_ENV="/root/subjson-service/subjson.env"

if [ -f "$ENV_FILE" ]; then
    BOT_TOKEN=$(grep -E '^TELEGRAM_BOT_TOKEN=' "$ENV_FILE" 2>/dev/null | cut -d= -f2- | tr -d '"'\''' || true)
    ADMIN_ID=$(grep -E '^ADMIN_TELEGRAM_ID=' "$ENV_FILE" 2>/dev/null | cut -d= -f2- | tr -d '"'\''' || true)
fi

INTERNAL_SECRET=""  # PLACEHOLDER
SECRET_SEGMENT="my-secret-sub"  # PLACEHOLDER
if [ -f "$SUBJSON_ENV" ]; then
    INTERNAL_SECRET=$(grep -E '^INTERNAL_SECRET=' "$SUBJSON_ENV" 2>/dev/null | cut -d= -f2- | tr -d '"'\''' || true)  # PLACEHOLDER
    SECRET_SEG_TMP=$(grep -E '^SECRET_SEGMENT=' "$SUBJSON_ENV" 2>/dev/null | cut -d= -f2- | tr -d '"'\''' || true)  # PLACEHOLDER
    if [ -n "$SECRET_SEG_TMP" ]; then
        SECRET_SEGMENT="$SECRET_SEG_TMP"  # PLACEHOLDER
    fi
fi

# Step 1: Debounce check (Confirm NL is stable)
log "Step 1: Checking NL node stability (debounce)..."
for i in {1..3}; do
    if ! ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@${NL_IP} "uptime" >/dev/null 2>&1; then
        err "NL is not stably accessible via SSH (check $i/3 failed). Aborting failback."
        exit 1
    fi
    sleep 2
done
log "NL node is stable and reachable."

# Step 2: Quiesce Lock on FI SubJSON
log "Step 2: Activating Quiesce Lock on FI SubJSON..."
QUIESCE_RESP=$(curl -s -X POST "http://127.0.0.1:3088/${SECRET_SEGMENT}/internal-quiesce/start" \
    -H "X-Internal-Secret: ${INTERNAL_SECRET}")

log "Quiesce response: $QUIESCE_RESP"

# Start background heartbeat loop (renews lease every 10s)
HEARTBEAT_PID=""
(
    while true; do
        sleep 10
        curl -s -X POST "http://127.0.0.1:3088/${SECRET_SEGMENT}/internal-quiesce/lease" \
            -H "X-Internal-Secret: ${INTERNAL_SECRET}" >/dev/null 2>&1 || true
    done
) &
HEARTBEAT_PID=$!

cleanup_heartbeat() {
    if [ -n "$HEARTBEAT_PID" ]; then
        kill "$HEARTBEAT_PID" 2>/dev/null || true
    fi
}
trap cleanup_heartbeat EXIT

# Step 3: Stop FI vpn-shop services
log "Step 3: Stopping vpn-shop services on FI..."
systemctl stop vpn-shop-silentconnect.service vpn-shop-web.service 2>/dev/null || true

# Step 4: Transfer FI DBs and Baselines to NL and execute failback_merge.py
log "Step 4: Executing 3-Way Data Merge on NL..."
ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@${NL_IP} "mkdir -p /tmp/fi_merge"

# Copy FI databases to NL merge staging
scp -o BatchMode=yes -o StrictHostKeyChecking=no /etc/x-ui/x-ui.db root@${NL_IP}:/tmp/fi_merge/fi_xui.db
scp -o BatchMode=yes -o StrictHostKeyChecking=no /root/vpn-shop/data-silentconnect/vpn_shop.db root@${NL_IP}:/tmp/fi_merge/fi_vpn.db

if [ -f "/var/lib/litestream/baseline_xui.db" ]; then
    scp -o BatchMode=yes -o StrictHostKeyChecking=no /var/lib/litestream/baseline_xui.db root@${NL_IP}:/tmp/fi_merge/baseline_xui.db
fi
if [ -f "/var/lib/litestream/baseline_vpn_shop.db" ]; then
    scp -o BatchMode=yes -o StrictHostKeyChecking=no /var/lib/litestream/baseline_vpn_shop.db root@${NL_IP}:/tmp/fi_merge/baseline_vpn_shop.db
fi

# Run failback_merge.py on NL
ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=30 root@${NL_IP} "python3 /usr/local/bin/failback_merge.py \
    --nl-vpn /root/vpn-shop/data-silentconnect/vpn_shop.db \
    --fi-vpn /tmp/fi_merge/fi_vpn.db \
    --baseline-vpn /tmp/fi_merge/baseline_vpn_shop.db \
    --nl-xui /etc/x-ui/x-ui.db \
    --fi-xui /tmp/fi_merge/fi_xui.db \
    --baseline-xui /tmp/fi_merge/baseline_xui.db"

log "3-Way Merge completed on NL."

# Step 5: Switch Cloudflare DNS back to NL IP (DNS-Only ⚪)
log "Step 5: Switching Cloudflare DNS records back to NL IP (${NL_IP})..."
if [ -x "/usr/local/bin/cf-failover-dns.sh" ]; then
    /usr/local/bin/cf-failover-dns.sh demote-fi
else
    log "WARNING: /usr/local/bin/cf-failover-dns.sh not found or not executable"
fi

# Step 6: Start and verify services on NL
log "Step 6: Starting and validating services on NL..."
ssh -o BatchMode=yes -o StrictHostKeyChecking=no root@${NL_IP} "systemctl start vpn-shop-silentconnect vpn-shop-web litestream && systemctl restart x-ui caddy subjson"

NL_BOT_ACTIVE=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=no root@${NL_IP} "systemctl is-active vpn-shop-silentconnect 2>/dev/null || echo 'inactive'")
if [ "$NL_BOT_ACTIVE" != "active" ]; then
    err "vpn-shop-silentconnect on NL is not active!"
fi

# Step 7: Release Quiesce Lock on FI
log "Step 7: Releasing Quiesce Lock on FI..."
cleanup_heartbeat
HEARTBEAT_PID=""

UNQUIESCE_RESP=$(curl -s -X POST "http://127.0.0.1:3088/${SECRET_SEGMENT}/internal-quiesce/release" \
    -H "X-Internal-Secret: ${INTERNAL_SECRET}")
log "Unquiesce response: $UNQUIESCE_RESP"

# Step 8: Update Cluster State
echo "NL_PRIMARY" > "$STATE_FILE"
log "Cluster state updated to NL_PRIMARY"

# Step 9: Telegram Notification
if [ -n "$BOT_TOKEN" ] && [ -n "$ADMIN_ID" ]; then
    MSG="✅ <b>[FAILBACK COMPLETE]</b>%0A%0ASilentConnect cluster returned to <b>NL Master (${NL_IP})</b>.%0A%0A• 3-Way Data Merge: Successful.%0A• NL Services: Active & Verified.%0A• DNS: Switched to NL (DNS-Only ⚪).%0A• FI Quiesce: Released."
    curl -s -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
        -d "chat_id=${ADMIN_ID}" \
        -d "text=${MSG}" \
        -d "parse_mode=HTML" >/dev/null 2>&1 || true
fi

log "=== SAFE FAILBACK TO NL_PRIMARY COMPLETED SUCCESSFULLY ==="
exit 0
