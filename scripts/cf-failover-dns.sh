#!/usr/bin/env bash
# ==============================================================================
# Cloudflare DNS Automation for SilentConnect Failover / Failback
#
# MANDATORY SAFETY GUARDRAIL:
# CLOUDFLARE PROXY (🟠) IS STRICTLY FORBIDDEN IN RUSSIA (BLOCKED BY TSPU DPI).
# ALL DNS RECORDS MUST BE STRICTLY DNS-ONLY (⚪) WITH "proxied": false.
# ==============================================================================

set -eo pipefail

NL_IP="${NL_IP:-${NL_MASTER_IP:-192.0.2.1}}"
FI_IP="${FI_IP:-${FI_STANDBY_IP:-198.51.100.1}}"
DOMAIN_MAIN="${DOMAIN_MAIN:-example.com}"
DOMAIN_SUB="${DOMAIN_SUB:-sub.${DOMAIN_MAIN}}"
DOMAIN_EDGE="${DOMAIN_EDGE:-edge.${DOMAIN_MAIN}}"
DOMAINS=("${DOMAIN_MAIN}" "${DOMAIN_SUB}" "${DOMAIN_EDGE}")

# Load environment configuration if available
if [ -f "/etc/cf-failover-dns.env" ]; then
    # shellcheck source=/dev/null
    source "/etc/cf-failover-dns.env"
fi
if [ -z "${CF_API_TOKEN:-}" ] && [ -f "/root/.cf_token" ]; then
    # shellcheck source=/dev/null
    source "/root/.cf_token"
fi
if [ -z "${CF_API_TOKEN:-}" ] && [ -f "/root/vpn-shop/.env" ]; then
    # shellcheck source=/dev/null
    CF_API_TOKEN_ENV=$(grep -E '^CF_API_TOKEN=' /root/vpn-shop/.env 2>/dev/null | cut -d= -f2- | tr -d '"'\''' || true)
    if [ -n "$CF_API_TOKEN_ENV" ]; then
        CF_API_TOKEN="$CF_API_TOKEN_ENV"
    fi
fi

CF_API_TOKEN="${CF_API_TOKEN:-${CLOUDFLARE_API_TOKEN:-}}"
CF_ZONE_ID="${CF_ZONE_ID:-${CLOUDFLARE_ZONE_ID:-}}"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [cf-failover-dns] $*"
}

err() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [cf-failover-dns] ERROR: $*" >&2
}

require_token() {
    if [ -z "$CF_API_TOKEN" ]; then
        err "CF_API_TOKEN is not set. Please set CF_API_TOKEN or configure /etc/cf-failover-dns.env"
        exit 1
    fi
}

get_zone_id() {
    if [ -n "$CF_ZONE_ID" ]; then
        echo "$CF_ZONE_ID"
        return 0
    fi

    require_token
    local zone_resp
    zone_resp=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=${DOMAIN_MAIN}" \
        -H "Authorization: Bearer ${CF_API_TOKEN}" \
        -H "Content-Type: application/json")

    local success
    success=$(echo "$zone_resp" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('success', False))" 2>/dev/null || echo "False")
    if [ "$success" != "True" ]; then
        err "Failed to query Zone ID from Cloudflare: $zone_resp"
        exit 1
    fi

    local zid
    zid=$(echo "$zone_resp" | python3 -c "import sys, json; data=json.load(sys.stdin); res=data.get('result', []); print(res[0]['id'] if res else '')" 2>/dev/null || echo "")
    if [ -z "$zid" ]; then
        err "Zone ${DOMAIN_MAIN} not found in Cloudflare account"
        exit 1
    fi

    CF_ZONE_ID="$zid"
    echo "$zid"
}

get_record_id() {
    local domain="$1"
    local zone_id="$2"

    local rec_resp
    rec_resp=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records?type=A&name=${domain}" \
        -H "Authorization: Bearer ${CF_API_TOKEN}" \
        -H "Content-Type: application/json")

    local rec_id
    rec_id=$(echo "$rec_resp" | python3 -c "import sys, json; data=json.load(sys.stdin); res=data.get('result', []); print(res[0]['id'] if res else '')" 2>/dev/null || echo "")
    echo "$rec_id"
}

update_record() {
    local domain="$1"
    local target_ip="$2"
    local zone_id
    zone_id=$(get_zone_id)

    log "Updating A record: ${domain} -> ${target_ip} (DNS-Only ⚪, proxied: false)..."

    local rec_id
    rec_id=$(get_record_id "$domain" "$zone_id")

    if [ -z "$rec_id" ]; then
        # Create record if missing
        log "Record ${domain} does not exist, creating new A record..."
        local create_resp
        create_resp=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records" \
            -H "Authorization: Bearer ${CF_API_TOKEN}" \
            -H "Content-Type: application/json" \
            --data '{"type":"A","name":"'"${domain}"'","content":"'"${target_ip}"'","ttl":60,"proxied":false}')

        verify_cf_response "$domain" "$target_ip" "$create_resp"
    else
        # Update existing record
        local update_resp
        update_resp=$(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records/${rec_id}" \
            -H "Authorization: Bearer ${CF_API_TOKEN}" \
            -H "Content-Type: application/json" \
            --data '{"type":"A","name":"'"${domain}"'","content":"'"${target_ip}"'","ttl":60,"proxied":false}')

        verify_cf_response "$domain" "$target_ip" "$update_resp"
    fi
}

verify_cf_response() {
    local domain="$1"
    local expected_ip="$2"
    local resp="$3"

    # Python verification of success and STRICT proxied == false check
    local check_result
    check_result=$(python3 -c "
import sys, json
try:
    data = json.loads('''$resp''')
    success = data.get('success', False)
    if not success:
        print(f'API_ERROR:{json.dumps(data.get(\"errors\", []))}')
        sys.exit(1)
    result = data.get('result', {})
    proxied = result.get('proxied', None)
    content = result.get('content', '')
    if proxied is not False:
        print(f'PROXIED_VIOLATION: proxied is {proxied}, must be False')
        sys.exit(2)
    if content != '$expected_ip':
        print(f'CONTENT_MISMATCH: got {content}, expected $expected_ip')
        sys.exit(3)
    print('OK')
except Exception as e:
    print(f'PARSE_ERROR:{e}')
    sys.exit(4)
" 2>&1)

    if [ "$check_result" = "OK" ]; then
        log "✅ [VERIFIED] ${domain} successfully updated to ${expected_ip} (DNS-Only ⚪, proxied: false)"
    else
        err "❌ Verification failed for ${domain}: ${check_result}"
        err "Full API Response: ${resp}"
        exit 1
    fi
}

cmd_status() {
    log "Checking Cloudflare DNS status for managed domains..."
    if [ -z "$CF_API_TOKEN" ]; then
        log "CF_API_TOKEN not configured. Testing public DNS resolution..."
        for d in "${DOMAINS[@]}"; do
            local resolved
            resolved=$(python3 -c "import socket; print(socket.gethostbyname('$d'))" 2>/dev/null || echo "UNRESOLVED")
            log "  ${d} -> ${resolved}"
        done
        return 0
    fi

    local zone_id
    zone_id=$(get_zone_id)

    for d in "${DOMAINS[@]}"; do
        local rec_resp
        rec_resp=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records?type=A&name=${d}" \
            -H "Authorization: Bearer ${CF_API_TOKEN}" \
            -H "Content-Type: application/json")

        python3 -c "
import sys, json
data = json.loads('''$rec_resp''')
res = data.get('result', [])
if res:
    rec = res[0]
    proxy_icon = '🟠 PROXIED (FORBIDDEN)' if rec.get('proxied') else '⚪ DNS-Only (VALID)'
    print(f\"  {rec.get('name')}: {rec.get('content')} [TTL: {rec.get('ttl')}s, {proxy_icon}]\")
else:
    print(f\"  $d: RECORD_NOT_FOUND\")
"
    done
}

cmd_promote_fi() {
    log "=== Promoting DNS to Secondary Node FI (${FI_IP}) ==="
    require_token
    for d in "${DOMAINS[@]}"; do
        update_record "$d" "$FI_IP"
    done
    log "=== Promote to FI Complete ==="
}

cmd_demote_fi() {
    log "=== Demoting DNS to Primary Node NL (${NL_IP}) ==="
    require_token
    for d in "${DOMAINS[@]}"; do
        update_record "$d" "$NL_IP"
    done
    log "=== Demote to NL Complete ==="
}

usage() {
    echo "Usage: $0 {promote-fi|demote-fi|status|health}"
    echo ""
    echo "Commands:"
    echo "  promote-fi  Switch A records for ${DOMAIN_MAIN}, sub, edge to FI IP (${FI_IP})"
    echo "  demote-fi   Switch A records back to NL IP (${NL_IP})"
    echo "  status      Query and show current Cloudflare A records"
    echo "  health      Perform DNS and connectivity health checks"
    exit 1
}

case "${1:-}" in
    promote-fi)
        cmd_promote_fi
        ;;
    demote-fi)
        cmd_demote_fi
        ;;
    status)
        cmd_status
        ;;
    health)
        cmd_status
        ;;
    *)
        usage
        ;;
esac
