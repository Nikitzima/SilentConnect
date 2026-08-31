#!/usr/bin/env python3
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import remote_exec as re

audit_cmd = """
echo '===================== SECTION 1: SYSTEMD SERVICES ====================='
systemctl status caddy x-ui xray-maxru subjson vpn-shop-silentconnect vpn-shop-web litestream --no-pager

echo '===================== SECTION 2: DOCKER CONTAINERS ====================='
docker ps -a --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
docker exec amnezia-awg2 awg show 2>&1

echo '===================== SECTION 3: LISTENING PORTS (ss -tulpn) ====================='
ss -tulpn

echo '===================== SECTION 4: LITESTREAM CONFIG & JOURNAL ====================='
cat /etc/litestream.yml
echo '--- Journal logs (last 50 lines) ---'
journalctl -u litestream -n 50 --no-pager

echo '===================== SECTION 5: CADDY CONFIG & VALIDATION ====================='
cat /etc/caddy/Caddyfile
caddy validate --config /etc/caddy/Caddyfile

echo '===================== SECTION 6: LOCAL ENDPOINTS & QUIESCE TEST ====================='
echo '--- Web Checkout 3090 ---'
curl -Is http://127.0.0.1:3090

echo '--- SubJSON Healthz 3088 ---'
curl -s http://127.0.0.1:3088/healthz
echo ''

echo '--- SubJSON Quiesce Protocol Test ---'
SECRET_SEG=$(grep -E '^SECRET_SEGMENT=' /root/subjson-service/subjson.env 2>/dev/null | cut -d= -f2- | tr -d '"' || echo 'my-secret-sub')
if [ -z "$SECRET_SEG" ]; then SECRET_SEG="my-secret-sub"; fi
INT_SEC=$(grep -E '^INTERNAL_SECRET=' /root/subjson-service/subjson.env 2>/dev/null | cut -d= -f2- | tr -d '"' || echo '')
echo "Testing with SECRET_SEG=${SECRET_SEG}"

echo '1. Start Quiesce:'
curl -s -X POST "http://127.0.0.1:3088/${SECRET_SEG}/internal-quiesce/start" -H "X-Internal-Secret: ${INT_SEC}"
echo ''

echo '2. Lease Heartbeat:'
curl -s -X POST "http://127.0.0.1:3088/${SECRET_SEG}/internal-quiesce/lease" -H "X-Internal-Secret: ${INT_SEC}"
echo ''

echo '3. Release Quiesce:'
curl -s -X POST "http://127.0.0.1:3088/${SECRET_SEG}/internal-quiesce/release" -H "X-Internal-Secret: ${INT_SEC}"
echo ''

echo '===================== SECTION 7: FAILOVER ASSETS & SCRIPTS ====================='
ls -la /usr/local/bin/cf-failover-dns.sh /usr/local/bin/failback_merge.py /usr/local/bin/promote_fi.sh /usr/local/bin/demote_fi.sh

echo '--- Syntax checks ---'
bash -n /usr/local/bin/cf-failover-dns.sh && echo 'cf-failover-dns.sh: SYNTAX OK'
python3 -m py_compile /usr/local/bin/failback_merge.py && echo 'failback_merge.py: SYNTAX OK'
bash -n /usr/local/bin/promote_fi.sh && echo 'promote_fi.sh: SYNTAX OK'
bash -n /usr/local/bin/demote_fi.sh && echo 'demote_fi.sh: SYNTAX OK'

echo '--- Cloudflare DNS Status Check (DNS-Only Verification) ---'
/usr/local/bin/cf-failover-dns.sh status 2>&1
"""

def main():
    code, out, err = re.run_cmd('nl', audit_cmd, timeout=120)
    out_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.agents', 'explorer_nl_v7', 'raw_audit_output.txt')
    with open(out_file, 'w', encoding='utf-8') as f:
        f.write(f"=== RETURN CODE === {code}\n")
        f.write("=== STDOUT ===\n")
        f.write(out)
        if err:
            f.write("\n=== STDERR ===\n")
            f.write(err)
    print(f"Audit output written to {out_file} (exit={code})")

if __name__ == '__main__':
    main()
