import os
import urllib.request
import subprocess
import json

fi_ip = os.environ.get("FI_STANDBY_IP", "198.51.100.1")
secret_segment = os.environ.get("SECRET_SEGMENT", "my-secret-sub")  # PLACEHOLDER

print("1. Testing SubJSON /healthz on NL...")
try:
    r1 = urllib.request.urlopen("http://127.0.0.1:8000/healthz", timeout=5).read().decode()
    print("NL Healthz:", r1)
except Exception as e:
    print("NL Healthz error:", e)

print("\n2. Testing SubJSON /healthz on FI...")
r2 = subprocess.run(["ssh", "-o", "StrictHostKeyChecking=no", f"root@{fi_ip}", "curl -s http://127.0.0.1:3088/healthz"], capture_output=True, text=True)
print("FI Healthz:", r2.stdout.strip())

print("\n3. Testing Quiesce status on NL...")
try:
    r3 = urllib.request.urlopen(f"http://127.0.0.1:8000/{secret_segment}/internal-quiesce?action=status", timeout=5).read().decode()
    print("NL Quiesce status:", r3)
except Exception as e:
    print("NL Quiesce error:", e)

print("\n4. Testing Quiesce status on FI...")
r4 = subprocess.run(["ssh", "-o", "StrictHostKeyChecking=no", f"root@{fi_ip}", f"curl -s http://127.0.0.1:3088/{secret_segment}/internal-quiesce?action=status"], capture_output=True, text=True)
print("FI Quiesce status:", r4.stdout.strip())

print("\n5. Testing Bot catalog & Store schema on NL...")
r5 = subprocess.run(["python3", "-m", "vpn_shop", "--env-file", ".env", "catalog"], cwd="/root/vpn-shop", capture_output=True, text=True)
print("Catalog Exit:", r5.returncode)
print("Catalog Output:\n", r5.stdout.strip())

print("\n6. Testing AmneziaWG Multi-Server peers on NL & FI...")
r6 = subprocess.run(["python3", "-c", """
import sys
sys.path.insert(0, "/root/vpn-shop")
from vpn_shop import awg_manager
nl_peers = awg_manager.peer_transfer("nl")
fi_peers = awg_manager.peer_transfer("fi")
print(f"NL active AWG peers: {len(nl_peers)}")
print(f"FI active AWG peers: {len(fi_peers)}")
"""], cwd="/root/vpn-shop", capture_output=True, text=True)
print("AWG Transfer Exit:", r6.returncode)
print("AWG Transfer Output:\n", r6.stdout.strip())
if r6.stderr:
    print("AWG Transfer Error:\n", r6.stderr.strip())

print("\n7. Testing Cloudflare DNS Script syntax & dry-run on NL...")
r7 = subprocess.run(["/usr/local/bin/cf-failover-dns.sh", "help"], capture_output=True, text=True)
print("CF Script Exit:", r7.returncode)
print("CF Script Output:\n", r7.stdout.strip() or r7.stderr.strip())

print("\n8. Testing Disaster Recovery Script syntax on FI...")
r8 = subprocess.run(["ssh", "-o", "StrictHostKeyChecking=no", f"root@{fi_ip}", "bash -n /usr/local/bin/promote_fi.sh && bash -n /usr/local/bin/demote_fi.sh && echo 'FI FAILOVER SCRIPTS SYNTAX OK'"], capture_output=True, text=True)
print("FI Scripts Exit:", r8.returncode)
print("FI Scripts Output:\n", r8.stdout.strip())
