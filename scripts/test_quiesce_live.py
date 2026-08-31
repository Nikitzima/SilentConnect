import os
import sys
import json
import urllib.request
import urllib.error

env_lines = open("/root/subjson-service/subjson.env").read().splitlines()
env = dict(line.split("=", 1) for line in env_lines if "=" in line and not line.startswith("#"))
secret_seg = env.get("SECRET_SEGMENT", "my-secret-sub").strip("/")
internal_sec = env.get("INTERNAL_SECRET", "").strip()

base_url = f"http://127.0.0.1:3088/{secret_seg}/internal-quiesce"

# 1. Test unauthorized request
req = urllib.request.Request(f"{base_url}/start", method="POST")
try:
    urllib.request.urlopen(req)
    print("FAIL: unauthorized start succeeded")
    sys.exit(1)
except urllib.error.HTTPError as e:
    assert e.code == 403
    print("1. Auth check (no secret): 403 FORBIDDEN - PASS")

# 2. Test start quiesce
req = urllib.request.Request(f"{base_url}/start", method="POST", headers={"X-Internal-Secret": internal_sec})
with urllib.request.urlopen(req) as resp:
    data = json.loads(resp.read().decode())
    assert data.get("status") == "QUIESCED_ACK", f"Unexpected status: {data}"
    assert data.get("lease_ttl") == 30.0, f"Unexpected lease_ttl: {data}"
    print("2. Quiesce start: QUIESCED_ACK (lease 30s) - PASS")

# 3. Test renew lease
req = urllib.request.Request(f"{base_url}/lease", method="POST", headers={"X-Internal-Secret": internal_sec})
with urllib.request.urlopen(req) as resp:
    data = json.loads(resp.read().decode())
    assert data.get("status") == "QUIESCED_ACK", f"Unexpected status: {data}"
    assert data.get("lease_extended") is True, f"Unexpected lease_extended: {data}"
    print("3. Quiesce renew lease: QUIESCED_ACK (extended) - PASS")

# 4. Test release quiesce
req = urllib.request.Request(f"{base_url}/release", method="POST", headers={"X-Internal-Secret": internal_sec})
with urllib.request.urlopen(req) as resp:
    data = json.loads(resp.read().decode())
    assert data.get("status") == "UNQUIESCED_ACK", f"Unexpected status: {data}"
    assert data.get("quiesce_released") is True, f"Unexpected quiesce_released: {data}"
    print("4. Quiesce release: UNQUIESCED_ACK - PASS")

print("ALL QUIESCE TESTS PASSED EMPIRICALLY!")
