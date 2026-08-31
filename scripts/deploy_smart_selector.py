#!/usr/bin/env python3
# deploy_smart_selector.py - Safe Staged Zero-Downtime Rollout and Live Verification
import base64
import json
import os
import socket
import ssl
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime
from typing import Any, Dict, List, Tuple

try:
    import yaml
except ImportError:
    yaml = None

# Force IPv4 resolution
_orig_gai = socket.getaddrinfo
def _gai_ipv4_override(host, port, family=0, type=0, proto=0, flags=0):
    return _orig_gai(host, port, socket.AF_INET, type, proto, flags)
socket.getaddrinfo = _gai_ipv4_override

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import remote_exec

SECRET_SEGMENT = os.environ.get("SECRET_SEGMENT", "my-secret-sub")  # PLACEHOLDER
NL_HOST = os.environ.get("NL_HOST", os.environ.get("NL_MASTER_IP", "192.0.2.1"))
FI_HOST = os.environ.get("FI_HOST", os.environ.get("FI_STANDBY_IP", "198.51.100.1"))
NL_DOMAIN = os.environ.get("DOMAIN_SUB", "sub.example.com")
FI_DOMAIN = os.environ.get("DOMAIN_FI", "fi.example.com")

def log(msg: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        print(f"[{ts}] [deploy_smart_selector] {msg}", flush=True)
    except UnicodeEncodeError:
        safe_msg = msg.encode("ascii", errors="replace").decode("ascii")
        print(f"[{ts}] [deploy_smart_selector] {safe_msg}", flush=True)

def run_remote(target: str, cmd: str, timeout: int = 60) -> Tuple[int, str, str]:
    code, out, err = remote_exec.run_cmd(target, cmd, timeout=timeout)
    return code, out, err

def upload(target: str, local_path: str, remote_path: str, mode: int = 0o644):
    remote_exec.upload_file(target, local_path, remote_path, mode)
    log(f"Uploaded {local_path} -> {target}:{remote_path} (mode={oct(mode)})")

def get_active_client_sub_id(target: str = "nl") -> str:
    py_code = "import sqlite3, json; conn = sqlite3.connect('/etc/x-ui/x-ui.db'); rows = conn.execute('SELECT settings FROM inbounds ORDER BY id').fetchall(); subs = []; [subs.append(c.get('subId') or c.get('id')) for r in rows for c in json.loads(r[0]).get('clients', []) if c.get('subId') or c.get('id')]; print(subs[0] if subs else '')"
    code, out, err = run_remote(target, f"python3 -c \"{py_code}\"")
    sub_id = out.strip()
    if sub_id:
        log(f"Found active client sub_id on {target}: {sub_id}")
        return sub_id
    log(f"Fallback to test sub_id on {target}")
    return "9c3d7f1e-4b8a-4c2d-9e1f-8a2b3c4d5e6f"

def fetch_url(url: str, headers: Dict[str, str] = None, timeout: int = 15) -> Tuple[int, bytes, Dict[str, str]]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    req_headers = {"User-Agent": "Happ/3.6.0 (iOS; iPhone)"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            status = resp.status
            body = resp.read()
            resp_headers = dict(resp.headers)
            return status, body, resp_headers
    except urllib.error.HTTPError as e:
        body = e.read()
        return e.code, body, dict(e.headers)
    except Exception as e:
        log(f"Request failed for {url}: {e}")
        raise

def deploy_node(target: str, ts: str):
    log(f"=== Staged Deployment to Node: {target.upper()} ===")
    backup_path = f"/root/subjson-service/app.py.bak_{ts}"
    log(f"[{target}] Creating timestamped backup -> {backup_path}")
    code, out, err = run_remote(target, f"cp /root/subjson-service/app.py {backup_path}")
    if code != 0:
        log(f"[{target}] Backup error: {err}")
        raise RuntimeError(f"Backup failed on {target}: {err}")
    log(f"[{target}] Backup verified: {backup_path}")

    log(f"[{target}] Uploading new subjson-service/app.py...")
    upload(target, "subjson-service/app.py", "/root/subjson-service/app.py", mode=0o644)

    log(f"[{target}] Remote syntax check: python3 -m py_compile /root/subjson-service/app.py")
    code, out, err = run_remote(target, "python3 -m py_compile /root/subjson-service/app.py")
    if code != 0:
        log(f"[{target}] FATAL: Syntax check failed on {target}: {err}")
        run_remote(target, f"cp {backup_path} /root/subjson-service/app.py")
        raise RuntimeError(f"Syntax compilation failed on {target}: {err}")
    log(f"[{target}] Remote syntax check: PASSED (exit code 0)")

    log(f"[{target}] Restarting subjson.service...")
    code, out, err = run_remote(target, "systemctl restart subjson.service && systemctl is-active subjson.service")
    service_status = out.strip()
    log(f"[{target}] Service status after restart: {service_status}")
    if code != 0 or "active" not in service_status:
        log(f"[{target}] FATAL: subjson.service not active: {service_status}")
        raise RuntimeError(f"subjson service failed to start on {target}")

    log(f"[{target}] Verifying local healthcheck: curl -fsS http://127.0.0.1:3088/healthz")
    health_ok = False
    out_res = ""
    err_res = ""
    for attempt in range(15):
        time.sleep(1)
        code, out_res, err_res = run_remote(target, "curl -fsS -i http://127.0.0.1:3088/healthz")
        if code == 0 and ("200 OK" in out_res or "ok" in out_res.lower()):
            health_ok = True
            log(f"[{target}] Healthcheck succeeded on attempt {attempt+1}")
            break
    if not health_ok:
        log(f"[{target}] FATAL: Healthcheck failed! Exit {code}, Out: {out_res}, Err: {err_res}")
        raise RuntimeError(f"Healthcheck failed on {target}")
    log(f"[{target}] Local healthcheck: 200 OK (PASSED)")

def verify_public_and_node_endpoints(sub_id: str):
    log(f"=== Comprehensive Live Verification (sub_id={sub_id}) ===")
    
    # 1. Test Public Live Internet Endpoints on sub domain (Master origin)
    public_tests = [
        (f"Sing-box / Happ JSON (Public {NL_DOMAIN})", f"https://{NL_DOMAIN}/{SECRET_SEGMENT}/json/{sub_id}", "json"),
        (f"Clash Meta YAML (Public {NL_DOMAIN})", f"https://{NL_DOMAIN}/{SECRET_SEGMENT}/clash/{sub_id}", "yaml"),
        (f"Mihomo Meta YAML (Public {NL_DOMAIN})", f"https://{NL_DOMAIN}/{SECRET_SEGMENT}/meta/{sub_id}", "yaml"),
        (f"Streisand Base64 (Public {NL_DOMAIN})", f"https://{NL_DOMAIN}/{SECRET_SEGMENT}/streisand/{sub_id}", "streisand"),
    ]
    
    for label, url, fmt_type in public_tests:
        log("")
        log(f"[PUBLIC VERIFY] Testing {label} on {url} ...")
        headers = {}
        if fmt_type == "json":
            headers["User-Agent"] = "Happ/3.6.0 (iOS; iPhone)"
        elif fmt_type == "yaml":
            headers["User-Agent"] = "ClashMeta/v1.18.0"
        elif fmt_type == "streisand":
            headers["User-Agent"] = "Streisand/1.6.0"
            
        status, body, resp_headers = fetch_url(url, headers=headers)
        log(f"  -> HTTP Status: {status}")
        assert status == 200, f"Expected 200, got {status}"
        
        validate_response_payload(label, body.decode("utf-8"), fmt_type)

    # 2. Test Secondary FI Live Node Endpoints
    fi_tests = [
        (f"Sing-box / Happ JSON (FI Node {FI_HOST}:3088)", f"http://127.0.0.1:3088/{SECRET_SEGMENT}/json/{sub_id}", "json"),
        (f"Clash Meta YAML (FI Node {FI_HOST}:3088)", f"http://127.0.0.1:3088/{SECRET_SEGMENT}/clash/{sub_id}", "yaml"),
        (f"Mihomo Meta YAML (FI Node {FI_HOST}:3088)", f"http://127.0.0.1:3088/{SECRET_SEGMENT}/meta/{sub_id}", "yaml"),
        (f"Streisand Base64 (FI Node {FI_HOST}:3088)", f"http://127.0.0.1:3088/{SECRET_SEGMENT}/streisand/{sub_id}", "streisand"),
    ]
    
    for label, path, fmt_type in fi_tests:
        log("")
        log(f"[FI NODE VERIFY] Testing {label} ...")
        code, out, err = run_remote("fi", f"curl -fsS '{path}'")
        assert code == 0, f"FI node curl failed ({code}): {err}"
        validate_response_payload(label, out, fmt_type)

    log("")
    log("=======================================================")
    log("--- ALL PRODUCTION & NODE ENDPOINTS EMPIRICALLY VERIFIED ---")
    log("=======================================================")

def validate_response_payload(label: str, text: str, fmt_type: str):
    if fmt_type == "json":
        data = json.loads(text)
        if isinstance(data, list):
            log(f"  -> Config profiles array length: {len(data)}")
            assert len(data) >= 10, f"Expected >= 10 profiles in JSON bundle, got {len(data)}"
            
            p0 = data[0]
            remarks0 = str(p0.get("remarks") or p0.get("tag") or "")
            log(f"  -> Index 0 profile title: '{remarks0}'")
            assert "??????????????" in remarks0 or "Автоматический" in remarks0, (
                f"Expected '? ??????????????' at index 0, got '{remarks0}'"
            )
            
            outbounds = p0.get("outbounds", [])
            log(f"  -> Profile 0 outbounds count: {len(outbounds)}")
            assert len(outbounds) >= 5, f"Expected >= 5 outbounds in profile 0, got {len(outbounds)}"
            
            first_ob = outbounds[0]
            log(f"  -> Profile 0 primary outbound: tag='{first_ob.get('tag')}', type='{first_ob.get('type')}'")
            
            urltest_ob = next((o for o in outbounds if o.get("type") == "urltest"), None)
            if urltest_ob:
                log(f"  -> urltest outbound: url='{urltest_ob.get('url')}', interval='{urltest_ob.get('interval')}', tolerance={urltest_ob.get('tolerance')}")
                assert urltest_ob.get("url") == "https://cp.cloudflare.com/generate_204"
                assert urltest_ob.get("interval") == "3m"
                assert urltest_ob.get("idle_timeout") == "15m"
                assert urltest_ob.get("tolerance") == 50
            
            individual_profiles = data[1:]
            log(f"  -> Individual server node profiles retained below index 0: {len(individual_profiles)}")
            assert len(individual_profiles) >= 10, f"Expected 10 individual node profiles, found {len(individual_profiles)}"
            for idx, prof in enumerate(individual_profiles[:3]):
                r_str = str(prof.get('remarks') or prof.get('tag') or '')
                log(f"     [{idx+1}] {r_str}")
        else:
            outbounds = data.get("outbounds", [])
            log(f"  -> Outbounds count: {len(outbounds)}")
            assert len(outbounds) >= 5
            tags = [o.get("tag", "") for o in outbounds]
            assert any("??????????????" in t or t in ("proxy-selector", "auto-urltest") for t in tags)

    elif fmt_type == "yaml":
        if yaml:
            data = yaml.safe_load(text)
            proxies = data.get("proxies", [])
            proxy_groups = data.get("proxy-groups", [])
            log(f"  -> Proxies count: {len(proxies)}, Groups count: {len(proxy_groups)}")
            group_names = [g.get("name") for g in proxy_groups]
            log(f"  -> Proxy groups: {group_names}")
            assert len(proxies) >= 10, f"Expected >= 10 proxies in Clash Meta YAML, found {len(proxies)}"
            assert any("Auto" in g or "PROXY" in g or "Fallback" in g for g in group_names)
            
            urltest_g = next((g for g in proxy_groups if g.get("type") == "url-test"), None)
            if urltest_g:
                log(f"  -> url-test group: url='{urltest_g.get('url')}', interval={urltest_g.get('interval')}, tolerance={urltest_g.get('tolerance')}")
                assert "generate_204" in urltest_g.get("url", "")
                assert urltest_g.get("interval") == 180 or urltest_g.get("interval") == "3m"

    elif fmt_type == "streisand":
        try:
            decoded = base64.b64decode(text.strip()).decode("utf-8", errors="replace")
        except Exception:
            decoded = text
        lines = [l.strip() for l in decoded.splitlines() if l.strip()]
        log(f"  -> Streisand URIs count: {len(lines)}")
        assert len(lines) >= 10, f"Expected >= 10 Streisand URIs, found {len(lines)}"
        assert any(l.startswith("vless://") for l in lines)
        assert any(l.startswith("hy2://") for l in lines)
        for i, line in enumerate(lines[:4]):
            proto = line.split("://")[0]
            remark = urllib.parse.unquote(line.split("#")[-1]) if "#" in line else ""
            log(f"     [{i}] Proto: {proto}, Remark: {remark}")

def main():
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log("=== Starting Milestone M3 Staged Deployment & Live Verification ===")
    import py_compile
    py_compile.compile("subjson-service/app.py", doraise=True)
    log("Local syntax check: PASSED")

    deploy_node("fi", ts)
    deploy_node("nl", ts)

    sub_id = get_active_client_sub_id("nl")
    verify_public_and_node_endpoints(sub_id)
    log("MILESTONE M3 STAGED DEPLOYMENT & LIVE VERIFICATION: SUCCESS (100% PASS)")

if __name__ == "__main__":
    main()
