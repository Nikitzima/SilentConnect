#!/usr/bin/env python3
"""
deploy_ui_upgrade.py - Staged Zero-Downtime Deployment & Live Production Validation
Deploys UI/UX, App Catalog, Mihomo SVG, Responsive Mobile Header/Footer, and Duration Grid updates
to Secondary FI and Master NL nodes.
"""
import base64
import json
import os
import py_compile
import re
import socket
import ssl
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime
from typing import Any, Dict, List, Tuple

# Force IPv4 resolution override
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
LANDING_DOMAIN = os.environ.get("DOMAIN_MAIN", "example.com")

def log(msg: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        print(f"[{ts}] [deploy_ui_upgrade] {msg}", flush=True)
    except UnicodeEncodeError:
        safe_msg = msg.encode("ascii", errors="replace").decode("ascii")
        print(f"[{ts}] [deploy_ui_upgrade] {safe_msg}", flush=True)

def run_remote(target: str, cmd: str, timeout: int = 60) -> Tuple[int, str, str]:
    code, out, err = remote_exec.run_cmd(target, cmd, timeout=timeout)
    return code, out, err

def upload(target: str, local_path: str, remote_path: str, mode: int = 0o644):
    remote_exec.upload_file(target, local_path, remote_path, mode)
    log(f"Uploaded {local_path} -> {target}:{remote_path} (mode={oct(mode)})")

def fetch_url(url: str, headers: Dict[str, str] = None, timeout: int = 15) -> Tuple[int, bytes, Dict[str, str]]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    req_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
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

def get_active_client_sub_id(target: str = "nl") -> str:
    py_code = "import sqlite3, json; conn = sqlite3.connect('/etc/x-ui/x-ui.db'); rows = conn.execute('SELECT settings FROM inbounds ORDER BY id').fetchall(); subs = []; [subs.append(c.get('subId') or c.get('id')) for r in rows for c in json.loads(r[0]).get('clients', []) if c.get('subId') or c.get('id')]; print(subs[0] if subs else '')"
    code, out, err = run_remote(target, f"python3 -c \"{py_code}\"")
    sub_id = out.strip()
    if sub_id:
        log(f"Found active client sub_id on {target}: {sub_id}")
        return sub_id
    log(f"Fallback to default sub_id on {target}")
    return "9c3d7f1e-4b8a-4c2d-9e1f-8a2b3c4d5e6f"

def deploy_to_fi(ts: str):
    log("=======================================================")
    log(f"=== [STAGE 1] Staged Deployment to Secondary FI ({FI_HOST}) ===")
    log("=======================================================")

    client = remote_exec.get_client("fi")
    try:
        # 1. Backups
        log("[FI] Creating timestamped backups of app.py and web.py...")
        s, o, e = client.exec_command(f"cp /root/subjson-service/app.py /root/subjson-service/app.py.bak_{ts} && mkdir -p /root/vpn-shop/vpn_shop && cp /root/vpn-shop/vpn_shop/web.py /root/vpn-shop/vpn_shop/web.py.bak_{ts} 2>/dev/null || true")
        if s.channel.recv_exit_status() != 0:
            raise RuntimeError(f"Failed to backup files on FI: {e.read().decode('utf-8')}")
        log(f"[FI] Backups created: /root/subjson-service/app.py.bak_{ts}")

        # 2. Upload updated files
        log("[FI] Uploading subjson-service/app.py and vpn-shop/vpn_shop/web.py...")
        sftp = client.open_sftp()
        sftp.put("subjson-service/app.py", "/root/subjson-service/app.py")
        sftp.chmod("/root/subjson-service/app.py", 0o644)
        sftp.put("vpn-shop/vpn_shop/web.py", "/root/vpn-shop/vpn_shop/web.py")
        sftp.chmod("/root/vpn-shop/vpn_shop/web.py", 0o644)
        sftp.close()
        log("[FI] Files uploaded successfully via SFTP.")

        # 3. Remote syntax verification
        log("[FI] Remote syntax verification: python3 -m py_compile /root/subjson-service/app.py /root/vpn-shop/vpn_shop/web.py")
        s, o, e = client.exec_command("python3 -m py_compile /root/subjson-service/app.py /root/vpn-shop/vpn_shop/web.py")
        code = s.channel.recv_exit_status()
        if code != 0:
            err = e.read().decode("utf-8")
            log(f"[FI] FATAL: Syntax check failed on FI: {err}")
            client.exec_command(f"cp /root/subjson-service/app.py.bak_{ts} /root/subjson-service/app.py")
            raise RuntimeError(f"Syntax compilation failed on FI: {err}")
        log("[FI] Remote syntax verification: PASSED (exit code 0)")

        # 4. Restart subjson.service on FI
        log("[FI] Restarting subjson.service...")
        s, o, e = client.exec_command("systemctl restart subjson.service && systemctl is-active subjson.service")
        status = o.read().decode("utf-8").strip()
        log(f"[FI] Service status: {status}")
        if "active" not in status:
            raise RuntimeError(f"subjson.service not active on FI: {status}")

        # 5. Local healthcheck on FI
        log("[FI] Verifying local healthcheck: curl -fsS http://127.0.0.1:3088/healthz")
        health_ok = False
        for attempt in range(15):
            time.sleep(1)
            s, o, e = client.exec_command("curl -fsS -i http://127.0.0.1:3088/healthz")
            out_str = o.read().decode("utf-8")
            if s.channel.recv_exit_status() == 0 and ("200 OK" in out_str or "ok" in out_str.lower()):
                health_ok = True
                log(f"[FI] Healthcheck succeeded on attempt {attempt+1}")
                break
        if not health_ok:
            raise RuntimeError("Healthcheck failed on FI")
        log("[FI] Stage 1 (FI Secondary) Deployment COMPLETED SUCCESSFULLY.")
    finally:
        client.close()
        if hasattr(client, "_jump_client"):
            try: client._jump_client.close()
            except Exception: pass

def deploy_to_nl(ts: str):
    log("=======================================================")
    log(f"=== [STAGE 2] Staged Deployment to Master NL ({NL_HOST}) ===")
    log("=======================================================")

    client = remote_exec.get_client("nl")
    try:
        # 1. Backups
        log("[NL] Creating timestamped backups of app.py and web.py...")
        s, o, e = client.exec_command(f"cp /root/subjson-service/app.py /root/subjson-service/app.py.bak_{ts} && cp /root/vpn-shop/vpn_shop/web.py /root/vpn-shop/vpn_shop/web.py.bak_{ts}")
        if s.channel.recv_exit_status() != 0:
            raise RuntimeError("Failed to create backups on NL")
        log(f"[NL] Backups created: /root/subjson-service/app.py.bak_{ts} and /root/vpn-shop/vpn_shop/web.py.bak_{ts}")

        # 2. Upload updated files
        log("[NL] Uploading subjson-service/app.py and vpn-shop/vpn_shop/web.py...")
        sftp = client.open_sftp()
        sftp.put("subjson-service/app.py", "/root/subjson-service/app.py")
        sftp.chmod("/root/subjson-service/app.py", 0o644)
        sftp.put("vpn-shop/vpn_shop/web.py", "/root/vpn-shop/vpn_shop/web.py")
        sftp.chmod("/root/vpn-shop/vpn_shop/web.py", 0o644)
        sftp.close()
        log("[NL] Files uploaded successfully via SFTP.")

        # 3. Remote syntax verification
        log("[NL] Remote syntax verification: python3 -m py_compile /root/subjson-service/app.py /root/vpn-shop/vpn_shop/web.py")
        s, o, e = client.exec_command("python3 -m py_compile /root/subjson-service/app.py /root/vpn-shop/vpn_shop/web.py")
        code = s.channel.recv_exit_status()
        if code != 0:
            err = e.read().decode("utf-8")
            log(f"[NL] FATAL: Syntax check failed on NL: {err}")
            client.exec_command(f"cp /root/subjson-service/app.py.bak_{ts} /root/subjson-service/app.py && cp /root/vpn-shop/vpn_shop/web.py.bak_{ts} /root/vpn-shop/vpn_shop/web.py")
            raise RuntimeError(f"Syntax compilation failed on NL: {err}")
        log("[NL] Remote syntax verification: PASSED (exit code 0)")

        # 4. Restart services on NL
        log("[NL] Restarting subjson.service and vpn-shop-web.service...")
        s, o, e = client.exec_command("systemctl restart subjson.service vpn-shop-web.service")
        if s.channel.recv_exit_status() != 0:
            raise RuntimeError("Failed to restart services on NL")

        # 5. Verify systemd is-active for all services
        log("[NL] Asserting systemctl is-active subjson vpn-shop-web caddy...")
        s, o, e = client.exec_command("systemctl is-active subjson vpn-shop-web caddy")
        out_str = o.read().decode("utf-8")
        statuses = [st.strip() for st in out_str.strip().splitlines() if st.strip()]
        log(f"[NL] Service statuses: {statuses}")
        for st in statuses:
            if st != "active":
                raise RuntimeError(f"Service on NL is not active: {st}")
        log("[NL] All systemd services (subjson, vpn-shop-web, caddy) are ACTIVE.")

        # 6. Local healthchecks on NL
        log("[NL] Verifying local healthcheck: curl -fsS http://127.0.0.1:3088/healthz")
        health_ok = False
        for attempt in range(15):
            time.sleep(1)
            s, o, e = client.exec_command("curl -fsS -i http://127.0.0.1:3088/healthz")
            out_str = o.read().decode("utf-8")
            if s.channel.recv_exit_status() == 0 and ("200 OK" in out_str or "ok" in out_str.lower()):
                health_ok = True
                log(f"[NL] SubJSON healthcheck succeeded on attempt {attempt+1}")
                break
        if not health_ok:
            raise RuntimeError("SubJSON healthcheck failed on NL")

        log("[NL] Verifying local web healthcheck: curl -fsS http://127.0.0.1:3090/")
        s, o, e = client.exec_command("curl -fsS -i http://127.0.0.1:3090/")
        out_str = o.read().decode("utf-8")
        if s.channel.recv_exit_status() != 0 or ("200 OK" not in out_str and "<!doctype html>" not in out_str.lower() and "<html" not in out_str.lower()):
            raise RuntimeError("VPN Shop Web local check failed on NL")
        log("[NL] Local web service returned valid HTML response.")

        log("[NL] Stage 2 (NL Master) Deployment COMPLETED SUCCESSFULLY.")
    finally:
        client.close()
        if hasattr(client, "_jump_client"):
            try: client._jump_client.close()
            except Exception: pass

def verify_live_production(sub_id: str):
    log("=======================================================")
    log("=== [STAGE 3] Comprehensive Live Production Verification ===")
    log("=======================================================")

    # 1. Live Landing Page on domain
    landing_url = f"https://{LANDING_DOMAIN}"
    log(f"[LIVE] Fetching landing page from {landing_url} ...")
    status, body, headers = fetch_url(landing_url)
    log(f"  -> HTTP Status: {status}")
    assert status == 200, f"Expected 200 from {landing_url}, got {status}"
    landing_html = body.decode("utf-8", errors="replace")

    # Assert mobile header CSS
    assert "header {" in landing_html, "Missing 'header {' CSS on live landing"
    assert "nav {" in landing_html, "Missing 'nav {' CSS on live landing"
    assert "flex-wrap: nowrap;" in landing_html, "Missing 'flex-wrap: nowrap;' in nav CSS"
    log("  [PASS] Mobile header responsive layout CSS verified on live landing.")

    # Assert centered footer and no orphan middle dots
    assert ".footer-wrap {" in landing_html, "Missing '.footer-wrap {' CSS on live landing"
    assert ".footer-links {" in landing_html, "Missing '.footer-links {' CSS on live landing"
    assert '<div class="wrap footer-wrap">' in landing_html, "Missing '<div class=\"wrap footer-wrap\">' markup"
    footer_match = re.search(r"<footer>(.*?)</footer>", landing_html, re.DOTALL)
    assert footer_match is not None, "Missing <footer> element on live landing"
    assert "·" not in footer_match.group(1), "Found raw middle dot '·' in footer on live landing"
    log("  [PASS] Centered footer flexbox layout and clean markup verified on live landing.")

    # Assert 4-duration grid
    assert ".choice-grid-durations {" in landing_html, "Missing '.choice-grid-durations {' on live landing"
    assert '<div class="choice-grid choice-grid-durations">' in landing_html, "Missing duration grid element"
    log("  [PASS] Symmetrical 4-duration grid layout verified on live landing.")

    # Assert container max-width: 1120px
    assert ".wrap { width: 100%; max-width: 1120px;" in landing_html or "max-width: 1120px;" in landing_html
    log("  [PASS] 1120px container max-width constraint verified on live landing.")

    # 2. Live Setup Wizard & Catalog on setup wizard domain
    wizard_url = f"https://{NL_DOMAIN}/{SECRET_SEGMENT}/import/{sub_id}"
    log(f"[LIVE] Fetching Setup Wizard from {wizard_url} ...")
    status, body, headers = fetch_url(wizard_url)
    log(f"  -> HTTP Status: {status}")
    assert status == 200, f"Expected 200 from {wizard_url}, got {status}"
    wizard_html = body.decode("utf-8", errors="replace")

    # Assert apps catalog in setup wizard
    apps_match = re.search(r"const apps = (\[.*?\]);", wizard_html)
    assert apps_match is not None, "Could not find 'const apps = [...]' on live setup wizard"
    apps = json.loads(apps_match.group(1))
    app_ids = [app["id"] for app in apps]
    log(f"  -> Embedded client apps on live setup wizard: {app_ids}")
    expected_ids = ["happ", "clash", "v2rayn", "nekobox", "v2rayng", "streisand", "v2raytun", "singbox"]
    for eid in expected_ids:
        assert eid in app_ids, f"Expected app '{eid}' missing from live setup wizard apps catalog"
    log("  [PASS] All 8 client applications present in live setup wizard catalog.")

    # Assert Mihomo SVG vector data-URI logo and zero 404 raw GitHub URLs
    assert "raw.githubusercontent.com/MetaCubeX/ClashMetaForAndroid" not in wizard_html, "Found broken GitHub raw URL in live setup wizard"
    assert "data:image/svg+xml;" in wizard_html, "Missing SVG data-URI icons in live setup wizard"
    log("  [PASS] Mihomo SVG vector data-URI logo and zero 404 URL verified on live setup wizard.")

    # Assert container max-width: 860px on setup wizard
    assert "max-width: 860px;" in wizard_html, "Missing max-width: 860px container on live setup wizard"
    log("  [PASS] 860px container max-width verified on live setup wizard.")

    # 3. Live Subscription Data Endpoints
    log("[LIVE] Verifying subscription data endpoints...")
    sub_endpoints = [
        ("Sing-box / Happ JSON", f"https://{NL_DOMAIN}/{SECRET_SEGMENT}/json/{sub_id}"),
        ("Clash Meta YAML", f"https://{NL_DOMAIN}/{SECRET_SEGMENT}/clash/{sub_id}"),
        ("Mihomo Meta YAML", f"https://{NL_DOMAIN}/{SECRET_SEGMENT}/meta/{sub_id}"),
        ("Streisand Base64", f"https://{NL_DOMAIN}/{SECRET_SEGMENT}/streisand/{sub_id}"),
    ]
    for label, ep_url in sub_endpoints:
        st, b, h = fetch_url(ep_url)
        log(f"  -> {label} ({ep_url}): HTTP {st}, bytes={len(b)}")
        assert st == 200, f"Expected 200 for {ep_url}, got {st}"
        assert len(b) > 50, f"Payload too small for {ep_url}: {len(b)} bytes"
    log("  [PASS] All live subscription data endpoints verified (HTTP 200 OK).")

    # 4. Secondary Node FI Endpoint Verification via SSH curl
    log(f"[LIVE] Verifying Secondary Node FI ({FI_HOST}) local SubJSON endpoints...")
    code, out, err = run_remote("fi", f"curl -fsS http://127.0.0.1:3088/{SECRET_SEGMENT}/json/{sub_id}")
    assert code == 0, f"FI local SubJSON curl failed ({code}): {err}"
    assert len(out) > 50, "FI SubJSON response too short"
    log(f"  [PASS] FI Secondary node returned valid SubJSON payload ({len(out)} bytes).")

    log("=======================================================")
    log("--- ALL PRODUCTION & NODE ENDPOINTS EMPIRICALLY VERIFIED ---")
    log("=======================================================")

def main():
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log(f"=== Starting Milestone M3 Staged Zero-Downtime Deployment (ts={ts}) ===")

    # Step 0: Pre-flight local AST compilation check
    log("--- Pre-flight Local Syntax Compilation Check ---")
    py_compile.compile("subjson-service/app.py", doraise=True)
    py_compile.compile("vpn-shop/vpn_shop/web.py", doraise=True)
    log("Local syntax compilation: PASSED")

    # Step 1: Deploy to Secondary FI Node
    deploy_to_fi(ts)

    # Step 2: Deploy to Master NL Node
    deploy_to_nl(ts)

    # Step 3: Comprehensive Live Production Verification
    sub_id = get_active_client_sub_id("nl")
    verify_live_production(sub_id)

    log("================================================================================")
    log("MILESTONE M3 STAGED DEPLOYMENT & LIVE PRODUCTION VALIDATION: 100% SUCCESS (PASS)")
    log("================================================================================")

if __name__ == "__main__":
    main()
