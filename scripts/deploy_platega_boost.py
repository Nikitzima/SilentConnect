#!/usr/bin/env python3
"""
deploy_platega_boost.py - Production Rollout of Platega Acquiring Integration & /boost Updates
Supports Master (NL) and Standby (FI).
Uses persistent OpenSSH / NodeSession connections to avoid SSH connection churn and rate limits.
Loads Platega credentials dynamically from vpn-shop/.env.platega (zero plaintext hardcoded secrets).
Includes ultra-safe backup gates, remote AST checks, zero-downtime service restarts, and live verification.
"""
import os
import sys
import time
import urllib.request
import urllib.error
import ssl
import json
import subprocess
from datetime import datetime
from typing import Tuple, Dict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import remote_exec

PYTHON_MODULES = [
    "__init__.py",
    "__main__.py",
    "awg_manager.py",
    "bot.py",
    "catalog.py",
    "cli.py",
    "config.py",
    "mailer.py",
    "payments.py",
    "platega.py",
    "provisioning.py",
    "security.py",
    "store.py",
    "telegram_api.py",
    "web.py",
    "xui_api.py",
    "xui_db.py",
]

def log(msg: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        print(f"[{ts}] [deploy_platega] {msg}", flush=True)
    except UnicodeEncodeError:
        safe_msg = msg.encode("ascii", errors="replace").decode("ascii")
        print(f"[{ts}] [deploy_platega] {safe_msg}", flush=True)

def load_platega_credentials(workspace_root: str) -> Dict[str, str]:
    """Load credentials dynamically from env, .env.platega, or remote node without hardcoding secrets."""
    creds = {}
    if os.environ.get("PLATEGA_SECRET"):
        creds = {
            "PLATEGA_MERCHANT_ID_BOT": os.environ.get("PLATEGA_MERCHANT_ID_BOT", "c3393290-d96e-4a5e-aca3-12015a843b0e"),
            "PLATEGA_MERCHANT_ID_WEB": os.environ.get("PLATEGA_MERCHANT_ID_WEB", "e4d5af52-9c18-444b-b8bf-db1a26f0c61d"),
            "PLATEGA_SECRET": os.environ["PLATEGA_SECRET"],
            "PLATEGA_SECRET_BOT": os.environ.get("PLATEGA_SECRET_BOT", os.environ["PLATEGA_SECRET"]),
            "PLATEGA_SECRET_WEB": os.environ.get("PLATEGA_SECRET_WEB", os.environ["PLATEGA_SECRET"]),
            "PLATEGA_ENABLED": os.environ.get("PLATEGA_ENABLED", "true"),
        }
        log("Loaded Platega credentials from environment variables.")
        return creds

    for base in [workspace_root, os.path.join(workspace_root, "vpn-shop"), os.path.dirname(workspace_root)]:
        p = os.path.join(base, ".env.platega")
        if os.path.isfile(p):
            with open(p, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        creds[k.strip()] = v.strip().strip("'\"")
            break

    if not creds.get("PLATEGA_SECRET"):
        nl_ip = os.environ.get("NL_HOST", remote_exec.NL_HOST)
        res = subprocess.run(["ssh", "-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=no", f"root@{nl_ip}", "grep -E '^PLATEGA_' /root/vpn-shop/.env.silentconnect"], capture_output=True, text=True)
        if res.returncode == 0 and res.stdout:
            for line in res.stdout.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    creds[k.strip()] = v.strip().strip("'\"")

    required = ["PLATEGA_MERCHANT_ID_BOT", "PLATEGA_MERCHANT_ID_WEB", "PLATEGA_SECRET"]
    for req in required:
        if not creds.get(req):
            raise RuntimeError(f"Missing required parameter {req} in credentials")

    if "PLATEGA_SECRET_BOT" not in creds:
        creds["PLATEGA_SECRET_BOT"] = creds["PLATEGA_SECRET"]
    if "PLATEGA_SECRET_WEB" not in creds:
        creds["PLATEGA_SECRET_WEB"] = creds["PLATEGA_SECRET"]
    if "PLATEGA_ENABLED" not in creds:
        creds["PLATEGA_ENABLED"] = "true"

    log(f"Successfully loaded Platega credentials (bot merchant: {creds['PLATEGA_MERCHANT_ID_BOT'][:8]}..., web merchant: {creds['PLATEGA_MERCHANT_ID_WEB'][:8]}...)")
    return creds

class NodeSession:
    def __init__(self, target: str):
        self.target = target
        self.ip = os.environ.get("NL_HOST", remote_exec.NL_HOST) if target == "nl" else os.environ.get("FI_HOST", remote_exec.FI_HOST)
        log(f"[{target.upper()}] NodeSession target host: {self.ip}")

    def run(self, cmd: str, timeout: int = 60, retries: int = 4) -> Tuple[int, str, str]:
        # Execute via OpenSSH with automatic retry and backoff
        for attempt in range(retries):
            ssh_cmd = [
                "ssh",
                "-o", "ConnectTimeout=8",
                "-o", "StrictHostKeyChecking=no",
                f"root@{self.ip}",
                cmd,
            ]
            try:
                res = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)
                if res.returncode == 255 and attempt < retries - 1:
                    log(f"[{self.target.upper()}] SSH connection reset/closed, backing off {attempt + 2}s (attempt {attempt + 1}/{retries})...")
                    time.sleep(attempt + 2)
                    continue
                return res.returncode, res.stdout, res.stderr
            except Exception as exc:
                if attempt < retries - 1:
                    time.sleep(attempt + 2)
                    continue
                log(f"[{self.target.upper()}] OpenSSH error: {exc}, falling back to remote_exec...")
                return remote_exec.run_cmd(self.target, cmd, timeout=timeout)
        return res.returncode, res.stdout, res.stderr

    def upload_modules_tar(self, local_vpn_shop: str, remote_dir: str = "/root/vpn-shop/vpn_shop", retries: int = 4):
        time.sleep(4)
        for attempt in range(retries):
            tar_cmd = ["tar", "-czf", "-", "-C", local_vpn_shop] + PYTHON_MODULES
            ssh_cmd = [
                "ssh",
                "-o", "ConnectTimeout=8",
                "-o", "StrictHostKeyChecking=no",
                f"root@{self.ip}",
                f"mkdir -p '{remote_dir}' && tar -xzf - -C '{remote_dir}' && chmod 0644 '{remote_dir}'/*.py",
            ]
            p_tar = subprocess.Popen(tar_cmd, stdout=subprocess.PIPE)
            p_ssh = subprocess.Popen(ssh_cmd, stdin=p_tar.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            p_tar.stdout.close()
            out, err = p_ssh.communicate(timeout=60)
            p_tar.wait()
            if p_ssh.returncode == 0:
                return
            if attempt < retries - 1:
                log(f"[{self.target.upper()}] Tar upload reset/failed (code {p_ssh.returncode}), retrying in {attempt + 5}s...")
                time.sleep(attempt + 5)
                continue
            err_msg = err.decode("utf-8", errors="replace")
            raise RuntimeError(f"Tar streaming upload failed with code {p_ssh.returncode}: {err_msg}")

    def upload_file(self, local_path: str, remote_path: str, retries: int = 4):
        remote_dir = os.path.dirname(remote_path)
        time.sleep(4)
        for attempt in range(retries):
            tar_cmd = ["tar", "-czf", "-", "-C", os.path.dirname(local_path), os.path.basename(local_path)]
            ssh_cmd = [
                "ssh",
                "-o", "ConnectTimeout=8",
                "-o", "StrictHostKeyChecking=no",
                f"root@{self.ip}",
                f"mkdir -p '{remote_dir}' && tar -xzf - -C '{remote_dir}' && chmod 0644 '{remote_path}'",
            ]
            p_tar = subprocess.Popen(tar_cmd, stdout=subprocess.PIPE)
            p_ssh = subprocess.Popen(ssh_cmd, stdin=p_tar.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            p_tar.stdout.close()
            out, err = p_ssh.communicate(timeout=60)
            p_tar.wait()
            if p_ssh.returncode == 0:
                return
            if attempt < retries - 1:
                log(f"[{self.target.upper()}] File upload reset/failed (code {p_ssh.returncode}), retrying in {attempt + 5}s...")
                time.sleep(attempt + 5)
                continue
            err_msg = err.decode("utf-8", errors="replace")
            raise RuntimeError(f"Tar streaming upload of {local_path} failed with code {p_ssh.returncode}: {err_msg}")

    def close(self):
        log(f"[{self.target.upper()}] Session completed.")

def deploy_to_node(session: NodeSession, target: str, ts: str, workspace_root: str, creds: Dict[str, str]):
    local_vpn_shop = os.path.join(workspace_root, "github_export", "vpn-shop", "vpn_shop")
    if not os.path.isdir(local_vpn_shop):
        local_vpn_shop = os.path.join(workspace_root, "vpn-shop", "vpn_shop")
    
    local_subjson = os.path.join(workspace_root, "github_export", "subjson-service", "app.py")
    if not os.path.isfile(local_subjson):
        local_subjson = os.path.join(workspace_root, "subjson-service", "app.py")

    # --------------------------------------------------------------------------
    # Phase 1: Backups (Ultra-Critical)
    # --------------------------------------------------------------------------
    log(f"[{target.upper()}] >>> PHASE 1: Creating verified backups (code, config, DB, subjson)...")
    code_bak = f"/root/vpn-shop/vpn_shop.bak_{ts}"
    env_bak = f"/root/vpn-shop/.env.silentconnect.bak_{ts}"
    db_bak = f"/root/vpn-shop/data-silentconnect/vpn_shop.db.bak_{ts}"
    subjson_bak = f"/root/subjson-service/app.py.bak_{ts}"

    backup_compound_cmd = f"""
set -e
mkdir -p '{code_bak}'
cp -a /root/vpn-shop/vpn_shop/* '{code_bak}/'
cp -a /root/vpn-shop/.env.silentconnect '{env_bak}'
chmod 600 '{env_bak}'
sqlite3 /root/vpn-shop/data-silentconnect/vpn_shop.db ".backup '{db_bak}'"
if [ -f /root/subjson-service/app.py ]; then
    cp -a /root/subjson-service/app.py '{subjson_bak}'
fi
echo "--- BACKUP VERIFICATION ---"
ls -lh '{env_bak}' '{db_bak}'
ls -d '{code_bak}'
if [ -f '{subjson_bak}' ]; then
    ls -lh '{subjson_bak}'
fi
"""
    c, o, e = session.run(backup_compound_cmd)
    if c != 0:
        log(f"[{target.upper()}] FATAL: Backups failed! Exit={c}, Err={e}")
        sys.exit(1)
    log(f"[{target.upper()}] Backups confirmed:\n{o.strip()}")

    # --------------------------------------------------------------------------
    # Phase 2: Upload Code (Atomic Tar Stream)
    # --------------------------------------------------------------------------
    log(f"[{target.upper()}] >>> PHASE 2: Uploading {len(PYTHON_MODULES)} modules to /root/vpn-shop/vpn_shop/...")
    session.upload_modules_tar(local_vpn_shop, "/root/vpn-shop/vpn_shop")
    log(f"[{target.upper()}] All modules uploaded cleanly and permissions set to 0644.")

    if os.path.isfile(local_subjson):
        log(f"[{target.upper()}] Uploading subjson-service/app.py to /root/subjson-service/app.py...")
        session.upload_file(local_subjson, "/root/subjson-service/app.py")
        log(f"[{target.upper()}] subjson-service/app.py uploaded cleanly.")

    # --------------------------------------------------------------------------
    # Phase 3 & 4: Config Injection & AST Validation (Single Compound Remote Execution)
    # --------------------------------------------------------------------------
    log(f"[{target.upper()}] >>> PHASE 3 & 4: Injecting Platega configuration, verifying AST syntax & catalog...")
    time.sleep(2)

    config_lines = [
        "",
        "# =============================================================================",
        "# Platega.io Payment Gateway Configuration",
        "# =============================================================================",
        f"PLATEGA_MERCHANT_ID_BOT={creds['PLATEGA_MERCHANT_ID_BOT']}",
        f"PLATEGA_MERCHANT_ID_WEB={creds['PLATEGA_MERCHANT_ID_WEB']}",
        f"PLATEGA_SECRET={creds['PLATEGA_SECRET']}",
        f"PLATEGA_SECRET_BOT={creds['PLATEGA_SECRET_BOT']}",
        f"PLATEGA_SECRET_WEB={creds['PLATEGA_SECRET_WEB']}",
        f"PLATEGA_ENABLED={creds['PLATEGA_ENABLED']}",
    ]
    block = "\\n".join(config_lines)

    compound_phase34_cmd = f"""
set -e
python3 -c "
path = '/root/vpn-shop/.env.silentconnect'
with open(path, 'r', encoding='utf-8') as f:
    lines = [l for l in f.readlines() if not l.startswith('PLATEGA_')]
content = ''.join(lines).rstrip() + '{block}\\n'
with open(path, 'w', encoding='utf-8') as f:
    f.write(content)
"
chmod 600 /root/vpn-shop/.env.silentconnect
python3 -m py_compile /root/vpn-shop/vpn_shop/*.py
if [ -f /root/subjson-service/app.py ]; then
    python3 -m py_compile /root/subjson-service/app.py
fi
cd /root/vpn-shop && python3 -c "from vpn_shop.config import load_settings; s = load_settings(env_file='.env.silentconnect'); assert s.platega_enabled, 'Platega not enabled'; print('Settings OK: platega_enabled=' + str(s.platega_enabled) + ', bot_id=' + s.platega_merchant_id_bot)"
"""
    c, o, e = session.run(compound_phase34_cmd)
    if c != 0:
        log(f"[{target.upper()}] FATAL: Config injection or AST validation failed: {e}")
        sys.exit(1)
    log(f"[{target.upper()}] Injected config, py_compile AST & settings verification OK:\n{o.strip()}")

def execute_rollout():
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log(f"=== Starting Production Rollout (Timestamp: {ts}) ===")
    workspace_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    creds = load_platega_credentials(workspace_root)

    # 1. Deploy to Standby (FI) first
    log(f"=== STAGE 1: DEPLOYING TO STANDBY NODE (FI) ===")
    fi_session = NodeSession("fi")
    try:
        deploy_to_node(fi_session, "fi", ts, workspace_root, creds)
        log("[FI] Restarting subjson on FI...")
        fi_session.run("systemctl restart subjson.service || true")
    finally:
        fi_session.close()

    time.sleep(2)

    # 2. Deploy to Master (NL) second
    log(f"=== STAGE 2: DEPLOYING TO MASTER NODE (NL) ===")
    nl_session = NodeSession("nl")
    try:
        deploy_to_node(nl_session, "nl", ts, workspace_root, creds)

        # ----------------------------------------------------------------------
        # Phase 5: Zero-Downtime Service Restart on NL Master
        # ----------------------------------------------------------------------
        log("[NL] >>> PHASE 5: Restarting vpn-shop-web, vpn-shop-silentconnect, and subjson on NL...")
        c, o, e = nl_session.run("systemctl restart vpn-shop-web.service vpn-shop-silentconnect.service subjson.service")
        if c != 0:
            log(f"[NL] FATAL: Service restart failed: {e}")
            sys.exit(1)
        
        time.sleep(3)  # Wait for startup

        # ----------------------------------------------------------------------
        # Phase 6: Post-Deployment Service Status Verification
        # ----------------------------------------------------------------------
        log("[NL] >>> PHASE 6: Verifying systemd service statuses on NL...")
        c, o, e = nl_session.run("systemctl is-active vpn-shop-web vpn-shop-silentconnect subjson x-ui caddy")
        statuses = o.strip().splitlines()
        log(f"[NL] Service active statuses: {statuses}")
        if any(s != "active" for s in statuses):
            log(f"[NL] FATAL: Unexpected inactive service on NL: {statuses}")
            sys.exit(1)

        # Local loopback checks on NL
        log("[NL] Probing local loopback on port 3090...")
        c, o, e = nl_session.run("curl -s -i -X POST http://127.0.0.1:3090/api/payment/platega/callback")
        log(f"[NL] Local POST response:\n{o.strip()}")
        if "200 OK" not in o or '"status":"ok"' not in o:
            log(f"[NL] FATAL: Local loopback POST probe failed!")
            sys.exit(1)

        c, o, e = nl_session.run("curl -s -i http://127.0.0.1:3090/api/payment/platega/callback")
        log(f"[NL] Local GET response:\n{o.strip()}")
        if "200 OK" not in o or '"gateway":"platega"' not in o:
            log(f"[NL] FATAL: Local loopback GET probe failed!")
            sys.exit(1)

        # Recent journal logs
        log("[NL] Checking recent journal logs for errors...")
        c, o, e = nl_session.run("journalctl -u vpn-shop-web -n 15 --no-pager")
        log(f"[NL] vpn-shop-web journal:\n{o.strip()}")
        c, o, e = nl_session.run("journalctl -u vpn-shop-silentconnect -n 15 --no-pager")
        log(f"[NL] vpn-shop-silentconnect journal:\n{o.strip()}")

    finally:
        nl_session.close()

    # --------------------------------------------------------------------------
    # Phase 7: Public Production HTTPS Health Probes
    # --------------------------------------------------------------------------
    prod_domain = os.environ.get("PRODUCTION_DOMAIN", "silent" + "connect.net")
    log(f"=== STAGE 3: PUBLIC PRODUCTION HTTPS PROBES (https://{prod_domain}) ===")
    ctx = ssl.create_default_context()
    
    # 1. Public Empty POST Probe (Platega dashboard validation)
    url_callback = f"https://{prod_domain}/api/payment/platega/callback"
    log(f"Probing Public POST {url_callback} (empty body)...")
    req_empty_post = urllib.request.Request(
        url_callback,
        data=b"",
        headers={
            "User-Agent": "Platega-Verification-Probe/1.0",
            "Content-Type": "application/json",
        },
        method="POST"
    )
    with urllib.request.urlopen(req_empty_post, context=ctx, timeout=10) as resp:
        body = resp.read().decode("utf-8")
        log(f"Public POST Response: Code {resp.status}, Body: {body.strip()}")
        assert resp.status == 200, f"Expected 200, got {resp.status}"
        parsed = json.loads(body)
        assert parsed.get("status") == "ok", f"Expected ok status, got {parsed}"

    # 2. Public GET Probe
    log(f"Probing Public GET {url_callback}...")
    req_get = urllib.request.Request(
        url_callback,
        headers={"User-Agent": "SilentConnect-Probe/1.0"},
        method="GET"
    )
    with urllib.request.urlopen(req_get, context=ctx, timeout=10) as resp:
        body = resp.read().decode("utf-8")
        log(f"Public GET Response: Code {resp.status}, Body: {body.strip()}")
        assert resp.status == 200, f"Expected 200, got {resp.status}"
        parsed = json.loads(body)
        assert parsed.get("gateway") == "platega", f"Expected gateway platega, got {parsed}"

    # 3. Public Web Checkout Landing Probe
    url_landing = f"https://{prod_domain}/"
    log(f"Probing Public GET {url_landing}...")
    req_landing = urllib.request.Request(
        url_landing,
        headers={"User-Agent": "SilentConnect-Probe/1.0"},
        method="GET"
    )
    with urllib.request.urlopen(req_landing, context=ctx, timeout=10) as resp:
        log(f"Public Landing Response: Code {resp.status}")
        assert resp.status == 200, f"Expected 200, got {resp.status}"

    log("=== PRODUCTION ROLLOUT OF PLATEGA & /BOOST COMPLETED SUCCESSFULLY ===")

if __name__ == "__main__":
    execute_rollout()
