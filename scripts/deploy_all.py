#!/usr/bin/env python3
"""
deploy_all.py - Complete Automated Deployment and Verification for Plan v7.0 Full Stack
"""
import os
import sys
import time
from datetime import datetime

# Import helper functions
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import remote_exec

def log(msg: str):
    try:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [deploy] {msg}")
    except UnicodeEncodeError:
        safe_msg = msg.encode("ascii", errors="replace").decode("ascii")
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [deploy] {safe_msg}")

def run_remote(target: str, cmd: str, timeout: int = 60):
    code, out, err = remote_exec.run_cmd(target, cmd, timeout=timeout)
    return code, out, err

def upload(target: str, local_path: str, remote_path: str, mode: int = 0o644):
    remote_exec.upload_file(target, local_path, remote_path, mode)
    log(f"Uploaded {local_path} -> {target}:{remote_path} (mode={oct(mode)})")

def main():
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log(f"=== Starting Plan v7.0 Full Stack Deployment (ts={ts}) ===")

    # --------------------------------------------------------------------------
    # 1. Deploy R4: Quiesce Lock in subjson-service/app.py on NL and FI
    # --------------------------------------------------------------------------
    log("=== Deploying Task R4: subjson-service/app.py ===")
    for target in ("nl", "fi"):
        log(f"Backing up /root/subjson-service/app.py on {target}...")
        c, o, e = run_remote(target, f"cp /root/subjson-service/app.py /root/subjson-service/app.py.bak_{ts}")
        log(f"Backup result {target}: code={c}")

        upload(target, "subjson-service/app.py", "/root/subjson-service/app.py", mode=0o644)

        # Compile syntax
        c, o, e = run_remote(target, "python3 -m py_compile /root/subjson-service/app.py")
        if c != 0:
            log(f"Syntax error on {target} app.py: {e}")
            sys.exit(1)
        log(f"Syntax validation on {target}: OK")

        # Restart subjson service safely
        c, o, e = run_remote(target, "systemctl restart subjson && systemctl is-active subjson")
        log(f"Restart subjson on {target}: exit={c}, status={o.strip()}")
        if c != 0 or o.strip() != "active":
            log(f"FATAL: subjson service failed on {target}!")
            sys.exit(1)

    # --------------------------------------------------------------------------
    # 2. Deploy R3: Cloudflare DNS Automation (cf-failover-dns.sh) on NL and FI
    # --------------------------------------------------------------------------
    log("=== Deploying Task R3: cf-failover-dns.sh ===")
    for target in ("nl", "fi"):
        upload(target, "scripts/cf-failover-dns.sh", "/usr/local/bin/cf-failover-dns.sh", mode=0o755)
        c, o, e = run_remote(target, "bash -n /usr/local/bin/cf-failover-dns.sh")
        if c != 0:
            log(f"Syntax error on {target} cf-failover-dns.sh: {e}")
            sys.exit(1)
        log(f"Syntax validation on {target} cf-failover-dns.sh: OK")

    # --------------------------------------------------------------------------
    # 3. Deploy R5: Safe 3-Way Data Merge (failback_merge.py) on NL and FI
    # --------------------------------------------------------------------------
    log("=== Deploying Task R5: failback_merge.py ===")
    for target in ("nl", "fi"):
        upload(target, "scripts/failback_merge.py", "/usr/local/bin/failback_merge.py", mode=0o755)
        upload(target, "scripts/test_failback_merge.py", "/tmp/test_failback_merge.py", mode=0o644)

        c, o, e = run_remote(target, "python3 -m py_compile /usr/local/bin/failback_merge.py")
        if c != 0:
            log(f"Syntax error on {target} failback_merge.py: {e}")
            sys.exit(1)

        # Run synthetic test suite on live Linux host
        c, o, e = run_remote(target, "python3 /tmp/test_failback_merge.py")
        log(f"Test suite on {target}: exit={c}\nSTDOUT:\n{o}\nSTDERR:\n{e}")
        if c != 0:
            log(f"Unit tests failed on {target}!")
            sys.exit(1)

    # --------------------------------------------------------------------------
    # 4. Deploy R6: Failover Scripts (promote_fi.sh, demote_fi.sh) on NL and FI
    # --------------------------------------------------------------------------
    log("=== Deploying Task R6: promote_fi.sh & demote_fi.sh ===")
    for target in ("nl", "fi"):
        upload(target, "scripts/promote_fi.sh", "/usr/local/bin/promote_fi.sh", mode=0o755)
        upload(target, "scripts/demote_fi.sh", "/usr/local/bin/demote_fi.sh", mode=0o755)

        c, o, e = run_remote(target, "bash -n /usr/local/bin/promote_fi.sh && bash -n /usr/local/bin/demote_fi.sh")
        if c != 0:
            log(f"Syntax error on {target} failover scripts: {e}")
            sys.exit(1)
        log(f"Syntax check on {target} promote_fi.sh & demote_fi.sh: OK")

    # --------------------------------------------------------------------------
    # 5. Configure Task R1: Standby Environment on FI
    # --------------------------------------------------------------------------
    log("=== Configuring Task R1: Warm Standby Environment on FI ===")

    # Sync vpn-shop code to FI
    log("Syncing vpn-shop/vpn_shop from workspace to FI...")
    for root, dirs, files in os.walk("vpn-shop/vpn_shop"):
        for file in files:
            if file.endswith(".py"):
                local_f = os.path.join(root, file)
                rel_f = os.path.relpath(local_f, "vpn-shop")
                remote_f = f"/root/vpn-shop/{rel_f}".replace("\\", "/")
                upload("fi", local_f, remote_f, mode=0o644)

    # Also sync awg_manager.py to NL to ensure parity
    upload("nl", "vpn-shop/vpn_shop/awg_manager.py", "/root/vpn-shop/vpn_shop/awg_manager.py", mode=0o644)
    upload("fi", "vpn-shop/awg_reconcile.py", "/root/vpn-shop/awg_reconcile.py", mode=0o644)

    # Configure /root/vpn-shop/.env.silentconnect on FI
    log("Configuring /root/vpn-shop/.env.silentconnect on FI with AWG_LOCAL_SERVER=fi...")
    fi_env_cmd = f"""
if [ -f "/root/vpn-shop/.env.silentconnect" ]; then
    cp /root/vpn-shop/.env.silentconnect /root/vpn-shop/.env.silentconnect.bak_{ts}
fi
# Copy base .env.silentconnect from NL if missing on FI
    NL_HOST_IP="${NL_MASTER_IP:-192.0.2.1}"
    ssh -o StrictHostKeyChecking=no root@$NL_HOST_IP "cat /root/vpn-shop/.env.silentconnect" > /root/vpn-shop/.env.silentconnect
fi

# Ensure AWG_LOCAL_SERVER=fi and SHOP_DB_PATH are configured
grep -q '^AWG_LOCAL_SERVER=' /root/vpn-shop/.env.silentconnect && sed -i 's/^AWG_LOCAL_SERVER=.*/AWG_LOCAL_SERVER=fi/' /root/vpn-shop/.env.silentconnect || echo 'AWG_LOCAL_SERVER=fi' >> /root/vpn-shop/.env.silentconnect
grep -q '^SHOP_DB_PATH=' /root/vpn-shop/.env.silentconnect && sed -i 's|^SHOP_DB_PATH=.*|SHOP_DB_PATH=/root/vpn-shop/data-silentconnect/vpn_shop.db|' /root/vpn-shop/.env.silentconnect || echo 'SHOP_DB_PATH=/root/vpn-shop/data-silentconnect/vpn_shop.db' >> /root/vpn-shop/.env.silentconnect

chmod 600 /root/vpn-shop/.env.silentconnect
"""
    c, o, e = run_remote("fi", fi_env_cmd)
    log(f"FI .env.silentconnect configured: code={c}")

    # Deploy systemd units on FI
    log("Installing vpn-shop systemd units on FI in DISABLED/INACTIVE state...")
    unit_bot = """[Unit]
Description=VPN Shop Bot - SilentConnect (FI Standby)
After=network-online.target x-ui.service subjson.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/root/vpn-shop
EnvironmentFile=/root/vpn-shop/.env.silentconnect
ExecStart=/usr/bin/python3 -m vpn_shop --env-file .env.silentconnect run-bot
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
"""
    unit_web = """[Unit]
Description=VPN Shop Web Checkout - SilentConnect (FI Standby)
After=network-online.target x-ui.service subjson.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/root/vpn-shop
EnvironmentFile=/root/vpn-shop/.env.silentconnect
ExecStart=/usr/bin/python3 -m vpn_shop --env-file .env.silentconnect run-web
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
"""
    # Write temp files and upload
    with open("scripts/vpn-shop-silentconnect.service", "w", encoding="utf-8") as f:
        f.write(unit_bot)
    with open("scripts/vpn-shop-web.service", "w", encoding="utf-8") as f:
        f.write(unit_web)

    upload("fi", "scripts/vpn-shop-silentconnect.service", "/etc/systemd/system/vpn-shop-silentconnect.service", mode=0o644)
    upload("fi", "scripts/vpn-shop-web.service", "/etc/systemd/system/vpn-shop-web.service", mode=0o644)

    c, o, e = run_remote("fi", "systemctl daemon-reload && systemctl disable --now vpn-shop-silentconnect.service vpn-shop-web.service 2>/dev/null || true")
    log(f"Systemd units configured on FI: code={c}")

    # Verify FI standby status
    c, o, e = run_remote("fi", "systemctl is-active vpn-shop-silentconnect vpn-shop-web ; echo '---' ; systemctl is-enabled vpn-shop-silentconnect vpn-shop-web")
    log(f"FI Standby Services Status (expected inactive / disabled):\n{o}")

    # Update /etc/litestream.yml on FI
    log("Updating /etc/litestream.yml on FI with vpn_shop.db replica mapping...")
    fi_litestream_yml = """dbs:
  - path: /etc/x-ui/x-ui.db
    replicas:
      - type: file
        path: /var/lib/litestream/x-ui-db.replica
  - path: /root/vpn-shop/data-silentconnect/vpn_shop.db
    replicas:
      - type: file
        path: /var/lib/litestream/vpn-shop-db.replica
"""
    with open("scripts/litestream_fi.yml", "w", encoding="utf-8") as f:
        f.write(fi_litestream_yml)
    run_remote("fi", f"cp /etc/litestream.yml /etc/litestream.yml.bak_{ts} 2>/dev/null || true")
    upload("fi", "scripts/litestream_fi.yml", "/etc/litestream.yml", mode=0o600)

    # Test litestream replica validation on FI
    c, o, e = run_remote("fi", "litestream databases -config /etc/litestream.yml")
    log(f"FI Litestream replica databases:\n{o}")

    # --------------------------------------------------------------------------
    # 6. Configure Task R2: Reverse Proxy (Caddyfile) on FI
    # --------------------------------------------------------------------------
    log("=== Configuring Task R2: Reverse Proxy (Caddyfile) on FI ===")
    domain_main = os.environ.get("DOMAIN_MAIN", "example.com")
    domain_sub = os.environ.get("DOMAIN_SUB", f"sub.{domain_main}")
    domain_edge = os.environ.get("DOMAIN_EDGE", f"edge.{domain_main}")
    domain_fi = os.environ.get("DOMAIN_FI", f"fi.{domain_main}")
    fi_ip = os.environ.get("FI_STANDBY_IP", "198.51.100.1")

    caddyfile_fi = f"""{{
	https_port 4430
	http_port 80
}}

# 1. Subscription & Proxy API Endpoints (SubJSON on :3088, XHTTP on :28080, WS on :10010)
{domain_sub}, {domain_edge}, {domain_fi}, {fi_ip}.sslip.io, {fi_ip}.nip.io {{
	@ws_test path /sc-ws-9c3d7f1e
	handle @ws_test {{
		reverse_proxy 127.0.0.1:10010
	}}

	@xhttp_tcp path /xh-mx-d1f7c0429d6a*
	handle @xhttp_tcp {{
		reverse_proxy 127.0.0.1:28080 {{
			transport http {{
				versions h2c 2
			}}
		}}
	}}

	handle_path /future-it-9e3d* {{
		root * /var/www/future-it
		file_server
	}}

	handle {{
		encode zstd gzip
		reverse_proxy 127.0.0.1:3088
	}}
}}

# 2. Main Brand & Web Checkout Endpoints (VPN Shop Web on :3090)
{domain_main}, www.{domain_main}, app.{fi_ip}.sslip.io {{
	handle_path /future-it-9e3d* {{
		root * /var/www/future-it
		file_server
	}}

	handle {{
		encode zstd gzip
		reverse_proxy 127.0.0.1:3090
	}}
}}
"""
    with open("scripts/Caddyfile.fi", "w", encoding="utf-8") as f:
        f.write(caddyfile_fi)

    run_remote("fi", f"cp /etc/caddy/Caddyfile /etc/caddy/Caddyfile.bak_{ts}")
    upload("fi", "scripts/Caddyfile.fi", "/etc/caddy/Caddyfile", mode=0o644)

    fi_caddy_val = """
mkdir -p /var/www/future-it
caddy validate --config /etc/caddy/Caddyfile
systemctl reload caddy
systemctl is-active caddy
"""
    c, o, e = run_remote("fi", fi_caddy_val)
    log(f"FI Caddyfile configured and validated: code={c}, out=\n{o}\n{e}")
    if c != 0:
        log("Caddy validation/reload failed on FI!")
        sys.exit(1)

    log("=== ALL PLAN v7.0 DEPLOYMENT TASKS COMPLETED SUCCESSFULLY ===")

if __name__ == "__main__":
    main()
