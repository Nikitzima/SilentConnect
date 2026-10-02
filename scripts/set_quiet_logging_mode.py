#!/usr/bin/env python3
"""
set_quiet_logging_mode.py
Sets quiet logging mode across NL, FI, PL:
- Disables Xray access logging ("access": "none") everywhere (privacy + zero disk waste)
- Sets Xray loglevel to "warning" (removes "debug" on PL)
- Disables UFW firewall scanner logging (ufw logging off)
- Caps systemd service log levels to "warning" for network tunnels
"""

import sys
import os
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
import remote_exec

QUIET_SCRIPT_REMOTE = r"""#!/usr/bin/env python3
import json
import os
import sqlite3
import subprocess

def run_cmd(cmd):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return p.returncode, p.stdout.strip(), p.stderr.strip()

print("[*] Setting quiet logging mode...")

# 1. Update /usr/local/x-ui/bin/config.json
xray_cfg_path = "/usr/local/x-ui/bin/config.json"
if os.path.exists(xray_cfg_path):
    try:
        with open(xray_cfg_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        if "log" in cfg:
            cfg["log"]["access"] = "none"
            cfg["log"]["loglevel"] = "warning"
            cfg["log"]["error"] = ""
            with open(xray_cfg_path, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2, ensure_ascii=False)
            print("[+] Updated /usr/local/x-ui/bin/config.json -> access: none, loglevel: warning")
    except Exception as e:
        print(f"[-] Error updating {xray_cfg_path}: {e}")

# 2. Update x-ui.db xrayTemplateConfig
db_path = "/etc/x-ui/x-ui.db"
if os.path.exists(db_path):
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key='xrayTemplateConfig'")
        row = cur.fetchone()
        if row and row[0]:
            tmpl = json.loads(row[0])
            if "log" in tmpl:
                tmpl["log"]["access"] = "none"
                tmpl["log"]["loglevel"] = "warning"
                tmpl["log"]["error"] = ""
                cur.execute("UPDATE settings SET value=? WHERE key='xrayTemplateConfig'", (json.dumps(tmpl),))
                conn.commit()
                print("[+] Updated x-ui.db xrayTemplateConfig -> access: none, loglevel: warning")
        conn.close()
    except Exception as e:
        print(f"[-] Error updating {db_path}: {e}")

# 3. Update /usr/local/etc/xray-ws443/config.json if present
ws443_cfg = "/usr/local/etc/xray-ws443/config.json"
if os.path.exists(ws443_cfg):
    try:
        with open(ws443_cfg, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        if "log" in cfg:
            cfg["log"]["access"] = "none"
            cfg["log"]["loglevel"] = "warning"
            cfg["log"]["error"] = ""
            with open(ws443_cfg, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2, ensure_ascii=False)
            print(f"[+] Updated {ws443_cfg} -> access: none, loglevel: warning")
            run_cmd("systemctl restart xray-ws443 2>/dev/null || true")
    except Exception as e:
        print(f"[-] Error updating {ws443_cfg}: {e}")

# 4. Turn off UFW packet scanner logging
code, out, err = run_cmd("ufw logging off")
print(f"[+] UFW logging: {out or err}")

# 5. Cap systemd service log level for hysteria if present
hysteria_service = "/etc/systemd/system/hysteria.service"
if os.path.exists(hysteria_service):
    run_cmd("grep -q 'LogLevelMax=' /etc/systemd/system/hysteria.service || sed -i '/\\[Service\\]/a LogLevelMax=warning' /etc/systemd/system/hysteria.service")
    run_cmd("systemctl daemon-reload")
    print("[+] Capped hysteria.service to LogLevelMax=warning")

# 6. Truncate existing access logs
run_cmd("truncate -s 0 /var/log/x-ui/access.log 2>/dev/null || true")
run_cmd("truncate -s 0 /var/log/xray-ws443/access.log 2>/dev/null || true")
run_cmd("truncate -s 0 /var/log/ufw.log 2>/dev/null || true")

# 7. Restart x-ui to apply quiet mode
run_cmd("systemctl restart x-ui 2>/dev/null || true")
print("[+] Restarted x-ui in quiet mode")
"""


def apply_quiet_mode(target: str):
    print(f"\n========================================================")
    print(f"[*] Applying quiet logging mode to {target.upper()}")
    print(f"========================================================")
    client = remote_exec.get_client(target)
    
    # Upload and execute remote script
    sftp = client.open_sftp()
    remote_script_path = "/tmp/apply_quiet_logging.py"
    with sftp.file(remote_script_path, "w") as f:
        f.write(QUIET_SCRIPT_REMOTE)
    sftp.chmod(remote_script_path, 0o755)
    sftp.close()

    stdin, stdout, stderr = client.exec_command(f"python3 {remote_script_path} && rm -f {remote_script_path}")
    out = stdout.read().decode('utf-8', errors='replace').strip()
    err = stderr.read().decode('utf-8', errors='replace').strip()
    print(out)
    if err:
        print(f"Stderr: {err}")
    client.close()


def main():
    nodes = ["nl", "fi", "pl"]
    for node in nodes:
        try:
            apply_quiet_mode(node)
        except Exception as e:
            print(f"[!] Error on {node}: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
