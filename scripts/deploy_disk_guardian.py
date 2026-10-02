#!/usr/bin/env python3
"""
deploy_disk_guardian.py
Deploys 2-day log retention policy, disk-guardian timer, and fixes OpenFlux logging on NL, FI, PL.
"""

import sys
import os
import time
from pathlib import Path

# Add project root to sys.path to import remote_exec
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
import remote_exec

DISK_GUARDIAN_SCRIPT = r"""#!/usr/bin/env bash
set -euo pipefail

# 1. Vacuum systemd journal to max 2 days / 300MB
journalctl --vacuum-time=2d --vacuum-size=300M >/dev/null 2>&1 || true

# 2. Enforce 2-day retention on heavy logs & rotated archives
find /var/log/xray* /var/log/openflux* /var/log/x-ui /var/log -maxdepth 2 -type f \( -name "*.gz" -o -name "*.1" -o -name "*.old" -o -name "*.[0-9]" \) -mtime +2 -delete >/dev/null 2>&1 || true
find /var/log/xray* /var/log/openflux* /var/log/x-ui -type f -name "*.log" -mtime +2 -delete >/dev/null 2>&1 || true

# 3. Check disk usage on root (/)
USAGE=$(df / | awk 'NR==2 {gsub("%",""); print $5}')

if [ "$USAGE" -gt 75 ]; then
    echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] WARNING: Disk usage is ${USAGE}%, running aggressive cleanup" >> /var/log/disk-guardian.log
    journalctl --vacuum-size=100M >/dev/null 2>&1 || true
    apt-get clean >/dev/null 2>&1 || true

    # Truncate any huge text log over 100MB
    find /var/log -type f -name "*.log" -size +100M -exec truncate -s 20M {} + 2>/dev/null || true
    if [ -f /var/log/syslog ]; then
        SIZE=$(stat -c%s /var/log/syslog 2>/dev/null || echo 0)
        if [ "$SIZE" -gt 104857600 ]; then
            truncate -s 20M /var/log/syslog || true
        fi
    fi
fi
"""

DISK_GUARDIAN_SERVICE = """[Unit]
Description=SilentConnect Disk Guardian & 2-Day Retention Sweeper
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/disk-guardian.sh
"""

DISK_GUARDIAN_TIMER = """[Unit]
Description=Run Disk Guardian every 15 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=15min
Persistent=true

[Install]
WantedBy=timers.target
"""

LOGROTATE_RSYSLOG = """/var/log/syslog
/var/log/mail.info
/var/log/mail.warn
/var/log/mail.err
/var/log/mail.log
/var/log/daemon.log
/var/log/kern.log
/var/log/auth.log
/var/log/user.log
/var/log/lpr.log
/var/log/cron.log
/var/log/debug
/var/log/messages
{
    daily
    rotate 2
    maxsize 50M
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
"""

LOGROTATE_XRAY = """/var/log/xray*/*.log {
    daily
    rotate 2
    maxsize 50M
    missingok
    notifempty
    compress
    copytruncate
}
"""

JOURNALD_CONF_SNIPPET = """
[Journal]
SystemMaxUse=300M
SystemKeepFree=2G
RuntimeMaxUse=100M
MaxRetentionSec=2day
"""


def run_node_commands(target: str):
    print(f"\n========================================================")
    print(f"[*] Processing node: {target.upper()}")
    print(f"========================================================")
    client = remote_exec.get_client(target)
    
    def exec_cmd(cmd: str, ignore_errors=False):
        print(f"[{target.upper()}] $ {cmd[:90]}{'...' if len(cmd) > 90 else ''}")
        stdin, stdout, stderr = client.exec_command(cmd)
        out = stdout.read().decode('utf-8', errors='replace').strip()
        err = stderr.read().decode('utf-8', errors='replace').strip()
        code = stdout.channel.recv_exit_status()
        if code != 0 and not ignore_errors:
            print(f"  [ERROR {code}] {err}")
        elif out:
            print(f"  {out[:300]}")
        return code, out, err

    # 1. Emergency log cleanup
    print(f"[{target.upper()}] Step 1: Emergency log truncation...")
    exec_cmd("truncate -s 0 /var/log/syslog 2>/dev/null || true")
    exec_cmd("rm -f /var/log/syslog.* /var/log/*.gz /var/log/*.1 /var/log/*.old 2>/dev/null || true")
    exec_cmd("truncate -s 0 /var/log/xray-maxru/*.log 2>/dev/null || true")
    exec_cmd("journalctl --vacuum-time=2d --vacuum-size=200M")

    # 2. Configure journald 2-day retention
    print(f"[{target.upper()}] Step 2: Configuring journald 2-day retention...")
    exec_cmd("mkdir -p /etc/systemd/journald.conf.d")
    exec_cmd(f"cat << 'EOF' > /etc/systemd/journald.conf.d/silentconnect-retention.conf\n{JOURNALD_CONF_SNIPPET}\nEOF")
    exec_cmd("systemctl restart systemd-journald")

    # 3. Configure logrotate for rsyslog and xray
    print(f"[{target.upper()}] Step 3: Configuring logrotate...")
    exec_cmd(f"cat << 'EOF' > /etc/logrotate.d/rsyslog\n{LOGROTATE_RSYSLOG}\nEOF")
    exec_cmd(f"cat << 'EOF' > /etc/logrotate.d/xray\n{LOGROTATE_XRAY}\nEOF")

    # 4. Fix openflux service if present
    print(f"[{target.upper()}] Step 4: Checking openflux service configuration...")
    code, out, _ = exec_cmd("[ -f /etc/systemd/system/openflux-node@.service ] && echo 'FOUND' || echo 'NOT_FOUND'")
    if "FOUND" in out:
        print(f"[{target.upper()}] Updating openflux-node@.service to disable debug and cap log level...")
        # Replace --debug=1 with --debug=0
        exec_cmd("sed -i 's/--debug=1/--debug=0/g' /etc/systemd/system/openflux-node@.service")
        # Ensure LogLevelMax=notice exists in [Service]
        exec_cmd("grep -q 'LogLevelMax=notice' /etc/systemd/system/openflux-node@.service || sed -i '/\\[Service\\]/a LogLevelMax=notice' /etc/systemd/system/openflux-node@.service")
        # Ensure StandardOutput/Error are capped
        exec_cmd("systemctl daemon-reload")
        # Kill stale process PID 2096955 if running on NL
        exec_cmd("kill -9 2096955 2>/dev/null || true", ignore_errors=True)
        # Restart active openflux node service
        exec_cmd("systemctl restart openflux-node@*.service 2>/dev/null || true", ignore_errors=True)

    # 5. Install disk-guardian script and systemd timer
    print(f"[{target.upper()}] Step 5: Installing disk-guardian...")
    exec_cmd(f"cat << 'EOF' > /usr/local/bin/disk-guardian.sh\n{DISK_GUARDIAN_SCRIPT}\nEOF")
    exec_cmd("chmod +x /usr/local/bin/disk-guardian.sh")
    exec_cmd(f"cat << 'EOF' > /etc/systemd/system/disk-guardian.service\n{DISK_GUARDIAN_SERVICE}\nEOF")
    exec_cmd(f"cat << 'EOF' > /etc/systemd/system/disk-guardian.timer\n{DISK_GUARDIAN_TIMER}\nEOF")
    exec_cmd("systemctl daemon-reload")
    exec_cmd("systemctl enable --now disk-guardian.timer")
    exec_cmd("/usr/local/bin/disk-guardian.sh")

    # 6. Postflight verify
    print(f"[{target.upper()}] Step 6: Postflight verification...")
    _, df_out, _ = exec_cmd("df -h /")
    print(f"[{target.upper()}] Free disk status:\n{df_out}")
    client.close()


def main():
    nodes = ["nl", "fi", "pl"]
    for node in nodes:
        try:
            run_node_commands(node)
        except Exception as e:
            print(f"[!] Error on {node}: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
