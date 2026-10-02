#!/usr/bin/env python3
"""
deploy_quiet_text_updates.py
Safely uploads updated web.py and bot.py to NL and PL, verifies py_compile, and restarts web/bot services.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
import remote_exec

LOCAL_WEB = PROJECT_ROOT / "vpn-shop" / "vpn_shop" / "web.py"
LOCAL_BOT = PROJECT_ROOT / "vpn-shop" / "vpn_shop" / "bot.py"


def deploy_to_node(target: str, restart_bot: bool = False):
    print(f"\n========================================================")
    print(f"[*] Deploying to {target.upper()}...")
    print(f"========================================================")
    client = remote_exec.get_client(target)
    sftp = client.open_sftp()

    # Upload files
    remote_web = "/root/vpn-shop/vpn_shop/web.py"
    remote_bot = "/root/vpn-shop/vpn_shop/bot.py"
    print(f"Uploading {LOCAL_WEB} -> {remote_web}")
    sftp.put(str(LOCAL_WEB), remote_web)
    print(f"Uploading {LOCAL_BOT} -> {remote_bot}")
    sftp.put(str(LOCAL_BOT), remote_bot)
    sftp.close()

    # Compile check
    stdin, stdout, stderr = client.exec_command(f"python3 -m py_compile {remote_web} {remote_bot}")
    code = stdout.channel.recv_exit_status()
    if code != 0:
        err = stderr.read().decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"Syntax error on {target}: {err}")
    print(f"[+] Remote py_compile passed on {target.upper()}")

    # Restart web
    client.exec_command("systemctl restart vpn-shop-web.service")
    stdin, stdout, _ = client.exec_command("systemctl is-active vpn-shop-web.service")
    web_status = stdout.read().decode("utf-8").strip()
    print(f"[+] vpn-shop-web.service status on {target.upper()}: {web_status}")

    # Restart bot if requested
    if restart_bot:
        client.exec_command("systemctl restart vpn-shop-silentconnect.service")
        stdin, stdout, _ = client.exec_command("systemctl is-active vpn-shop-silentconnect.service")
        bot_status = stdout.read().decode("utf-8").strip()
        print(f"[+] vpn-shop-silentconnect.service status on {target.upper()}: {bot_status}")

    client.close()


def main():
    deploy_to_node("nl", restart_bot=True)
    deploy_to_node("pl", restart_bot=False)
    print("\n[+] All nodes updated successfully!")


if __name__ == "__main__":
    main()
