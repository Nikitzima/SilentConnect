#!/usr/bin/env python3
"""
deploy_webp_assets.py
Uploads converted .webp images and updated web.py to NL, PL, and FI.
Restarts vpn-shop-web.service.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
import remote_exec

LOCAL_WEB = PROJECT_ROOT / "vpn-shop" / "vpn_shop" / "web.py"
LOCAL_ASSETS_DIR = PROJECT_ROOT / "vpn-shop" / "assets" / "telegram"
WEBP_FILES = [
    "avatar.webp",
    "welcome.webp",
    "bot_menu_hero.webp",
    "quickstart.webp",
    "telegram_icon.webp",
    "telegram_official.webp",
]


def deploy_to_node(target: str):
    print(f"\n========================================================")
    print(f"[*] Deploying WebP assets and web.py to {target.upper()}...")
    print(f"========================================================")
    client = remote_exec.get_client(target)
    sftp = client.open_sftp()

    # 1. Ensure remote directory exists
    remote_assets_dir = "/root/vpn-shop/assets/telegram"
    stdin, stdout, _ = client.exec_command(f"mkdir -p {remote_assets_dir}")
    stdout.channel.recv_exit_status()

    # 2. Upload WebP images
    for webp_name in WEBP_FILES:
        local_path = LOCAL_ASSETS_DIR / webp_name
        remote_path = f"{remote_assets_dir}/{webp_name}"
        if local_path.is_file():
            print(f"  Uploading {webp_name}...")
            sftp.put(str(local_path), remote_path)

    # 3. Upload web.py
    remote_web = "/root/vpn-shop/vpn_shop/web.py"
    print(f"  Uploading web.py...")
    sftp.put(str(LOCAL_WEB), remote_web)
    sftp.close()

    # 4. Verify syntax
    stdin, stdout, stderr = client.exec_command(f"python3 -m py_compile {remote_web}")
    code = stdout.channel.recv_exit_status()
    if code != 0:
        err = stderr.read().decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"Syntax error on {target}: {err}")
    print(f"[+] Remote py_compile passed on {target.upper()}")

    # 5. Restart vpn-shop-web.service if running
    stdin, stdout, _ = client.exec_command("systemctl is-active vpn-shop-web.service")
    status = stdout.read().decode("utf-8").strip()
    if status in {"active", "activating"}:
        client.exec_command("systemctl restart vpn-shop-web.service")
        stdin, stdout, _ = client.exec_command("systemctl is-active vpn-shop-web.service")
        new_status = stdout.read().decode("utf-8").strip()
        print(f"[+] vpn-shop-web.service status on {target.upper()}: {new_status}")
    else:
        print(f"[-] vpn-shop-web.service is {status} on {target.upper()} (standby node)")

    client.close()


def main():
    nodes = ["nl", "pl", "fi"]
    for node in nodes:
        try:
            deploy_to_node(node)
        except Exception as e:
            print(f"[!] Error deploying to {node}: {e}", file=sys.stderr)
    print("\n[+] All nodes updated with WebP assets successfully!")


if __name__ == "__main__":
    main()
