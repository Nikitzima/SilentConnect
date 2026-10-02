#!/usr/bin/env python3
"""
deploy_cabinet_webp_assets.py
Uploads converted cabinet .webp images and updated app.py/web.py to NL, PL, and FI.
Restarts subjson.service and vpn-shop-web.service with zero VPN downtime.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
import remote_exec

LOCAL_SUBJSON_APP = PROJECT_ROOT / "subjson-service" / "app.py"
LOCAL_SUBJSON_APPS_DIR = PROJECT_ROOT / "subjson-service" / "assets" / "apps"
LOCAL_SUBJSON_BRAND_DIR = PROJECT_ROOT / "subjson-service" / "assets" / "branding"

LOCAL_WEB_APP = PROJECT_ROOT / "vpn-shop" / "vpn_shop" / "web.py"
LOCAL_WEB_APPS_DIR = PROJECT_ROOT / "vpn-shop" / "assets" / "apps"

WEBP_APP_ICONS = [
    "amneziavpn.webp",
    "amneziawg.webp",
    "clash.webp",
    "clash_mi.webp",
    "happ.webp",
    "nekobox.webp",
    "singbox.webp",
    "streisand.webp",
    "v2rayn.webp",
    "v2rayng.webp",
]


def deploy_to_node(target: str):
    print(f"\n========================================================")
    print(f"[*] Deploying Cabinet WebP Assets & Code to {target.upper()}...")
    print(f"========================================================")
    client = remote_exec.get_client(target)
    sftp = client.open_sftp()

    # 1. Ensure remote directories exist
    remote_subjson_apps = "/root/subjson-service/assets/apps"
    remote_subjson_brand = "/root/subjson-service/assets/branding"
    remote_web_apps = "/root/vpn-shop/assets/apps"

    for rdir in [remote_subjson_apps, remote_subjson_brand, remote_web_apps]:
        stdin, stdout, _ = client.exec_command(f"mkdir -p {rdir}")
        stdout.channel.recv_exit_status()

    # 2. Upload WebP app icons to subjson-service
    print("  Uploading app icons to /root/subjson-service/assets/apps/...")
    for icon_name in WEBP_APP_ICONS:
        local_path = LOCAL_SUBJSON_APPS_DIR / icon_name
        remote_path = f"{remote_subjson_apps}/{icon_name}"
        if local_path.is_file():
            sftp.put(str(local_path), remote_path)

    # 3. Upload branding avatar to subjson-service
    local_avatar = LOCAL_SUBJSON_BRAND_DIR / "avatar.webp"
    if local_avatar.is_file():
        print("  Uploading avatar.webp to /root/subjson-service/assets/branding/...")
        sftp.put(str(local_avatar), f"{remote_subjson_brand}/avatar.webp")

    # 4. Upload app icons to vpn-shop
    print("  Uploading app icons to /root/vpn-shop/assets/apps/...")
    for icon_name in WEBP_APP_ICONS:
        local_path = LOCAL_WEB_APPS_DIR / icon_name
        remote_path = f"{remote_web_apps}/{icon_name}"
        if local_path.is_file():
            sftp.put(str(local_path), remote_path)

    # 5. Upload app.py to subjson-service
    remote_app_py = "/root/subjson-service/app.py"
    print(f"  Uploading updated app.py ({LOCAL_SUBJSON_APP.stat().st_size} bytes)...")
    sftp.put(str(LOCAL_SUBJSON_APP), remote_app_py)

    # 6. Upload web.py to vpn-shop
    remote_web_py = "/root/vpn-shop/vpn_shop/web.py"
    print(f"  Uploading updated web.py ({LOCAL_WEB_APP.stat().st_size} bytes)...")
    sftp.put(str(LOCAL_WEB_APP), remote_web_py)

    sftp.close()

    # 7. Remote py_compile verification
    for py_file in [remote_app_py, remote_web_py]:
        stdin, stdout, stderr = client.exec_command(f"python3 -m py_compile {py_file}")
        code = stdout.channel.recv_exit_status()
        if code != 0:
            err = stderr.read().decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"Syntax error in {py_file} on {target}: {err}")
    print(f"[+] Remote py_compile passed for app.py and web.py on {target.upper()}")

    # 8. Restart subjson.service
    stdin, stdout, _ = client.exec_command("systemctl is-active subjson.service")
    subjson_status = stdout.read().decode("utf-8").strip()
    if subjson_status in {"active", "activating"}:
        client.exec_command("systemctl restart subjson.service")
        stdin, stdout, _ = client.exec_command("systemctl is-active subjson.service")
        new_status = stdout.read().decode("utf-8").strip()
        print(f"[+] subjson.service status on {target.upper()}: {new_status}")
    else:
        print(f"[-] subjson.service is {subjson_status} on {target.upper()}")

    # 9. Restart vpn-shop-web.service
    stdin, stdout, _ = client.exec_command("systemctl is-active vpn-shop-web.service")
    web_status = stdout.read().decode("utf-8").strip()
    if web_status in {"active", "activating"}:
        client.exec_command("systemctl restart vpn-shop-web.service")
        stdin, stdout, _ = client.exec_command("systemctl is-active vpn-shop-web.service")
        new_status = stdout.read().decode("utf-8").strip()
        print(f"[+] vpn-shop-web.service status on {target.upper()}: {new_status}")
    else:
        print(f"[-] vpn-shop-web.service is {web_status} on {target.upper()}")

    # 10. Smoke probe static endpoints locally on node
    stdin, stdout, _ = client.exec_command("curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3088/assets/apps/happ.webp")
    happ_code = stdout.read().decode("utf-8").strip()
    stdin, stdout, _ = client.exec_command("curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3088/assets/branding/avatar.webp")
    avatar_code = stdout.read().decode("utf-8").strip()
    print(f"[+] Health check on {target.upper()}: /assets/apps/happ.webp -> {happ_code}, /assets/branding/avatar.webp -> {avatar_code}")

    client.close()


def main():
    nodes = ["nl", "pl", "fi"]
    for node in nodes:
        try:
            deploy_to_node(node)
        except Exception as e:
            print(f"[!] Deployment error on {node.upper()}: {e}")
            sys.exit(1)
    print("\n[SUCCESS] All nodes successfully updated with local WebP cabinet assets!")


if __name__ == "__main__":
    main()
