import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
import scripts.remote_exec as r

client = r.get_client('nl')
cmd = """python3 -c "
import sys, pathlib; sys.path.insert(0, '/root/vpn-shop')
from vpn_shop.config import load_settings
from vpn_shop.xui_api import XuiApiClient

settings = load_settings(pathlib.Path('/root/vpn-shop'))
print('Panel URL:', settings.xui_panel_url)
print('Username:', settings.xui_username)
api = XuiApiClient(panel_url=settings.xui_panel_url, username=settings.xui_username, password=settings.xui_password, verify_tls=False)
api.login()
print('Logged in successfully! CSRF token:', api._csrf_token)
inbounds = api.list_inbounds()
print('Inbounds count:', len(inbounds))
"
"""
stdin, stdout, stderr = client.exec_command(cmd)
print(stdout.read().decode('utf-8', errors='replace'))
err = stderr.read().decode('utf-8', errors='replace')
if err.strip():
    print("ERR:", err)
client.close()
