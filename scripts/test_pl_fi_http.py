import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
import scripts.remote_exec as r

for target in ['pl', 'fi']:
    print(f"\n=== TEST XuiApiClient with HTTP ON {target.upper()} ===")
    client = r.get_client(target)
    cmd = """python3 -c "
import sys, pathlib; sys.path.insert(0, '/root/vpn-shop')
from vpn_shop.xui_api import XuiApiClient

api = XuiApiClient(panel_url='http://127.0.0.1:2053/e3gzIe9TsXpSddXQXk/', username='Nikitzima', password='Nik!t@1881', verify_tls=False)
api.login()
print('Logged in successfully on', sys.argv, '! CSRF token:', api._csrf_token)
inbounds = api.get_inbounds()
print('Inbounds count:', len(inbounds))
for ib in inbounds:
    print('  Inbound id:', ib['id'], 'port:', ib['port'], 'protocol:', ib['protocol'])
"
"""
    stdin, stdout, stderr = client.exec_command(cmd)
    print(stdout.read().decode('utf-8', errors='replace'))
    err = stderr.read().decode('utf-8', errors='replace')
    if err.strip():
        print("ERR:", err)
    client.close()
