import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
import scripts.remote_exec as r

for target in ['pl', 'fi']:
    print(f"\n=== TEST 3X-UI LOGIN OVER HTTP ON {target.upper()} ===")
    client = r.get_client(target)
    cmd = """python3 -c "
import urllib.request, urllib.parse, json, http.cookiejar

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

# Get base
req = urllib.request.Request('http://127.0.0.1:2053/e3gzIe9TsXpSddXQXk/', headers={'User-Agent': 'test'})
resp = opener.open(req)
print('Base page status:', resp.status)

# Login
login_data = json.dumps({'username': 'Nikitzima', 'password': 'Nik!t@1881'}).encode()
req2 = urllib.request.Request('http://127.0.0.1:2053/e3gzIe9TsXpSddXQXk/login', data=login_data, headers={'Content-Type': 'application/json', 'User-Agent': 'test'})
resp2 = opener.open(req2)
print('Login response:', resp2.read().decode())

# Inbounds list
req3 = urllib.request.Request('http://127.0.0.1:2053/e3gzIe9TsXpSddXQXk/panel/api/inbounds/list', headers={'Accept': 'application/json', 'User-Agent': 'test'}, method='POST')
resp3 = opener.open(req3)
inbounds = json.loads(resp3.read().decode())
print('Inbounds count:', len(inbounds.get('obj', [])))
for ib in inbounds.get('obj', []):
    print('  Inbound id:', ib['id'], 'port:', ib['port'], 'protocol:', ib['protocol'], 'tag:', ib.get('tag'))
"
"""
    stdin, stdout, stderr = client.exec_command(cmd)
    print(stdout.read().decode('utf-8', errors='replace'))
    err = stderr.read().decode('utf-8', errors='replace')
    if err.strip():
        print("ERR:", err)
    client.close()
