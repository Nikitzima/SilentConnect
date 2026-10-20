import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
import scripts.remote_exec as r

for target in ['nl', 'pl', 'fi']:
    print(f"\n=== TEST 3X-UI URL ON {target.upper()} ===")
    client = r.get_client(target)
    cmd = """
echo -n "HTTPS on 2053: "
curl -k -s -o /dev/null -w "%{http_code}" https://127.0.0.1:2053/e3gzIe9TsXpSddXQXk/ || echo "ERR"
echo ""
echo -n "HTTP on 2053: "
curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:2053/e3gzIe9TsXpSddXQXk/ || echo "ERR"
echo ""
echo -n "HTTPS on 2096: "
curl -k -s -o /dev/null -w "%{http_code}" https://127.0.0.1:2096/ || echo "ERR"
echo ""
echo -n "HTTP on 2096: "
curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:2096/ || echo "ERR"
echo ""
"""
    stdin, stdout, stderr = client.exec_command(cmd)
    print(stdout.read().decode('utf-8', errors='replace'))
    client.close()
