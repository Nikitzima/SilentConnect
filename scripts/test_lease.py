import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
import scripts.remote_exec as r

client = r.get_client('nl')
cmd = """python3 -c "
import sys, pathlib; sys.path.insert(0, '/root/vpn-shop')
from vpn_shop.config import load_settings
from vpn_shop.store import Store

settings = load_settings(pathlib.Path('/root/vpn-shop'))
store = Store(settings.database_path)

# Test lease acquisition
acquired1 = store.try_acquire_cluster_lease('test_task', 'nl', ttl_seconds=30)
print('Acquire 1 (nl):', acquired1)
acquired2 = store.try_acquire_cluster_lease('test_task', 'pl', ttl_seconds=30)
print('Acquire 2 (pl - should be False):', acquired2)
acquired3 = store.try_acquire_cluster_lease('test_task', 'nl', ttl_seconds=30)
print('Acquire 3 (nl renewing - should be True):', acquired3)

with store.connection() as conn:
    row = conn.execute('SELECT lease_name, holder_node, acquired_at, expires_at FROM cluster_leases WHERE lease_name = ?', ('test_task',)).fetchone()
    print('Lease row:', dict(row) if row else 'None')
"
"""
stdin, stdout, stderr = client.exec_command(cmd)
print(stdout.read().decode('utf-8', errors='replace'))
err = stderr.read().decode('utf-8', errors='replace')
if err.strip():
    print("ERR:", err)
client.close()
