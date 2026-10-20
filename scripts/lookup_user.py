import sys
import json
import sqlite3
sys.path.insert(0, 'scripts')
import remote_exec

remote_code = """
import sqlite3, json, datetime

print("=== VPN_SHOP.DB ===")
try:
    conn = sqlite3.connect("/root/vpn-shop/vpn_shop.db")
    conn.row_factory = sqlite3.Row
    orders = conn.execute("SELECT * FROM orders WHERE public_id LIKE '%yogm1tu2or%'").fetchall()
    for o in orders:
        print("ORDER:", dict(o))
        payments = conn.execute("SELECT * FROM payments WHERE order_id = ?", (o["id"],)).fetchall()
        for py in payments:
            print("  PAYMENT:", dict(py))

    profiles = conn.execute("SELECT * FROM profiles WHERE public_id LIKE '%yogm1tu2or%' OR xui_email LIKE '%yogm1tu2or%'").fetchall()
    for p in profiles:
        print("PROFILE:", dict(p))
    conn.close()
except Exception as e:
    print("vpn_shop err:", e)

print("\\n=== X-UI.DB ===")
try:
    conn_xui = sqlite3.connect("/etc/x-ui/x-ui.db")
    conn_xui.row_factory = sqlite3.Row
    inbounds = conn_xui.execute("SELECT id, remark, settings FROM inbounds").fetchall()
    for ib in inbounds:
        settings = json.loads(ib["settings"] or "{}")
        clients = settings.get("clients", [])
        for c in clients:
            email = str(c.get("email", ""))
            sub_id = str(c.get("subId", ""))
            if "yogm1tu2or" in email or "yogm1tu2or" in sub_id:
                print(f"INBOUND {ib['id']} ({ib['remark']}) CLIENT:")
                print(json.dumps(c, indent=2, ensure_ascii=False))
                # Client stats
                exp = c.get("expiryTime", 0)
                if exp > 0:
                    exp_dt = datetime.datetime.fromtimestamp(exp / 1000)
                    print(f"  Expires: {exp_dt}")
                print(f"  Up: {c.get('up', 0) / 1024**2:.2f} MB, Down: {c.get('down', 0) / 1024**2:.2f} MB, Total: {c.get('total', 0)}")
    
    # Also check client_traffics table if exists
    try:
        traffics = conn_xui.execute("SELECT * FROM client_traffics WHERE email LIKE '%yogm1tu2or%'").fetchall()
        for tr in traffics:
            print("CLIENT_TRAFFIC:", dict(tr))
            exp = tr["expiry_time"]
            if exp > 0:
                print("  Expiry:", datetime.datetime.fromtimestamp(exp / 1000))
    except Exception as te:
        print("traffics table:", te)

    conn_xui.close()
except Exception as e:
    print("x-ui err:", e)
"""

code, out, err = remote_exec.run_cmd("nl", f"python3 -c '{remote_code}'")
print(out)
if err:
    print("ERR:", err)
