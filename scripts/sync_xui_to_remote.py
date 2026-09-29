#!/usr/bin/env python3
import sqlite3
import json
import subprocess
import sys
import os

def sync_to_remote(remote_host):
    print(f"=== Syncing X-UI clients NL -> {remote_host} ===")
    local_db = "/etc/x-ui/x-ui.db"
    conn = sqlite3.connect(local_db)
    c = conn.cursor()

    local_clients = c.execute("""
        SELECT id, email, sub_id, uuid, password, auth, flow, security, reverse,
        wg_private_key, wg_public_key, wg_allowed_ips, wg_pre_shared_key, wg_keep_alive, secret, ad_tag,
        limit_ip, total_gb, expiry_time, enable, tg_id, group_name, comment, reset, created_at, updated_at
        FROM clients
    """).fetchall()

    local_traffics = c.execute("""
        SELECT id, inbound_id, enable, email, up, down, expiry_time, total, reset, last_online
        FROM client_traffics
    """).fetchall()
    conn.close()

    payload = json.dumps({"clients": local_clients, "traffics": local_traffics})

    remote_worker = """import sqlite3, json, sys, subprocess, os, time

raw = sys.stdin.read()
payload = json.loads(raw)
clients = payload["clients"]
traffics = payload["traffics"]

conn = sqlite3.connect('/etc/x-ui/x-ui.db')
c = conn.cursor()
changed = False

existing_clients = {r[1]: r for r in c.execute("SELECT id, email, sub_id, uuid, enable, expiry_time FROM clients").fetchall()}
for row in clients:
    email = row[1]
    sub_id = row[2]
    uuid = row[3]
    enable = row[19]
    expiry = row[18]
    if email not in existing_clients:
        c.execute('''
            INSERT INTO clients (
                email, sub_id, uuid, password, auth, flow, security, reverse,
                wg_private_key, wg_public_key, wg_allowed_ips, wg_pre_shared_key,
                wg_keep_alive, secret, ad_tag, limit_ip, total_gb, expiry_time,
                enable, tg_id, group_name, comment, reset, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', row[1:])
        changed = True
        print(f"Added client {email}")
    else:
        cur = existing_clients[email]
        if cur[4] != enable or cur[5] != expiry or cur[2] != sub_id:
            c.execute("UPDATE clients SET enable=?, expiry_time=?, sub_id=? WHERE email=?", (enable, expiry, sub_id, email))
            changed = True
            print(f"Updated client {email}")

existing_traffics = {r[3]: r for r in c.execute("SELECT id, inbound_id, enable, email, up, down, expiry_time, total, reset, last_online FROM client_traffics").fetchall()}
for row in traffics:
    tr_email = row[3]
    if tr_email not in existing_traffics:
        try:
            c.execute('''
                INSERT INTO client_traffics (
                    inbound_id, enable, email, up, down, expiry_time, total, reset, last_online
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', row[1:10])
            changed = True
            print(f"Added traffic record for {tr_email}")
        except Exception as te:
            print(f"Traffic insert error for {tr_email}: {te}", file=sys.stderr)

inbounds = c.execute("SELECT id, tag, settings FROM inbounds").fetchall()
for ib_id, tag, settings_raw in inbounds:
    if not settings_raw:
        continue
    try:
        s_obj = json.loads(settings_raw)
        curr_clients = s_obj.get("clients", [])
        curr_map = {cl.get("id"): cl for cl in curr_clients}
        ib_changed = False

        for row in clients:
            uuid = row[3]
            email = row[1]
            sub_id = row[2]
            enable = bool(row[19])
            expiry = row[18] or 0

            if uuid not in curr_map:
                new_cl = {
                    "id": uuid,
                    "email": email,
                    "subId": sub_id,
                    "enable": enable,
                    "expiryTime": expiry,
                    "totalGB": 0,
                    "limitIp": 0,
                    "flow": "xtls-rprx-vision" if tag in ["inbound-23385", "inbound-24443"] else "",
                    "created_at": row[24] or 0,
                    "updated_at": row[25] or 0
                }
                curr_clients.append(new_cl)
                curr_map[uuid] = new_cl
                ib_changed = True
            else:
                cl = curr_map[uuid]
                if cl.get("enable") != enable or cl.get("expiryTime") != expiry or cl.get("subId") != sub_id:
                    cl["enable"] = enable
                    cl["expiryTime"] = expiry
                    cl["subId"] = sub_id
                    ib_changed = True

        if ib_changed:
            s_obj["clients"] = curr_clients
            c.execute("UPDATE inbounds SET settings=? WHERE id=?", (json.dumps(s_obj), ib_id))
            changed = True
    except Exception as e:
        print(f"Inbound update error: {e}", file=sys.stderr)

# Ensure client_inbounds table is synchronized for 3x-ui v2.4+
c.execute('''
CREATE TABLE IF NOT EXISTS `client_inbounds` (
    `client_id` integer,
    `inbound_id` integer,
    `flow_override` text,
    `created_at` integer,
    PRIMARY KEY (`client_id`,`inbound_id`)
)
''')
all_remote_clients = c.execute("SELECT id, email, uuid FROM clients").fetchall()
now_ms = int(time.time() * 1000)
for cid, email, uid in all_remote_clients:
    for ib_id, tag, _ in inbounds:
        flow = "xtls-rprx-vision" if tag in ["inbound-23385", "inbound-24443"] else ""
        exists = c.execute("SELECT 1 FROM client_inbounds WHERE client_id=? AND inbound_id=?", (cid, ib_id)).fetchone()
        if not exists:
            c.execute("INSERT INTO client_inbounds (client_id, inbound_id, flow_override, created_at) VALUES (?, ?, ?, ?)",
                      (cid, ib_id, flow, now_ms))
            changed = True

if changed:
    conn.commit()
    print("Database updated on remote.")
else:
    print("Database already up to date on remote.")
conn.close()

# If xray-maxru service exists (e.g. on FI), sync its config and reload
maxru_sync = "/usr/local/etc/xray-maxru/sync_xui_to_xray.py"
if os.path.exists(maxru_sync):
    try:
        res = subprocess.run(["python3", maxru_sync], capture_output=True, text=True, timeout=15)
        print("xray-maxru sync:", res.stdout.strip())
        subprocess.run(["systemctl", "restart", "xray-maxru"], check=False)
    except Exception as me:
        print("Error syncing xray-maxru:", me, file=sys.stderr)

# Restart x-ui and subjson if changes occurred
if changed:
    print("Restarting x-ui and subjson...")
    subprocess.run(["systemctl", "restart", "x-ui"], check=False)
    subprocess.run(["systemctl", "restart", "subjson"], check=False)
"""
    worker_cmd = f"cat << 'WORKER_EOF' > /tmp/xui_sync_worker.py\n{remote_worker}\nWORKER_EOF\n"
    subprocess.run(["ssh", "-o", "ConnectTimeout=10", "-o", "ConnectionAttempts=3", "-o", "StrictHostKeyChecking=no", remote_host, "bash"], input=worker_cmd, text=True, check=True)
    
    res = subprocess.run(["ssh", "-o", "ConnectTimeout=10", "-o", "ConnectionAttempts=3", "-o", "StrictHostKeyChecking=no", remote_host, "python3 /tmp/xui_sync_worker.py"], input=payload, text=True, capture_output=True)
    print(res.stdout)
    if res.stderr:
        print("Stderr:", res.stderr, file=sys.stderr)

if __name__ == "__main__":
    env_hosts = os.environ.get("SYNC_REMOTE_HOSTS", "").split(",")
    targets = [h.strip() for h in env_hosts if h.strip()]
    if not targets:
        pl_node = os.environ.get("PL_NODE_SSH", "root@pl.example.com")
        fi_node = os.environ.get("FI_NODE_SSH", "root@fi.example.com")
        targets = [pl_node, fi_node]
    for h in targets:
        try:
            sync_to_remote(h)
        except Exception as e:
            print(f"Failed sync to {h}: {e}", file=sys.stderr)
