#!/usr/bin/env python3
import json
import sqlite3
import tempfile
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "vpn-shop"))

from vpn_shop.xui_db import XuiDatabase

class TestXuiDatabaseMultiInboundRenewal(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="test_xui_db_"))
        self.db_path = self.temp_dir / "x-ui.db"
        
        # Create mock 3x-ui schema
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute("""
        CREATE TABLE inbounds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            up INTEGER,
            down INTEGER,
            total INTEGER,
            remark TEXT,
            enable INTEGER,
            port INTEGER,
            protocol TEXT,
            settings TEXT,
            stream_settings TEXT,
            tag TEXT,
            sniffing TEXT
        )
        """)
        
        c.execute("""
        CREATE TABLE clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            inbound_id INTEGER,
            enable INTEGER,
            email TEXT UNIQUE,
            uuid TEXT UNIQUE,
            sub_id TEXT,
            expiry_time INTEGER,
            limit_ip INTEGER,
            updated_at INTEGER
        )
        """)
        
        c.execute("""
        CREATE TABLE client_traffics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            inbound_id INTEGER,
            enable INTEGER,
            email TEXT UNIQUE,
            up INTEGER,
            down INTEGER,
            expiry_time INTEGER,
            total INTEGER,
            reset INTEGER,
            last_online INTEGER
        )
        """)
        
        c.execute("""
        CREATE TABLE client_inbounds (
            client_id INTEGER,
            inbound_id INTEGER,
            flow_override TEXT,
            created_at INTEGER,
            PRIMARY KEY (client_id, inbound_id)
        )
        """)
        
        # Insert 2 inbounds: id 1 (port 8443) and id 2 (port 23385)
        # Client is expired (expiry_time = 1000, enable = False / 0)
        client_data_1 = [{"id": "test-uuid-1", "email": "test@user.com", "enable": False, "expiryTime": 1000}]
        client_data_2 = [{"id": "test-uuid-1", "email": "test@user.com", "enable": False, "expiryTime": 1000}]
        
        c.execute("INSERT INTO inbounds (id, remark, port, protocol, settings, stream_settings, sniffing) VALUES (?, ?, ?, ?, ?, ?, ?)",
                  (1, "inbound-8443", 8443, "vless", json.dumps({"clients": client_data_1}), "{}", "{}"))
        c.execute("INSERT INTO inbounds (id, remark, port, protocol, settings, stream_settings, sniffing) VALUES (?, ?, ?, ?, ?, ?, ?)",
                  (2, "inbound-23385", 23385, "vless", json.dumps({"clients": client_data_2}), "{}", "{}"))
        
        c.execute("INSERT INTO clients (id, inbound_id, enable, email, uuid, sub_id, expiry_time, limit_ip, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                  (1, 1, 0, "test@user.com", "test-uuid-1", "sub123", 1000, 3, 1000))
        
        c.execute("INSERT INTO client_traffics (inbound_id, enable, email, up, down, expiry_time, total) VALUES (?, ?, ?, 0, 0, ?, 0)",
                  (1, 0, "test@user.com", 1000))
        
        conn.commit()
        conn.close()
        
        self.xui = XuiDatabase(self.db_path)

    def test_update_client_expiry_direct_updates_all_inbounds_and_clients_table(self):
        new_expiry_ms = 2000000000000
        success = self.xui.update_client_expiry_direct(1, "test@user.com", new_expiry_ms, enable=True, device_limit=6)
        self.assertTrue(success)

        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        # 1. Check clients table was updated
        cl = c.execute("SELECT enable, expiry_time, limit_ip FROM clients WHERE email='test@user.com'").fetchone()
        self.assertEqual(cl[0], 1)
        self.assertEqual(cl[1], new_expiry_ms)
        self.assertEqual(cl[2], 6)

        # 2. Check BOTH inbounds were updated (not just inbound 1!)
        for ib_id in (1, 2):
            raw = c.execute("SELECT settings FROM inbounds WHERE id=?", (ib_id,)).fetchone()[0]
            st = json.loads(raw)
            client_entry = st["clients"][0]
            self.assertTrue(client_entry["enable"])
            self.assertEqual(client_entry["expiryTime"], new_expiry_ms)
            self.assertEqual(client_entry.get("limitIp"), 6)

        # 3. Check client_traffics was updated
        tr = c.execute("SELECT enable, expiry_time FROM client_traffics WHERE email='test@user.com'").fetchone()
        self.assertEqual(tr[0], 1)
        self.assertEqual(tr[1], new_expiry_ms)

        # 4. Check client_inbounds mapping was created for both inbounds
        ci = c.execute("SELECT inbound_id FROM client_inbounds WHERE client_id=1").fetchall()
        inbound_ids = {r[0] for r in ci}
        self.assertEqual(inbound_ids, {1, 2})

        conn.close()

if __name__ == '__main__':
    unittest.main()
