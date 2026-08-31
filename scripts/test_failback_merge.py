#!/usr/bin/env python3
"""
Comprehensive automated synthetic test suite for failback_merge.py.
"""
import unittest
import os
import json
import sqlite3
import tempfile
import shutil
from pathlib import Path

import sys
sys.path.insert(0, "/usr/local/bin")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import failback_merge

class TestFailbackMerge(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_failback_")
        self.nl_vpn = os.path.join(self.test_dir, "nl_vpn_shop.db")
        self.fi_vpn = os.path.join(self.test_dir, "fi_vpn_shop.db")
        self.base_vpn = os.path.join(self.test_dir, "base_vpn_shop.db")

        self.nl_xui = os.path.join(self.test_dir, "nl_xui.db")
        self.fi_xui = os.path.join(self.test_dir, "fi_xui.db")
        self.base_xui = os.path.join(self.test_dir, "base_xui.db")

        self._create_vpn_schema(self.nl_vpn)
        self._create_vpn_schema(self.fi_vpn)
        self._create_vpn_schema(self.base_vpn)

        self._create_xui_schema(self.nl_xui)
        self._create_xui_schema(self.fi_xui)
        self._create_xui_schema(self.base_xui)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_vpn_schema(self, db_path: str):
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.executescript("""
            CREATE TABLE telegram_users (
                user_id TEXT PRIMARY KEY,
                chat_id INTEGER,
                username TEXT,
                first_name TEXT,
                last_name TEXT,
                is_bot INTEGER DEFAULT 0,
                last_seen_at INTEGER
            );
            CREATE TABLE referrers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT UNIQUE,
                code TEXT UNIQUE,
                balance_rub INTEGER DEFAULT 0,
                created_at INTEGER
            );
            CREATE TABLE profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                public_id TEXT UNIQUE,
                xui_inbound_id INTEGER,
                transport TEXT,
                profile_mode TEXT,
                family_label TEXT,
                xui_email TEXT UNIQUE,
                xui_client_id TEXT,
                status TEXT,
                created_at INTEGER,
                expires_at INTEGER,
                last_renewed_at INTEGER,
                deleted_at INTEGER,
                notes TEXT
            );
            CREATE TABLE orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                public_id TEXT UNIQUE,
                user_id TEXT,
                chat_id INTEGER,
                status TEXT,
                amount_rub INTEGER,
                duration_days INTEGER,
                device_limit INTEGER,
                customer_email TEXT,
                provisioned_profile_id INTEGER,
                closed_at INTEGER,
                meta_json TEXT,
                created_at INTEGER,
                updated_at INTEGER
            );
            CREATE TABLE profile_owners (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_public_id TEXT UNIQUE,
                user_id TEXT,
                chat_id INTEGER,
                source_order_public_id TEXT,
                created_at INTEGER,
                updated_at INTEGER
            );
            CREATE TABLE referral_ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                order_public_id TEXT UNIQUE,
                referrer_id INTEGER,
                buyer_user_id TEXT,
                reward_rub INTEGER,
                status TEXT,
                created_at INTEGER
            );
            CREATE TABLE awg_peers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sub_id TEXT,
                server_code TEXT,
                tunnel_ip TEXT,
                bytes_used INTEGER DEFAULT 0,
                last_rx INTEGER DEFAULT 0,
                last_tx INTEGER DEFAULT 0,
                active INTEGER DEFAULT 1,
                inactive_reason TEXT,
                UNIQUE(sub_id, server_code)
            );
        """)
        conn.commit()
        conn.close()

    def _create_xui_schema(self, db_path: str):
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.executescript("""
            CREATE TABLE inbounds (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                up INTEGER DEFAULT 0,
                down INTEGER DEFAULT 0,
                total INTEGER DEFAULT 0,
                remark TEXT,
                enable INTEGER DEFAULT 1,
                expiry_time INTEGER DEFAULT 0,
                listen TEXT,
                port INTEGER,
                protocol TEXT,
                settings TEXT,
                stream_settings TEXT,
                tag TEXT,
                sniffing TEXT
            );
            CREATE TABLE client_traffics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                inbound_id INTEGER,
                enable INTEGER DEFAULT 1,
                email TEXT UNIQUE,
                up INTEGER DEFAULT 0,
                down INTEGER DEFAULT 0,
                expiry_time INTEGER DEFAULT 0,
                total INTEGER DEFAULT 0,
                reset INTEGER DEFAULT 0,
                last_online INTEGER DEFAULT 0
            );
        """)
        conn.commit()
        conn.close()

    def test_vpn_shop_merge_new_orders_and_profiles(self):
        # 1. Seed NL DB
        nl_conn = sqlite3.connect(self.nl_vpn)
        nl_cur = nl_conn.cursor()
        nl_cur.execute("INSERT INTO telegram_users VALUES ('u1', 111, 'alice', 'Alice', '', 0, 1000);")
        nl_cur.execute("INSERT INTO profiles VALUES (1, 'prof-existing', 1, 'vless', 'client', 'Alice', 'alice@sc.net', 'uuid-1', 'active', 1000, 2000, 1000, NULL, 'orig');")
        nl_cur.execute("INSERT INTO orders VALUES (1, 'ord-old', 'u1', 111, 'closed', 149, 30, 3, 'a@a.com', 1, 1000, '{}', 1000, 1000);")
        nl_conn.commit()
        nl_conn.close()

        # 2. Seed FI DB with:
        # - Updated expiry on 'prof-existing'
        # - Brand new profile 'prof-new'
        # - Brand new order 'ord-new' linked to 'prof-new' (FI local id=2, which maps to NL new id)
        fi_conn = sqlite3.connect(self.fi_vpn)
        fi_cur = fi_conn.cursor()
        fi_cur.execute("INSERT INTO telegram_users VALUES ('u1', 111, 'alice', 'Alice', '', 0, 1500);")
        fi_cur.execute("INSERT INTO telegram_users VALUES ('u2', 222, 'bob', 'Bob', '', 0, 1200);")
        fi_cur.execute("INSERT INTO profiles VALUES (1, 'prof-existing', 1, 'vless', 'client', 'Alice', 'alice@sc.net', 'uuid-1', 'active', 1000, 5000, 1500, NULL, 'renewed on fi');")
        fi_cur.execute("INSERT INTO profiles VALUES (2, 'prof-new', 1, 'vless', 'client', 'Bob', 'bob@sc.net', 'uuid-2', 'active', 1200, 6000, 1200, NULL, 'created on fi');")
        fi_cur.execute("INSERT INTO orders VALUES (2, 'ord-new', 'u2', 222, 'closed', 199, 30, 3, 'b@b.com', 2, 1200, '{}', 1200, 1200);")
        fi_conn.commit()
        fi_conn.close()

        # Run merge
        stats = failback_merge.merge_vpn_shop(self.nl_vpn, self.fi_vpn)
        self.assertEqual(stats["profiles_inserted"], 1)
        self.assertEqual(stats["orders_inserted"], 1)

        # Verify merged state in NL
        res_conn = sqlite3.connect(self.nl_vpn)
        res_cur = res_conn.cursor()

        # Check existing profile updated expiry
        res_cur.execute("SELECT expires_at, last_renewed_at, notes FROM profiles WHERE public_id = 'prof-existing';")
        row = res_cur.fetchone()
        self.assertEqual(row[0], 5000)
        self.assertEqual(row[1], 1500)

        # Check new profile inserted
        res_cur.execute("SELECT id, public_id FROM profiles WHERE public_id = 'prof-new';")
        prof_new = res_cur.fetchone()
        self.assertIsNotNone(prof_new)
        prof_new_nl_id = prof_new[0]

        # Check new order inserted with remapped provisioned_profile_id
        res_cur.execute("SELECT provisioned_profile_id, status FROM orders WHERE public_id = 'ord-new';")
        ord_new = res_cur.fetchone()
        self.assertIsNotNone(ord_new)
        self.assertEqual(ord_new[0], prof_new_nl_id)
        self.assertEqual(ord_new[1], 'closed')

        res_conn.close()

    def test_xui_merge_inbounds_and_traffic_deltas(self):
        # 1. Baseline DB: client1 had 100 MB up, 200 MB down
        base_conn = sqlite3.connect(self.base_xui)
        base_cur = base_conn.cursor()
        base_cur.execute("INSERT INTO client_traffics VALUES (1, 1, 1, 'client1@sc.net', 100, 200, 10000, 0, 0, 500);")
        base_conn.commit()
        base_conn.close()

        # 2. NL DB: client1 has 120 MB up, 210 MB down
        nl_inbound_settings = {
            "clients": [
                {"id": "uuid-1", "email": "client1@sc.net", "expiryTime": 10000, "enable": True, "limitIp": 3}
            ]
        }
        nl_conn = sqlite3.connect(self.nl_xui)
        nl_cur = nl_conn.cursor()
        nl_cur.execute("INSERT INTO inbounds (id, settings) VALUES (1, ?);", (json.dumps(nl_inbound_settings),))
        nl_cur.execute("INSERT INTO client_traffics VALUES (1, 1, 1, 'client1@sc.net', 120, 210, 10000, 0, 0, 550);")
        nl_conn.commit()
        nl_conn.close()

        # 3. FI DB: client1 generated +50 MB up (total 150), +80 MB down (total 280), expiry extended to 20000
        # and client2 was created
        fi_inbound_settings = {
            "clients": [
                {"id": "uuid-1", "email": "client1@sc.net", "expiryTime": 20000, "enable": True, "limitIp": 3},
                {"id": "uuid-2", "email": "client2@sc.net", "expiryTime": 15000, "enable": True, "limitIp": 5}
            ]
        }
        fi_conn = sqlite3.connect(self.fi_xui)
        fi_cur = fi_conn.cursor()
        fi_cur.execute("INSERT INTO inbounds (id, settings) VALUES (1, ?);", (json.dumps(fi_inbound_settings),))
        fi_cur.execute("INSERT INTO client_traffics VALUES (1, 1, 1, 'client1@sc.net', 150, 280, 20000, 0, 0, 700);")
        fi_cur.execute("INSERT INTO client_traffics VALUES (2, 1, 1, 'client2@sc.net', 30, 40, 15000, 0, 0, 650);")
        fi_conn.commit()
        fi_conn.close()

        # Run merge with baseline
        stats = failback_merge.merge_xui(self.nl_xui, self.fi_xui, baseline_db_path=self.base_xui)
        self.assertEqual(stats["inbounds_clients_added"], 1)
        self.assertEqual(stats["inbounds_clients_updated"], 1)
        self.assertEqual(stats["total_up_delta_bytes"], 50 + 30) # (150-100) + 30
        self.assertEqual(stats["total_down_delta_bytes"], 80 + 40) # (280-200) + 40

        # Verify NL DB
        res_conn = sqlite3.connect(self.nl_xui)
        res_cur = res_conn.cursor()

        # Check client1 traffic: 120 + 50 = 170 up, 210 + 80 = 290 down, expiry 20000, last_online 700
        res_cur.execute("SELECT up, down, expiry_time, last_online FROM client_traffics WHERE email = 'client1@sc.net';")
        c1 = res_cur.fetchone()
        self.assertEqual(c1[0], 170)
        self.assertEqual(c1[1], 290)
        self.assertEqual(c1[2], 20000)
        self.assertEqual(c1[3], 700)

        # Check client2 inserted
        res_cur.execute("SELECT up, down, expiry_time FROM client_traffics WHERE email = 'client2@sc.net';")
        c2 = res_cur.fetchone()
        self.assertIsNotNone(c2)
        self.assertEqual(c2[0], 30)
        self.assertEqual(c2[1], 40)

        # Check inbounds JSON
        res_cur.execute("SELECT settings FROM inbounds WHERE id = 1;")
        inbound_json = json.loads(res_cur.fetchone()[0])
        clients = {c["email"]: c for c in inbound_json["clients"]}
        self.assertIn("client1@sc.net", clients)
        self.assertIn("client2@sc.net", clients)
        self.assertEqual(clients["client1@sc.net"]["expiryTime"], 20000)
        self.assertEqual(clients["client2@sc.net"]["limitIp"], 5)

        res_conn.close()

if __name__ == "__main__":
    unittest.main()
