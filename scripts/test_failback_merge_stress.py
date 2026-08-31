#!/usr/bin/env python3
"""
Adversarial Stress Test Suite for failback_merge.py (3-Way SQLite & X-UI Data Merger)
Author: challenger_v7_1
"""
import unittest
import os
import json
import sqlite3
import tempfile
import shutil
import time
from pathlib import Path

import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import failback_merge

class TestFailbackMergeStress(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="stress_failback_")
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
            CREATE TABLE trial_redemptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT UNIQUE,
                status TEXT,
                delivered_at INTEGER,
                created_at INTEGER,
                updated_at INTEGER
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

    # --------------------------------------------------------------------------
    # 1. Conflicting Renewal Dates and Timestamp Conflicts
    # --------------------------------------------------------------------------
    def test_conflicting_renewal_dates_and_timestamps(self):
        """Stress-test 3-way conflict resolution on subscription expiry and last_renewed_at."""
        # NL has 3 profiles:
        # p1: NL expires 10000, renewed 1000 -> FI renewed to 25000, renewed 2000 => Max wins (25000)
        # p2: NL expires 40000, renewed 3000 -> FI renewed to 20000, renewed 1500 => Max wins (40000)
        # p3: NL expires NULL -> FI expires 50000 => Max wins (50000)
        nl_conn = sqlite3.connect(self.nl_vpn)
        nl_cur = nl_conn.cursor()
        nl_cur.execute("INSERT INTO profiles VALUES (1, 'p1', 1, 'vless', 'client', 'P1', 'p1@sc.net', 'u1', 'active', 1000, 10000, 1000, NULL, 'nl');")
        nl_cur.execute("INSERT INTO profiles VALUES (2, 'p2', 1, 'vless', 'client', 'P2', 'p2@sc.net', 'u2', 'active', 1000, 40000, 3000, NULL, 'nl');")
        nl_cur.execute("INSERT INTO profiles VALUES (3, 'p3', 1, 'vless', 'client', 'P3', 'p3@sc.net', 'u3', 'expired', 1000, NULL, NULL, NULL, 'nl');")
        nl_conn.commit()
        nl_conn.close()

        fi_conn = sqlite3.connect(self.fi_vpn)
        fi_cur = fi_conn.cursor()
        fi_cur.execute("INSERT INTO profiles VALUES (1, 'p1', 1, 'vless', 'client', 'P1', 'p1@sc.net', 'u1', 'active', 1000, 25000, 2000, NULL, 'renewed on fi');")
        fi_cur.execute("INSERT INTO profiles VALUES (2, 'p2', 1, 'vless', 'client', 'P2', 'p2@sc.net', 'u2', 'active', 1000, 20000, 1500, NULL, 'older on fi');")
        fi_cur.execute("INSERT INTO profiles VALUES (3, 'p3', 1, 'vless', 'client', 'P3', 'p3@sc.net', 'u3', 'active', 1000, 50000, 4000, NULL, 'revived on fi');")
        fi_conn.commit()
        fi_conn.close()

        stats = failback_merge.merge_vpn_shop(self.nl_vpn, self.fi_vpn)
        self.assertEqual(stats["profiles_merged"], 3)

        res_conn = sqlite3.connect(self.nl_vpn)
        res_cur = res_conn.cursor()

        # Check p1
        res_cur.execute("SELECT expires_at, last_renewed_at, notes FROM profiles WHERE public_id = 'p1';")
        r1 = res_cur.fetchone()
        self.assertEqual(r1[0], 25000)
        self.assertEqual(r1[1], 2000)

        # Check p2
        res_cur.execute("SELECT expires_at, last_renewed_at FROM profiles WHERE public_id = 'p2';")
        r2 = res_cur.fetchone()
        self.assertEqual(r2[0], 40000)
        self.assertEqual(r2[1], 3000)

        # Check p3
        res_cur.execute("SELECT expires_at, status FROM profiles WHERE public_id = 'p3';")
        r3 = res_cur.fetchone()
        self.assertEqual(r3[0], 50000)
        self.assertEqual(r3[1], 'active')

        res_conn.close()

    # --------------------------------------------------------------------------
    # 2. Orphaned Foreign Keys and Corrupted References
    # --------------------------------------------------------------------------
    def test_orphaned_foreign_keys_resilience(self):
        """Verify that orders and ledger entries referencing non-existent profiles/referrers merge safely."""
        # NL has 1 profile with id=1, public_id='prof-existing'
        nl_conn = sqlite3.connect(self.nl_vpn)
        nl_cur = nl_conn.cursor()
        nl_cur.execute("INSERT INTO profiles VALUES (1, 'prof-existing', 1, 'vless', 'client', 'E', 'e@sc.net', 'u-e', 'active', 100, 1000, 100, NULL, 'ok');")
        nl_cur.execute("INSERT INTO referrers VALUES (1, 'u-ref1', 'REF1', 500, 100);")
        nl_conn.commit()
        nl_conn.close()

        # FI has:
        # - order1 referencing valid FI profile id=1 ('prof-existing') -> should remap to NL id 1
        # - order2 referencing ghost FI profile id=9999 (non-existent) -> should remap to None cleanly
        # - order3 referencing valid FI profile id=2 ('prof-new') -> should remap to NL new id
        # - referral_ledger referencing ghost referrer id=8888 -> should handle cleanly
        fi_conn = sqlite3.connect(self.fi_vpn)
        fi_cur = fi_conn.cursor()
        fi_cur.execute("INSERT INTO profiles VALUES (1, 'prof-existing', 1, 'vless', 'client', 'E', 'e@sc.net', 'u-e', 'active', 100, 1000, 100, NULL, 'ok');")
        fi_cur.execute("INSERT INTO profiles VALUES (2, 'prof-new', 1, 'vless', 'client', 'N', 'n@sc.net', 'u-n', 'active', 200, 2000, 200, NULL, 'new');")

        fi_cur.execute("INSERT INTO orders VALUES (10, 'ord-valid1', 'u1', 11, 'closed', 100, 30, 3, 'a@a.com', 1, 500, '{}', 500, 500);")
        fi_cur.execute("INSERT INTO orders VALUES (11, 'ord-ghost-fk', 'u2', 22, 'closed', 200, 30, 3, 'b@b.com', 9999, 600, '{}', 600, 600);")
        fi_cur.execute("INSERT INTO orders VALUES (12, 'ord-valid2', 'u3', 33, 'closed', 300, 30, 3, 'c@c.com', 2, 700, '{}', 700, 700);")

        fi_cur.execute("INSERT INTO referral_ledger VALUES (1, 'ord-ghost-fk', 8888, 'u2', 50, 'credited', 600);")
        fi_conn.commit()
        fi_conn.close()

        stats = failback_merge.merge_vpn_shop(self.nl_vpn, self.fi_vpn)
        self.assertEqual(stats["orders_inserted"], 3)
        self.assertEqual(stats["referral_ledger_merged"], 1)

        res_conn = sqlite3.connect(self.nl_vpn)
        res_cur = res_conn.cursor()

        # Check ord-valid1 -> provisioned_profile_id = 1
        res_cur.execute("SELECT provisioned_profile_id FROM orders WHERE public_id = 'ord-valid1';")
        self.assertEqual(res_cur.fetchone()[0], 1)

        # Check ord-ghost-fk -> provisioned_profile_id = None
        res_cur.execute("SELECT provisioned_profile_id FROM orders WHERE public_id = 'ord-ghost-fk';")
        self.assertIsNone(res_cur.fetchone()[0])

        # Check ord-valid2 -> provisioned_profile_id is the newly generated NL id for 'prof-new'
        res_cur.execute("SELECT id FROM profiles WHERE public_id = 'prof-new';")
        new_prof_id = res_cur.fetchone()[0]
        res_cur.execute("SELECT provisioned_profile_id FROM orders WHERE public_id = 'ord-valid2';")
        self.assertEqual(res_cur.fetchone()[0], new_prof_id)

        # Check referral ledger entry was recorded
        res_cur.execute("SELECT referrer_id, status FROM referral_ledger WHERE order_public_id = 'ord-ghost-fk';")
        r_entry = res_cur.fetchone()
        self.assertEqual(r_entry[0], 8888)
        self.assertEqual(r_entry[1], 'credited')

        res_conn.close()

    # --------------------------------------------------------------------------
    # 3. Traffic Delta Calculations (Counter Resets, Missing Baseline, 64-bit Overflow)
    # --------------------------------------------------------------------------
    def test_traffic_delta_edge_cases(self):
        """Stress-test traffic delta calculation under counter resets, missing baseline, and massive 64-bit counters."""
        TB_50 = 50 * 1024 * 1024 * 1024 * 1024 # 50 Terabytes

        # 1. Baseline:
        # - c_normal: up=100, down=200
        # - c_reset: up=500, down=800
        # - c_huge: up=TB_50, down=TB_50
        base_conn = sqlite3.connect(self.base_xui)
        base_cur = base_conn.cursor()
        base_cur.execute("INSERT INTO client_traffics VALUES (1, 1, 1, 'normal@sc.net', 100, 200, 1000, 0, 0, 10);")
        base_cur.execute("INSERT INTO client_traffics VALUES (2, 1, 1, 'reset@sc.net', 500, 800, 1000, 0, 0, 10);")
        base_cur.execute("INSERT INTO client_traffics VALUES (3, 1, 1, 'huge@sc.net', ?, ?, 1000, 0, 0, 10);", (TB_50, TB_50))
        base_conn.commit()
        base_conn.close()

        # 2. NL DB:
        # - c_normal: up=110, down=220 (10 up, 20 down occurred on NL)
        # - c_reset: up=520, down=820
        # - c_huge: up=TB_50 + 1000, down=TB_50 + 2000
        nl_conn = sqlite3.connect(self.nl_xui)
        nl_cur = nl_conn.cursor()
        nl_cur.execute("INSERT INTO inbounds (id, settings) VALUES (1, '{\"clients\": []}');")
        nl_cur.execute("INSERT INTO client_traffics VALUES (1, 1, 1, 'normal@sc.net', 110, 220, 1000, 0, 0, 15);")
        nl_cur.execute("INSERT INTO client_traffics VALUES (2, 1, 1, 'reset@sc.net', 520, 820, 1000, 0, 0, 15);")
        nl_cur.execute("INSERT INTO client_traffics VALUES (3, 1, 1, 'huge@sc.net', ?, ?, 1000, 0, 0, 15);", (TB_50 + 1000, TB_50 + 2000))
        nl_conn.commit()
        nl_conn.close()

        # 3. FI DB:
        # - c_normal: up=160, down=350 -> Delta should be: up=(160-100)=60, down=(350-200)=150
        # - c_reset: up=30, down=40 (daemon restarted, counters reset to zero!) -> Delta should be max(0, 30-500) = 0! NL not decreased.
        # - c_huge: up=TB_50 + 500000, down=TB_50 + 800000 -> Delta up=500000, down=800000
        # - c_new_fi: up=5000, down=8000 (created solely during FI outage) -> Added to NL
        fi_conn = sqlite3.connect(self.fi_xui)
        fi_cur = fi_conn.cursor()
        fi_cur.execute("INSERT INTO inbounds (id, settings) VALUES (1, '{\"clients\": [{\"email\": \"new_fi@sc.net\", \"expiryTime\": 99999}]}');")
        fi_cur.execute("INSERT INTO client_traffics VALUES (1, 1, 1, 'normal@sc.net', 160, 350, 1000, 0, 0, 25);")
        fi_cur.execute("INSERT INTO client_traffics VALUES (2, 1, 1, 'reset@sc.net', 30, 40, 1000, 0, 0, 25);")
        fi_cur.execute("INSERT INTO client_traffics VALUES (3, 1, 1, 'huge@sc.net', ?, ?, 1000, 0, 0, 25);", (TB_50 + 500000, TB_50 + 800000))
        fi_cur.execute("INSERT INTO client_traffics VALUES (4, 1, 1, 'new_fi@sc.net', 5000, 8000, 99999, 0, 0, 30);")
        fi_conn.commit()
        fi_conn.close()

        stats = failback_merge.merge_xui(self.nl_xui, self.fi_xui, baseline_db_path=self.base_xui)

        # Expected deltas:
        # normal: 60 up, 150 down
        # reset: 0 up, 0 down
        # huge: 500000 up, 800000 down
        # new_fi: 5000 up, 8000 down
        # Total up: 60 + 0 + 500000 + 5000 = 505060
        # Total down: 150 + 0 + 800000 + 8000 = 808150
        self.assertEqual(stats["total_up_delta_bytes"], 505060)
        self.assertEqual(stats["total_down_delta_bytes"], 808150)
        self.assertEqual(stats["traffic_clients_added"], 1)

        # Verify NL DB records
        res_conn = sqlite3.connect(self.nl_xui)
        res_cur = res_conn.cursor()

        # normal: NL 110 + 60 = 170 up, 220 + 150 = 370 down
        res_cur.execute("SELECT up, down FROM client_traffics WHERE email = 'normal@sc.net';")
        r_norm = res_cur.fetchone()
        self.assertEqual(r_norm[0], 170)
        self.assertEqual(r_norm[1], 370)

        # reset: NL 520 + 0 = 520 up, 820 + 0 = 820 down (counters not diminished!)
        res_cur.execute("SELECT up, down FROM client_traffics WHERE email = 'reset@sc.net';")
        r_reset = res_cur.fetchone()
        self.assertEqual(r_reset[0], 520)
        self.assertEqual(r_reset[1], 820)

        # huge: (TB_50 + 1000) + 500000 = TB_50 + 501000
        res_cur.execute("SELECT up, down FROM client_traffics WHERE email = 'huge@sc.net';")
        r_huge = res_cur.fetchone()
        self.assertEqual(r_huge[0], TB_50 + 501000)
        self.assertEqual(r_huge[1], TB_50 + 802000)

        # new_fi: inserted as 5000 up, 8000 down
        res_cur.execute("SELECT up, down, expiry_time FROM client_traffics WHERE email = 'new_fi@sc.net';")
        r_new = res_cur.fetchone()
        self.assertEqual(r_new[0], 5000)
        self.assertEqual(r_new[1], 8000)
        self.assertEqual(r_new[2], 99999)

        res_conn.close()

    # --------------------------------------------------------------------------
    # 4. Inbound Settings JSON Reconciliation Edge Cases
    # --------------------------------------------------------------------------
    def test_inbounds_json_settings_edge_cases(self):
        """Stress-test JSON settings merging with missing fields, malformed JSON resilience, and limitIp precedence."""
        nl_settings = {
            "clients": [
                {"id": "uuid-1", "email": "alice@sc.net", "limitIp": 2, "enable": False, "expiryTime": 1000},
                {"id": "uuid-2", "email": "bob@sc.net", "limitIp": 5, "enable": True, "expiryTime": 5000}
            ]
        }
        nl_conn = sqlite3.connect(self.nl_xui)
        nl_cur = nl_conn.cursor()
        nl_cur.execute("INSERT INTO inbounds (id, settings) VALUES (1, ?);", (json.dumps(nl_settings),))
        nl_conn.commit()
        nl_conn.close()

        fi_settings = {
            "clients": [
                # Alice renewed with limitIp upgraded to 4, enable=True, expiryTime=3000
                {"id": "uuid-1", "email": "alice@sc.net", "limitIp": 4, "enable": True, "expiryTime": 3000},
                # Bob limitIp was 3 (lower than NL's 5) -> NL's 5 should be preserved
                {"id": "uuid-2", "email": "bob@sc.net", "limitIp": 3, "enable": True, "expiryTime": 4000},
                # Charlie is new
                {"id": "uuid-3", "email": "charlie@sc.net", "limitIp": 3, "enable": True, "expiryTime": 8000}
            ]
        }
        fi_conn = sqlite3.connect(self.fi_xui)
        fi_cur = fi_conn.cursor()
        fi_cur.execute("INSERT INTO inbounds (id, settings) VALUES (1, ?);", (json.dumps(fi_settings),))
        fi_conn.commit()
        fi_conn.close()

        stats = failback_merge.merge_xui(self.nl_xui, self.fi_xui)
        self.assertEqual(stats["inbounds_clients_added"], 1)
        self.assertEqual(stats["inbounds_clients_updated"], 2)

        res_conn = sqlite3.connect(self.nl_xui)
        res_cur = res_conn.cursor()
        res_cur.execute("SELECT settings FROM inbounds WHERE id = 1;")
        merged_settings = json.loads(res_cur.fetchone()[0])
        clients = {c["email"]: c for c in merged_settings["clients"]}

        # Alice: limitIp=4, enable=True, expiryTime=3000
        self.assertEqual(clients["alice@sc.net"]["limitIp"], 4)
        self.assertEqual(clients["alice@sc.net"]["enable"], True)
        self.assertEqual(clients["alice@sc.net"]["expiryTime"], 3000)

        # Bob: limitIp=5 preserved, expiryTime=5000 preserved
        self.assertEqual(clients["bob@sc.net"]["limitIp"], 5)
        self.assertEqual(clients["bob@sc.net"]["expiryTime"], 5000)

        # Charlie: added
        self.assertIn("charlie@sc.net", clients)
        self.assertEqual(clients["charlie@sc.net"]["expiryTime"], 8000)

        res_conn.close()

    # --------------------------------------------------------------------------
    # 5. AWG Peers Obfuscation & Telemetry Merge
    # --------------------------------------------------------------------------
    def test_awg_peers_telemetry_merge(self):
        """Stress-test awg_peers synchronization across nodes."""
        nl_conn = sqlite3.connect(self.nl_vpn)
        nl_cur = nl_conn.cursor()
        nl_cur.execute("INSERT INTO awg_peers VALUES (1, 'sub-1', 'nl', '10.8.1.5', 1000, 50, 60, 1, NULL);")
        nl_cur.execute("INSERT INTO awg_peers VALUES (2, 'sub-2', 'nl', '10.8.1.6', 2000, 80, 90, 1, NULL);")
        nl_conn.commit()
        nl_conn.close()

        fi_conn = sqlite3.connect(self.fi_vpn)
        fi_cur = fi_conn.cursor()
        # sub-1 has higher traffic on FI
        fi_cur.execute("INSERT INTO awg_peers VALUES (1, 'sub-1', 'nl', '10.8.1.5', 5000, 150, 160, 1, NULL);")
        # sub-3 is new peer created on FI
        fi_cur.execute("INSERT INTO awg_peers VALUES (3, 'sub-3', 'fi', '10.8.2.5', 800, 30, 40, 1, NULL);")
        fi_conn.commit()
        fi_conn.close()

        stats = failback_merge.merge_vpn_shop(self.nl_vpn, self.fi_vpn)
        self.assertEqual(stats["awg_peers_merged"], 2)

        res_conn = sqlite3.connect(self.nl_vpn)
        res_cur = res_conn.cursor()

        # sub-1 merged with max bytes (5000), max rx (150), max tx (160)
        res_cur.execute("SELECT bytes_used, last_rx, last_tx FROM awg_peers WHERE sub_id = 'sub-1';")
        r1 = res_cur.fetchone()
        self.assertEqual(r1[0], 5000)
        self.assertEqual(r1[1], 150)
        self.assertEqual(r1[2], 160)

        # sub-3 inserted
        res_cur.execute("SELECT server_code, bytes_used FROM awg_peers WHERE sub_id = 'sub-3';")
        r3 = res_cur.fetchone()
        self.assertIsNotNone(r3)
        self.assertEqual(r3[0], 'fi')
        self.assertEqual(r3[1], 800)

        res_conn.close()

    # --------------------------------------------------------------------------
    # 6. Dry Run and Backup File Creation Verification
    # --------------------------------------------------------------------------
    def test_dry_run_and_backup_creation(self):
        """Verify dry-run mode makes NO disk modifications, and normal run creates valid backup file."""
        nl_conn = sqlite3.connect(self.nl_vpn)
        nl_cur = nl_conn.cursor()
        nl_cur.execute("INSERT INTO profiles VALUES (1, 'prof-x', 1, 'vless', 'client', 'X', 'x@sc.net', 'u-x', 'active', 100, 1000, 100, NULL, 'orig');")
        nl_conn.commit()
        nl_conn.close()

        fi_conn = sqlite3.connect(self.fi_vpn)
        fi_cur = fi_conn.cursor()
        fi_cur.execute("INSERT INTO profiles VALUES (1, 'prof-x', 1, 'vless', 'client', 'X', 'x@sc.net', 'u-x', 'active', 100, 9999, 500, NULL, 'modified');")
        fi_conn.commit()
        fi_conn.close()

        # 1. Dry run
        dry_stats = failback_merge.merge_vpn_shop(self.nl_vpn, self.fi_vpn, dry_run=True)
        self.assertEqual(dry_stats["profiles_merged"], 1)

        # Check NL DB was NOT modified
        c1 = sqlite3.connect(self.nl_vpn)
        r1 = c1.cursor().execute("SELECT expires_at, notes FROM profiles WHERE public_id = 'prof-x';").fetchone()
        self.assertEqual(r1[0], 1000)
        self.assertEqual(r1[1], 'orig')
        c1.close()

        # Check no .bak files were created during dry run
        bak_files_dry = list(Path(self.test_dir).glob("nl_vpn_shop.db.bak_*"))
        self.assertEqual(len(bak_files_dry), 0)

        # 2. Live run
        live_stats = failback_merge.merge_vpn_shop(self.nl_vpn, self.fi_vpn, dry_run=False)
        self.assertEqual(live_stats["profiles_merged"], 1)

        # Check NL DB WAS modified
        c2 = sqlite3.connect(self.nl_vpn)
        r2 = c2.cursor().execute("SELECT expires_at, notes FROM profiles WHERE public_id = 'prof-x';").fetchone()
        self.assertEqual(r2[0], 9999)
        c2.close()

        # Check .bak file was created and is a valid SQLite database
        bak_files_live = list(Path(self.test_dir).glob("nl_vpn_shop.db.bak_*"))
        self.assertGreaterEqual(len(bak_files_live), 1)
        bak_conn = sqlite3.connect(str(bak_files_live[0]))
        bak_cur = bak_conn.cursor()
        bak_cur.execute("PRAGMA integrity_check;")
        self.assertEqual(bak_cur.fetchone()[0], "ok")
        # Backup has original state
        bak_r = bak_cur.execute("SELECT expires_at FROM profiles WHERE public_id = 'prof-x';").fetchone()
        self.assertEqual(bak_r[0], 1000)
        bak_conn.close()

if __name__ == "__main__":
    unittest.main()
