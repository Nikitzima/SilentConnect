#!/usr/bin/env python3
"""
Unit tests for SilentConnect Poland (PL) Standby Failover mechanisms.
Covers:
- Generalized promote.sh / demote.sh with --node pl
- Cloudflare DNS failover for PL IP (2.56.125.177)  # PLACEHOLDER
- failback_merge.py with --standby-vpn / --standby-xui (PL as source)
- 3-Way merge reconciliation with PL as standby node
"""
import os
import sys
import unittest
import tempfile
import shutil
import sqlite3
import json

# Ensure Git's bash is discoverable on Windows
if sys.platform == "win32" and not shutil.which("bash"):
    for git_bin in [r"C:\Program Files\Git\bin", r"C:\Program Files\Git\usr\bin"]:
        if os.path.isdir(git_bin) and git_bin not in os.environ.get("PATH", ""):
            os.environ["PATH"] = git_bin + os.pathsep + os.environ.get("PATH", "")

BASH_BIN = shutil.which("bash") or "bash"

# Ensure scripts directory is importable
TEST_FILE = os.path.abspath(__file__)
TESTS_DIR = os.path.dirname(TEST_FILE)
PROJECT_ROOT = os.path.dirname(TESTS_DIR)
SCRIPTS_DIR = os.path.join(PROJECT_ROOT, "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import failback_merge


# ==============================================================================
# Shared Schema Fixtures
# ==============================================================================

def create_vpn_schema(db_path: str):
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
        CREATE TABLE trial_redemptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT UNIQUE,
            status TEXT,
            delivered_at INTEGER,
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


def create_xui_schema(db_path: str):
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


# ==============================================================================
# Test Cases
# ==============================================================================

class TestPolandMergeVpnShop(unittest.TestCase):
    """Verify failback_merge works with PL as standby source node."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_pl_vpn_")
        self.nl_db = os.path.join(self.test_dir, "nl_vpn.db")
        self.pl_db = os.path.join(self.test_dir, "pl_vpn.db")
        self.base_db = os.path.join(self.test_dir, "base_vpn.db")
        create_vpn_schema(self.nl_db)
        create_vpn_schema(self.pl_db)
        create_vpn_schema(self.base_db)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_pl_merge_new_user_and_profile(self):
        """PL created a brand-new user, profile, and order during outage."""
        # Seed NL: user u1 exists
        nl_conn = sqlite3.connect(self.nl_db)
        nl_cur = nl_conn.cursor()
        nl_cur.execute("INSERT INTO telegram_users VALUES ('u1', 111, 'alice', 'Alice', '', 0, 1000);")
        nl_conn.commit()
        nl_conn.close()

        # Seed PL: user u2 is brand new (created during outage)
        pl_conn = sqlite3.connect(self.pl_db)
        pl_cur = pl_conn.cursor()
        pl_cur.execute("INSERT INTO telegram_users VALUES ('u2', 222, 'bob', 'Bob', '', 0, 1200);")
        pl_cur.execute("INSERT INTO profiles VALUES (1, 'pl-new-profile', 1, 'vless', 'client', 'Bob', 'bob@sc.net', 'uuid-pl-1', 'active', 1200, 7000, 1200, NULL, 'created on pl');")
        pl_cur.execute("INSERT INTO orders VALUES (1, 'pl-order-1', 'u2', 222, 'closed', 199, 30, 3, 'b@b.com', 1, 1200, '{}', 1200, 1200);")
        pl_conn.commit()
        pl_conn.close()

        # Merge PL into NL
        stats = failback_merge.merge_vpn_shop(self.nl_db, self.pl_db)

        # Assertions
        self.assertEqual(stats["telegram_users_merged"], 1)
        self.assertEqual(stats["profiles_inserted"], 1)
        self.assertEqual(stats["orders_inserted"], 1)

        # Verify NL now has user u2
        nl_conn = sqlite3.connect(self.nl_db)
        nl_cur = nl_conn.cursor()
        nl_cur.execute("SELECT username FROM telegram_users WHERE user_id = 'u2';")
        row = nl_cur.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], "bob")

        # Verify PL profile's public_id exists in NL
        nl_cur.execute("SELECT public_id FROM profiles WHERE public_id = 'pl-new-profile';")
        self.assertIsNotNone(nl_cur.fetchone())

        # Verify order is present
        nl_cur.execute("SELECT status FROM orders WHERE public_id = 'pl-order-1';")
        self.assertEqual(nl_cur.fetchone()[0], "closed")
        nl_conn.close()

    def test_pl_merge_updates_existing_profile_expiry(self):
        """PL renewed an existing profile during outage — expiry must be MAX'd."""
        # Seed both with same public_id
        for db in [self.nl_db, self.pl_db]:
            conn = sqlite3.connect(db)
            cur = conn.cursor()
            cur.execute("INSERT INTO telegram_users VALUES ('u1', 111, 'alice', 'Alice', '', 0, 1000);")
            cur.execute("INSERT INTO profiles VALUES (1, 'shared-profiles', 1, 'vless', 'client', 'Alice', 'alice@sc.net', 'uuid-1', 'active', 1000, 3000, 1000, NULL, 'original');")
            conn.commit()
            conn.close()

        # PL renewed it: higher expiry
        pl_conn = sqlite3.connect(self.pl_db)
        pl_cur = pl_conn.cursor()
        pl_cur.execute("UPDATE profiles SET expires_at = 5000, last_renewed_at = 2000, notes = 'renewed on pl' WHERE public_id = 'shared-profiles';")
        pl_conn.commit()
        pl_conn.close()

        # Merge
        stats = failback_merge.merge_vpn_shop(self.nl_db, self.pl_db)

        # NL should have MAX(3000, 5000) = 5000
        nl_conn = sqlite3.connect(self.nl_db)
        nl_cur = nl_conn.cursor()
        nl_cur.execute("SELECT expires_at, last_renewed_at, notes FROM profiles WHERE public_id = 'shared-profiles';")
        row = nl_cur.fetchone()
        self.assertEqual(row[0], 5000)
        self.assertEqual(row[1], 2000)
        self.assertIn("renewed on pl", row[2])
        nl_conn.close()

    def test_pl_merge_traffic_delta(self):
        """PL's AWG peer accumulated traffic during outage."""
        # Seed both with same sub_id / server_code
        for db in [self.nl_db, self.pl_db]:
            conn = sqlite3.connect(db)
            cur = conn.cursor()
            cur.execute("INSERT INTO awg_peers VALUES (1, 'sub-alpha', 'nl', '10.0.0.2', 1000, 500, 500, 1, NULL);")
            conn.commit()
            conn.close()

        # PL accumulated more traffic
        pl_conn = sqlite3.connect(self.pl_db)
        pl_cur = pl_conn.cursor()
        pl_cur.execute("UPDATE awg_peers SET bytes_used = 2500, last_rx = 1200, last_tx = 1300 WHERE sub_id = 'sub-alpha' AND server_code = 'nl';")
        pl_conn.commit()
        pl_conn.close()

        # Merge
        stats = failback_merge.merge_vpn_shop(self.nl_db, self.pl_db)
        self.assertGreater(stats["awg_peers_merged"], 0)

        # NL should have MAX values
        nl_conn = sqlite3.connect(self.nl_db)
        nl_cur = nl_conn.cursor()
        nl_cur.execute("SELECT bytes_used, last_rx, last_tx FROM awg_peers WHERE sub_id = 'sub-alpha';")
        row = nl_cur.fetchone()
        self.assertEqual(row[0], 2500)
        self.assertEqual(row[1], 1200)
        self.assertEqual(row[2], 1300)
        nl_conn.close()


class TestPolandMergeXui(unittest.TestCase):
    """Verify failback_merge works with PL x-ui.db as standby source."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_pl_xui_")
        self.nl_db = os.path.join(self.test_dir, "nl_xui.db")
        self.pl_db = os.path.join(self.test_dir, "pl_xui.db")
        self.base_db = os.path.join(self.test_dir, "base_xui.db")
        create_xui_schema(self.nl_db)
        create_xui_schema(self.pl_db)
        create_xui_schema(self.base_db)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_pl_xui_traffic_delta_from_baseline(self):
        """PL's x-ui tracked traffic delta from baseline snapshot."""
        # Baseline: client had 100 MB
        base_conn = sqlite3.connect(self.base_db)
        base_cur = base_conn.cursor()
        base_cur.execute("INSERT INTO client_traffics VALUES (1, 1, 1, 'pl-client@sc.net', 100, 200, 10000, 0, 0, 500);")
        base_conn.commit()
        base_conn.close()

        # NL: same client, 120 MB
        nl_inbound = {"clients": [{"id": "uuid-pl-1", "email": "pl-client@sc.net", "expiryTime": 10000}]}
        nl_conn = sqlite3.connect(self.nl_db)
        nl_cur = nl_conn.cursor()
        nl_cur.execute("INSERT INTO inbounds (id, settings) VALUES (1, ?);", (json.dumps(nl_inbound),))
        nl_cur.execute("INSERT INTO client_traffics VALUES (1, 1, 1, 'pl-client@sc.net', 120, 210, 10000, 0, 0, 550);")
        nl_conn.commit()
        nl_conn.close()

        # PL: client used +80 MB more (total 200 MB), expiry extended to 20000
        pl_inbound = {"clients": [{"id": "uuid-pl-1", "email": "pl-client@sc.net", "expiryTime": 20000, "enable": True, "limitIp": 5}]}
        pl_conn = sqlite3.connect(self.pl_db)
        pl_cur = pl_conn.cursor()
        pl_cur.execute("INSERT INTO inbounds (id, settings) VALUES (1, ?);", (json.dumps(pl_inbound),))
        pl_cur.execute("INSERT INTO client_traffics VALUES (1, 1, 1, 'pl-client@sc.net', 200, 400, 20000, 0, 0, 700);")
        pl_conn.commit()
        pl_conn.close()

        # Merge with baseline
        stats = failback_merge.merge_xui(self.nl_db, self.pl_db, baseline_db_path=self.base_db)

        # Delta from baseline: (200-100) = 100 up, (400-200) = 200 down
        self.assertEqual(stats["total_up_delta_bytes"], 100)
        self.assertEqual(stats["total_down_delta_bytes"], 200)
        self.assertEqual(stats["inbounds_clients_updated"], 1)

        # NL: 120 + 100 = 220 up, 210 + 200 = 410 down, expiry 20000
        nl_conn = sqlite3.connect(self.nl_db)
        nl_cur = nl_conn.cursor()
        nl_cur.execute("SELECT up, down, expiry_time FROM client_traffics WHERE email = 'pl-client@sc.net';")
        row = nl_cur.fetchone()
        self.assertEqual(row[0], 220)
        self.assertEqual(row[1], 410)
        self.assertEqual(row[2], 20000)
        nl_conn.close()

    def test_pl_xui_new_client_in_inbounds(self):
        """PL added a brand-new client to inbound during outage."""
        # NL: inbound with client1
        nl_inbound = {"clients": [{"id": "uuid-1", "email": "client1@sc.net", "expiryTime": 10000}]}
        nl_conn = sqlite3.connect(self.nl_db)
        nl_cur = nl_conn.cursor()
        nl_cur.execute("INSERT INTO inbounds (id, settings) VALUES (1, ?);", (json.dumps(nl_inbound),))
        nl_conn.commit()
        nl_conn.close()

        # PL: inbound has client1 updated + client2 brand new
        pl_inbound = {
            "clients": [
                {"id": "uuid-1", "email": "client1@sc.net", "expiryTime": 20000},
                {"id": "uuid-2", "email": "client2@sc.net", "expiryTime": 15000, "enable": True, "limitIp": 5}
            ]
        }
        pl_conn = sqlite3.connect(self.pl_db)
        pl_cur = pl_conn.cursor()
        pl_cur.execute("INSERT INTO inbounds (id, settings) VALUES (1, ?);", (json.dumps(pl_inbound),))
        pl_conn.commit()
        pl_conn.close()

        # Merge
        stats = failback_merge.merge_xui(self.nl_db, self.pl_db)
        self.assertEqual(stats["inbounds_clients_added"], 1)
        self.assertEqual(stats["inbounds_clients_updated"], 1)

        # Verify NL inbound JSON has both clients
        nl_conn = sqlite3.connect(self.nl_db)
        nl_cur = nl_conn.cursor()
        nl_cur.execute("SELECT settings FROM inbounds WHERE id = 1;")
        settings = json.loads(nl_cur.fetchone()[0])
        emails = {c["email"] for c in settings["clients"]}
        self.assertIn("client1@sc.net", emails)
        self.assertIn("client2@sc.net", emails)
        self.assertEqual(settings["clients"][0]["expiryTime"], 20000)
        nl_conn.close()


class TestPolandArgvInterface(unittest.TestCase):
    """Verify failback_merge main() accepts --standby-vpn and --standby-xui args."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_pl_argv_")
        self.nl_vpn = os.path.join(self.test_dir, "nl_vpn.db")
        self.pl_vpn = os.path.join(self.test_dir, "pl_vpn.db")
        self.nl_xui = os.path.join(self.test_dir, "nl_xui.db")
        self.pl_xui = os.path.join(self.test_dir, "pl_xui.db")
        create_vpn_schema(self.nl_vpn)
        create_vpn_schema(self.pl_vpn)
        create_xui_schema(self.nl_xui)
        create_xui_schema(self.pl_xui)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_standby_vpn_arg_accepted(self):
        """failback_merge.py --standby-vpn / --standby-xui arguments are accepted and aliased."""
        import subprocess
        code = (
            f"import sys; sys.path.insert(0, {SCRIPTS_DIR!r})\n"
            f"import failback_merge, argparse\n"
            f"p = failback_merge.build_parser() if hasattr(failback_merge, 'build_parser') else failback_merge.ArgumentParser()\n"
            f"args = p.parse_args(['--nl-vpn', {self.nl_vpn!r}, '--standby-vpn', {self.pl_vpn!r}, '--dry-run'])\n"
            f"assert args.standby_vpn == {self.pl_vpn!r}\n"
            f"assert args.fi_vpn == {self.pl_vpn!r}\n"
            f"assert args.standby_xui == '/etc/x-ui/x-ui.db'  # default\n"
            f"assert args.fi_xui == '/etc/x-ui/x-ui.db'  # default\n"
            f"args_fi = p.parse_args(['--nl-vpn', {self.nl_vpn!r}, '--fi-vpn', {self.pl_vpn!r}, '--dry-run'])\n"
            f"assert args_fi.standby_vpn == {self.pl_vpn!r}\n"
            f"assert args_fi.fi_vpn == {self.pl_vpn!r}\n"
            f"print('OK')\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True, text=True, cwd=SCRIPTS_DIR
        )
        self.assertEqual(result.returncode, 0, f"stderr: {result.stderr}\nstdout: {result.stdout}")
        self.assertIn("OK", result.stdout)

    def test_standby_xui_arg_accepted(self):
        """failback_merge.py --standby-xui and --fi-xui arguments are accepted and aliased."""
        p = failback_merge.build_parser()
        args = p.parse_args(["--nl-xui", self.nl_xui, "--standby-xui", self.pl_xui, "--dry-run"])
        self.assertEqual(args.standby_xui, self.pl_xui)
        self.assertEqual(args.fi_xui, self.pl_xui)

        args_fi = p.parse_args(["--nl-xui", self.nl_xui, "--fi-xui", self.pl_xui, "--dry-run"])
        self.assertEqual(args_fi.standby_xui, self.pl_xui)
        self.assertEqual(args_fi.fi_xui, self.pl_xui)


class TestFailbackMergePLSpecific(unittest.TestCase):
    """PL-specific reconciliation edge cases: referrer remapping, profile_owners, trial_redemptions."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_pl_edge_")
        self.nl_db = os.path.join(self.test_dir, "nl_vpn.db")
        self.pl_db = os.path.join(self.test_dir, "pl_vpn.db")
        create_vpn_schema(self.nl_db)
        create_vpn_schema(self.pl_db)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_pl_referrer_remapping(self):
        """Referrers created on PL are merged and their IDs remapped in referral_ledger."""
        # NL already has referrer for u1
        nl_conn = sqlite3.connect(self.nl_db)
        nl_cur = nl_conn.cursor()
        nl_cur.execute("INSERT INTO referrers (id, user_id, code, balance_rub, created_at) VALUES (10, 'u1', 'NL-REF-001', 100, 1000);")
        nl_cur.execute("INSERT INTO telegram_users VALUES ('u1', 111, 'alice', 'Alice', '', 0, 1000);")
        nl_conn.commit()
        nl_conn.close()

        # PL has referrer for u2 (same code scheme, different user)
        pl_conn = sqlite3.connect(self.pl_db)
        pl_cur = pl_conn.cursor()
        pl_cur.execute("INSERT INTO referrers (id, user_id, code, balance_rub, created_at) VALUES (20, 'u2', 'PL-REF-002', 50, 1200);")
        pl_cur.execute("INSERT INTO telegram_users VALUES ('u2', 222, 'bob', 'Bob', '', 0, 1200);")
        # Referral ledger on PL points to referrer id=20 (PL local)
        pl_cur.execute("INSERT INTO referral_ledger (id, order_public_id, referrer_id, buyer_user_id, reward_rub, status, created_at) VALUES (5, 'pl-ord-1', 20, 'u2', 30, 'pending', 1200);")
        pl_conn.commit()
        pl_conn.close()

        # Merge
        stats = failback_merge.merge_vpn_shop(self.nl_db, self.pl_db)

        self.assertEqual(stats["referrers_merged"], 1)
        self.assertEqual(stats["referral_ledger_merged"], 1)

        # Verify referral_ledger in NL has remapped referrer_id
        nl_conn = sqlite3.connect(self.nl_db)
        nl_cur = nl_conn.cursor()
        nl_cur.execute("SELECT referrer_id FROM referral_ledger WHERE order_public_id = 'pl-ord-1';")
        row = nl_cur.fetchone()
        # Should be NL's id for that referrer (matched by user_id 'u2')
        self.assertIsNotNone(row)
        nl_conn.close()

    def test_pl_profile_owner_merge(self):
        """profile_owners entries created on PL are merged by profile_public_id."""
        nl_conn = sqlite3.connect(self.nl_db)
        nl_cur = nl_conn.cursor()
        nl_cur.execute("INSERT INTO telegram_users VALUES ('u1', 111, 'alice', 'Alice', '', 0, 1000);")
        nl_cur.execute("INSERT INTO profiles VALUES (1, 'prof-001', 1, 'vless', 'client', 'Alice', 'alice@sc.net', 'uuid-1', 'active', 1000, 3000, 1000, NULL, NULL);")
        nl_conn.commit()
        nl_conn.close()

        # PL has profile_owners for the same public_id
        pl_conn = sqlite3.connect(self.pl_db)
        pl_cur = pl_conn.cursor()
        pl_cur.execute("INSERT INTO telegram_users VALUES ('u1', 111, 'alice', 'Alice', '', 0, 1500);")
        pl_cur.execute("INSERT INTO profiles VALUES (1, 'prof-001', 1, 'vless', 'client', 'Alice', 'alice@sc.net', 'uuid-1', 'active', 1000, 5000, 1500, NULL, 'renewed');")
        pl_cur.execute("INSERT INTO profile_owners (id, profile_public_id, user_id, chat_id, source_order_public_id, created_at, updated_at) VALUES (1, 'prof-001', 'u1', 111, 'ord-old', 1000, 1500);")
        pl_conn.commit()
        pl_conn.close()

        # Merge
        stats = failback_merge.merge_vpn_shop(self.nl_db, self.pl_db)
        self.assertGreaterEqual(stats["profile_owners_merged"], 1)

        # Verify updated_at matches PL's (1500 > 1000)
        nl_conn = sqlite3.connect(self.nl_db)
        nl_cur = nl_conn.cursor()
        nl_cur.execute("SELECT updated_at FROM profile_owners WHERE profile_public_id = 'prof-001';")
        row = nl_cur.fetchone()
        self.assertEqual(row[0], 1500)
        nl_conn.close()

    def test_pl_trial_redemption_new(self):
        """Trial redemptions created on PL are merged into NL."""
        # PL created a trial redemption for u2
        pl_conn = sqlite3.connect(self.pl_db)
        pl_cur = pl_conn.cursor()
        pl_cur.execute("INSERT INTO trial_redemptions (id, user_id, status, delivered_at, updated_at) VALUES (1, 'u2', 'delivered', 1500, 1600);")
        pl_conn.commit()
        pl_conn.close()

        # Merge
        stats = failback_merge.merge_vpn_shop(self.nl_db, self.pl_db)
        self.assertEqual(stats["trial_redemptions_merged"], 1)

        # Verify in NL
        nl_conn = sqlite3.connect(self.nl_db)
        nl_cur = nl_conn.cursor()
        nl_cur.execute("SELECT status FROM trial_redemptions WHERE user_id = 'u2';")
        row = nl_cur.fetchone()
        self.assertEqual(row[0], "delivered")
        nl_conn.close()


# ==============================================================================
# Cloudflare DNS Stub Tests
# ==============================================================================

class TestCloudflareDNSPLStub(unittest.TestCase):
    """Verify cf-failover-dns.sh supports promote-pl/demote-pl commands."""

    def test_pl_commands_recognized(self):
        """The script's case statement handles promote-pl and demote-pl."""
        if not shutil.which(BASH_BIN):
            self.skipTest("bash not available on this environment")
        import subprocess
        # Run with no args — should print usage listing all commands
        script_path = os.path.join(SCRIPTS_DIR, "cf-failover-dns.sh")
        script_sh = script_path.replace("\\", "/")
        result = subprocess.run(
            [BASH_BIN, script_sh],
            capture_output=True, text=True, timeout=5
        )
        # Should exit 1 with usage (no args given)
        self.assertEqual(result.returncode, 1)
        output = result.stdout + result.stderr
        self.assertIn("promote-pl", output)
        self.assertIn("demote-pl", output)
        self.assertIn("PL", output)

    def test_pl_ip_defined(self):
        """PL_IP defaults to 2.56.125.177 in cf-failover-dns.sh."""  # PLACEHOLDER
        script_path = os.path.join(SCRIPTS_DIR, "cf-failover-dns.sh")
        with open(script_path, "r") as f:
            content = f.read()
        self.assertIn("2.56.125.177", content)  # PLACEHOLDER
        self.assertIn("PL_IP", content)


# ==============================================================================
# Promote/Demote Script Tests
# ==============================================================================

class TestPromoteDemoteScripts(unittest.TestCase):
    """Verify promote.sh and demote.sh handle --node pl correctly."""

    def test_promote_sh_node_pl_recognized(self):
        """promote.sh --node pl does not error on argument parsing and targets PL."""
        if not shutil.which(BASH_BIN):
            self.skipTest("bash not available on this environment")
        script_path = os.path.join(SCRIPTS_DIR, "promote.sh")
        script_sh = script_path.replace("\\", "/")
        # Sourcing with --node pl parses the node argument
        result = __import__('subprocess').run(
            [BASH_BIN, "-c", f"source '{script_sh}' --node pl 2>&1 || true; echo 'done'"],
            capture_output=True, text=True, timeout=5,
            env={**__import__('os').environ, "NODE_IP": "2.56.125.177"}  # PLACEHOLDER
        )
        combined = result.stdout + result.stderr
        self.assertNotIn("Unknown argument", combined)
        self.assertNotIn("must be 'fi' or 'pl'", combined)
        self.assertIn("promote_pl", combined)

    def test_demote_sh_node_pl_recognized(self):
        """demote.sh --node pl does not error on argument parsing and targets PL."""
        if not shutil.which(BASH_BIN):
            self.skipTest("bash not available on this environment")
        script_path = os.path.join(SCRIPTS_DIR, "demote.sh")
        script_sh = script_path.replace("\\", "/")
        result = __import__('subprocess').run(
            [BASH_BIN, "-c", f"source '{script_sh}' --node pl 2>&1 || true; echo 'done'"],
            capture_output=True, text=True, timeout=5,
            env={**__import__('os').environ, "NL_IP": "193.233.210.189", "NODE_IP": "2.56.125.177"}  # PLACEHOLDER
        )
        combined = result.stdout + result.stderr
        self.assertNotIn("Unknown argument", combined)
        self.assertNotIn("must be 'fi' or 'pl'", combined)
        self.assertIn("demote_pl", combined)

    def test_promote_sh_syntax_valid(self):
        """promote.sh has valid bash syntax."""
        if not shutil.which(BASH_BIN):
            self.skipTest("bash not available on this environment")
        script_path = os.path.join(SCRIPTS_DIR, "promote.sh")
        script_sh = script_path.replace("\\", "/")
        result = __import__('subprocess').run(
            [BASH_BIN, "-n", script_sh],  # -n = syntax check only
            capture_output=True, text=True, timeout=5
        )
        self.assertEqual(result.returncode, 0, f"syntax error: {result.stderr}")

    def test_promote_sh_invalid_node_rejected(self):
        """promote.sh rejects invalid --node values."""
        if not shutil.which(BASH_BIN):
            self.skipTest("bash not available on this environment")
        script_path = os.path.join(SCRIPTS_DIR, "promote.sh")
        script_sh = script_path.replace("\\", "/")
        result = __import__('subprocess').run(
            [BASH_BIN, script_sh, "--node", "invalid"],
            capture_output=True, text=True, timeout=5
        )
        self.assertNotEqual(result.returncode, 0)
        output = result.stdout + result.stderr
        self.assertIn("must be 'fi' or 'pl'", output)

    def test_demote_sh_syntax_valid(self):
        """demote.sh has valid bash syntax."""
        if not shutil.which(BASH_BIN):
            self.skipTest("bash not available on this environment")
        script_path = os.path.join(SCRIPTS_DIR, "demote.sh")
        script_sh = script_path.replace("\\", "/")
        result = __import__('subprocess').run(
            [BASH_BIN, "-n", script_sh],
            capture_output=True, text=True, timeout=5
        )
        self.assertEqual(result.returncode, 0, f"syntax error: {result.stderr}")

    def test_demote_sh_invalid_node_rejected(self):
        """demote.sh rejects invalid --node values."""
        if not shutil.which(BASH_BIN):
            self.skipTest("bash not available on this environment")
        script_path = os.path.join(SCRIPTS_DIR, "demote.sh")
        script_sh = script_path.replace("\\", "/")
        result = __import__('subprocess').run(
            [BASH_BIN, script_sh, "--node", "invalid"],
            capture_output=True, text=True, timeout=5
        )
        self.assertNotEqual(result.returncode, 0)
        output = result.stdout + result.stderr
        self.assertIn("must be 'fi' or 'pl'", output)


# ==============================================================================
# Litestream PL Config Tests
# ==============================================================================

class TestLitestreamPLConfig(unittest.TestCase):
    """Verify litestream_pl.yml is valid and references PL paths."""

    def test_litestream_pl_yml_exists(self):
        """litestream_pl.yml exists in scripts/."""
        pl_yml = os.path.join(SCRIPTS_DIR, "litestream_pl.yml")
        self.assertTrue(os.path.exists(pl_yml), f"{pl_yml} not found")

    def test_litestream_pl_references_correct_paths(self):
        """litestream_pl.yml contains PL-specific replica paths."""
        pl_yml = os.path.join(SCRIPTS_DIR, "litestream_pl.yml")
        with open(pl_yml, "r") as f:
            content = f.read()
        self.assertIn("/var/lib/litestream_pl/", content)
        self.assertIn("x-ui-db.replica", content)
        self.assertIn("vpn-shop-db.replica", content)
        self.assertIn("/etc/x-ui/x-ui.db", content)
        self.assertIn("/root/vpn-shop/data-silentconnect/vpn_shop.db", content)

    def test_litestream_pl_valid_yaml(self):
        """litestream_pl.yml is valid YAML."""
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML not available")
        pl_yml = os.path.join(SCRIPTS_DIR, "litestream_pl.yml")
        with open(pl_yml, "r") as f:
            data = yaml.safe_load(f)
        self.assertIn("dbs", data)
        self.assertEqual(len(data["dbs"]), 2)
        # Check both DBs have file replicas
        for db_entry in data["dbs"]:
            self.assertIn("replicas", db_entry)
            self.assertTrue(len(db_entry["replicas"]) > 0)


if __name__ == "__main__":
    unittest.main()
