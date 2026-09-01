#!/usr/bin/env python3
"""
Test Suite for Phase P2 Optimizations:
- In-memory Client Cache and mtime invalidation (xui_db.py & subjson-service/app.py)
- Bounded LRU Rate Limiter with max capacity and sliding window enforcement
- Bot Background Worker Isolation, non-blocking polling, and bounded exponential backoff
"""

import collections
import concurrent.futures
import copy
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

# Ensure paths to vpn-shop and subjson-service are resolvable
_repo_root = Path(__file__).resolve().parent.parent
_vpn_shop_path = _repo_root / "vpn-shop"
_subjson_path = _repo_root / "subjson-service"

for p in [str(_repo_root), str(_vpn_shop_path), str(_subjson_path)]:
    if p not in sys.path:
        sys.path.insert(0, p)

# Set necessary test environment variables before importing app
os.environ["SECRET_SEGMENT"] = "test-secret-123"  # PLACEHOLDER
os.environ["INTERNAL_SECRET"] = "internal-token-xyz"  # PLACEHOLDER
os.environ["HYSTERIA_SALAMANDER_PASSWORD"] = "dummy_salamander_pwd"  # PLACEHOLDER
os.environ["HYSTERIA_AUTH_PASSWORD"] = "test_auth_pwd"  # PLACEHOLDER
os.environ["PUBLIC_HOST"] = "edge.example.com"
os.environ["PUBLIC_SUBSCRIPTION_ORIGIN"] = "https://sub.example.com"
os.environ["RELAY_PUBLIC_HOST"] = "relay.example.com"

from vpn_shop.config import Settings
from vpn_shop.xui_db import XuiDatabase
from vpn_shop.bot import ShopBot
import app as subjson_app


def create_mock_xui_db(db_path: Path) -> None:
    """Create a mock x-ui SQLite database with schema and sample inbounds."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute(
        """
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
        """
    )
    conn.execute(
        """
        CREATE TABLE client_traffics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            inbound_id INTEGER,
            enable INTEGER DEFAULT 1,
            email TEXT UNIQUE,
            up INTEGER DEFAULT 0,
            down INTEGER DEFAULT 0,
            expiry_time INTEGER DEFAULT 0,
            total INTEGER DEFAULT 0,
            last_online INTEGER DEFAULT 0
        );
        """
    )

    sample_settings_tcp = {
        "clients": [
            {
                "id": "uuid-1111",
                "email": "user1@example.com",
                "subId": "sub-1111",
                "limitIp": 3,
                "totalGB": 0,
                "expiryTime": 1780000000000,
                "enable": True,
                "tgId": "",
                "subRev": 0,
            },
            {
                "id": "uuid-2222",
                "email": "user2@example.com",
                "subId": "sub-2222",
                "limitIp": 3,
                "totalGB": 0,
                "expiryTime": 1780000000000,
                "enable": True,
                "tgId": "",
                "subRev": 0,
            },
        ]
    }
    sample_stream_tcp = {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
            "show": False,
            "xver": 0,
            "dest": "sber.ru:443",
            "serverNames": ["sber.ru"],
            "privateKey": "priv_key_1",
            "shortIds": ["0123456789abcdef"],
        },
    }

    sample_settings_ws = {
        "clients": [
            {
                "id": "uuid-3333",
                "email": "user3@example.com",
                "subId": "sub-3333",
                "limitIp": 3,
                "totalGB": 0,
                "expiryTime": 1780000000000,
                "enable": True,
                "tgId": "",
                "subRev": 0,
            }
        ]
    }
    sample_stream_ws = {
        "network": "ws",
        "security": "tls",
        "wsSettings": {"path": "/sc-ws-9c3d7f1e"},
    }

    conn.execute(
        """
        INSERT INTO inbounds (id, remark, protocol, port, settings, stream_settings, sniffing)
        VALUES (1, 'VLESS-REALITY-TCP', 'vless', 443, ?, ?, '{}')
        """,
        (json.dumps(sample_settings_tcp), json.dumps(sample_stream_tcp)),
    )
    conn.execute(
        """
        INSERT INTO inbounds (id, remark, protocol, port, settings, stream_settings, sniffing)
        VALUES (2, 'VLESS-WS', 'vless', 8443, ?, ?, '{}')
        """,
        (json.dumps(sample_settings_ws), json.dumps(sample_stream_ws)),
    )
    conn.execute(
        """
        INSERT INTO client_traffics (inbound_id, enable, email, up, down, total, expiry_time)
        VALUES (1, 1, 'user1@example.com', 1024, 2048, 0, 1780000000000),
               (1, 1, 'user2@example.com', 512, 1024, 0, 1780000000000),
               (2, 1, 'user3@example.com', 256, 512, 0, 1780000000000)
        """
    )
    conn.commit()
    conn.close()


class TestXuiDatabaseCache(unittest.TestCase):
    """Verify in-memory client cache and mtime invalidation in XuiDatabase."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="xui_cache_test_")
        self.db_path = Path(self.tmp_dir) / "x-ui.db"
        create_mock_xui_db(self.db_path)
        self.xui = XuiDatabase(self.db_path)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_find_client_by_email_and_sub_id_cached(self):
        # First call loads cache
        c1 = self.xui.find_client_by_email("user1@example.com")
        self.assertIsNotNone(c1)
        self.assertEqual(c1["inbound_id"], 1)
        self.assertEqual(c1["client"]["id"], "uuid-1111")
        self.assertEqual(c1["client"]["subId"], "sub-1111")

        # Sub ID lookup
        c2 = self.xui.find_client_by_sub_id("sub-2222")
        self.assertIsNotNone(c2)
        self.assertEqual(c2["client"]["email"], "user2@example.com")

        # Miss lookup
        c_none = self.xui.find_client_by_email("nonexistent@example.com")
        self.assertIsNone(c_none)

    def test_cache_deepcopy_isolation(self):
        c1 = self.xui.find_client_by_email("user1@example.com")
        self.assertIsNotNone(c1)
        # Mutate returned dictionary
        c1["client"]["email"] = "mutated@example.com"
        c1["settings"]["clients"] = []

        # Subsequent lookup must return original unmutated cached data
        c1_fresh = self.xui.find_client_by_email("user1@example.com")
        self.assertIsNotNone(c1_fresh)
        self.assertEqual(c1_fresh["client"]["email"], "user1@example.com")

    def test_mtime_invalidation_on_external_db_update(self):
        # Warm cache
        c1 = self.xui.find_client_by_email("user1@example.com")
        self.assertIsNotNone(c1)

        # Modify DB externally (add new client and touch mtime)
        time.sleep(0.05)  # Ensure distinct mtime timestamp
        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT settings FROM inbounds WHERE id = 1").fetchone()
        st = json.loads(row[0])
        st["clients"].append({
            "id": "uuid-new-9999",
            "email": "user99@example.com",
            "subId": "sub-9999",
            "limitIp": 3,
            "expiryTime": 1800000000000,
            "enable": True,
        })
        conn.execute("UPDATE inbounds SET settings = ? WHERE id = 1", (json.dumps(st),))
        conn.commit()
        conn.close()

        # Update mtime explicitly in case filesystem has low mtime resolution
        new_mtime = time.time() + 5.0
        os.utime(self.db_path, (new_mtime, new_mtime))

        # Lookup newly added client: cache must invalidate and find user99
        c99 = self.xui.find_client_by_email("user99@example.com")
        self.assertIsNotNone(c99)
        self.assertEqual(c99["client"]["id"], "uuid-new-9999")

        c99_sub = self.xui.find_client_by_sub_id("sub-9999")
        self.assertIsNotNone(c99_sub)
        self.assertEqual(c99_sub["client"]["email"], "user99@example.com")

    def test_update_client_expiry_direct_invalidates_cache(self):
        # Warm cache
        c1 = self.xui.find_client_by_email("user1@example.com")
        self.assertIsNotNone(c1)
        self.assertEqual(c1["client"]["expiryTime"], 1780000000000)

        # Direct expiry update
        new_exp = 1999999999000
        ok = self.xui.update_client_expiry_direct(1, "user1@example.com", new_exp, enable=True, device_limit=6)
        self.assertTrue(ok)

        # Cache was invalidated: next lookup gets updated record
        c1_updated = self.xui.find_client_by_email("user1@example.com")
        self.assertIsNotNone(c1_updated)
        self.assertEqual(c1_updated["client"]["expiryTime"], new_exp)
        self.assertEqual(c1_updated["client"]["limitIp"], 6)

    def test_missing_db_resilience(self):
        missing_xui = XuiDatabase(Path(self.tmp_dir) / "nonexistent.db")
        self.assertIsNone(missing_xui.find_client_by_email("any@example.com"))
        self.assertIsNone(missing_xui.find_client_by_sub_id("any-sub"))


class TestSubjsonInboundsCache(unittest.TestCase):
    """Verify subjson-service inbounds caching and subscription lookups."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="subjson_cache_test_")
        self.db_path = Path(self.tmp_dir) / "x-ui.db"
        create_mock_xui_db(self.db_path)

        self.orig_xui_db_path = subjson_app.XUI_DB_PATH
        subjson_app.XUI_DB_PATH = str(self.db_path)
        subjson_app.invalidate_inbounds_cache()

    def tearDown(self):
        subjson_app.XUI_DB_PATH = self.orig_xui_db_path
        subjson_app.invalidate_inbounds_cache()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_find_subscription_cached_lookup(self):
        row, settings, stream_settings, sniffing, client = subjson_app.find_subscription("sub-1111")
        self.assertEqual(client["email"], "user1@example.com")
        self.assertEqual(stream_settings["network"], "tcp")

        # By email
        row2, _, _, _, client2 = subjson_app.find_subscription("user2@example.com")
        self.assertEqual(client2["subId"], "sub-2222")

        # By uuid (id)
        row3, _, _, _, client3 = subjson_app.find_subscription("uuid-3333")
        self.assertEqual(client3["email"], "user3@example.com")

        # Non-existent raises KeyError
        with self.assertRaises(KeyError):
            subjson_app.find_subscription("invalid-sub-xyz")

    def test_find_subscription_by_network(self):
        row_tcp, _, stream_tcp, _, cl_tcp = subjson_app.find_subscription_by_network("sub-1111", network="tcp")
        self.assertEqual(stream_tcp["network"], "tcp")
        self.assertEqual(cl_tcp["email"], "user1@example.com")

        row_ws, _, stream_ws, _, cl_ws = subjson_app.find_subscription_by_network("sub-3333", network="ws")
        self.assertEqual(stream_ws["network"], "ws")
        self.assertEqual(cl_ws["email"], "user3@example.com")

    def test_mtime_invalidation_in_subjson(self):
        # Warm cache
        subjson_app.find_subscription("sub-1111")

        # Modify DB externally
        time.sleep(0.05)
        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT settings FROM inbounds WHERE id = 1").fetchone()
        st = json.loads(row[0])
        st["clients"].append({
            "id": "uuid-subjson-new",
            "email": "subjson_new@example.com",
            "subId": "sub-new-4444",
            "expiryTime": 1800000000000,
            "enable": True,
        })
        conn.execute("UPDATE inbounds SET settings = ? WHERE id = 1", (json.dumps(st),))
        conn.commit()
        conn.close()

        new_mtime = time.time() + 10.0
        os.utime(self.db_path, (new_mtime, new_mtime))

        # Must find newly added subscription
        _, _, _, _, client_new = subjson_app.find_subscription("sub-new-4444")
        self.assertEqual(client_new["email"], "subjson_new@example.com")


class TestBoundedLRURateLimiter(unittest.TestCase):
    """Verify Bounded LRU sliding window rate limiter in subjson-service."""

    def setUp(self):
        self.saved_enabled = subjson_app.RATE_LIMIT_ENABLED
        self.saved_rpm = subjson_app.RATE_LIMIT_RPM
        self.saved_max_entries = subjson_app.RATE_LIMIT_MAX_ENTRIES
        with subjson_app._rate_lock:
            subjson_app._rate_map.clear()

    def tearDown(self):
        subjson_app.RATE_LIMIT_ENABLED = self.saved_enabled
        subjson_app.RATE_LIMIT_RPM = self.saved_rpm
        subjson_app.RATE_LIMIT_MAX_ENTRIES = self.saved_max_entries
        with subjson_app._rate_lock:
            subjson_app._rate_map.clear()

    def test_sliding_window_rate_limiting(self):
        subjson_app.RATE_LIMIT_ENABLED = True
        subjson_app.RATE_LIMIT_RPM = 5

        # First 5 requests must pass
        for _ in range(5):
            self.assertTrue(subjson_app.check_rate_limit("192.168.1.100"))

        # 6th request within window must be rate-limited
        self.assertFalse(subjson_app.check_rate_limit("192.168.1.100"))

        # Different IP is not affected
        self.assertTrue(subjson_app.check_rate_limit("192.168.1.101"))

    def test_bounded_lru_capacity_eviction(self):
        subjson_app.RATE_LIMIT_ENABLED = True
        subjson_app.RATE_LIMIT_RPM = 100
        subjson_app.RATE_LIMIT_MAX_ENTRIES = 50

        # Insert 70 unique IPs
        for i in range(70):
            ip = f"10.0.0.{i}"
            self.assertTrue(subjson_app.check_rate_limit(ip))

        with subjson_app._rate_lock:
            self.assertEqual(len(subjson_app._rate_map), 50)
            # Oldest IPs (10.0.0.0 to 10.0.0.19) should have been evicted
            self.assertNotIn("10.0.0.0", subjson_app._rate_map)
            self.assertNotIn("10.0.0.19", subjson_app._rate_map)
            # Most recent IPs should be present
            self.assertIn("10.0.0.69", subjson_app._rate_map)

    def test_lru_move_to_end_preserves_active_ips(self):
        subjson_app.RATE_LIMIT_ENABLED = True
        subjson_app.RATE_LIMIT_RPM = 100
        subjson_app.RATE_LIMIT_MAX_ENTRIES = 10

        # Fill with 10 IPs
        for i in range(10):
            subjson_app.check_rate_limit(f"10.0.0.{i}")

        # Re-access 10.0.0.0 (making it most recently used)
        subjson_app.check_rate_limit("10.0.0.0")

        # Now add another new IP (10.0.0.99)
        subjson_app.check_rate_limit("10.0.0.99")

        with subjson_app._rate_lock:
            self.assertEqual(len(subjson_app._rate_map), 10)
            # 10.0.0.1 was least recently used and should have been evicted
            self.assertNotIn("10.0.0.1", subjson_app._rate_map)
            # 10.0.0.0 was refreshed and must remain in map
            self.assertIn("10.0.0.0", subjson_app._rate_map)
            self.assertIn("10.0.0.99", subjson_app._rate_map)

    def test_rate_limiter_disabled(self):
        subjson_app.RATE_LIMIT_ENABLED = False
        subjson_app.RATE_LIMIT_RPM = 1

        for _ in range(10):
            self.assertTrue(subjson_app.check_rate_limit("192.168.1.200"))


class TestBotBackgroundWorkerIsolation(unittest.TestCase):
    """Verify background worker isolation and bounded polling backoff in ShopBot."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="bot_test_")
        self.settings = Settings(
            root_dir=Path(self.tmp_dir),
            data_dir=Path(self.tmp_dir),
            database_path=Path(self.tmp_dir) / "vpn_shop.db",
            telegram_bot_token="123456:dummy_token",
            telegram_bot_username="SilentConnectTestBot",
            brand_name="SilentConnect",
            support_tg_url="https://t.me/dummy_support_bot",  # PLACEHOLDER
            welcome_media="",
            quickstart_media="",
            admin_usernames=("admin",),
            admin_user_ids=(12345,),
            subscription_base_url="https://sub.example.com/my-secret-sub",
            payment_instructions_text="Pay here",
            payment_transfer_url="https://pay.example.com",
            payment_bank_note="note",
            xui_panel_url="https://127.0.0.1:2053",
            xui_username="admin",
            xui_password="dummy_password",  # PLACEHOLDER
            xui_verify_tls=False,
            xui_db_path=Path(self.tmp_dir) / "x-ui.db",
            xui_xhttp_inbound_id=1,
            xui_tcp_inbound_id=2,
            web_listen_host="127.0.0.1",
            web_listen_port=8080,
            web_public_base_url="https://example.com",
            monthly_price_xhttp_rub=150,
            monthly_price_tcp_rub=150,
            monthly_price_3_devices_rub=300,
            monthly_price_6_devices_rub=500,
            monthly_price_9_devices_rub=700,
            default_device_limit=2,
            invite_required=False,
            terms_version="2026-08",
            purge_after_days=30,
            support_email="support@example.com",
            smtp_host="smtp.example.com",
            smtp_port=587,
            smtp_user="smtp_user",
            smtp_password="dummy_smtp_password",  # PLACEHOLDER
            smtp_from_email="noreply@example.com",
            cf_turnstile_site_key="turnstile_site",
            cf_turnstile_secret_key="turnstile_secret",
        )
        self.store = MagicMock()
        self.store.list_expired_profiles.return_value = []
        self.store.list_referral_balances.return_value = []
        self.store.list_profiles_due_for_reminder.return_value = []
        self.bot = ShopBot(self.settings, self.store)

    def tearDown(self):
        self.bot.shutdown()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_bot_initializes_background_executor_and_lock(self):
        self.assertIsNotNone(self.bot._periodic_task_lock)
        self.assertIsNotNone(self.bot._background_executor)
        self.assertIsInstance(self.bot._background_executor, concurrent.futures.ThreadPoolExecutor)

    def test_run_periodic_tasks_async_dispatch(self):
        executed_event = threading.Event()

        def mock_cleanup():
            executed_event.set()

        self.bot.cleanup_expired_test_profiles = mock_cleanup
        self.bot._last_test_profile_cleanup_at = 0

        # Dispatch asynchronously
        self.bot.run_periodic_tasks(async_dispatch=True)

        # Wait for background thread execution
        self.assertTrue(executed_event.wait(timeout=2.0))

    def test_run_periodic_tasks_mutual_exclusion(self):
        # Acquire lock to simulate running task
        self.assertTrue(self.bot._periodic_task_lock.acquire(blocking=False))
        try:
            called = []
            self.bot._execute_periodic_tasks = lambda: called.append(True)
            self.bot._last_test_profile_cleanup_at = 0

            # Invoking while locked must return immediately without running
            self.bot.run_periodic_tasks(async_dispatch=False)
            self.assertEqual(len(called), 0)
        finally:
            self.bot._periodic_task_lock.release()

    def test_bot_shutdown_cleanly(self):
        self.bot.shutdown()
        # Ensure idempotent shutdown
        self.bot.shutdown()


if __name__ == "__main__":
    unittest.main(verbosity=2)
