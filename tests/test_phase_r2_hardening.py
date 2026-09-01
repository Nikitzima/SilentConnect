import importlib.util
import json
from collections import OrderedDict
import os
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure paths are importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
VPN_SHOP_DIR = PROJECT_ROOT / "vpn-shop"
SUBJSON_DIR = PROJECT_ROOT / "subjson-service"
SCRIPTS_DIR = PROJECT_ROOT / "scripts"

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(VPN_SHOP_DIR) not in sys.path:
    sys.path.insert(0, str(VPN_SHOP_DIR))
if str(SUBJSON_DIR) not in sys.path:
    sys.path.insert(0, str(SUBJSON_DIR))
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

# Test environment configuration
os.environ["SECRET_SEGMENT"] = "test-r2-hardening-secret"
os.environ["INTERNAL_SECRET"] = "internal-token-r2-xyz"
os.environ["HYSTERIA_SALAMANDER_PASSWORD"] = "485a96779d1ad79d0fa80ca0"
os.environ["HYSTERIA_AUTH_PASSWORD"] = "test_auth_pwd"
os.environ["PUBLIC_HOST"] = "sub.example.com"
os.environ["WS443_PUBLIC_HOST"] = "edge.example.com"
os.environ["PUBLIC_SUBSCRIPTION_ORIGIN"] = "https://sub.example.com"
os.environ["RELAY_PUBLIC_HOST"] = "relay.example.com"

# Import modules
from vpn_shop import security, store, web, xui_db, bot
from vpn_shop.config import Settings
from vpn_shop.store import Store
from vpn_shop.web import WebCheckout, verify_cf_turnstile, WEB_RATE_LIMIT_MAX_ENTRIES
from vpn_shop.xui_db import XuiDatabase
from scripts.failback_merge import make_backup, check_integrity

# Import subjson app
subjson_path = SUBJSON_DIR / "app.py"
spec_subjson = importlib.util.spec_from_file_location("subjson_app_r2", str(subjson_path))
subjson_app = importlib.util.module_from_spec(spec_subjson)
spec_subjson.loader.exec_module(subjson_app)


class TestPhaseR2Hardening(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.shop_db_path = self.temp_path / "vpn_shop.db"
        self.xui_db_path = self.temp_path / "x-ui.db"
        subjson_app.XUI_DB_PATH = str(self.xui_db_path)
        os.environ["STORE_DB_PATH"] = str(self.shop_db_path)
        os.environ["XUI_DB_PATH"] = str(self.xui_db_path)

        # Initialize mock shop db
        self.store = Store(self.shop_db_path)
        self.store.init()

        # Initialize mock xui db with WAL mode
        conn = sqlite3.connect(str(self.xui_db_path))
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute(
                """
                CREATE TABLE inbounds (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    remark TEXT,
                    protocol TEXT,
                    port INTEGER,
                    settings TEXT,
                    stream_settings TEXT,
                    sniffing TEXT
                )
                """
            )
            settings_json = json.dumps({
                "clients": [
                    {"id": "uuid-client-1", "email": "client1@test.com", "subId": "sub111111111111"}
                ]
            })
            conn.execute(
                "INSERT INTO inbounds (remark, protocol, port, settings, stream_settings, sniffing) VALUES (?, ?, ?, ?, ?, ?)",
                ("VLESS TCP", "vless", 443, settings_json, json.dumps({"network": "tcp"}), json.dumps({"enabled": True}))
            )
            conn.commit()
        finally:
            conn.close()

        subjson_app.invalidate_inbounds_cache()

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def _make_mock_settings(self) -> MagicMock:
        settings = MagicMock(spec=Settings)
        settings.root_dir = self.temp_path
        settings.data_dir = self.temp_path
        settings.database_path = self.shop_db_path
        settings.telegram_bot_token = "dummy:token"
        settings.telegram_bot_username = "SilentConnectVPNBot"
        settings.support_tg_url = "https://t.me/support"
        settings.web_public_base_url = "https://vpn.example.com"
        settings.subscription_base_url = "https://sub.example.com"
        settings.terms_version = "2026-08-22"
        settings.default_device_limit = 3
        settings.monthly_price_tcp_rub = 100
        settings.monthly_price_xhttp_rub = 150
        settings.monthly_price_3_devices_rub = 100
        settings.monthly_price_6_devices_rub = 200
        settings.monthly_price_9_devices_rub = 300
        settings.cf_turnstile_site_key = ""
        settings.cf_turnstile_secret_key = ""
        settings.cf_turnstile_enabled = False
        settings.invite_required = False
        settings.xui_panel_url = "http://127.0.0.1:2053"
        settings.xui_username = "admin"
        settings.xui_password = "admin"
        settings.xui_verify_tls = False
        settings.xui_db_path = self.xui_db_path
        settings.xui_xhttp_inbound_id = 1
        settings.xui_tcp_inbound_id = 1
        return settings

    # =========================================================================
    # Task 1: Fix Critical IDOR in subjson-service/app.py
    # =========================================================================
    def test_fix1_idor_elimination_numeric_id(self):
        """Verify that _find_subscription_impl resolves by public_id but rejects numeric DB id."""
        # Insert profile with numeric id = 100, public_id = 'prof_secure_public_id_99'
        conn = sqlite3.connect(str(self.shop_db_path))
        try:
            conn.execute(
                """
                INSERT INTO profiles (id, public_id, xui_inbound_id, transport, profile_mode, xui_email, xui_client_id, status, created_at, expires_at)
                VALUES (100, 'prof_secure_public_id_99', 1, 'tcp', 'anonymous', 'client1@test.com', 'uuid-client-1', 'active', 1000, 2000000000)
                """
            )
            conn.commit()
        finally:
            conn.close()

        # Lookup by public_id must succeed
        row, settings, stream_settings, sniffing, client = subjson_app._find_subscription_impl("prof_secure_public_id_99")
        self.assertEqual(client.get("email"), "client1@test.com")

        # Lookup by numeric id '100' or '1' must raise KeyError (IDOR eliminated)
        with self.assertRaises(KeyError):
            subjson_app._find_subscription_impl("100")

        with self.assertRaises(KeyError):
            subjson_app._find_subscription_impl("1")

    # =========================================================================
    # Task 2: WAL-Safe Cache Invalidation in subjson-service and xui_db
    # =========================================================================
    def test_fix2_wal_safe_cache_invalidation(self):
        """Verify that newly written clients in WAL mode are immediately visible in cache."""
        xui = XuiDatabase(self.xui_db_path)
        # First read populates cache
        client1 = xui.find_client_by_email("client1@test.com")
        self.assertIsNotNone(client1)
        self.assertIsNone(xui.find_client_by_email("client2@test.com"))

        # Write new client in WAL mode via separate connection without checkpoint
        conn = sqlite3.connect(str(self.xui_db_path))
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            settings_json = json.dumps({
                "clients": [
                    {"id": "uuid-client-1", "email": "client1@test.com", "subId": "sub111111111111"},
                    {"id": "uuid-client-2", "email": "client2@test.com", "subId": "sub222222222222"}
                ]
            })
            conn.execute("UPDATE inbounds SET settings = ? WHERE id = 1", (settings_json,))
            conn.commit()
        finally:
            conn.close()

        # XuiDatabase must detect updated WAL signature and find client2 immediately
        client2 = xui.find_client_by_email("client2@test.com")
        self.assertIsNotNone(client2)
        self.assertEqual((client2.get("client") or {}).get("subId"), "sub222222222222")

        # Also verify subjson app._ensure_inbounds_cache detects WAL changes
        sub2 = subjson_app.find_subscription("sub222222222222")
        self.assertIsNotNone(sub2)
        self.assertEqual(sub2[4].get("email"), "client2@test.com")

    # =========================================================================
    # Task 3: Pre-Allocation & Atomic Reservation of Promo / Invites
    # =========================================================================
    def test_fix3_store_restore_promo_and_invite(self):
        """Verify restore_promo_code and restore_invite safely decrement used_count."""
        code, promo = self.store.create_promo_code(
            promo_type="discount",
            transport="tcp",
            duration_days=30,
            discount_percent=50,
            profile_mode="anonymous",
            max_uses=1,
        )
        promo_id = promo["id"]

        # Consume promo
        consumed = self.store.consume_promo_code(promo_id)
        self.assertEqual(consumed["used_count"], 1)
        self.assertIsNone(self.store.find_valid_promo(code))

        # Restore promo
        restored = self.store.restore_promo_code(promo_id)
        self.assertEqual(restored["used_count"], 0)
        self.assertIsNotNone(self.store.find_valid_promo(code))

        # Restore again doesn't go below 0
        restored2 = self.store.restore_promo_code(promo_id)
        self.assertEqual(restored2["used_count"], 0)

        # Same for invite
        icode, invite = self.store.create_invite(max_uses=1)
        invite_id = invite["id"]
        self.store.consume_invite(invite_id)
        self.assertIsNone(self.store.find_valid_invite(icode))

        irestored = self.store.restore_invite(invite_id)
        self.assertEqual(irestored["used_count"], 0)
        self.assertIsNotNone(self.store.find_valid_invite(icode))

    def test_fix3_web_maybe_auto_deliver_free_order_preallocation_and_rollback(self):
        """Verify web order pre-allocates promo and rolls back if provisioning fails."""
        settings = self._make_mock_settings()
        provisioner_mock = MagicMock()
        web_app = WebCheckout(settings=settings, store=self.store)
        web_app.provisioner = provisioner_mock

        # 1. Test race / exhausted promo: order creation with exhausted promo fails
        code, promo = self.store.create_promo_code(
            promo_type="fixed",
            transport="tcp",
            duration_days=30,
            discount_percent=100,
            fixed_price_rub=0,
            profile_mode="anonymous",
            max_uses=1,
        )
        self.store.consume_promo_code(promo["id"]) # exhaust promo

        order = self.store.create_order(
            kind="purchase",
            status="auto_provision",
            transport="tcp",
            duration_days=30,
            profile_mode="anonymous",
            family_label=None,
            base_price_rub=100,
            final_price_rub=0,
            promo_id=promo["id"],
            invite_id=None,
            customer_chat_id=None,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version="2026-08-22",
            customer_email="test@example.com",
        )

        with self.assertRaises(ValueError):
            web_app.maybe_auto_deliver_free_web_order(order)
        provisioner_mock.create_profile_for_order.assert_not_called()

        # 2. Test rollback on provisioning exception
        code2, promo2 = self.store.create_promo_code(
            promo_type="fixed",
            transport="tcp",
            duration_days=30,
            discount_percent=100,
            fixed_price_rub=0,
            profile_mode="anonymous",
            max_uses=1,
        )
        order2 = self.store.create_order(
            kind="purchase",
            status="auto_provision",
            transport="tcp",
            duration_days=30,
            profile_mode="anonymous",
            family_label=None,
            base_price_rub=100,
            final_price_rub=0,
            promo_id=promo2["id"],
            invite_id=None,
            customer_chat_id=None,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version="2026-08-22",
            customer_email="test@example.com",
        )

        provisioner_mock.create_profile_for_order.side_effect = RuntimeError("x-ui RPC timeout")
        with self.assertRaises(RuntimeError):
            web_app.maybe_auto_deliver_free_web_order(order2)

        # Promo should have been restored back to 0 uses
        p2_row = self.store.get_promo_code(promo2["id"])
        self.assertEqual(p2_row["used_count"], 0)

    def test_fix3_bot_complete_order_preallocation_and_rollback(self):
        """Verify bot complete_order pre-allocates promo and rolls back if provisioning fails."""
        settings = self._make_mock_settings()
        provisioner_mock = MagicMock()
        telegram_mock = MagicMock()
        bot_instance = bot.ShopBot(settings=settings, store=self.store)
        bot_instance.provisioner = provisioner_mock
        bot_instance.telegram = telegram_mock

        # 1. Exhausted promo
        code, promo = self.store.create_promo_code(
            promo_type="fixed",
            transport="tcp",
            duration_days=30,
            discount_percent=100,
            fixed_price_rub=0,
            profile_mode="anonymous",
            max_uses=1,
        )
        self.store.consume_promo_code(promo["id"])

        order = self.store.create_order(
            kind="purchase",
            status="waiting_payment",
            transport="tcp",
            duration_days=30,
            profile_mode="anonymous",
            family_label=None,
            base_price_rub=100,
            final_price_rub=0,
            promo_id=promo["id"],
            invite_id=None,
            customer_chat_id=123456,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version="2026-08-22",
        )

        with self.assertRaises(RuntimeError):
            bot_instance.complete_order(order, actor="admin")
        provisioner_mock.create_profile_for_order.assert_not_called()

        # 2. Provisioning failure rollback
        code2, promo2 = self.store.create_promo_code(
            promo_type="fixed",
            transport="tcp",
            duration_days=30,
            discount_percent=100,
            fixed_price_rub=0,
            profile_mode="anonymous",
            max_uses=1,
        )
        order2 = self.store.create_order(
            kind="purchase",
            status="waiting_payment",
            transport="tcp",
            duration_days=30,
            profile_mode="anonymous",
            family_label=None,
            base_price_rub=100,
            final_price_rub=0,
            promo_id=promo2["id"],
            invite_id=None,
            customer_chat_id=123456,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version="2026-08-22",
        )

        provisioner_mock.create_profile_for_order.side_effect = RuntimeError("Database locked")
        with self.assertRaises(RuntimeError):
            bot_instance.complete_order(order2, actor="admin")

        # Promo should have been restored
        p2_row = self.store.get_promo_code(promo2["id"])
        self.assertEqual(p2_row["used_count"], 0)

    # =========================================================================
    # Task 4: Bounded Rate Limiter in vpn_shop/web.py
    # =========================================================================
    def test_fix4_bounded_rate_limiter_lru(self):
        """Verify web rate limiters are thread-safe bounded OrderedDicts with LRU eviction."""
        settings = self._make_mock_settings()
        web_app = WebCheckout(settings=settings, store=self.store)

        self.assertIsInstance(web_app._cabinet_rate_limits, OrderedDict)
        self.assertIsInstance(web_app._promo_check_limits, OrderedDict)
        self.assertEqual(WEB_RATE_LIMIT_MAX_ENTRIES, 10000)

        # Test thread-safe bounded insertion and LRU eviction
        web_app._promo_check_limits.clear()
        
        # Simulate inserting 10005 entries
        with web_app._rate_limit_lock:
            for i in range(10005):
                key = f"promo:192.0.2.{i}"
                web_app._promo_check_limits[key] = [time.time()]
                web_app._promo_check_limits.move_to_end(key)
                while len(web_app._promo_check_limits) > WEB_RATE_LIMIT_MAX_ENTRIES:
                    web_app._promo_check_limits.popitem(last=False)

        self.assertEqual(len(web_app._promo_check_limits), WEB_RATE_LIMIT_MAX_ENTRIES)
        # Oldest 5 keys should have been evicted
        for i in range(5):
            self.assertNotIn(f"promo:192.0.2.{i}", web_app._promo_check_limits)
        # Newest key should be present
        self.assertIn("promo:192.0.2.10004", web_app._promo_check_limits)

    # =========================================================================
    # Task 5: WAL-Safe Online Backup in scripts/failback_merge.py
    # =========================================================================
    def test_fix5_wal_safe_online_backup(self):
        """Verify make_backup uses SQLite online backup API to capture WAL transactions."""
        test_db = self.temp_path / "wal_backup_source.db"
        conn = sqlite3.connect(str(test_db))
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("CREATE TABLE test_data (id INTEGER PRIMARY KEY, msg TEXT);")
            conn.execute("INSERT INTO test_data (msg) VALUES ('committed in wal');")
            conn.commit()
        finally:
            conn.close()

        # Perform backup
        backup_path = make_backup(str(test_db))
        self.assertTrue(Path(backup_path).exists())

        # Verify integrity and content of backup file
        bak_conn = sqlite3.connect(backup_path)
        try:
            check_integrity(bak_conn, "Backup DB")
            row = bak_conn.execute("SELECT msg FROM test_data WHERE id = 1").fetchone()
            self.assertEqual(row[0], "committed in wal")
        finally:
            bak_conn.close()

    # =========================================================================
    # Task 6: Fail-Closed Turnstile in web.py
    # =========================================================================
    def test_fix6_fail_closed_turnstile(self):
        """Verify verify_cf_turnstile fails closed when secret_key is set and token is missing/empty."""
        secret = "0x4AAAAAAATestSecretKey123"

        # 1. Missing / whitespace token must fail closed (return False)
        self.assertFalse(verify_cf_turnstile(secret, ""))
        self.assertFalse(verify_cf_turnstile(secret, "   "))
        self.assertFalse(verify_cf_turnstile(secret, None))

        # 2. No secret configured -> verification disabled (return True)
        self.assertTrue(verify_cf_turnstile("", ""))
        self.assertTrue(verify_cf_turnstile(None, ""))

        # 3. Valid token with mocked Turnstile API response
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_res = MagicMock()
            mock_res.read.return_value = json.dumps({"success": True}).encode("utf-8")
            mock_urlopen.return_value.__enter__.return_value = mock_res
            self.assertTrue(verify_cf_turnstile(secret, "valid_turnstile_token", "127.0.0.1"))

        # 4. Failed Turnstile API response
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_res = MagicMock()
            mock_res.read.return_value = json.dumps({"success": False, "error-codes": ["invalid-input-response"]}).encode("utf-8")
            mock_urlopen.return_value.__enter__.return_value = mock_res
            self.assertFalse(verify_cf_turnstile(secret, "invalid_turnstile_token", "127.0.0.1"))

    # =========================================================================
    # Task 7: Production Secret Fail-Fast
    # =========================================================================
    def test_fix7_production_secret_fail_fast_security(self):
        """Verify security.py and app.py raise RuntimeError in production when default secrets are used."""
        # 1. security.py validate_production_secrets
        with patch.dict(os.environ, {"ENV": "production", "SERVER_PEPPER": "silentconnect-pepper-secret-v1"}):
            with self.assertRaises(RuntimeError):
                security.validate_production_secrets()

        with patch.dict(os.environ, {"PRODUCTION": "1", "SERVER_PEPPER": ""}):
            with self.assertRaises(RuntimeError):
                security.validate_production_secrets()

        with patch.dict(os.environ, {"ENV": "production", "SERVER_PEPPER": "cryptographically-secure-random-pepper-xyz"}):
            # Should NOT raise
            security.validate_production_secrets()

        # 2. subjson-service/app.py validate_production_secrets
        with patch.dict(os.environ, {"ENV": "production", "SECRET_SEGMENT": "my-secret-sub"}):
            with self.assertRaises(RuntimeError):
                subjson_app.validate_production_secrets()

        with patch.dict(os.environ, {"PRODUCTION": "true", "SECRET_SEGMENT": "secret-sub"}):
            with self.assertRaises(RuntimeError):
                subjson_app.validate_production_secrets()

        with patch.dict(os.environ, {"ENV": "production", "SECRET_SEGMENT": ""}):
            with self.assertRaises(RuntimeError):
                subjson_app.validate_production_secrets()

        with patch.dict(os.environ, {"ENV": "production", "SECRET_SEGMENT": "custom-production-sub-path-999"}):
            # Should NOT raise
            subjson_app.validate_production_secrets()


if __name__ == "__main__":
    unittest.main()
