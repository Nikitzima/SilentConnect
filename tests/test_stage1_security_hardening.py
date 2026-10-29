from __future__ import annotations

import io
import json
import os
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "vpn-shop"))
sys.path.insert(0, str(REPO_ROOT / "subjson-service"))

os.environ.setdefault("HYSTERIA_SALAMANDER_PASSWORD", "test_pw")
os.environ.setdefault("HYSTERIA_AUTH_PASSWORD", "test_pw")
os.environ.setdefault("SERVER_PEPPER", "test_pepper")

import app as subjson_app
from vpn_shop.config import Settings
from vpn_shop.security import now_ts
from vpn_shop.store import Store, default_awg_quota_bytes_for_devices
from vpn_shop.web import (
    BoundedThreadingHTTPServer,
    RequestHandler,
    WebCheckout,
)


class TestStage1WebHardening(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_vpn_shop.db"
        self.store = Store(self.db_path)
        self.store.init()

        self.settings = MagicMock(spec=Settings)
        self.settings.root_dir = Path(self.temp_dir.name)
        self.settings.data_dir = Path(self.temp_dir.name)
        self.settings.database_path = self.db_path
        self.settings.web_listen_host = "127.0.0.1"
        self.settings.web_listen_port = 8080
        self.settings.web_public_base_url = "https://example.com"
        self.settings.subscription_base_url = "https://sub.example.com"
        self.settings.terms_version = "v1"
        self.settings.support_tg_url = "https://t.me/support"
        self.settings.telegram_bot_token = ""
        self.settings.telegram_bot_username = "SilentConnectVPNBot"
        self.settings.platega_merchant_id_bot = ""
        self.settings.platega_merchant_id_web = ""
        self.settings.platega_secret = "test_secret"
        self.settings.platega_secret_bot = ""
        self.settings.platega_secret_web = ""
        self.settings.digiseller_enabled = True
        self.settings.digiseller_seller_id = "1348126"
        self.settings.digiseller_api_key = "TEST_KEY"
        self.settings.digiseller_secret_key = "secret123"
        self.settings.digiseller_product_id = "33111"
        self.settings.digiseller_min_price_rub = 149
        self.settings.cf_turnstile_secret_key = "turnstile_secret_test"
        self.settings.admin_user_ids = ()
        self.settings.monthly_price_tcp_rub = 149
        self.settings.monthly_price_xhttp_rub = 149
        self.settings.monthly_price_3_devices_rub = 149
        self.settings.monthly_price_6_devices_rub = 249
        self.settings.monthly_price_9_devices_rub = 349
        self.settings.default_device_limit = 3
        self.settings.xui_panel_url = "http://127.0.0.1:2053"
        self.settings.xui_username = "admin"
        self.settings.xui_password = "admin"
        self.settings.xui_verify_tls = False
        self.settings.xui_xhttp_inbound_id = 1
        self.settings.xui_tcp_inbound_id = 2
        self.settings.xui_db_path = Path(self.temp_dir.name) / "xui.db"
        self.settings.smtp_host = ""
        self.settings.smtp_user = ""
        self.settings.smtp_password = ""
        self.settings.smtp_from = ""
        self.settings.support_email = "support@example.com"

        self.checkout = WebCheckout(self.settings, self.store)

    def tearDown(self) -> None:
        try:
            self.temp_dir.cleanup()
        except (PermissionError, OSError):
            pass

    def test_01_bounded_server_configuration(self) -> None:
        """Verify BoundedThreadingHTTPServer has request_queue_size=128 and ThreadPoolExecutor."""
        self.assertEqual(BoundedThreadingHTTPServer.request_queue_size, 128)
        self.assertTrue(BoundedThreadingHTTPServer.daemon_threads)

        server = BoundedThreadingHTTPServer(("127.0.0.1", 0), RequestHandler, max_workers=64)
        self.assertEqual(server._executor._max_workers, 64)
        server.server_close()

    def test_02_idor_blocking_anon_and_ord_prefixes(self) -> None:
        """get_profile_by_any_sub_id must reject anon- and ord_ immediately to prevent IDOR."""
        self.assertIsNone(self.checkout.get_profile_by_any_sub_id("anon-12345"))
        self.assertIsNone(self.checkout.get_profile_by_any_sub_id("ord_abcdef123456"))
        self.assertIsNone(self.checkout.get_profile_by_any_sub_id(""))
        self.assertIsNone(self.checkout.get_profile_by_any_sub_id(None))

    def test_03_assert_profile_awg_eligible(self) -> None:
        """assert_profile_awg_eligible checks status, expiration, and traffic quota."""
        # Active, valid profile
        prof = self.store.create_profile(
            xui_inbound_id=1,
            transport="tcp",
            profile_mode="personal",
            family_label=None,
            xui_email="user1@test.com",
            xui_client_id="uuid1",
            expires_at=now_ts() + 86400,
            awg_quota_bytes=default_awg_quota_bytes_for_devices(3),
            awg_reset_at=now_ts() + 86400,
        )
        # Should not raise
        self.checkout.assert_profile_awg_eligible(prof)

        # Inactive status
        inactive_prof = dict(prof)
        inactive_prof["status"] = "cancelled"
        with self.assertRaises(ValueError):
            self.checkout.assert_profile_awg_eligible(inactive_prof)

        # Expired
        expired_prof = dict(prof)
        expired_prof["expires_at"] = now_ts() - 100
        with self.assertRaises(ValueError):
            self.checkout.assert_profile_awg_eligible(expired_prof)

    def test_04_ensure_awg_slot_and_switch_country_check_eligibility(self) -> None:
        """ensure_awg_slot and switch_awg_slot_country must reject expired profiles."""
        prof = self.store.create_profile(
            xui_inbound_id=1,
            transport="tcp",
            profile_mode="personal",
            family_label=None,
            xui_email="expired@test.com",
            xui_client_id="uuid_exp",
            expires_at=now_ts() - 3600,
            awg_quota_bytes=default_awg_quota_bytes_for_devices(3),
            awg_reset_at=now_ts() - 3600,
        )
        with self.assertRaises(ValueError):
            self.checkout.ensure_awg_slot(prof["public_id"], 1)

        res = self.checkout.switch_awg_slot_country(prof["public_id"], 1, "nl")
        self.assertFalse(res["ok"])
        self.assertIn("истек", res["error"])

    def test_05_safe_read_body_handler(self) -> None:
        """_read_body validates Content-Length and enforces boundaries 0 <= length <= max_bytes."""
        handler = RequestHandler.__new__(RequestHandler)
        handler.headers = {"Content-Length": "10"}
        handler.rfile = io.BytesIO(b"0123456789")
        data = RequestHandler._read_body(handler, max_bytes=65536)
        self.assertEqual(data, b"0123456789")

        # Exceeds max_bytes
        handler.headers = {"Content-Length": "100"}
        handler.rfile = io.BytesIO(b"x" * 100)
        with self.assertRaises(ValueError):
            RequestHandler._read_body(handler, max_bytes=50)

        # Negative Content-Length
        handler.headers = {"Content-Length": "-1"}
        with self.assertRaises(ValueError):
            RequestHandler._read_body(handler, max_bytes=65536)

        # Non-integer
        handler.headers = {"Content-Length": "not_a_number"}
        with self.assertRaises(ValueError):
            RequestHandler._read_body(handler, max_bytes=65536)

        # Empty / missing header
        handler.headers = {}
        self.assertEqual(RequestHandler._read_body(handler, max_bytes=65536), b"")

    def test_06_platega_callback_fail_closed_and_validation(self) -> None:
        """Platega callback requires tx_id, fails closed on API error, and verifies amount/payload."""
        # 1. Missing tx_id
        res, code = self.checkout.handle_platega_callback({"status": "CONFIRMED", "payload": "ord_123"})
        self.assertEqual(code, 404)  # order not found

        # Create test order
        order = self.store.create_order(
            kind="purchase",
            status="waiting_payment",
            transport="tcp",
            duration_days=30,
            profile_mode="personal",
            family_label=None,
            base_price_rub=149,
            final_price_rub=149,
            promo_id=None,
            invite_id=None,
            customer_chat_id=None,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version="v1",
            customer_email="platega_test@example.com",
        )
        ord_id = order["public_id"]

        # Missing tx_id with valid order
        res, code = self.checkout.handle_platega_callback({"status": "CONFIRMED", "payload": ord_id, "id": ""})
        self.assertEqual(code, 400)
        self.assertEqual(res["message"], "missing_transaction_id")

        # Configured platega with unreachable API -> 503 fail-closed
        self.checkout.platega = MagicMock()
        self.checkout.platega.is_configured = True
        self.checkout.platega.get_transaction_status.side_effect = ConnectionError("Platega API timeout")

        res, code = self.checkout.handle_platega_callback({
            "status": "CONFIRMED",
            "id": "tx_fail_closed_999",
            "payload": ord_id,
            "amount": 149.0,
        })
        self.assertEqual(code, 503)
        self.assertEqual(res["message"], "verification_unavailable")

        # Payload mismatch
        self.checkout.platega.get_transaction_status.side_effect = None
        self.checkout.platega.get_transaction_status.return_value = {
            "status": "CONFIRMED",
            "payload": "different_order_id",
            "amount": 149.0,
        }
        res, code = self.checkout.handle_platega_callback({
            "status": "CONFIRMED",
            "id": "tx_mismatch_888",
            "payload": ord_id,
            "amount": 149.0,
        })
        self.assertEqual(code, 400)
        self.assertEqual(res["message"], "payload_mismatch")

        # Amount too low
        self.checkout.platega.get_transaction_status.return_value = {
            "status": "CONFIRMED",
            "payload": ord_id,
            "amount": 50.0,
        }
        res, code = self.checkout.handle_platega_callback({
            "status": "CONFIRMED",
            "id": "tx_underpaid_777",
            "payload": ord_id,
            "amount": 50.0,
        })
        self.assertEqual(code, 400)
        self.assertEqual(res["message"], "amount_too_low")

    def test_07_digiseller_callback_refund_state_check(self) -> None:
        """Digiseller refund must reject if invoice_state is not in (2, 4, 5, 35)."""
        invoice_id = "inv_ref_test_001"
        self.checkout.digiseller = MagicMock()
        self.checkout.digiseller.verify_webhook_signature.return_value = True

        # State 3 (paid/active) must NOT be refunded
        self.checkout.digiseller.get_purchase_info.return_value = {
            "retval": 0,
            "content": {
                "invoice_id": invoice_id,
                "invoice_state": 3,
            },
        }
        res, code = self.checkout.handle_digiseller_callback({
            "id_invoice": invoice_id,
            "action": "refund",
        })
        self.assertEqual(code, 400)
        self.assertEqual(res["message"], "invalid_refund_invoice_state")

        # State 5 (refunded) must be accepted
        self.checkout.digiseller.get_purchase_info.return_value = {
            "retval": 0,
            "content": {
                "invoice_id": "inv_ref_test_002",
                "invoice_state": 5,
            },
        }
        res, code = self.checkout.handle_digiseller_callback({
            "id_invoice": "inv_ref_test_002",
            "action": "refund",
        })
        self.assertEqual(code, 200)
        self.assertEqual(res["message"], "refund_processed")


class TestStage1SubjsonHardening(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_vpn_shop.db"
        self.store = Store(self.db_path)
        self.store.init()

        # Point subjson to this temp store db
        self._orig_find_store_db_path = subjson_app.find_store_db_path
        subjson_app.find_store_db_path = lambda: str(self.db_path)
        subjson_app.invalidate_inbounds_cache()

    def tearDown(self) -> None:
        subjson_app.find_store_db_path = self._orig_find_store_db_path
        try:
            self.temp_dir.cleanup()
        except (PermissionError, OSError):
            pass

    def test_08_subjson_bounded_server(self) -> None:
        """subjson BoundedThreadingHTTPServer has request_queue_size=128."""
        self.assertEqual(subjson_app.BoundedThreadingHTTPServer.request_queue_size, 128)
        self.assertTrue(subjson_app.BoundedThreadingHTTPServer.daemon_threads)

    def test_09_subjson_three_tier_indexing_and_idor_protection(self) -> None:
        """subjson strictly maintains 3-tier indexing and blocks anon- and ord_ queries."""
        # Verify cache dicts exist
        self.assertIsInstance(subjson_app._cached_sub_index, dict)
        self.assertIsInstance(subjson_app._cached_uuid_index, dict)
        self.assertIsInstance(subjson_app._cached_email_index, dict)

        # IDOR probe must immediately raise KeyError
        with self.assertRaises(KeyError):
            subjson_app._find_subscription_impl("anon-12345")
        with self.assertRaises(KeyError):
            subjson_app._find_subscription_impl("ord_abcdef123456")

        # Setup mock cache entries
        mock_row = MagicMock()
        mock_settings = {"clients": []}
        mock_stream = {}
        mock_sniffing = {}
        mock_client = {"subId": "sub_test_123", "id": "uuid_test_456", "email": "email_test_789"}

        with patch.object(subjson_app, "_get_xui_db_mtime", return_value=(1000.0, 0.0, 0)):
            subjson_app._inbounds_cache_mtime = (1000.0, 0.0, 0)
            subjson_app._cached_sub_index["sub_test_123"] = (mock_row, mock_settings, mock_stream, mock_sniffing, mock_client)
            subjson_app._cached_uuid_index["uuid_test_456"] = (mock_row, mock_settings, mock_stream, mock_sniffing, mock_client)
            subjson_app._cached_email_index["email_test_789"] = (mock_row, mock_settings, mock_stream, mock_sniffing, mock_client)

            # Direct subId lookup succeeds
            r, s, st, sn, c = subjson_app._find_subscription_impl("sub_test_123")
            self.assertEqual(c["subId"], "sub_test_123")

            # UUID direct lookup is NOT in sub_index, so it falls back to profiles table lookup
            # Without profile, it raises KeyError
            with self.assertRaises(KeyError):
                subjson_app._find_subscription_impl("uuid_test_456")

    def test_09b_ensure_inbounds_cache_populates_global_indexes(self) -> None:
        """_ensure_inbounds_cache strictly updates module-level global cache dicts."""
        import tempfile
        import sqlite3
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
            db_path = tf.name
        try:
            conn = sqlite3.connect(db_path)
            conn.execute("""
                CREATE TABLE inbounds (
                    id INTEGER PRIMARY KEY,
                    remark TEXT,
                    protocol TEXT,
                    port INTEGER,
                    settings TEXT,
                    stream_settings TEXT,
                    sniffing TEXT
                )
            """)
            client_json = json.dumps({
                "clients": [{
                    "id": "255302f5-5765-4ce1-b753-b2664421a819",
                    "subId": "28njm8v72ruyu2he",
                    "email": "test-admin@silentconnect"
                }]
            })
            conn.execute(
                "INSERT INTO inbounds VALUES (1, 'VLESS', 'vless', 443, ?, '{}', '{}')",
                (client_json,)
            )
            conn.commit()
            conn.close()

            with patch.object(subjson_app, "XUI_DB_PATH", db_path):
                subjson_app.invalidate_inbounds_cache()
                subjson_app._ensure_inbounds_cache()
                
                # Check module-level globals are populated (not left empty by missing global stmt)
                self.assertIn("28njm8v72ruyu2he", subjson_app._cached_sub_index)
                self.assertIn("255302f5-5765-4ce1-b753-b2664421a819", subjson_app._cached_uuid_index)
                self.assertIn("test-admin@silentconnect", subjson_app._cached_email_index)
                
                # find_subscription must resolve the real UUID
                row, settings, stream, sniff, client = subjson_app.find_subscription("28njm8v72ruyu2he")
                self.assertEqual(client["id"], "255302f5-5765-4ce1-b753-b2664421a819")
        finally:
            if os.path.exists(db_path):
                os.unlink(db_path)

    def test_10_subjson_rate_limit_no_localhost_bypass(self) -> None:
        """check_bind_email_rate_limit must not bypass 127.0.0.1."""
        client_ip = "127.0.0.1"
        with subjson_app.BIND_EMAIL_RATE_LIMIT_LOCK:
            subjson_app.BIND_EMAIL_RATE_LIMITS.clear()

        # Send 15 requests
        for _ in range(15):
            allowed = subjson_app.check_bind_email_rate_limit(client_ip, max_requests=15, window_sec=300)
            self.assertTrue(allowed)

        # 16th request must be blocked
        blocked = subjson_app.check_bind_email_rate_limit(client_ip, max_requests=15, window_sec=300)
        self.assertFalse(blocked)

    def test_11_find_store_linked_email_delivered_filter(self) -> None:
        """find_store_linked_email only returns email from orders with status='delivered'."""
        with patch.object(subjson_app, "get_store_db", side_effect=self.store.connect):
            prof = self.store.create_profile(
                xui_inbound_id=1,
                transport="tcp",
                profile_mode="personal",
                family_label=None,
                xui_email="linked@test.com",
                xui_client_id="uuid_linked",
                expires_at=now_ts() + 86400,
                awg_quota_bytes=default_awg_quota_bytes_for_devices(3),
                awg_reset_at=now_ts() + 86400,
            )

            # Create waiting_payment order (not delivered)
            with self.store.connection() as conn:
                conn.execute(
                    """
                    INSERT INTO orders(public_id, kind, status, transport, duration_days, profile_mode,
                                       base_price_rub, final_price_rub, privacy_ack, loss_policy_ack,
                                       terms_version, provisioned_profile_id, customer_email, created_at, updated_at)
                    VALUES('ord_waiting', 'new', 'waiting_payment', 'tcp', 30, 'personal',
                           149, 149, 1, 1, '2026-04-20', ?, 'undelivered@test.com', ?, ?)
                    """,
                    (prof["id"], now_ts(), now_ts())
                )

            # Should return empty because order is not delivered
            self.assertEqual(subjson_app.find_store_linked_email(prof["public_id"]), "")

            # Update order to delivered
            with self.store.connection() as conn:
                conn.execute("UPDATE orders SET status = 'delivered' WHERE public_id = 'ord_waiting'")

            # Now should return customer_email
            self.assertEqual(subjson_app.find_store_linked_email(prof["public_id"]), "undelivered@test.com")

    def test_12_encrypt_happ_link_ttl_cache(self) -> None:
        """encrypt_happ_link caches results for TTL seconds and avoids repeat outbound calls."""
        subjson_app._HAPP_LINK_CACHE.clear()
        test_url = "https://sub.silentconnect.net/test-sub-url"
        encrypted_val = "happ://encrypted-key-123"

        # Prime cache
        with subjson_app._HAPP_LINK_CACHE_LOCK:
            subjson_app._HAPP_LINK_CACHE[test_url] = (time.time(), encrypted_val)

        # Call encrypt_happ_link - should return cached value without network call
        with patch("urllib.request.urlopen") as mock_url:
            result = subjson_app.encrypt_happ_link(test_url)
            self.assertEqual(result, encrypted_val)
            mock_url.assert_not_called()

    def test_13_is_quiesced_lease_expiration(self) -> None:
        """is_quiesced auto-clears if QUIESCE_LEASE_UNTIL has passed."""
        with subjson_app.QUIESCE_LOCK:
            subjson_app.QUIESCE_ACTIVE = True
            subjson_app.QUIESCE_LEASE_UNTIL = time.time() + 10.0

        self.assertTrue(subjson_app.is_quiesced())

        # Expired lease
        with subjson_app.QUIESCE_LOCK:
            subjson_app.QUIESCE_ACTIVE = True
            subjson_app.QUIESCE_LEASE_UNTIL = time.time() - 1.0

        self.assertFalse(subjson_app.is_quiesced())
        self.assertFalse(subjson_app.QUIESCE_ACTIVE)

    def test_14_telegram_markdown_escaping(self) -> None:
        """_escape_tg_markdown correctly escapes Markdown v1 special characters."""
        raw = "order_123*vip*[pack]`id`"
        escaped = subjson_app._escape_tg_markdown(raw)
        self.assertEqual(escaped, "order\\_123\\*vip\\*\\[pack\\]\\`id\\`")


if __name__ == "__main__":
    unittest.main()
