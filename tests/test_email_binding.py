import os
import sys
import time
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

TEST_DIR = Path(__file__).resolve().parent
REPO_ROOT = TEST_DIR.parent
SUBJSON_DIR = REPO_ROOT / "subjson-service"
VPNSHOP_DIR = REPO_ROOT / "vpn-shop"

for p in (str(REPO_ROOT), str(SUBJSON_DIR), str(VPNSHOP_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

# Set test environment variables before importing app
os.environ["SECRET_SEGMENT"] = "my-secret-sub"
os.environ["INTERNAL_SECRET"] = "internal-token-xyz"
os.environ["HYSTERIA_SALAMANDER_PASSWORD"] = "485a96779d1ad79d0fa80ca0"
os.environ["HYSTERIA_AUTH_PASSWORD"] = "test_auth_pwd"
os.environ["PUBLIC_HOST"] = "sub.example.com"
os.environ["WS443_PUBLIC_HOST"] = "edge.example.com"
os.environ["FI_STANDBY_HOST"] = "fi.example.com"
os.environ["PUBLIC_SUBSCRIPTION_ORIGIN"] = "https://sub.example.com"

import app as subjson_app
from vpn_shop.store import Store
from vpn_shop.config import Settings


class TestEmailBinding(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_dir = Path(self.tmpdir.name)
        self.shop_db_path = self.db_dir / "vpn_shop.db"
        self.xui_db_path = self.db_dir / "x-ui.db"

        self.store = Store(str(self.shop_db_path))
        self.store.init()

        with sqlite3.connect(self.xui_db_path) as conn:
            conn.execute(
                """
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
                );
                """
            )
            settings = {
                "clients": [
                    {
                        "id": "uuid-test-1234",
                        "email": "anon-testsub123",
                        "subId": "sub_test_token_123",
                        "enable": True,
                        "expiryTime": int((time.time() + 86400 * 30) * 1000),
                    }
                ]
            }
            conn.execute(
                "INSERT INTO inbounds (id, enable, protocol, settings) VALUES (1, 1, 'vless', ?)",
                (json.dumps(settings),)
            )
            conn.commit()

        self.orig_xui_db = subjson_app.XUI_DB_PATH
        self.orig_find_store = subjson_app.find_store_db_path
        subjson_app.XUI_DB_PATH = str(self.xui_db_path)
        subjson_app.find_store_db_path = lambda: str(self.shop_db_path)
        subjson_app.invalidate_inbounds_cache()

        with subjson_app.BIND_EMAIL_RATE_LIMIT_LOCK:
            subjson_app.BIND_EMAIL_RATE_LIMITS.clear()

    def tearDown(self):
        subjson_app.XUI_DB_PATH = self.orig_xui_db
        subjson_app.find_store_db_path = self.orig_find_store
        subjson_app.invalidate_inbounds_cache()
        import gc
        gc.collect()
        try:
            self.tmpdir.cleanup()
        except Exception:
            pass

    def test_mask_email(self):
        self.assertEqual(subjson_app.mask_email("a@b.com"), "a***@b.com")
        self.assertEqual(subjson_app.mask_email("alex@gmail.com"), "al***@gmail.com")
        self.assertEqual(subjson_app.mask_email("test.user@mail.ru"), "te***@mail.ru")
        self.assertEqual(subjson_app.mask_email(""), "")
        self.assertEqual(subjson_app.mask_email("invalid"), "")

    def test_bind_email_validation(self):
        with self.assertRaises(ValueError) as ctx:
            subjson_app.bind_subscription_email("sub_test_token_123", "not-an-email")
        self.assertIn("корректный адрес", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            subjson_app.bind_subscription_email("sub_test_token_123", "@domain.com")
        self.assertIn("корректный адрес", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            subjson_app.bind_subscription_email("non_existent_token_999", "user@test.com")
        self.assertIn("Подписка не найдена", str(ctx.exception))

    def test_bind_email_success_with_existing_order(self):
        prof = self.store.create_profile(
            xui_inbound_id=1,
            transport="tcp",
            profile_mode="anonymous",
            family_label=None,
            xui_email="anon-testsub123",
            xui_client_id="uuid-test-1234",
            expires_at=int(time.time() + 86400 * 30),
        )
        ord_obj = self.store.create_order(
            kind="standard",
            status="delivered",
            transport="tcp",
            duration_days=30,
            profile_mode="anonymous",
            family_label=None,
            base_price_rub=100,
            final_price_rub=100,
            promo_id=None,
            invite_id=None,
            customer_chat_id=None,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version="2026-04-20",
            customer_email="",
            meta={"device_limit": 3},
        )
        self.store.link_order_profile(ord_obj["public_id"], prof["public_id"])

        with patch("vpn_shop.mailer.send_subscription_email_async") as mock_mail:
            res = subjson_app.bind_subscription_email(
                sub_id="sub_test_token_123",
                customer_email="User@Gmail.COM",
                email_reminders=True,
                client_ip="192.168.1.50",
            )
            self.assertTrue(res["ok"])
            self.assertEqual(res["customer_email"], "user@gmail.com")

        orders = self.store.get_active_profiles_by_customer_email("user@gmail.com")
        self.assertEqual(len(orders), 1)
        self.assertEqual(orders[0]["public_id"], prof["public_id"])

        linked = subjson_app.find_store_linked_email("sub_test_token_123")
        self.assertEqual(linked, "user@gmail.com")

        reminders = self.store.get_profiles_due_for_email_reminder(
            "1_day", min_seconds_left=0, max_seconds_left=86400 * 40
        )
        self.assertEqual(len(reminders), 1)
        self.assertEqual(reminders[0]["customer_email"], "user@gmail.com")

    def test_bind_email_success_without_prior_order(self):
        with patch("vpn_shop.mailer.send_subscription_email_async") as mock_mail:
            res = subjson_app.bind_subscription_email(
                sub_id="sub_test_token_123",
                customer_email="alex.new@proton.me",
                email_reminders=True,
                client_ip="10.0.0.1",
            )
            self.assertTrue(res["ok"])
            self.assertEqual(res["customer_email"], "alex.new@proton.me")

        profiles = self.store.get_active_profiles_by_customer_email("alex.new@proton.me")
        self.assertEqual(len(profiles), 1)
        self.assertEqual(profiles[0]["xui_email"], "anon-testsub123")

        linked = subjson_app.find_store_linked_email("sub_test_token_123")
        self.assertEqual(linked, "alex.new@proton.me")

    def test_bind_email_rate_limit(self):
        ip = "198.51.100.42"
        for _ in range(5):
            self.assertTrue(subjson_app.check_bind_email_rate_limit(ip, max_requests=5, window_sec=60))
        self.assertFalse(subjson_app.check_bind_email_rate_limit(ip, max_requests=5, window_sec=60))

    def test_setup_page_html_contains_bind_elements(self):
        html_bytes = subjson_app.setup_page_html(
            subscription_url="https://sub.example.com/my-secret-sub/json/sub_test_token_123",
            subscription_id="sub_test_token_123",
            quoted_sub_id="sub_test_token_123",
            import_query="url=test",
            customer_email="al***@gmail.com",
        )
        html_str = html_bytes.decode("utf-8")

        self.assertIn('id="bind_email_only"', html_str)
        self.assertIn("toggleBindEmailOnly(this.checked)", html_str)
        self.assertIn('id="renew-plan-selectors"', html_str)
        self.assertIn('id="linked-email-badge"', html_str)
        self.assertIn('id="renew-submit-btn"', html_str)
        self.assertIn('id="renew-price-label"', html_str)
        self.assertIn("al***@gmail.com", html_str)
        self.assertIn("Только привязать почту", html_str)


if __name__ == "__main__":
    unittest.main()
