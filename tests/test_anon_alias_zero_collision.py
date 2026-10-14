import json
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
VPN_SHOP_DIR = PROJECT_ROOT / "vpn-shop"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(VPN_SHOP_DIR) not in sys.path:
    sys.path.insert(0, str(VPN_SHOP_DIR))

from vpn_shop import bot
from vpn_shop.config import Settings
from vpn_shop.security import order_to_profile_alias, public_id
from vpn_shop.store import Store


class TestAnonAliasZeroCollision(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.store = Store(self.db_path)
        self.store.init()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_order_to_profile_alias(self):
        """Verify deterministic conversion from order public_id to anon- profile alias."""
        self.assertEqual(order_to_profile_alias("ord_sw9hanyu8q12"), "anon-sw9hanyu8q12")
        self.assertEqual(order_to_profile_alias("ord_sw9hanyu8q12", suffix="tcp"), "anon-sw9hanyu8q12-tcp")
        self.assertEqual(order_to_profile_alias("ord_sw9hanyu8q12", suffix="xhttp"), "anon-sw9hanyu8q12-xhttp")
        # Non-prefixed fallback
        self.assertEqual(order_to_profile_alias("sw9hanyu8q12"), "anon-sw9hanyu8q12")
        self.assertEqual(order_to_profile_alias("sw9hanyu8q12", suffix="tcp"), "anon-sw9hanyu8q12-tcp")

    def test_public_id_default_entropy(self):
        """Verify default token entropy has 12 chars plus prefix."""
        pid = public_id("ord")
        self.assertTrue(pid.startswith("ord_"))
        token = pid.removeprefix("ord_")
        self.assertEqual(len(token), 12)

    def test_create_order_retry_loop_on_collision(self):
        """Verify that create_order retries up to 5 times if a collision occurs on orders.public_id."""
        # 1. Create an existing order first
        existing_order = self.store.create_order(
            kind="purchase",
            status="waiting_payment",
            transport="tcp",
            duration_days=30,
            profile_mode="anonymous",
            family_label=None,
            base_price_rub=100,
            final_price_rub=100,
            promo_id=None,
            invite_id=None,
            customer_chat_id=123,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version="2026-08-22",
        )
        colliding_id = existing_order["public_id"]

        call_count = 0
        def colliding_public_id(prefix, size=12):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return colliding_id  # Triggers real SQLite IntegrityError
            return public_id(prefix, size=size)

        with patch("vpn_shop.store.public_id", side_effect=colliding_public_id):
            order = self.store.create_order(
                kind="purchase",
                status="waiting_payment",
                transport="tcp",
                duration_days=30,
                profile_mode="anonymous",
                family_label=None,
                base_price_rub=100,
                final_price_rub=100,
                promo_id=None,
                invite_id=None,
                customer_chat_id=456,
                privacy_ack=True,
                loss_policy_ack=True,
                terms_version="2026-08-22",
            )
            self.assertIsNotNone(order)
            self.assertNotEqual(order["public_id"], colliding_id)
            self.assertEqual(call_count, 3)  # Collided twice, succeeded on 3rd try!

    def _make_mock_settings(self):
        settings = MagicMock(spec=Settings)
        settings.root_dir = Path(self.temp_dir.name)
        settings.data_dir = Path(self.temp_dir.name)
        settings.database_path = self.db_path
        settings.telegram_bot_token = "123456:dummy_token"
        settings.telegram_bot_username = "SilentConnectVPNBot"
        settings.support_tg_url = "https://t.me/support"
        settings.admin_user_ids = (12345,)
        settings.admin_usernames = ()
        settings.default_device_limit = 3
        settings.monthly_price_tcp_rub = 100
        settings.monthly_price_xhttp_rub = 150
        settings.monthly_price_3_devices_rub = 100
        settings.monthly_price_6_devices_rub = 200
        settings.monthly_price_9_devices_rub = 300
        settings.subscription_base_url = "https://sub.example.com/sub/json"
        settings.web_public_base_url = "https://vpn.example.com"
        settings.xui_panel_url = "http://127.0.0.1:2053"
        settings.xui_username = "admin"
        settings.xui_password = "admin"
        settings.xui_verify_tls = False
        settings.xui_xhttp_inbound_id = 1
        settings.xui_tcp_inbound_id = 2
        settings.xui_db_path = Path(self.temp_dir.name) / "xui.db"
        settings.smtp_host = ""
        settings.smtp_user = ""
        settings.smtp_password = ""
        settings.smtp_from = ""
        return settings

    def test_recover_stale_orders_with_anon_and_legacy_ord(self):
        """Verify recover_stale_orders recovers both new anon- aliases and legacy ord_ aliases."""
        settings = self._make_mock_settings()
        bot_instance = bot.ShopBot(settings=settings, store=self.store)
        bot_instance.telegram = MagicMock()

        # 1. New anon- order
        order_new = self.store.create_order(
            kind="purchase",
            status="waiting_payment",
            transport="tcp",
            duration_days=30,
            profile_mode="anonymous",
            family_label=None,
            base_price_rub=100,
            final_price_rub=100,
            promo_id=None,
            invite_id=None,
            customer_chat_id=111,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version="2026-08-22",
        )
        self.store.transition_order(order_new["public_id"], "provisioning", expected_from=("waiting_payment",))

        # 2. Legacy ord_ order
        order_legacy = self.store.create_order(
            kind="purchase",
            status="waiting_payment",
            transport="tcp",
            duration_days=30,
            profile_mode="anonymous",
            family_label=None,
            base_price_rub=100,
            final_price_rub=100,
            promo_id=None,
            invite_id=None,
            customer_chat_id=222,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version="2026-08-22",
        )
        self.store.transition_order(order_legacy["public_id"], "provisioning", expected_from=("waiting_payment",))

        # Backdate both
        with self.store._connect() as conn:
            conn.execute(
                "UPDATE orders SET updated_at = ? WHERE public_id IN (?, ?)",
                (int(time.time()) - 1000, order_new["public_id"], order_legacy["public_id"]),
            )
            conn.commit()

        expected_anon = order_to_profile_alias(order_new["public_id"])
        expected_legacy = str(order_legacy["public_id"])

        mock_xui_db = MagicMock()
        def mock_find_by_email(email):
            if email == expected_anon:
                return {
                    "inbound_id": 1,
                    "client": {
                        "id": "uuid-anon-1",
                        "email": expected_anon,
                        "subId": "sub_anon_1",
                        "expiryTime": (int(time.time()) + 86400 * 30) * 1000,
                    }
                }
            if email == expected_legacy:
                return {
                    "inbound_id": 1,
                    "client": {
                        "id": "uuid-legacy-2",
                        "email": expected_legacy,
                        "subId": "sub_legacy_2",
                        "expiryTime": (int(time.time()) + 86400 * 30) * 1000,
                    }
                }
            return None

        mock_xui_db.find_client_by_email.side_effect = mock_find_by_email
        bot_instance.provisioner.xui_db = mock_xui_db

        recovered = bot_instance.recover_stale_orders(older_than_seconds=600)
        self.assertEqual(len(recovered), 2)
        recovered_orders = {r["order"] for r in recovered}
        self.assertIn(order_new["public_id"], recovered_orders)
        self.assertIn(order_legacy["public_id"], recovered_orders)

        prof_new = self.store.get_profile_for_order(order_new["public_id"])
        self.assertEqual(prof_new["xui_email"], expected_anon)

        prof_legacy = self.store.get_profile_for_order(order_legacy["public_id"])
        self.assertEqual(prof_legacy["xui_email"], expected_legacy)

    def test_subjson_display_identifier_prettification(self):
        """Verify that subjson subscription_summary formats ord_ emails cleanly as anon-."""
        import os
        os.environ.setdefault("HYSTERIA_SALAMANDER_PASSWORD", "test_salamander_pwd")
        os.environ.setdefault("HYSTERIA_AUTH_PASSWORD", "test_auth_pwd")
        os.environ.setdefault("PUBLIC_HOST", "sub.example.com")
        os.environ.setdefault("WS443_PUBLIC_HOST", "edge.example.com")
        os.environ.setdefault("FI_STANDBY_HOST", "fi.example.com")
        os.environ.setdefault("PUBLIC_SUBSCRIPTION_ORIGIN", "https://sub.example.com")

        subjson_dir = PROJECT_ROOT / "subjson-service"
        if str(subjson_dir) not in sys.path:
            sys.path.insert(0, str(subjson_dir))
        import app as subjson_app

        orig_find_sub = subjson_app.find_subscription
        try:
            # 1. Legacy ord_ email in X-UI
            subjson_app.find_subscription = lambda sid: (
                1, "tag", "vless", 443,
                {"email": "ord_sw9hanyu8q", "id": "uuid-1", "expiryTime": (int(time.time()) + 86400) * 1000}
            )
            summary_legacy = subjson_app.subscription_summary("test_sub_id")
            self.assertEqual(summary_legacy["identifier"], "anon-sw9hanyu8q")

            # 2. Modern anon- email in X-UI
            subjson_app.find_subscription = lambda sid: (
                1, "tag", "vless", 443,
                {"email": "anon-sw9hanyu8q", "id": "uuid-1", "expiryTime": (int(time.time()) + 86400) * 1000}
            )
            summary_anon = subjson_app.subscription_summary("test_sub_id")
            self.assertEqual(summary_anon["identifier"], "anon-sw9hanyu8q")
        finally:
            subjson_app.find_subscription = orig_find_sub


if __name__ == "__main__":
    unittest.main()
