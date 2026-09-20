import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock

PROJECT_ROOT = Path(__file__).resolve().parent.parent
VPN_SHOP_DIR = PROJECT_ROOT / "vpn-shop"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(VPN_SHOP_DIR) not in sys.path:
    sys.path.insert(0, str(VPN_SHOP_DIR))

from vpn_shop import bot
from vpn_shop.config import Settings
from vpn_shop.store import Store


class TestOrderRaceCondition(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.store = Store(self.db_path)
        self.store.init()

    def tearDown(self):
        self.temp_dir.cleanup()

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
        return settings

    def test_concurrent_complete_order_provisions_exactly_once(self):
        """Verify two concurrent complete_order calls for the same order provision exactly once."""
        settings = self._make_mock_settings()
        provisioner_mock = MagicMock()
        created_profiles = []

        def fake_create_profile(order):
            # Simulate real network/db latency during provisioning
            time.sleep(0.05)
            prof = self.store.create_profile(
                xui_inbound_id=1,
                transport=order["transport"],
                profile_mode=order["profile_mode"],
                family_label=order.get("family_label"),
                xui_email=f"user_{order['public_id']}_{len(created_profiles)}",
                xui_client_id=f"client_{len(created_profiles)}",
                expires_at=int(time.time()) + 86400 * 30,
            )
            created_profiles.append(prof)
            return {
                "profile": prof,
                "subscription_url": f"https://sub.example.com/{prof['public_id']}",
                "sub_id": prof["public_id"],
                "expires_at": prof["expires_at"],
            }

        provisioner_mock.create_profile_for_order.side_effect = fake_create_profile

        bot_instance = bot.ShopBot(settings=settings, store=self.store)
        bot_instance.provisioner = provisioner_mock
        bot_instance.telegram = MagicMock()

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
            customer_chat_id=123456,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version="2026-08-22",
        )

        results = []
        errors = []

        def call_complete(actor_name):
            try:
                ord_data = self.store.get_order(order["public_id"])
                res = bot_instance.complete_order(ord_data, actor=actor_name)
                results.append((actor_name, res))
            except Exception as exc:
                errors.append((actor_name, exc))

        t1 = threading.Thread(target=call_complete, args=("webhook_caller",))
        t2 = threading.Thread(target=call_complete, args=("user_check_caller",))

        t1.start()
        t2.start()
        t1.join()
        t2.join()

        self.assertEqual(len(created_profiles), 1, f"Expected exactly 1 profile created, but got {len(created_profiles)}")
        self.assertEqual(provisioner_mock.create_profile_for_order.call_count, 1)

        final_order = self.store.get_order(order["public_id"])
        self.assertEqual(final_order["status"], "delivered")
