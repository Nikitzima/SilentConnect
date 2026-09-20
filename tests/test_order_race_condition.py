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
        settings.smtp_host = ""
        settings.smtp_user = ""
        settings.smtp_password = ""
        settings.smtp_from = ""
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

    def test_concurrent_maybe_auto_deliver_free_web_order_provisions_exactly_once(self):
        """Verify two concurrent maybe_auto_deliver_free_web_order calls provision exactly once."""
        from vpn_shop import web
        settings = self._make_mock_settings()
        provisioner_mock = MagicMock()
        created_profiles = []

        def fake_create_profile(order):
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

        checkout = web.WebCheckout(settings=settings, store=self.store)
        checkout.provisioner = provisioner_mock

        code, promo = self.store.create_promo_code(
            promo_type="fixed",
            transport="tcp",
            duration_days=30,
            discount_percent=100,
            fixed_price_rub=0,
            profile_mode="anonymous",
            max_uses=1,
        )

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
            customer_email="free@example.com",
        )

        results = []
        errors = []

        def call_deliver():
            try:
                ord_data = self.store.get_order(order["public_id"])
                res = checkout.maybe_auto_deliver_free_web_order(ord_data)
                results.append(res)
            except Exception as exc:
                errors.append(exc)

        t1 = threading.Thread(target=call_deliver)
        t2 = threading.Thread(target=call_deliver)

        t1.start()
        t2.start()
        t1.join()
        t2.join()

        self.assertEqual(len(created_profiles), 1, f"Expected 1 profile created, got {len(created_profiles)}")
        self.assertEqual(provisioner_mock.create_profile_for_order.call_count, 1)

        final_order = self.store.get_order(order["public_id"])
        self.assertEqual(final_order["status"], "delivered")
        promo_row = self.store.get_promo_code(promo["id"])
        self.assertEqual(promo_row["used_count"], 1)

    def test_recover_stale_order_after_cas_crash(self):
        """Crash scenario (a): Process crashed right after CAS into provisioning.
        Neither profile nor X-UI client was created.
        Stale recovery should mark order 'failed' and restore promo code.
        """
        settings = self._make_mock_settings()
        bot_instance = bot.ShopBot(settings=settings, store=self.store)

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
        )
        self.store.transition_order(order["public_id"], "provisioning", expected_from=("auto_provision",))

        with self.store._connect() as conn:
            conn.execute(
                "UPDATE orders SET updated_at = ? WHERE public_id = ?",
                (int(time.time()) - 1000, order["public_id"]),
            )
            conn.commit()

        recovered = bot_instance.recover_stale_orders(older_than_seconds=600)
        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0]["action"], "failed")

        final_order = self.store.get_order(order["public_id"])
        self.assertEqual(final_order["status"], "failed")
        promo_row = self.store.get_promo_code(promo["id"])
        self.assertEqual(promo_row["used_count"], 0)

    def test_recover_stale_order_after_xui_client_creation_crash(self):
        """Crash scenario (b): Process crashed after X-UI client was created, but before profile was linked.
        Stale recovery should find the deterministic X-UI client, create profile, link it, and mark delivered.
        """
        settings = self._make_mock_settings()
        bot_instance = bot.ShopBot(settings=settings, store=self.store)

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
        self.store.transition_order(order["public_id"], "provisioning", expected_from=("waiting_payment",))

        mock_xui_db = MagicMock()
        mock_xui_db.find_client_by_email.return_value = {
            "inbound_id": 2,
            "client": {
                "id": "mock-uuid-1234",
                "email": str(order["public_id"]),
                "subId": "mocksub123",
                "expiryTime": (int(time.time()) + 86400 * 30) * 1000,
            }
        }
        bot_instance.provisioner.xui_db = mock_xui_db

        with self.store._connect() as conn:
            conn.execute(
                "UPDATE orders SET updated_at = ? WHERE public_id = ?",
                (int(time.time()) - 1000, order["public_id"]),
            )
            conn.commit()

        recovered = bot_instance.recover_stale_orders(older_than_seconds=600)
        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0]["action"], "delivered")

        final_order = self.store.get_order(order["public_id"])
        self.assertEqual(final_order["status"], "delivered")
        self.assertIsNotNone(final_order["provisioned_profile_id"])

        linked_profile = self.store.get_profile_for_order(order["public_id"])
        self.assertIsNotNone(linked_profile)
        self.assertEqual(linked_profile["xui_email"], str(order["public_id"]))

