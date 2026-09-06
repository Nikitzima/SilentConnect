import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock

PROJECT_ROOT = Path(__file__).resolve().parent.parent
VPN_SHOP_DIR = PROJECT_ROOT / "vpn-shop"
if str(VPN_SHOP_DIR) not in sys.path:
    sys.path.insert(0, str(VPN_SHOP_DIR))

from vpn_shop.bot import ShopBot
from vpn_shop.config import Settings
from vpn_shop.store import Store
from vpn_shop.web import WebCheckout


TEST_ADMIN_ID = 111222333
MOCK_PAYMENT_URL = "https://bank.example.com/pay/secret"


def make_test_settings(temp_dir: Path) -> Settings:
    db_path = temp_dir / "vpn_shop.db"
    return Settings(
        root_dir=temp_dir,
        data_dir=temp_dir,
        database_path=db_path,
        telegram_bot_token="123456:TEST_TOKEN",
        telegram_bot_username="SilentConnectVPNBot",
        brand_name="SilentConnect",
        welcome_media="",
        support_tg_url="https://t.me/example_support",
        quickstart_media="",
        admin_usernames=("admin",),
        admin_user_ids=(TEST_ADMIN_ID,),
        subscription_base_url="https://sub.example.com",
        payment_instructions_text="Переведите на карту",
        payment_transfer_url=MOCK_PAYMENT_URL,
        payment_bank_note="МТС Банк",
        xui_panel_url="",
        xui_username="",
        xui_password="",
        xui_verify_tls=False,
        xui_db_path=temp_dir / "x-ui.db",
        xui_xhttp_inbound_id=1,
        xui_tcp_inbound_id=2,
        web_listen_host="127.0.0.1",
        web_listen_port=3090,
        web_public_base_url="https://example.com",
        monthly_price_xhttp_rub=199,
        monthly_price_tcp_rub=199,
        monthly_price_3_devices_rub=199,
        monthly_price_6_devices_rub=299,
        monthly_price_9_devices_rub=399,
        default_device_limit=3,
        invite_required=False,
        terms_version="2026-04-20",
        purge_after_days=30,
        support_email="support@example.com",
        smtp_host="",
        smtp_port=587,
        smtp_user="",
        smtp_password="",
        smtp_from_email="support@example.com",
        cf_turnstile_site_key="",
        cf_turnstile_secret_key="",
        cf_turnstile_enabled=False,
    )


class TestOperatorPaymentFlow(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        temp_path = Path(self.temp_dir.name)
        self.settings = make_test_settings(temp_path)
        self.store = Store(self.settings.data_dir / "vpn_shop.db")
        self.store.init()
        self.store.set_session(TEST_ADMIN_ID, "admin", "menu", {"admin": True})

        self.web = WebCheckout(settings=self.settings, store=self.store)
        self.web.telegram = MagicMock()

        self.bot = ShopBot(self.settings, self.store)
        self.bot.telegram = MagicMock()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_web_render_order_privacy_and_operator_link(self):
        offer_code = list(self.web.offers.keys())[0]
        order = self.web.create_order(
            offer_code=offer_code,
            customer_email="customer@example.com",
        )
        self.assertEqual(order["status"], "waiting_payment")

        html_bytes = self.web.render_order({}, order)
        html = html_bytes.decode("utf-8")

        # Must contain operator button pointing to support_tg_url
        self.assertIn("💬 Написать оператору для оплаты", html)
        self.assertIn(self.settings.support_tg_url, html)
        self.assertIn(str(order["public_id"]), html)

        # Must NOT expose private mock payment link or bank notes
        self.assertNotIn(MOCK_PAYMENT_URL, html)
        self.assertNotIn("МТС Банк", html)

    def test_web_create_order_sends_instant_admin_notification(self):
        self.web.telegram.reset_mock()
        offer_code = list(self.web.offers.keys())[0]
        order = self.web.create_order(
            offer_code=offer_code,
            customer_email="customer2@example.com",
        )
        self.assertEqual(order["status"], "waiting_payment")

        # Admin must have received an immediate notification
        self.web.telegram.send_message.assert_called()
        call_args = self.web.telegram.send_message.call_args[0]
        sent_chat_id = call_args[0]
        sent_text = call_args[1]
        kwargs = self.web.telegram.send_message.call_args[1]

        self.assertEqual(str(sent_chat_id), str(TEST_ADMIN_ID))
        self.assertIn("Новый заказ на сайте (ожидает оплаты)", sent_text)
        self.assertIn(order["public_id"], sent_text)
        self.assertIn("customer2@example.com", sent_text)

        # Inline buttons must be attached
        markup = kwargs.get("reply_markup") or {}
        keyboard = markup.get("inline_keyboard", [])
        button_callbacks = [btn["callback_data"] for row in keyboard for btn in row]
        self.assertIn(f"admin:confirm:{order['public_id']}", button_callbacks)
        self.assertIn(f"admin:cancel:{order['public_id']}", button_callbacks)

    def test_web_mark_paid_sends_payment_reported_alert(self):
        offer_code = list(self.web.offers.keys())[0]
        order = self.web.create_order(
            offer_code=offer_code,
            customer_email="customer3@example.com",
        )
        self.web.telegram.reset_mock()

        result_msg = self.web.mark_paid({}, order)
        self.assertIn("Уведомление отправлено", result_msg)

        self.web.telegram.send_message.assert_called()
        sent_text = self.web.telegram.send_message.call_args[0][1]
        self.assertIn("🔔 Покупатель с сайта нажал «Оплачено»!", sent_text)
        self.assertIn(order["public_id"], sent_text)
        self.assertIn("customer3@example.com", sent_text)

    def test_bot_waiting_payment_markup_and_message(self):
        order = self.store.create_order(
            kind="standard",
            transport="tcp",
            duration_days=30,
            base_price_rub=199,
            final_price_rub=199,
            status="waiting_payment",
            profile_mode="anonymous",
            family_label=None,
            promo_id=None,
            invite_id=None,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version=self.settings.terms_version,
            customer_chat_id=12345,
            meta={"device_limit": 3},
        )

        markup = self.bot._public_waiting_payment_markup(order["public_id"])
        msg = self.bot._waiting_payment_message(order)

        buttons = [btn for row in markup.get("inline_keyboard", []) for btn in row]
        operator_btn = next((b for b in buttons if "💬 Написать оператору для оплаты" in b.get("text", "")), None)
        self.assertIsNotNone(operator_btn)
        self.assertEqual(operator_btn.get("url"), self.settings.support_tg_url)

        self.assertIn("💬 Написать оператору для оплаты", msg)
        self.assertIn(order["public_id"], msg)
        self.assertNotIn(MOCK_PAYMENT_URL, msg)
        self.assertNotIn("МТС Банк", msg)


if __name__ == "__main__":
    unittest.main()
