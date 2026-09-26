import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

PROJECT_ROOT = Path(__file__).resolve().parent.parent
VPN_SHOP_DIR = PROJECT_ROOT / "vpn-shop"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(VPN_SHOP_DIR) not in sys.path:
    sys.path.insert(0, str(VPN_SHOP_DIR))

from vpn_shop.bot import ShopBot
from vpn_shop.config import Settings
from vpn_shop.store import Store


class TestBotPromoSessionFlow(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.store = Store(self.db_path)
        self.store.init()

        self.settings = MagicMock(spec=Settings)
        self.settings.root_dir = Path(self.temp_dir.name)
        self.settings.data_dir = Path(self.temp_dir.name)
        self.settings.database_path = self.db_path
        self.settings.telegram_bot_token = "123456:dummy_token"
        self.settings.telegram_bot_username = "SilentConnectVPNBot"
        self.settings.support_tg_url = "https://t.me/support"
        self.settings.admin_user_ids = (12345,)
        self.settings.admin_usernames = ()
        self.settings.default_device_limit = 3
        self.settings.monthly_price_tcp_rub = 100
        self.settings.monthly_price_xhttp_rub = 150
        self.settings.monthly_price_3_devices_rub = 100
        self.settings.monthly_price_6_devices_rub = 200
        self.settings.monthly_price_9_devices_rub = 300
        self.settings.subscription_base_url = "https://sub.example.com/sub/json"
        self.settings.web_public_base_url = "https://vpn.example.com"
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
        self.settings.brand_name = "SilentConnect"
        self.settings.platega_merchant_id_bot = ""
        self.settings.platega_merchant_id_web = ""
        self.settings.platega_secret = ""
        self.settings.platega_secret_bot = ""
        self.settings.platega_secret_web = ""
        self.settings.platega_enabled = False

        self.bot = ShopBot(self.settings, self.store)
        self.bot.telegram = MagicMock()
        self.bot.provisioner = MagicMock()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_promo_leak_and_start_reset(self):
        chat_id = 8569278809

        # 1. User was previously in renewal flow: promo_return="renewal" was saved in session
        self.store.set_session(
            chat_id,
            "public",
            "menu",
            {
                "public_access": True,
                "renewal_profile_public_id": "prf_twqb4wfgmv",
                "promo_return": "renewal",
            },
        )

        # 2. User clicks "Ввести промокод" from main menu (public:promo callback)
        update_promo_click = {
            "callback_query": {
                "id": "cb1",
                "data": "public:promo",
                "message": {"message_id": 101, "chat": {"id": chat_id}},
                "from": {"id": chat_id, "first_name": "Test"},
            }
        }
        self.bot.handle_update(update_promo_click)

        # Verify state is await_promo_code
        session = self.store.get_session(chat_id)
        self.assertEqual(session["state"], "await_promo_code")
        context = self.bot._context_from_session(session)
        # BUG CHECK: promo_return and renewal_profile_public_id must NOT be present!
        self.assertNotIn("promo_return", context)
        self.assertNotIn("renewal_profile_public_id", context)

        # 3. User types /start to exit
        update_start = {
            "message": {
                "message_id": 102,
                "chat": {"id": chat_id},
                "from": {"id": chat_id, "first_name": "Test"},
                "text": "/start",
            }
        }
        self.bot.handle_update(update_start)

        # BUG CHECK: /start should reset state to "menu", not remain in "await_promo_code"
        session_after_start = self.store.get_session(chat_id)
        self.assertEqual(session_after_start["state"], "menu")

    def test_fixed_promo_creates_order_not_renewal_error(self):
        chat_id = 8569278809
        # Create a fixed price promo (10 rub)
        code, promo = self.store.create_promo_code(
            promo_type="fixed",
            transport="tcp",
            duration_days=30,
            discount_percent=0,
            fixed_price_rub=10,
            device_limit=3,
            profile_mode="family",
            family_label="FamilyTest",
        )

        # Simulate user entering promo with stuck renewal context
        self.store.set_session(
            chat_id,
            "public",
            "await_promo_code",
            {"public_access": True, "promo_return": "renewal", "renewal_profile_public_id": "prf_twqb4wfgmv"},
        )
        # Calling promo prompt should clean it up!
        self.bot._send_public_promo_prompt(chat_id)
        session = self.store.get_session(chat_id)

        # Input the promo code
        self.bot.handle_promo_input(chat_id, code, session)

        # Should NOT send "Этот промокод выдаёт новый готовый доступ, а не скидку на продление"
        for call in self.bot.telegram.send_message.call_args_list:
            text = call[0][1]
            self.assertNotIn("Этот промокод выдаёт новый готовый доступ, а не скидку на продление", text)


if __name__ == "__main__":
    unittest.main()
