#!/usr/bin/env python3
import json
import os
import sqlite3
import tempfile
import sys
from pathlib import Path
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "vpn-shop"))

from vpn_shop.config import Settings
from vpn_shop.store import Store
from vpn_shop.web import WebCheckout
from vpn_shop.bot import ShopBot
from vpn_shop.security import hash_token, constant_time_equals

class TestRenewalAndRedesign(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="test_vpn_renewal_"))
        self.db_path = self.temp_dir / "shop.db"
        self.store = Store(self.db_path)
        self.store.init()

        self.settings = Settings(
            root_dir=self.temp_dir,
            data_dir=self.temp_dir,
            database_path=self.db_path,
            telegram_bot_token="test:token",
            telegram_bot_username="SilentConnectVPNBot",
            brand_name="SilentConnect",
            support_tg_url="https://t.me/SilentConnectSupport",
            welcome_media="",
            quickstart_media="",
            admin_usernames=("admin",),
            admin_user_ids=(),
            subscription_base_url="https://sub.example.com",
            payment_instructions_text="Переведите на карту",
            payment_transfer_url="",
            payment_bank_note="СБП",
            xui_panel_url="",
            xui_username="",
            xui_password="",
            xui_verify_tls=False,
            xui_db_path=self.temp_dir / "x-ui.db",
            xui_xhttp_inbound_id=1,
            xui_tcp_inbound_id=2,
            web_listen_host="127.0.0.1",
            web_listen_port=3090,
            web_public_base_url="https://example.com",
            monthly_price_xhttp_rub=149,
            monthly_price_tcp_rub=149,
            monthly_price_3_devices_rub=149,
            monthly_price_6_devices_rub=199,
            monthly_price_9_devices_rub=235,
            default_device_limit=3,
            invite_required=False,
            terms_version="2026-04-20",
            purge_after_days=90,
            support_email="support@example.com",
            smtp_host="",
            smtp_port=465,
            smtp_user="",
            smtp_password="",
            smtp_from_email="support@example.com",
            cf_turnstile_site_key="",
            cf_turnstile_secret_key="",
            platega_enabled=True,
            platega_merchant_id_bot="c3393290-d96e-4a5e-aca3-12015a843b0e",
            platega_merchant_id_web="e4d5af52-9c18-444b-b8bf-db1a26f0c61d",
            platega_secret="test-secret",
        )

        self.checkout = WebCheckout(self.settings, store=self.store)
        self.dummy_tg = MagicMock()
        self.bot = ShopBot(self.settings, self.store)
        self.bot.telegram = self.dummy_tg

    def test_order_redesign_prominent_platega_and_no_oplacheno(self):
        order = self.checkout.create_order("tcp_3_30")
        meta = dict(order.get("meta_json") or {})
        meta["platega_url"] = "https://pay.platega.io/?id=ord-test-123"
        order["meta_json"] = meta

        html = self.checkout.render_order({}, order).decode("utf-8")

        # 1. Platega CTA is present and prominent
        self.assertIn("btn-platega-primary", html)
        self.assertIn("https://pay.platega.io/?id=ord-test-123", html)
        self.assertIn("Оплатить онлайн", html)

        # 2. 'Оплачено' button is COMPLETELY REMOVED
        self.assertNotIn("<button>Оплачено</button>", html)
        self.assertNotIn("type=\"submit\">Оплачено", html)
        self.assertNotIn(">Оплачено<", html)

        # 3. 'Скопировать ссылку заказа' is secondary
        self.assertIn("btn secondary", html)
        self.assertIn("copyText('order-link')", html)

        # 4. Support and cancel buttons in secondary card
        self.assertIn("order-secondary-card", html)
        self.assertIn("SilentConnectSupport", html)
        self.assertIn("Отменить заказ ✖", html)

    def test_bot_order_messages_commission_notice(self):
        order = self.checkout.create_order("tcp_3_30")
        meta = dict(order.get("meta_json") or {})
        meta["platega_url"] = "https://pay.platega.io/?id=ord-test-123"
        order["meta_json"] = meta
        msg = self.bot._waiting_payment_message(order)

        self.assertIn("Комиссия шлюза оплачивается покупателем", msg)
        self.assertIn("без комиссии", msg)
        self.assertIn("поддержку", msg)

    def test_bot_main_menu_no_boost(self):
        markup = self.bot._public_home_markup()
        btn_texts = [btn["text"] for row in markup["inline_keyboard"] for btn in row]
        for t in btn_texts:
            self.assertNotIn("Boost", t)
            self.assertNotIn("⚡", t)

    def test_unified_pricing_no_99_placeholder(self):
        from vpn_shop.catalog import quote_price
        # 3 devices must be 149 (NOT 99)
        self.assertEqual(quote_price(3, 30), 149)
        self.assertEqual(quote_price(3, 90), 399)
        self.assertEqual(quote_price(3, 180), 719)
        self.assertEqual(quote_price(3, 360), 1249)

        # 6 devices
        self.assertEqual(quote_price(6, 30), 199)
        self.assertEqual(quote_price(6, 90), 539)
        self.assertEqual(quote_price(6, 180), 959)
        self.assertEqual(quote_price(6, 360), 1669)

        # 9 devices
        self.assertEqual(quote_price(9, 30), 239)
        self.assertEqual(quote_price(9, 90), 629)
        self.assertEqual(quote_price(9, 180), 1129)
        self.assertEqual(quote_price(9, 360), 1969)

        # Web Checkout order creation
        order_3_30 = self.checkout.create_order("tcp_3_30")
        self.assertEqual(order_3_30["final_price_rub"], 149)
        self.assertEqual(order_3_30["base_price_rub"], 149)

        # Bot renewal base price
        self.assertEqual(self.bot.base_price_for_duration("tcp", 30, device_limit=3), 149)
        self.assertEqual(self.bot.base_price_for_duration("tcp", 90, device_limit=3), 399)

if __name__ == "__main__":
    unittest.main()
