"""Unit and integration test suite for Milestone 4: Interactive Server Selector in Telegram Bot Admin Panel (bot.py).
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure vpn-shop is on sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "vpn_shop"))

from vpn_shop import awg_manager, bot, config


SAMPLE_SERVER_CONF = """[Interface]
Address = 10.8.1.1/24
PrivateKey = aW5pdGlhbF9zZXJ2ZXJfcHJpdmF0ZV9rZXk=
ListenPort = 44121
Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 20
H1 = 1
H2 = 2
H3 = 3
H4 = 4
"""


class DummyTelegram:
    def __init__(self):
        self.sent_messages = []
        self.sent_documents = []
        self.answered_callbacks = []

    def send_message(self, chat_id, text, reply_markup=None, **kwargs):
        self.sent_messages.append({
            "chat_id": chat_id,
            "text": text,
            "reply_markup": reply_markup,
            "kwargs": kwargs,
        })
        return {"ok": True, "result": {"message_id": 100 + len(self.sent_messages)}}

    def send_document(self, chat_id, document, caption=None, **kwargs):
        doc_path = Path(document)
        doc_content = doc_path.read_text(encoding="utf-8") if doc_path.exists() else ""
        self.sent_documents.append({
            "chat_id": chat_id,
            "document_name": doc_path.name,
            "document_content": doc_content,
            "caption": caption,
            "kwargs": kwargs,
        })
        return {"ok": True, "result": {"message_id": 200 + len(self.sent_documents)}}

    def answer_callback_query(self, callback_query_id, text=None, **kwargs):
        self.answered_callbacks.append({
            "callback_query_id": callback_query_id,
            "text": text,
            "kwargs": kwargs,
        })
        return {"ok": True}


class TestBotMilestone4(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp_dir.name)
        self.db_path = self.tmp_path / "test_bot_m4.db"
        self.allowed_ips_file = self.tmp_path / "allowed-ips.txt"
        self.allowed_ips_file.write_text("198.51.100.0/24, 203.0.113.0/24", encoding="utf-8")

        self.orig_db = awg_manager.DB_PATH
        awg_manager.DB_PATH = str(self.db_path)
        awg_manager.SERVERS["nl"]["allowed_ips_file"] = str(self.allowed_ips_file)
        awg_manager.SERVERS["fi"]["allowed_ips_file"] = str(self.allowed_ips_file)
        awg_manager.ensure_table()

        # Create real Settings instance
        self.settings = config.Settings(
            root_dir=self.tmp_path,
            data_dir=self.tmp_path,
            database_path=self.db_path,
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
            xui_db_path=self.tmp_path / "x-ui.db",
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
        self.sessions = {}

        def get_session(chat_id):
            return self.sessions.get(str(chat_id))

        def set_session(chat_id, scope, state, context):
            self.sessions[str(chat_id)] = {
                "chat_id": str(chat_id),
                "scope": scope,
                "state": state,
                "context_json": context,
            }

        self.store.get_session.side_effect = get_session
        self.store.set_session.side_effect = set_session

        # Instantiate ShopBot with mocks
        with patch("vpn_shop.bot.TelegramBotClient"), patch("vpn_shop.bot.Provisioner"):
            self.shop_bot = bot.ShopBot(self.settings, self.store)
            self.telegram = DummyTelegram()
            self.shop_bot.telegram = self.telegram
            self.provisioner = MagicMock()
            self.provisioner.xui_db = MagicMock()
            self.shop_bot.provisioner = self.provisioner

    def tearDown(self):
        awg_manager.DB_PATH = self.orig_db
        try:
            self.tmp_dir.cleanup()
        except Exception:
            pass

    def test_admin_menu_has_share_warp(self):
        """Admin menu must have 'Поделиться warp' button with callback 'admin:share_warp'."""
        self.shop_bot.send_admin_menu(12345)
        self.assertTrue(len(self.telegram.sent_messages) > 0)
        last_msg = self.telegram.sent_messages[-1]
        markup = last_msg["reply_markup"]
        
        button_callbacks = []
        for row in markup.get("inline_keyboard", []):
            for btn in row:
                button_callbacks.append(btn.get("callback_data"))
        self.assertIn("admin:share_warp", button_callbacks)

    def test_admin_share_warp_server_selection_keyboard(self):
        """Clicking 'admin:share_warp' must display NL and FI server selection buttons."""
        callback_query = {
            "id": "cb_1",
            "from": {"id": 12345, "username": "admin"},
            "message": {"chat": {"id": 12345}, "message_id": 10},
            "data": "admin:share_warp",
        }
        self.shop_bot.handle_callback(callback_query)

        self.assertEqual(len(self.telegram.answered_callbacks), 1)
        self.assertEqual(len(self.telegram.sent_messages), 1)

        msg = self.telegram.sent_messages[-1]
        self.assertIn("Выберите сервер", msg["text"])
        markup = msg["reply_markup"]

        buttons = {}
        for row in markup.get("inline_keyboard", []):
            for btn in row:
                buttons[btn.get("callback_data")] = btn.get("text")

        self.assertIn("admin:share_warp_srv:nl", buttons)
        self.assertIn("admin:share_warp_srv:fi", buttons)
        self.assertIn("warp.example.com:44121", buttons["admin:share_warp_srv:nl"])
        self.assertIn("fi.example.com:49752", buttons["admin:share_warp_srv:fi"])

    def test_admin_select_server_nl(self):
        """Selecting NL server sets state to admin_wait_warp_sub_url with server_code=nl."""
        callback_query = {
            "id": "cb_nl",
            "from": {"id": 12345, "username": "admin"},
            "message": {"chat": {"id": 12345}, "message_id": 10},
            "data": "admin:share_warp_srv:nl",
        }
        self.shop_bot.handle_callback(callback_query)

        session = self.store.get_session(12345)
        self.assertIsNotNone(session)
        self.assertEqual(session["state"], "admin_wait_warp_sub_url")
        self.assertEqual(session["context_json"].get("server_code"), "nl")
        self.assertEqual(session["context_json"].get("target_server"), "nl")

        last_msg = self.telegram.sent_messages[-1]
        self.assertIn("Нидерланды", last_msg["text"])
        self.assertIn("warp.example.com", last_msg["text"])
        self.assertIn("500 ГБ", last_msg["text"])

    def test_admin_select_server_fi(self):
        """Selecting FI server sets state to admin_wait_warp_sub_url with server_code=fi."""
        callback_query = {
            "id": "cb_fi",
            "from": {"id": 12345, "username": "admin"},
            "message": {"chat": {"id": 12345}, "message_id": 10},
            "data": "admin:share_warp_srv:fi",
        }
        self.shop_bot.handle_callback(callback_query)

        session = self.store.get_session(12345)
        self.assertIsNotNone(session)
        self.assertEqual(session["state"], "admin_wait_warp_sub_url")
        self.assertEqual(session["context_json"].get("server_code"), "fi")
        self.assertEqual(session["context_json"].get("target_server"), "fi")

        last_msg = self.telegram.sent_messages[-1]
        self.assertIn("Финляндия", last_msg["text"])
        self.assertIn("fi.example.com", last_msg["text"])
        self.assertIn("500 ГБ", last_msg["text"])

    @patch("vpn_shop.awg_manager._server_conf")
    @patch.object(awg_manager, "_dex")
    def test_handle_warp_sub_url_flow_nl(self, mock_dex, mock_server_conf):
        """Full flow for delivering NL warp config upon receiving sub_id."""
        mock_server_conf.return_value = SAMPLE_SERVER_CONF
        mock_dex.side_effect = lambda *args, **kwargs: "mock_output"
        sub_id = "testSubIdNl123"

        # Mock client lookup in xui_db
        self.provisioner.xui_db.find_client_by_sub_id.return_value = {
            "client": {"id": "uuid-1", "email": "user1@example.com", "sub_id": sub_id},
        }
        self.provisioner.xui_db.get_client_traffic.return_value = {
            "expiry_time": 1800000000000,  # Valid epoch ms
        }

        # Set session as if admin selected NL
        self.store.set_session(12345, "admin", "admin_wait_warp_sub_url", {"admin": True, "server_code": "nl"})
        session = self.store.get_session(12345)

        # Admin sends subscription URL
        sub_url = f"https://sub.example.com/my-secret-sub/json/{sub_id}"
        self.shop_bot.handle_warp_sub_url(12345, sub_url, session, {"id": 12345, "username": "admin"})

        # Check peer created in database for server_code='nl'
        peer = awg_manager.get_peer(sub_id, server_code="nl")
        self.assertIsNotNone(peer)
        self.assertEqual(peer["server_code"], "nl")
        self.assertTrue(peer["tunnel_ip"].startswith("10.8.1."))

        # Check document delivered
        self.assertEqual(len(self.telegram.sent_documents), 1)
        sent_doc = self.telegram.sent_documents[-1]
        self.assertIn("warp-NL-testSubIdNl123.conf", sent_doc["document_name"])
        self.assertIn("Нидерланды", sent_doc["caption"])
        self.assertIn("warp.example.com:44121", sent_doc["caption"])
        self.assertIn(sub_id, sent_doc["caption"])
        self.assertIn("500 ГБ", sent_doc["caption"])
        self.assertIn("Address = 10.8.1.", sent_doc["document_content"])
        self.assertIn("Endpoint = warp.example.com:44121", sent_doc["document_content"])

    @patch("vpn_shop.awg_manager._server_conf")
    @patch.object(awg_manager, "_dex")
    def test_handle_warp_sub_url_flow_fi(self, mock_dex, mock_server_conf):
        """Full flow for delivering FI warp config upon receiving sub_id."""
        mock_server_conf.return_value = SAMPLE_SERVER_CONF
        mock_dex.side_effect = lambda *args, **kwargs: "mock_output"
        sub_id = "testSubIdFi456"

        # Mock client lookup in xui_db
        self.provisioner.xui_db.find_client_by_sub_id.return_value = {
            "client": {"id": "uuid-2", "email": "user2@example.com", "sub_id": sub_id},
        }
        self.provisioner.xui_db.get_client_traffic.return_value = {
            "expiry_time": 0,  # Lifetime
        }

        # Set session as if admin selected FI
        self.store.set_session(12345, "admin", "admin_wait_warp_sub_url", {"admin": True, "server_code": "fi"})
        session = self.store.get_session(12345)

        # Admin sends plain sub_id
        self.shop_bot.handle_warp_sub_url(12345, sub_id, session, {"id": 12345, "username": "admin"})

        # Check peer created in database for server_code='fi'
        peer = awg_manager.get_peer(sub_id, server_code="fi")
        self.assertIsNotNone(peer)
        self.assertEqual(peer["server_code"], "fi")
        self.assertTrue(peer["tunnel_ip"].startswith("10.8.2."))

        # Check document delivered
        self.assertEqual(len(self.telegram.sent_documents), 1)
        sent_doc = self.telegram.sent_documents[-1]
        self.assertIn("warp-FI-testSubIdFi456.conf", sent_doc["document_name"])
        self.assertIn("Финляндия", sent_doc["caption"])
        self.assertIn("fi.example.com:49752", sent_doc["caption"])
        self.assertIn(sub_id, sent_doc["caption"])
        self.assertIn("бессрочно", sent_doc["caption"])
        self.assertIn("500 ГБ", sent_doc["caption"])
        self.assertIn("Address = 10.8.2.", sent_doc["document_content"])
        self.assertIn("Endpoint = fi.example.com:49752", sent_doc["document_content"])


if __name__ == "__main__":
    unittest.main()
