from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from http import HTTPStatus
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "vpn-shop"))

from vpn_shop.config import Settings, load_settings
from vpn_shop.platega import PlategaClient, PlategaApiError, PlategaAuthError
from vpn_shop.store import Store
from vpn_shop.web import WebCheckout, RequestHandler
from vpn_shop.bot import ShopBot


class DummyTelegram:
    def __init__(self):
        self.sent_messages = []
        self.answered_callbacks = []

    def send_message(self, chat_id, text, reply_markup=None, **kwargs):
        msg = {
            "chat_id": chat_id,
            "text": text,
            "reply_markup": reply_markup,
            "kwargs": kwargs,
        }
        self.sent_messages.append(msg)
        return {"ok": True, "message_id": 100 + len(self.sent_messages)}

    def answer_callback_query(self, callback_query_id, text=None, **kwargs):
        self.answered_callbacks.append({"id": callback_query_id, "text": text})
        return {"ok": True}


class TestPlategaClient(unittest.TestCase):
    def setUp(self):
        self.merchant_bot = "c3393290-d96e-4a5e-aca3-12015a843b0e"
        self.merchant_web = "e4d5af52-9c18-444b-b8bf-db1a26f0c61d"
        self.secret = "dummy_secret_sample_test_key_1234567890"
        self.client = PlategaClient(
            merchant_id_bot=self.merchant_bot,
            merchant_id_web=self.merchant_web,
            secret=self.secret,
            base_url="https://app.platega.io",
        )

    @patch("urllib.request.urlopen")
    def test_create_transaction_request_structure(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "transactionId": "tx-uuid-1234",
            "url": "https://pay.platega.io/?id=tx-uuid-1234",
            "status": "PENDING",
            "expiresIn": "00:15:00",
            "rate": 1.0,
        }).encode("utf-8")
        mock_response.headers = {}
        mock_urlopen.return_value.__enter__.return_value = mock_response

        res = self.client.create_transaction(
            amount=100,
            currency="RUB",
            description="SilentConnect #ord_test1",
            payload="ord_test1",
            return_url="https://example.com/success",
            failed_url="https://example.com/failed",
            metadata={"order_id": "ord_test1"},
            is_bot=True,
        )

        self.assertEqual(res["transactionId"], "tx-uuid-1234")
        self.assertEqual(res["url"], "https://pay.platega.io/?id=tx-uuid-1234")

        # Verify urllib Request was called with expected URL, headers, and body
        call_args = mock_urlopen.call_args[0]
        req = call_args[0]
        self.assertEqual(req.full_url, "https://app.platega.io/v2/transaction/process")
        self.assertEqual(req.get_header("X-merchantid"), self.merchant_bot)
        self.assertEqual(req.get_header("X-secret"), self.secret)
        self.assertEqual(req.get_method(), "POST")

        sent_body = json.loads(req.data.decode("utf-8"))
        self.assertEqual(sent_body["paymentDetails"]["amount"], 100)
        self.assertEqual(sent_body["paymentDetails"]["currency"], "RUB")
        self.assertEqual(sent_body["description"], "SilentConnect #ord_test1")
        self.assertEqual(sent_body["payload"], "ord_test1")
        self.assertEqual(sent_body["return"], "https://example.com/success")
        self.assertEqual(sent_body["failedUrl"], "https://example.com/failed")
        self.assertEqual(sent_body["metadata"]["order_id"], "ord_test1")

    @patch("urllib.request.urlopen")
    def test_get_transaction_status(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "id": "tx-uuid-1234",
            "status": "CONFIRMED",
            "amount": 100,
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        status = self.client.get_transaction_status("tx-uuid-1234", is_bot=False)
        self.assertEqual(status["status"], "CONFIRMED")
        req = mock_urlopen.call_args[0][0]
        self.assertEqual(req.full_url, "https://app.platega.io/transaction/tx-uuid-1234")
        self.assertEqual(req.get_header("X-merchantid"), self.merchant_web)
        self.assertEqual(req.get_header("X-secret"), self.secret)

    def test_verify_webhook_signature(self):
        # Valid bot merchant headers
        headers_bot = {
            "X-MerchantId": self.merchant_bot,
            "X-Secret": self.secret,
        }
        self.assertTrue(self.client.verify_webhook_signature(headers_bot))

        # Valid web merchant headers (case-insensitive)
        headers_web = {
            "x-merchantid": self.merchant_web,
            "x-secret": self.secret,
        }
        self.assertTrue(self.client.verify_webhook_signature(headers_web))

        # Invalid secret
        headers_bad_secret = {
            "X-MerchantId": self.merchant_bot,
            "X-Secret": "wrong_secret",
        }
        self.assertFalse(self.client.verify_webhook_signature(headers_bad_secret))

        # Invalid merchant
        headers_bad_merchant = {
            "X-MerchantId": "00000000-0000-0000-0000-000000000000",
            "X-Secret": self.secret,
        }
        self.assertFalse(self.client.verify_webhook_signature(headers_bad_merchant))

        # Missing headers
        self.assertFalse(self.client.verify_webhook_signature({}))


class TestPlategaWebAndBotIntegration(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_vpn_shop.db"
        self.store = Store(self.db_path)
        self.store.init()

        # Build settings with Platega enabled
        self.settings = Settings(
            root_dir=REPO_ROOT / "vpn-shop",
            data_dir=Path(self.temp_dir.name),
            database_path=self.db_path,
            telegram_bot_token="123456789:AAFakeTokenForTestTestingPurposes123",
            telegram_bot_username="SilentConnectVPNBot",
            brand_name="SilentConnect",
            support_tg_url="https://t.me/SilentConnectHelp",
            welcome_media="",
            quickstart_media="",
            admin_usernames=("admin",),
            admin_user_ids=(999,),
            subscription_base_url="https://example.com/sub/json",
            payment_instructions_text="Перевод",
            payment_transfer_url="https://payment.example.com",
            payment_bank_note="СБП",
            xui_panel_url="https://127.0.0.1:2053/",
            xui_username="admin",
            xui_password="password",
            xui_verify_tls=False,
            xui_db_path=Path(self.temp_dir.name) / "x-ui.db",
            xui_xhttp_inbound_id=1,
            xui_tcp_inbound_id=2,
            web_listen_host="127.0.0.1",
            web_listen_port=3090,
            web_public_base_url="https://example.com",
            monthly_price_xhttp_rub=100,
            monthly_price_tcp_rub=100,
            monthly_price_3_devices_rub=100,
            monthly_price_6_devices_rub=150,
            monthly_price_9_devices_rub=200,
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
            cf_turnstile_enabled=False,
            platega_merchant_id_bot="c3393290-d96e-4a5e-aca3-12015a843b0e",
            platega_merchant_id_web="e4d5af52-9c18-444b-b8bf-db1a26f0c61d",
            platega_secret="PLACEHOLDER_platega_secret_key_12345",
            platega_enabled=True,
        )
        self.checkout = WebCheckout(self.settings, self.store)
        self.dummy_tg = DummyTelegram()
        self.checkout.telegram = self.dummy_tg

        # Mock bot on checkout
        self.bot = ShopBot(self.settings, self.store)
        self.bot.telegram = self.dummy_tg
        self.checkout._bot = self.bot

        # Mock provisioner to avoid real 3x-ui connection in tests
        self.mock_profile = {
            "public_id": "prof_test123",
            "xui_client_id": "client-uuid",
            "xui_email": "test@example.com",
            "expires_at": 1800000000,
        }
        with self.store._connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO profiles(
                    public_id, xui_inbound_id, transport, profile_mode, family_label,
                    xui_email, xui_client_id, created_at, expires_at, status, notes
                ) VALUES(?, 1, 'tcp', 'family', 'Family', 'test@example.com', 'client-uuid', 1000, 1800000000, 'active', '')
                """,
                (self.mock_profile["public_id"],),
            )
        self.checkout.provisioner.create_profile_for_order = MagicMock(return_value={
            "profile": self.mock_profile,
            "subscription_url": "https://example.com/sub/json/prof_test123",
        })
        self.bot.provisioner.create_profile_for_order = self.checkout.provisioner.create_profile_for_order
        self.bot.provisioner.renew_profile = MagicMock(return_value={
            "profile": self.mock_profile,
            "sub_id": "prof_test123",
            "expires_at": 1800000000,
        })

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_platega_empty_post_validation_ping(self):
        """Platega dashboard validation sends an empty POST request and expects 200 OK."""
        # Create a mock RequestHandler instance
        handler = RequestHandler.__new__(RequestHandler)
        handler.checkout = self.checkout
        handler.headers = {}
        handler.client_address = ("127.0.0.1", 45678)
        handler.path = "/api/payment/platega/callback"
        handler.rfile = io.BytesIO(b"")

        sent_status = None
        sent_body = None

        def mock_send_json(status, body):
            nonlocal sent_status, sent_body
            sent_status = status
            sent_body = body

        handler._send_json = mock_send_json

        # Test empty body
        handler.do_POST()
        self.assertEqual(sent_status, HTTPStatus.OK)
        parsed = json.loads(sent_body.decode("utf-8"))
        self.assertEqual(parsed.get("status"), "ok")

        # Test empty json "{}" body
        handler.rfile = io.BytesIO(b"{}")
        handler.headers = {"Content-Length": "2"}
        handler.do_POST()
        self.assertEqual(sent_status, HTTPStatus.OK)

    def test_platega_unauthorized_post(self):
        """Non-empty callback without valid credentials must return 401."""
        handler = RequestHandler.__new__(RequestHandler)
        handler.checkout = self.checkout
        handler.headers = {
            "Content-Length": "30",
            "X-MerchantId": "c3393290-d96e-4a5e-aca3-12015a843b0e",
            "X-Secret": "invalid_secret",
        }
        handler.client_address = ("127.0.0.1", 45678)
        handler.path = "/api/payment/platega/callback"
        handler.rfile = io.BytesIO(b'{"status": "CONFIRMED", "id": "1"}')

        sent_status = None
        sent_body = None

        def mock_send_json(status, body):
            nonlocal sent_status, sent_body
            sent_status = status
            sent_body = body

        handler._send_json = mock_send_json
        handler.do_POST()
        self.assertEqual(sent_status, HTTPStatus.UNAUTHORIZED)

    def test_confirmed_callback_fulfills_web_order_idempotently(self):
        """Valid CONFIRMED callback automatically provisions the order and handles duplicate calls."""
        # 1. Create a web order
        order = self.checkout.create_order("tcp_3_30", customer_email="user@test.com")
        order_public_id = str(order["public_id"])
        self.assertEqual(order["status"], "waiting_payment")

        # 2. Simulate valid CONFIRMED callback from Platega
        callback_payload = {
            "id": "tx-platega-998877",
            "amount": order["final_price_rub"],
            "currency": "RUB",
            "status": "CONFIRMED",
            "paymentMethod": 2,
            "payload": order_public_id,
        }
        raw_body = json.dumps(callback_payload).encode("utf-8")

        handler = RequestHandler.__new__(RequestHandler)
        handler.checkout = self.checkout
        handler.headers = {
            "Content-Length": str(len(raw_body)),
            "X-MerchantId": self.settings.platega_merchant_id_web,
            "X-Secret": self.settings.platega_secret,
        }
        handler.client_address = ("127.0.0.1", 45678)
        handler.path = "/api/payment/platega/callback"
        handler.rfile = io.BytesIO(raw_body)

        sent_status = None
        sent_body = None

        def mock_send_json(status, body):
            nonlocal sent_status, sent_body
            sent_status = status
            sent_body = body

        handler._send_json = mock_send_json

        # Process callback
        handler.do_POST()
        self.assertEqual(sent_status, HTTPStatus.OK)
        parsed = json.loads(sent_body.decode("utf-8"))
        self.assertEqual(parsed.get("status"), "ok")
        self.assertEqual(parsed.get("message"), "confirmed")

        # Check order is now delivered
        updated_order = self.store.get_order(order_public_id)
        self.assertEqual(updated_order["status"], "delivered")
        self.assertIsNotNone(updated_order["closed_at"])
        self.assertEqual(updated_order["meta_json"]["platega_transaction_id"], "tx-platega-998877")

        # 3. Test duplicate webhook delivery (idempotency)
        handler.rfile = io.BytesIO(raw_body)
        handler.do_POST()
        self.assertEqual(sent_status, HTTPStatus.OK)
        dup_parsed = json.loads(sent_body.decode("utf-8"))
        self.assertEqual(dup_parsed.get("status"), "ok")
        self.assertIn("duplicate", dup_parsed.get("message", "") + "already_delivered")

    def test_amount_too_low_rejected(self):
        """If confirmed amount is less than order price, reject to prevent fraud."""
        order = self.checkout.create_order("tcp_3_30")
        order_public_id = str(order["public_id"])

        callback_payload = {
            "id": "tx-underpaid-1",
            "amount": 1,  # Only paid 1 RUB instead of 100
            "currency": "RUB",
            "status": "CONFIRMED",
            "payload": order_public_id,
        }
        res = self.checkout.handle_platega_callback(callback_payload, raw_body=json.dumps(callback_payload).encode("utf-8"))
        self.assertEqual(res["status"], "error")
        self.assertEqual(res["message"], "amount_too_low")

        # Order must remain in waiting_payment
        order_check = self.store.get_order(order_public_id)
        self.assertEqual(order_check["status"], "waiting_payment")

    def test_bot_waiting_payment_markup_generates_platega_link(self):
        """When Platega is enabled, bot checkout produces an online payment button."""
        order = self.store.create_order(
            kind="standard",
            status="waiting_payment",
            transport="tcp",
            duration_days=30,
            profile_mode="family",
            family_label="Family",
            base_price_rub=100,
            final_price_rub=100,
            promo_id=None,
            invite_id=None,
            customer_chat_id=123456,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version="2026-04-20",
        )
        order_public_id = str(order["public_id"])

        with patch.object(self.bot.platega, "create_transaction") as mock_create:
            mock_create.return_value = {
                "transactionId": "tx-bot-1234",
                "url": "https://pay.platega.io/?id=tx-bot-1234",
            }
            markup = self.bot._public_waiting_payment_markup(order_public_id, order)

            buttons = [btn for row in markup["inline_keyboard"] for btn in row]
            pay_button = next((b for b in buttons if "Оплатить" in b["text"]), None)
            self.assertIsNotNone(pay_button)
            self.assertEqual(pay_button["url"], "https://pay.platega.io/?id=tx-bot-1234")

    def test_boost_command_and_callback(self):
        """Test /boost command and callback in Telegram bot."""
        chat_id = 987654

        # Test /boost command
        message = {
            "chat": {"id": chat_id},
            "from": {"id": chat_id, "username": "tester"},
            "text": "/boost",
        }
        self.bot.handle_message(message)

        self.assertTrue(len(self.dummy_tg.sent_messages) > 0)
        last_msg = self.dummy_tg.sent_messages[-1]
        self.assertIn("Boost", last_msg["text"])
        self.assertIn("Ускорение", last_msg["text"])
        self.assertIsNotNone(last_msg["reply_markup"])

        # Test public:boost callback
        cb = {
            "id": "cb_query_1",
            "from": {"id": chat_id, "username": "tester"},
            "data": "public:boost",
            "message": {"chat": {"id": chat_id}, "message_id": 42},
        }
        self.bot.handle_callback(cb)
        self.assertEqual(len(self.dummy_tg.answered_callbacks), 1)
        self.assertEqual(self.dummy_tg.answered_callbacks[0]["id"], "cb_query_1")

    def test_render_order_includes_platega_button(self):
        """Test that web checkout render_order displays Platega card and button when order awaits payment."""
        order = self.checkout.create_order("tcp_3_30")
        meta = dict(order.get("meta_json") or {})
        meta["platega_url"] = "https://pay.platega.io/?id=test-order-url"
        order["meta_json"] = meta

        html_bytes = self.checkout.render_order({}, order)
        html_str = html_bytes.decode("utf-8")
        self.assertIn("https://pay.platega.io/?id=test-order-url", html_str)
        self.assertIn("Оплатить онлайн", html_str)

    def test_pending_callback_does_not_block_subsequent_confirmed_callback(self):
        """CRITICAL: A PENDING status callback must not prevent later CONFIRMED callback from fulfilling order."""
        order = self.checkout.create_order("tcp_3_30")
        order_public_id = str(order["public_id"])
        tx_id = "tx-lifecycle-12345"

        # 1. Simulate initial PENDING callback
        pending_payload = {
            "id": tx_id,
            "status": "PENDING",
            "amount": 100,
            "payload": order_public_id,
        }
        res1 = self.checkout.handle_platega_callback(pending_payload, raw_body=json.dumps(pending_payload).encode("utf-8"))
        self.assertEqual(res1["status"], "ok")
        self.assertEqual(self.store.get_order(order_public_id)["status"], "waiting_payment")

        # 2. Simulate subsequent CONFIRMED callback for same tx_id
        confirmed_payload = {
            "id": tx_id,
            "status": "CONFIRMED",
            "amount": 100,
            "payload": order_public_id,
        }
        res2 = self.checkout.handle_platega_callback(confirmed_payload, raw_body=json.dumps(confirmed_payload).encode("utf-8"))
        self.assertEqual(res2["status"], "ok")
        self.assertEqual(res2["message"], "confirmed")
        # Crucial check: Order must be delivered now!
        self.assertEqual(self.store.get_order(order_public_id)["status"], "delivered")

    def test_payment_details_amount_extraction(self):
        """Platega sending amount in paymentDetails.amount must be parsed correctly."""
        order = self.checkout.create_order("tcp_3_30")
        order_public_id = str(order["public_id"])

        callback_payload = {
            "id": "tx-details-999",
            "status": "CONFIRMED",
            "paymentDetails": {"amount": 100, "currency": "RUB"},
            "payload": order_public_id,
        }
        res = self.checkout.handle_platega_callback(callback_payload, raw_body=json.dumps(callback_payload).encode("utf-8"))
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["message"], "confirmed")
        updated = self.store.get_order(order_public_id)
        self.assertEqual(updated["status"], "delivered")
        self.assertEqual(updated["meta_json"]["platega_confirmed_amount"], 100.0)

    def test_boost_command_with_botname_suffix(self):
        """Telegram client sending /boost@SilentConnectVPNBot must be recognized."""
        chat_id = 987655
        message = {
            "chat": {"id": chat_id},
            "from": {"id": chat_id, "username": "tester"},
            "text": "/boost@SilentConnectVPNBot",
        }
        self.bot.handle_message(message)
        self.assertTrue(len(self.dummy_tg.sent_messages) > 0)
        last_msg = self.dummy_tg.sent_messages[-1]
        self.assertIn("Boost", last_msg["text"])

    def test_bot_check_payment_callback_handling(self):
        """User tapping 'Проверить зачисление' checks status via Platega and confirms order."""
        order = self.store.create_order(
            kind="standard",
            status="waiting_payment",
            transport="tcp",
            duration_days=30,
            profile_mode="family",
            family_label="Family",
            base_price_rub=100,
            final_price_rub=100,
            promo_id=None,
            invite_id=None,
            customer_chat_id=123456,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version="2026-04-20",
        )
        order_public_id = str(order["public_id"])
        meta = dict(order.get("meta_json") or {})
        meta["platega_transaction_id"] = "tx-live-999"
        self.store.update_order_meta(order_public_id, meta)

        with patch.object(self.bot.platega, "get_transaction_status") as mock_status:
            mock_status.return_value = {"id": "tx-live-999", "status": "CONFIRMED"}
            cb = {
                "id": "cb_check_1",
                "from": {"id": 123456},
                "data": f"public:check_payment:{order_public_id}",
                "message": {"chat": {"id": 123456}, "message_id": 99},
            }
            self.bot.handle_callback(cb)

            updated = self.store.get_order(order_public_id)
            self.assertEqual(updated["status"], "delivered")

    def test_platega_candidate_fallback(self):
        """When merchant_id_bot fails auth, PlategaClient automatically falls back to merchant_id_web."""
        client = PlategaClient(
            merchant_id_bot="bad-bot-merchant",
            merchant_id_web="good-web-merchant",
            secret="shared_or_web_secret",
        )
        with patch.object(client, "_request") as mock_req:
            mock_req.side_effect = [
                PlategaAuthError("Bad key", status_code=401),
                {"transactionId": "tx-fallback-ok", "url": "https://pay.platega.io/?id=tx-fallback-ok"},
            ]
            res = client.create_transaction(amount=100, is_bot=True)
            self.assertEqual(res["transactionId"], "tx-fallback-ok")
            self.assertEqual(mock_req.call_count, 2)
            self.assertEqual(mock_req.call_args_list[0][0][2], "bad-bot-merchant")
            self.assertEqual(mock_req.call_args_list[1][0][2], "good-web-merchant")


if __name__ == "__main__":
    unittest.main()

