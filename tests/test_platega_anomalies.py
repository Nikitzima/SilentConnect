from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "vpn-shop"))
sys.path.insert(0, str(REPO_ROOT / "subjson-service"))

from vpn_shop.bot import ShopBot
from vpn_shop.config import Settings
from vpn_shop.mailer import (
    render_order_reviewed_email_html,
    render_order_reviewed_email_text,
    send_order_reviewed_email_async,
)
from vpn_shop.security import now_ts
from vpn_shop.store import Store
from vpn_shop.web import WebCheckout


class TestPlategaAnomaliesAndCallbacks(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_vpn_shop.db"
        self.store = Store(self.db_path)
        self.store.init()

        self.settings = MagicMock()
        self.settings.root_dir = Path(self.temp_dir.name)
        self.settings.data_dir = Path(self.temp_dir.name)
        self.settings.database_path = self.db_path
        self.settings.web_public_base_url = "https://example.com"
        self.settings.subscription_base_url = "https://sub.example.com"
        self.settings.terms_version = "v1"
        self.settings.support_tg_url = "https://t.me/support"
        self.settings.telegram_bot_token = "TEST_TOKEN"
        self.settings.telegram_bot_username = "SilentConnectVPNBot"
        self.settings.platega_enabled = True
        self.settings.platega_merchant_id_bot = ""
        self.settings.platega_merchant_id_web = ""
        self.settings.platega_secret = "test_secret"
        self.settings.platega_secret_bot = ""
        self.settings.platega_secret_web = ""
        self.settings.digiseller_enabled = False
        self.settings.admin_user_ids = (12345,)
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
        self.mock_telegram = MagicMock()
        self.checkout.telegram = self.mock_telegram
        self.mock_bot = MagicMock()
        self.mock_bot.telegram = self.mock_telegram
        self.checkout._bot = self.mock_bot

    def tearDown(self) -> None:
        try:
            self.temp_dir.cleanup()
        except (PermissionError, OSError):
            pass

    def _create_order(
        self,
        public_id: str | None = None,
        status: str = "waiting_payment",
        email: str = "user@example.com",
        duration_days: int = 30,
        meta_json: dict | None = None,
    ) -> dict:
        order = self.store.create_order(
            kind="standard",
            status=status,
            transport="tcp",
            duration_days=duration_days,
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
            customer_email=email,
            meta=meta_json or {},
        )
        if public_id and public_id != order["public_id"]:
            with self.store._connect() as conn:
                conn.execute("UPDATE orders SET public_id = ? WHERE id = ?", (public_id, order["id"]))
            order = self.store.get_order(public_id)
        return order

    def test_platega_webhook_retry_silent(self) -> None:
        """A delivered order with existing platega_confirmed_at should return 200 silently on retry."""
        tx_id = "tx_123"
        order = self._create_order(
            "ord_delivered_1",
            status="delivered",
            meta_json={
                "platega_transaction_id": tx_id,
                "platega_confirmed_at": now_ts(),
                "platega_confirmed_amount": 149.0,
            },
        )
        data = {
            "status": "CONFIRMED",
            "id": tx_id,
            "amount": 149.0,
            "currency": "RUB",
            "payload": "ord_delivered_1",
        }
        res, code = self.checkout.handle_platega_callback(data)
        self.assertEqual(code, 200)
        self.assertEqual(res.get("message"), "already_delivered")
        self.mock_telegram.send_message.assert_not_called()

    def test_platega_webhook_collision_already_delivered_manual(self) -> None:
        """A delivered order without platega_confirmed_at (manual delivery) triggers collision alert."""
        tx_id = "tx_collision_1"
        order = self._create_order(
            "ord_manual_del",
            status="delivered",
            meta_json={"delivered_by": "admin_manual"},
        )
        data = {
            "status": "CONFIRMED",
            "id": tx_id,
            "amount": 149.0,
            "currency": "RUB",
            "payload": "ord_manual_del",
        }
        self.mock_telegram.send_message.return_value = {"message_id": 999}
        res, code = self.checkout.handle_platega_callback(data)

        self.assertEqual(code, 200)
        self.assertEqual(res.get("message"), "collision_reported")

        refreshed = self.store.get_order("ord_manual_del")
        meta = refreshed.get("meta_json") or {}
        self.assertEqual(meta.get("platega_collision_type"), "already_delivered")
        self.assertEqual(meta.get("platega_collision_tx_id"), tx_id)
        self.assertEqual(meta.get("platega_collision_amount"), 149.0)

        # Telegram alert was sent to admin
        self.mock_telegram.send_message.assert_called_once()
        call_args = self.mock_telegram.send_message.call_args
        admin_id, text = call_args[0][0], call_args[0][1]
        self.assertEqual(admin_id, 12345)
        self.assertIn("⚠️ Двойная оплата в Platega!", text)
        self.assertIn("#ord_manual_del", text)
        self.assertIn(tx_id, text)

        reply_markup = call_args[1].get("reply_markup") or {}
        buttons = reply_markup.get("inline_keyboard") or []
        self.assertEqual(len(buttons), 3)
        self.assertEqual(buttons[0][0]["text"], "🔗 Открыть Platega")
        self.assertEqual(buttons[0][0]["url"], "https://app.platega.io")
        self.assertEqual(buttons[1][0]["callback_data"], f"admin:platega_ext:ord_manual_del:{tx_id}")
        self.assertEqual(buttons[2][0]["callback_data"], f"admin:platega_ack_refund:ord_manual_del:{tx_id}")

    def test_platega_webhook_collision_already_delivered_different_tx_id(self) -> None:
        """A delivered order receiving a DIFFERENT transaction ID triggers collision alert."""
        tx_orig = "tx_original"
        tx_new = "tx_second_payment"
        order = self._create_order(
            "ord_del_2",
            status="delivered",
            meta_json={
                "platega_transaction_id": tx_orig,
                "platega_confirmed_at": now_ts(),
            },
        )
        data = {
            "status": "CONFIRMED",
            "id": tx_new,
            "amount": 149.0,
            "currency": "RUB",
            "payload": "ord_del_2",
        }
        res, code = self.checkout.handle_platega_callback(data)
        self.assertEqual(code, 200)
        self.assertEqual(res.get("message"), "collision_reported")

        refreshed = self.store.get_order("ord_del_2")
        meta = refreshed.get("meta_json") or {}
        self.assertEqual(meta.get("platega_collision_type"), "already_delivered")
        self.assertEqual(meta.get("platega_collision_tx_id"), tx_new)

    def test_platega_webhook_collision_cancelled_order(self) -> None:
        """A cancelled order receiving a CONFIRMED webhook triggers cancelled anomaly alert."""
        tx_id = "tx_canc_1"
        order = self._create_order("ord_canc_1", status="cancelled")
        data = {
            "status": "CONFIRMED",
            "id": tx_id,
            "amount": 149.0,
            "currency": "RUB",
            "payload": "ord_canc_1",
        }
        self.mock_telegram.send_message.return_value = {"message_id": 888}
        res, code = self.checkout.handle_platega_callback(data)

        self.assertEqual(code, 200)
        self.assertEqual(res.get("message"), "collision_cancelled_reported")

        refreshed = self.store.get_order("ord_canc_1")
        meta = refreshed.get("meta_json") or {}
        self.assertEqual(meta.get("platega_collision_type"), "cancelled")
        self.assertEqual(meta.get("platega_collision_tx_id"), tx_id)
        # Status MUST stay cancelled until admin explicitly acts
        self.assertEqual(refreshed.get("status"), "cancelled")

        self.mock_telegram.send_message.assert_called_once()
        call_args = self.mock_telegram.send_message.call_args
        text = call_args[0][1]
        self.assertIn("🚨 Оплата в Platega по ОТМЁНЕННОМУ заказу!", text)
        self.assertIn("#ord_canc_1", text)

        buttons = call_args[1]["reply_markup"]["inline_keyboard"]
        self.assertEqual(buttons[0][0]["text"], "🔗 Открыть Platega")
        self.assertEqual(buttons[1][0]["callback_data"], f"admin:platega_act:ord_canc_1:{tx_id}")
        self.assertEqual(buttons[2][0]["callback_data"], f"admin:platega_ack_refund:ord_canc_1:{tx_id}")

    @patch("vpn_shop.bot.send_order_reviewed_email_async")
    def test_admin_callback_platega_ext(self, mock_email: MagicMock) -> None:
        """admin:platega_ext renews profile, updates meta, edits message, and sends review email."""
        bot = ShopBot(self.settings, self.store)
        bot.telegram = MagicMock()

        # Create profile and delivered order
        prof = self.store.create_profile(
            xui_inbound_id=1,
            transport="tcp",
            profile_mode="personal",
            family_label=None,
            xui_email="user_ext_1",
            xui_client_id="cid_ext_1",
            expires_at=now_ts() + 86400,
            notes="test",
        )
        order = self._create_order(
            "ord_ext_1",
            status="delivered",
            email="client@example.com",
            duration_days=30,
            meta_json={
                "platega_collision_type": "already_delivered",
            },
        )
        self.store.link_order_profile("ord_ext_1", prof["public_id"])

        # Mock provisioner renew_profile
        bot.provisioner = MagicMock()
        bot.provisioner.renew_profile.return_value = {
            "profile": prof,
            "subscription_url": "https://sub.example.com/ext_sub",
            "expires_at": now_ts() + 31 * 86400,
        }

        callback = {
            "id": "cb_ext_1",
            "data": "admin:platega_ext:ord_ext_1:tx_ext_123",
            "from": {"id": 12345, "username": "admin_chief"},
            "message": {
                "message_id": 555,
                "chat": {"id": 12345},
                "text": "⚠️ Двойная оплата в Platega!\n\n• Заказ: #ord_ext_1\n• Сумма: 149.00 RUB\n\nВыберите действие ниже:",
            },
        }

        bot.handle_callback(callback)

        bot.provisioner.renew_profile.assert_called_once_with(prof["public_id"], 30, device_limit=3)

        refreshed = self.store.get_order("ord_ext_1")
        meta = refreshed.get("meta_json") or {}
        self.assertEqual(meta.get("platega_collision_resolution"), "extended")
        self.assertEqual(meta.get("platega_collision_resolved_by"), "tg:12345")

        # Telegram message edit check
        bot.telegram.edit_message_text.assert_called_once()
        edit_kwargs = bot.telegram.edit_message_text.call_args[1]
        self.assertEqual(edit_kwargs["chat_id"], 12345)
        self.assertEqual(edit_kwargs["message_id"], 555)
        self.assertIn("✅ РЕШЕНО: Подписка успешно продлена ещё на 30 дн.", edit_kwargs["text"])
        self.assertEqual(edit_kwargs.get("reply_markup"), {"inline_keyboard": []})

        # Toast answer
        bot.telegram.answer_callback_query.assert_any_call("cb_ext_1", "Продление выполняется...")

        # Review email sent
        mock_email.assert_called_once()
        email_kwargs = mock_email.call_args[1]
        self.assertEqual(email_kwargs["customer_email"], "client@example.com")
        self.assertEqual(email_kwargs["order_public_id"], "ord_ext_1")
        self.assertEqual(email_kwargs["duration_days"], 30)
        self.assertEqual(email_kwargs["device_limit"], 3)

    def test_admin_callback_platega_act(self) -> None:
        """admin:platega_act activates cancelled order via complete_order and updates telegram message."""
        bot = ShopBot(self.settings, self.store)
        bot.telegram = MagicMock()
        bot.provisioner = MagicMock()
        bot.provisioner.create_profile_for_order.return_value = {
            "profile": {"public_id": "prof_act_1", "id": 1, "expires_at": now_ts() + 30 * 86400},
            "subscription_url": "https://sub.example.com/act_sub",
        }

        order = self._create_order(
            "ord_act_1",
            status="cancelled",
            duration_days=30,
            meta_json={"platega_collision_type": "cancelled"},
        )

        callback = {
            "id": "cb_act_1",
            "data": "admin:platega_act:ord_act_1:tx_act_999",
            "from": {"id": 12345, "username": "admin_chief"},
            "message": {
                "message_id": 666,
                "chat": {"id": 12345},
                "text": "🚨 Оплата в Platega по ОТМЁНЕННОМУ заказу!\n\n• Заказ: #ord_act_1\n\nВыберите действие ниже:",
            },
        }

        with patch("vpn_shop.bot.send_subscription_email_async") as mock_del_email:
            bot.handle_callback(callback)

        refreshed = self.store.get_order("ord_act_1")
        self.assertEqual(refreshed.get("status"), "delivered")
        meta = refreshed.get("meta_json") or {}
        self.assertEqual(meta.get("platega_collision_resolution"), "activated")
        self.assertEqual(meta.get("platega_collision_resolved_by"), "tg:12345")
        self.assertEqual(meta.get("platega_collision_resolved_tx_id"), "tx_act_999")
        self.assertEqual(meta.get("platega_transaction_id"), "tx_act_999")
        self.assertIsNotNone(meta.get("platega_confirmed_at"))

        bot.telegram.edit_message_text.assert_called_once()
        edit_kwargs = bot.telegram.edit_message_text.call_args[1]
        self.assertIn("✅ РЕШЕНО: Заказ активирован, доступ отправлен клиенту", edit_kwargs["text"])
        self.assertEqual(edit_kwargs.get("reply_markup"), {"inline_keyboard": []})

    def test_admin_callback_platega_ack_refund(self) -> None:
        """admin:platega_ack_refund records manual refund and edits message."""
        bot = ShopBot(self.settings, self.store)
        bot.telegram = MagicMock()

        order = self._create_order(
            "ord_ref_1",
            status="delivered",
            meta_json={"platega_collision_type": "already_delivered"},
        )

        callback = {
            "id": "cb_ref_1",
            "data": "admin:platega_ack_refund:ord_ref_1:tx_ref_555",
            "from": {"id": 12345, "username": "admin_chief"},
            "message": {
                "message_id": 777,
                "chat": {"id": 12345},
                "text": "⚠️ Двойная оплата в Platega!\n\n• Заказ: #ord_ref_1\n\nВыберите действие ниже:",
            },
        }

        bot.handle_callback(callback)

        refreshed = self.store.get_order("ord_ref_1")
        meta = refreshed.get("meta_json") or {}
        self.assertEqual(meta.get("platega_collision_resolution"), "refund_manual")
        self.assertEqual(meta.get("platega_collision_resolved_by"), "tg:12345")
        self.assertEqual(meta.get("platega_collision_resolved_tx_id"), "tx_ref_555")

        bot.telegram.edit_message_text.assert_called_once()
        edit_kwargs = bot.telegram.edit_message_text.call_args[1]
        self.assertIn("ℹ️ ОТМЕЧЕНО: Оформлен возврат в кабинете Platega", edit_kwargs["text"])
        self.assertEqual(edit_kwargs.get("reply_markup"), {"inline_keyboard": []})

    def test_admin_callback_unauthorized(self) -> None:
        """Non-admin user cannot trigger platega collision callbacks."""
        bot = ShopBot(self.settings, self.store)
        bot.telegram = MagicMock()

        order = self._create_order("ord_unauth_1", status="cancelled")

        callback = {
            "id": "cb_hacker",
            "data": "admin:platega_act:ord_unauth_1:tx_hack",
            "from": {"id": 999999999, "username": "intruder"},
            "message": {"message_id": 123, "chat": {"id": 999999999}},
        }

        bot.handle_callback(callback)

        bot.telegram.answer_callback_query.assert_called_once_with("cb_hacker", "Доступ запрещен", show_alert=True)
        refreshed = self.store.get_order("ord_unauth_1")
        self.assertEqual(refreshed.get("status"), "cancelled")
        meta = refreshed.get("meta_json") or {}
        self.assertNotIn("platega_collision_resolution", meta)

    def test_admin_callback_idempotency(self) -> None:
        """Clicking callback on already resolved collision returns already resolved toast."""
        bot = ShopBot(self.settings, self.store)
        bot.telegram = MagicMock()

        order = self._create_order(
            "ord_idem_1",
            status="delivered",
            meta_json={
                "platega_collision_resolution": "extended",
                "platega_collision_resolved_by": "tg:12345",
            },
        )

        callback = {
            "id": "cb_idem_1",
            "data": "admin:platega_ext:ord_idem_1:tx_idem",
            "from": {"id": 12345, "username": "admin_chief"},
            "message": {"message_id": 444, "chat": {"id": 12345}},
        }

        bot.handle_callback(callback)

        bot.telegram.answer_callback_query.assert_called_once_with(
            "cb_idem_1",
            "Уже решено: extended",
            show_alert=True,
        )

    def test_order_reviewed_email_content(self) -> None:
        """Verifies custom reviewed email HTML and text generation."""
        html = render_order_reviewed_email_html(
            customer_email="test@example.com",
            order_public_id="ord_rev_email_1",
            duration_days=30,
            setup_url="https://example.com/order/ord_rev_email_1/token123",
            json_url="https://sub.example.com/sub_json",
            cabinet_url="https://example.com/cabinet",
            support_email="support@example.com",
            support_tg="https://t.me/SilentConnectSupport",
        )
        self.assertIn("ord_rev_email_1", html)
        self.assertIn("пересмотрен нашей службой поддержки", html)
        self.assertIn("+30дней", html.replace(" ", ""))
        self.assertIn("Приятного пользования!", html)
        self.assertIn("https://example.com/order/ord_rev_email_1/token123", html)

        text = render_order_reviewed_email_text(
            customer_email="test@example.com",
            order_public_id="ord_rev_email_1",
            duration_days=30,
            setup_url="https://example.com/order/ord_rev_email_1/token123",
            json_url="https://sub.example.com/sub_json",
            cabinet_url="https://example.com/cabinet",
        )
        self.assertIn("ord_rev_email_1", text)
        self.assertIn("пересмотрен нашей службой поддержки", text)
        self.assertIn("+30 дней", text)
        self.assertIn("Приятного пользования!", text)

    def test_platega_webhook_delivered_failed_status_no_alert(self) -> None:
        """Non-confirmed (e.g. FAILED, EXPIRED) webhooks on delivered orders do not trigger collision alerts."""
        order = self._create_order("ord_del_failed", status="delivered")
        data = {
            "status": "FAILED",
            "id": "tx_del_failed_1",
            "amount": 149.0,
            "currency": "RUB",
            "payload": "ord_del_failed",
        }
        res, code = self.checkout.handle_platega_callback(data)
        self.assertEqual(code, 200)
        self.assertEqual(res.get("message"), "delivered_order_failed_ignored")
        self.mock_telegram.send_message.assert_not_called()
        refreshed = self.store.get_order("ord_del_failed")
        meta = refreshed.get("meta_json") or {}
        self.assertNotIn("platega_collision_type", meta)

    def test_platega_webhook_retry_after_admin_activation_silent(self) -> None:
        """Retry of Platega webhook after admin activation does NOT send false double payment alert."""
        tx_id = "tx_act_retry_99"
        order = self._create_order("ord_act_retry", status="cancelled")
        # Step 1: Webhook arrives for cancelled order
        self.mock_telegram.send_message.return_value = {"message_id": 101}
        res1, code1 = self.checkout.handle_platega_callback({
            "status": "CONFIRMED",
            "id": tx_id,
            "amount": 149.0,
            "currency": "RUB",
            "payload": "ord_act_retry",
        })
        self.assertEqual(code1, 200)
        self.assertEqual(res1.get("message"), "collision_cancelled_reported")
        self.mock_telegram.send_message.assert_called_once()

        # Step 2: Admin activates the order
        bot = ShopBot(self.settings, self.store)
        bot.telegram = self.mock_telegram
        bot.provisioner = MagicMock()
        bot.provisioner.create_profile_for_order.return_value = {
            "profile": {"public_id": "p_act_ret", "id": 10, "expires_at": now_ts() + 30 * 86400},
            "subscription_url": "https://sub.example.com/p_act_ret",
        }
        cb = {
            "id": "cb_act_ret",
            "data": f"admin:platega_act:ord_act_retry:{tx_id}",
            "from": {"id": 12345},
            "message": {"message_id": 101, "chat": {"id": 12345}, "text": "alert"},
        }
        with patch("vpn_shop.bot.send_subscription_email_async"):
            bot.handle_callback(cb)

        refreshed = self.store.get_order("ord_act_retry")
        self.assertEqual(refreshed.get("status"), "delivered")

        # Step 3: Duplicate webhook arrives (e.g. gateway retry)
        self.mock_telegram.send_message.reset_mock()
        res2, code2 = self.checkout.handle_platega_callback({
            "status": "CONFIRMED",
            "id": tx_id,
            "amount": 149.0,
            "currency": "RUB",
            "payload": "ord_act_retry",
        })
        self.assertEqual(code2, 200)
        self.assertIn(res2.get("message"), ("already_delivered", "duplicate_ignored"))
        self.mock_telegram.send_message.assert_not_called()

        # Step 4: Even if webhook_events table was purged, order-level resolution prevents collision alerts
        with self.store._connect() as conn:
            conn.execute("DELETE FROM webhook_events")
        res3, code3 = self.checkout.handle_platega_callback({
            "status": "CONFIRMED",
            "id": tx_id,
            "amount": 149.0,
            "currency": "RUB",
            "payload": "ord_act_retry",
        })
        self.assertEqual(code3, 200)
        self.assertEqual(res3.get("message"), "already_delivered")
        self.mock_telegram.send_message.assert_not_called()

    def test_platega_webhook_retry_after_admin_extend_silent(self) -> None:
        """Retry of Platega webhook after admin extends does NOT trigger a second anomaly alert."""
        tx_id = "tx_ext_retry_77"
        prof = self.store.create_profile(
            xui_inbound_id=1,
            transport="tcp",
            profile_mode="personal",
            family_label=None,
            xui_email="user_ext_ret",
            xui_client_id="cid_ext_ret",
            expires_at=now_ts() + 86400,
            notes="test",
        )
        order = self._create_order("ord_ext_retry", status="delivered")
        self.store.link_order_profile("ord_ext_retry", prof["public_id"])

        # Collision alert fired
        self.mock_telegram.send_message.return_value = {"message_id": 202}
        res1, code1 = self.checkout.handle_platega_callback({
            "status": "CONFIRMED",
            "id": tx_id,
            "amount": 149.0,
            "currency": "RUB",
            "payload": "ord_ext_retry",
        })
        self.assertEqual(code1, 200)
        self.assertEqual(res1.get("message"), "collision_reported")

        # Admin extends
        bot = ShopBot(self.settings, self.store)
        bot.telegram = self.mock_telegram
        bot.provisioner = MagicMock()
        bot.provisioner.renew_profile.return_value = {
            "profile": prof,
            "subscription_url": "https://sub.example.com/p",
            "expires_at": now_ts() + 31 * 86400,
        }
        cb = {
            "id": "cb_ext_ret",
            "data": f"admin:platega_ext:ord_ext_retry:{tx_id}",
            "from": {"id": 12345},
            "message": {"message_id": 202, "chat": {"id": 12345}, "text": "alert"},
        }
        with patch("vpn_shop.bot.send_order_reviewed_email_async"):
            bot.handle_callback(cb)

        # Retry callback arrives
        self.mock_telegram.send_message.reset_mock()
        res2, code2 = self.checkout.handle_platega_callback({
            "status": "CONFIRMED",
            "id": tx_id,
            "amount": 149.0,
            "currency": "RUB",
            "payload": "ord_ext_retry",
        })
        self.assertEqual(code2, 200)
        self.assertIn(res2.get("message"), ("already_delivered", "duplicate_ignored"))
        self.mock_telegram.send_message.assert_not_called()

        with self.store._connect() as conn:
            conn.execute("DELETE FROM webhook_events")
        res3, code3 = self.checkout.handle_platega_callback({
            "status": "CONFIRMED",
            "id": tx_id,
            "amount": 149.0,
            "currency": "RUB",
            "payload": "ord_ext_retry",
        })
        self.assertEqual(code3, 200)
        self.assertEqual(res3.get("message"), "already_delivered")
        self.mock_telegram.send_message.assert_not_called()

    def test_platega_webhook_retry_after_admin_refund_silent(self) -> None:
        """Retry of Platega webhook after admin marks manual refund acknowledges without second alert."""
        tx_id = "tx_ref_retry_55"
        order = self._create_order("ord_ref_retry", status="cancelled")

        # Anomaly alert fired
        self.mock_telegram.send_message.return_value = {"message_id": 303}
        self.checkout.handle_platega_callback({
            "status": "CONFIRMED",
            "id": tx_id,
            "amount": 149.0,
            "currency": "RUB",
            "payload": "ord_ref_retry",
        })

        # Admin acknowledges refund
        bot = ShopBot(self.settings, self.store)
        bot.telegram = self.mock_telegram
        cb = {
            "id": "cb_ref_ret",
            "data": f"admin:platega_ack_refund:ord_ref_retry:{tx_id}",
            "from": {"id": 12345},
            "message": {"message_id": 303, "chat": {"id": 12345}, "text": "alert"},
        }
        bot.handle_callback(cb)

        # Retry callback arrives
        self.mock_telegram.send_message.reset_mock()
        res2, code2 = self.checkout.handle_platega_callback({
            "status": "CONFIRMED",
            "id": tx_id,
            "amount": 149.0,
            "currency": "RUB",
            "payload": "ord_ref_retry",
        })
        self.assertEqual(code2, 200)
        self.assertIn(res2.get("message"), ("already_resolved", "duplicate_ignored"))
        self.mock_telegram.send_message.assert_not_called()

        with self.store._connect() as conn:
            conn.execute("DELETE FROM webhook_events")
        res3, code3 = self.checkout.handle_platega_callback({
            "status": "CONFIRMED",
            "id": tx_id,
            "amount": 149.0,
            "currency": "RUB",
            "payload": "ord_ref_retry",
        })
        self.assertEqual(code3, 200)
        self.assertEqual(res3.get("message"), "already_resolved")
        self.mock_telegram.send_message.assert_not_called()

    def test_order_reviewed_email_resend_api(self) -> None:
        """Verifies send_order_reviewed_email_sync uses Resend API when RESEND_API_KEY is configured."""
        from vpn_shop.mailer import send_order_reviewed_email_sync
        import io
        import os

        self.settings.smtp_host = ""
        self.settings.smtp_user = "resend"
        self.settings.smtp_password = ""
        self.settings.smtp_from_email = "SilentConnect <support@example.com>"

        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"id": "msg_resend_999"}'
        mock_resp.__enter__.return_value = mock_resp

        with patch.dict(os.environ, {"RESEND_API_KEY": "re_mock_test_key"}):
            with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
                ok = send_order_reviewed_email_sync(
                    self.settings,
                    customer_email="test@example.com",
                    order_public_id="ord_resend_1",
                    duration_days=30,
                    setup_url="https://example.com/setup",
                    json_url="https://sub.example.com/json",
                    cabinet_url="https://example.com/cabinet",
                )
                self.assertTrue(ok)
                mock_urlopen.assert_called_once()
                req = mock_urlopen.call_args[0][0]
                self.assertEqual(req.full_url, "https://api.resend.com/emails")
                self.assertEqual(req.headers.get("Authorization"), "Bearer re_mock_test_key")

    def test_order_reviewed_email_custom_device_limit(self) -> None:
        """Verifies render_order_reviewed_email_html renders custom device limits correctly."""
        html_6 = render_order_reviewed_email_html(
            customer_email="test@example.com",
            order_public_id="ord_dev_6",
            duration_days=30,
            setup_url="https://example.com/setup",
            json_url="https://sub.example.com/json",
            cabinet_url="https://example.com/cabinet",
            device_limit=6,
        )
        self.assertIn("6 устройств", html_6)

        html_1 = render_order_reviewed_email_html(
            customer_email="test@example.com",
            order_public_id="ord_dev_1",
            duration_days=30,
            setup_url="https://example.com/setup",
            json_url="https://sub.example.com/json",
            cabinet_url="https://example.com/cabinet",
            device_limit=1,
        )
        self.assertIn("1 устройство", html_1)


if __name__ == "__main__":
    unittest.main()
