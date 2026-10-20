"""Unit tests for Digiseller integration, webhooks, and compliance in SilentConnect."""

from __future__ import annotations

import hashlib
import hmac
import json
import tempfile
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "vpn-shop"))

from vpn_shop.config import Settings
from vpn_shop.digiseller import (
    DigisellerApiError,
    DigisellerClient,
    build_default_listing_content,
)
from vpn_shop.store import Store
from vpn_shop.web import WebCheckout
from vpn_shop.bot import ShopBot


class TestDigisellerClient(unittest.TestCase):
    """Test suite for DigisellerClient authentication and signature verification."""

    def setUp(self) -> None:
        self.seller_id = "1348126"
        self.api_key = "MOCK_API_KEY_1234567890"
        self.secret_key = "MOCK_SECRET_KEY_9876543210"
        self.client = DigisellerClient(
            seller_id=self.seller_id,
            api_key=self.api_key,
            secret_key=self.secret_key,
        )

    def test_client_init(self) -> None:
        self.assertEqual(self.client.seller_id, "1348126")
        self.assertEqual(self.client.api_key, self.api_key)
        self.assertEqual(self.client.secret_key, self.secret_key)
        self.assertEqual(self.client.base_url, "https://api.digiseller.com")

    def test_missing_credentials_raises(self) -> None:
        empty_client = DigisellerClient(seller_id="", api_key="")
        with self.assertRaises(DigisellerApiError):
            empty_client.get_token()

    def test_signature_verification_format0_official(self) -> None:
        # Official Digiseller format from my.digiseller.com UI:
        # "хэш от строки, состоящей из вашего пароля в нижнем регистре, номера заказа и идентификатора товара через ';'"
        id_d = "6277867"
        id_i = "12345678"
        raw_sig = f"{self.secret_key.lower()};{id_i};{id_d}".encode("utf-8")
        sign = hashlib.sha256(raw_sig).hexdigest()

        # Test POST payload with uppercase keys
        payload_post = {
            "ID_I": id_i,
            "ID_D": id_d,
            "Amount": "149",
            "Currency": "RUB",
            "Email": "buyer@example.com",
            "Date": "2026-10-17 16:45:00",
            "SHA256": sign,
        }
        self.assertTrue(self.client.verify_webhook_signature(payload_post))

        # Test GET payload with lowercase keys
        payload_get = {
            "id_i": id_i,
            "id_d": id_d,
            "amount": "149",
            "curr": "RUB",
            "date": "2026-10-17 16:45:00",
            "email": "buyer@example.com",
            "sha256": sign,
        }
        self.assertTrue(self.client.verify_webhook_signature(payload_get))

    def test_signature_verification_format1(self) -> None:
        id_goods = "12345"
        id_invoice = "67890"
        date_pay = "2026-10-16 12:00:00"
        amount = "149"
        raw_sig = f"{id_goods}{id_invoice}{date_pay}{amount}{self.secret_key}".encode("utf-8")
        sign = hashlib.sha256(raw_sig).hexdigest()

        payload = {
            "id_goods": id_goods,
            "id_invoice": id_invoice,
            "date_pay": date_pay,
            "amount": amount,
            "sign": sign,
        }
        self.assertTrue(self.client.verify_webhook_signature(payload))

    def test_signature_verification_format2(self) -> None:
        id_invoice = "67890"
        raw_sig = f"{id_invoice}{self.secret_key}".encode("utf-8")
        sign = hashlib.sha256(raw_sig).hexdigest()

        payload = {
            "id_invoice": id_invoice,
            "sign": sign,
        }
        # Format 2 is deprecated and rejected for security hardening
        self.assertFalse(self.client.verify_webhook_signature(payload))

    def test_signature_verification_format3_hmac(self) -> None:
        payload = {
            "amount": "149",
            "email_buyer": "buyer@example.com",
            "id_invoice": "99999",
        }
        sorted_keys = sorted(payload.keys())
        data_str = ";".join(f"{k}:{payload[k]}" for k in sorted_keys) + ";"
        sign = hmac.new(self.secret_key.encode("utf-8"), data_str.encode("utf-8"), hashlib.sha256).hexdigest()

        payload_with_sign = dict(payload)
        payload_with_sign["sign"] = sign
        self.assertTrue(self.client.verify_webhook_signature(payload_with_sign))

    def test_signature_verification_format4_md5_rejected(self) -> None:
        """MD5 signatures must be rejected by hardened SHA256 security policy."""
        id_goods = "111"
        id_invoice = "222"
        date_pay = "2026-10-16"
        amount = "149"
        sign = hashlib.md5(f"{id_goods}{id_invoice}{date_pay}{amount}{self.secret_key}".encode("utf-8")).hexdigest()

        payload = {
            "id_goods": id_goods,
            "id_invoice": id_invoice,
            "date_pay": date_pay,
            "amount": amount,
            "sign": sign,
        }
        self.assertFalse(self.client.verify_webhook_signature(payload))

    def test_invalid_signature_rejected(self) -> None:
        payload = {
            "id_invoice": "67890",
            "sign": "invalid_bogus_signature",
        }
        self.assertFalse(self.client.verify_webhook_signature(payload))

    def test_zero_vpn_compliance(self) -> None:
        """Verify strictly that the generated listing contains zero forbidden 'VPN' terms."""
        content = build_default_listing_content()
        name_ru = content["name_ru"]
        desc_ru = content["description_ru"]
        desc_en = content["description_en"]

        # Ensure no standalone VPN words or circumvention claims
        forbidden_terms = [" впн", "впн ", "vpn сервис", "обход блокировок", "обхода блокировок", "заблокированных сайтов"]
        for term in forbidden_terms:
            self.assertNotIn(term, name_ru.lower())
            self.assertNotIn(term, desc_ru.lower())
            self.assertNotIn(term, desc_en.lower())

        # Ensure key approved features are present
        self.assertIn("1 Gbps", name_ru)
        self.assertIn("3 устройства", name_ru)
        self.assertIn("VLESS Reality", name_ru)
        self.assertIn("AmneziaWG", name_ru)
        self.assertIn("Hysteria 2", name_ru)


class TestDigisellerWebhookIntegration(unittest.TestCase):
    """Integration test suite for Digiseller webhook processing and order fulfillment."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_vpn_shop.db"
        self.store = Store(self.db_path)
        self.store.init()

        self.settings = MagicMock(spec=Settings)
        self.settings.root_dir = Path(self.temp_dir.name)
        self.settings.data_dir = Path(self.temp_dir.name)
        self.settings.database_path = self.db_path
        self.settings.terms_version = "v1"
        self.settings.support_tg_url = "https://t.me/support"
        self.settings.telegram_bot_token = ""
        self.settings.telegram_bot_username = "SilentConnectVPNBot"
        self.settings.subscription_base_url = "https://sub.example.com"
        self.settings.web_public_base_url = "https://example.com"
        self.settings.platega_merchant_id_bot = ""
        self.settings.platega_merchant_id_web = ""
        self.settings.platega_secret = ""
        self.settings.platega_secret_bot = ""
        self.settings.platega_secret_web = ""
        self.settings.digiseller_enabled = True
        self.settings.digiseller_seller_id = "1348126"
        self.settings.digiseller_api_key = "TEST_KEY"
        self.settings.digiseller_secret_key = "TEST_SECRET_123"
        self.settings.digiseller_product_id = "33111"
        self.settings.digiseller_min_price_rub = 149
        self.settings.admin_user_ids = ()
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
        self.settings.cf_turnstile_secret_key = ""
        self.settings.smtp_host = ""
        self.settings.smtp_user = ""
        self.settings.smtp_password = ""
        self.settings.smtp_from = ""

        self.checkout = WebCheckout(self.settings, self.store)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_webhook_disabled_rejected(self) -> None:
        self.settings.digiseller_enabled = False
        res, code = self.checkout.handle_digiseller_callback({"sign": "any"})
        self.assertEqual(code, 503)
        self.assertEqual(res.get("status"), "error")
        self.assertEqual(res.get("message"), "digiseller_disabled")

    def test_webhook_unauthorized_rejected(self) -> None:
        res, code = self.checkout.handle_digiseller_callback({"sign": "invalid_sig"})
        self.assertEqual(code, 401)
        self.assertEqual(res.get("status"), "error")
        self.assertEqual(res.get("message"), "unauthorized")

    def test_webhook_successful_delivery_with_digiseller_schema(self) -> None:
        invoice_id = "777888"
        raw_sig = f"{self.settings.digiseller_secret_key.lower()};{invoice_id};33111".encode("utf-8")
        sign = hashlib.sha256(raw_sig).hexdigest()

        payload = {
            "id_invoice": invoice_id,
            "id_goods": "33111",
            "amount": "149",
            "email_buyer": "customer@example.com",
            "unique_code": "CODE_ABC123",
            "sign": sign,
        }
        raw_body = json.dumps(payload).encode("utf-8")

        mock_bot = MagicMock()
        def fake_complete_order(order, actor="digiseller_webhook"):
            self.store.transition_order(order["public_id"], "provisioning", actor=actor, reason="test_start")
            self.store.transition_order(order["public_id"], "delivered", actor=actor, reason="test_done")
            return {
                "status": "delivered",
                "profile_public_id": "test_profile_123",
                "subscription_url": "https://sub.example.com/my-secret-sub/import/test_profile_123",
            }
        mock_bot.complete_order.side_effect = fake_complete_order
        self.checkout._bot = mock_bot

        # Mock Digiseller API purchase/info returning canonical nested content schema
        mock_purchase_info = {
            "retval": 0,
            "retdesc": None,
            "content": {
                "invoice_id": invoice_id,
                "item_id": "33111",
                "amount": 149.00,
                "currency": "RUB",
                "profit": 145.27,
                "date_pay": "2026-10-17T12:00:00",
                "buyer_info": {
                    "email": "verified_customer@example.com",
                    "payment_method": "Банковская карта",
                },
                "lock_state": "free",
            },
        }

        with patch.object(self.checkout.digiseller, "get_purchase_info", return_value=mock_purchase_info), \
             patch.object(self.checkout.digiseller, "deliver_unique_code", return_value={"retval": 0}) as mock_deliver, \
             patch("vpn_shop.web.send_subscription_email_async"):
            res, code = self.checkout.handle_digiseller_callback(payload, raw_body=raw_body)
            self.assertEqual(code, 200)
            self.assertEqual(res.get("status"), "ok")
            self.assertEqual(res.get("message"), "delivered")
            self.assertTrue(res.get("order_id"))
            self.assertEqual(res.get("sub_url"), "https://sub.example.com/my-secret-sub/import/test_profile_123")

            # Verify deliver_unique_code was invoked with sub_url
            mock_deliver.assert_called_once()
            self.assertIn("CODE_ABC123", mock_deliver.call_args[0][0])
            self.assertIn("Личный кабинет", mock_deliver.call_args[0][1])

        # Verify order in store: verified API email prioritized
        order = self.store.get_order_by_digiseller_invoice(invoice_id)
        self.assertIsNotNone(order)
        self.assertEqual(order["status"], "delivered")
        self.assertEqual(order["customer_email"], "verified_customer@example.com")
        self.assertTrue((order.get("meta_json") or {}).get("digiseller_delivered"))

        # Test duplicate callback is idempotently ignored
        dup_res, dup_code = self.checkout.handle_digiseller_callback(payload, raw_body=raw_body)
        self.assertEqual(dup_code, 200)
        self.assertEqual(dup_res.get("status"), "ok")
        self.assertEqual(dup_res.get("message"), "duplicate_ignored")

    def test_unpaid_order_fails_closed(self) -> None:
        """If Digiseller API returns date_pay empty (unpaid), provisioning must be rejected."""
        invoice_id = "555444"
        raw_sig = f"{self.settings.digiseller_secret_key.lower()};{invoice_id};33111".encode("utf-8")
        sign = hashlib.sha256(raw_sig).hexdigest()

        payload = {"id_invoice": invoice_id, "id_goods": "33111", "sign": sign}
        mock_unpaid_info = {
            "retval": 0,
            "content": {
                "invoice_id": invoice_id,
                "item_id": "33111",
                "date_pay": "",  # Unpaid!
                "lock_state": "free",
            },
        }

        with patch.object(self.checkout.digiseller, "get_purchase_info", return_value=mock_unpaid_info):
            res, code = self.checkout.handle_digiseller_callback(payload)
            self.assertEqual(code, 400)
            self.assertEqual(res.get("message"), "not_paid_missing_date_pay")

        # Order must NOT exist
        order = self.store.get_order_by_digiseller_invoice(invoice_id)
        self.assertIsNone(order)

    def test_refund_and_tombstone(self) -> None:
        """Verify refund revokes profile access and tombstones future delayed sales."""
        invoice_id = "999111"
        raw_sig = f"{self.settings.digiseller_secret_key.lower()};{invoice_id};33111".encode("utf-8")
        sign = hashlib.sha256(raw_sig).hexdigest()

        # Step 1: Deliver initial sale
        sale_payload = {
            "id_invoice": invoice_id,
            "id_goods": "33111",
            "amount": "149",
            "sign": sign,
        }
        mock_bot = MagicMock()
        mock_bot.complete_order.return_value = {"status": "delivered", "profile_public_id": "prf_refund_123"}
        self.checkout._bot = mock_bot

        mock_info = {
            "retval": 0,
            "content": {
                "invoice_id": invoice_id,
                "item_id": "33111",
                "date_pay": "2026-10-17T12:00:00",
                "lock_state": "free",
            },
        }
        with patch.object(self.checkout.digiseller, "get_purchase_info", return_value=mock_info), \
             patch("vpn_shop.web.send_subscription_email_async"):
            res, code = self.checkout.handle_digiseller_callback(sale_payload)
            self.assertEqual(code, 200)

        # Step 2: Webhook refund arrives
        refund_payload = {
            "id_invoice": invoice_id,
            "id_goods": "33111",
            "action": "refund",
            "sign": sign,
        }
        with patch.object(self.checkout, "revoke_profile_access") as mock_revoke, \
             patch.object(self.checkout.digiseller, "get_purchase_info", return_value={"retval": 0}):
            ref_res, ref_code = self.checkout.handle_digiseller_callback(refund_payload)
            self.assertEqual(ref_code, 200)
            self.assertEqual(ref_res.get("message"), "refund_processed")
            mock_revoke.assert_called_once()

        # Verify order status is cancelled in store
        order = self.store.get_order_by_digiseller_invoice(invoice_id)
        self.assertEqual(order["status"], "cancelled")

        # Step 3: Out-of-order tombstone verification
        # If sale arrives after tombstone, provisioning must be aborted
        self.assertTrue(self.store.is_refund_tombstoned("digiseller", invoice_id))

    def test_product_id_unconfigured_fail_closed(self):
        """Verify that if DIGISELLER_PRODUCT_ID is empty/unset, webhook rejects fail-closed."""
        self.settings.digiseller_product_id = ""
        invoice_id = "inv_unset_prod_999"
        sign = hashlib.sha256(f"{self.settings.digiseller_secret_key.lower()};{invoice_id};33111".encode()).hexdigest()
        payload = {
            "id_invoice": invoice_id,
            "id_goods": "33111",
            "sign": sign,
        }
        mock_info = {
            "retval": 0,
            "content": {
                "invoice_id": invoice_id,
                "item_id": "33111",
                "date_pay": "2026-10-17T12:00:00",
                "lock_state": "free",
            },
        }
        with patch.object(self.checkout.digiseller, "get_purchase_info", return_value=mock_info):
            res, code = self.checkout.handle_digiseller_callback(payload)
            self.assertEqual(code, 400)
            self.assertEqual(res.get("message"), "product_mismatch")

    def test_parse_purchase_info_invoice_state_paid_and_refund(self):
        """Test invoice_state 3 is valid, and 2/5 are rejected."""
        # 1. State 3 (success) with purchase_date and currency_type
        success_resp = {
            "retval": 0,
            "content": {
                "invoice_id": 1001,
                "item_id": 33111,
                "invoice_state": 3,
                "purchase_date": "2026-10-17 12:00:00",
                "amount": 149.0,
                "currency_type": "WMZ",
                "buyer_info": {"email": "buyer@example.com"},
            },
        }
        parsed = self.checkout.digiseller.parse_purchase_info(success_resp)
        self.assertTrue(parsed["valid"])
        self.assertEqual(parsed["currency"], "WMZ")
        self.assertEqual(parsed["email"], "buyer@example.com")

        # 2. State 5 (refunded)
        refund_resp = {
            "retval": 0,
            "content": {
                "invoice_id": 1002,
                "item_id": 33111,
                "invoice_state": 5,
                "purchase_date": "2026-10-17 12:00:00",
            },
        }
        parsed_ref = self.checkout.digiseller.parse_purchase_info(refund_resp)
        self.assertFalse(parsed_ref["valid"])
        self.assertEqual(parsed_ref["reason"], "refunded")

        # 3. State 2 (cancelled)
        cancel_resp = {
            "retval": 0,
            "content": {
                "invoice_id": 1003,
                "item_id": 33111,
                "invoice_state": 2,
            },
        }
        parsed_cancel = self.checkout.digiseller.parse_purchase_info(cancel_resp)
        self.assertFalse(parsed_cancel["valid"])
        self.assertEqual(parsed_cancel["reason"], "payment_cancelled")

    def test_order_creates_web_token_and_sends_email(self):
        """Digiseller purchase must attach web_token and dispatch subscription email."""
        invoice_id = "inv_email_test_123"
        sign = hashlib.sha256(f"{self.settings.digiseller_secret_key.lower()};{invoice_id};33111".encode()).hexdigest()
        payload = {
            "id_invoice": invoice_id,
            "id_goods": "33111",
            "sign": sign,
            "unique_code": "CODE_XYZ_999",
        }
        mock_purchase_info = {
            "retval": 0,
            "content": {
                "invoice_id": invoice_id,
                "item_id": "33111",
                "invoice_state": 3,
                "purchase_date": "2026-10-17 12:00:00",
                "amount": 149.0,
                "currency": "RUB",
                "buyer_info": {"email": "digi_buyer@example.com"},
                "lock_state": "free",
            },
        }

        mock_bot = MagicMock()
        mock_bot.complete_order.return_value = {
            "status": "delivered",
            "subscription_url": "https://sub.example.com/my-secret-sub/import/prf_digi_999",
            "profile_public_id": "prf_digi_999",
        }
        self.checkout._bot = mock_bot

        with patch.object(self.checkout.digiseller, "get_purchase_info", return_value=mock_purchase_info), \
             patch.object(self.checkout.digiseller, "deliver_unique_code", return_value={"retval": 0}) as mock_deliver, \
             patch("vpn_shop.web.send_subscription_email_async") as mock_send_email:
            res, code = self.checkout.handle_digiseller_callback(payload)
            self.assertEqual(code, 200)
            self.assertEqual(res.get("status"), "ok")

            # Verify email was dispatched to buyer
            mock_send_email.assert_called_once()
            call_kwargs = mock_send_email.call_args[1]
            self.assertEqual(call_kwargs["customer_email"], "digi_buyer@example.com")
            self.assertIn("/order/", call_kwargs["cabinet_url"])

            # Verify web_token attached to order (hashed in db)
            order = self.store.get_order_by_digiseller_invoice(invoice_id)
            self.assertIsNotNone(order)
            self.assertTrue(order.get("web_token_hash"))

            # Verify deliver_unique_code included cabinet_url
            mock_deliver.assert_called_once()
            delivery_msg = mock_deliver.call_args[0][1]
            self.assertIn("Личный кабинет", delivery_msg)
            self.assertIn("/order/", delivery_msg)

    def test_bot_revoke_profile_access(self):
        """Verify ShopBot.revoke_profile_access expires profile, disables slots, and updates xui."""
        bot = MagicMock(spec=ShopBot)
        bot.store = self.store
        bot.xui_db = MagicMock()
        bot.settings = self.settings

        # Create active profile and slot
        prof = self.store.create_profile(
            xui_inbound_id=2,
            transport="tcp",
            profile_mode="individual",
            family_label=None,
            xui_email="revoke_test@example.com",
            xui_client_id="uuid_123",
            expires_at=1000000000,
        )
        slot = self.store.create_awg_slot(
            profile_public_id=prof["public_id"],
            slot_index=1,
            slot_label="Устройство 1",
            public_key="key_123",
            private_key_enc="enc_123",
            client_ip="10.8.0.99",
            enabled=True,
            server_code="nl",
        )
        self.assertTrue(slot["enabled"])

        # Invoke revoke_profile_access method bound to bot
        ShopBot.revoke_profile_access(bot, prof["public_id"])

        # Profile must be marked expired
        refreshed = self.store.get_profile(prof["public_id"])
        self.assertEqual(refreshed["status"], "expired")

        # Slot must be disabled
        slots = self.store.list_awg_slots(prof["public_id"])
        self.assertEqual(len(slots), 1)
        self.assertFalse(slots[0]["enabled"])

        # X-UI update must have been invoked with enable=False
        bot.xui_db.update_client_expiry_direct.assert_called_once_with(
            inbound_id=2,
            email="revoke_test@example.com",
            new_expiry_ms=1,
            enable=False,
        )

    def test_reconcile_digiseller_orders_dispute_revocation(self):
        """Verify reconcile_digiseller_orders cancels order and revokes profile on API dispute."""
        bot = MagicMock(spec=ShopBot)
        bot.store = self.store
        bot.settings = self.settings
        bot.settings.digiseller_enabled = True
        bot.settings.digiseller_api_key = "test_key"
        bot.revoke_profile_access = MagicMock()

        # Create delivered order with profile
        prof = self.store.create_profile(
            xui_inbound_id=2,
            transport="tcp",
            profile_mode="individual",
            family_label=None,
            xui_email="dispute_test@example.com",
            xui_client_id="uuid_456",
            expires_at=1000000000,
        )
        order = self.store.create_order(
            kind="purchase",
            status="delivered",
            transport="tcp",
            duration_days=30,
            profile_mode="individual",
            family_label=None,
            base_price_rub=149,
            final_price_rub=149,
            promo_id=None,
            invite_id=None,
            customer_chat_id=None,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version="1.0",
            customer_email="dispute@example.com",
            external_id="digiseller:inv_disp_123",
            meta={
                "source": "digiseller",
                "digiseller_invoice_id": "inv_disp_123",
                "digiseller_unique_code": "CODE_DISP",
                "digiseller_delivered": True,
            },
        )
        with self.store._connect() as conn:
            conn.execute(
                "UPDATE orders SET provisioned_profile_id = ? WHERE public_id = ?",
                (prof["id"], order["public_id"]),
            )

        mock_digi_client = MagicMock()
        mock_digi_client.get_purchase_info.return_value = {
            "retval": 0,
            "content": {
                "invoice_id": "inv_disp_123",
                "item_id": "33111",
                "invoice_state": 5,  # Refund/Dispute!
                "lock_state": "blocked",
            },
        }
        mock_digi_client.parse_purchase_info.return_value = {
            "valid": False,
            "reason": "refunded",
            "invoice_state": 5,
            "raw": {"lock_state": "blocked"},
        }
        bot.digiseller = mock_digi_client

        ShopBot.reconcile_digiseller_orders(bot)

        # Order must now be cancelled
        updated_order = self.store.get_order(order["public_id"])
        self.assertEqual(updated_order["status"], "cancelled")

        # revoke_profile_access must have been called with prof["public_id"]
        bot.revoke_profile_access.assert_called_once_with(prof["public_id"])


if __name__ == "__main__":
    unittest.main()


