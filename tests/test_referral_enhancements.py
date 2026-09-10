"""Comprehensive test suite for the modernized SilentConnect Referral System.

Covers:
1. Accounting model (balance = max(total_earned - total_paid, 0), partial and full payouts).
2. Anti-retroactive protection (already_customer blocks paid/waiting users).
3. Invitee 10% first order discounts (Bot and Web).
4. Instant Telegram notifications (on registration & accrual) and 500 RUB admin threshold alert.
5. Cross-channel renewal attribution (web & subjson inline renewals inheriting referrer).
6. 4-step referral attribution resolution chain.
7. Admin referral payout execution & UI report formatting.
8. Web referral cookie and banner rendering.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
VPN_SHOP_DIR = PROJECT_ROOT / "vpn-shop"
SUBJSON_DIR = PROJECT_ROOT / "subjson-service"
SCRIPTS_DIR = PROJECT_ROOT / "scripts"

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(VPN_SHOP_DIR) not in sys.path:
    sys.path.insert(0, str(VPN_SHOP_DIR))
if str(SUBJSON_DIR) not in sys.path:
    sys.path.insert(0, str(SUBJSON_DIR))
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

os.environ.setdefault("SERVER_PEPPER", "unit-test-pepper-0123456789abcdefghijklmnop")
os.environ.setdefault("HYSTERIA_SALAMANDER_PASSWORD", "test-salamander-pwd-123")
os.environ.setdefault("HYSTERIA_AUTH_PASSWORD", "test-auth-pwd-123")
os.environ.setdefault("SECRET_SEGMENT", "test-secret-sub")
os.environ.setdefault("PUBLIC_HOST", "sub.example.com")
os.environ.setdefault("INTERNAL_SECRET", "internal-test-token")

from vpn_shop import config, security, store, web, bot
from vpn_shop.config import load_settings, REFERRAL_INVITEE_DISCOUNT_PERCENT, REFERRAL_COOKIE_NAME
from vpn_shop.payments import ManualPaymentProcessor
from vpn_shop.store import Store
from vpn_shop.web import WebCheckout, RequestHandler

import importlib.util
subjson_path = SUBJSON_DIR / "app.py"
spec_subjson = importlib.util.spec_from_file_location("subjson_app_ref", str(subjson_path))
subjson_app = importlib.util.module_from_spec(spec_subjson)
spec_subjson.loader.exec_module(subjson_app)


def make_test_store() -> tuple[Store, Path]:
    tmp = Path(tempfile.mkdtemp())
    st = Store(tmp / "vpn_shop.db")
    st.init()
    return st, tmp


class TestReferralStoreAccounting(unittest.TestCase):
    """Test accounting formulas and partial/full payouts."""

    def setUp(self):
        self.store, self.tmp_dir = make_test_store()

    def test_balance_empty(self):
        ref = self.store.ensure_referrer(user_id=1001, chat_id=1001, commission_percent=10)
        bal = self.store.get_referral_balance(ref["id"])
        self.assertIsNotNone(bal)
        self.assertEqual(bal["total_earned_rub"], 0)
        self.assertEqual(bal["total_paid_rub"], 0)
        self.assertEqual(bal["balance_rub"], 0)

    def test_ledger_accrual_and_balance_calculation(self):
        ref = self.store.ensure_referrer(user_id=2001, chat_id=2001, commission_percent=10)
        self.store.attach_referral(code=ref["code"], referred_user_id=3001, referred_chat_id=3001)

        # Order 1: 1000 RUB -> 100 RUB commission
        order1 = self.store.create_order(
            kind="purchase",
            status="waiting_payment",
            transport="tcp",
            duration_days=30,
            profile_mode="single",
            family_label=None,
            base_price_rub=1000,
            final_price_rub=1000,
            promo_id=None,
            invite_id=None,
            customer_chat_id=3001,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version="v1",
        )
        ledger1, old_bal, new_bal = self.store.create_referral_ledger_for_order(order1)
        self.assertIsNotNone(ledger1)
        self.assertEqual(ledger1["amount_rub"], 100)
        self.assertEqual(old_bal, 0)
        self.assertEqual(new_bal, 100)

        # Order 2: 500 RUB -> 50 RUB commission
        order2 = self.store.create_order(
            kind="purchase",
            status="waiting_payment",
            transport="tcp",
            duration_days=30,
            profile_mode="single",
            family_label=None,
            base_price_rub=500,
            final_price_rub=500,
            promo_id=None,
            invite_id=None,
            customer_chat_id=3001,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version="v1",
        )
        ledger2, old_bal2, new_bal2 = self.store.create_referral_ledger_for_order(order2)
        self.assertEqual(ledger2["amount_rub"], 50)
        self.assertEqual(old_bal2, 100)
        self.assertEqual(new_bal2, 150)

        bal = self.store.get_referral_balance(ref["id"])
        self.assertEqual(bal["total_earned_rub"], 150)
        self.assertEqual(bal["total_paid_rub"], 0)
        self.assertEqual(bal["balance_rub"], 150)

    def test_partial_and_full_payouts(self):
        ref = self.store.ensure_referrer(user_id=2002, chat_id=2002, commission_percent=10)
        self.store.attach_referral(code=ref["code"], referred_user_id=3002, referred_chat_id=3002)

        # Accrue 750 RUB total (3 orders of 2500 RUB = 250 RUB each)
        for _ in range(3):
            ord_item = self.store.create_order(
                kind="purchase",
                status="waiting_payment",
                transport="tcp",
                duration_days=30,
                profile_mode="single",
                family_label=None,
                base_price_rub=2500,
                final_price_rub=2500,
                promo_id=None,
                invite_id=None,
                customer_chat_id=3002,
                privacy_ack=True,
                loss_policy_ack=True,
                terms_version="v1",
            )
            self.store.create_referral_ledger_for_order(ord_item)

        bal_before = self.store.get_referral_balance(ref["id"])
        self.assertEqual(bal_before["total_earned_rub"], 750)
        self.assertEqual(bal_before["balance_rub"], 750)

        # Partial payout of 500 RUB
        payout1 = self.store.create_referral_payout(referrer_id=ref["id"], actor="admin-test", amount_rub=500)
        self.assertIsNotNone(payout1)
        self.assertEqual(payout1["amount_rub"], 500)
        self.assertEqual(payout1["actor"], "admin-test")

        bal_after_partial = self.store.get_referral_balance(ref["id"])
        self.assertEqual(bal_after_partial["total_earned_rub"], 750)
        self.assertEqual(bal_after_partial["total_paid_rub"], 500)
        self.assertEqual(bal_after_partial["balance_rub"], 250)

        # Full payout of remaining 250 RUB (amount_rub=None)
        payout2 = self.store.create_referral_payout(referrer_id=ref["id"], actor="admin-test", amount_rub=None)
        self.assertIsNotNone(payout2)
        self.assertEqual(payout2["amount_rub"], 250)

        bal_after_full = self.store.get_referral_balance(ref["id"])
        self.assertEqual(bal_after_full["total_earned_rub"], 750)
        self.assertEqual(bal_after_full["total_paid_rub"], 750)
        self.assertEqual(bal_after_full["balance_rub"], 0)

        # Payout when balance is 0 returns None
        payout_empty = self.store.create_referral_payout(referrer_id=ref["id"], actor="admin-test", amount_rub=100)
        self.assertIsNone(payout_empty)

    def test_payout_capped_at_current_balance(self):
        ref = self.store.ensure_referrer(user_id=2003, chat_id=2003, commission_percent=10)
        self.store.attach_referral(code=ref["code"], referred_user_id=3003, referred_chat_id=3003)

        ord_item = self.store.create_order(
            kind="purchase",
            status="waiting_payment",
            transport="tcp",
            duration_days=30,
            profile_mode="single",
            family_label=None,
            base_price_rub=1000,
            final_price_rub=1000,
            promo_id=None,
            invite_id=None,
            customer_chat_id=3003,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version="v1",
        )
        self.store.create_referral_ledger_for_order(ord_item)

        # Balance is 100 RUB, but admin requested 500 RUB
        payout = self.store.create_referral_payout(referrer_id=ref["id"], actor="admin-test", amount_rub=500)
        self.assertIsNotNone(payout)
        self.assertEqual(payout["amount_rub"], 100)

        bal = self.store.get_referral_balance(ref["id"])
        self.assertEqual(bal["balance_rub"], 0)


class TestAntiRetroactiveProtection(unittest.TestCase):
    """Test anti-retroactive protection preventing existing customers from attaching referral codes."""

    def setUp(self):
        self.store, self.tmp_dir = make_test_store()
        self.ref = self.store.ensure_referrer(user_id=5001, chat_id=5001, commission_percent=10)

    def test_new_user_can_attach(self):
        status, attr = self.store.attach_referral(code=self.ref["code"], referred_user_id=6001, referred_chat_id=6001)
        self.assertEqual(status, "created")
        self.assertIsNotNone(attr)
        self.assertEqual(attr["referrer_id"], self.ref["id"])

    def test_delivered_paid_order_blocks_referral(self):
        # Existing user with delivered paid order
        self.store.create_order(
            kind="purchase",
            status="delivered",
            transport="tcp",
            duration_days=30,
            profile_mode="single",
            family_label=None,
            base_price_rub=199,
            final_price_rub=199,
            promo_id=None,
            invite_id=None,
            customer_chat_id=6002,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version="v1",
        )
        status, attr = self.store.attach_referral(code=self.ref["code"], referred_user_id=6002, referred_chat_id=6002)
        self.assertEqual(status, "already_customer")
        self.assertIsNone(attr)

    def test_waiting_payment_paid_order_blocks_referral(self):
        # Existing user with waiting_payment paid order
        self.store.create_order(
            kind="purchase",
            status="waiting_payment",
            transport="tcp",
            duration_days=30,
            profile_mode="single",
            family_label=None,
            base_price_rub=399,
            final_price_rub=399,
            promo_id=None,
            invite_id=None,
            customer_chat_id=6003,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version="v1",
        )
        status, attr = self.store.attach_referral(code=self.ref["code"], referred_user_id=6003, referred_chat_id=6003)
        self.assertEqual(status, "already_customer")
        self.assertIsNone(attr)

    def test_free_or_trial_order_does_not_block_referral(self):
        # User who only took a free trial (final_price_rub = 0)
        self.store.create_order(
            kind="purchase",
            status="delivered",
            transport="tcp",
            duration_days=7,
            profile_mode="single",
            family_label=None,
            base_price_rub=0,
            final_price_rub=0,
            promo_id=None,
            invite_id=None,
            customer_chat_id=6004,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version="v1",
            meta={"source": "trial"},
        )
        status, attr = self.store.attach_referral(code=self.ref["code"], referred_user_id=6004, referred_chat_id=6004)
        self.assertEqual(status, "created")
        self.assertIsNotNone(attr)

    def test_self_referral_blocked(self):
        status, attr = self.store.attach_referral(
            code=self.ref["code"],
            referred_user_id=self.ref["user_id"],
            referred_chat_id=self.ref["chat_id"],
        )
        self.assertEqual(status, "self")

    def test_already_referred_returns_exists(self):
        self.store.attach_referral(code=self.ref["code"], referred_user_id=6005, referred_chat_id=6005)
        # Try to attach again
        status, attr = self.store.attach_referral(code=self.ref["code"], referred_user_id=6005, referred_chat_id=6005)
        self.assertEqual(status, "exists")
        self.assertIsNotNone(attr)


class TestInviteeDiscounts(unittest.TestCase):
    """Test 10% discount on first paid subscription for invitees in Bot and Web."""

    def setUp(self):
        self.store, self.tmp_dir = make_test_store()
        self.ref = self.store.ensure_referrer(user_id=7001, chat_id=7001, commission_percent=10)

    def test_bot_invitee_first_order_discount(self):
        invitee_chat_id = 8001
        self.store.attach_referral(code=self.ref["code"], referred_user_id=invitee_chat_id, referred_chat_id=invitee_chat_id)

        # Check attribution and prior delivered orders
        attr = self.store.get_referral_attribution_for_user(invitee_chat_id)
        self.assertIsNotNone(attr)
        prior_paid = self.store.count_delivered_paid_orders(customer_chat_id=invitee_chat_id)
        self.assertEqual(prior_paid, 0)

        # In Bot logic:
        base_price = 1000
        ref_discount = REFERRAL_INVITEE_DISCOUNT_PERCENT if prior_paid == 0 else 0
        final_price = max(base_price * (100 - ref_discount) // 100, 0)
        self.assertEqual(ref_discount, 10)
        self.assertEqual(final_price, 900)

        # Mark order as delivered
        self.store.create_order(
            kind="purchase",
            status="delivered",
            transport="tcp",
            duration_days=30,
            profile_mode="single",
            family_label=None,
            base_price_rub=base_price,
            final_price_rub=final_price,
            promo_id=None,
            invite_id=None,
            customer_chat_id=invitee_chat_id,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version="v1",
        )

        # Second order should get 0% referral discount
        prior_paid2 = self.store.count_delivered_paid_orders(customer_chat_id=invitee_chat_id)
        self.assertEqual(prior_paid2, 1)
        ref_discount2 = REFERRAL_INVITEE_DISCOUNT_PERCENT if prior_paid2 == 0 else 0
        self.assertEqual(ref_discount2, 0)

    def test_web_create_order_with_referral(self):
        settings = load_settings()
        web_checkout = WebCheckout(settings, self.store)

        email = "invitee@example.com"
        order = web_checkout.create_order(
            offer_code="tcp_30",
            customer_email=email,
            ref_code=self.ref["code"],
        )
        # Offer base price 149, 10% discount -> 134 RUB
        self.assertEqual(order["base_price_rub"], 149)
        self.assertEqual(order["final_price_rub"], 134)
        self.assertEqual(order["meta_json"]["referral_discount"], 10)
        self.assertEqual(order["meta_json"]["referrer_id"], self.ref["id"])

        # Check that referral attribution was created for email
        attr = self.store.get_referral_attribution_for_user(email)
        self.assertIsNotNone(attr)
        self.assertEqual(attr["referrer_id"], self.ref["id"])

        # If order is completed, subsequent order by same email gets no referral discount
        with self.store._connect() as conn:
            conn.execute("UPDATE orders SET status = 'delivered' WHERE public_id = ?", (order["public_id"],))

        order2 = web_checkout.create_order(
            offer_code="tcp_30",
            customer_email=email,
            ref_code=self.ref["code"],
        )
        self.assertEqual(order2["final_price_rub"], 149)
        self.assertNotIn("referral_discount", order2["meta_json"])


class TestReferrerNotificationsAndThresholdAlert(unittest.TestCase):
    """Test Telegram messages to referrer and 500 RUB admin threshold alert."""

    def setUp(self):
        self.store, self.tmp_dir = make_test_store()
        self.ref = self.store.ensure_referrer(user_id=9001, chat_id=9001, commission_percent=10)

    def test_payment_processor_accrual_and_threshold_alert(self):
        notifier = MagicMock()
        admin_notifier = MagicMock()
        processor = ManualPaymentProcessor(
            store=self.store,
            provisioner=MagicMock(),
            subscription_recover=MagicMock(),
            notifier=notifier,
            admin_notifier=admin_notifier,
        )

        self.store.attach_referral(code=self.ref["code"], referred_user_id=9002, referred_chat_id=9002)

        # Order 1: 4000 RUB -> 400 RUB commission (balance becomes 400, < 500)
        order1 = self.store.create_order(
            kind="purchase",
            status="waiting_payment",
            transport="tcp",
            duration_days=30,
            profile_mode="single",
            family_label=None,
            base_price_rub=4000,
            final_price_rub=4000,
            promo_id=None,
            invite_id=None,
            customer_chat_id=9002,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version="v1",
        )
        processor._accrue_referral(order1)

        # Referrer got accrual notification
        notifier.send_message.assert_called_once()
        msg = notifier.send_message.call_args[0][1]
        self.assertIn("+400 RUB (10%)", msg)
        self.assertIn("Баланс: 400 RUB", msg)
        # Admin threshold NOT triggered yet
        admin_notifier.assert_not_called()

        # Reset mocks
        notifier.reset_mock()
        admin_notifier.reset_mock()

        # Order 2: 1500 RUB -> 150 RUB commission (balance 400 -> 550, crosses 500 threshold!)
        order2 = self.store.create_order(
            kind="purchase",
            status="waiting_payment",
            transport="tcp",
            duration_days=30,
            profile_mode="single",
            family_label=None,
            base_price_rub=1500,
            final_price_rub=1500,
            promo_id=None,
            invite_id=None,
            customer_chat_id=9002,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version="v1",
        )
        processor._accrue_referral(order2)

        # Referrer got accrual notification
        notifier.send_message.assert_called_once()
        msg2 = notifier.send_message.call_args[0][1]
        self.assertIn("+150 RUB (10%)", msg2)
        self.assertIn("Баланс: 550 RUB", msg2)

        # Admin threshold WAS triggered!
        admin_notifier.assert_called_once()
        args = admin_notifier.call_args[0]
        self.assertEqual(args[0], self.ref["id"])
        self.assertEqual(args[1], 550)

        # Order 3: balance goes 550 -> 650 (already >= 500, should NOT trigger threshold alert again)
        notifier.reset_mock()
        admin_notifier.reset_mock()
        order3 = self.store.create_order(
            kind="purchase",
            status="waiting_payment",
            transport="tcp",
            duration_days=30,
            profile_mode="single",
            family_label=None,
            base_price_rub=1000,
            final_price_rub=1000,
            promo_id=None,
            invite_id=None,
            customer_chat_id=9002,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version="v1",
        )
        processor._accrue_referral(order3)
        notifier.send_message.assert_called_once()
        admin_notifier.assert_not_called()


class TestCrossChannelRenewalPersistence(unittest.TestCase):
    """Test referral attribution inheritance across Web and LK renewals (4-step chain)."""

    def setUp(self):
        self.store, self.tmp_dir = make_test_store()
        self.ref = self.store.ensure_referrer(user_id=11001, chat_id=11001, commission_percent=10)

    def test_renewal_order_4_step_resolution_chain(self):
        # 1. First order created with customer_chat_id
        invitee_chat = 12001
        self.store.attach_referral(code=self.ref["code"], referred_user_id=invitee_chat, referred_chat_id=invitee_chat)

        order1 = self.store.create_order(
            kind="purchase",
            status="delivered",
            transport="tcp",
            duration_days=30,
            profile_mode="single",
            family_label=None,
            base_price_rub=1000,
            final_price_rub=900,
            promo_id=None,
            invite_id=None,
            customer_chat_id=invitee_chat,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version="v1",
        )
        prof = self.store.create_profile(
            xui_inbound_id=1,
            transport="tcp",
            profile_mode="single",
            family_label=None,
            xui_email="test_user_ref@vpn",
            xui_client_id="uuid-1",
            expires_at=int(time.time()) + 30 * 86400,
        )
        with self.store._connect() as conn:
            conn.execute("UPDATE orders SET provisioned_profile_id = ? WHERE public_id = ?", (prof["id"], order1["public_id"]))

        # 2. Now an inline renewal order comes in from LK without customer_chat_id, but with provisioned_profile_id
        renewal_order = self.store.create_order(
            kind="renewal",
            status="waiting_payment",
            transport="tcp",
            duration_days=30,
            profile_mode="single",
            family_label=None,
            base_price_rub=1000,
            final_price_rub=1000,
            promo_id=None,
            invite_id=None,
            customer_chat_id=None,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version="v1",
        )
        with self.store._connect() as conn:
            conn.execute("UPDATE orders SET provisioned_profile_id = ? WHERE public_id = ?", (prof["id"], renewal_order["public_id"]))
        refreshed_renewal = self.store.get_order(renewal_order["public_id"])

        # 4-step resolution chain should resolve to referrer via earlier order for this profile
        ledger, old_bal, new_bal = self.store.create_referral_ledger_for_order(refreshed_renewal)
        self.assertIsNotNone(ledger)
        self.assertEqual(ledger["referrer_id"], self.ref["id"])
        self.assertEqual(ledger["amount_rub"], 100)

    def test_web_renewal_order_inherits_referrer_and_chat_id(self):
        settings = load_settings()
        web_checkout = WebCheckout(settings, self.store)
        web_checkout.provisioner = MagicMock()
        web_checkout.provisioner.xui_db.find_client_by_sub_id.return_value = {
            "client": {"email": "renewal_client@vpn", "id": "uuid-renewal", "expiryTime": 1700000000000},
            "inbound_id": 1,
        }

        prof = self.store.create_profile(
            xui_inbound_id=1,
            transport="tcp",
            profile_mode="single",
            family_label=None,
            xui_email="renewal_client@vpn",
            xui_client_id="uuid-renewal",
            expires_at=int(time.time()) + 30 * 86400,
        )
        # Create initial order with referrer_id in meta and customer_chat_id
        initial_order = self.store.create_order(
            kind="purchase",
            status="delivered",
            transport="tcp",
            duration_days=30,
            profile_mode="single",
            family_label=None,
            base_price_rub=199,
            final_price_rub=179,
            promo_id=None,
            invite_id=None,
            customer_chat_id=13001,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version="v1",
            customer_email="web_user@example.com",
            meta={"referrer_id": self.ref["id"], "referrer_code": self.ref["code"]},
        )
        with self.store._connect() as conn:
            conn.execute("UPDATE orders SET provisioned_profile_id = ? WHERE public_id = ?", (prof["id"], initial_order["public_id"]))

        renewal = web_checkout.create_web_renewal_order(
            sub_id="sub_test_123",
            duration_days=30,
        )

        self.assertEqual(renewal["customer_chat_id"], "13001")
        self.assertEqual(renewal["meta_json"]["referrer_id"], self.ref["id"])
        self.assertEqual(renewal["meta_json"]["referrer_code"], self.ref["code"])


class TestAdminReferralUIFormatting(unittest.TestCase):
    """Test admin referral report formatting and smart payout execution."""

    def setUp(self):
        self.store, self.tmp_dir = make_test_store()
        self.ref = self.store.ensure_referrer(user_id=14001, chat_id=14001, commission_percent=10)

    def test_format_referral_admin_report(self):
        # Accrue some funds
        self.store.attach_referral(code=self.ref["code"], referred_user_id=15001, referred_chat_id=15001)
        ord_item = self.store.create_order(
            kind="purchase",
            status="waiting_payment",
            transport="tcp",
            duration_days=30,
            profile_mode="single",
            family_label=None,
            base_price_rub=5000,
            final_price_rub=5000,
            promo_id=None,
            invite_id=None,
            customer_chat_id=15001,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version="v1",
        )
        self.store.create_referral_ledger_for_order(ord_item)

        balances = self.store.list_referral_balances()
        self.assertEqual(len(balances), 1)

        mock_bot = MagicMock()
        mock_bot._display_user = bot.ShopBot._display_user
        report = bot.ShopBot._format_referral_admin_report(mock_bot, balances)

        self.assertIn("Реферальная программа", report)
        self.assertIn("500 RUB", report)
        self.assertIn("14001", report)


class TestWebReferralBannerAndCookie(unittest.TestCase):
    """Test web handler referral cookie parsing and banner presentation in render_home."""

    def setUp(self):
        self.store, self.tmp_dir = make_test_store()
        self.ref = self.store.ensure_referrer(user_id=16001, chat_id=16001, commission_percent=10)
        self.settings = load_settings()
        self.web_checkout = WebCheckout(self.settings, self.store)

    def test_render_home_with_ref_code(self):
        content = self.web_checkout.render_home(ref_code=self.ref["code"])
        html = content.decode("utf-8") if isinstance(content, bytes) else content
        # Should render 10% discount referral banner
        self.assertIn("🎁 Реферальный бонус: вам доступна скидка 10% на первую подписку!", html)
        self.assertIn(f'value="{self.ref["code"]}"', html)

    def test_render_home_without_ref_code(self):
        content = self.web_checkout.render_home(ref_code="")
        html = content.decode("utf-8") if isinstance(content, bytes) else content
        self.assertNotIn("Реферальный бонус: вам доступна скидка 10%", html)


class TestShopBotReferralFeatures(unittest.TestCase):
    """Test ShopBot handle_public_start, payout execution, and threshold alerts."""

    def setUp(self):
        self.store, self.tmp_dir = make_test_store()
        self.ref = self.store.ensure_referrer(user_id=17001, chat_id=17001, commission_percent=10)
        import dataclasses
        self.settings = dataclasses.replace(load_settings(), admin_user_ids=(99901, 99902))
        self.bot = bot.ShopBot.__new__(bot.ShopBot)
        self.bot.store = self.store
        self.bot.settings = self.settings
        self.bot.telegram = MagicMock()
        self.bot.show_public_menu = MagicMock()
        self.bot.show_admin_referrals = MagicMock()
        self.bot._context_from_session = lambda s: dict((s or {}).get("context_json") or {})

    def test_handle_public_start_new_user(self):
        invitee_chat = 18001
        self.bot.handle_public_start(
            chat_id=invitee_chat,
            start_arg=self.ref["code"],
            user={"id": invitee_chat, "username": "alice_ref"},
        )

        # Referrer got notified
        self.bot.telegram.send_message.assert_called_once()
        call_chat, call_msg = self.bot.telegram.send_message.call_args[0]
        self.assertEqual(call_chat, self.ref["chat_id"])
        self.assertIn("@alice_ref", call_msg)
        self.assertIn("10%", call_msg)

        # Invitee got welcome message
        self.bot.show_public_menu.assert_called_once()
        invitee_msg = self.bot.show_public_menu.call_args[0][1]
        self.assertIn("10%", invitee_msg)
        self.assertIn("7 дней", invitee_msg)

        # Session context saved referral discount
        session = self.store.get_session(invitee_chat)
        ctx = (session or {}).get("context_json") or {}
        self.assertEqual(ctx.get("referral_discount"), 10)
        self.assertEqual(ctx.get("referrer_id"), self.ref["id"])

    def test_handle_public_start_already_customer(self):
        invitee_chat = 18002
        # Prior delivered order
        self.store.create_order(
            kind="purchase",
            status="delivered",
            transport="tcp",
            duration_days=30,
            profile_mode="single",
            family_label=None,
            base_price_rub=199,
            final_price_rub=199,
            promo_id=None,
            invite_id=None,
            customer_chat_id=invitee_chat,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version="v1",
        )

        self.bot.handle_public_start(
            chat_id=invitee_chat,
            start_arg=self.ref["code"],
            user={"id": invitee_chat, "username": "bob_old"},
        )

        # Referrer not notified
        self.bot.telegram.send_message.assert_not_called()
        # Invitee shown already customer notice
        self.bot.show_public_menu.assert_called_once()
        invitee_msg = self.bot.show_public_menu.call_args[0][1]
        self.assertIn("Реферальный бонус доступен только для новых пользователей", invitee_msg)

    def test_handle_public_start_self(self):
        self.bot.handle_public_start(
            chat_id=int(self.ref["chat_id"]),
            start_arg=self.ref["code"],
            user={"id": int(self.ref["user_id"]), "username": "self_ref"},
        )
        self.bot.show_public_menu.assert_called_once()
        msg = self.bot.show_public_menu.call_args[0][1]
        self.assertIn("Свою же реферальную ссылку использовать нельзя", msg)

    def test_bot_execute_referral_payout(self):
        # Accrue 1000 RUB
        self.store.attach_referral(code=self.ref["code"], referred_user_id=18003, referred_chat_id=18003)
        ord_item = self.store.create_order(
            kind="purchase",
            status="waiting_payment",
            transport="tcp",
            duration_days=30,
            profile_mode="single",
            family_label=None,
            base_price_rub=10000,
            final_price_rub=10000,
            promo_id=None,
            invite_id=None,
            customer_chat_id=18003,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version="v1",
        )
        self.store.create_referral_ledger_for_order(ord_item)

        admin_user = {"id": 99901, "username": "superadmin"}
        self.bot.execute_referral_payout(
            chat_id=99901,
            referrer_id=self.ref["id"],
            user=admin_user,
            amount_rub=400,
        )

        bal = self.store.get_referral_balance(self.ref["id"])
        self.assertEqual(bal["balance_rub"], 600)
        self.assertEqual(bal["total_paid_rub"], 400)

        # Admin notified and show_admin_referrals called
        self.bot.telegram.send_message.assert_called()
        self.bot.show_admin_referrals.assert_called_once()

    def test_bot_notify_admins_threshold(self):
        self.bot.notify_admins_referral_threshold(
            referrer_id=self.ref["id"],
            balance=650,
            user_info="@partner",
        )
        self.assertEqual(self.bot.telegram.send_message.call_count, 2)
        called_ids = [c[0][0] for c in self.bot.telegram.send_message.call_args_list]
        self.assertIn(99901, called_ids)
        self.assertIn(99902, called_ids)
        msg_text = self.bot.telegram.send_message.call_args_list[0][0][1]
        self.assertIn("650 RUB", msg_text)
        self.assertIn("@partner", msg_text)


class TestRequestHandlerCookieHandling(unittest.TestCase):
    """Test cookie parsing in RequestHandler."""

    def test_get_cookie_sc_ref(self):
        handler = RequestHandler.__new__(RequestHandler)
        handler.headers = {"Cookie": "sc_ref=ref_abcdef12; other=val"}
        self.assertEqual(handler._get_cookie("sc_ref"), "ref_abcdef12")

        handler.headers = {"Cookie": "foo=bar"}
        self.assertEqual(handler._get_cookie("sc_ref"), "")

        handler.headers = {}
        self.assertEqual(handler._get_cookie("sc_ref"), "")



if __name__ == "__main__":
    unittest.main()
