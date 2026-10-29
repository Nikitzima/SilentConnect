import hmac
import hashlib
import os
import tempfile
import unittest
from pathlib import Path

import sys
from pathlib import Path

vpn_shop_path = Path(__file__).resolve().parent.parent / "vpn-shop"
if str(vpn_shop_path) not in sys.path:
    sys.path.insert(0, str(vpn_shop_path))

subjson_path = Path(__file__).resolve().parent.parent / "subjson-service"
if str(subjson_path) not in sys.path:
    sys.path.insert(0, str(subjson_path))

import os

os.environ.setdefault("HYSTERIA_SALAMANDER_PASSWORD", "test_pw")
os.environ.setdefault("HYSTERIA_AUTH_PASSWORD", "test_pw")
os.environ.setdefault("SERVER_PEPPER", "test_pepper")

from vpn_shop import security
from vpn_shop.store import Store
import app as subjson_app


class TestDualPepperCompatibility(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_vpn_shop.db"
        self.store = Store(self.db_path)
        self.store.init()

        # Save original SERVER_PEPPER
        self._orig_pepper = os.environ.get("SERVER_PEPPER")

    def tearDown(self) -> None:
        if self._orig_pepper is not None:
            os.environ["SERVER_PEPPER"] = self._orig_pepper
        else:
            os.environ.pop("SERVER_PEPPER", None)
        self.temp_dir.cleanup()

    def test_01_candidates_generation(self) -> None:
        """When SERVER_PEPPER is set to a new value, candidates returns (new, legacy)."""
        new_pepper = "new-random-super-secret-pepper-32-bytes"
        os.environ["SERVER_PEPPER"] = new_pepper

        sec_cands = security.hash_secret_candidates("TESTCODE")
        self.assertEqual(len(sec_cands), 2)
        # Primary is hashed with new pepper
        expected_primary = hmac.new(new_pepper.encode("utf-8"), b"TESTCODE", hashlib.sha256).hexdigest()
        self.assertEqual(sec_cands[0], expected_primary)
        # Legacy is hashed with DEFAULT_SERVER_PEPPER
        expected_legacy = hmac.new(security.DEFAULT_SERVER_PEPPER.encode("utf-8"), b"TESTCODE", hashlib.sha256).hexdigest()
        self.assertEqual(sec_cands[1], expected_legacy)

        tok_cands = security.hash_token_candidates("my_token", purpose="order_web")
        self.assertEqual(len(tok_cands), 2)
        expected_tok_primary = hmac.new(new_pepper.encode("utf-8"), b"order_web\x00my_token", hashlib.sha256).hexdigest()
        self.assertEqual(tok_cands[0], expected_tok_primary)
        expected_tok_legacy = hmac.new(security.DEFAULT_SERVER_PEPPER.encode("utf-8"), b"order_web\x00my_token", hashlib.sha256).hexdigest()
        self.assertEqual(tok_cands[1], expected_tok_legacy)

    def test_02_promo_dual_pepper_resolution(self) -> None:
        """A promo code created under the legacy default pepper is resolved and consumed under a new pepper."""
        # 1. Create a promo code directly in DB using legacy hash (simulating pre-existing DB promo)
        promo_code = "LEGACYPROMO10"
        legacy_hash = hmac.new(security.DEFAULT_SERVER_PEPPER.encode("utf-8"), promo_code.encode("utf-8"), hashlib.sha256).hexdigest()
        now = security.now_ts()

        with self.store._connect() as conn:
            conn.execute(
                """
                INSERT INTO promo_codes(
                    code_hash, code_preview, promo_type, transport, duration_days,
                    discount_percent, device_limit, profile_mode, max_uses, expires_at, created_at
                ) VALUES (?, ?, 'discount', 'tcp', 30, 10, 3, 'individual', 5, ?, ?)
                """,
                (legacy_hash, "LEGACY***", now + 86400, now),
            )

        # 2. Switch environment to new pepper
        os.environ["SERVER_PEPPER"] = "brand-new-rotated-pepper-2026"

        # 3. Find valid promo must succeed
        found = self.store.find_valid_promo(promo_code)
        self.assertIsNotNone(found)
        self.assertEqual(found["code_preview"], "LEGACY***")
        self.assertEqual(found["discount_percent"], 10)

        # 4. Consume promo code must succeed
        consumed = self.store.consume_promo_code(promo_code)
        self.assertIsNotNone(consumed)
        self.assertEqual(consumed["used_count"], 1)

    def test_03_order_web_token_dual_pepper_resolution(self) -> None:
        """An order with web_token_hash created under legacy pepper is resolved under a new pepper."""
        # 1. Create order
        token = "secret_web_token_12345"
        legacy_hash = hmac.new(security.DEFAULT_SERVER_PEPPER.encode("utf-8"), f"order_web\x00{token}".encode("utf-8"), hashlib.sha256).hexdigest()

        order = self.store.create_order(
            kind="purchase",
            status="waiting_payment",
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
            terms_version="v1",
            customer_email="user@example.com",
        )
        ord_id = order["public_id"]

        with self.store._connect() as conn:
            conn.execute(
                "UPDATE orders SET web_token_hash = ? WHERE public_id = ?",
                (legacy_hash, ord_id),
            )

        # 2. Switch environment to new pepper
        os.environ["SERVER_PEPPER"] = "brand-new-rotated-pepper-2026"

        # 3. Verify Store.get_order_by_web_token works
        resolved_order = self.store.get_order_by_web_token(ord_id, token)
        self.assertIsNotNone(resolved_order)
        self.assertEqual(resolved_order["public_id"], ord_id)

        # 4. Verify subjson _verify_order_web_token works
        reloaded_order = self.store.get_order(ord_id)
        verified = subjson_app._verify_order_web_token(reloaded_order, token)
        self.assertTrue(verified)

        # Invalid token must fail
        self.assertFalse(subjson_app._verify_order_web_token(reloaded_order, "wrong_token"))


if __name__ == "__main__":
    unittest.main()
