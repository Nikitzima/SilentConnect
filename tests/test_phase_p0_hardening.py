import hmac
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure paths are importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "vpn-shop"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "subjson-service"))

from vpn_shop.security import hash_secret, masked_code, now_ts
from vpn_shop.store import Store
from vpn_shop.config import Settings
from vpn_shop.provisioning import Provisioner


class TestPhaseP0Hardening(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_vpn_shop.db"
        self.store = Store(self.db_path)
        self.store.init()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_hash_secret_hmac_pepper(self):
        val = "test-secret-value-123"
        h1 = hash_secret(val)
        self.assertEqual(len(h1), 64)
        # Same value with same pepper should produce same hash
        self.assertEqual(h1, hash_secret(val))

        # Different pepper should produce different hash
        with patch.dict(os.environ, {"SERVER_PEPPER": "custom-pepper-key-xyz"}):
            h2 = hash_secret(val)
            self.assertNotEqual(h1, h2)

    def test_masked_code_entropy_reduction(self):
        self.assertEqual(masked_code("INV-ABCD-1234-EFGH"), "INV-...")
        self.assertEqual(masked_code("PROMO-5678-WXYZ"), "PROMO-...")
        self.assertEqual(masked_code("TEST-CODE"), "TEST-...")
        self.assertEqual(masked_code("SIMPLE"), "SIM...")
        self.assertEqual(masked_code(""), "")
        self.assertEqual(masked_code("AB"), "A...")

    def test_atomic_invite_consumption(self):
        code, invite = self.store.create_invite(max_uses=1)
        invite_id = invite["id"]

        # find_valid_invite should see it before consumption
        self.assertIsNotNone(self.store.find_valid_invite(code))

        # First consumption by ID should succeed
        c1 = self.store.consume_invite(invite_id)
        self.assertIsNotNone(c1)
        self.assertEqual(c1["used_count"], 1)

        # Second consumption should return None (already at max_uses)
        c2 = self.store.consume_invite(invite_id)
        self.assertIsNone(c2)

        # find_valid_invite should return None now
        self.assertIsNone(self.store.find_valid_invite(code))

    def test_atomic_invite_consumption_by_code(self):
        code, invite = self.store.create_invite(max_uses=2)

        # Consume by code string
        c1 = self.store.consume_invite(code)
        self.assertIsNotNone(c1)
        self.assertEqual(c1["used_count"], 1)

        c2 = self.store.consume_invite(code)
        self.assertIsNotNone(c2)
        self.assertEqual(c2["used_count"], 2)

        c3 = self.store.consume_invite(code)
        self.assertIsNone(c3)

    def test_atomic_invite_expired_rejection(self):
        past_ts = now_ts() - 100
        code, invite = self.store.create_invite(max_uses=1, expires_at=past_ts)
        self.assertIsNone(self.store.find_valid_invite(code))
        self.assertIsNone(self.store.consume_invite(invite["id"]))

    def test_atomic_promo_consumption(self):
        code, promo = self.store.create_promo_code(
            promo_type="discount",
            transport="tcp",
            duration_days=30,
            discount_percent=20,
            profile_mode="anonymous",
            max_uses=1,
        )
        promo_id = promo["id"]

        self.assertIsNotNone(self.store.find_valid_promo(code))
        self.assertIsNotNone(self.store.get_valid_promo_by_id(promo_id))

        # First consumption by ID
        c1 = self.store.consume_promo_code(promo_id)
        self.assertIsNotNone(c1)
        self.assertEqual(c1["used_count"], 1)
        self.assertIsNotNone(c1["last_used_at"])

        # Second consumption should fail
        c2 = self.store.consume_promo_code(promo_id)
        self.assertIsNone(c2)

        self.assertIsNone(self.store.find_valid_promo(code))
        self.assertIsNone(self.store.get_valid_promo_by_id(promo_id))

    def test_atomic_promo_consumption_by_code(self):
        code, promo = self.store.create_promo_code(
            promo_type="fixed",
            transport="xhttp",
            duration_days=30,
            discount_percent=100,
            profile_mode="anonymous",
            max_uses=1,
        )

        c1 = self.store.consume_promo_code(code)
        self.assertIsNotNone(c1)
        self.assertEqual(c1["used_count"], 1)

        c2 = self.store.consume_promo_code(code)
        self.assertIsNone(c2)

    def test_provisioner_sqlite_fallback_logging(self):
        settings = MagicMock()
        settings.xui_db_path = Path(self.temp_dir.name) / "invalid_nonexistent_dir" / "x-ui.db"
        settings.xui_panel_url = "http://127.0.0.1:2053"
        settings.xui_username = "admin"
        settings.xui_password = "password"
        settings.xui_verify_tls = False
        settings.subscription_base_url = "https://sub.example.com"
        settings.default_device_limit = 3
        settings.xui_tcp_inbound_id = 1
        settings.xui_xhttp_inbound_id = 2

        provisioner = Provisioner(settings, self.store)
        provisioner.xui_api = MagicMock()
        provisioner.xui_api.get_inbound.return_value = {
            "id": 1,
            "remark": "test-inbound",
            "protocol": "vless",
            "port": 443,
            "settings": "{}",
        }
        provisioner.xui_api.add_client.return_value = None
        provisioner.xui_db.find_client_by_email = MagicMock(return_value=None)

        with self.assertLogs("vpn_shop.provisioning", level="ERROR") as log_cm:
            res = provisioner._provision_profile(
                transport="tcp",
                duration_days=30,
                profile_mode="anonymous",
                family_label=None,
            )
            self.assertIsNotNone(res["profile"])
            self.assertTrue(any("Direct SQLite fallback failed for inbound" in msg for msg in log_cm.output))


if __name__ == "__main__":
    unittest.main()
