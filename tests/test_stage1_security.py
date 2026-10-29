from __future__ import annotations

import os
import queue
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent
VPN_SHOP_DIR = REPO_ROOT / "vpn-shop"
if str(VPN_SHOP_DIR) not in sys.path:
    sys.path.insert(0, str(VPN_SHOP_DIR))

from vpn_shop import security
from vpn_shop.config import Settings, load_settings
from vpn_shop.libsql_replica import LibsqlReplicaManager
from vpn_shop.store import Store


class TestSecurityHardening(unittest.TestCase):
    def test_safe_json_for_script(self) -> None:
        payload = {"xss": "<script>alert('xss' & 'more')</script>"}
        encoded = security.safe_json_for_script(payload)
        self.assertNotIn("<", encoded)
        self.assertNotIn(">", encoded)
        self.assertNotIn("&", encoded)
        self.assertNotIn("'", encoded)
        self.assertIn("\\u003cscript\\u003e", encoded)
        self.assertIn("\\u0026", encoded)
        self.assertIn("\\u0027", encoded)

    def test_is_valid_email(self) -> None:
        self.assertTrue(security.is_valid_email("user@example.com"))
        self.assertTrue(security.is_valid_email("first.last+tag@sub.domain.co"))
        self.assertFalse(security.is_valid_email(""))
        self.assertFalse(security.is_valid_email(None))
        self.assertFalse(security.is_valid_email("notanemail"))
        self.assertFalse(security.is_valid_email("@example.com"))
        self.assertFalse(security.is_valid_email("user@"))
        self.assertFalse(security.is_valid_email("user@.com"))
        self.assertFalse(security.is_valid_email("user@example"))
        self.assertFalse(security.is_valid_email("user@toolong" + "a" * 200 + ".com"))

    def test_client_ip_from_headers_untrusted_peer(self) -> None:
        # Untrusted peer cannot spoof any headers
        headers = {"CF-Connecting-IP": "198.51.100.1", "X-Forwarded-For": "198.51.100.2"}
        ip = security.client_ip_from_headers(headers, "203.0.113.50")
        self.assertEqual(ip, "203.0.113.50")

    def test_client_ip_from_headers_cf_connecting_ip_requires_trust_cf(self) -> None:
        headers = {"CF-Connecting-IP": "198.51.100.1", "X-Forwarded-For": "198.51.100.2, 127.0.0.1"}
        with patch.dict(os.environ, {"TRUST_CF_HEADERS": "0"}):
            # Without TRUST_CF_HEADERS, CF-Connecting-IP is ignored; XFF is walked
            ip = security.client_ip_from_headers(headers, "127.0.0.1")
            self.assertEqual(ip, "198.51.100.2")

        with patch.dict(os.environ, {"TRUST_CF_HEADERS": "1"}):
            # With TRUST_CF_HEADERS=1 and trusted peer, CF-Connecting-IP is used
            ip = security.client_ip_from_headers(headers, "127.0.0.1")
            self.assertEqual(ip, "198.51.100.1")

    def test_client_ip_from_headers_walks_xff_right_to_left(self) -> None:
        with patch.dict(os.environ, {"TRUST_CF_HEADERS": "0", "TRUSTED_PROXY_CIDRS": "127.0.0.0/8,10.0.0.0/8"}):
            # Spoofed IP, Real Client IP, Trusted Intermediate Proxy
            headers = {"X-Forwarded-For": "192.0.2.4, 203.0.113.99, 10.0.0.1"}
            ip = security.client_ip_from_headers(headers, "127.0.0.1")
            self.assertEqual(ip, "203.0.113.99")

    def test_wireguard_key_encryption_and_decryption(self) -> None:
        raw_key = "dGVzdC1wcml2YXRlLWtleS13aXJlZ3VhcmQ="
        enc = security.encrypt_wg_secret(raw_key)
        self.assertTrue(enc.startswith(security.ENC_PREFIX))
        dec = security.decrypt_wg_secret(enc)
        self.assertEqual(dec, raw_key)

        # Backwards compatibility: plaintext without prefix returns as-is
        self.assertEqual(security.decrypt_wg_secret(raw_key), raw_key)
        self.assertEqual(security.encrypt_wg_secret(""), "")
        self.assertEqual(security.decrypt_wg_secret(""), "")


class TestConfigDefaultsAndSeparation(unittest.TestCase):
    def test_config_xui_defaults_and_secret_separation(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            settings = load_settings(REPO_ROOT / "vpn-shop")
            self.assertEqual(settings.xui_username, "")
            self.assertEqual(settings.xui_password, "")
            self.assertEqual(settings.cluster_sync_secret, "")
            self.assertEqual(settings.serverless_bridge_secret, "")
            self.assertEqual(settings.server_pepper, "")

    def test_config_clean_secret_separation(self) -> None:
        with patch.dict(
            os.environ,
            {
                "CLUSTER_SYNC_SECRET": "cluster-secret-123",
                "SERVERLESS_BRIDGE_SECRET": "bridge-secret-456",
                "SERVER_PEPPER": "pepper-789",
            },
            clear=True,
        ):
            settings = load_settings(REPO_ROOT / "vpn-shop")
            self.assertEqual(settings.cluster_sync_secret, "cluster-secret-123")
            self.assertEqual(settings.serverless_bridge_secret, "bridge-secret-456")
            self.assertEqual(settings.server_pepper, "pepper-789")


class TestLibsqlReplicaPool(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = Path(self.tmp.name)
        self.tmp.close()
        # Create a sample table in the sqlite db
        conn = sqlite3.connect(self.db_path)
        conn.execute("CREATE TABLE test_tab (id INTEGER PRIMARY KEY, val TEXT);")
        conn.execute("INSERT INTO test_tab (val) VALUES ('hello');")
        conn.commit()
        conn.close()

    def tearDown(self) -> None:
        self.db_path.unlink(missing_ok=True)

    def test_ro_connection_pool_and_eviction_on_error(self) -> None:
        mgr = object.__new__(LibsqlReplicaManager)
        import queue
        mgr._path = str(self.db_path)
        mgr._ro_local = threading.local() if hasattr(threading, "local") else None
        mgr._ro_pool = queue.LifoQueue(maxsize=32)

        # 1. Borrow connection and return it
        with mgr.ro_connection() as conn:
            self.assertIsNotNone(conn)
            cur = conn.execute("SELECT val FROM test_tab WHERE id = 1;")
            self.assertEqual(cur.fetchone()[0], "hello")

        # Connection should have been returned to pool
        self.assertEqual(mgr._ro_pool.qsize(), 1)
        cached_conn = mgr._ro_pool.queue[0]

        # 2. Reuse pooled connection
        with mgr.ro_connection() as conn2:
            self.assertIs(conn2, cached_conn)

        # 3. If an error occurs inside context, connection is closed and evicted
        with self.assertRaises(ValueError):
            with mgr.ro_connection() as conn3:
                raise ValueError("Simulated handler crash")

        # Pool should now be empty because crashed connection was closed & evicted
        self.assertEqual(mgr._ro_pool.qsize(), 0)


class TestStoreHardening(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = Path(self.tmp.name)
        self.tmp.close()
        self.store = Store(self.db_path)
        self.store.init()

    def tearDown(self) -> None:
        self.db_path.unlink(missing_ok=True)

    def test_index_open_orders_promo_replaces_unique(self) -> None:
        with self.store.connection() as conn:
            indices = {
                row["name"]: row["sql"]
                for row in conn.execute("SELECT name, sql FROM sqlite_master WHERE type='index'").fetchall()
            }
            self.assertNotIn("uq_open_orders_promo", indices)
            self.assertIn("ix_open_orders_promo", indices)

    def test_get_open_order_for_promo_unlimited_and_limited(self) -> None:
        # Create unlimited promo (max_uses = 0)
        code_unlim, promo_unlim = self.store.create_promo_code(
            transport="xhttp",
            duration_days=30,
            discount_percent=10,
            profile_mode="trial",
            max_uses=0,
        )
        # Create an open order for promo_unlim
        with self.store.transaction() as conn:
            conn.execute(
                """
                INSERT INTO orders (
                    public_id, promo_id, status, created_at, updated_at,
                    transport, duration_days, profile_mode, base_price_rub, final_price_rub, terms_version, kind
                )
                VALUES ('ord_unlim_1', ?, 'waiting_payment', 1000, 1000, 'xhttp', 30, 'trial', 100, 90, 'v1', 'new')
                """,
                (promo_unlim["id"],),
            )

        # For unlimited promo, get_open_order_for_promo must return None
        self.assertIsNone(self.store.get_open_order_for_promo(promo_unlim["id"]))

        # Create limited promo (max_uses = 2)
        code_lim, promo_lim = self.store.create_promo_code(
            transport="xhttp",
            duration_days=30,
            discount_percent=20,
            profile_mode="trial",
            max_uses=2,
        )
        # Order 1: open count = 1, used = 0 (< 2). Should not block!
        with self.store.transaction() as conn:
            conn.execute(
                """
                INSERT INTO orders (
                    public_id, promo_id, status, created_at, updated_at,
                    transport, duration_days, profile_mode, base_price_rub, final_price_rub, terms_version, kind
                )
                VALUES ('ord_lim_1', ?, 'waiting_payment', 1000, 1000, 'xhttp', 30, 'trial', 100, 80, 'v1', 'new')
                """,
                (promo_lim["id"],),
            )
        self.assertIsNone(self.store.get_open_order_for_promo(promo_lim["id"]))

        # Order 2: open count = 2, used = 0 (2 + 0 >= 2). Should block!
        with self.store.transaction() as conn:
            conn.execute(
                """
                INSERT INTO orders (
                    public_id, promo_id, status, created_at, updated_at,
                    transport, duration_days, profile_mode, base_price_rub, final_price_rub, terms_version, kind
                )
                VALUES ('ord_lim_2', ?, 'waiting_payment', 1005, 1005, 'xhttp', 30, 'trial', 100, 80, 'v1', 'new')
                """,
                (promo_lim["id"],),
            )
        blocking_order = self.store.get_open_order_for_promo(promo_lim["id"])
        self.assertIsNotNone(blocking_order)
        self.assertEqual(blocking_order["public_id"], "ord_lim_1")

    def test_get_active_profiles_by_customer_email_requires_delivered(self) -> None:
        email = "customer@example.com"
        # 1. Create a profile
        with self.store.transaction() as conn:
            cur = conn.execute(
                """
                INSERT INTO profiles (
                    public_id, xui_inbound_id, transport, profile_mode, xui_email,
                    xui_client_id, status, created_at, expires_at
                ) VALUES (
                    'prf_sec_test', 1, 'xhttp', 'trial', 'sec_test_email',
                    'client-uuid-1', 'active', 1000, 9999999
                )
                """
            )
            prof_id = cur.lastrowid

            # Order not delivered yet ('waiting_payment')
            conn.execute(
                """
                INSERT INTO orders (
                    public_id, customer_email, provisioned_profile_id, status, created_at, updated_at,
                    transport, duration_days, profile_mode, base_price_rub, final_price_rub, terms_version, kind
                ) VALUES (
                    'ord_undelivered', ?, ?, 'waiting_payment', 1000, 1000, 'xhttp', 30, 'trial', 100, 100, 'v1', 'new'
                )
                """,
                (email, prof_id),
            )

        # Must not be returned while order is undelivered
        profiles = self.store.get_active_profiles_by_customer_email(email)
        self.assertEqual(len(profiles), 0)

        # Update order to 'delivered'
        with self.store.transaction() as conn:
            conn.execute("UPDATE orders SET status = 'delivered' WHERE public_id = 'ord_undelivered'")

        # Now it must be returned
        profiles = self.store.get_active_profiles_by_customer_email(email)
        self.assertEqual(len(profiles), 1)
        self.assertEqual(profiles[0]["public_id"], "prf_sec_test")

    def test_wireguard_keys_stored_encrypted_and_retrieved_decrypted(self) -> None:
        raw_privkey = "4L+privateKeyTestWireGuardKeySecretValue=="
        raw_psk = "8P+presharedKeyTestWireGuardKeySecretValue=="

        # Create profile first
        with self.store.transaction() as conn:
            conn.execute(
                """
                INSERT INTO profiles (
                    public_id, xui_inbound_id, transport, profile_mode, xui_email,
                    xui_client_id, status, created_at, expires_at
                ) VALUES (
                    'prf_awg_enc', 1, 'xhttp', 'paid', 'awg_enc_email',
                    'client-uuid-2', 'active', 1000, 9999999
                )
                """
            )

        slot = self.store.create_awg_slot(
            profile_public_id="prf_awg_enc",
            slot_index=1,
            slot_label="My Phone",
            public_key="pubKey123==",
            private_key_enc=raw_privkey,
            preshared_key=raw_psk,
            client_ip="10.8.1.55",
            server_code="nl",
        )

        # Returned slot has transparently decrypted keys
        self.assertEqual(slot["private_key_enc"], raw_privkey)
        self.assertEqual(slot["preshared_key"], raw_psk)

        # But in raw SQLite, the values are stored encrypted!
        with self.store.connection() as conn:
            raw_row = conn.execute("SELECT private_key_enc, preshared_key FROM awg_slots WHERE id = ?", (slot["id"],)).fetchone()
            self.assertTrue(raw_row["private_key_enc"].startswith("enc:v1:"))
            self.assertTrue(raw_row["preshared_key"].startswith("enc:v1:"))
            self.assertNotEqual(raw_row["private_key_enc"], raw_privkey)

        # Fetching via get_awg_slot also transparently decrypts
        fetched = self.store.get_awg_slot(slot["id"])
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["private_key_enc"], raw_privkey)
        self.assertEqual(fetched["preshared_key"], raw_psk)


if __name__ == "__main__":
    unittest.main()
