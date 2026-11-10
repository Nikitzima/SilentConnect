from __future__ import annotations

import os
import pathlib
import sys
import time
import unittest
from unittest.mock import MagicMock, patch

ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent
VPN_SHOP_DIR = ROOT_DIR / "vpn-shop"
SUBJSON_DIR = ROOT_DIR / "subjson-service"
for p in (str(VPN_SHOP_DIR), str(SUBJSON_DIR), str(ROOT_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

os.environ.setdefault("HYSTERIA_SALAMANDER_PASSWORD", "test-salamander-pass")  # PLACEHOLDER
os.environ.setdefault("HYSTERIA_AUTH_PASSWORD", "test-auth-pass")  # PLACEHOLDER
os.environ.setdefault("TCP_REALITY_PUBLIC_KEY", "test-pub-key")  # PLACEHOLDER

from vpn_shop.store import Store, DatabaseQueryError
from vpn_shop import security
from vpn_shop import openflux_manager


import tempfile
from pathlib import Path

class TestAudit16Fixes(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_audit16.db"
        self.store = Store(self.db_path)
        self.store.init()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_01_awg_slots_filtering_by_profile_expiration(self):
        now = int(time.time())
        # Insert 2 profiles: 1 active, 1 expired
        with self.store.transaction() as conn:
            conn.execute(
                """
                INSERT INTO profiles (public_id, xui_inbound_id, transport, profile_mode, xui_email, xui_client_id, status, created_at, expires_at)
                VALUES ('prf_active_1', 1, 'tcp', 'anonymous', 'user1@test', 'cid1', 'active', ?, ?)
                """,
                (now, now + 3600),
            )
            conn.execute(
                """
                INSERT INTO profiles (public_id, xui_inbound_id, transport, profile_mode, xui_email, xui_client_id, status, created_at, expires_at)
                VALUES ('prf_expired_1', 1, 'tcp', 'anonymous', 'user2@test', 'cid2', 'expired', ?, ?)
                """,
                (now, now - 100),
            )
            # Both slots enabled=1
            conn.execute(
                """
                INSERT INTO awg_slots (profile_public_id, slot_index, slot_label, public_key, private_key_enc, preshared_key,
                                       client_ip, enabled, created_at, updated_at, server_code)
                VALUES ('prf_active_1', 1, 'Device 1', 'pub_act', 'priv_act', 'psk_act', '10.8.0.2', 1, ?, ?, 'nl')
                """,
                (now, now),
            )
            conn.execute(
                """
                INSERT INTO awg_slots (profile_public_id, slot_index, slot_label, public_key, private_key_enc, preshared_key,
                                       client_ip, enabled, created_at, updated_at, server_code)
                VALUES ('prf_expired_1', 1, 'Device 1', 'pub_exp', 'priv_exp', 'psk_exp', '10.8.0.3', 1, ?, ?, 'nl')
                """,
                (now, now),
            )

        # list_active_awg_slots must return ONLY prf_active_1
        active_slots = self.store.list_active_awg_slots()
        self.assertEqual(len(active_slots), 1)
        self.assertEqual(active_slots[0]["profile_public_id"], "prf_active_1")

        # Now simulate profile renewal of prf_expired_1: status -> active, expires_at -> future
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE profiles SET status = 'active', expires_at = ? WHERE public_id = 'prf_expired_1'",
                (now + 86400,),
            )

        # Both slots must now be active without any mutation to awg_slots table
        active_slots_after_renew = self.store.list_active_awg_slots()
        self.assertEqual(len(active_slots_after_renew), 2)
        pids = {s["profile_public_id"] for s in active_slots_after_renew}
        self.assertIn("prf_active_1", pids)
        self.assertIn("prf_expired_1", pids)

    def test_02_public_id_regex_and_miss_cooldown(self):
        import contextlib
        import sqlite3
        mock_replica = MagicMock()

        @contextlib.contextmanager
        def ro_mock():
            conn = sqlite3.connect(self.db_path, timeout=5.0, isolation_level=None)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
            finally:
                conn.close()

        mock_replica.ro_connection = ro_mock
        self.store._replica_mgr = mock_replica

        # 1. Invalid format does NOT trigger force_sync
        self.store.get_order("invalid_format_attack_123")
        self.assertEqual(mock_replica.force_sync.call_count, 0)

        self.store.get_profile("scanner_profile_test")
        self.assertEqual(mock_replica.force_sync.call_count, 0)

        # 2. Valid format base36 ID triggers force_sync on first miss
        valid_ord = "ord_yogm1tu2or12"
        self.store.get_order(valid_ord)
        self.assertEqual(mock_replica.force_sync.call_count, 1)

        # 3. Repeat call for the same key within cooldown does NOT trigger force_sync
        self.store.get_order(valid_ord)
        self.assertEqual(mock_replica.force_sync.call_count, 1)

        # 4. Valid profile ID triggers force_sync on first miss
        valid_prf = "prf_abc123xyz999"
        self.store.get_profile(valid_prf)
        self.assertEqual(mock_replica.force_sync.call_count, 2)

        # Repeat call for the same profile key does NOT trigger force_sync
        self.store.get_profile(valid_prf)
        self.assertEqual(mock_replica.force_sync.call_count, 2)

    def test_03_derive_sub_order_token_no_legacy_pepper(self):
        with patch.dict("os.environ", {"SERVER_PEPPER": "my-secret-production-pepper-2026"}):
            candidates = security.derive_sub_order_token_candidates("ord_123456abcdef", "sub_abc123")
            self.assertEqual(len(candidates), 1)
            primary = candidates[0]
            # Primary must not equal HMAC derived from DEFAULT_SERVER_PEPPER
            default_token = security.derive_sub_order_token("ord_123456abcdef", "sub_abc123")
            self.assertEqual(primary, default_token)


    def test_04_openflux_healing_stops_expired_containers(self):
        import sqlite3
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute(
            """
            CREATE TABLE profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                public_id TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'active',
                expires_at INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        now = int(time.time())
        conn.execute("INSERT INTO profiles (public_id, status, expires_at) VALUES ('prf_act', 'active', ?)", (now + 3600,))
        conn.execute("INSERT INTO profiles (public_id, status, expires_at) VALUES ('prf_exp', 'expired', ?)", (now - 100,))
        conn.commit()

        openflux_manager.init_openflux_db(conn)
        conn.execute(
            """
            INSERT INTO openflux_slots (profile_public_id, status, active_server, active_container_name, created_at, updated_at)
            VALUES ('prf_act', 'active', 'nl', 'openflux-worker-prf_act', ?, ?)
            """,
            (now, now),
        )
        conn.execute(
            """
            INSERT INTO openflux_slots (profile_public_id, status, active_server, active_container_name, created_at, updated_at)
            VALUES ('prf_exp', 'active', 'de', 'openflux-worker-prf_exp', ?, ?)
            """,
            (now, now),
        )
        conn.commit()

        stopped_containers = []

        def mock_stop(srv, ctr):
            stopped_containers.append((srv, ctr))
            return True

        with patch("vpn_shop.openflux_manager.stop_openflux_worker", side_effect=mock_stop), \
             patch("vpn_shop.openflux_manager.ensure_openflux_slot_healthy", return_value=True):
            healed = openflux_manager.heal_all_active_slots(conn)

        # Only prf_act should be healed
        self.assertEqual(healed, 1)
        # prf_exp container must be explicitly stopped
        self.assertIn(("de", "openflux-worker-prf_exp"), stopped_containers)

        # prf_exp slot must be uninitialized in DB
        exp_slot = conn.execute("SELECT status, active_container_name FROM openflux_slots WHERE profile_public_id = 'prf_exp'").fetchone()
        self.assertEqual(exp_slot["status"], "uninitialized")
        self.assertIsNone(exp_slot["active_container_name"])

    def test_05_slot_switch_cooldown(self):
        import app
        key = "test_slot_sw_key"
        # First call must be allowed
        self.assertTrue(app.check_slot_switch_cooldown(key, cooldown_seconds=15.0))
        # Second immediate call within 15s must be rejected
        self.assertFalse(app.check_slot_switch_cooldown(key, cooldown_seconds=15.0))

    def test_06_atomic_update_order_meta_and_external_id(self):
        order = self.store.create_order(
            kind="primary",
            status="waiting_payment",
            transport="tcp",
            duration_days=30,
            profile_mode="anonymous",
            family_label=None,
            base_price_rub=149,
            final_price_rub=149,
            promo_id=None,
            invite_id=None,
            customer_chat_id=None,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version="2.0",
        )
        pub_id = order["public_id"]
        test_meta = {"test_key": "test_val", "foo": "bar"}
        self.store.update_order_meta_and_external_id(pub_id, test_meta, "tx_atomic_123")

        ord_row = self.store.get_order(pub_id)
        self.assertIsNotNone(ord_row)
        self.assertEqual(ord_row["meta_json"], test_meta)
        self.assertEqual(ord_row["external_id"], "tx_atomic_123")

    def test_07_bind_subscription_email_blocks_overwrite_when_email_already_bound(self):
        import app
        # Test that attempting to bind a new email when already bound raises ValueError
        # We can test by mocking get_store_db returning an order with an existing email
        import sqlite3
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute("CREATE TABLE profiles (id INTEGER PRIMARY KEY, public_id TEXT, xui_email TEXT, status TEXT)")
        conn.execute("INSERT INTO profiles VALUES (1, 'prf_123', 'test@user', 'active')")
        conn.execute("CREATE TABLE orders (id INTEGER PRIMARY KEY, provisioned_profile_id INTEGER, status TEXT, customer_email TEXT, meta_json TEXT)")
        conn.execute("INSERT INTO orders VALUES (1, 1, 'delivered', 'original_owner@gmail.com', '{}')")
        conn.commit()

        with patch("app.find_subscription", return_value=({"id": 1}, None, None, None, {"email": "test@user", "inbound_id": 1})), \
             patch("app.get_store_db", return_value=conn), \
             patch("app.check_bind_email_rate_limit", return_value=True):
            with self.assertRaises(ValueError) as ctx:
                app.bind_subscription_email("sub_test_123", "attacker_new@mail.ru", client_ip="127.0.0.1")
            self.assertIn("уже привязана почта", str(ctx.exception))

    def test_08_cooldowns_work_when_monotonic_clock_near_zero(self):
        import contextlib
        import sqlite3
        import app

        mock_replica = MagicMock()

        @contextlib.contextmanager
        def ro_mock():
            conn = sqlite3.connect(self.db_path, timeout=5.0, isolation_level=None)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
            finally:
                conn.close()

        mock_replica.ro_connection = ro_mock
        self.store._replica_mgr = mock_replica

        with patch("time.monotonic", return_value=5.0):
            # First miss on newly booted OS (monotonic < 60s) must still sync
            self.store.get_order("ord_boot123456")
            self.assertEqual(mock_replica.force_sync.call_count, 1)
            # Immediate repeat within cooldown must not sync again
            self.store.get_order("ord_boot123456")
            self.assertEqual(mock_replica.force_sync.call_count, 1)

            self.store.get_profile("prf_boot123456")
            self.assertEqual(mock_replica.force_sync.call_count, 2)
            self.store.get_profile("prf_boot123456")
            self.assertEqual(mock_replica.force_sync.call_count, 2)

            self.store.get_profile_by_xui_email("boot_test@example.com")
            self.assertEqual(mock_replica.force_sync.call_count, 3)
            self.store.get_profile_by_xui_email("boot_test@example.com")
            self.assertEqual(mock_replica.force_sync.call_count, 3)

            # Slot switch cooldown under low uptime (monotonic < 15s) must allow first call
            self.assertTrue(app.check_slot_switch_cooldown("boot_slot_key", cooldown_seconds=15.0))
            self.assertFalse(app.check_slot_switch_cooldown("boot_slot_key", cooldown_seconds=15.0))

    def test_09_expire_past_due_profiles_handles_stale_ro_and_idle_active(self):
        import contextlib
        import sqlite3

        now = int(time.time())
        p1 = self.store.create_profile(
            xui_inbound_id=1,
            transport="tcp",
            profile_mode="personal",
            family_label=None,
            xui_email="p1@example.com",
            xui_client_id="11111111-1111-1111-1111-111111111111",
            xui_sub_id="sub_p1_exp",
            expires_at=now + 86400,
        )
        p2 = self.store.create_profile(
            xui_inbound_id=1,
            transport="tcp",
            profile_mode="personal",
            family_label=None,
            xui_email="p2@example.com",
            xui_client_id="22222222-2222-2222-2222-222222222222",
            xui_sub_id="sub_p2_exp",
            expires_at=now + 86400,
        )

        # Case A: Active non-expired -> no write transaction opened at all
        with patch.object(self.store, "transaction", wraps=self.store.transaction) as tx_spy:
            self.assertEqual(self.store.expire_past_due_profiles(now=now), [])
            self.assertEqual(tx_spy.call_count, 0)

        # Separate stale RO sqlite DB to simulate Turso RO lag
        ro_db_path = Path(self.temp_dir.name) / "ro_stale.db"
        ro_src = sqlite3.connect(self.db_path)
        ro_dst = sqlite3.connect(ro_db_path)
        ro_src.backup(ro_dst)
        ro_src.close()
        ro_dst.close()

        @contextlib.contextmanager
        def stale_ro_conn():
            conn = sqlite3.connect(ro_db_path)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
            finally:
                conn.close()

        # Case B: Stale RO sees P1 as expired, while primary already renewed P1
        ro_conn_mut = sqlite3.connect(ro_db_path)
        ro_conn_mut.execute("UPDATE profiles SET expires_at = ? WHERE public_id = ?", (now - 100, p1["public_id"]))
        ro_conn_mut.commit()
        ro_conn_mut.close()

        with patch.object(self.store, "read_connection", side_effect=stale_ro_conn):
            expired_res = self.store.expire_past_due_profiles(now=now)
        self.assertEqual(expired_res, [])
        self.assertEqual(self.store.get_profile(p1["public_id"])["status"], "active")

        # Case C: Primary expires BOTH P1 and P2, while RO only sees P1 due -> primary RETURNING updates & returns BOTH
        with self.store.transaction() as wconn:
            wconn.execute("UPDATE profiles SET expires_at = ? WHERE public_id IN (?, ?)", (now - 50, p1["public_id"], p2["public_id"]))
        with patch.object(self.store, "read_connection", side_effect=stale_ro_conn):
            expired_both = self.store.expire_past_due_profiles(now=now)
        returned_pids = {row["public_id"] for row in expired_both}
        self.assertEqual(returned_pids, {p1["public_id"], p2["public_id"]})
        self.assertEqual(self.store.get_profile(p1["public_id"])["status"], "expired")
        self.assertEqual(self.store.get_profile(p2["public_id"])["status"], "expired")

    def test_10_consume_magic_link_authoritative_bypasses_stale_ro(self):
        import contextlib
        import sqlite3

        # Snapshot DB BEFORE minting magic link to simulate lagging RO replica
        stale_ro_path = Path(self.temp_dir.name) / "ro_before_magic.db"
        src = sqlite3.connect(self.db_path)
        dst = sqlite3.connect(stale_ro_path)
        src.backup(dst)
        src.close()
        dst.close()

        raw_token = "magic-lag-token-xyz-123456"
        self.store.create_magic_link(email="cabinet-user@example.com", token=raw_token, ttl_seconds=900, request_ip="203.0.113.5")

        @contextlib.contextmanager
        def lagging_ro():
            conn = sqlite3.connect(stale_ro_path)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
            finally:
                conn.close()

        mock_mgr = MagicMock()

        def open_primary():
            conn = sqlite3.connect(self.db_path, timeout=5.0, isolation_level=None)
            conn.row_factory = sqlite3.Row
            return conn

        mock_mgr.connect.side_effect = open_primary
        mock_mgr.ro_connection = lagging_ro
        self.store._replica_mgr = mock_mgr
        # Default read path sees stale RO and misses link
        self.assertIsNone(self.store.consume_magic_link(raw_token, single_use=False))
        # Authoritative path bypasses stale RO and reads primary DB directly
        email = self.store.consume_magic_link(raw_token, single_use=False, authoritative=True)
        self.assertEqual(email, "cabinet-user@example.com")

    def test_11_update_order_meta_and_external_id_strips_web_token(self):
        order = self.store.create_order(
            kind="primary",
            status="waiting_payment",
            transport="tcp",
            duration_days=30,
            profile_mode="anonymous",
            family_label=None,
            base_price_rub=149,
            final_price_rub=149,
            promo_id=None,
            invite_id=None,
            customer_chat_id=None,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version="2.0",
        )
        pub_id = order["public_id"]
        self.store.update_order_meta_and_external_id(
            pub_id,
            {"payment_provider": "yoomoney", "web_token": "secret-plaintext-token"},
            "ext_stripped_1",
        )
        stored = self.store.get_order(pub_id)
        self.assertIsNotNone(stored)
        self.assertEqual(stored["external_id"], "ext_stripped_1")
        self.assertEqual(stored["meta_json"], {"payment_provider": "yoomoney"})
        self.assertNotIn("web_token", stored["meta_json"])

    def test_12_miss_sync_global_rate_limit_and_lru_eviction(self):
        import contextlib
        import sqlite3

        mock_mgr = MagicMock()

        @contextlib.contextmanager
        def ro_mock():
            conn = sqlite3.connect(self.db_path, timeout=5.0, isolation_level=None)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
            finally:
                conn.close()

        mock_mgr.ro_connection = ro_mock
        self.store._replica_mgr = mock_mgr

        with patch("time.monotonic", return_value=100.0):
            # Repeat same ID within 60s -> only 1 sync
            for _ in range(5):
                self.store.get_order("ord_same_cooldown")
            self.assertEqual(mock_mgr.force_sync.call_count, 1)

            # Storm of 30 distinct missing IDs -> capped globally at 20 syncs per 60s
            mock_mgr.force_sync.reset_mock()
            for idx in range(30):
                self.store.get_order(f"ord_storm_{idx}")
            self.assertEqual(mock_mgr.force_sync.call_count, 19)  # 1 prior + 19 = 20 total in window

        # Window expires (+61s) -> sync allowed again
        with patch("time.monotonic", return_value=161.5):
            mock_mgr.force_sync.reset_mock()
            self.store.get_order("ord_after_window")
            self.assertEqual(mock_mgr.force_sync.call_count, 1)


if __name__ == "__main__":
    unittest.main()
