from __future__ import annotations

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

from vpn_shop.libsql_replica import (
    LibsqlCursorWrapper,
    LibsqlRow,
    LibsqlConnectionProxy,
    LibsqlReplicaManager,
)
from vpn_shop.store import Store, ORDER_TRANSITIONS


class LibsqlRowAndCursorTests(unittest.TestCase):
    def test_libsql_row_behavior(self) -> None:
        cols = ["id", "public_id", "email"]
        vals = (1, "ord_123", "user@example.com")
        row = LibsqlRow(cols, vals)

        self.assertEqual(row["public_id"], "ord_123")
        self.assertEqual(row[1], "ord_123")
        self.assertEqual(row.keys(), cols)
        self.assertEqual([row[c] for c in cols], list(vals))
        self.assertEqual(dict(zip(row.keys(), [row[c] for c in cols])), {"id": 1, "public_id": "ord_123", "email": "user@example.com"})

    def test_libsql_cursor_wrapper(self) -> None:
        raw_cur = MagicMock()
        raw_cur.description = [("col_a",), ("col_b",)]
        raw_cur.fetchone.return_value = ("val1", "val2")
        raw_cur.fetchall.return_value = [("val1", "val2"), ("val3", "val4")]
        raw_cur.rowcount = 2
        raw_cur.lastrowid = 10

        cur = LibsqlCursorWrapper(raw_cur)
        self.assertEqual(cur.rowcount, 2)
        self.assertEqual(cur.lastrowid, 10)

        one = cur.fetchone()
        self.assertIsNotNone(one)
        self.assertEqual(one["col_a"], "val1")

        all_rows = cur.fetchall()
        self.assertEqual(len(all_rows), 2)
        self.assertEqual(all_rows[1]["col_b"], "val4")


class LibsqlConnectionProxyTests(unittest.TestCase):
    def test_transaction_lifecycle_and_in_transaction(self) -> None:
        mock_mgr = MagicMock()
        mock_mgr._lock = MagicMock()
        mock_mgr._conn = MagicMock()

        proxy = LibsqlConnectionProxy(mock_mgr)
        self.assertFalse(proxy.in_transaction)

        # BEGIN acquires lock
        proxy.execute("BEGIN IMMEDIATE;")
        mock_mgr._lock.acquire.assert_called_once()
        self.assertTrue(proxy.in_transaction)

        # COMMIT releases lock
        proxy.execute("COMMIT;")
        self.assertFalse(proxy.in_transaction)
        mock_mgr._lock.release.assert_called_once()

        # Close
        proxy.close()
        self.assertTrue(proxy._closed)
        self.assertEqual(mock_mgr._lock.release.call_count, 1)

    def test_integrity_error_wrapping(self) -> None:
        mock_mgr = MagicMock()
        mock_mgr._lock = MagicMock()
        mock_mgr._conn = MagicMock()
        mock_mgr._conn.execute.side_effect = RuntimeError("UNIQUE constraint failed: orders.public_id")

        proxy = LibsqlConnectionProxy(mock_mgr)
        with self.assertRaises(sqlite3.IntegrityError):
            proxy.execute("INSERT INTO orders (public_id) VALUES ('ord_123')")
        proxy.close()

    def test_force_sync_called_on_commit_if_wrote(self) -> None:
        mock_mgr = MagicMock()
        mock_mgr._lock = MagicMock()
        mock_mgr._conn = MagicMock()

        proxy = LibsqlConnectionProxy(mock_mgr)
        proxy.execute("INSERT INTO orders (public_id) VALUES ('test')")
        self.assertTrue(proxy._wrote)

        proxy.commit()
        mock_mgr.force_sync.assert_called_once()
        self.assertFalse(proxy._wrote)
        proxy.close()

    def test_autocommit_on_close_if_wrote_and_not_in_transaction(self) -> None:
        mock_mgr = MagicMock()
        mock_mgr._lock = MagicMock()
        mock_mgr._conn = MagicMock()

        proxy = LibsqlConnectionProxy(mock_mgr)
        proxy.execute("UPDATE orders SET status = 'delivered' WHERE public_id = 'ord_1'")
        self.assertTrue(proxy._wrote)
        self.assertFalse(proxy.in_transaction)

        proxy.close()
        mock_mgr._conn.commit.assert_called_once()
        mock_mgr.force_sync.assert_called_once()
        self.assertTrue(proxy._closed)

    def test_force_sync_respects_min_interval_cooldown(self) -> None:
        mgr = object.__new__(LibsqlReplicaManager)
        mgr._sync_lock = threading.Lock()
        mgr._exec_lock = threading.RLock()
        mgr._sync_interval = 900.0
        mgr._last_sync_at = time.monotonic()
        mgr._conn = MagicMock()

        # Immediate repeat force_sync with min_interval should NOT call conn.sync()
        mgr.force_sync(min_interval=2.0)
        mgr._conn.sync.assert_not_called()

        # After cooldown passes, conn.sync() is called
        mgr._last_sync_at = time.monotonic() - 3.0
        mgr.force_sync(min_interval=2.0)
        mgr._conn.sync.assert_called_once()


class StoreReplicaReadRetryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = Path(self.tmp.name)
        self.tmp.close()

    def tearDown(self) -> None:
        self.db_path.unlink(missing_ok=True)

    def test_order_transitions_contain_pending_provision(self) -> None:
        self.assertIn("pending_provision", ORDER_TRANSITIONS["waiting_payment"])
        self.assertIn("pending_provision", ORDER_TRANSITIONS["auto_provision"])
        self.assertIn("pending_provision", ORDER_TRANSITIONS["provisioning"])
        self.assertIn("provisioning", ORDER_TRANSITIONS["pending_provision"])
        self.assertIn("delivered", ORDER_TRANSITIONS["pending_provision"])
        self.assertIn("failed", ORDER_TRANSITIONS["pending_provision"])
        self.assertIn("cancelled", ORDER_TRANSITIONS["pending_provision"])

    def test_read_after_remote_write_retry(self) -> None:
        store = Store(self.db_path)
        store.init()

        mock_replica = MagicMock()
        store._replica_mgr = mock_replica

        # get_order misses first time, then succeeds on retry after force_sync
        call_count = 0
        original_connect = store._connect

        from contextlib import contextmanager

        @contextmanager
        def mock_connect():
            nonlocal call_count
            call_count += 1
            mock_conn = MagicMock()
            mock_cur = MagicMock()
            if call_count == 1:
                mock_cur.fetchone.return_value = None
            else:
                cols = ["public_id", "status"]
                mock_cur.fetchone.return_value = LibsqlRow(cols, ("ord_sync_123", "waiting_payment"))
            mock_conn.execute.return_value = mock_cur
            yield mock_conn

        with patch.object(store, "read_connection", side_effect=mock_connect):
            order = store.get_order("ord_sync_123")
            self.assertIsNotNone(order)
            self.assertEqual(order["public_id"], "ord_sync_123")
            mock_replica.force_sync.assert_called_once()
            self.assertEqual(call_count, 2)

    def test_get_profile_read_miss_triggers_sync(self) -> None:
        store = Store(self.db_path)
        store.init()

        mock_replica = MagicMock()
        store._replica_mgr = mock_replica

        call_count = 0
        from contextlib import contextmanager

        @contextmanager
        def mock_connect():
            nonlocal call_count
            call_count += 1
            mock_conn = MagicMock()
            mock_cur = MagicMock()
            if call_count == 1:
                mock_cur.fetchone.return_value = None
            else:
                cols = ["public_id", "status", "expires_at"]
                mock_cur.fetchone.return_value = LibsqlRow(cols, ("prf_test_sync", "active", time.time() + 3600))
            mock_conn.execute.return_value = mock_cur
            yield mock_conn

        with patch.object(store, "read_connection", side_effect=mock_connect):
            prof = store.get_profile("prf_test_sync")
            self.assertIsNotNone(prof)
            self.assertEqual(prof["public_id"], "prf_test_sync")
            mock_replica.force_sync.assert_called_once()
            self.assertEqual(call_count, 2)

    def test_get_profile_expired_triggers_renewal_sync(self) -> None:
        store = Store(self.db_path)
        store.init()

        mock_replica = MagicMock()
        store._replica_mgr = mock_replica

        call_count = 0
        from contextlib import contextmanager

        @contextmanager
        def mock_connect():
            nonlocal call_count
            call_count += 1
            mock_conn = MagicMock()
            mock_cur = MagicMock()
            if call_count == 1:
                cols = ["public_id", "status", "expires_at"]
                mock_cur.fetchone.return_value = LibsqlRow(cols, ("prf_renewed", "expired", time.time() - 100))
            else:
                cols = ["public_id", "status", "expires_at"]
                mock_cur.fetchone.return_value = LibsqlRow(cols, ("prf_renewed", "active", time.time() + 86400))
            mock_conn.execute.return_value = mock_cur
            yield mock_conn

        with patch.object(store, "read_connection", side_effect=mock_connect):
            prof = store.get_profile("prf_renewed")
            self.assertIsNotNone(prof)
            self.assertEqual(prof["status"], "active")
            mock_replica.force_sync.assert_called_once()
            self.assertEqual(call_count, 2)


if __name__ == "__main__":
    unittest.main()
