import os
import sys
import sqlite3
import time
import unittest
from unittest.mock import patch

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

VPN_SHOP_DIR = os.path.join(PROJECT_ROOT, "vpn-shop")
if VPN_SHOP_DIR not in sys.path:
    sys.path.insert(0, VPN_SHOP_DIR)

from vpn_shop.openflux_manager import (
    activate_openflux_slot,
    build_openflux_stream_link,
    cancel_server_switch,
    choose_least_loaded_server,
    cleanup_expired_migrations,
    confirm_server_switch,
    get_or_create_openflux_slot,
    init_openflux_db,
    start_server_switch,
)


class TestOpenFluxManager(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("CREATE TABLE profiles (public_id TEXT PRIMARY KEY);")
        self.conn.execute("INSERT INTO profiles (public_id) VALUES ('test_user_123');")
        self.conn.commit()
        init_openflux_db(self.conn)

    def tearDown(self):
        self.conn.close()

    def test_initial_state_uninitialized(self):
        slot = get_or_create_openflux_slot(self.conn, "test_user_123")
        self.assertEqual(slot["status"], "uninitialized")
        self.assertIsNone(slot["active_server"])
        self.assertIsNone(slot["active_doc_url"])
        self.assertIsNone(slot["active_container_name"])

    def test_build_openflux_stream_link(self):
        url = "https://cloud.mail.ru/public/TEST/Doc123"
        link = build_openflux_stream_link(url, "nl")
        self.assertTrue(link.startswith("openflux://v1/"))

    def test_smart_balancer_picks_least_loaded(self):
        # Insert 2 active on NL, 1 active on PL, 0 on FI
        self.conn.execute(
            """
            INSERT INTO openflux_slots (profile_public_id, status, active_server, created_at, updated_at)
            VALUES ('u1', 'active', 'nl', 1, 1),
                   ('u2', 'active', 'nl', 1, 1),
                   ('u3', 'active', 'pl', 1, 1);
            """
        )
        self.conn.commit()

        srv = choose_least_loaded_server(self.conn)
        self.assertEqual(srv, "fi")

    @patch("vpn_shop.openflux_manager.rclone_create_user_doc", return_value=True)
    @patch("vpn_shop.openflux_manager.rclone_get_public_link", return_value="https://cloud.mail.ru/public/NL/Doc")
    @patch("vpn_shop.openflux_manager.start_openflux_worker", return_value=True)
    def test_activate_slot(self, mock_worker, mock_link, mock_create):
        slot = activate_openflux_slot(self.conn, "test_user_123")
        self.assertEqual(slot["status"], "active")
        self.assertEqual(slot["active_server"], "nl")
        self.assertEqual(slot["active_doc_url"], "https://cloud.mail.ru/public/NL/Doc")
        self.assertEqual(slot["active_container_name"], "openflux-worker-test_user_123")
        mock_create.assert_called_once()
        mock_worker.assert_called_once_with("nl", "openflux-worker-test_user_123", "https://cloud.mail.ru/public/NL/Doc")

    @patch("vpn_shop.openflux_manager.rclone_create_user_doc", return_value=True)
    @patch("vpn_shop.openflux_manager.rclone_get_public_link", return_value="https://cloud.mail.ru/public/NL/Doc")
    @patch("vpn_shop.openflux_manager.start_openflux_worker", return_value=True)
    @patch("vpn_shop.openflux_manager.stop_openflux_worker", return_value=True)
    @patch("vpn_shop.openflux_manager.rclone_delete_user_doc", return_value=True)
    def test_two_phase_handover_success(self, mock_del, mock_stop, mock_start, mock_link, mock_create):
        # 1. Activate on NL
        activate_openflux_slot(self.conn, "test_user_123")

        # 2. Phase 1: Switch to PL
        mock_link.return_value = "https://cloud.mail.ru/public/PL/Doc"
        slot = start_server_switch(self.conn, "test_user_123", "pl")
        self.assertEqual(slot["status"], "migrating")
        self.assertEqual(slot["active_server"], "nl")  # Old still active!
        self.assertEqual(slot["pending_server"], "pl")
        self.assertEqual(slot["pending_doc_url"], "https://cloud.mail.ru/public/PL/Doc")
        self.assertIsNotNone(slot["pending_started_at"])

        # 3. Phase 2: Confirm switch
        final_slot = confirm_server_switch(self.conn, "test_user_123")
        self.assertEqual(final_slot["status"], "active")
        self.assertEqual(final_slot["active_server"], "pl")
        self.assertEqual(final_slot["active_doc_url"], "https://cloud.mail.ru/public/PL/Doc")
        self.assertIsNone(final_slot["pending_server"])

        # Verify old worker was stopped and old doc was deleted
        mock_stop.assert_called_with("nl", "openflux-worker-test_user_123")
        mock_del.assert_called_with("NL_test_user_123.docx")

    @patch("vpn_shop.openflux_manager.rclone_create_user_doc", return_value=True)
    @patch("vpn_shop.openflux_manager.rclone_get_public_link", return_value="https://cloud.mail.ru/public/NL/Doc")
    @patch("vpn_shop.openflux_manager.start_openflux_worker", return_value=True)
    @patch("vpn_shop.openflux_manager.stop_openflux_worker", return_value=True)
    @patch("vpn_shop.openflux_manager.rclone_delete_user_doc", return_value=True)
    def test_two_phase_handover_cancel(self, mock_del, mock_stop, mock_start, mock_link, mock_create):
        activate_openflux_slot(self.conn, "test_user_123")
        start_server_switch(self.conn, "test_user_123", "fi")

        slot = cancel_server_switch(self.conn, "test_user_123")
        self.assertEqual(slot["status"], "active")
        self.assertEqual(slot["active_server"], "nl")
        self.assertIsNone(slot["pending_server"])
        mock_stop.assert_called_with("fi", "openflux-worker-test_user_123-pending")
        mock_del.assert_called_with("FI_test_user_123_pending.docx")

    @patch("vpn_shop.openflux_manager.stop_openflux_worker", return_value=True)
    @patch("vpn_shop.openflux_manager.rclone_delete_user_doc", return_value=True)
    def test_watchdog_cleanup_expired(self, mock_del, mock_stop):
        now = int(time.time())
        # Insert expired migration (started 400s ago)
        self.conn.execute(
            """
            INSERT INTO openflux_slots (
                profile_public_id, status, active_server, pending_server,
                pending_doc_name, pending_container_name, pending_started_at,
                created_at, updated_at
            ) VALUES (
                'test_user_123', 'migrating', 'nl', 'pl',
                'PL_test_user_123_pending.docx', 'openflux-worker-test_user_123-pending',
                ?, ?, ?
            )
            """,
            (now - 400, now - 400, now - 400),
        )
        self.conn.commit()

        cleaned = cleanup_expired_migrations(self.conn, timeout_seconds=300)
        self.assertEqual(cleaned, 1)

        slot = get_or_create_openflux_slot(self.conn, "test_user_123")
        self.assertEqual(slot["status"], "active")
        self.assertIsNone(slot["pending_server"])


if __name__ == "__main__":
    unittest.main()
