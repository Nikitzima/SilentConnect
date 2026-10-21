import base64
import json
import sqlite3
import unittest
from unittest.mock import patch, MagicMock
import zlib

import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "vpn-shop"))

from vpn_shop import openflux_manager


class TestOpenFluxManager(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(
            """
            CREATE TABLE profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                public_id TEXT NOT NULL UNIQUE
            );
            """
        )
        self.conn.execute("INSERT INTO profiles (public_id) VALUES ('prf_test_user_1')")
        self.conn.execute("INSERT INTO profiles (public_id) VALUES ('prf_test_user_2')")
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def test_build_openflux_stream_link_cupsonline(self):
        test_url = "https://interview.cups.online/live-coding/?room=12345678-1234-1234-1234-123456789abc"
        link = openflux_manager.build_openflux_stream_link(test_url, "nl")
        self.assertTrue(link.startswith("openflux://v1/"))

        # Decode link
        b64 = link[len("openflux://v1/"):]
        # Add padding if needed
        rem = len(b64) % 4
        if rem > 0:
            b64 += "=" * (4 - rem)
        raw_deflate = base64.urlsafe_b64decode(b64.encode("ascii"))
        decompressed = zlib.decompress(raw_deflate, -zlib.MAX_WBITS)
        payload = json.loads(decompressed.decode("utf-8"))

        self.assertEqual(payload["mode"], "stream")
        self.assertEqual(len(payload["transports"]), 1)
        self.assertEqual(payload["transports"][0]["type"], "cupsonline")
        self.assertEqual(payload["transports"][0]["url"], test_url)
        self.assertIn("Нидерланды", payload["name"])

    @patch("urllib.request.urlopen")
    def test_create_cups_room_scraping(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = (
            b'<html><head><meta name="test"></head><body>'
            b'<div data-room="{&quot;uuid&quot;: &quot;f4ef3561-97e3-4365-8323-1e4c40b35320&quot;, &quot;access_type&quot;: &quot;public&quot;}"></div>'
            b'</body></html>'
        )
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        room_uuid, room_url = openflux_manager.create_cups_room()
        self.assertEqual(room_uuid, "f4ef3561-97e3-4365-8323-1e4c40b35320")
        self.assertEqual(room_url, "https://interview.cups.online/live-coding/?room=f4ef3561-97e3-4365-8323-1e4c40b35320")

    @patch("vpn_shop.openflux_manager.start_openflux_worker", return_value=True)
    @patch("vpn_shop.openflux_manager.stop_openflux_worker", return_value=True)
    @patch("vpn_shop.openflux_manager.rename_openflux_worker", return_value=True)
    @patch("vpn_shop.openflux_manager.create_cups_room")
    def test_slot_activation_and_handover(self, mock_create_room, mock_rename, mock_stop, mock_start):
        mock_create_room.side_effect = [
            ("uuid_nl_1", "https://interview.cups.online/live-coding/?room=uuid_nl_1"),
            ("uuid_pl_2", "https://interview.cups.online/live-coding/?room=uuid_pl_2"),
        ]

        # 1. Uninitialized
        slot = openflux_manager.get_or_create_openflux_slot(self.conn, "prf_test_user_1")
        self.assertEqual(slot["status"], "uninitialized")

        # 2. Activate
        with patch("vpn_shop.openflux_manager._is_node_reachable", return_value=True):
            slot = openflux_manager.activate_openflux_slot(self.conn, "prf_test_user_1")
        self.assertEqual(slot["status"], "active")
        self.assertIn("cups_uuid_nl_1", slot["active_doc_name"])
        self.assertIn("openflux-worker-prf_test_user_1", slot["active_container_name"])
        mock_start.assert_called()

        # 3. Two-phase migration: start switch to other server
        target_srv = "pl" if slot["active_server"] == "nl" else "nl"
        slot = openflux_manager.start_server_switch(self.conn, "prf_test_user_1", target_srv)
        self.assertEqual(slot["status"], "migrating")
        self.assertEqual(slot["pending_server"], target_srv)
        self.assertIn("cups_uuid_pl_2", slot["pending_doc_name"])

        # 4. Confirm switch
        slot = openflux_manager.confirm_server_switch(self.conn, "prf_test_user_1", async_cleanup=False)
        self.assertEqual(slot["status"], "active")
        self.assertEqual(slot["active_server"], target_srv)
        self.assertIsNone(slot["pending_server"])


if __name__ == "__main__":
    unittest.main()
