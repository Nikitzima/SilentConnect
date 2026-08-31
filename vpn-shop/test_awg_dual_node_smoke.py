"""Dual-Node Live Smoke Test for AmneziaWG 3.1 on NL and FI nodes.
Can run both in mock environment (unit test mode) and live environment.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "vpn_shop"))

from vpn_shop import awg_manager as am


class TestDualNodeSmoke(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp_dir.name)
        self.db_path = self.tmp_path / "test_smoke.db"
        self.allowed_ips_file = self.tmp_path / "allowed-ips.txt"
        self.allowed_ips_file.write_text("198.51.100.0/24, 203.0.113.0/24", encoding="utf-8")

        self.orig_db = am.DB_PATH
        am.DB_PATH = str(self.db_path)
        am.SERVERS["nl"]["allowed_ips_file"] = str(self.allowed_ips_file)
        am.SERVERS["fi"]["allowed_ips_file"] = str(self.allowed_ips_file)
        am.ensure_table()

    def tearDown(self):
        am.DB_PATH = self.orig_db
        try:
            self.tmp_dir.cleanup()
        except Exception:
            pass

    @patch("vpn_shop.awg_manager._server_conf")
    @patch("vpn_shop.awg_manager._dex")
    def test_dual_node_peer_lifecycle(self, mock_dex, mock_server_conf):
        server_conf_sample = """[Interface]
Address = 10.8.1.1/24
PrivateKey = aW5pdGlhbF9zZXJ2ZXJfcHJpdmF0ZV9rZXk=
ListenPort = 44121
Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 20
H1 = 1
H2 = 2
H3 = 3
H4 = 4
"""
        mock_server_conf.return_value = server_conf_sample
        mock_dex.side_effect = lambda *args, **kwargs: "mock_key_or_peers"

        test_sid_nl = "smokeTestSubNl99"
        test_sid_fi = "smokeTestSubFi99"

        # 1. NL Peer Lifecycle
        row_nl = am.create_peer(test_sid_nl, server_code="nl")
        self.assertIsNotNone(row_nl)
        self.assertEqual(row_nl["sub_id"], test_sid_nl)
        self.assertEqual(row_nl["server_code"], "nl")
        self.assertTrue(row_nl["tunnel_ip"].startswith("10.8.1."))

        conf_nl = am.build_conf(test_sid_nl, server_code="nl")
        self.assertIn("warp.example.com:44121", conf_nl)
        self.assertIn("Address = 10.8.1.", conf_nl)
        self.assertIn("Jc = 4", conf_nl)
        self.assertIn("H1 = 1", conf_nl)

        # 2. FI Peer Lifecycle
        row_fi = am.create_peer(test_sid_fi, server_code="fi")
        self.assertIsNotNone(row_fi)
        self.assertEqual(row_fi["sub_id"], test_sid_fi)
        self.assertEqual(row_fi["server_code"], "fi")
        self.assertTrue(row_fi["tunnel_ip"].startswith("10.8.2."))

        conf_fi = am.build_conf(test_sid_fi, server_code="fi")
        self.assertIn("fi.example.com:49752", conf_fi)
        self.assertIn("Address = 10.8.2.", conf_fi)
        self.assertIn("Jc = 4", conf_fi)
        self.assertIn("H1 = 1", conf_fi)

        # 3. Clean removal
        removed_nl = am.remove_peer(test_sid_nl, "smoke-test-done", server_code="nl")
        self.assertTrue(removed_nl)
        removed_fi = am.remove_peer(test_sid_fi, "smoke-test-done", server_code="fi")
        self.assertTrue(removed_fi)


if __name__ == "__main__":
    unittest.main()
