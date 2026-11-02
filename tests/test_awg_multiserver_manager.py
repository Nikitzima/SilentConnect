"""Comprehensive unit and integration test suite for Multi-Server Peer Management & Schema (NL, DE, FI).
"""

from __future__ import annotations

import gc
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parents[1]
VPN_SHOP_DIR = REPO_ROOT / "vpn-shop"
if str(VPN_SHOP_DIR) not in sys.path:
    sys.path.insert(0, str(VPN_SHOP_DIR))
if str(VPN_SHOP_DIR / "vpn_shop") not in sys.path:
    sys.path.insert(0, str(VPN_SHOP_DIR / "vpn_shop"))

from vpn_shop import awg_manager
try:
    from vpn_shop import awg_reconcile
except ImportError:
    import awg_reconcile


class TestMultiServerAwgManager(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp_dir.name) / f"test_vpn_shop_{self._testMethodName}.db"
        self.allowed_ips_file = Path(self.tmp_dir.name) / "allowed-ips.txt"
        self.allowed_ips_file.write_text("198.51.100.0/24, 203.0.113.0/24", encoding="utf-8")

        self.orig_db = awg_manager.DB_PATH
        awg_manager.DB_PATH = str(self.db_path)
        awg_manager._STORE_INSTANCE = None
        for code in ("nl", "de", "fi"):
            if code in awg_manager.SERVERS:
                awg_manager.SERVERS[code]["allowed_ips_file"] = str(self.allowed_ips_file)

    def tearDown(self):
        awg_manager.DB_PATH = self.orig_db
        if getattr(awg_manager, "_STORE_INSTANCE", None) is not None:
            try:
                awg_manager._STORE_INSTANCE.close()
            except Exception:
                pass
            awg_manager._STORE_INSTANCE = None
        gc.collect()
        try:
            self.tmp_dir.cleanup()
        except Exception:
            pass

    def test_servers_registry_structure(self):
        """Verify SERVERS dictionary parameters for NL, DE, and FI."""
        self.assertIn("nl", awg_manager.SERVERS)
        self.assertIn("de", awg_manager.SERVERS)
        self.assertIn("fi", awg_manager.SERVERS)

        nl = awg_manager.SERVERS["nl"]
        self.assertEqual(nl["subnet"], "10.8.1")
        self.assertEqual(nl["endpoint_port"], "44121")
        self.assertEqual(nl["mode"], "local")
        self.assertEqual(nl["container"], "amnezia-awg2")
        self.assertEqual(nl["conf_path"], "/opt/amnezia/awg/awg0.conf")
        self.assertEqual(nl["reserved_ips"], {"10.8.1.1", "10.8.1.2", "10.8.1.3", "10.8.1.4", "10.8.1.6"})

        de = awg_manager.SERVERS["de"]
        self.assertEqual(de["subnet"], "10.8.4")
        self.assertEqual(de["endpoint_port"], "44121")
        self.assertEqual(de["mode"], "ssh")
        self.assertEqual(de["container"], "amnezia-awg2")
        self.assertEqual(de["conf_path"], "/opt/amnezia/awg/awg0.conf")
        self.assertEqual(de["reserved_ips"], {"10.8.4.1", "10.8.4.2", "10.8.4.3", "10.8.4.4", "10.8.4.6"})

        fi = awg_manager.SERVERS["fi"]
        self.assertEqual(fi["subnet"], "10.8.2")
        self.assertEqual(fi["endpoint_port"], "49752")
        self.assertEqual(fi["mode"], "ssh")
        self.assertEqual(fi["ssh_user"], "root")
        self.assertEqual(fi["container"], "amnezia-awg2")
        self.assertEqual(fi["conf_path"], "/opt/amnezia/awg/awg0.conf")
        self.assertEqual(fi["reserved_ips"], {"10.8.2.1", "10.8.2.2", "10.8.2.3", "10.8.2.4", "10.8.2.6"})

    def test_fresh_database_schema(self):
        """Verify fresh database initialization contains server_code and composite PK."""
        awg_manager.ensure_table()
        with sqlite3.connect(str(self.db_path)) as conn:
            cols = {row[1]: row for row in conn.execute("PRAGMA table_info(awg_peers)").fetchall()}
            self.assertIn("server_code", cols)
            self.assertIn("sub_id", cols)
            self.assertIn("tunnel_ip", cols)

            indices = conn.execute("PRAGMA index_list(awg_peers)").fetchall()
            index_names = [idx[1] for idx in indices]
            self.assertIn("idx_awg_peers_server_ip", index_names)

    def test_database_migration_with_existing_67_peers(self):
        """Simulate pre-existing table without server_code and ensure 100% data preservation."""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                """
                CREATE TABLE awg_peers (
                    sub_id        TEXT PRIMARY KEY,
                    private_key   TEXT NOT NULL,
                    public_key    TEXT NOT NULL,
                    preshared_key TEXT NOT NULL,
                    tunnel_ip     TEXT NOT NULL,
                    created_at    TEXT NOT NULL,
                    period_start  TEXT NOT NULL,
                    bytes_used    INTEGER NOT NULL DEFAULT 0,
                    last_rx       INTEGER NOT NULL DEFAULT 0,
                    last_tx       INTEGER NOT NULL DEFAULT 0,
                    active        INTEGER NOT NULL DEFAULT 1,
                    inactive_reason TEXT
                )
                """
            )
            for i in range(1, 68):
                conn.execute(
                    """
                    INSERT INTO awg_peers (
                        sub_id, private_key, public_key, preshared_key,
                        tunnel_ip, created_at, period_start, bytes_used, last_rx, last_tx,
                        active, inactive_reason
                    ) VALUES (?, ?, ?, ?, ?, '2026-08-01 10:00:00', '2026-08-01', 1000, 500, 500, 1, '')
                    """,
                    (f"sub_{i:03d}", f"priv_{i}", f"pub_{i}", f"psk_{i}", f"10.8.1.{i+6}"),
                )

        awg_manager.ensure_table()

        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM awg_peers").fetchall()
            self.assertEqual(len(rows), 67)
            for row in rows:
                self.assertEqual(row["server_code"], "nl")

            for code, ip in (("de", "10.8.4.10"), ("fi", "10.8.2.10")):
                conn.execute(
                    """
                    INSERT INTO awg_peers (
                        sub_id, server_code, private_key, public_key, preshared_key,
                        tunnel_ip, created_at, period_start, bytes_used, last_rx, last_tx,
                        active, inactive_reason
                    ) VALUES ('sub_001', ?, ?, ?, ?, ?,
                              '2026-08-28 12:00:00', '2026-08-28', 0, 0, 0, 1, '')
                    """,
                    (code, f"priv_{code}", f"pub_{code}", f"psk_{code}", ip),
                )
                peer = conn.execute("SELECT * FROM awg_peers WHERE sub_id='sub_001' AND server_code=?", (code,)).fetchone()
                self.assertIsNotNone(peer)
                self.assertEqual(peer["tunnel_ip"], ip)

    @patch("vpn_shop.awg_manager.subprocess.run")
    def test_dex_routing_local_vs_ssh(self, mock_run):
        """Verify _dex dispatches local docker for NL and ssh for DE and FI."""
        mock_run.return_value = MagicMock(returncode=0, stdout="mock_output\n", stderr="")

        res_nl = awg_manager._dex("nl", "awg show")
        self.assertEqual(res_nl, "mock_output")
        args_nl = mock_run.call_args[0][0]
        self.assertEqual(args_nl, ["docker", "exec", "-i", "amnezia-awg2", "bash", "-c", "awg show"])

        for remote_code in ("de", "fi"):
            res_rem = awg_manager._dex(remote_code, "awg show")
            self.assertEqual(res_rem, "mock_output")
            args_rem = mock_run.call_args[0][0]
            self.assertEqual(args_rem[0], "ssh")
            self.assertIn("BatchMode=yes", args_rem)
            self.assertIn(f"root@{awg_manager.SERVERS[remote_code]['host']}", args_rem)
            self.assertIn("docker exec -i amnezia-awg2 bash -c 'awg show'", args_rem[-1])

    @patch("vpn_shop.awg_manager._server_conf")
    def test_ip_allocation_nl_de_and_fi(self, mock_conf):
        """Verify IP allocation selects next available IP skipping reserved for NL, DE, and FI."""
        def _side_effect(server_code="nl"):
            if server_code == "nl":
                return "[Interface]\nPrivateKey = priv\n\n[Peer]\nAllowedIPs = 10.8.1.5/32\n"
            if server_code == "de":
                return "[Interface]\nPrivateKey = priv\n\n[Peer]\nAllowedIPs = 10.8.4.5/32, 10.8.4.7/32\n"
            return "[Interface]\nPrivateKey = priv\n\n[Peer]\nAllowedIPs = 10.8.2.5/32, 10.8.2.7/32\n"

        mock_conf.side_effect = _side_effect

        self.assertEqual(awg_manager._next_free_ip("nl"), "10.8.1.7")
        self.assertEqual(awg_manager._next_free_ip("de"), "10.8.4.8")
        self.assertEqual(awg_manager._next_free_ip("fi"), "10.8.2.8")

    @patch("vpn_shop.awg_manager._dex")
    @patch("vpn_shop.awg_manager._server_conf")
    def test_create_and_get_peer_lifecycle_three_nodes(self, mock_conf, mock_dex):
        """Test peer creation, retrieval, and clean removal across NL, DE, and FI."""
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
        mock_conf.return_value = server_conf_sample
        mock_dex.side_effect = lambda *args, **kwargs: "mock_key_or_output"

        for code, prefix in (("nl", "10.8.1."), ("de", "10.8.4."), ("fi", "10.8.2.")):
            peer = awg_manager.create_peer("user_123", server_code=code)
            self.assertEqual(peer["sub_id"], "user_123")
            self.assertEqual(peer["server_code"], code)
            self.assertTrue(peer["tunnel_ip"].startswith(prefix))

            fetched = awg_manager.get_peer("user_123", server_code=code)
            self.assertIsNotNone(fetched)
            self.assertEqual(fetched["server_code"], code)

            removed = awg_manager.remove_peer("user_123", reason="smoke-done", server_code=code)
            self.assertTrue(removed)
            self.assertEqual(awg_manager.get_peer("user_123", server_code=code)["active"], 0)

            readded = awg_manager.readd_peer("user_123", server_code=code)
            self.assertTrue(readded)
            self.assertEqual(awg_manager.get_peer("user_123", server_code=code)["active"], 1)

    @patch("vpn_shop.awg_manager._dex")
    @patch("vpn_shop.awg_manager._server_conf")
    def test_build_conf_generation_all_nodes(self, mock_conf, mock_dex):
        """Verify client .conf generation contains correct endpoint, IP, and obfuscation params for NL, DE, FI."""
        server_conf_sample = """[Interface]
Address = 10.8.1.1/24
PrivateKey = aW5pdGlhbF9zZXJ2ZXJfcHJpdmF0ZV9rZXk=
ListenPort = 44121
Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 20
S3 = 30
S4 = 40
H1 = 111
H2 = 222
H3 = 333
H4 = 444
I1 = 1
I2 = 2
I3 = 3
I4 = 4
I5 = 5
HeaderProtectionKey = 123456
ContentPaddingAddition = 50
RekeyAfterTime = 120
"""
        mock_conf.return_value = server_conf_sample
        mock_dex.side_effect = lambda *args, **kwargs: "server_public_key_base64"

        for code, prefix, port in (("nl", "10.8.1.", "44121"), ("de", "10.8.4.", "44121"), ("fi", "10.8.2.", "49752")):
            awg_manager.create_peer("client_conf_test", server_code=code)
            conf = awg_manager.build_conf("client_conf_test", server_code=code)
            self.assertIn(f"Endpoint = {awg_manager.SERVERS[code]['endpoint_host']}:{port}", conf)
            self.assertIn(f"Address = {prefix}", conf)
            self.assertIn("Jc = 4", conf)
            self.assertIn("HeaderProtectionKey = 123456", conf)
            self.assertIn("AllowedIPs = 198.51.100.0/24, 203.0.113.0/24", conf)

    @patch("vpn_shop.awg_manager._dex")
    def test_peer_transfer_parsing(self, mock_dex):
        """Verify peer_transfer parses awg show dump output into rx/tx counters."""
        mock_dump = (
            "pubkey_1111111111111111111111111111111111111111=\tpsk\tendpoint\tallowed\t1700000000\t1048576\t2097152\t25\n"
            "pubkey_2222222222222222222222222222222222222222=\tpsk\tendpoint\tallowed\t1700000000\t5000000\t6000000\t25\n"
        )
        mock_dex.return_value = mock_dump

        transfers = awg_manager.peer_transfer("nl")
        self.assertEqual(len(transfers), 2)
        self.assertEqual(transfers["pubkey_1111111111111111111111111111111111111111="], (1048576, 2097152))
        self.assertEqual(transfers["pubkey_2222222222222222222222222222222222222222="], (5000000, 6000000))

    @patch.object(awg_reconcile, "_dex")
    def test_ensure_torrent_block_idempotency(self, mock_dex):
        """Verify DPI torrent rules are only inserted if not already existing."""
        mock_dex.return_value = "-P FORWARD ACCEPT\n-A FORWARD -m string --string \"BitTorrent protocol\" --algo bm -j REJECT\n"
        awg_reconcile.ensure_torrent_block("nl")

        inserted_commands = [call[0][0] for call in mock_dex.call_args_list if "iptables -I" in str(call)]
        self.assertTrue(any("d1:ad2:id20:" in cmd for cmd in inserted_commands))
        self.assertTrue(any("BT-SEARCH" in cmd for cmd in inserted_commands))
        self.assertFalse(any("BitTorrent protocol" in cmd for cmd in inserted_commands))

    def test_reconcile_quota_constants(self):
        """Verify 500 GB quota in reconcile."""
        self.assertEqual(awg_reconcile.QUOTA_GB, 500)
        self.assertEqual(awg_reconcile.QUOTA_BYTES, 500 * (1024 ** 3))


if __name__ == "__main__":
    unittest.main()
