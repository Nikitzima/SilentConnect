"""Comprehensive unit and integration test suite for Milestone 3: Multi-Server Peer Management & Schema.
"""

from __future__ import annotations

import gc
import os
import sys
import tempfile
import unittest
import sqlite3
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add vpn-shop to sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "vpn_shop"))

from vpn_shop import awg_manager
try:
    from vpn_shop import awg_reconcile
except ImportError:
    import awg_reconcile


class TestMultiServerAwgManager(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp_dir.name) / "test_vpn_shop.db"
        self.allowed_ips_file = Path(self.tmp_dir.name) / "allowed-ips.txt"
        self.allowed_ips_file.write_text("198.51.100.0/24, 203.0.113.0/24", encoding="utf-8")

        # Point awg_manager to temp DB and config files
        self.orig_db = awg_manager.DB_PATH
        awg_manager.DB_PATH = str(self.db_path)
        awg_manager.SERVERS["nl"]["allowed_ips_file"] = str(self.allowed_ips_file)
        awg_manager.SERVERS["fi"]["allowed_ips_file"] = str(self.allowed_ips_file)

    def tearDown(self):
        awg_manager.DB_PATH = self.orig_db
        gc.collect()
        try:
            self.tmp_dir.cleanup()
        except Exception:
            pass

    def test_servers_registry_structure(self):
        """Verify SERVERS dictionary parameters for NL and FI."""
        self.assertIn("nl", awg_manager.SERVERS)
        self.assertIn("fi", awg_manager.SERVERS)

        nl = awg_manager.SERVERS["nl"]
        self.assertEqual(nl["subnet"], "10.8.1")
        self.assertEqual(nl["endpoint_host"], os.environ.get("AWG_NL_ENDPOINT", "warp.example.com"))
        self.assertEqual(nl["endpoint_port"], "44121")
        self.assertEqual(nl["mode"], "local")
        self.assertEqual(nl["container"], "amnezia-awg2")
        self.assertEqual(nl["conf_path"], "/opt/amnezia/awg/awg0.conf")
        self.assertEqual(nl["reserved_ips"], {"10.8.1.1", "10.8.1.2", "10.8.1.3", "10.8.1.4", "10.8.1.6"})

        fi = awg_manager.SERVERS["fi"]
        self.assertEqual(fi["subnet"], "10.8.2")
        self.assertEqual(fi["endpoint_host"], os.environ.get("AWG_FI_ENDPOINT", "fi.example.com"))
        self.assertEqual(fi["endpoint_port"], "49752")
        self.assertEqual(fi["mode"], "ssh")
        self.assertEqual(fi["host"], os.environ.get("AWG_FI_HOST", "198.51.100.1"))
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

            # Check unique index
            indices = conn.execute("PRAGMA index_list(awg_peers)").fetchall()
            index_names = [idx[1] for idx in indices]
            self.assertIn("idx_awg_peers_server_ip", index_names)

    def test_database_migration_with_existing_67_peers(self):
        """Simulate pre-existing table without server_code and ensure 100% data preservation."""
        # Create legacy table structure
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
            # Insert 67 simulated production peers
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

        # Trigger migration
        awg_manager.ensure_table()

        # Verify all 67 peers exist, have server_code='nl', and composite PK allows multi-server
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM awg_peers").fetchall()
            self.assertEqual(len(rows), 67)
            for row in rows:
                self.assertEqual(row["server_code"], "nl")

            # Check that adding the same sub_id on 'fi' succeeds due to composite PK
            conn.execute(
                """
                INSERT INTO awg_peers (
                    sub_id, server_code, private_key, public_key, preshared_key,
                    tunnel_ip, created_at, period_start, bytes_used, last_rx, last_tx,
                    active, inactive_reason
                ) VALUES ('sub_001', 'fi', 'priv_fi', 'pub_fi', 'psk_fi', '10.8.2.10',
                          '2026-08-28 12:00:00', '2026-08-28', 0, 0, 0, 1, '')
                """
            )
            fi_peer = conn.execute("SELECT * FROM awg_peers WHERE sub_id='sub_001' AND server_code='fi'").fetchone()
            self.assertIsNotNone(fi_peer)
            self.assertEqual(fi_peer["tunnel_ip"], "10.8.2.10")

    @patch("vpn_shop.awg_manager.subprocess.run")
    def test_dex_routing_local_vs_ssh(self, mock_run):
        """Verify _dex dispatches local docker for NL and ssh for FI."""
        mock_run.return_value = MagicMock(returncode=0, stdout="mock_output\n", stderr="")

        # Test NL local execution (positional server_code)
        res_nl = awg_manager._dex("nl", "awg show")
        self.assertEqual(res_nl, "mock_output")
        args_nl = mock_run.call_args[0][0]
        self.assertEqual(args_nl, ["docker", "exec", "-i", "amnezia-awg2", "sh", "-c", "awg show"])

        # Test NL local execution (keyword server_code)
        res_nl2 = awg_manager._dex("awg show", server_code="nl")
        self.assertEqual(res_nl2, "mock_output")

        # Test FI remote execution via SSH (positional server_code)
        res_fi = awg_manager._dex("fi", "awg show")
        self.assertEqual(res_fi, "mock_output")
        args_fi = mock_run.call_args[0][0]
        self.assertEqual(args_fi[0], "ssh")
        self.assertIn("-o", args_fi)
        self.assertIn("BatchMode=yes", args_fi)
        self.assertIn("ConnectTimeout=10", args_fi)
        self.assertIn("StrictHostKeyChecking=accept-new", args_fi)
        self.assertIn(f"root@{awg_manager.SERVERS['fi']['host']}", args_fi)
        self.assertIn("docker exec -i amnezia-awg2 sh -c 'awg show'", args_fi[-1])

        # Test FI remote execution (keyword server_code)
        res_fi2 = awg_manager._dex("awg show", server_code="fi")
        self.assertEqual(res_fi2, "mock_output")

    @patch("vpn_shop.awg_manager._server_conf")
    def test_ip_allocation_nl_and_fi(self, mock_conf):
        """Verify IP allocation selects next available IP skipping reserved for each server."""
        # NL server conf has peer with 10.8.1.5
        mock_conf.side_effect = lambda server_code="nl": (
            "[Interface]\nPrivateKey = priv\n\n[Peer]\nAllowedIPs = 10.8.1.5/32\n"
            if server_code == "nl" else
            "[Interface]\nPrivateKey = priv\n\n[Peer]\nAllowedIPs = 10.8.2.5/32, 10.8.2.7/32\n"
        )

        # NL: 10.8.1.1..4, 6 reserved; 5 used in conf -> next is 10.8.1.7
        next_nl = awg_manager._next_free_ip("nl")
        self.assertEqual(next_nl, "10.8.1.7")

        # FI: 10.8.2.1..4, 6 reserved; 5, 7 used in conf -> next is 10.8.2.8
        next_fi = awg_manager._next_free_ip("fi")
        self.assertEqual(next_fi, "10.8.2.8")

    @patch("vpn_shop.awg_manager._dex")
    @patch("vpn_shop.awg_manager._server_conf")
    def test_create_and_get_peer_lifecycle(self, mock_conf, mock_dex):
        """Test peer creation and retrieval across NL and FI."""
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

        # Create NL peer
        peer_nl = awg_manager.create_peer("user_123", server_code="nl")
        self.assertEqual(peer_nl["sub_id"], "user_123")
        self.assertEqual(peer_nl["server_code"], "nl")
        self.assertTrue(peer_nl["tunnel_ip"].startswith("10.8.1."))

        # Create FI peer for same user
        peer_fi = awg_manager.create_peer("user_123", server_code="fi")
        self.assertEqual(peer_fi["sub_id"], "user_123")
        self.assertEqual(peer_fi["server_code"], "fi")
        self.assertTrue(peer_fi["tunnel_ip"].startswith("10.8.2."))

        # Verify get_peer retrieves correct server record
        get_nl = awg_manager.get_peer("user_123", server_code="nl")
        self.assertIsNotNone(get_nl)
        self.assertEqual(get_nl["server_code"], "nl")

        get_fi = awg_manager.get_peer("user_123", server_code="fi")
        self.assertIsNotNone(get_fi)
        self.assertEqual(get_fi["server_code"], "fi")

    @patch("vpn_shop.awg_manager._dex")
    @patch("vpn_shop.awg_manager._server_conf")
    def test_remove_and_readd_peer(self, mock_conf, mock_dex):
        """Verify peer removal and reactivation properly updates DB status and avoids duplicate blocks."""
        server_conf_sample = """[Interface]
Address = 10.8.1.1/24
PrivateKey = server_priv
[Peer]
PublicKey = mock_pub_key
AllowedIPs = 10.8.1.5/32
"""
        mock_conf.return_value = server_conf_sample
        mock_dex.side_effect = lambda *args, **kwargs: "mock_pub_key"

        # Create peer
        awg_manager.create_peer("test_rem_readd", server_code="nl")
        peer = awg_manager.get_peer("test_rem_readd", server_code="nl")
        self.assertEqual(peer["active"], 1)

        # Remove peer
        removed = awg_manager.remove_peer("test_rem_readd", reason="test expired", server_code="nl")
        self.assertTrue(removed)
        peer_after_remove = awg_manager.get_peer("test_rem_readd", server_code="nl")
        self.assertEqual(peer_after_remove["active"], 0)
        self.assertEqual(peer_after_remove["inactive_reason"], "test expired")

        # Readd peer
        readded = awg_manager.readd_peer("test_rem_readd", server_code="nl")
        self.assertTrue(readded)
        peer_after_readd = awg_manager.get_peer("test_rem_readd", server_code="nl")
        self.assertEqual(peer_after_readd["active"], 1)
        self.assertEqual(peer_after_readd["inactive_reason"], "")

    @patch("vpn_shop.awg_manager._dex")
    @patch("vpn_shop.awg_manager._server_conf")
    def test_build_conf_generation(self, mock_conf, mock_dex):
        """Verify client .conf generation contains correct endpoint, IP, and obfuscation params."""
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

        # Create peers
        awg_manager.create_peer("client_conf_test", server_code="nl")
        awg_manager.create_peer("client_conf_test", server_code="fi")

        # Build NL conf
        conf_nl = awg_manager.build_conf("client_conf_test", server_code="nl")
        self.assertIn(f"Endpoint = {awg_manager.SERVERS['nl']['endpoint_host']}:44121", conf_nl)
        self.assertIn("Address = 10.8.1.", conf_nl)
        self.assertIn("Jc = 4", conf_nl)
        self.assertIn("HeaderProtectionKey = 123456", conf_nl)
        self.assertIn("AllowedIPs = 198.51.100.0/24, 203.0.113.0/24, ::/0", conf_nl)

        # Build FI conf
        conf_fi = awg_manager.build_conf("client_conf_test", server_code="fi")
        self.assertIn(f"Endpoint = {awg_manager.SERVERS['fi']['endpoint_host']}:49752", conf_fi)
        self.assertIn("Address = 10.8.2.", conf_fi)
        self.assertIn("Jc = 4", conf_fi)
        self.assertIn("HeaderProtectionKey = 123456", conf_fi)

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

        # mock_dex should have been called for query ("iptables -S FORWARD") and missing rules (d1:ad2:id20:, BT-SEARCH), but not BitTorrent protocol
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
