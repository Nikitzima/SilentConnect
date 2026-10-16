import http.client
import json
import os
import sys
import tempfile
import threading
import unittest
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch, MagicMock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "vpn-shop") not in sys.path:
    sys.path.insert(0, str(ROOT / "vpn-shop"))
if str(ROOT / "subjson-service") not in sys.path:
    sys.path.insert(0, str(ROOT / "subjson-service"))

os.environ.setdefault("SERVER_PEPPER", "resilience-test-pepper-0123456789abcdef")
os.environ.setdefault("SECRET_SEGMENT", "test-secret-sub")
os.environ.setdefault("CLUSTER_SYNC_SECRET", "resilience-sync-secret-12345678")

from vpn_shop.store import Store
from vpn_shop.config import Settings, load_settings
from vpn_shop.web import WebCheckout, RequestHandler, build_slot_conf, AwgNodeUnavailableError, WG_KEY_REGEX


class TestAwgClusterResilienceStep1(unittest.TestCase):
    def test_server_public_key_strict_regex(self):
        """Test strict regex validation of Curve25519 WireGuard public key."""
        valid_key = "OAxzJl7ocbkYzVx0Hh0aKKAnjH1inPt6YQyUi0iorVQ="
        self.assertEqual(len(valid_key), 44)
        self.assertTrue(bool(WG_KEY_REGEX.match(valid_key)))

        # Invalid cases
        invalid_keys = [
            "",
            "1111111111111111111111111111111111111111111=",  # Fake placeholder
            "short_key=",
            "too_long_key_123456789012345678901234567890123456=",
            "invalid_characters_in_key_!@#$%^&*()_+=123=",
            "validlength44charactersbutnotbase64padding==",
        ]
        slot = {
            "server_code": "nl",
            "client_ip": "10.8.1.10",
            "private_key_enc": "cHVibGlj",
            "preshared_key": "",
        }

        for inv in invalid_keys:
            with patch.dict(os.environ, {"AWG_SERVER_PUBLIC_KEY": inv, "AWG_NL_SERVER_PUBKEY": inv}):
                with patch("vpn_shop.awg_manager._server_conf", return_value=""):
                    with self.assertRaises(AwgNodeUnavailableError, msg=f"Should reject: {inv}"):
                        build_slot_conf(slot, server_code="nl")

        # Valid key works
        with patch.dict(os.environ, {"AWG_SERVER_PUBLIC_KEY": valid_key, "AWG_NL_SERVER_PUBKEY": valid_key}):
            with patch("vpn_shop.awg_manager._server_conf", return_value=""):
                conf = build_slot_conf(slot, server_code="nl")
                self.assertIn(f"PublicKey = {valid_key}", conf)

    def test_fail_closed_returns_503_and_retry_after(self):
        """Test that config download, QR, and config_text return 503 on AwgNodeUnavailableError."""
        tmp_dir = Path(tempfile.mkdtemp())
        db_path = tmp_dir / "resilience.db"
        store = Store(db_path)
        store.init()

        import dataclasses
        base_settings = load_settings(tmp_dir)
        settings = dataclasses.replace(
            base_settings,
            database_path=db_path,
            cluster_sync_secret="resilience-sync-secret-12345678",
            cf_turnstile_enabled=False,
            cf_turnstile_secret_key="",
            web_listen_host="127.0.0.1",
            web_listen_port=0,
        )
        checkout = WebCheckout(settings, store)
        RequestHandler.checkout = checkout

        server = ThreadingHTTPServer(("127.0.0.1", 0), RequestHandler)
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        try:
            profile = store.create_profile(
                xui_inbound_id=1,
                transport="vless",
                profile_mode="individual",
                family_label=None,
                xui_email="resilience_test@example.com",
                xui_client_id="resilience-client-123",
                expires_at=1900000000,
                device_limit=3,
            )
            sub_id = profile["public_id"]
            checkout.ensure_awg_slot(sub_id, 1)

            endpoints = [
                f"/sub/awg/{sub_id}/slot/1/config",
                f"/sub/awg/{sub_id}/slot/1/qr",
                f"/sub/awg/{sub_id}/slot/1/config_text",
            ]

            # Invalidate key so AwgNodeUnavailableError is triggered
            with patch.dict(os.environ, {"AWG_SERVER_PUBLIC_KEY": "", "AWG_NL_SERVER_PUBKEY": ""}):
                with patch("vpn_shop.awg_manager._server_conf", return_value=""):
                    for ep in endpoints:
                        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                        conn.request("GET", ep)
                        resp = conn.getresponse()
                        body = resp.read()
                        conn.close()

                        self.assertEqual(resp.status, HTTPStatus.SERVICE_UNAVAILABLE, f"Failed on endpoint {ep}")
                        self.assertEqual(resp.getheader("Retry-After"), "30")
                        self.assertEqual(resp.getheader("Content-Type"), "application/json; charset=utf-8")
                        data = json.loads(body.decode("utf-8"))
                        self.assertFalse(data["ok"])
                        self.assertEqual(data["error"], "service_temporarily_unavailable")
                        self.assertIn("Сервис временно недоступен", data["message"])
        finally:
            server.shutdown()
            server.server_close()


class TestAwgClusterResilienceStep2(unittest.TestCase):
    def test_node_identity_agreement(self):
        """When sources agree, the correct node code is returned."""
        from vpn_shop.awg_manager import get_current_node_code
        tmp_marker = Path(tempfile.mktemp())
        try:
            tmp_marker.write_text("nl\n", encoding="utf-8")
            with patch.dict(os.environ, {"AWG_LOCAL_SERVER": "nl"}):
                with patch("socket.gethostname", return_value="nikitzimawarp.aeza.network"):
                    code = get_current_node_code(marker_file=tmp_marker)
                    self.assertEqual(code, "nl")
        finally:
            if tmp_marker.exists():
                tmp_marker.unlink()

    def test_node_identity_conflict_raises_error(self):
        """When sources disagree, NodeIdentityConflictError is raised."""
        from vpn_shop.awg_manager import get_current_node_code, NodeIdentityConflictError
        tmp_marker = Path(tempfile.mktemp())
        try:
            tmp_marker.write_text("pl\n", encoding="utf-8")
            # Marker says 'pl', but env says 'nl' -> conflict!
            with patch.dict(os.environ, {"AWG_LOCAL_SERVER": "nl"}):
                with patch("socket.gethostname", return_value="unknown-host"):
                    with self.assertRaises(NodeIdentityConflictError):
                        get_current_node_code(marker_file=tmp_marker)

            # Marker says 'pl', but hostname says 'fi' -> conflict!
            with patch.dict(os.environ, {}, clear=False):
                if "AWG_LOCAL_SERVER" in os.environ:
                    del os.environ["AWG_LOCAL_SERVER"]
                with patch("socket.gethostname", return_value="SilentConnect-ubuntu-4gb-hel1-1"):
                    with self.assertRaises(NodeIdentityConflictError):
                        get_current_node_code(marker_file=tmp_marker)
        finally:
            if tmp_marker.exists():
                tmp_marker.unlink()

    def test_node_identity_missing_raises_error(self):
        """When no source is present, NodeIdentityMissingError is raised."""
        from vpn_shop.awg_manager import get_current_node_code, NodeIdentityMissingError
        non_existent_marker = Path(tempfile.mktemp())
        with patch.dict(os.environ, {}, clear=False):
            if "AWG_LOCAL_SERVER" in os.environ:
                del os.environ["AWG_LOCAL_SERVER"]
            with patch("socket.gethostname", return_value="arbitrary-unrecognized-pc"):
                with patch("pathlib.Path.is_file", return_value=False):
                    with self.assertRaises(NodeIdentityMissingError):
                        get_current_node_code(marker_file=non_existent_marker)


class TestAwgClusterResilienceStep3(unittest.TestCase):
    def test_strict_host_key_failure_no_auto_trust(self):
        """When SSH reports host key verification failure, ClusterSecurityError is raised."""
        from vpn_shop.awg_manager import _dex, ClusterSecurityError
        import subprocess

        fake_err = (
            "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
            "@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n"
            "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
            "Host key verification failed.\n"
        )
        mock_proc = MagicMock()
        mock_proc.returncode = 255
        mock_proc.stderr = fake_err

        with patch("vpn_shop.awg_manager._get_server", return_value={"mode": "ssh", "container": "amnezia-awg2", "host": "198.51.100.2"}):
            with patch("subprocess.run", return_value=mock_proc):
                with self.assertRaises(ClusterSecurityError) as ctx:
                    _dex("echo test", server_code="pl")
                self.assertIn("SSH host key verification failed", str(ctx.exception))

    def test_pin_key_fingerprint_and_confirmation(self):
        """Test compute_ed25519_fingerprint and confirmation enforcement in cluster_node_tool."""
        sys.path.insert(0, str(ROOT / "scripts"))
        from cluster_node_tool import compute_ed25519_fingerprint, run_pin_key

        test_b64 = "AAAAC3NzaC1lZDI1NTE5AAAAIBCuty5sukUqTXCuhswOIoN3l64PHpK01RfPL9h53Ohe"
        fp = compute_ed25519_fingerprint(test_b64)
        self.assertEqual(fp, "SHA256:663GGoUWCbA+CCnN71FtipYmw+8zOz1z39n6g0+KXgs")

        # Wrong confirmation -> aborts
        fake_keyscan_output = f"198.51.100.2 ssh-ed25519 {test_b64}\n"
        mock_proc = MagicMock()
        mock_proc.stdout = fake_keyscan_output
        mock_proc.stderr = ""
        mock_proc.returncode = 0

        tmp_known_hosts = Path(tempfile.mktemp())
        try:
            with patch("subprocess.run", return_value=mock_proc):
                # Wrong phrase
                with patch("builtins.input", return_value="WRONG PHRASE"):
                    rc = run_pin_key("pl", force_confirm=False, custom_known_hosts=str(tmp_known_hosts))
                    self.assertEqual(rc, 1)
                    self.assertFalse(tmp_known_hosts.exists())

                # Correct phrase
                with patch("builtins.input", return_value="CONFIRM PIN pl"):
                    rc = run_pin_key("pl", force_confirm=False, custom_known_hosts=str(tmp_known_hosts))
                    self.assertEqual(rc, 0)
                    self.assertTrue(tmp_known_hosts.exists())
                    content = tmp_known_hosts.read_text(encoding="utf-8")
                    self.assertIn(test_b64, content)
        finally:
            if tmp_known_hosts.exists():
                tmp_known_hosts.unlink()



class TestAwgClusterResilienceStep4(unittest.TestCase):
    def test_db_query_error_aborts_even_with_allow_empty(self):
        """DatabaseQueryError must abort reconciliation immediately, even if allow_empty=True."""
        from vpn_shop.awg_manager import reconcile_awg_peers
        from vpn_shop.store import DatabaseQueryError

        with patch("vpn_shop.store.Store.list_active_awg_slots", side_effect=DatabaseQueryError("DB disk I/O failure")):
            with self.assertRaises(DatabaseQueryError):
                reconcile_awg_peers(server_code="nl", dry_run=True, allow_empty=True)

    def test_empty_db_aborts_without_allow_empty(self):
        """Zero active slots returned from DB aborts unless allow_empty is explicitly set."""
        from vpn_shop.awg_manager import reconcile_awg_peers, ReconciliationAbortedError

        with patch("vpn_shop.store.Store.list_active_awg_slots", return_value=[]):
            # Without allow_empty -> must raise ReconciliationAbortedError
            with self.assertRaises(ReconciliationAbortedError) as ctx:
                reconcile_awg_peers(server_code="nl", dry_run=True, allow_empty=False)
            self.assertIn("Zero active slots", str(ctx.exception))

            # With allow_empty=True -> proceeds
            with patch("vpn_shop.awg_manager._server_conf", return_value="[Interface]\nAddress = 10.8.1.1/24\n"):
                res = reconcile_awg_peers(server_code="nl", dry_run=True, allow_empty=True, force_mass_delete=True)
                self.assertTrue(res["dry_run"])
                self.assertEqual(res["active_slots_db"], 0)

    def test_mass_deletion_circuit_breaker(self):
        """Mass deletion (>30% or >10 peers) aborts unless force_mass_delete=True."""
        from vpn_shop.awg_manager import reconcile_awg_peers, ReconciliationAbortedError

        # Create conf with 20 peers (all manageable IPs 10.8.1.10 - 10.8.1.29)
        conf_lines = ["[Interface]", "Address = 10.8.1.1/24", "PrivateKey = dummy_key"]
        for i in range(10, 30):
            conf_lines.extend([
                "",
                "[Peer]",
                f"PublicKey = pubkey_manageable_{i:02d}=====================",
                f"AllowedIPs = 10.8.1.{i}/32",
            ])
        conf_text = "\n".join(conf_lines) + "\n"

        # Desired DB has only 5 peers (so 15 peers / 75% would be deleted)
        desired_slots = [
            {"public_key": f"pubkey_manageable_{i:02d}=====================", "client_ip": f"10.8.1.{i}", "preshared_key": ""}
            for i in range(10, 15)
        ]

        with patch("vpn_shop.store.Store.list_active_awg_slots", return_value=desired_slots):
            with patch("vpn_shop.awg_manager._server_conf", return_value=conf_text):
                # 1. Without force_mass_delete -> circuit breaker triggers!
                with self.assertRaises(ReconciliationAbortedError) as ctx:
                    reconcile_awg_peers(server_code="nl", dry_run=True, force_mass_delete=False)
                self.assertIn("Mass deletion circuit breaker triggered", str(ctx.exception))

                # 2. With force_mass_delete=True -> allowed to proceed
                res = reconcile_awg_peers(server_code="nl", dry_run=True, force_mass_delete=True)
                self.assertEqual(len(res["to_remove"]), 15)
                self.assertEqual(len(res["unchanged_count"] if isinstance(res["unchanged_count"], list) else [1] * res["unchanged_count"]), 5)

    def test_reconciliation_master_lock_concurrency(self):
        """master_node_lock provides reentrancy in same thread and mutual exclusion across threads."""
        from vpn_shop.awg_manager import master_node_lock
        import time

        # 1. Reentrancy test in same thread
        with master_node_lock("nl"):
            with master_node_lock("nl"):
                with master_node_lock("nl"):
                    pass  # Must not deadlock or raise

        # 2. Thread mutual exclusion test
        order = []
        def worker1():
            with master_node_lock("pl"):
                order.append("w1_start")
                time.sleep(0.05)
                order.append("w1_end")

        def worker2():
            time.sleep(0.01)
            with master_node_lock("pl"):
                order.append("w2_start")
                order.append("w2_end")

        t1 = threading.Thread(target=worker1)
        t2 = threading.Thread(target=worker2)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # worker 1 must complete before worker 2 enters
        self.assertEqual(order, ["w1_start", "w1_end", "w2_start", "w2_end"])

    def test_corrupt_config_rejected_in_staging_dir(self):
        """Corrupt configuration is rejected in staging directory and does not overwrite live conf."""
        from vpn_shop.awg_manager import _apply_staged_awg_conf

        executed_scripts = []
        def fake_dex(cmd, inp=None, server_code="nl"):
            executed_scripts.append((cmd, inp))
            if "awg-quick strip" in cmd and "exit 42" in cmd:
                # Simulate validation failure in staging
                raise RuntimeError("Command failed: STAGING_VALIDATION_FAILED (exit 42)")
            return ""

        with patch("vpn_shop.awg_manager._dex", side_effect=fake_dex):
            with self.assertRaises(RuntimeError) as ctx:
                _apply_staged_awg_conf("nl", "CORRUPT CONFIG SYNTAX ERROR")
            self.assertIn("STAGING_VALIDATION_FAILED", str(ctx.exception))

        # Verify staging script contained the security checks
        script, passed_inp = executed_scripts[0]
        self.assertIn("STAGE_DIR=", script)
        self.assertIn("awg-quick strip", script)
        self.assertIn("exit 42", script)
        self.assertIn("chmod 600", script)
        self.assertEqual(passed_inp, "CORRUPT CONFIG SYNTAX ERROR")

    def test_backup_rotation_limits_to_20_and_chmod_600(self):
        """Backup creation uses explicit chmod 600 on the new backup and rotates to latest 20."""
        from vpn_shop.awg_manager import _apply_staged_awg_conf

        captured = {}
        def fake_dex(cmd, inp=None, server_code="nl"):
            captured["cmd"] = cmd
            captured["inp"] = inp
            return ""

        with patch("vpn_shop.awg_manager._dex", side_effect=fake_dex):
            _apply_staged_awg_conf("pl", "[Interface]\nAddress = 10.8.3.1/24\n")

        cmd = captured["cmd"]
        # Explicit chmod 600 on timestamped backup file
        self.assertIn('chmod 600 "$BAK_FILE"', cmd)
        # Rotation keeping latest 20
        self.assertIn("tail -n +21 | xargs -r rm -f", cmd)


if __name__ == "__main__":
    unittest.main()

