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


if __name__ == "__main__":
    unittest.main()
