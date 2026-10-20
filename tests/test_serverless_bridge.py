from __future__ import annotations

import hashlib
import hmac
import json
import sys
import time
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
VPN_SHOP_DIR = REPO_ROOT / "vpn-shop"
if str(VPN_SHOP_DIR) not in sys.path:
    sys.path.insert(0, str(VPN_SHOP_DIR))

from vpn_shop.bridge import (
    MAX_CLOCK_SKEW_SECONDS,
    sign_bridge_payload,
    verify_and_dispatch_bridge,
)

BRIDGE_SECRET = "test_super_secret_bridge_hmac_key_2026"


class ServerlessBridgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = 1_776_000_000
        self.provisioner = MagicMock()
        self.awg = MagicMock()

    def _call(self, payload: dict[str, Any], *, ts: int | None = None, sig: str | None = None) -> tuple[int, dict[str, Any]]:
        raw = json.dumps(payload).encode("utf-8")
        timestamp = self.now if ts is None else ts
        signature = sign_bridge_payload(BRIDGE_SECRET, timestamp, raw) if sig is None else sig
        headers = {
            "X-Bridge-Timestamp": str(timestamp),
            "X-Bridge-Signature": signature,
        }
        return verify_and_dispatch_bridge(
            headers=headers,
            raw_body=raw,
            secret=BRIDGE_SECRET,
            provisioner=self.provisioner,
            awg_manager=self.awg,
            now_fn=lambda: self.now,
        )

    def test_valid_hmac_signature_accepted(self) -> None:
        self.provisioner.xui_db.find_client_by_email.return_value = {"inbound_id": 2, "client": {"subId": "abc123"}}
        status, data = self._call({"action": "find_client_by_email", "email": "ord_123"})
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"])
        self.assertEqual(data["result"]["client"]["subId"], "abc123")

    def test_ping_action_returns_pong(self) -> None:
        status, data = self._call({"action": "ping"})
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"])
        self.assertEqual(data["result"], "pong")
        self.assertEqual(data["ts"], self.now)

    def test_invalid_hmac_signature_rejected(self) -> None:
        status, data = self._call({"action": "find_client_by_email", "email": "ord_123"}, sig="deadbeef" * 8)
        self.assertEqual(status, 403)
        self.assertEqual(data["error"], "invalid_signature")

    def test_replay_attack_older_than_300s_rejected(self) -> None:
        status, data = self._call(
            {"action": "find_client_by_email", "email": "ord_123"},
            ts=self.now - 301,
        )
        self.assertEqual(status, 401)
        self.assertEqual(data["error"], "timestamp_out_of_window")

    def test_future_timestamp_skew_older_than_300s_rejected(self) -> None:
        status, data = self._call(
            {"action": "find_client_by_email", "email": "ord_123"},
            ts=self.now + 305,
        )
        self.assertEqual(status, 401)
        self.assertEqual(data["error"], "timestamp_out_of_window")

    def test_dispatch_provision_profile(self) -> None:
        self.provisioner.create_profile_for_order.return_value = {
            "profile": {"public_id": "prof_1"},
            "subscription_url": "https://sub.example.com/json/sub1",
            "sub_id": "sub1",
        }
        status, data = self._call(
            {"action": "provision_profile", "order": {"public_id": "ord_1", "transport": "tcp", "duration_days": 30}}
        )
        self.assertEqual(status, 200)
        self.assertEqual(data["result"]["sub_id"], "sub1")
        self.provisioner.create_profile_for_order.assert_called_once()

    def test_dispatch_renew_profile(self) -> None:
        self.provisioner.renew_profile.return_value = {"profile": {"public_id": "prof_1"}, "expires_at": 1800000000}
        status, data = self._call(
            {"action": "renew_profile", "profile_public_id": "prof_1", "duration_days": 90, "device_limit": 6}
        )
        self.assertEqual(status, 200)
        self.provisioner.renew_profile.assert_called_once_with("prof_1", 90, device_limit=6)

    def test_dispatch_build_warp_conf(self) -> None:
        self.awg.get_peer.return_value = None
        self.awg.build_conf.return_value = "[Interface]\nPrivateKey = xxx\n"
        status, data = self._call({"action": "build_warp_conf", "sub_id": "sub123", "server_code": "fi"})
        self.assertEqual(status, 200)
        self.awg.create_peer.assert_called_once_with("sub123", server_code="fi")
        self.assertIn("[Interface]", data["conf"])

    def test_dispatch_find_client_by_sub_id(self) -> None:
        self.provisioner.xui_db.find_client_by_sub_id.return_value = {"client": {"subId": "sub_456"}}
        status, data = self._call({"action": "find_client_by_sub_id", "sub_id": "sub_456"})
        self.assertEqual(status, 200)
        self.assertEqual(data["found"]["client"]["subId"], "sub_456")

    def test_dispatch_get_client_traffic(self) -> None:
        self.provisioner.xui_db.get_client_traffic.return_value = {"up": 1000, "down": 2000}
        status, data = self._call({"action": "get_client_traffic", "email": "usr_test"})
        self.assertEqual(status, 200)
        self.assertEqual(data["traffic"]["up"], 1000)

    def test_dispatch_list_client_traffic(self) -> None:
        self.provisioner.xui_db.list_client_traffic.return_value = [{"email": "usr1"}, {"email": "usr2"}]
        status, data = self._call({"action": "list_client_traffic", "limit": 10})
        self.assertEqual(status, 200)
        self.assertEqual(len(data["rows"]), 2)

    def test_dispatch_set_profile_enabled(self) -> None:
        self.provisioner.set_profile_enabled.return_value = {"enabled": False, "xui_email": "usr1"}
        status, data = self._call({"action": "set_profile_enabled", "profile_public_id": "prof_1", "enabled": False})
        self.assertEqual(status, 200)
        self.assertFalse(data["result"]["enabled"])

    def test_dispatch_provision_profile_without_order(self) -> None:
        self.provisioner._provision_profile.return_value = {
            "sub_id": "sub_trial",
            "xui_client_id": "cl_1",
            "expires_at": 1780000000,
        }
        status, data = self._call({
            "action": "provision_profile",
            "transport": "tcp",
            "duration_days": 7,
            "profile_mode": "standard",
            "notes": "trial",
        })
        self.assertEqual(status, 200)
        self.assertEqual(data["result"]["sub_id"], "sub_trial")

    def test_dispatch_send_subscription_email(self) -> None:
        status, data = self._call({
            "action": "send_subscription_email",
            "customer_email": "buyer@example.com",
            "order_public_id": "ord_999",
            "duration_days": 30,
        })
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"])


class ServerlessBridgeHttpIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import dataclasses
        from http.server import ThreadingHTTPServer
        import tempfile
        import threading
        from vpn_shop.config import load_settings
        from vpn_shop.store import Store
        from vpn_shop.web import RequestHandler, WebCheckout

        cls.tmp_dir = Path(tempfile.mkdtemp())
        db_path = cls.tmp_dir / "vpn_shop.db"
        cls.store = Store(db_path)
        cls.store.init()

        base_settings = load_settings(cls.tmp_dir)
        cls.settings = dataclasses.replace(
            base_settings,
            database_path=db_path,
            serverless_bridge_secret=BRIDGE_SECRET,
            cf_turnstile_enabled=False,
            cf_turnstile_secret_key="",
            web_listen_host="127.0.0.1",
            web_listen_port=0,
        )
        cls.checkout = WebCheckout(cls.settings, cls.store)
        cls.checkout.provisioner = MagicMock()
        RequestHandler.checkout = cls.checkout

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), RequestHandler)
        cls.port = cls.server.server_address[1]
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "server", None):
            cls.server.shutdown()
            cls.server.server_close()
        import shutil
        shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def test_http_post_bridge_success(self):
        import http.client
        self.checkout.provisioner.xui_db = MagicMock()
        self.checkout.provisioner.xui_db.find_client_by_email.return_value = {"client": {"email": "user@test"}}

        ts = int(time.time())
        body = json.dumps({"action": "find_client_by_email", "email": "user@test"}).encode("utf-8")
        sig = sign_bridge_payload(BRIDGE_SECRET, ts, body)

        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request(
            "POST",
            "/api/bridge",
            body=body,
            headers={
                "Content-Type": "application/json",
                "X-Bridge-Timestamp": str(ts),
                "X-Bridge-Signature": sig,
            },
        )
        resp = conn.getresponse()
        data = json.loads(resp.read().decode("utf-8"))
        conn.close()

        self.assertEqual(resp.status, 200)
        self.assertTrue(data.get("ok"))
        self.assertEqual(data["result"]["client"]["email"], "user@test")

    def test_http_post_bridge_unauthorized_missing_headers(self):
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("POST", "/api/bridge", body=b"{}")
        resp = conn.getresponse()
        conn.close()
        self.assertEqual(resp.status, 401)


if __name__ == "__main__":
    unittest.main()

