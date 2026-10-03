import http.client
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from unittest.mock import patch

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SUBJSON_DIR = os.path.join(PROJECT_ROOT, "subjson-service")
VPN_SHOP_DIR = os.path.join(PROJECT_ROOT, "vpn-shop")
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
if SUBJSON_DIR not in sys.path:
    sys.path.insert(0, SUBJSON_DIR)
if VPN_SHOP_DIR not in sys.path:
    sys.path.insert(0, VPN_SHOP_DIR)

os.environ["SECRET_SEGMENT"] = "test-secret-123"  # PLACEHOLDER
os.environ["INTERNAL_SECRET"] = "internal-token-xyz"  # PLACEHOLDER
os.environ["HYSTERIA_SALAMANDER_PASSWORD"] = "dummy_salamander_pwd"  # PLACEHOLDER
os.environ["HYSTERIA_AUTH_PASSWORD"] = "test_auth_pwd"  # PLACEHOLDER
os.environ["PUBLIC_HOST"] = "edge.example.com"
os.environ["PUBLIC_SUBSCRIPTION_ORIGIN"] = "https://sub.example.com"
os.environ["RELAY_PUBLIC_HOST"] = "relay.example.com"

import app


class TestServerHarness:
    def __init__(self):
        self.server = None
        self.port = 0
        self.thread = None

    def start(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), app.RequestHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2.0)


class TestOpenFluxEndpoints(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="oflux_test_")
        self.db_path = os.path.join(self.temp_dir, "vpn_shop.db")
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                public_id TEXT UNIQUE,
                xui_inbound_id INTEGER,
                transport TEXT,
                profile_mode TEXT,
                family_label TEXT,
                xui_email TEXT,
                xui_client_id TEXT,
                status TEXT,
                created_at INTEGER,
                expires_at INTEGER,
                last_renewed_at INTEGER,
                deleted_at INTEGER,
                notes TEXT
            )
        """)
        now = int(time.time())
        conn.execute("""
            INSERT INTO profiles (public_id, transport, profile_mode, xui_email, status, created_at, expires_at)
            VALUES ('user123', 'tcp', 'anonymous', 'user123@example.com', 'active', ?, ?)
        """, (now, now + 30 * 86400))
        conn.commit()
        conn.close()

        os.environ["STORE_DB_PATH"] = self.db_path
        app.STORE_DB_PATH = self.db_path
        self.harness = TestServerHarness()
        self.harness.start()

    def tearDown(self):
        self.harness.stop()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def request(self, method: str, path: str, body: dict = None) -> tuple[int, dict | bytes, dict]:
        conn = http.client.HTTPConnection("127.0.0.1", self.harness.port, timeout=5)
        headers = {}
        payload = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            payload = json.dumps(body).encode("utf-8")
        conn.request(method, path, body=payload, headers=headers)
        resp = conn.getresponse()
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        raw = resp.read()
        conn.close()

        content_type = resp_headers.get("content-type", "").lower()
        if "application/json" in content_type:
            try:
                parsed = json.loads(raw.decode("utf-8"))
                return resp.status, parsed, resp_headers
            except Exception:
                return resp.status, raw, resp_headers
        return resp.status, raw, resp_headers

    def test_openflux_slot_lifecycle_flow(self):
        with patch("vpn_shop.openflux_manager.rclone_create_user_doc", return_value=True), \
             patch("vpn_shop.openflux_manager.rclone_get_public_link", return_value="https://cloud.mail.ru/public/NL/doc1"), \
             patch("vpn_shop.openflux_manager.start_openflux_worker", return_value=True), \
             patch("vpn_shop.openflux_manager.stop_openflux_worker", return_value=True), \
             patch("vpn_shop.openflux_manager.rename_openflux_worker", return_value=True), \
             patch("vpn_shop.openflux_manager.rclone_delete_user_doc", return_value=True):

            # 1. State before activation
            status, body, _ = self.request("GET", "/sub/openflux/user123/state")
            self.assertEqual(status, HTTPStatus.OK)
            self.assertTrue(body["ok"])
            self.assertEqual(body["slot"]["status"], "uninitialized")
            self.assertEqual(body["slot"]["profile_public_id"], "user123")

            # 2. Activate slot
            status, body, _ = self.request("POST", "/sub/openflux/user123/activate")
            self.assertEqual(status, HTTPStatus.OK)
            self.assertTrue(body["ok"])
            self.assertEqual(body["slot"]["status"], "active")
            self.assertEqual(body["slot"]["active_server"], "nl")
            self.assertTrue(body["slot"]["active_link"].startswith("openflux://v1/"))

            # 3. QR code for active slot
            status, qr_bytes, headers = self.request("GET", "/sub/openflux/user123/qr?target=active")
            self.assertEqual(status, HTTPStatus.OK)
            self.assertIn("image/png", headers["content-type"])
            self.assertTrue(qr_bytes.startswith(b"\x89PNG"))

            # 4. Prepare switch to PL
            with patch("vpn_shop.openflux_manager.rclone_get_public_link", return_value="https://cloud.mail.ru/public/PL/doc2"):
                status, body, _ = self.request("POST", "/sub/openflux/user123/switch/prepare", {"target": "pl"})
                self.assertEqual(status, HTTPStatus.OK)
                self.assertTrue(body["ok"])
                self.assertEqual(body["slot"]["status"], "migrating")
                self.assertEqual(body["slot"]["active_server"], "nl")
                self.assertEqual(body["slot"]["pending_server"], "pl")
                self.assertTrue(body["slot"]["pending_link"].startswith("openflux://v1/"))

            # 5. QR code for pending slot
            status, qr_bytes, headers = self.request("GET", "/sub/openflux/user123/qr?target=pending")
            self.assertEqual(status, HTTPStatus.OK)
            self.assertIn("image/png", headers["content-type"])
            self.assertTrue(qr_bytes.startswith(b"\x89PNG"))

            # 6. Cancel switch
            status, body, _ = self.request("POST", "/sub/openflux/user123/switch/cancel")
            self.assertEqual(status, HTTPStatus.OK)
            self.assertTrue(body["ok"])
            self.assertEqual(body["slot"]["status"], "active")
            self.assertEqual(body["slot"]["active_server"], "nl")
            self.assertIsNone(body["slot"]["pending_server"])

            # 7. Prepare switch to FI and Confirm
            with patch("vpn_shop.openflux_manager.rclone_get_public_link", return_value="https://cloud.mail.ru/public/FI/doc3"):
                status, body, _ = self.request("POST", "/sub/openflux/user123/switch/prepare", {"target": "fi"})
                self.assertEqual(status, HTTPStatus.OK)
                self.assertEqual(body["slot"]["status"], "migrating")

            status, body, _ = self.request("POST", "/sub/openflux/user123/switch/confirm")
            self.assertEqual(status, HTTPStatus.OK)
            self.assertTrue(body["ok"])
            self.assertEqual(body["slot"]["status"], "active")
            self.assertEqual(body["slot"]["active_server"], "fi")
            self.assertIsNone(body["slot"]["pending_server"])


if __name__ == "__main__":
    unittest.main()
