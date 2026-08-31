#!/usr/bin/env python3
"""
Unit tests for Quiesce Lock and Lease management in subjson-service.
"""
import unittest
import time
import os
import json
import threading

# Set required mock environment variables before importing app
os.environ.setdefault("HYSTERIA_SALAMANDER_PASSWORD", "test-salamander-pass")
os.environ.setdefault("HYSTERIA_AUTH_PASSWORD", "test-auth-pass")
os.environ.setdefault("TCP_REALITY_PUBLIC_KEY", "test-pub-key")
os.environ.setdefault("TCP_REALITY_SHORT_ID", "1234abcd")
os.environ.setdefault("TCP_REALITY_SNI_CLASSIC", "sber.ru")
os.environ.setdefault("TCP_REALITY_SNI_FAST", "st.kinopoisk.ru")
os.environ.setdefault("GRPC_REALITY_PUBLIC_KEY", "test-grpc-pub-key")
os.environ.setdefault("GRPC_REALITY_SHORT_ID", "4d7a")
os.environ.setdefault("GRPC_REALITY_SNI", "vk.com")
os.environ.setdefault("SECRET_SEGMENT", "test-secret-segment")
os.environ.setdefault("INTERNAL_SECRET", "test-internal-token-12345")
os.environ.setdefault("XUI_DB_PATH", ":memory:")
os.environ.setdefault("STATIC_JSON_CONFIG_DIR", "/tmp")

# Load subjson.env if present
env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "subjson.env")
if os.path.exists(env_file):
    with open(env_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ[k.strip()] = v.strip()

import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import app
from http.server import HTTPServer
from http.client import HTTPConnection

class TestQuiesceLogic(unittest.TestCase):
    def setUp(self):
        # Reset quiesce state before each test
        with app.QUIESCE_LOCK:
            app.QUIESCE_ACTIVE = False
            app.QUIESCE_LEASE_UNTIL = 0.0

    def tearDown(self):
        with app.QUIESCE_LOCK:
            app.QUIESCE_ACTIVE = False
            app.QUIESCE_LEASE_UNTIL = 0.0

    def test_is_quiesced_basic(self):
        self.assertFalse(app.is_quiesced())
        with app.QUIESCE_LOCK:
            app.QUIESCE_ACTIVE = True
            app.QUIESCE_LEASE_UNTIL = time.time() + 30.0
        self.assertTrue(app.is_quiesced())

    def test_is_quiesced_timeout_expiry(self):
        with app.QUIESCE_LOCK:
            app.QUIESCE_ACTIVE = True
            app.QUIESCE_LEASE_UNTIL = time.time() - 0.1 # already expired
        self.assertFalse(app.is_quiesced())
        # State should be reset
        self.assertFalse(app.QUIESCE_ACTIVE)
        self.assertEqual(app.QUIESCE_LEASE_UNTIL, 0.0)

class TestQuiesceHTTPHandler(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start a local test server
        os.environ["SECRET_SEGMENT"] = "test-secret-segment"  # PLACEHOLDER
        os.environ["INTERNAL_SECRET"] = "test-internal-token-12345"  # PLACEHOLDER
        app.SECRET_SEGMENT = "test-secret-segment"  # PLACEHOLDER
        app.INTERNAL_SECRET = "test-internal-token-12345"  # PLACEHOLDER
        cls.server = HTTPServer(("127.0.0.1", 0), app.RequestHandler)
        cls.port = cls.server.server_port
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        with app.QUIESCE_LOCK:
            app.QUIESCE_ACTIVE = False
            app.QUIESCE_LEASE_UNTIL = 0.0

    def _request(self, method: str, path: str, headers: dict = None, body: str = None):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=5)
        h = headers or {}
        conn.request(method, path, body=body, headers=h)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8")
        conn.close()
        return resp.status, resp.getheaders(), data

    def test_quiesce_unauthorized(self):
        status, _, data = self._request("POST", "/test-secret-segment/internal-quiesce/start")
        self.assertEqual(status, 403)
        res = json.loads(data)
        self.assertEqual(res.get("error"), "forbidden")

    def test_quiesce_start_and_lease_and_release(self):
        auth_header = {"X-Internal-Secret": "test-internal-token-12345"}

        # 1. Start quiesce
        status, _, data = self._request("POST", "/test-secret-segment/internal-quiesce/start", headers=auth_header)
        self.assertEqual(status, 200)
        res = json.loads(data)
        self.assertEqual(res.get("status"), "QUIESCED_ACK")
        self.assertTrue(res.get("ack"))
        self.assertEqual(res.get("lease_ttl"), 30.0)
        self.assertTrue(app.is_quiesced())

        # 2. Extend lease
        status, _, data = self._request("POST", "/test-secret-segment/internal-quiesce/lease", headers=auth_header)
        self.assertEqual(status, 200)
        res = json.loads(data)
        self.assertEqual(res.get("status"), "QUIESCED_ACK")
        self.assertTrue(res.get("lease_extended"))
        self.assertEqual(res.get("expires_in"), 30.0)
        self.assertTrue(app.is_quiesced())

        # 3. Release quiesce
        status, _, data = self._request("POST", "/test-secret-segment/internal-quiesce/release", headers=auth_header)
        self.assertEqual(status, 200)
        res = json.loads(data)
        self.assertEqual(res.get("status"), "UNQUIESCED_ACK")
        self.assertTrue(res.get("quiesce_released"))
        self.assertFalse(app.is_quiesced())

    def test_quiesce_lease_when_not_quiesced(self):
        auth_header = {"X-Internal-Secret": "test-internal-token-12345"}
        status, _, data = self._request("POST", "/test-secret-segment/internal-quiesce/lease", headers=auth_header)
        self.assertEqual(status, 400)
        res = json.loads(data)
        self.assertEqual(res.get("status"), "NOT_QUIESCED")
        self.assertEqual(res.get("error"), "not_quiesced")

    def test_quiesce_blocks_post_and_bot_routes(self):
        auth_header = {"X-Internal-Secret": "test-internal-token-12345"}
        # Start quiesce
        self._request("POST", "/test-secret-segment/internal-quiesce/start", headers=auth_header)
        self.assertTrue(app.is_quiesced())

        # POST renewal should be blocked with 503
        status, _, data = self._request("POST", "/test-secret-segment/renew/sub123", body="duration_days=30")
        self.assertEqual(status, 503)
        res = json.loads(data)
        self.assertEqual(res.get("error"), "quiesce_merge_in_progress")

        # GET healthz should still succeed (200)
        status, _, data = self._request("GET", "/healthz")
        self.assertEqual(status, 200)

if __name__ == "__main__":
    unittest.main()
