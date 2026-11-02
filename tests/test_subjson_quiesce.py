#!/usr/bin/env python3
"""
Unit and concurrency stress tests for Quiesce Lock and Lease management in subjson-service.
Covers basic state machine, HTTP endpoints, unauthorized rejection, lease expiration, and 30-worker concurrent stress.
"""
from __future__ import annotations

import concurrent.futures
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import threading
import time
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
SUBJSON_DIR = REPO_ROOT / "subjson-service"
VPN_SHOP_DIR = REPO_ROOT / "vpn-shop"
if str(SUBJSON_DIR) not in sys.path:
    sys.path.insert(0, str(SUBJSON_DIR))
if str(VPN_SHOP_DIR) not in sys.path:
    sys.path.insert(0, str(VPN_SHOP_DIR))

os.environ.setdefault("HYSTERIA_SALAMANDER_PASSWORD", "test-salamander-pass")
os.environ.setdefault("HYSTERIA_AUTH_PASSWORD", "test-auth-pass")
os.environ.setdefault("TCP_REALITY_PUBLIC_KEY", "test-pub-key")
os.environ.setdefault("TCP_REALITY_SHORT_ID", "1234abcd")
os.environ.setdefault("TCP_REALITY_SNI_CLASSIC", "sber.ru")
os.environ.setdefault("TCP_REALITY_SNI_FAST", "st.kinopoisk.ru")
os.environ.setdefault("GRPC_REALITY_PUBLIC_KEY", "test-grpc-pub-key")
os.environ.setdefault("GRPC_REALITY_SHORT_ID", "4d7a")
os.environ.setdefault("GRPC_REALITY_SNI", "vk.com")
os.environ.setdefault("SECRET_SEGMENT", "test-secret-quiesce")
os.environ.setdefault("INTERNAL_SECRET", "super-internal-quiesce-secret-xyz")
os.environ.setdefault("XUI_DB_PATH", ":memory:")
os.environ.setdefault("STATIC_JSON_CONFIG_DIR", "/tmp")

import app


class TestQuiesceLogic(unittest.TestCase):
    def setUp(self):
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
            app.QUIESCE_LEASE_UNTIL = time.time() - 0.1
        self.assertFalse(app.is_quiesced())


class TestQuiesceHTTPAndStressHarness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.orig_secret_seg = app.SECRET_SEGMENT
        cls.orig_internal_sec = app.INTERNAL_SECRET
        os.environ["SECRET_SEGMENT"] = "test-secret-quiesce"  # PLACEHOLDER
        os.environ["INTERNAL_SECRET"] = "super-internal-quiesce-secret-xyz"  # PLACEHOLDER
        app.SECRET_SEGMENT = "test-secret-quiesce"  # PLACEHOLDER
        app.INTERNAL_SECRET = "super-internal-quiesce-secret-xyz"  # PLACEHOLDER
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), app.RequestHandler)
        cls.port = cls.server.server_port
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.auth_headers = {"X-Internal-Secret": app.INTERNAL_SECRET}

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        app.SECRET_SEGMENT = cls.orig_secret_seg  # PLACEHOLDER
        app.INTERNAL_SECRET = cls.orig_internal_sec  # PLACEHOLDER

    def setUp(self):
        app.SECRET_SEGMENT = "test-secret-quiesce"  # PLACEHOLDER
        app.INTERNAL_SECRET = "super-internal-quiesce-secret-xyz"  # PLACEHOLDER
        os.environ["SECRET_SEGMENT"] = "test-secret-quiesce"  # PLACEHOLDER
        os.environ["INTERNAL_SECRET"] = "super-internal-quiesce-secret-xyz"  # PLACEHOLDER
        with app.QUIESCE_LOCK:
            app.QUIESCE_ACTIVE = False
            app.QUIESCE_LEASE_UNTIL = 0.0

    def tearDown(self):
        with app.QUIESCE_LOCK:
            app.QUIESCE_ACTIVE = False
            app.QUIESCE_LEASE_UNTIL = 0.0

    def _request(self, method: str, path: str, headers: dict | None = None, body: str | None = None):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            data = resp.read().decode("utf-8")
            return resp.status, resp.getheaders(), data
        finally:
            conn.close()

    def test_unauthorized_access_variations(self):
        paths = [
            f"/{app.SECRET_SEGMENT}/internal-quiesce/start",
            f"/{app.SECRET_SEGMENT}/internal-quiesce/lease",
            f"/{app.SECRET_SEGMENT}/internal-quiesce/release",
        ]
        bad_headers_list = [
            {},
            {"X-Internal-Secret": ""},
            {"X-Internal-Secret": "wrong-secret"},
            {"X-Internal-Secret": "super-internal-quiesce-secret-xy"},
            {"X-Other-Header": app.INTERNAL_SECRET},
        ]
        for p in paths:
            for bad_h in bad_headers_list:
                status, _, data = self._request("POST", p, headers=bad_h)
                self.assertEqual(status, 403, f"Expected 403 on {p} with headers {bad_h}")
                res = json.loads(data)
                self.assertEqual(res.get("error"), "forbidden")
                self.assertFalse(app.is_quiesced())

    def test_unknown_quiesce_action_and_wrong_segment(self):
        status, _, data = self._request(
            "POST",
            f"/{app.SECRET_SEGMENT}/internal-quiesce/invalid_action_xyz",
            headers=self.auth_headers,
        )
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(data).get("error"), "unknown_quiesce_action")

        status2, _, _ = self._request(
            "POST",
            "/wrong-segment/internal-quiesce/start",
            headers=self.auth_headers,
        )
        self.assertNotEqual(status2, 200)
        self.assertFalse(app.is_quiesced())

    def test_lease_when_not_quiesced(self):
        status, _, data = self._request(
            "POST",
            f"/{app.SECRET_SEGMENT}/internal-quiesce/lease",
            headers=self.auth_headers,
        )
        self.assertEqual(status, 400)
        res = json.loads(data)
        self.assertEqual(res.get("status"), "NOT_QUIESCED")

    def test_lease_expiration_and_route_blocking_lifecycle(self):
        status, _, data = self._request(
            "POST",
            f"/{app.SECRET_SEGMENT}/internal-quiesce/start",
            headers=self.auth_headers,
        )
        self.assertEqual(status, 200)
        res = json.loads(data)
        self.assertEqual(res.get("status"), "QUIESCED_ACK")
        self.assertTrue(app.is_quiesced())

        # Extend lease
        status, _, data = self._request(
            "POST",
            f"/{app.SECRET_SEGMENT}/internal-quiesce/lease",
            headers=self.auth_headers,
        )
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(data).get("lease_extended"))

        # Read-only healthz and legal terms succeed
        status, _, _ = self._request("GET", "/healthz")
        self.assertEqual(status, 200)
        status, _, _ = self._request("GET", f"/{app.SECRET_SEGMENT}/legal/terms")
        self.assertEqual(status, 200)

        # POST and bot routes blocked with 503
        status, _, data = self._request("POST", f"/{app.SECRET_SEGMENT}/renew/sub1", body="duration_days=30")
        self.assertEqual(status, 503)
        self.assertIn("quiesce_merge_in_progress", data)

        # Expire lease
        with app.QUIESCE_LOCK:
            app.QUIESCE_LEASE_UNTIL = time.time() - 1.0
        self.assertFalse(app.is_quiesced())

        # Release explicitly
        status, _, data = self._request(
            "POST",
            f"/{app.SECRET_SEGMENT}/internal-quiesce/release",
            headers=self.auth_headers,
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data).get("status"), "UNQUIESCED_ACK")
        self.assertFalse(app.is_quiesced())

    def test_in_memory_and_http_concurrency_hammer(self):
        errors = []
        num_workers = 20
        iterations_per_worker = 8

        def worker_task(worker_id: int):
            try:
                for i in range(iterations_per_worker):
                    op = (worker_id + i) % 5
                    if op == 0:
                        status, _, data = self._request(
                            "POST",
                            f"/{app.SECRET_SEGMENT}/internal-quiesce/start",
                            headers=self.auth_headers,
                        )
                        if status != 200:
                            errors.append(f"start failed: {status} {data}")
                    elif op == 1:
                        status, _, data = self._request(
                            "POST",
                            f"/{app.SECRET_SEGMENT}/internal-quiesce/lease",
                            headers=self.auth_headers,
                        )
                        if status not in (200, 400):
                            errors.append(f"lease unexpected: {status} {data}")
                    elif op == 2:
                        status, _, data = self._request(
                            "POST",
                            f"/{app.SECRET_SEGMENT}/internal-quiesce/release",
                            headers=self.auth_headers,
                        )
                        if status != 200:
                            errors.append(f"release failed: {status} {data}")
                    elif op == 3:
                        status, _, _ = self._request("GET", "/healthz")
                        if status != 200:
                            errors.append(f"healthz failed: {status}")
                    elif op == 4:
                        status, _, _ = self._request(
                            "POST",
                            f"/{app.SECRET_SEGMENT}/internal-quiesce/start",
                            headers={"X-Internal-Secret": "bogus"},
                        )
                        if status != 403:
                            errors.append(f"unauthorized returned {status}")
            except Exception as exc:
                errors.append(str(exc))

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(worker_task, wid) for wid in range(num_workers)]
            concurrent.futures.wait(futures)

        self.assertEqual(len(errors), 0, f"Concurrent hammer errors: {errors[:5]}")


if __name__ == "__main__":
    unittest.main()
