#!/usr/bin/env python3
"""
Adversarial & Stress Test Suite for Quiesce Lock and Lease Management in subjson-service.
Author: challenger_v7_1
"""
import unittest
import time
import os
import json
import threading
import concurrent.futures
from http.server import ThreadingHTTPServer
from http.client import HTTPConnection

# Configure environment variables
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

import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app

class TestQuiesceStressHarness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["SECRET_SEGMENT"] = "test-secret-quiesce"  # PLACEHOLDER
        os.environ["INTERNAL_SECRET"] = "super-internal-quiesce-secret-xyz"  # PLACEHOLDER
        app.SECRET_SEGMENT = "test-secret-quiesce"  # PLACEHOLDER
        app.INTERNAL_SECRET = "super-internal-quiesce-secret-xyz"  # PLACEHOLDER
        # Match production ThreadingHTTPServer
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), app.RequestHandler)
        cls.port = cls.server.server_port
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.auth_headers = {"X-Internal-Secret": app.INTERNAL_SECRET}

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        with app.QUIESCE_LOCK:
            app.QUIESCE_ACTIVE = False
            app.QUIESCE_LEASE_UNTIL = 0.0

    def tearDown(self):
        with app.QUIESCE_LOCK:
            app.QUIESCE_ACTIVE = False
            app.QUIESCE_LEASE_UNTIL = 0.0

    def _request(self, method: str, path: str, headers: dict = None, body: str = None):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            h = headers or {}
            conn.request(method, path, body=body, headers=h)
            resp = conn.getresponse()
            data = resp.read().decode("utf-8")
            return resp.status, resp.getheaders(), data
        finally:
            conn.close()

    # --------------------------------------------------------------------------
    # 1. Security & Authentication Boundary Tests
    # --------------------------------------------------------------------------
    def test_unauthorized_access_variations(self):
        """Verify that any missing, invalid, or empty secret token is strictly rejected."""
        paths = [
            f"/{app.SECRET_SEGMENT}/internal-quiesce/start",
            f"/{app.SECRET_SEGMENT}/internal-quiesce/lease",
            f"/{app.SECRET_SEGMENT}/internal-quiesce/release",
        ]
        bad_headers_list = [
            {},
            {"X-Internal-Secret": ""},
            {"X-Internal-Secret": "wrong-secret"},
            {"X-Internal-Secret": "super-internal-quiesce-secret-xy"}, # 1 char missing
            {"X-Other-Header": app.INTERNAL_SECRET},
        ]

        for p in paths:
            for bad_h in bad_headers_list:
                status, _, data = self._request("POST", p, headers=bad_h)
                self.assertEqual(status, 403, f"Expected 403 on {p} with headers {bad_h}")
                res = json.loads(data)
                self.assertEqual(res.get("error"), "forbidden")
                self.assertFalse(app.is_quiesced(), "Unauthorized call modified quiesce state!")

    def test_unknown_quiesce_action(self):
        """Verify that unknown actions return 404 without altering state."""
        status, _, data = self._request(
            "POST",
            f"/{app.SECRET_SEGMENT}/internal-quiesce/invalid_action_xyz",
            headers=self.auth_headers
        )
        self.assertEqual(status, 404)
        res = json.loads(data)
        self.assertEqual(res.get("error"), "unknown_quiesce_action")

    def test_wrong_secret_segment(self):
        """Verify that accessing wrong secret segment does not trigger quiesce."""
        status, _, _ = self._request(
            "POST",
            "/wrong-segment/internal-quiesce/start",
            headers=self.auth_headers
        )
        # Should not be 200 QUIESCED_ACK
        self.assertNotEqual(status, 200)
        self.assertFalse(app.is_quiesced())

    # --------------------------------------------------------------------------
    # 2. Lease Expiration Without Heartbeat & Recovery
    # --------------------------------------------------------------------------
    def test_lease_expiration_lifecycle(self):
        """Verify full lifecycle: start -> active -> expire -> lease rejected -> restart."""
        # 1. Start quiesce
        status, _, data = self._request(
            "POST",
            f"/{app.SECRET_SEGMENT}/internal-quiesce/start",
            headers=self.auth_headers
        )
        self.assertEqual(status, 200)
        res = json.loads(data)
        self.assertEqual(res.get("status"), "QUIESCED_ACK")
        self.assertEqual(res.get("lease_ttl"), 30.0)
        self.assertTrue(app.is_quiesced())

        # 2. POST is blocked during active lease
        status, _, data = self._request("POST", f"/{app.SECRET_SEGMENT}/renew/sub1", body="duration_days=30")
        self.assertEqual(status, 503)

        # 3. Simulate passage of 31 seconds by modifying QUIESCE_LEASE_UNTIL into the past
        with app.QUIESCE_LOCK:
            app.QUIESCE_LEASE_UNTIL = time.time() - 1.0

        # 4. Verification that is_quiesced() automatically flips to False and clears state
        self.assertFalse(app.is_quiesced())
        with app.QUIESCE_LOCK:
            self.assertFalse(app.QUIESCE_ACTIVE)
            self.assertEqual(app.QUIESCE_LEASE_UNTIL, 0.0)

        # 5. Heartbeat after expiration must return 400 NOT_QUIESCED
        status, _, data = self._request(
            "POST",
            f"/{app.SECRET_SEGMENT}/internal-quiesce/lease",
            headers=self.auth_headers
        )
        self.assertEqual(status, 400)
        res = json.loads(data)
        self.assertEqual(res.get("status"), "NOT_QUIESCED")

        # 6. Restarting quiesce works properly
        status, _, data = self._request(
            "POST",
            f"/{app.SECRET_SEGMENT}/internal-quiesce/start",
            headers=self.auth_headers
        )
        self.assertEqual(status, 200)
        self.assertTrue(app.is_quiesced())

        # 7. Release explicitly
        status, _, data = self._request(
            "POST",
            f"/{app.SECRET_SEGMENT}/internal-quiesce/release",
            headers=self.auth_headers
        )
        self.assertEqual(status, 200)
        res = json.loads(data)
        self.assertEqual(res.get("status"), "UNQUIESCED_ACK")
        self.assertFalse(app.is_quiesced())

    # --------------------------------------------------------------------------
    # 3. Route Behavior Under Quiesce
    # --------------------------------------------------------------------------
    def test_route_behavior_under_quiesce(self):
        """Verify healthz and legal terms are allowed while mutations are blocked."""
        # Unquiesced state: healthz is 200
        status, _, _ = self._request("GET", "/healthz")
        self.assertEqual(status, 200)

        # Quiesce the service
        self._request("POST", f"/{app.SECRET_SEGMENT}/internal-quiesce/start", headers=self.auth_headers)
        self.assertTrue(app.is_quiesced())

        # Read-only healthz and legal terms MUST succeed
        status, _, data = self._request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertIn("ok", data)

        status, _, data = self._request("GET", f"/{app.SECRET_SEGMENT}/legal/terms")
        self.assertEqual(status, 200)

        # Bot and mutation routes MUST be blocked with 503
        status, _, data = self._request("POST", f"/{app.SECRET_SEGMENT}/renew/sub1")
        self.assertEqual(status, 503)
        self.assertIn("quiesce_merge_in_progress", data)

        status, _, data = self._request("GET", f"/{app.SECRET_SEGMENT}/bot-query")
        self.assertEqual(status, 503)

        # Release quiesce
        self._request("POST", f"/{app.SECRET_SEGMENT}/internal-quiesce/release", headers=self.auth_headers)
        self.assertFalse(app.is_quiesced())

    # --------------------------------------------------------------------------
    # 4. Pure In-Memory Concurrency Stress on Quiesce Lock
    # --------------------------------------------------------------------------
    def test_in_memory_concurrency_race(self):
        """Stress-test is_quiesced() and lock state changes with 100 concurrent threads."""
        errors = []
        num_threads = 100
        rounds = 200

        def runner(tid: int):
            try:
                for r in range(rounds):
                    action = (tid + r) % 4
                    if action == 0:
                        with app.QUIESCE_LOCK:
                            app.QUIESCE_ACTIVE = True
                            app.QUIESCE_LEASE_UNTIL = time.time() + 30.0
                    elif action == 1:
                        with app.QUIESCE_LOCK:
                            if app.QUIESCE_ACTIVE and time.time() <= app.QUIESCE_LEASE_UNTIL:
                                app.QUIESCE_LEASE_UNTIL = time.time() + 30.0
                    elif action == 2:
                        with app.QUIESCE_LOCK:
                            app.QUIESCE_ACTIVE = False
                            app.QUIESCE_LEASE_UNTIL = 0.0
                    else:
                        q = app.is_quiesced()
                        self.assertIsInstance(q, bool)
            except Exception as e:
                errors.append(f"Thread {tid} failed: {e}")

        threads = [threading.Thread(target=runner, args=(i,)) for i in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"In-memory race errors: {errors}")

    # --------------------------------------------------------------------------
    # 5. HTTP Concurrency Stress Test
    # --------------------------------------------------------------------------
    def test_concurrent_quiesce_http_hammer(self):
        """Execute 30 concurrent worker threads firing start/lease/release/queries simultaneously."""
        errors = []
        num_workers = 30
        iterations_per_worker = 10

        def worker_task(worker_id: int):
            try:
                for i in range(iterations_per_worker):
                    op = (worker_id + i) % 5
                    if op == 0:
                        # start
                        status, _, data = self._request(
                            "POST",
                            f"/{app.SECRET_SEGMENT}/internal-quiesce/start",
                            headers=self.auth_headers
                        )
                        if status != 200:
                            errors.append(f"Worker {worker_id} start failed: {status} {data}")
                    elif op == 1:
                        # lease
                        status, _, data = self._request(
                            "POST",
                            f"/{app.SECRET_SEGMENT}/internal-quiesce/lease",
                            headers=self.auth_headers
                        )
                        # Could be 200 (if active) or 400 (if released by another thread)
                        if status not in (200, 400):
                            errors.append(f"Worker {worker_id} lease unexpected status: {status} {data}")
                    elif op == 2:
                        # release
                        status, _, data = self._request(
                            "POST",
                            f"/{app.SECRET_SEGMENT}/internal-quiesce/release",
                            headers=self.auth_headers
                        )
                        if status != 200:
                            errors.append(f"Worker {worker_id} release failed: {status} {data}")
                    elif op == 3:
                        # healthz check (should ALWAYS be 200)
                        status, _, data = self._request("GET", "/healthz")
                        if status != 200:
                            errors.append(f"Worker {worker_id} healthz failed: {status}")
                    elif op == 4:
                        # unauthorized attempt (should ALWAYS be 403)
                        status, _, data = self._request(
                            "POST",
                            f"/{app.SECRET_SEGMENT}/internal-quiesce/start",
                            headers={"X-Internal-Secret": "bogus"}
                        )
                        if status != 403:
                            errors.append(f"Worker {worker_id} unauthorized attempt returned {status}")
            except Exception as e:
                errors.append(f"Worker {worker_id} exception: {e}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(worker_task, wid) for wid in range(num_workers)]
            concurrent.futures.wait(futures)

        self.assertEqual(len(errors), 0, f"Concurrent hammer detected {len(errors)} errors: {errors[:5]}")

        # Final state check: after releasing, lock and state must be consistent
        with app.QUIESCE_LOCK:
            app.QUIESCE_ACTIVE = False
            app.QUIESCE_LEASE_UNTIL = 0.0

        self.assertFalse(app.is_quiesced())

if __name__ == "__main__":
    unittest.main()
