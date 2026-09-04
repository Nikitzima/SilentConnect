"""
Comprehensive Endpoints, Routing, Response Headers, Quiesce Lock,
Rate Limiter, and Web UI Integration Test Suite for subjson-service/app.py.
"""

import copy
import http.client
import json
import os
import shutil
import socket
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from http import HTTPStatus
from http.server import ThreadingHTTPServer

# Ensure project root and subjson-service are in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SUBJSON_DIR = os.path.join(PROJECT_ROOT, "subjson-service")
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
if SUBJSON_DIR not in sys.path:
    sys.path.insert(0, SUBJSON_DIR)

# Set necessary test environment variables before importing app
os.environ["SECRET_SEGMENT"] = "test-secret-123"  # PLACEHOLDER
os.environ["INTERNAL_SECRET"] = "internal-token-xyz"  # PLACEHOLDER
os.environ["HYSTERIA_SALAMANDER_PASSWORD"] = "dummy_salamander_pwd"  # PLACEHOLDER
os.environ["HYSTERIA_AUTH_PASSWORD"] = "test_auth_pwd"  # PLACEHOLDER
os.environ["PUBLIC_HOST"] = "edge.example.com"
os.environ["PUBLIC_SUBSCRIPTION_ORIGIN"] = "https://sub.example.com"
os.environ["RELAY_PUBLIC_HOST"] = "relay.example.com"

import app


class TestServerHarness:
    """Helper to start and stop an in-process ThreadingHTTPServer with RequestHandler."""

    def __init__(self):
        self.server = None
        self.port = 0
        self.thread = None

    def start(self):
        # Bind to port 0 to get an ephemeral free port
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), app.RequestHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None

    def request(self, method: str, path: str, headers: dict = None, body: bytes = None) -> tuple[int, dict, bytes]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        req_headers = headers or {}
        conn.request(method, path, body=body, headers=req_headers)
        res = conn.getresponse()
        resp_headers = {k.lower(): v for k, v in res.getheaders()}
        resp_body = res.read()
        conn.close()
        return res.status, resp_headers, resp_body


class TestRequestHandlerRoutingAndEndpoints(unittest.TestCase):
    """Test full routing matrix, response codes, and content headers."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(prefix="endpoint_test_")
        cls.db_path = os.path.join(cls.temp_dir, "x-ui-test.db")
        cls.shop_db_path = os.path.join(cls.temp_dir, "vpn_shop.db")
        test_db_source = os.path.join(PROJECT_ROOT, "бэкапы_баз_данных", "x-ui-test.db")
        if os.path.exists(test_db_source):
            shutil.copyfile(test_db_source, cls.db_path)
        else:
            conn_xui = sqlite3.connect(cls.db_path)
            conn_xui.execute("""
                CREATE TABLE inbounds (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    up INTEGER,
                    down INTEGER,
                    total INTEGER,
                    remark TEXT,
                    enable INTEGER,
                    expiry_time INTEGER,
                    listen TEXT,
                    port INTEGER,
                    protocol TEXT,
                    settings TEXT,
                    stream_settings TEXT,
                    tag TEXT,
                    sniffing TEXT
                )
            """)
            settings_json = json.dumps({
                "clients": [
                    {
                        "id": "034d060d-8f33-4280-b22c-6b128813646f",
                        "email": "MainDefConf",
                        "limitIp": 0,
                        "totalGB": 0,
                        "expiryTime": 0,
                        "enable": True,
                        "tgId": "",
                        "subId": "MainDefConf",
                        "reset": 0
                    }
                ]
            })
            conn_xui.execute("""
                INSERT INTO inbounds (id, user_id, up, down, total, remark, enable, expiry_time, listen, port, protocol, settings, stream_settings, tag, sniffing)
                VALUES (2, 1, 0, 0, 0, 'tcp-inbound', 1, 0, '0.0.0.0', 443, 'vless', ?, '{}', 'inbound-443', '{}')
            """, (settings_json,))
            conn_xui.commit()
            conn_xui.close()
        app.XUI_DB_PATH = cls.db_path
        os.environ["XUI_DB_PATH"] = cls.db_path

        # Setup shop db
        conn = sqlite3.connect(cls.shop_db_path)
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
            INSERT INTO profiles (public_id, xui_inbound_id, transport, profile_mode, xui_email, xui_client_id, status, created_at, expires_at)
            VALUES ('prf_active1', 2, 'tcp', 'anonymous', 'MainDefConf', '034d060d-8f33-4280-b22c-6b128813646f', 'active', ?, ?)
        """, (now, now + 30 * 86400))
        conn.commit()
        conn.close()
        os.environ["STORE_DB_PATH"] = cls.shop_db_path

        cls.harness = TestServerHarness()
        cls.harness.start()
        cls.secret = app.SECRET_SEGMENT
        cls.sub_id = "MainDefConf"

    @classmethod
    def tearDownClass(cls):
        cls.harness.stop()
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_healthz_endpoint(self):
        """Verify /healthz returns 200 OK and {'ok': True}."""
        status, headers, body = self.harness.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertIn("application/json", headers.get("content-type", ""))
        data = json.loads(body.decode("utf-8"))
        self.assertTrue(data.get("ok"))

    def test_legal_terms_endpoint(self):
        """Verify /legal/terms and /{SECRET}/legal/terms return 200 HTML."""
        for path in ["/legal/terms", f"/{self.secret}/legal/terms"]:
            status, headers, body = self.harness.request("GET", path)
            self.assertEqual(status, 200)
            self.assertIn("text/html", headers.get("content-type", ""))
            self.assertIn(b"SilentConnect", body)

    def test_json_and_sub_routes_return_11_profiles(self):
        """Verify /{SECRET}/json/{sub_id}, /sub/..., /happ/... return 11 profiles with smart auto-selector at index 0."""
        routes = ["json", "sub", "json-ru", "sub-ru", "happ"]
        for r in routes:
            path = f"/{self.secret}/{r}/{self.sub_id}"
            status, headers, body = self.harness.request("GET", path)
            self.assertEqual(status, 200, f"Route {path} failed with status {status}")
            self.assertIn("application/json", headers.get("content-type", ""))
            profiles = json.loads(body.decode("utf-8"))
            self.assertIsInstance(profiles, list)
            self.assertEqual(len(profiles), 11, f"Expected 11 profiles on route {path}, got {len(profiles)}")
            
            # Check smart auto-selector at index 0 (Native Xray Balancer)
            smart = profiles[0]
            self.assertIn("Автоматический", smart.get("remarks", ""))
            self.assertIn("observatory", smart)
            self.assertIn("balancers", smart.get("routing", {}))

        # Native Sing-box routes return dictionary config
        for s_route in ["singbox", "sing-box", "sfa"]:
            path = f"/{self.secret}/{s_route}/{self.sub_id}"
            status, headers, body = self.harness.request("GET", path)
            self.assertEqual(status, 200)
            sb_cfg = json.loads(body.decode("utf-8"))
            self.assertIsInstance(sb_cfg, dict)
            self.assertIn("outbounds", sb_cfg)

    def test_json_global_routes(self):
        """Verify /{SECRET}/json-global/{sub_id} and /sub-global/... return global route configuration."""
        for r in ["json-global", "sub-global", "happ-global"]:
            path = f"/{self.secret}/{r}/{self.sub_id}"
            status, headers, body = self.harness.request("GET", path)
            self.assertEqual(status, 200)
            profiles = json.loads(body.decode("utf-8"))
            self.assertEqual(len(profiles), 11)
            # Smart selector in global mode should omit direct ru bypass
            smart = profiles[0]
            rules = smart.get("routing", {}).get("rules", [])
            direct_rules = [ru for ru in rules if ru.get("outboundTag") == "direct"]
            self.assertFalse(any(any("ru" in str(d) for d in ru.get("domain", [])) for ru in direct_rules))

        path = f"/{self.secret}/singbox-global/{self.sub_id}"
        status, headers, body = self.harness.request("GET", path)
        self.assertEqual(status, 200)
        sb_cfg = json.loads(body.decode("utf-8"))
        self.assertIsInstance(sb_cfg, dict)
        self.assertIn("outbounds", sb_cfg)

    def test_clash_and_meta_yaml_routes(self):
        """Verify /{SECRET}/clash/{sub_id}, /meta/..., /clash-meta/... return valid Clash Meta YAML."""
        routes = ["clash", "meta", "clash-meta"]
        for r in routes:
            path = f"/{self.secret}/{r}/{self.sub_id}"
            status, headers, body = self.harness.request("GET", path)
            self.assertEqual(status, 200, f"Route {path} failed with {status}")
            self.assertIn("text/yaml", headers.get("content-type", ""))
            
            # Assert response headers
            self.assertEqual(headers.get("profile-update-interval"), "24")
            self.assertEqual(headers.get("profile-title"), "SilentConnect Clash")
            self.assertIn("subscription-userinfo", headers)
            self.assertIn("profile-web-page-url", headers)
            self.assertEqual(headers.get("x-content-type-options"), "nosniff")
            self.assertEqual(headers.get("referrer-policy"), "no-referrer")
            
            yaml_text = body.decode("utf-8")
            self.assertIn("🚀 PROXY", yaml_text)
            self.assertIn("⚡ Auto URL-Test", yaml_text)
            self.assertIn("🛡️ Priority Fallback", yaml_text)
            self.assertIn("🇳🇱 NL Classic Reality TCP", yaml_text)
            self.assertIn("🇫🇮 FI Stealth XHTTP Reality", yaml_text)

    def test_clash_global_routes(self):
        """Verify /{SECRET}/clash-global/{sub_id} and /meta-global/... return global Clash config."""
        for r in ["clash-global", "meta-global"]:
            path = f"/{self.secret}/{r}/{self.sub_id}"
            status, headers, body = self.harness.request("GET", path)
            self.assertEqual(status, 200)
            self.assertIn("text/yaml", headers.get("content-type", ""))
            self.assertEqual(headers.get("profile-title"), "SilentConnect Clash Global")
            yaml_text = body.decode("utf-8")
            self.assertIn("🚀 PROXY", yaml_text)

    def test_streisand_and_b64_routes(self):
        """Verify /{SECRET}/streisand/{sub_id}, /b64/..., /base64/... return Base64 URI list."""
        routes = ["streisand", "b64", "base64"]
        for r in routes:
            path = f"/{self.secret}/{r}/{self.sub_id}"
            status, headers, body = self.harness.request("GET", path)
            self.assertEqual(status, 200, f"Route {path} failed with {status}")
            self.assertIn("text/plain", headers.get("content-type", ""))
            
            # Assert headers
            self.assertEqual(headers.get("profile-update-interval"), "24")
            self.assertEqual(headers.get("profile-title"), "SilentConnect Streisand")
            self.assertIn("subscription-userinfo", headers)
            self.assertIn("profile-web-page-url", headers)
            
            b64_text = body.decode("utf-8").strip()
            import base64
            decoded = base64.b64decode(b64_text).decode("utf-8")
            lines = [l for l in decoded.splitlines() if l.strip()]
            self.assertEqual(len(lines), 10)
            unquoted_lines = [urllib.parse.unquote(l) for l in lines]
            self.assertTrue(any("Классический TCP (NL)" in l for l in unquoted_lines))
            self.assertTrue(any("XHTTP Reality (FI)" in l for l in unquoted_lines))

    def test_import_setup_page(self):
        """Verify /{SECRET}/import/{sub_id} serves Web UI setup page with Clash Meta card."""
        path = f"/{self.secret}/import/{self.sub_id}"
        status, headers, body = self.harness.request("GET", path)
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers.get("content-type", ""))
        html_text = body.decode("utf-8")
        self.assertIn("Clash Meta / Mihomo", html_text)
        self.assertIn("Happ", html_text)
        self.assertIn("Streisand", html_text)
        self.assertIn("V2RayTun", html_text)

    def test_1click_import_clash_and_meta_pages(self):
        """Verify 1-click import pages for /{SECRET}/import/clash/{sub_id} and /meta/."""
        for target in ["clash", "meta"]:
            path = f"/{self.secret}/import/{target}/{self.sub_id}"
            status, headers, body = self.harness.request("GET", path)
            self.assertEqual(status, 200)
            self.assertIn("text/html", headers.get("content-type", ""))
            html_text = body.decode("utf-8")
            self.assertIn("clash://install-config?url=", html_text)
            self.assertIn("Clash Meta", html_text)

    def test_1click_import_happ_streisand_v2raytun(self):
        """Verify 1-click import pages for happ, streisand, v2raytun."""
        for target in ["happ", "streisand", "v2raytun"]:
            path = f"/{self.secret}/import/{target}/{self.sub_id}"
            status, headers, body = self.harness.request("GET", path)
            self.assertEqual(status, 200)
            self.assertIn("text/html", headers.get("content-type", ""))
            html_text = body.decode("utf-8")
            self.assertIn("SilentConnect", html_text)

    def test_backward_compatibility_single_and_test_routes(self):
        """Verify legacy single-profile and test routes still work."""
        legacy_routes = [
            "legacy", "xray", "json-legacy", "sub-legacy",
            "json-test-fragment", "json-multi", "json-dual-test",
            "json-nl-test-fp", "json-xhttp-test", "json-xhttp-tcp-caddy-test",
            "json-dual-auto-test", "json-auto-wifi-first-test",
            "json-sosproxy", "json-relay", "json-google",
            "json-hybrid", "raw"
        ]
        for r in legacy_routes:
            path = f"/{self.secret}/{r}/{self.sub_id}"
            status, headers, body = self.harness.request("GET", path)
            self.assertEqual(status, 200, f"Legacy route {path} failed with status {status}")
            self.assertIn("application/json", headers.get("content-type", ""))


class TestQuiesceLockAndSecurity(unittest.TestCase):
    """Test Quiesce 30s renewable lease, secret token authentication, and write protection."""

    @classmethod
    def setUpClass(cls):
        cls.harness = TestServerHarness()
        cls.harness.start()
        cls.secret = app.SECRET_SEGMENT
        cls.token = app.INTERNAL_SECRET
        cls.sub_id = "test-quiesce-sub"

    @classmethod
    def tearDownClass(cls):
        with app.QUIESCE_LOCK:
            app.QUIESCE_ACTIVE = False
            app.QUIESCE_LEASE_UNTIL = 0.0
        cls.harness.stop()

    def setUp(self):
        with app.QUIESCE_LOCK:
            app.QUIESCE_ACTIVE = False
            app.QUIESCE_LEASE_UNTIL = 0.0

    def tearDown(self):
        with app.QUIESCE_LOCK:
            app.QUIESCE_ACTIVE = False
            app.QUIESCE_LEASE_UNTIL = 0.0

    def test_quiesce_unauthorized_access(self):
        """Verify Quiesce endpoint rejects requests without valid X-Internal-Secret."""
        path = f"/{self.secret}/internal-quiesce/start"
        status, _, body = self.harness.request("GET", path)
        self.assertEqual(status, 403)
        data = json.loads(body.decode("utf-8"))
        self.assertEqual(data.get("status"), "FORBIDDEN")

        status, _, body = self.harness.request("GET", path, headers={"X-Internal-Secret": "wrong-secret"})
        self.assertEqual(status, 403)

    def test_quiesce_lifecycle_start_lease_release(self):
        """Verify Quiesce start -> lease heartbeat -> release cycle."""
        headers = {"X-Internal-Secret": self.token}
        
        # 1. Start quiesce
        path_start = f"/{self.secret}/internal-quiesce/start"
        status, _, body = self.harness.request("GET", path_start, headers=headers)
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertEqual(data.get("status"), "QUIESCED_ACK")
        self.assertEqual(data.get("lease_ttl"), 30.0)
        self.assertTrue(app.is_quiesced())

        # 2. Extend lease / heartbeat
        path_lease = f"/{self.secret}/internal-quiesce/lease"
        status, _, body = self.harness.request("GET", path_lease, headers=headers)
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertEqual(data.get("status"), "QUIESCED_ACK")
        self.assertTrue(data.get("lease_extended"))
        self.assertTrue(app.is_quiesced())

        # 3. Release quiesce
        path_release = f"/{self.secret}/internal-quiesce/release"
        status, _, body = self.harness.request("GET", path_release, headers=headers)
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertEqual(data.get("status"), "UNQUIESCED_ACK")
        self.assertFalse(app.is_quiesced())

    def test_quiesce_blocks_post_writes_but_allows_get_reads(self):
        """Verify active Quiesce blocks POST writes (503) while allowing GET reads (200)."""
        headers = {"X-Internal-Secret": self.token}
        self.harness.request("GET", f"/{self.secret}/internal-quiesce/start", headers=headers)
        self.assertTrue(app.is_quiesced())

        # GET subscription is allowed during failover
        status_get, _, _ = self.harness.request("GET", f"/{self.secret}/json/{self.sub_id}")
        self.assertEqual(status_get, 200)

        # POST renew / order is blocked during failover
        status_post, _, body_post = self.harness.request("POST", f"/{self.secret}/renew/{self.sub_id}")
        self.assertEqual(status_post, 503)
        data = json.loads(body_post.decode("utf-8"))
        self.assertEqual(data.get("error"), "quiesce_merge_in_progress")

    def test_quiesce_lease_expiration(self):
        """Verify Quiesce during maintenance persists without accidental expiry until explicit release."""
        with app.QUIESCE_LOCK:
            app.QUIESCE_ACTIVE = True
            app.QUIESCE_LEASE_UNTIL = time.time() - 1.0  # Expired timestamp during long operation

        # Quiesce remains active to protect state until explicit release
        self.assertTrue(app.is_quiesced())

        # Explicit release clears quiesced state
        headers = {"X-Internal-Secret": self.token}
        status, _, body = self.harness.request("GET", f"/{self.secret}/internal-quiesce/release", headers=headers)
        self.assertEqual(status, 200)
        self.assertFalse(app.is_quiesced())


class TestRateLimiterInteractions(unittest.TestCase):
    """Test rate limiting behavior and exemptions."""

    def test_healthz_exempt_from_rate_limiter(self):
        """Assert healthz endpoint is never blocked by rate limiter."""
        harness = TestServerHarness()
        harness.start()
        try:
            for _ in range(10):
                status, _, body = harness.request("GET", "/healthz")
                self.assertEqual(status, 200)
        finally:
            harness.stop()

    def test_rate_limiter_blocks_abuse(self):
        """Assert subscription endpoints trigger 429 when RPM limit is reached."""
        saved_rpm = app.RATE_LIMIT_RPM
        saved_enabled = app.RATE_LIMIT_ENABLED
        try:
            app.RATE_LIMIT_RPM = 5
            app.RATE_LIMIT_ENABLED = True
            with app._rate_lock:
                app._rate_map.clear()

            harness = TestServerHarness()
            harness.start()
            try:
                for i in range(5):
                    status, _, _ = harness.request("GET", f"/{app.SECRET_SEGMENT}/json/test-rate-sub")
                    self.assertEqual(status, 200)
                
                # 6th request should hit 429 Too Many Requests
                status, headers, body = harness.request("GET", f"/{app.SECRET_SEGMENT}/json/test-rate-sub")
                self.assertEqual(status, 429)
                data = json.loads(body.decode("utf-8"))
                self.assertEqual(data.get("error"), "rate_limited")
            finally:
                harness.stop()
        finally:
            app.RATE_LIMIT_RPM = saved_rpm
            app.RATE_LIMIT_ENABLED = saved_enabled
            with app._rate_lock:
                app._rate_map.clear()


if __name__ == "__main__":
    unittest.main(verbosity=2)
