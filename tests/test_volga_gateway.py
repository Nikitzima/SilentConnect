"""
Unit tests for Volga White-List Gateway and 302 Redirect System.
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
from http import HTTPStatus
from http.server import ThreadingHTTPServer

PROJECT_ROOT = r"c:\Users\Yuric\OneDrive\Desktop\сервер\github_export"
SUBJSON_DIR = os.path.join(PROJECT_ROOT, "subjson-service")
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
if SUBJSON_DIR not in sys.path:
    sys.path.insert(0, SUBJSON_DIR)

os.environ["SECRET_SEGMENT"] = "test-secret-123"
os.environ["INTERNAL_SECRET"] = "internal-token-xyz"
os.environ["HYSTERIA_SALAMANDER_PASSWORD"] = "dummy_salamander_pwd"
os.environ["HYSTERIA_AUTH_PASSWORD"] = "test_auth_pwd"
os.environ["PUBLIC_HOST"] = "edge.example.com"
os.environ["PUBLIC_SUBSCRIPTION_ORIGIN"] = "https://sub.example.com"
os.environ["RELAY_PUBLIC_HOST"] = "relay.example.com"
os.environ["VOLGA_GATEWAY_DOMAIN"] = "d5dlk4c65l2s5p0q3g0h.7qsg961h.apigw.yandexcloud.net"

import app


class TestVolgaGateway(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.mkdtemp()
        cls.xui_db_path = os.path.join(cls.tmp_dir, "x-ui.db")
        cls.store_db_path = os.path.join(cls.tmp_dir, "vpn_shop.db")

        # Initialize mock x-ui DB
        conn = sqlite3.connect(cls.xui_db_path)
        conn.execute("""
            CREATE TABLE inbounds (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                up INTEGER,
                down INTEGER,
                total INTEGER,
                remark TEXT,
                enable INTEGER,
                port INTEGER,
                protocol TEXT,
                settings TEXT,
                stream_settings TEXT,
                tag TEXT,
                sniffing TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE client_traffics (
                id INTEGER PRIMARY KEY,
                inbound_id INTEGER,
                enable INTEGER,
                email TEXT,
                up INTEGER,
                down INTEGER,
                expiry_time INTEGER,
                total INTEGER
            )
        """)
        # Insert active subscription client
        client_settings = {
            "clients": [{
                "id": "c7a8b9c0-1111-2222-3333-444455556666",
                "flow": "xtls-rprx-vision",
                "email": "test-active-user",
                "subId": "active-token-123",
                "enable": True,
                "expiryTime": int((time.time() + 86400) * 1000)
            }]
        }
        conn.execute(
            "INSERT INTO inbounds (id, enable, port, protocol, settings, stream_settings, tag) VALUES (1, 1, 443, 'vless', ?, '{}', 'vless-in')",
            (json.dumps(client_settings),)
        )
        conn.execute(
            "INSERT INTO client_traffics (id, inbound_id, enable, email, up, down, expiry_time, total) VALUES (1, 1, 1, 'test-active-user', 100, 200, ?, 0)",
            (int((time.time() + 86400) * 1000),)
        )

        # Insert expired subscription client
        client_expired_settings = {
            "clients": [{
                "id": "c7a8b9c0-9999-8888-7777-666655554444",
                "flow": "xtls-rprx-vision",
                "email": "test-expired-user",
                "subId": "expired-token-999",
                "enable": True,
                "expiryTime": int((time.time() - 86400) * 1000)
            }]
        }
        conn.execute(
            "INSERT INTO inbounds (id, enable, port, protocol, settings, stream_settings, tag) VALUES (2, 1, 444, 'vless', ?, '{}', 'vless-expired')",
            (json.dumps(client_expired_settings),)
        )
        conn.execute(
            "INSERT INTO client_traffics (id, inbound_id, enable, email, up, down, expiry_time, total) VALUES (2, 2, 0, 'test-expired-user', 100, 200, ?, 0)",
            (int((time.time() - 86400) * 1000),)
        )
        conn.commit()
        conn.close()

        # Initialize mock store DB
        conn2 = sqlite3.connect(cls.store_db_path)
        conn2.execute("""
            CREATE TABLE profiles (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                order_id INTEGER,
                xui_email TEXT,
                status TEXT,
                created_at INTEGER,
                expires_at INTEGER
            )
        """)
        conn2.execute("INSERT INTO profiles VALUES (1, 100, 1, 'test-active-user', 'active', ?, ?)", (int(time.time()), int(time.time() + 86400)))
        conn2.execute("INSERT INTO profiles VALUES (2, 101, 2, 'test-expired-user', 'expired', ?, ?)", (int(time.time() - 100000), int(time.time() - 86400)))
        conn2.commit()
        conn2.close()

        cls.orig_xui_db = app.XUI_DB_PATH
        app.XUI_DB_PATH = cls.xui_db_path
        os.environ["XUI_DB_PATH"] = cls.xui_db_path
        os.environ["STORE_DB_PATH"] = cls.store_db_path

        # Start test HTTP server
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), app.RequestHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        app.XUI_DB_PATH = cls.orig_xui_db

    def test_volga_nl_active_redirect(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("GET", "/volga/nl/active-token-123")
        res = conn.getresponse()
        self.assertEqual(res.status, HTTPStatus.FOUND)
        self.assertEqual(res.getheader("Location"), "https://disk.yandex.ru/i/_-g0vNUuu69ffw")
        conn.close()

    def test_volga_pl_active_redirect(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("GET", "/volga/pl/active-token-123")
        res = conn.getresponse()
        self.assertEqual(res.status, HTTPStatus.FOUND)
        self.assertEqual(res.getheader("Location"), "https://disk.yandex.ru/i/hb1xodFfECGL8w")
        conn.close()

    def test_volga_fi_active_redirect(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("GET", "/volga/fi/active-token-123")
        res = conn.getresponse()
        self.assertEqual(res.status, HTTPStatus.FOUND)
        self.assertEqual(res.getheader("Location"), "https://yadi.sk/d/I0ULWUKv_9YzpA")
        conn.close()

    def test_volga_expired_subscription_forbidden(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("GET", "/volga/nl/expired-token-999")
        res = conn.getresponse()
        self.assertEqual(res.status, HTTPStatus.FORBIDDEN)
        data = json.loads(res.read().decode())
        self.assertEqual(data["error"], "subscription_inactive_or_not_found")
        conn.close()

    def test_volga_unknown_token_forbidden(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("GET", "/volga/nl/completely-random-token")
        res = conn.getresponse()
        self.assertEqual(res.status, HTTPStatus.FORBIDDEN)
        conn.close()

    def test_volga_unknown_server_not_found(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("GET", "/volga/de/active-token-123")
        res = conn.getresponse()
        self.assertEqual(res.status, HTTPStatus.NOT_FOUND)
        conn.close()

    def test_setup_page_contains_volga_gateway_urls(self):
        html_bytes = app.setup_page_html(
            subscription_url="https://sub.example.com/test-secret-123/json/active-token-123",
            subscription_id="active-token-123",
            quoted_sub_id="active-token-123",
            import_query="",
        )
        html_str = html_bytes.decode("utf-8")
        expected_nl = "https://d5dlk4c65l2s5p0q3g0h.7qsg961h.apigw.yandexcloud.net/volga/nl/active-token-123"
        expected_pl = "https://d5dlk4c65l2s5p0q3g0h.7qsg961h.apigw.yandexcloud.net/volga/pl/active-token-123"
        expected_fi = "https://d5dlk4c65l2s5p0q3g0h.7qsg961h.apigw.yandexcloud.net/volga/fi/active-token-123"
        self.assertIn(expected_nl, html_str)
        self.assertIn(expected_pl, html_str)
        self.assertIn(expected_fi, html_str)
        self.assertIn("isSubActive = true", html_str)


if __name__ == "__main__":
    unittest.main()
