import http.client
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import MagicMock, patch

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

VPN_SHOP_DIR = os.path.join(PROJECT_ROOT, "vpn-shop")
if VPN_SHOP_DIR not in sys.path:
    sys.path.insert(0, VPN_SHOP_DIR)

SUBJSON_DIR = os.path.join(PROJECT_ROOT, "subjson-service")
if SUBJSON_DIR not in sys.path:
    sys.path.insert(0, SUBJSON_DIR)

os.environ["SECRET_SEGMENT"] = "my-secret-sub"
os.environ["INTERNAL_SECRET"] = "internal-token-xyz"
os.environ["HYSTERIA_SALAMANDER_PASSWORD"] = "485a96779d1ad79d0fa80ca0"
os.environ["HYSTERIA_AUTH_PASSWORD"] = "test_auth_pwd"
os.environ["PUBLIC_HOST"] = "sub.example.com"
os.environ["WS443_PUBLIC_HOST"] = "edge.example.com"
os.environ["FI_STANDBY_HOST"] = "fi.example.com"
os.environ["PUBLIC_SUBSCRIPTION_ORIGIN"] = "https://sub.example.com"

import app
from app import setup_page_html, render_subjson_awg_container


class TestServerHarness:
    """Helper to start and stop an in-process ThreadingHTTPServer with RequestHandler."""

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
            self.server = None

    def request(self, method: str, path: str, headers: dict = None, body: bytes = None) -> tuple[int, dict, bytes]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        req_headers = headers or {}
        conn.request(method, path, body=body, headers=req_headers)
        res = conn.getresponse()
        resp_headers = {k.lower(): v for k, v in res.getheaders()}
        resp_body = res.read()
        conn.close()
        return res.status, resp_headers, resp_body


class TestSubjsonAwgWizard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.happ_patcher = patch("app.encrypt_happ_link", return_value="happ://crypt/dummy")
        cls.happ_patcher.start()
        cls.temp_dir = Path(tempfile.mkdtemp(prefix="awg_wizard_test_"))
        db_path = cls.temp_dir / "vpn_shop.db"
        os.environ["SHOP_DATABASE_PATH"] = str(db_path)

        from vpn_shop.config import load_settings
        from vpn_shop.store import Store
        from vpn_shop.web import WebCheckout
        import dataclasses

        cls.store = Store(db_path)
        cls.store.init()

        base_settings = load_settings(cls.temp_dir)
        cls.settings = dataclasses.replace(
            base_settings,
            database_path=db_path,
            cf_turnstile_enabled=False,
            cf_turnstile_secret_key="",
            web_listen_host="127.0.0.1",
            web_listen_port=0,
        )
        cls.checkout = WebCheckout(cls.settings, cls.store)
        app._shop_checkout_instance = cls.checkout

        import uuid
        uid = uuid.uuid4().hex[:8]
        cls.profile = cls.store.create_profile(
            xui_inbound_id=1,
            transport="vless",
            profile_mode="individual",
            family_label=None,
            xui_email=f"sub_{uid}@domain.com",
            xui_client_id=str(uuid.uuid4()),
            expires_at=1800000000,
            device_limit=3,
        )
        cls.sub_id = cls.profile["public_id"]
        cls.profile_id = cls.profile["public_id"]

        # Ensure slot 1 is provisioned
        cls.checkout.ensure_awg_slot(cls.profile_id, 1, default_label="Устройство 1")

        cls.harness = TestServerHarness()
        cls.harness.start()

    @classmethod
    def tearDownClass(cls):
        cls.harness.stop()
        cls.happ_patcher.stop()
        app._shop_checkout_instance = None
        if os.path.exists(cls.temp_dir):
            shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_setup_page_html_contains_awg_elements(self):
        html_bytes = setup_page_html(
            subscription_url="https://sub.example.com/my-secret-sub/json/28njm8v72ruyu2he",
            subscription_id="28njm8v72ruyu2he",
            quoted_sub_id="28njm8v72ruyu2he",
            import_query="",
        )
        html = html_bytes.decode("utf-8")

        self.assertIn('id="pill-mode-awg"', html)
        self.assertIn("Игровой", html)
        self.assertIn("AmneziaVPN, AmneziaWG", html)
        self.assertIn("setConnectionMode('awg')", html)
        self.assertIn('id="awg-mode-container"', html)
        self.assertIn('id="awg-qr-modal"', html)
        self.assertIn('id="awg-qr-image"', html)
        self.assertIn('id="awg-switch-modal"', html)
        self.assertIn("openAwgQrModal", html)
        self.assertIn("closeAwgQrModal", html)
        self.assertIn("copyAwgKey", html)
        self.assertIn("openAwgSwitchModal", html)
        self.assertIn("renameAwgSlot", html)

    def test_render_subjson_awg_container_fallback(self):
        out = render_subjson_awg_container("dummy_sub_123", "https://t.me/example_support")
        self.assertIn("Скоростной режим AmneziaWG", out)

    def test_render_subjson_awg_container_with_profile(self):
        mock_wc = MagicMock()
        mock_wc.get_profile_by_any_sub_id.return_value = {
            "public_id": "prf_test123",
            "device_limit": 3,
            "expires_at": 1800000000,
        }
        mock_wc.render_awg_slots_widget.return_value = '<div class="mock-slots">SLOTS_OK</div>'

        with patch("app.get_shop_checkout", return_value=mock_wc):
            out = render_subjson_awg_container("prf_test123", "https://t.me/example_support")
            self.assertIn("SLOTS_OK", out)
            self.assertIn("Установка клиента Amnezia VPN", out)
            self.assertIn("App Store (iOS)", out)
            self.assertIn("Google Play (Android)", out)

    def test_awg_slot_config_download_direct_and_secret(self):
        for route_prefix in ["/sub/awg", "/my-secret-sub/awg"]:
            url = f"{route_prefix}/{self.sub_id}/slot/1/config"
            status, headers, body = self.harness.request("GET", url)
            self.assertEqual(status, HTTPStatus.OK, f"Failed on {url}")
            self.assertIn("application/x-wireguard-profile", headers.get("content-type", ""))
            self.assertIn("attachment", headers.get("content-disposition", ""))
            conf_text = body.decode("utf-8")
            self.assertIn("[Interface]", conf_text)
            self.assertIn("PrivateKey", conf_text)
            self.assertIn("[Peer]", conf_text)

    def test_awg_slot_qr_generation(self):
        for route_prefix in ["/sub/awg", "/my-secret-sub/awg"]:
            url = f"{route_prefix}/{self.sub_id}/slot/1/qr"
            status, headers, body = self.harness.request("GET", url)
            self.assertEqual(status, HTTPStatus.OK, f"Failed on {url}")
            self.assertIn("image/png", headers.get("content-type", ""))
            self.assertTrue(body.startswith(b"\x89PNG"), "Response is not a valid PNG")

    def test_awg_slot_rename_with_various_keys(self):
        # 1. Using slot_label key
        payload1 = json.dumps({"slot_label": "Home Laptop"}).encode("utf-8")
        status, _, body = self.harness.request(
            "POST",
            f"/sub/awg/{self.sub_id}/slot/1/rename",
            headers={"Content-Type": "application/json", "Content-Length": str(len(payload1))},
            body=payload1,
        )
        self.assertEqual(status, HTTPStatus.OK)
        res1 = json.loads(body.decode("utf-8"))
        self.assertTrue(res1["ok"])
        self.assertEqual(res1["slot_label"], "Home Laptop")
        self.assertEqual(res1.get("slot_index"), 1)

        # 2. Using name key
        payload2 = json.dumps({"name": "Work MacBook"}).encode("utf-8")
        status, _, body = self.harness.request(
            "POST",
            f"/sub/awg/{self.sub_id}/slot/2/rename",
            headers={"Content-Type": "application/json", "Content-Length": str(len(payload2))},
            body=payload2,
        )
        self.assertEqual(status, HTTPStatus.OK)
        res2 = json.loads(body.decode("utf-8"))
        self.assertTrue(res2["ok"])
        self.assertEqual(res2["slot_label"], "Work MacBook")

        # 3. Using label key on secret segment route
        payload3 = json.dumps({"label": "iPad Pro"}).encode("utf-8")
        status, _, body = self.harness.request(
            "POST",
            f"/my-secret-sub/awg/{self.sub_id}/slot/3/rename",
            headers={"Content-Type": "application/json", "Content-Length": str(len(payload3))},
            body=payload3,
        )
        self.assertEqual(status, HTTPStatus.OK)
        res3 = json.loads(body.decode("utf-8"))
        self.assertTrue(res3["ok"])
        self.assertEqual(res3["slot_label"], "iPad Pro")

    def test_json_endpoint_pure_json_and_import_wizard(self):
        json_url = f"/my-secret-sub/json/{self.sub_id}"

        # Browser (Mozilla) gets pure JSON on /json/
        status, headers, body = self.harness.request(
            "GET", json_url, headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"}
        )
        self.assertEqual(status, HTTPStatus.OK)
        self.assertIn("application/json", headers.get("content-type", ""))
        json.loads(body.decode("utf-8"))

        # curl gets pure JSON on /json/
        status, headers, body = self.harness.request(
            "GET", json_url, headers={"User-Agent": "curl/8.1.2"}
        )
        self.assertEqual(status, HTTPStatus.OK)
        self.assertIn("application/json", headers.get("content-type", ""))

        # VPN clients get pure JSON
        for vpn_ua in ["Happ/1.2.0", "Sing-box/1.8.0", "v2rayN/6.23", "ClashMeta/1.16", "Shadowrocket/1982", "Incy/1.0.0"]:
            status, headers, body = self.harness.request(
                "GET", json_url, headers={"User-Agent": vpn_ua}
            )
            self.assertEqual(status, HTTPStatus.OK, f"Failed for UA: {vpn_ua}")
            self.assertIn("application/json", headers.get("content-type", ""))

        # Human-facing Connection Wizard is on /import/
        import_url = f"/my-secret-sub/import/{self.sub_id}"
        status, headers, body = self.harness.request(
            "GET", import_url, headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"}
        )
        self.assertEqual(status, HTTPStatus.OK)
        self.assertIn("text/html", headers.get("content-type", ""))
        body_text = body.decode("utf-8")
        self.assertIn("pill-mode-awg", body_text)
        self.assertIn("awg-platform-tabs", body_text)
        self.assertIn("awg-apps-selector", body_text)
        self.assertIn("awg-steps-container", body_text)


if __name__ == "__main__":
    unittest.main()
