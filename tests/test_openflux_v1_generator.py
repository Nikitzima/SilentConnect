import unittest
import json
import zlib
import base64
import hashlib
from pathlib import Path
import sys

# Add subjson-service to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "subjson-service"))

import os

# Setup environment before importing app
os.environ.setdefault("HYSTERIA_SALAMANDER_PASSWORD", "485a96779d1ad79d0fa80ca0")
os.environ.setdefault("HYSTERIA_AUTH_PASSWORD", "test_auth_pass_443")
os.environ.setdefault("SECRET_SEGMENT", "test-secret")
os.environ.setdefault("LISTEN_PORT", "3088")
os.environ.setdefault("PUBLIC_HOST", "sub.example.com")
os.environ.setdefault("WS443_PUBLIC_HOST", "edge.example.com")
os.environ.setdefault("FI_STANDBY_HOST", "fi.example.com")
os.environ.setdefault("PUBLIC_SUBSCRIPTION_ORIGIN", "https://sub.example.com")
os.environ.setdefault("FALLBACK_SUBSCRIPTION_ORIGIN", "https://example.com")

import app

class TestOpenFluxV1Generator(unittest.TestCase):
    def decode_link(self, link: str) -> dict:
        self.assertTrue(link.startswith("openflux://v1/"), f"Link does not start with openflux://v1/: {link}")
        payload_b64 = link[len("openflux://v1/"):]
        self.assertFalse("=" in payload_b64, "Link contains padding '=' which should be stripped")
        self.assertFalse("\n" in payload_b64, "Link contains newline")
        self.assertFalse(" " in payload_b64, "Link contains space")

        padded = payload_b64 + "=" * ((4 - len(payload_b64) % 4) % 4)
        raw_deflate = base64.urlsafe_b64decode(padded)
        json_bytes = zlib.decompress(raw_deflate, -zlib.MAX_WBITS)
        return json.loads(json_bytes.decode("utf-8"))

    def test_roundtrip_encode_decode(self):
        link, primary, backup = app.build_openflux_v1_link("nl", "sub_user_abc123")
        self.assertTrue(link.startswith("openflux://v1/"))
        data = self.decode_link(link)

        self.assertIn("name", data)
        self.assertIn("secret", data)
        self.assertIn("context", data)
        self.assertIn("transports", data)
        self.assertGreaterEqual(len(data["transports"]), 1)
        self.assertEqual(data["transports"][0]["type"], "vyandex")
        self.assertEqual(data["transports"][0]["url"], primary)
        self.assertEqual(data["context"], primary)

    def test_consistent_hashing(self):
        link1, p1, b1 = app.build_openflux_v1_link("nl", "customer_steady_42")
        link2, p2, b2 = app.build_openflux_v1_link("nl", "customer_steady_42")
        self.assertEqual(link1, link2, "Consistent hash must yield identical links for the same sub_id")
        self.assertEqual(p1, p2)
        self.assertEqual(b1, b2)

    def test_country_selection(self):
        for c in ["nl", "pl", "fi"]:
            link, p, b = app.build_openflux_v1_link(c, "customer_test")
            data = self.decode_link(link)
            self.assertEqual(data["transports"][0]["type"], "vyandex")
            self.assertTrue(len(data["transports"][0]["url"]) > 0)

    def test_setup_page_openflux_ui(self):
        html_bytes = app.setup_page_html(
            subscription_url="https://sub.example.com/test-secret/json/sub_user_abc123",
            subscription_id="sub_user_abc123",
            quoted_sub_id="sub_user_abc123",
            import_query="",
        )
        html_str = html_bytes.decode("utf-8")

        # Verify Hero Card & UI components are present
        self.assertIn("wl-hero-card", html_str)
        self.assertIn("wl-country-tabs", html_str)
        self.assertIn("wl-tab-nl", html_str)
        self.assertIn("wl-hero-cta", html_str)
        self.assertIn("wl-qr-modal", html_str)
        self.assertIn("openflux://v1/", html_str)

        # Verify NO hosted binary ZIPs or obsolete downloads are present
        self.assertNotIn("openflux-silentconnect-bypass.zip", html_str)
        self.assertNotIn("universal-bypass-tool-linux-amd64", html_str)
        self.assertNotIn(".conf", html_str.split("whitelist-mode-container")[1].split("awg-mode-container")[0])

    def test_openflux_qr_generation(self):
        from vpn_shop import qr
        link, _, _ = app.build_openflux_v1_link("nl", "sub_user_abc123")
        qr_bytes = qr.generate_qr_png(link, box_size=6, border=2)
        self.assertTrue(qr_bytes.startswith(b"\x89PNG\r\n\x1a\n"), "Must generate valid PNG header")
        self.assertGreater(len(qr_bytes), 100)


if __name__ == "__main__":
    unittest.main()
