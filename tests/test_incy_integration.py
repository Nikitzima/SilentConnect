import json
import os
import pathlib
import sys
import unittest
from PIL import Image

ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent
VPN_SHOP_DIR = ROOT_DIR / "vpn-shop"
SUBJSON_DIR = ROOT_DIR / "subjson-service"

for p in (str(VPN_SHOP_DIR), str(SUBJSON_DIR), str(ROOT_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

os.environ.setdefault("HYSTERIA_SALAMANDER_PASSWORD", "test-salamander-pass")  # PLACEHOLDER
os.environ.setdefault("HYSTERIA_AUTH_PASSWORD", "test-auth-pass")  # PLACEHOLDER
os.environ.setdefault("TCP_REALITY_PUBLIC_KEY", "test-pub-key")  # PLACEHOLDER
os.environ.setdefault("TCP_REALITY_SHORT_ID", "1234abcd")  # PLACEHOLDER
os.environ.setdefault("TCP_REALITY_SNI_CLASSIC", "sber.ru")
os.environ.setdefault("TCP_REALITY_SNI_FAST", "st.kinopoisk.ru")
os.environ.setdefault("GRPC_REALITY_PUBLIC_KEY", "test-grpc-pub-key")  # PLACEHOLDER
os.environ.setdefault("GRPC_REALITY_SHORT_ID", "4d7a")  # PLACEHOLDER
os.environ.setdefault("GRPC_REALITY_SNI", "vk.com")
os.environ.setdefault("SECRET_SEGMENT", "my-secret-sub")  # PLACEHOLDER
os.environ.setdefault("INTERNAL_SECRET", "test-internal-secret")  # PLACEHOLDER
os.environ.setdefault("XUI_DB_PATH", ":memory:")
os.environ.setdefault("STATIC_JSON_CONFIG_DIR", "/tmp")

import app as subjson_app


class TestIncyIntegration(unittest.TestCase):
    def test_incy_icon_asset(self):
        icon_path = SUBJSON_DIR / "assets" / "apps" / "incy.webp"
        self.assertTrue(icon_path.is_file(), f"incy.webp missing at {icon_path}")
        with Image.open(icon_path) as im:
            self.assertEqual(im.format, "WEBP")
            self.assertEqual(im.size, (256, 256))

    def test_encrypt_and_decrypt_incy_link(self):
        test_url = "https://sub.example.com/my-secret-sub/import/testsub123"
        link = subjson_app.encrypt_incy_link(test_url, name="SilentConnect")
        self.assertTrue(link.startswith("incy://crypt1/"), f"Unexpected link scheme: {link}")

        # Decrypt using INCY_K1_KEY
        import base64
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        b64payload = link[len("incy://crypt1/"):]
        pad = (4 - len(b64payload) % 4) % 4
        wire = base64.urlsafe_b64decode(b64payload + "=" * pad)
        iv = wire[:12]
        ct_and_tag = wire[12:]
        aesgcm = AESGCM(subjson_app.INCY_K1_KEY)
        decrypted_json = json.loads(aesgcm.decrypt(iv, ct_and_tag, None).decode("utf-8"))
        self.assertEqual(decrypted_json.get("url"), test_url)
        self.assertEqual(decrypted_json.get("n"), "SilentConnect")
        self.assertEqual(decrypted_json.get("v"), 1)

    def test_setup_page_contains_incy(self):
        sub_id = "testincy01"
        html_bytes = subjson_app.setup_page_html(
            subscription_url=f"https://sub.example.com/{subjson_app.SECRET_SEGMENT}/json/{sub_id}",
            subscription_id=sub_id,
            quoted_sub_id=sub_id,
            import_query="",
        )
        html_str = html_bytes.decode("utf-8")
        self.assertIn("INCY", html_str)
        self.assertIn("/assets/apps/incy.webp", html_str)
        self.assertIn("incy://crypt1/", html_str)

    def test_frontend_app_js_contains_incy(self):
        app_js_path = SUBJSON_DIR / "v2.1" / "app.js"
        content = app_js_path.read_text(encoding="utf-8")
        self.assertIn("id: 'incy'", content)
        self.assertIn("INCY_DOWNLOAD", content)
        self.assertIn("https://apps.apple.com/app/incy/id6756943388", content)
        self.assertIn("https://play.google.com/store/apps/details?id=llc.itdev.incy", content)
        self.assertIn("badge-xray", content)
        # Check badges configuration
        self.assertIn("{ id: 'happ', name: 'Happ', badge: ''", content)
        self.assertIn("{ id: 'incy', name: 'INCY', badge: 'рекомендуем'", content)
        self.assertIn("appMain: 'incy'", content)
        self.assertIn("{ id: 'amneziavpn', name: 'AmneziaVPN', badge: 'рекомендуем'", content)
        self.assertIn("{ id: 'amneziawg', name: 'AmneziaWG', badge: ''", content)
        self.assertIn("1. TestFlight в App Store", content)
        self.assertIn("2. Присоединиться в TestFlight", content)
        self.assertIn("id=\"ofImportBtn\"", content)


if __name__ == "__main__":
    unittest.main()
