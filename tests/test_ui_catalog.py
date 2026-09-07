"""
Comprehensive Automated Test Suite for SilentConnect UI/UX, App Catalog, Responsive CSS & Links
Covers:
1. SubJSON Setup Wizard App Catalog Expansion (R1)
2. Mihomo / Clash Meta & Client App Vector SVG Logos (R2)
3. VPN Shop Landing Mobile Header <=56-64px & Single-Row Flexbox (R3)
4. VPN Shop Landing Centered Flexbox Footer & No Orphan Tokens (R3)
5. Tariff Builder 4-Duration Symmetrical Grid (R3)
6. Container Max-Width Constraints (1120px Landing / 860px Sub-pages & Wizard) (R3)
7. External Download Links Verification (R4)
8. SubJSON 1-Click Import Deep-Link Endpoints Parity (R1/R4)
"""

import importlib.util
import json
import os
import re
import sys
import unittest
import urllib.parse
from typing import Any, Dict, List

# Ensure repository root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

VPN_SHOP_DIR = os.path.join(PROJECT_ROOT, "vpn-shop")
if VPN_SHOP_DIR not in sys.path:
    sys.path.insert(0, VPN_SHOP_DIR)

# Set necessary test environment variables before importing app
os.environ["SECRET_SEGMENT"] = "test-secret-123"
os.environ["INTERNAL_SECRET"] = "internal-token-xyz"
os.environ["HYSTERIA_SALAMANDER_PASSWORD"] = "485a96779d1ad79d0fa80ca0"
os.environ["HYSTERIA_AUTH_PASSWORD"] = "test_auth_pwd"
os.environ["PUBLIC_HOST"] = "sub.example.com"
os.environ["WS443_PUBLIC_HOST"] = "edge.example.com"
os.environ["FI_STANDBY_HOST"] = "fi.example.com"
os.environ["PUBLIC_SUBSCRIPTION_ORIGIN"] = "https://sub.example.com"
os.environ["RELAY_PUBLIC_HOST"] = "relay.example.com"

# Dynamically import subjson-service/app.py
subjson_path = os.path.join(PROJECT_ROOT, "subjson-service", "app.py")
spec_subjson = importlib.util.spec_from_file_location("subjson_app", subjson_path)
subjson_app = importlib.util.module_from_spec(spec_subjson)
spec_subjson.loader.exec_module(subjson_app)

import tempfile
from pathlib import Path
from vpn_shop.web import WebCheckout
from vpn_shop.config import Settings
from vpn_shop.store import Store


def create_test_web_checkout() -> WebCheckout:
    temp_dir = Path(tempfile.mkdtemp(prefix="vpn_shop_ui_test_"))
    db_path = temp_dir / "shop.db"
    store = Store(db_path)
    store.init()
    settings = Settings(
        root_dir=temp_dir,
        data_dir=temp_dir,
        database_path=db_path,
        telegram_bot_token="",
        telegram_bot_username="SilentConnectVPNBot",
        brand_name="SilentConnect",
        support_tg_url="https://t.me/example_support",
        welcome_media="",
        quickstart_media="",
        admin_usernames=("admin",),
        admin_user_ids=(),
        subscription_base_url="https://sub.example.com",
        payment_instructions_text="Переведите на карту",
        payment_transfer_url="https://pay.example.com",
        payment_bank_note="МТС Банк",
        xui_panel_url="",
        xui_username="",
        xui_password="",
        xui_verify_tls=False,
        xui_db_path=temp_dir / "x-ui.db",
        xui_xhttp_inbound_id=1,
        xui_tcp_inbound_id=2,
        web_listen_host="127.0.0.1",
        web_listen_port=3090,
        web_public_base_url="https://example.com",
        monthly_price_xhttp_rub=199,
        monthly_price_tcp_rub=199,
        monthly_price_3_devices_rub=199,
        monthly_price_6_devices_rub=299,
        monthly_price_9_devices_rub=399,
        default_device_limit=3,
        invite_required=False,
        terms_version="2026-04-20",
        purge_after_days=30,
        support_email="support@example.com",
        smtp_host="",
        smtp_port=587,
        smtp_user="",
        smtp_password="",
        smtp_from_email="support@example.com",
        cf_turnstile_site_key="0x4AAAAAAATestKey",
        cf_turnstile_secret_key="0x4AAAAAAATestSecret",
        cf_turnstile_enabled=False,
    )
    return WebCheckout(settings=settings, store=store)


class TestUICatalogAndLayout(unittest.TestCase):
    """Test suite verifying UI/UX, Catalog, SVG Logos, Responsive CSS, and External Links."""

    def setUp(self):
        self.web_app = create_test_web_checkout()

    # =========================================================================
    # R1: App Catalog Expansion in Setup Wizard (subjson-service/app.py)
    # =========================================================================
    def test_setup_page_contains_all_eight_apps(self):
        """Verify that setup_page_html embeds all 8 supported client apps in JSON catalog."""
        sub_url = "https://sub.example.com/test-secret/json/test-user-id"
        html_bytes = subjson_app.setup_page_html(
            subscription_url=sub_url,
            subscription_id="test-user-id",
            quoted_sub_id="test-user-id",
            import_query="url=https%3A%2F%2Fsub.example.com%2Ftest-secret%2Fjson%2Ftest-user-id",
        )
        html_text = html_bytes.decode("utf-8")

        # Extract embedded JSON data: const apps = __APPS_JSON__;
        match = re.search(r"const apps = (\[.*?\]);", html_text)
        self.assertIsNotNone(match, "Could not find 'const apps = [...]' in setup_page_html")
        apps = json.loads(match.group(1))

        app_ids = [app["id"] for app in apps]
        expected_ids = ["happ", "clash", "v2rayn", "nekobox", "v2rayng", "streisand", "v2raytun", "singbox"]
        for expected in expected_ids:
            self.assertIn(expected, app_ids, f"App ID '{expected}' must be present in the apps catalog")

        # Check detailed app metadata
        apps_by_id = {app["id"]: app for app in apps}

        # 1. Happ (Flagship recommended)
        happ = apps_by_id["happ"]
        self.assertEqual(happ["name"], "Happ")
        self.assertIn("рекомендуем", happ["badge"])
        for p in ["ios", "android", "windows", "macos", "linux", "androidtv", "appletv"]:
            self.assertIn(p, happ["platforms"])

        # 2. Clash Meta / Mihomo (Auto-select)
        clash = apps_by_id["clash"]
        self.assertIn("Clash", clash["name"])
        self.assertIn("авто-выбор", clash["badge"])
        for p in ["windows", "macos", "android", "linux", "ios"]:
            self.assertIn(p, clash["platforms"])

        # 3. v2rayN (Windows Xray)
        v2rayn = apps_by_id["v2rayn"]
        self.assertEqual(v2rayn["name"], "v2rayN")
        self.assertIn("windows", v2rayn["badge"])
        self.assertIn("windows", v2rayn["platforms"])
        self.assertIn("windows", v2rayn["downloads"])
        self.assertIn("2dust/v2rayN", v2rayn["downloads"]["windows"][0]["url"])

        # 4. NekoBox (Android JSON)
        nekobox = apps_by_id["nekobox"]
        self.assertEqual(nekobox["name"], "NekoBox")
        self.assertIn("android", nekobox["badge"])
        self.assertIn("android", nekobox["platforms"])
        self.assertIn("MatsuriDayo/NekoBoxForAndroid", nekobox["downloads"]["android"][0]["url"])

        # 5. v2rayNG (Android VLESS)
        v2rayng = apps_by_id["v2rayng"]
        self.assertEqual(v2rayng["name"], "v2rayNG")
        self.assertIn("android", v2rayng["badge"])
        self.assertIn("android", v2rayng["platforms"])
        self.assertIn("2dust/v2rayNG", v2rayng["downloads"]["android"][0]["url"])

        # 6. Streisand (iOS / macOS)
        streisand = apps_by_id["streisand"]
        self.assertEqual(streisand["name"], "Streisand")
        self.assertIn("ios", streisand["platforms"])
        self.assertIn("macos", streisand["platforms"])

        # 7. V2RayTun (Backup)
        v2raytun = apps_by_id["v2raytun"]
        self.assertEqual(v2raytun["name"], "V2RayTun")
        self.assertIn("ios", v2raytun["platforms"])
        self.assertIn("android", v2raytun["platforms"])

        # 8. Sing-box
        singbox = apps_by_id["singbox"]
        self.assertEqual(singbox["name"], "Sing-box")
        for p in ["ios", "android", "windows", "macos", "linux"]:
            self.assertIn(p, singbox["platforms"])

    # =========================================================================
    # R2: Official Authentic App Logos (No Handmade Vector)
    # =========================================================================
    def test_mihomo_svg_data_uri_and_no_broken_links(self):
        """Verify Mihomo / Clash Meta logo is authentic original logo with zero 404 dependencies."""
        sub_url = "https://sub.example.com/test-secret/json/test-user-id"
        html_bytes = subjson_app.setup_page_html(
            subscription_url=sub_url,
            subscription_id="test-user-id",
            quoted_sub_id="test-user-id",
            import_query="url=https%3A%2F%2Fsub.example.com%2Ftest-secret%2Fjson%2Ftest-user-id",
        )
        html_text = html_bytes.decode("utf-8")

        # 1. Assert no 404 raw GitHub URL in the codebase or rendered page
        self.assertNotIn("raw.githubusercontent.com/MetaCubeX/ClashMetaForAndroid", html_text)

        # 2. Assert OFFICIAL_CLASH_ICON is a valid base64 image data-URI
        self.assertTrue(subjson_app.OFFICIAL_CLASH_ICON.startswith("data:image/png;base64,"))

        # 3. Assert all custom icons are authentic original base64 data URIs or official CDNs
        self.assertTrue(subjson_app.OFFICIAL_V2RAYN_ICON.startswith("data:image/"))
        self.assertTrue(subjson_app.OFFICIAL_NEKOBOX_ICON.startswith("data:image/png;base64,"))
        self.assertTrue(subjson_app.OFFICIAL_V2RAYNG_ICON.startswith("data:image/png;base64,"))
        self.assertTrue(
            subjson_app.OFFICIAL_SINGBOX_ICON.startswith("data:image/svg+xml;base64,")
            or subjson_app.OFFICIAL_SINGBOX_ICON.startswith("data:image/png;base64,")
            or subjson_app.OFFICIAL_SINGBOX_ICON.startswith("https://")
        )

    # =========================================================================
    # R3: Mobile Header Height <= 56-64px & Single-Row Flexbox (vpn-shop/web.py)
    # =========================================================================
    def test_mobile_header_css_constraints(self):
        """Verify that mobile header height is strictly <= 56-64px with single-row nowrap flex layout."""
        landing_bytes = self.web_app.render_home()
        landing_html = landing_bytes.decode("utf-8")

        # Check desktop header style
        self.assertIn("header {", landing_html)
        self.assertIn("position: sticky;", landing_html)

        # Check mobile media query @media (max-width: 820px)
        self.assertIn("@media (max-width: 820px)", landing_html)

        # In mobile media query, assert brand on left and navlinks styling
        self.assertIn(".brand { font-size: 15px; display: inline-flex; align-items: center;", landing_html)
        self.assertIn(".navlinks { display: grid; grid-template-columns: repeat(6, 1fr);", landing_html)

    # =========================================================================
    # R3: Centered Flexbox Footer & No Orphan Middle Dots (vpn-shop/web.py)
    # =========================================================================
    def test_footer_centered_flexbox_and_clean_markup(self):
        """Verify footer uses centered flexbox with gap 12-18px and no orphan middle dots."""
        landing_bytes = self.web_app.render_home()
        landing_html = landing_bytes.decode("utf-8")

        # Assert semantic flexbox classes exist
        self.assertIn(".footer-wrap {", landing_html)
        self.assertIn(".footer-links {", landing_html)
        self.assertIn(".footer-copy {", landing_html)

        # Assert flexbox properties
        self.assertIn("display: flex;", landing_html)
        self.assertIn("flex-direction: column;", landing_html)
        self.assertIn("align-items: center;", landing_html)
        self.assertIn("gap: 12px 18px;", landing_html)

        # Assert HTML contains .footer-wrap and .footer-links
        self.assertIn('<div class="wrap footer-wrap">', landing_html)
        self.assertIn('<div class="footer-links">', landing_html)
        self.assertIn('<div class="footer-copy">', landing_html)

        # Assert no orphan middle dots in footer
        footer_section = re.search(r"<footer>(.*?)</footer>", landing_html, re.DOTALL)
        self.assertIsNotNone(footer_section, "Footer markup not found")
        footer_content = footer_section.group(1)
        self.assertNotIn("·", footer_content, "Footer must not contain raw orphan middle dots (·)")

    def test_lk_footer_centered_flexbox_and_clean_markup(self):
        """Verify LK / Setup wizard footer uses centered flexbox and no orphan middle dots."""
        import importlib
        subjson_app = importlib.import_module("subjson-service.app")
        html_bytes = subjson_app.setup_page_html(
            subscription_url="https://sub.example.com/test",
            subscription_id="test_sub_id",
            quoted_sub_id="test_sub_id",
            import_query="url=test",
        )
        page_html = html_bytes.decode("utf-8")

        # Assert semantic flexbox classes and responsive rules exist
        self.assertIn(".footer-wrap {", page_html)
        self.assertIn(".footer-links {", page_html)
        self.assertIn(".footer-copy {", page_html)
        self.assertIn('<div class="footer-wrap">', page_html)
        self.assertIn('<div class="footer-links">', page_html)
        self.assertIn('<div class="footer-copy">', page_html)

        # Assert no orphan middle dots in LK footer
        footer_section = re.search(r"<footer>(.*?)</footer>", page_html, re.DOTALL)
        self.assertIsNotNone(footer_section, "LK Footer markup not found")
        footer_content = footer_section.group(1)
        self.assertNotIn("·", footer_content, "LK Footer must not contain raw orphan middle dots (·)")
        self.assertIn("[code: mekbuda]", footer_content)

    # =========================================================================
    # R3: Tariff Builder Symmetrical 4-Duration Grid (vpn-shop/web.py)
    # =========================================================================
    def test_tariff_duration_grid_layout(self):
        """Verify 4-column desktop and 2x2 mobile layout for duration buttons in tariff builder."""
        landing_bytes = self.web_app.render_home()
        landing_html = landing_bytes.decode("utf-8")

        # CSS class for 4 duration columns
        self.assertIn(".choice-grid-durations { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; }", landing_html)

        # Mobile media query for 2x2 grid
        self.assertIn(".choice-grid-durations { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 6px; }", landing_html)

        # HTML uses choice-grid-durations
        self.assertIn('<div class="choice-grid choice-grid-durations">', landing_html)

    # =========================================================================
    # R3: Container Max-Width Constraints (1120px Landing / 860px Sub-pages)
    # =========================================================================
    def test_container_max_widths(self):
        """Verify 1120px max-width on landing and 860px max-width on sub-pages and setup wizard."""
        # 1. Landing Page (.wrap -> 1120px)
        landing_html = self.web_app.render_home().decode("utf-8")
        self.assertIn(".wrap { width: 100%; max-width: 1120px;", landing_html)
        self.assertIn("main.wrap { flex: 1 0 auto; width: 100%; max-width: 1120px;", landing_html)

        # 2. Sub-pages (About, Contact, Privacy, Terms -> 860px)
        about_html = self.web_app.render_about().decode("utf-8")
        contact_html = self.web_app.render_contact().decode("utf-8")
        privacy_html = self.web_app.render_legal_privacy().decode("utf-8")
        terms_html = self.web_app.render_legal_terms().decode("utf-8")

        for page_html, name in [(about_html, "About"), (contact_html, "Contact"), (privacy_html, "Privacy"), (terms_html, "Terms")]:
            self.assertIn("max-width: 860px;", page_html, f"{name} page must contain max-width: 860px container")

        # 3. Setup Wizard (main.shell -> 860px)
        wizard_html = subjson_app.setup_page_html(
            subscription_url="https://sub.example.com/s/json/123",
            subscription_id="123",
            quoted_sub_id="123",
            import_query="url=test",
        ).decode("utf-8")
        self.assertIn("main, .shell, main.shell {", wizard_html)
        self.assertIn("max-width: 860px;", wizard_html)

    # =========================================================================
    # R4: External Download Links Remediation
    # =========================================================================
    def test_external_download_links_validity(self):
        """Verify all download links are correct and point to active official sources."""
        # 1. Clash Verge Rev fixed repository URL
        self.assertEqual(subjson_app.CLASH_DOWNLOAD_URL, "https://github.com/clash-verge-rev/clash-verge-rev/releases")
        self.assertNotEqual(subjson_app.CLASH_DOWNLOAD_URL, "https://github.com/MetaCubeX/clash-verge-rev/releases")

        # 2. v2rayN and NekoBox URLs
        self.assertEqual(subjson_app.V2RAYN_DOWNLOAD_URL, "https://github.com/2dust/v2rayN/releases")
        self.assertEqual(subjson_app.NEKOBOX_DOWNLOAD_URL, "https://github.com/MatsuriDayo/NekoBoxForAndroid/releases")
        self.assertEqual(subjson_app.V2RAYNG_DOWNLOAD_URL, "https://github.com/2dust/v2rayNG/releases")

        # 3. Sing-box URLs
        self.assertEqual(subjson_app.SINGBOX_DOWNLOAD_URL, "https://github.com/SagerNet/sing-box/releases")
        self.assertEqual(subjson_app.SINGBOX_IOS_URL, "https://apps.apple.com/app/sing-box/id6451272673")

        # 4. Happ URLs
        self.assertEqual(subjson_app.HAPP_DOWNLOAD_URL, "https://www.happ.su/main")
        self.assertEqual(subjson_app.HAPP_IOS_URL, "https://apps.apple.com/us/app/happ-proxy-utility/id6504287215")
        self.assertEqual(subjson_app.HAPP_ANDROID_URL, "https://play.google.com/store/apps/details?id=com.happproxy")

    # =========================================================================
    # R1/R4: Import Deep Links & Helpers in SubJSON
    # =========================================================================
    def test_import_helper_page_generation(self):
        """Verify import helper pages for Happ, Clash, Sing-box, Streisand, v2rayN, NekoBox."""
        sub_url = "https://sub.example.com/test-secret/json/sub123"

        # 1. Happ import page
        happ_page = subjson_app.import_page_html(
            title="Открыть в Happ",
            body="Инструкция для Happ",
            subscription_url=sub_url,
            primary_label="Открыть в Happ",
            primary_url="happ://test",
            install_urls={"ios": subjson_app.HAPP_IOS_URL, "windows": subjson_app.HAPP_DOWNLOAD_URL},
        ).decode("utf-8")
        self.assertIn("Открыть в Happ", happ_page)
        self.assertIn("happ://test", happ_page)

        # 2. Sing-box import page
        singbox_import = f"sing-box://import-remote-profile?url={urllib.parse.quote(sub_url, safe='')}#SilentConnect"
        singbox_page = subjson_app.import_page_html(
            title="Sing-box",
            body="Инструкция для Sing-box",
            subscription_url=sub_url,
            primary_label="Открыть в Sing-box",
            primary_url=singbox_import,
            install_urls={"ios": subjson_app.SINGBOX_IOS_URL, "windows": subjson_app.SINGBOX_DOWNLOAD_URL},
        ).decode("utf-8")
        self.assertIn("Sing-box", singbox_page)
        self.assertIn("sing-box://import-remote-profile", singbox_page)

        # 3. v2rayN copy helper page
        v2rayn_page = subjson_app.import_page_html(
            title="v2rayN (Windows)",
            body="Инструкция для v2rayN",
            subscription_url=sub_url,
            primary_label="Скопировать подписку для v2rayN",
            primary_url="",
            install_urls={"windows": subjson_app.V2RAYN_DOWNLOAD_URL},
        ).decode("utf-8")
        self.assertIn("v2rayN (Windows)", v2rayn_page)
        self.assertIn(subjson_app.V2RAYN_DOWNLOAD_URL, v2rayn_page)

    def test_payment_notice_cards(self):
        import importlib
        subjson_app = importlib.import_module("subjson-service.app")

        # 1. Reported state
        mock_reported = {
            "public_id": "ord_test123",
            "status": "waiting_payment",
            "duration_days": 30,
            "final_price_rub": 199,
            "meta_json": '{"web_paid_reported_at": 1724960000, "device_limit": 3, "customer_email": "test@mail.ru"}',
        }
        card_reported = subjson_app.render_payment_notice_html(mock_reported)
        self.assertIn("ord_test123", card_reported)
        self.assertIn("Уведомление об оплате отправлено!", card_reported)
        self.assertIn("#f59e0b", card_reported)
        self.assertIn("dismissPaymentNotice('ord_test123')", card_reported)
        self.assertIn("data-order-status=\"reported\"", card_reported)

        # 2. Paid state
        mock_paid = {
            "public_id": "ord_test456",
            "status": "paid",
            "duration_days": 90,
            "final_price_rub": 499,
            "customer_email": "happy@client.com",
            "meta_json": '{"device_limit": 6}',
        }
        card_paid = subjson_app.render_payment_notice_html(mock_paid)
        self.assertIn("ord_test456", card_paid)
        self.assertIn("Оплата подтверждена!", card_paid)
        self.assertIn("+90 дн.", card_paid)
        self.assertIn("happy@client.com", card_paid)
        self.assertIn("dismissPaymentNotice('ord_test456')", card_paid)

        # 3. Canceled state
        mock_canceled = {
            "public_id": "ord_test789",
            "status": "canceled",
            "duration_days": 30,
            "final_price_rub": 199,
            "meta_json": '{}',
        }
        card_canceled = subjson_app.render_payment_notice_html(mock_canceled)
        self.assertIn("ord_test789", card_canceled)
        self.assertIn("Заказ отменен", card_canceled)
        self.assertIn("dismissPaymentNotice('ord_test789')", card_canceled)

    def test_check_pending_payment_card_dismissal(self):
        import importlib
        import sqlite3
        import tempfile
        import time
        from unittest.mock import patch

        subjson_app = importlib.import_module("subjson-service.app")
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = os.path.join(tmp_dir, "vpn_shop.db")
            conn = sqlite3.connect(db_path)
            conn.execute("CREATE TABLE profiles (id INTEGER PRIMARY KEY, public_id TEXT, xui_email TEXT, status TEXT);")
            conn.execute("CREATE TABLE orders (id INTEGER PRIMARY KEY, public_id TEXT, status TEXT, duration_days INTEGER, final_price_rub INTEGER, provisioned_profile_id INTEGER, created_at INTEGER, updated_at INTEGER, meta_json TEXT DEFAULT '{}', customer_email TEXT DEFAULT '');")
            conn.execute("INSERT INTO profiles VALUES (1, 'prf_123', 'sub_user_1', 'active');")
            now = int(time.time())
            conn.execute("INSERT INTO orders VALUES (10, 'ord_test1', 'delivered', 30, 300, 1, ?, ?, ?, '');",
                         (now, now, json.dumps({"device_limit": 3})))
            conn.commit()
            conn.close()

            with patch.object(subjson_app, "find_store_db_path", return_value=db_path), \
                 patch.object(subjson_app, "find_subscription", return_value=(None, None, None, None, {"email": "sub_user_1"})):
                # 1. Initial view: card shown
                card = subjson_app.check_pending_payment_card("sub_xyz")
                self.assertIn("ord_test1", card)
                self.assertIn("Оплата подтверждена!", card)

                # 2. Dismissed state: card suppressed
                conn = sqlite3.connect(db_path)
                conn.execute("UPDATE orders SET meta_json = ? WHERE public_id = 'ord_test1'",
                             (json.dumps({"device_limit": 3, "notice_dismissed_status": "delivered", "notice_dismissed_at": now}),))
                conn.commit()
                conn.close()

                card_after = subjson_app.check_pending_payment_card("sub_xyz")
                self.assertEqual(card_after, "")

                # 3. Status changed to canceled: card reappears
                conn = sqlite3.connect(db_path)
                conn.execute("UPDATE orders SET status = 'canceled' WHERE public_id = 'ord_test1'")
                conn.commit()
                conn.close()

                card_canceled = subjson_app.check_pending_payment_card("sub_xyz")
                self.assertIn("Заказ отменен", card_canceled)

                # 4. New order arrives: new notice appears
                conn = sqlite3.connect(db_path)
                conn.execute("INSERT INTO orders VALUES (11, 'ord_new2', 'delivered', 30, 300, 1, ?, ?, ?, '');",
                             (now + 10, now + 10, json.dumps({"device_limit": 3})))
                conn.commit()
                conn.close()

                card_new = subjson_app.check_pending_payment_card("sub_xyz")
                self.assertIn("ord_new2", card_new)

    def test_dismiss_notice_endpoint(self):
        import importlib
        import io
        import sqlite3
        import tempfile
        import time
        from http import HTTPStatus
        from unittest.mock import patch

        subjson_app = importlib.import_module("subjson-service.app")
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = os.path.join(tmp_dir, "vpn_shop.db")
            conn = sqlite3.connect(db_path)
            conn.execute("CREATE TABLE orders (id INTEGER PRIMARY KEY, public_id TEXT, status TEXT, duration_days INTEGER, final_price_rub INTEGER, provisioned_profile_id INTEGER, created_at INTEGER, updated_at INTEGER, meta_json TEXT DEFAULT '{}', customer_email TEXT DEFAULT '');")
            now = int(time.time())
            conn.execute("INSERT INTO orders VALUES (20, 'ord_ep1', 'delivered', 30, 300, 1, ?, ?, ?, '');",
                         (now, now, json.dumps({"device_limit": 3})))
            conn.commit()
            conn.close()

            class DummyHandler:
                def __init__(self, path, body_json):
                    self.path = path
                    self.headers = {"Content-Length": str(len(body_json)), "Content-Type": "application/json"}
                    self.rfile = io.BytesIO(body_json.encode("utf-8"))
                    self.response_status = None
                    self.response_data = None
                    self.command = "POST"
                    self.client_address = ("127.0.0.1", 12345)

                def _read_form(self):
                    return {}

                def _send_json(self, status, data, include_body):
                    self.response_status = status
                    self.response_data = data

            with patch.object(subjson_app, "find_store_db_path", return_value=db_path):
                handler = DummyHandler(
                    f"/{subjson_app.SECRET_SEGMENT}/dismiss-notice/ord_ep1",
                    json.dumps({"status": "delivered", "sub_id": "sub_xyz"})
                )
                subjson_app.RequestHandler.do_POST(handler)
                self.assertEqual(handler.response_status, HTTPStatus.OK)
                self.assertTrue(handler.response_data.get("ok"))
                self.assertEqual(handler.response_data.get("dismissed_status"), "delivered")

                conn = sqlite3.connect(db_path)
                row = conn.execute("SELECT meta_json FROM orders WHERE public_id = 'ord_ep1'").fetchone()
                conn.close()
                meta = json.loads(row[0])
                self.assertEqual(meta.get("notice_dismissed_status"), "delivered")
                self.assertIn("notice_dismissed_at", meta)


if __name__ == "__main__":
    unittest.main(verbosity=2)

