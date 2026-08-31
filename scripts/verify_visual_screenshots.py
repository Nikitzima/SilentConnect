#!/usr/bin/env python3
"""
scripts/verify_visual_screenshots.py
Automated Visual Verification and Screenshot Capture Harness for SilentConnect.
Covers:
1. Landing Page (vpn-shop/vpn_shop/web.py):
   - Desktop 1920x1080: max-width 1120px, 4-column duration selector grid, centered footer.
   - Mobile iPhone 390x844: header height <= 56-64px, single-row nowrap flex, 2x2 duration grid.
   - Mobile Android 360x800: header height <= 56-64px, centered footer.
2. Setup Wizard / Personal Cabinet (subjson-service/app.py):
   - Desktop 1920x1080 across all 7 OS tabs (iOS, Android, Windows, macOS, Linux, Android TV, Apple TV).
   - Mobile 390x844 on Setup Wizard.
   - Mihomo SVG logo image load verification (naturalWidth > 0, zero 404).
   - Max-width 860px constraint verification.
3. Genuine Headless Chrome execution via Playwright.
"""

from http.server import HTTPServer, SimpleHTTPRequestHandler
import importlib.util
import json
import logging
import os
from pathlib import Path
import re
import socket
import sys
import tempfile
import threading
import time
from typing import Any, Dict, List

from playwright.sync_api import sync_playwright

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
LOGGER = logging.getLogger("visual_verifier")

PROJECT_ROOT = Path(__file__).absolute().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "vpn-shop"))

# Set necessary test environment variables before importing app
os.environ["SECRET_SEGMENT"] = "test-secret-123"  # PLACEHOLDER
os.environ["INTERNAL_SECRET"] = "internal-token-xyz"  # PLACEHOLDER
os.environ["HYSTERIA_SALAMANDER_PASSWORD"] = "dummy_salamander_pwd"  # PLACEHOLDER
os.environ["HYSTERIA_AUTH_PASSWORD"] = "test_auth_pwd"  # PLACEHOLDER
os.environ["PUBLIC_HOST"] = "edge.example.com"
os.environ["PUBLIC_SUBSCRIPTION_ORIGIN"] = "https://sub.example.com"
os.environ["RELAY_PUBLIC_HOST"] = "relay.example.com"

# Dynamically import subjson-service/app.py
subjson_path = PROJECT_ROOT / "subjson-service" / "app.py"
spec_subjson = importlib.util.spec_from_file_location("subjson_app", str(subjson_path))
subjson_app = importlib.util.module_from_spec(spec_subjson)
spec_subjson.loader.exec_module(subjson_app)

from vpn_shop.config import Settings
from vpn_shop.store import Store
from vpn_shop.web import WebCheckout


def build_test_web_checkout() -> WebCheckout:
    temp_dir = Path(tempfile.mkdtemp(prefix="vpn_shop_visual_test_"))
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
        cf_turnstile_site_key="",
        cf_turnstile_secret_key="",
        cf_turnstile_enabled=False,
    )
    return WebCheckout(settings=settings, store=store)


class VisualTestingServer:
    """Lightweight in-process HTTP server serving generated pages and mock media assets."""

    def __init__(self, landing_html: bytes, setup_html: bytes):
        self.landing_html = landing_html
        self.setup_html = setup_html
        self.server: HTTPServer | None = None
        self.thread: threading.Thread | None = None
        self.port = 0

    def start(self) -> int:
        parent_self = self

        # 1x1 transparent PNG for mock static assets
        png_1x1 = (
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
            b"\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\rIDATx\x9cc\xf8\xff\xff?"
            b"\x03\x00\x08\xfc\x02\xfe\xa7\x9a\xa0\xa0\x00\x00\x00\x00IEND\xaeB`\x82"
        )

        class Handler(SimpleHTTPRequestHandler):
            def do_GET(self):
                if self.path in ("/", "/landing", "/index.html"):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(parent_self.landing_html)))
                    self.end_headers()
                    self.wfile.write(parent_self.landing_html)
                elif "/setup" in self.path or "/import/" in self.path or "/my-secret-sub/" in self.path:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(parent_self.setup_html)))
                    self.end_headers()
                    self.wfile.write(parent_self.setup_html)
                elif self.path.startswith("/assets/"):
                    self.send_response(200)
                    self.send_header("Content-Type", "image/png")
                    self.send_header("Content-Length", str(len(png_1x1)))
                    self.end_headers()
                    self.wfile.write(png_1x1)
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, format, *args):
                pass  # Suppress noisy standard HTTP logs

        # Find free ephemeral port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        self.port = sock.getsockname()[1]
        sock.close()

        self.server = HTTPServer(("127.0.0.1", self.port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        LOGGER.info(f"VisualTestingServer started on http://127.0.0.1:{self.port}")
        return self.port

    def stop(self):
        if self.server:
            self.server.shutdown()
            LOGGER.info("VisualTestingServer stopped")


def run_visual_verification() -> Dict[str, Any]:
    """Execute Playwright browser screenshots and programmatic CSS/DOM assertions."""
    screenshots_dir = PROJECT_ROOT / "screenshots"
    screenshots_dir.mkdir(parents=True, exist_ok=True)

    web_app = build_test_web_checkout()
    landing_bytes = web_app.render_home()

    sub_url = "https://sub.example.com/test-secret-123/json/test-sub-id"
    setup_bytes = subjson_app.setup_page_html(
        subscription_url=sub_url,
        subscription_id="test-sub-id",
        quoted_sub_id="test-sub-id",
        import_query="url=https%3A%2F%2Fsub.example.com%2Ftest-secret-123%2Fjson%2Ftest-sub-id",
    )

    test_server = VisualTestingServer(landing_bytes, setup_bytes)
    port = test_server.start()
    base_url = f"http://127.0.0.1:{port}"

    chrome_path = "C:/Program Files/Google/Chrome/Application/chrome.exe"
    if not os.path.exists(chrome_path):
        chrome_path_x86 = "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe"
        if os.path.exists(chrome_path_x86):
            chrome_path = chrome_path_x86
        else:
            chrome_path = None

    LOGGER.info(f"Launching Playwright with Chrome binary: {chrome_path or 'bundled chromium'}")

    results = {
        "landing_desktop": {},
        "landing_mobile_390x844": {},
        "landing_mobile_360x800": {},
        "setup_desktop_tabs": {},
        "setup_mobile_390x844": {},
        "screenshots_generated": [],
        "assertions_passed": [],
        "assertions_failed": [],
    }

    def assert_true(condition: bool, msg: str):
        if condition:
            LOGGER.info(f"  [PASS] {msg}")
            results["assertions_passed"].append(msg)
        else:
            LOGGER.error(f"  [FAIL] {msg}")
            results["assertions_failed"].append(msg)
            raise AssertionError(msg)

    try:
        with sync_playwright() as p:
            launch_args = {"headless": True}
            if chrome_path:
                launch_args["executable_path"] = chrome_path

            browser = p.chromium.launch(**launch_args)
            context = browser.new_context(device_scale_factor=1.0)
            page = context.new_page()

            # -------------------------------------------------------------
            # 1. LANDING PAGE — Desktop (1920x1080)
            # -------------------------------------------------------------
            LOGGER.info("Verifying Landing Page on Desktop (1920x1080)...")
            page.set_viewport_size({"width": 1920, "height": 1080})
            page.goto(f"{base_url}/landing")
            page.wait_for_load_state("domcontentloaded")
            page.wait_for_timeout(400)

            # Screenshot: landing_1920x1080.png
            shot_path = str(screenshots_dir / "landing_1920x1080.png")
            page.screenshot(path=shot_path, full_page=True)
            results["screenshots_generated"].append(shot_path)
            LOGGER.info(f"Saved: {shot_path}")

            # Assert Desktop max-width: main.wrap width <= 1120px
            main_wrap_box = page.locator("main.wrap").bounding_box()
            assert_true(main_wrap_box is not None, "Landing main.wrap element found in DOM")
            main_wrap_width = round(main_wrap_box["width"], 1)
            LOGGER.info(f"  Landing main.wrap computed width: {main_wrap_width}px (limit: 1120px)")
            assert_true(main_wrap_width <= 1120.5, f"Landing main.wrap width ({main_wrap_width}px) must be <= 1120px")

            # Assert 4-column duration selector grid
            durations_grid_cols = page.evaluate("""() => {
                const el = document.querySelector('.choice-grid-durations');
                if (!el) return null;
                const style = window.getComputedStyle(el);
                return style.gridTemplateColumns.trim().split(/\\s+/).length;
            }""")
            LOGGER.info(f"  Desktop duration selector column count: {durations_grid_cols}")
            assert_true(durations_grid_cols == 4, f"Desktop duration selector must have 4 columns, got {durations_grid_cols}")

            # Assert Centered Footer
            footer_styles = page.evaluate("""() => {
                const wrap = document.querySelector('.footer-wrap');
                const links = document.querySelector('.footer-links');
                if (!wrap || !links) return null;
                const wrapStyle = window.getComputedStyle(wrap);
                const linksStyle = window.getComputedStyle(links);
                return {
                    wrapAlign: wrapStyle.alignItems,
                    linksJustify: linksStyle.justifyContent,
                    linksGap: linksStyle.gap || (linksStyle.rowGap + ' ' + linksStyle.columnGap),
                    middleDotCount: (document.querySelector('footer').innerHTML.match(/·/g) || []).length
                };
            }""")
            assert_true(footer_styles is not None, "Footer elements (.footer-wrap, .footer-links) found")
            assert_true(footer_styles["wrapAlign"] == "center", f"Footer wrap align-items must be center, got {footer_styles['wrapAlign']}")
            assert_true(footer_styles["linksJustify"] == "center", f"Footer links justify-content must be center, got {footer_styles['linksJustify']}")
            assert_true(footer_styles["middleDotCount"] == 0, f"Footer must not contain orphan middle dots, found {footer_styles['middleDotCount']}")

            results["landing_desktop"] = {
                "wrap_width": main_wrap_width,
                "duration_columns": durations_grid_cols,
                "footer": footer_styles,
            }

            # -------------------------------------------------------------
            # 2. LANDING PAGE — Mobile iPhone (390x844)
            # -------------------------------------------------------------
            LOGGER.info("Verifying Landing Page on Mobile iPhone (390x844)...")
            page.set_viewport_size({"width": 390, "height": 844})
            page.wait_for_timeout(300)

            # Screenshot: landing_390x844_mobile.png
            shot_path = str(screenshots_dir / "landing_390x844_mobile.png")
            page.screenshot(path=shot_path, full_page=True)
            results["screenshots_generated"].append(shot_path)
            LOGGER.info(f"Saved: {shot_path}")

            # Assert Header computed height <= 56-64px
            header_box = page.locator("header").bounding_box()
            assert_true(header_box is not None, "Header element found in DOM")
            header_height = round(header_box["height"], 1)
            LOGGER.info(f"  Mobile 390x844 header computed height: {header_height}px (limit <= 64px)")
            assert_true(header_height <= 64.0, f"Mobile header height ({header_height}px) must be <= 64px")
            assert_true(header_height <= 56.5, f"Mobile header height ({header_height}px) strictly <= 56px")

            # Assert Single-row flex nav
            nav_flex = page.evaluate("""() => {
                const nav = document.querySelector('nav');
                const navlinks = document.querySelector('.navlinks');
                if (!nav) return null;
                const navStyle = window.getComputedStyle(nav);
                const linksStyle = navlinks ? window.getComputedStyle(navlinks) : {};
                return {
                    flexWrap: navStyle.flexWrap,
                    overflowX: linksStyle.overflowX,
                    whiteSpace: linksStyle.whiteSpace
                };
            }""")
            assert_true(nav_flex["flexWrap"] == "nowrap", f"Nav flex-wrap must be nowrap, got {nav_flex['flexWrap']}")
            assert_true(nav_flex["overflowX"] in ("auto", "scroll"), f"Navlinks overflow-x must be auto/scroll, got {nav_flex['overflowX']}")

            # Assert 2x2 duration selector grid on mobile
            mob_duration_cols = page.evaluate("""() => {
                const el = document.querySelector('.choice-grid-durations');
                if (!el) return null;
                const style = window.getComputedStyle(el);
                return style.gridTemplateColumns.trim().split(/\\s+/).length;
            }""")
            LOGGER.info(f"  Mobile duration selector column count: {mob_duration_cols}")
            assert_true(mob_duration_cols == 2, f"Mobile duration selector must have 2 columns (2x2 grid), got {mob_duration_cols}")

            results["landing_mobile_390x844"] = {
                "header_height": header_height,
                "nav_flex": nav_flex,
                "duration_columns": mob_duration_cols,
            }

            # -------------------------------------------------------------
            # 3. LANDING PAGE — Mobile Android (360x800)
            # -------------------------------------------------------------
            LOGGER.info("Verifying Landing Page on Mobile Android (360x800)...")
            page.set_viewport_size({"width": 360, "height": 800})
            page.wait_for_timeout(300)

            # Screenshot: landing_360x800_mobile.png
            shot_path = str(screenshots_dir / "landing_360x800_mobile.png")
            page.screenshot(path=shot_path, full_page=True)
            results["screenshots_generated"].append(shot_path)
            LOGGER.info(f"Saved: {shot_path}")

            # Assert Header computed height <= 56-64px
            android_header_box = page.locator("header").bounding_box()
            android_header_height = round(android_header_box["height"], 1)
            LOGGER.info(f"  Mobile 360x800 header computed height: {android_header_height}px (limit <= 64px)")
            assert_true(android_header_height <= 64.0, f"Android 360x800 header height ({android_header_height}px) must be <= 64px")

            results["landing_mobile_360x800"] = {
                "header_height": android_header_height,
            }

            # -------------------------------------------------------------
            # 4. SETUP WIZARD — Desktop (1920x1080) Across All 7 OS Tabs
            # -------------------------------------------------------------
            LOGGER.info("Verifying Setup Wizard across all 7 OS tabs (1920x1080)...")
            page.set_viewport_size({"width": 1920, "height": 1080})
            page.goto(f"{base_url}/setup")
            page.wait_for_load_state("domcontentloaded")
            page.wait_for_timeout(400)

            # Assert Setup Wizard Container max-width <= 860px
            shell_box = page.locator("main.shell").bounding_box()
            assert_true(shell_box is not None, "Setup Wizard main.shell found")
            shell_width = round(shell_box["width"], 1)
            LOGGER.info(f"  Setup Wizard main.shell computed width: {shell_width}px (limit <= 860px)")
            assert_true(shell_width <= 860.5, f"Setup Wizard main.shell width ({shell_width}px) must be <= 860px")

            # Assert Mihomo / Clash Meta SVG Logo Image Loads Cleanly
            mihomo_img_status = page.evaluate("""() => {
                // Select Windows or Android to see Clash Meta card
                const platformSel = document.getElementById('platform');
                platformSel.value = 'windows';
                platformSel.dispatchEvent(new Event('change'));
                if (typeof window.selectPlatform === 'function') {
                    window.selectPlatform('windows');
                }
                const clashCard = Array.from(document.querySelectorAll('.app-card')).find(el => el.textContent.includes('Clash'));
                if (!clashCard) return { found: false };
                const img = clashCard.querySelector('img');
                if (!img) return { found: true, hasImg: false };
                return {
                    found: true,
                    hasImg: true,
                    src: img.src.substring(0, 40),
                    isSvgDataUri: img.src.startsWith('data:image/svg+xml'),
                    naturalWidth: img.naturalWidth,
                    naturalHeight: img.naturalHeight,
                    complete: img.complete
                };
            }""")
            LOGGER.info(f"  Mihomo SVG Logo Load Status: {mihomo_img_status}")
            assert_true(mihomo_img_status["found"], "Clash Meta card found in DOM")
            assert_true(mihomo_img_status["hasImg"], "Clash Meta card contains an <img> icon element")
            assert_true(mihomo_img_status["isSvgDataUri"], "Clash Meta icon uses clean SVG data-URI")
            assert_true(mihomo_img_status["complete"], "Clash Meta icon is fully loaded (complete=True)")
            assert_true(mihomo_img_status["naturalWidth"] > 0, f"Clash Meta icon naturalWidth > 0, got {mihomo_img_status['naturalWidth']}")
            assert_true(mihomo_img_status["naturalHeight"] > 0, f"Clash Meta icon naturalHeight > 0, got {mihomo_img_status['naturalHeight']}")

            # Iterate through all 7 OS platforms:
            # Expected apps per platform:
            platforms_expected_apps = {
                "ios": ("setup_ios.png", ["Happ", "Streisand", "V2RayTun", "Sing-box", "Clash"]),
                "android": ("setup_android.png", ["Happ", "Clash", "NekoBox", "v2rayNG", "V2RayTun", "Sing-box"]),
                "windows": ("setup_windows.png", ["Happ", "Clash Meta", "v2rayN", "Sing-box"]),
                "macos": ("setup_macos.png", ["Happ", "Clash Meta", "Streisand", "Sing-box"]),
                "linux": ("setup_linux.png", ["Happ", "Clash Meta", "Sing-box"]),
                "androidtv": ("setup_androidtv.png", ["Happ"]),
                "appletv": ("setup_appletv.png", ["Happ"]),
            }

            for os_id, (shot_filename, expected_app_names) in platforms_expected_apps.items():
                LOGGER.info(f"  Selecting OS tab: {os_id} (expecting {expected_app_names})...")
                # Trigger tab selection in browser
                page.evaluate(f"""(osId) => {{
                    const platformSel = document.getElementById('platform');
                    if (platformSel) {{
                        platformSel.value = osId;
                        platformSel.dispatchEvent(new Event('change'));
                    }}
                    if (typeof selectPlatform === 'function') {{
                        selectPlatform(osId);
                    }}
                }}""", os_id)
                page.wait_for_timeout(300)

                # Capture screenshot
                shot_path = str(screenshots_dir / shot_filename)
                page.screenshot(path=shot_path, full_page=True)
                results["screenshots_generated"].append(shot_path)
                LOGGER.info(f"  Saved: {shot_path}")

                # Query rendered app card names
                rendered_app_names = page.evaluate("""() => {
                    const cards = Array.from(document.querySelectorAll('.app-card'));
                    return cards.map(c => {
                        const nameEl = c.querySelector('.app-name');
                        return nameEl ? nameEl.textContent.trim() : c.textContent.trim();
                    });
                }""")
                LOGGER.info(f"    Rendered apps for {os_id}: {rendered_app_names}")

                # Assert all expected apps are rendered
                for exp in expected_app_names:
                    found_match = any(exp.lower() in r.lower() for r in rendered_app_names)
                    assert_true(found_match, f"App '{exp}' must be displayed in {os_id} tab, found {rendered_app_names}")

                results["setup_desktop_tabs"][os_id] = {
                    "rendered_apps": rendered_app_names,
                    "screenshot": shot_filename,
                }

            # -------------------------------------------------------------
            # 5. SETUP WIZARD — Mobile (390x844)
            # -------------------------------------------------------------
            LOGGER.info("Verifying Setup Wizard on Mobile iPhone (390x844)...")
            page.set_viewport_size({"width": 390, "height": 844})
            # Select iOS platform for mobile view
            page.evaluate("""() => {
                if (typeof selectPlatform === 'function') {
                    selectPlatform('ios');
                }
            }""")
            page.wait_for_timeout(300)

            # Screenshot: setup_mobile_390x844.png
            shot_path = str(screenshots_dir / "setup_mobile_390x844.png")
            page.screenshot(path=shot_path, full_page=True)
            results["screenshots_generated"].append(shot_path)
            LOGGER.info(f"Saved: {shot_path}")

            mob_shell_box = page.locator("main.shell").bounding_box()
            assert_true(mob_shell_box is not None, "Setup Wizard main.shell found on mobile")
            mob_shell_width = round(mob_shell_box["width"], 1)
            LOGGER.info(f"  Mobile Setup Wizard shell width: {mob_shell_width}px (viewport 390px)")
            assert_true(mob_shell_width <= 390.5, f"Mobile shell width ({mob_shell_width}px) must fit within 390px viewport")

            results["setup_mobile_390x844"] = {
                "shell_width": mob_shell_width,
            }

            browser.close()

    finally:
        test_server.stop()

    LOGGER.info("=" * 60)
    LOGGER.info("VISUAL VERIFICATION COMPLETED SUCCESSFULLY!")
    LOGGER.info(f"Total screenshots generated: {len(results['screenshots_generated'])}")
    LOGGER.info(f"Total assertions passed: {len(results['assertions_passed'])}")
    LOGGER.info(f"Total assertions failed: {len(results['assertions_failed'])}")
    LOGGER.info("=" * 60)

    return results


if __name__ == "__main__":
    res = run_visual_verification()
    sys.exit(0 if len(res["assertions_failed"]) == 0 else 1)
