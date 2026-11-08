from __future__ import annotations

from dataclasses import replace
import http.client
import json
import os
import pathlib
import re
import sqlite3
import sys
import tempfile
import threading
import time
from typing import Any
from urllib.parse import quote
import unittest
from unittest.mock import patch

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

from vpn_shop.config import load_settings
from vpn_shop.store import Store
from vpn_shop.web import BoundedThreadingHTTPServer as ShopHTTPServer, RequestHandler as ShopRequestHandler, WebCheckout
import app as subjson_app


def _extract_sc_prod(html_bytes: bytes | str) -> dict[str, Any]:
    text = html_bytes.decode("utf-8") if isinstance(html_bytes, bytes) else html_bytes
    m = re.search(
        r"<script>\s*window\.SC_PROD\s*=\s*(\{.*?\});\s*window\.__SC_BOOT__\s*=\s*window\.SC_PROD;\s*</script>",
        text,
        re.DOTALL,
    )
    if not m:
        raise AssertionError("window.SC_PROD script tag not found in rendered HTML")
    raw_json = m.group(1).replace("<\\/", "</")
    return json.loads(raw_json)


def _init_mock_xui_db(db_path: pathlib.Path, sub_id: str, expires_ms: int) -> None:
    conn = sqlite3.connect(str(db_path))
    settings_obj = {
        "clients": [
            {
                "id": "00000000-0000-4000-8000-000000000001",
                "email": f"user_{sub_id}@example.com",
                "subId": sub_id,
                "enable": True,
                "expiryTime": expires_ms,
                "limitIp": 6,
                "totalGB": 0,
            }
        ]
    }
    stream_obj = {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
            "serverNames": ["example.com"],
            "shortIds": ["01234567"],
            "settings": {"publicKey": "mock_reality_pub_key"},
        },
    }
    with conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS inbounds (id INTEGER PRIMARY KEY, port INTEGER, protocol TEXT, settings TEXT, stream_settings TEXT, sniffing TEXT DEFAULT '{}', tag TEXT, remark TEXT, enable INTEGER)"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS client_traffics (id INTEGER PRIMARY KEY, inbound_id INTEGER, enable INTEGER, email TEXT, up INTEGER, down INTEGER, expiry_time INTEGER, total INTEGER)"
        )
        conn.execute(
            "INSERT INTO inbounds (id, port, protocol, settings, stream_settings, sniffing, tag, remark, enable) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (1, 443, "vless", json.dumps(settings_obj), json.dumps(stream_obj), "{}", "vless-reality", "NL", 1),
        )
        conn.execute(
            "INSERT INTO client_traffics (id, inbound_id, enable, email, up, down, expiry_time, total) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (1, 1, 1, f"user_{sub_id}@example.com", 1024 * 1024, 2048 * 1024, expires_ms, 0),
        )
    conn.close()
    subjson_app.invalidate_inbounds_cache()


class TestStage2WebSecurityAndRedesign(unittest.TestCase):
    """End-to-end SSR, hydration, and HTTP security test suite for Stage 2 (v2.1 + SC-17 + SC-23)."""

    def test_sc17_local_threejs_and_no_cdn(self):
        """SC-17: Three.js 0.160.0 is vendored locally and no external CDN remains in template.html."""
        for base in (VPN_SHOP_DIR, SUBJSON_DIR):
            three_min = base / "v2.1" / "vendor" / "three.module.min.js"
            buf_utils = base / "v2.1" / "vendor" / "utils" / "BufferGeometryUtils.js"
            tpl = base / "v2.1" / "template.html"
            self.assertTrue(three_min.is_file(), f"Missing {three_min}")
            self.assertGreater(three_min.stat().st_size, 500_000)
            self.assertTrue(buf_utils.is_file(), f"Missing {buf_utils}")
            tpl_text = tpl.read_text(encoding="utf-8")
            self.assertNotIn("unpkg.com", tpl_text)
            self.assertNotIn("cdn.jsdelivr.net", tpl_text)
            self.assertIn("/v2.1/vendor/three.module.min.js", tpl_text)
            self.assertIn("<!--__SC_PROD_SCRIPT__-->", tpl_text)

    def test_sc17_csp_headers_updated(self):
        """SC-17: SECURITY_HEADERS CSP allows Google Fonts CSS/fonts and self scripts."""
        web_py = (VPN_SHOP_DIR / "vpn_shop" / "web.py").read_text(encoding="utf-8")
        app_py = (SUBJSON_DIR / "app.py").read_text(encoding="utf-8")
        for src in (web_py, app_py):
            self.assertIn("https://fonts.googleapis.com", src)
            self.assertIn("https://fonts.gstatic.com", src)

    def test_sc23_no_wildcard_cors_and_same_origin_post_guard(self):
        """SC-23: Wildcard CORS is removed from private endpoints and cross-origin POST guard exists."""
        web_py = (VPN_SHOP_DIR / "vpn_shop" / "web.py").read_text(encoding="utf-8")
        app_py = (SUBJSON_DIR / "app.py").read_text(encoding="utf-8")
        self.assertNotIn('send_header("Access-Control-Allow-Origin", "*")', web_py)
        self.assertNotIn('send_header("Access-Control-Allow-Origin", "*")', app_py)
        self.assertIn("_verify_same_origin", web_py)
        self.assertIn("cross_origin_forbidden", app_py)

    def test_v21_prod_adapter_and_germany_node(self):
        """Stage 2: v2.1/app.js includes SC_PROD hydration adapter and Germany (de) node."""
        for base in (VPN_SHOP_DIR, SUBJSON_DIR):
            app_js = (base / "v2.1" / "app.js").read_text(encoding="utf-8")
            tpl_html = (base / "v2.1" / "template.html").read_text(encoding="utf-8")
            self.assertIn("window.SC_PROD", app_js)
            self.assertIn("Германия", app_js)
            self.assertIn("de.edge.", tpl_html)

    def test_v21_ssr_views_and_sc_prod_hydration(self):
        """Render all vpn-shop v2.1 views and verify SC_PROD JSON hydration & sc-ssr-compat fallback."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = pathlib.Path(tmpdir)
            db_path = tmp_path / "test_shop.db"
            base_settings = load_settings(VPN_SHOP_DIR)
            settings = replace(
                base_settings,
                root_dir=VPN_SHOP_DIR,
                database_path=db_path,
                platega_enabled=False,
                cf_turnstile_site_key="0x4AAAAAA_mock_turnstile",  # PLACEHOLDER
                cf_turnstile_secret_key="",
                web_public_base_url="https://example.com",
                subscription_base_url="https://sub.example.com/my-secret-sub",
            )
            store = Store(db_path)
            checkout = WebCheckout(settings, store)

            # 1. Landing view
            home_bytes = checkout.render_home(flash="Тестовое уведомление")
            home_prod = _extract_sc_prod(home_bytes)
            self.assertEqual(home_prod["view"], "landing")
            self.assertEqual(home_prod["errorMessage"], "Тестовое уведомление")
            self.assertEqual(home_prod["turnstileSiteKey"], "0x4AAAAAA_mock_turnstile")  # PLACEHOLDER
            self.assertIn(b'id="sc-ssr-compat"', home_bytes)

            # 2. Legal & informational views
            for method_name, expected_doc in (
                ("render_legal_privacy", "privacy"),
                ("render_legal_terms", "terms"),
                ("render_legal_refund", "refund"),
                ("render_about", "about"),
                ("render_contact", "contact"),
            ):
                doc_bytes = getattr(checkout, method_name)()
                doc_prod = _extract_sc_prod(doc_bytes)
                self.assertEqual(doc_prod["view"], "legal")
                self.assertEqual(doc_prod["legalDoc"], expected_doc)

            # 3. Order views (waiting, delivered, cancelled)
            order = checkout.create_order("tcp_6_180", "", customer_email="buyer@example.com")
            headers = {"Host": "example.com"}

            waiting_bytes = checkout.render_order(headers, order)
            waiting_prod = _extract_sc_prod(waiting_bytes)
            self.assertEqual(waiting_prod["view"], "order")
            self.assertEqual(waiting_prod["order"]["state"], "waiting")
            self.assertEqual(waiting_prod["order"]["publicId"], order["public_id"])
            self.assertIn("Домашний", waiting_prod["order"]["planLabel"])
            self.assertEqual(waiting_prod["order"]["awgLabel"], "500 ГБ в месяц")
            self.assertEqual(waiting_prod["order"]["emailMasked"], "buyer@example.com")

            # Transition to delivered with a provisioned profile
            now = int(time.time())
            xui_db = tmp_path / "shop_xui.db"
            _init_mock_xui_db(xui_db, "sub6devtest12345", (now + 180 * 86400) * 1000)
            checkout.provisioner.xui_db.path = xui_db

            prof = store.create_profile(
                xui_inbound_id=1,
                transport="tcp",
                profile_mode="universal",
                family_label="SilentConnect",
                xui_email="user_sub6devtest12345@example.com",
                xui_client_id="00000000-0000-4000-8000-000000000001",
                xui_sub_id="sub6devtest12345",
                expires_at=now + 180 * 86400,
                device_limit=6,
            )
            store.link_order_profile(order["public_id"], prof["public_id"])
            store.transition_order(order["public_id"], "provisioning", actor="test")
            store.transition_order(order["public_id"], "delivered", actor="test")
            delivered_order = store.get_order(order["public_id"])
            delivered_order["meta_json"]["web_token"] = order["meta_json"].get("web_token", "tok")

            delivered_bytes = checkout.render_order(headers, delivered_order)
            delivered_prod = _extract_sc_prod(delivered_bytes)
            self.assertEqual(delivered_prod["view"], "order")
            self.assertEqual(delivered_prod["order"]["state"], "delivered")
            self.assertIn("sub6devtest12345", delivered_prod["order"]["subscriptionUrl"])
            self.assertIn("sub6devtest12345", delivered_prod["order"]["setupUrl"])

            # Cancelled order
            order_cancel = checkout.create_order("tcp_3_30", "", customer_email="cancel@example.com")
            checkout.cancel_order(order_cancel)
            cancelled_order = store.get_order(order_cancel["public_id"])
            cancelled_bytes = checkout.render_order(headers, cancelled_order)
            cancelled_prod = _extract_sc_prod(cancelled_bytes)
            self.assertEqual(cancelled_prod["view"], "order")
            self.assertEqual(cancelled_prod["order"]["state"], "cancelled")
            self.assertEqual(cancelled_prod["order"]["awgLabel"], "250 ГБ в месяц")

            # 4. Cabinet view
            cab_profiles = [
                {
                    "public_id": prof["public_id"],
                    "sub_id": "sub6devtest12345",
                    "expires_at": now + 180 * 86400,
                    "device_limit": 6,
                    "transport": "tcp",
                    "setup_url": "https://sub.example.com/my-secret-sub/setup/sub6devtest12345",
                }
            ]
            cab_bytes = checkout.render_cabinet("buyer@example.com", cab_profiles)
            cab_prod = _extract_sc_prod(cab_bytes)
            self.assertEqual(cab_prod["view"], "cabinet")
            self.assertEqual(cab_prod["cabinet"]["email"], "buyer@example.com")
            self.assertEqual(len(cab_prod["cabinet"]["items"]), 1)
            item = cab_prod["cabinet"]["items"][0]
            self.assertEqual(item["planTitle"], "Домашний")
            self.assertEqual(item["devices"], 6)
            self.assertEqual(item["awgLabel"], "500 ГБ / мес")
            self.assertTrue(item["isActive"])

    def test_subjson_setup_page_v21_hydration_with_awg_and_openflux(self):
        """Verify subjson-service setup_page_html() hydrates v2.1 SC_PROD with QuotaEvaluation & 6 AWG slots."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = pathlib.Path(tmpdir)
            shop_db = tmp_path / "vpn_shop.db"
            xui_db = tmp_path / "x-ui.db"
            sub_id = "subhome6devices01"
            now = int(time.time())
            expires_at = now + 90 * 86400

            _init_mock_xui_db(xui_db, sub_id, expires_at * 1000)

            base_settings = load_settings(VPN_SHOP_DIR)
            settings = replace(
                base_settings,
                root_dir=VPN_SHOP_DIR,
                database_path=shop_db,
                platega_enabled=False,
                web_public_base_url="https://example.com",
                subscription_base_url="https://sub.example.com/my-secret-sub",
            )
            store = Store(shop_db)
            checkout = WebCheckout(settings, store)

            prof = store.create_profile(
                xui_inbound_id=1,
                transport="tcp",
                profile_mode="universal",
                family_label="SilentConnect",
                xui_email=f"user_{sub_id}@example.com",
                xui_client_id="00000000-0000-4000-8000-000000000001",
                xui_sub_id=sub_id,
                expires_at=expires_at,
                device_limit=6,
            )
            # Record 50 GB used out of 500 GB quota (next reset in 25 days)
            with store._connect() as conn:
                conn.execute(
                    "UPDATE profiles SET awg_quota_bytes = ?, awg_used_bytes = ?, awg_reset_at = ? WHERE public_id = ?",
                    (500 * (1024**3), 50 * (1024**3), now + 25 * 86400, prof["public_id"]),
                )

            mock_slots = [
                {
                    "slot_index": idx,
                    "slot_label": f"Устройство {idx}",
                    "server_code": "nl",
                    "client_ip": f"10.8.1.{10 + idx}",
                    "enabled": 1,
                }
                for idx in range(1, 7)
            ]
            with patch.object(subjson_app, "XUI_DB_PATH", str(xui_db)), \
                 patch.object(subjson_app, "get_shop_checkout", return_value=checkout), \
                 patch.object(subjson_app, "get_shop_settings", return_value=settings), \
                 patch.object(checkout, "ensure_awg_slots_for_profile", return_value=mock_slots):
                html_bytes = subjson_app.setup_page_html(
                    subscription_url=f"https://sub.example.com/{subjson_app.SECRET_SEGMENT}/json/{sub_id}",
                    subscription_id=sub_id,
                    quoted_sub_id=quote(sub_id, safe=""),
                    import_query="",
                    customer_email="homeuser@example.com",
                )

            sc_prod = _extract_sc_prod(html_bytes)
            self.assertEqual(sc_prod["view"], "sub")
            sub_data = sc_prod["sub"]
            self.assertEqual(sub_data["subId"], sub_id)
            self.assertFalse(sub_data["isExpired"])
            self.assertEqual(sub_data["planBadge"], "Домашний")
            self.assertTrue(sub_data["emailBound"])

            awg = sub_data["awg"]
            self.assertEqual(awg["packageGb"], 500)
            self.assertEqual(awg["usedGb"], 50.0)
            self.assertEqual(awg["remGb"], 450.0)
            self.assertEqual(awg["percentRemaining"], 90)
            self.assertEqual(awg["maxSlots"], 6)
            self.assertEqual(len(awg["slots"]), 6)
            self.assertEqual(awg["slots"][0]["address"], "10.8.1.11")
            self.assertEqual(awg["slots"][5]["address"], "10.8.1.16")

            oflux = sub_data["openflux"]
            self.assertIn(oflux["state"], {"inactive", "active", "migrating"})
            self.assertIn("apiBase", oflux)

    def test_http_csp_headers_static_assets_and_path_traversal_and_same_origin(self):
        """Start both vpn-shop and subjson-service HTTP servers and verify SC-17 & SC-23 over real sockets."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = pathlib.Path(tmpdir)
            shop_db = tmp_path / "http_shop.db"
            xui_db = tmp_path / "http_xui.db"
            sub_id = "subhttptest12345"
            now = int(time.time())
            _init_mock_xui_db(xui_db, sub_id, (now + 30 * 86400) * 1000)

            base_settings = load_settings(VPN_SHOP_DIR)
            settings = replace(
                base_settings,
                root_dir=VPN_SHOP_DIR,
                database_path=shop_db,
                platega_enabled=False,
                cf_turnstile_secret_key="",
                web_public_base_url="https://example.com",
                subscription_base_url="https://sub.example.com/my-secret-sub",
            )
            store = Store(shop_db)
            checkout = WebCheckout(settings, store)
            ShopRequestHandler.checkout = checkout

            shop_srv = ShopHTTPServer(("127.0.0.1", 0), ShopRequestHandler, max_workers=4)
            shop_port = shop_srv.server_address[1]
            shop_thread = threading.Thread(target=shop_srv.serve_forever, daemon=True)
            shop_thread.start()

            sub_srv = subjson_app.BoundedThreadingHTTPServer(("127.0.0.1", 0), subjson_app.RequestHandler, max_workers=4)
            sub_port = sub_srv.server_address[1]
            sub_thread = threading.Thread(target=sub_srv.serve_forever, daemon=True)
            sub_thread.start()

            try:
                with patch.object(subjson_app, "XUI_DB_PATH", str(xui_db)), \
                     patch.object(subjson_app, "get_shop_checkout", return_value=checkout):
                    # 1. Check vpn-shop GET /, static assets, CSP, and path traversal
                    conn = http.client.HTTPConnection("127.0.0.1", shop_port, timeout=5)
                    conn.request("GET", "/", headers={"Host": "127.0.0.1"})
                    resp = conn.getresponse()
                    body = resp.read()
                    self.assertEqual(resp.status, 200)
                    csp = resp.getheader("Content-Security-Policy") or ""
                    self.assertIn("https://fonts.googleapis.com", csp)
                    self.assertIn("https://fonts.gstatic.com", csp)
                    self.assertEqual(_extract_sc_prod(body)["view"], "landing")

                    for asset_path in ("/v2.1/app.js", "/v2.1/vendor/three.module.min.js", "/v2.1/vendor/utils/BufferGeometryUtils.js"):
                        conn.request("GET", asset_path, headers={"Host": "127.0.0.1"})
                        r_asset = conn.getresponse()
                        asset_bytes = r_asset.read()
                        self.assertEqual(r_asset.status, 200, f"Failed {asset_path}")
                        self.assertGreater(len(asset_bytes), 1000)

                    # Raw template.html and path traversal must not be served
                    conn.request("GET", "/v2.1/template.html", headers={"Host": "127.0.0.1"})
                    r_tpl = conn.getresponse()
                    r_tpl.read()
                    self.assertEqual(r_tpl.status, 404)

                    conn.request("GET", "/v2.1/../web.py", headers={"Host": "127.0.0.1"})
                    r_trav = conn.getresponse()
                    r_trav.read()
                    self.assertIn(r_trav.status, (403, 404))

                    # 2. SC-23: Cross-origin POST on vpn-shop must be rejected with 403
                    conn.request(
                        "POST",
                        "/api/check-promo",
                        body=b'{"code":"TEST"}',
                        headers={
                            "Host": "example.com",
                            "Origin": "https://evil.example.org",
                            "Content-Type": "application/json",
                        },
                    )
                    r_evil = conn.getresponse()
                    evil_json = json.loads(r_evil.read().decode("utf-8"))
                    self.assertEqual(r_evil.status, 403)
                    self.assertEqual(evil_json.get("error"), "csrf_origin_mismatch")

                    # Same-origin POST on vpn-shop passes origin guard
                    conn.request(
                        "POST",
                        "/api/check-promo",
                        body=b'{"code":"TEST"}',
                        headers={
                            "Host": "example.com",
                            "Origin": "https://example.com",
                            "Content-Type": "application/json",
                        },
                    )
                    r_same = conn.getresponse()
                    r_same.read()
                    self.assertEqual(r_same.status, 200)

                    # Android WebView / in-app browser (VK / Telegram) with Origin: null passes
                    conn.request(
                        "POST",
                        "/api/check-promo",
                        body=b'{"code":"TEST"}',
                        headers={
                            "Host": "example.com",
                            "Origin": "null",
                            "Content-Type": "application/json",
                        },
                    )
                    r_null = conn.getresponse()
                    r_null.read()
                    self.assertEqual(r_null.status, 200)

                    # Android app package origin (android-app://com.vkontakte.android) passes
                    conn.request(
                        "POST",
                        "/api/check-promo",
                        body=b'{"code":"TEST"}',
                        headers={
                            "Host": "example.com",
                            "Origin": "android-app://com.vkontakte.android",
                            "Content-Type": "application/json",
                        },
                    )
                    r_vk = conn.getresponse()
                    r_vk.read()
                    self.assertEqual(r_vk.status, 200)

                    # Explicit Sec-Fetch-Site: cross-site is blocked
                    conn.request(
                        "POST",
                        "/api/check-promo",
                        body=b'{"code":"TEST"}',
                        headers={
                            "Host": "example.com",
                            "Sec-Fetch-Site": "cross-site",
                            "Content-Type": "application/json",
                        },
                    )
                    r_cross = conn.getresponse()
                    r_cross.read()
                    self.assertEqual(r_cross.status, 403)
                    conn.close()

                    # 3. Check subjson-service GET setup page, static assets, and SC-23 POST guard
                    sconn = http.client.HTTPConnection("127.0.0.1", sub_port, timeout=5)
                    sconn.request(
                        "GET",
                        f"/{subjson_app.SECRET_SEGMENT}/setup/{sub_id}",
                        headers={"Host": "sub.example.com"},
                    )
                    sresp = sconn.getresponse()
                    sbody = sresp.read()
                    self.assertEqual(sresp.status, 200)
                    scsp = sresp.getheader("Content-Security-Policy") or ""
                    self.assertIn("https://fonts.googleapis.com", scsp)
                    self.assertEqual(_extract_sc_prod(sbody)["view"], "sub")

                    sconn.request("GET", "/v2.1/vendor/three.module.min.js", headers={"Host": "sub.example.com"})
                    s_three = sconn.getresponse()
                    self.assertEqual(s_three.status, 200)
                    self.assertGreater(len(s_three.read()), 500_000)

                    sconn.request("GET", "/v2.1/template.html", headers={"Host": "sub.example.com"})
                    s_tpl = sconn.getresponse()
                    s_tpl.read()
                    self.assertIn(s_tpl.status, (403, 404))

                    # Cross-origin POST on subjson-service rejected with 403
                    sconn.request(
                        "POST",
                        f"/{subjson_app.SECRET_SEGMENT}/dismiss-notice/ord_123",
                        body=b"{}",
                        headers={
                            "Host": "sub.example.com",
                            "Origin": "https://attacker.example.org",
                            "Content-Type": "application/json",
                        },
                    )
                    s_evil = sconn.getresponse()
                    s_evil_json = json.loads(s_evil.read().decode("utf-8"))
                    self.assertEqual(s_evil.status, 403)
                    self.assertEqual(s_evil_json.get("error"), "cross_origin_forbidden")
                    sconn.close()
            finally:
                shop_srv.shutdown()
                shop_srv.server_close()
                sub_srv.shutdown()
                sub_srv.server_close()

    def test_v21_dom_contract_and_ssr_integrity(self):
        """Verify all DOM IDs required by app.js exist in template.html and SSR HTML is structurally sound."""
        tpl_text = (VPN_SHOP_DIR / "v2.1" / "template.html").read_text(encoding="utf-8")
        required_ids = (
            "cabinetEmail",
            "subHeroId",
            "subStatusBadge",
            "subMetricPlan",
            "subMetricExpires",
            "subMetricMainTraffic",
            "subMetricAwgQuota",
            "awgResetDate",
            "awgRemainingText",
            "awgTotalText",
            "awgPctText",
            "awgQuotaFill",
            "ordClaimTgBtn",
            "subBotLink",
            "subPartnerBotLink",
            "renewRemainDaysNote",
        )
        for dom_id in required_ids:
            self.assertIn(f'id="{dom_id}"', tpl_text, f"Missing required DOM ID #{dom_id} in template.html")
        for forbidden_str in ("Польша", "Варшава", "из из ", "Примеры для теста:"):
            self.assertNotIn(forbidden_str, tpl_text, f"Forbidden prototype string {forbidden_str!r} found in template.html")

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = pathlib.Path(tmpdir)
            shop_db = tmp_path / "dom_shop.db"
            xui_db = tmp_path / "dom_xui.db"
            sub_id = "subdomcontract01"
            now = int(time.time())
            expires_at = now + 60 * 86400
            _init_mock_xui_db(xui_db, sub_id, expires_at * 1000)

            base_settings = load_settings(VPN_SHOP_DIR)
            settings = replace(
                base_settings,
                root_dir=VPN_SHOP_DIR,
                database_path=shop_db,
                platega_enabled=False,
                cf_turnstile_site_key="0x4AAAAAA_dom_test_key",  # PLACEHOLDER
                web_public_base_url="https://example.com",
                subscription_base_url="https://sub.example.com/my-secret-sub",
            )
            store = Store(shop_db)
            checkout = WebCheckout(settings, store)

            with patch.object(subjson_app, "XUI_DB_PATH", str(xui_db)), \
                 patch.object(subjson_app, "get_shop_checkout", return_value=checkout), \
                 patch.object(subjson_app, "get_shop_settings", return_value=settings):
                sub_html = subjson_app.setup_page_html(
                    subscription_url=f"https://sub.example.com/{subjson_app.SECRET_SEGMENT}/json/{sub_id}",
                    subscription_id=sub_id,
                    quoted_sub_id=quote(sub_id, safe=""),
                    import_query="",
                    customer_email="dom@example.com",
                    headers={"Host": "previewsub.example.com"},
                ).decode("utf-8")

            # 1. Verify compat template closes BEFORE window.SC_PROD and app.js
            compat_end = sub_html.find("</template>")
            prod_script_pos = sub_html.find("window.SC_PROD")
            app_js_pos = sub_html.find('/v2.1/app.js')
            self.assertGreater(compat_end, 0)
            self.assertGreater(prod_script_pos, compat_end, "window.SC_PROD must appear after </template>")
            self.assertGreater(app_js_pos, prod_script_pos, "app.js must appear after window.SC_PROD")

            # 2. Verify SSR pre-toggles view visibility (#view-sub visible, #view-landing hidden)
            self.assertRegex(sub_html, r'<main[^>]*id="view-landing"[^>]*\bhidden\b')
            self.assertNotRegex(sub_html, r'<main[^>]*id="view-sub"[^>]*\bhidden\b')

            # 3. Verify Turnstile key & action URLs & preview host resolution in SC_PROD
            sc_prod = _extract_sc_prod(sub_html)
            self.assertEqual(sc_prod.get("turnstileSiteKey"), "0x4AAAAAA_dom_test_key")  # PLACEHOLDER
            self.assertEqual(sc_prod.get("publicBaseUrl"), "https://example.com")
            self.assertEqual(sc_prod["sub"].get("renewActionUrl"), f"/{subjson_app.SECRET_SEGMENT}/renew/{sub_id}")
            self.assertEqual(sc_prod["sub"].get("bindEmailActionUrl"), f"/{subjson_app.SECRET_SEGMENT}/bind-email/{sub_id}")
            self.assertEqual(sc_prod["sub"].get("qrUrl"), f"/{subjson_app.SECRET_SEGMENT}/qr/{sub_id}")

    def test_subscription_setup_url_preserves_secret_segment(self) -> None:
        from vpn_shop.web import subscription_setup_url
        # 3 parts (with /json/)
        url3 = "https://sub.example.com/my-secret-sub/json/cvgh0qqws79dbpcl"
        self.assertEqual(subscription_setup_url(url3), "https://sub.example.com/my-secret-sub/import/cvgh0qqws79dbpcl")
        # 2 parts (secret segment + sub_id)
        url2 = "https://sub.example.com/my-secret-sub/cvgh0qqws79dbpcl"
        self.assertEqual(subscription_setup_url(url2), "https://sub.example.com/my-secret-sub/import/cvgh0qqws79dbpcl")

    def test_recover_subscription_race_condition_fallback(self) -> None:
        """When 3X-UI has not yet synced client into x-ui.db, recover_subscription uses profile xui_sub_id."""
        with tempfile.TemporaryDirectory() as td:
            shop_db = pathlib.Path(td) / "shop.db"
            settings = replace(
                load_settings(),
                database_path=str(shop_db),
                subscription_base_url="https://sub.example.com/my-secret-sub",
            )
            store = Store(shop_db)
            checkout = WebCheckout(settings, store)

            prof = store.create_profile(
                xui_inbound_id=1,
                transport="vless",
                profile_mode="standard",
                family_label=None,
                xui_email="anon-race-test",
                xui_client_id="uuid-1234",
                expires_at=int(time.time()) + 86400 * 30,
                xui_sub_id="test_sub_id_fast_123",
            )
            order = store.create_order(
                kind="new",
                status="delivered",
                transport="vless",
                duration_days=30,
                profile_mode="standard",
                family_label=None,
                base_price_rub=149,
                final_price_rub=149,
                promo_id=None,
                invite_id=None,
                customer_chat_id="web:anon-race-test",
                privacy_ack=True,
                loss_policy_ack=True,
                terms_version="1.0",
                customer_email="race@example.com",
            )
            store.link_order_profile(order["public_id"], prof["public_id"])
            delivered_order = store.get_order(order["public_id"])
            self.assertIsNotNone(delivered_order)

            # 3X-UI has NOT synced yet: find_client_by_email returns None
            with patch.object(checkout.provisioner.xui_db, "find_client_by_email", return_value=None):
                sub_url = checkout.recover_subscription(delivered_order)
                self.assertEqual(sub_url, "https://sub.example.com/my-secret-sub/test_sub_id_fast_123")

    def test_mailer_email_links_sanitize_json_to_import(self) -> None:
        from vpn_shop.mailer import render_subscription_email_html, render_subscription_email_text
        html = render_subscription_email_html(
            customer_email="test@example.com",
            order_public_id="ord_test123",
            plan_name="Личный",
            duration_days=30,
            setup_url="https://sub.example.com/my-secret-sub/json/cvgh0qqws79dbpcl",
            json_url="https://sub.example.com/my-secret-sub/json/cvgh0qqws79dbpcl",
            cabinet_url="https://example.com/order/ord_test123/token123",
        )
        # Button MUST link to /import/, NOT /json/
        self.assertIn('href="https://sub.example.com/my-secret-sub/import/cvgh0qqws79dbpcl" class="btn"', html)
        self.assertNotIn('href="https://sub.example.com/my-secret-sub/json/cvgh0qqws79dbpcl" class="btn"', html)
        # Web setup link in box
        self.assertIn('>https://sub.example.com/my-secret-sub/import/cvgh0qqws79dbpcl<', html)
        # Raw JSON link in box
        self.assertIn('>https://sub.example.com/my-secret-sub/json/cvgh0qqws79dbpcl<', html)

        text = render_subscription_email_text(
            customer_email="test@example.com",
            order_public_id="ord_test123",
            plan_name="Личный",
            duration_days=30,
            setup_url="https://sub.example.com/my-secret-sub/json/cvgh0qqws79dbpcl",
            json_url="https://sub.example.com/my-secret-sub/json/cvgh0qqws79dbpcl",
            cabinet_url="https://example.com/order/ord_test123/token123",
        )
        self.assertIn("https://sub.example.com/my-secret-sub/import/cvgh0qqws79dbpcl", text)
        self.assertIn("https://sub.example.com/my-secret-sub/json/cvgh0qqws79dbpcl", text)



    def test_order_reviewed_mailer_links_sanitize_json_to_import(self) -> None:
        from vpn_shop.mailer import render_order_reviewed_email_html, render_order_reviewed_email_text
        html = render_order_reviewed_email_html(
            customer_email="reviewed@example.com",
            order_public_id="ord_reviewed99",
            duration_days=30,
            setup_url="https://sub.example.com/my-secret-sub/json/cvgh0qqws79dbpcl",
            json_url="https://sub.example.com/my-secret-sub/json/cvgh0qqws79dbpcl",
            cabinet_url="https://example.com/order/ord_reviewed99/token123",
        )
        # Button MUST link to /import/, NOT /json/
        self.assertIn('href="https://sub.example.com/my-secret-sub/import/cvgh0qqws79dbpcl" class="btn"', html)
        self.assertNotIn('href="https://sub.example.com/my-secret-sub/json/cvgh0qqws79dbpcl" class="btn"', html)
        # Web setup link in box
        self.assertIn('>https://sub.example.com/my-secret-sub/import/cvgh0qqws79dbpcl<', html)
        # Raw JSON link in box
        self.assertIn('>https://sub.example.com/my-secret-sub/json/cvgh0qqws79dbpcl<', html)

        text = render_order_reviewed_email_text(
            customer_email="reviewed@example.com",
            order_public_id="ord_reviewed99",
            duration_days=30,
            setup_url="https://sub.example.com/my-secret-sub/json/cvgh0qqws79dbpcl",
            json_url="https://sub.example.com/my-secret-sub/json/cvgh0qqws79dbpcl",
            cabinet_url="https://example.com/order/ord_reviewed99/token123",
        )
        self.assertIn("https://sub.example.com/my-secret-sub/import/cvgh0qqws79dbpcl", text)
        self.assertIn("https://sub.example.com/my-secret-sub/json/cvgh0qqws79dbpcl", text)

    def test_order_waiting_payment_and_provisioning_renders_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = pathlib.Path(tmpdir)
            shop_db = tmp_path / "vpn_shop.db"
            store = Store(shop_db)
            base_settings = load_settings(VPN_SHOP_DIR)
            settings = replace(
                base_settings,
                root_dir=VPN_SHOP_DIR,
                database_path=shop_db,
                platega_enabled=False,
                web_public_base_url="https://preview.example.com",
                subscription_base_url="https://sub.example.com/my-secret-sub",
            )
            checkout = WebCheckout(settings, store)
            order = store.create_order(
                kind="new",
                status="waiting_payment",
                transport="vless",
                duration_days=30,
                profile_mode="standard",
                family_label=None,
                base_price_rub=149,
                final_price_rub=149,
                promo_id=None,
                invite_id=None,
                customer_chat_id="web:anon-test",
                privacy_ack=True,
                loss_policy_ack=True,
                terms_version="1.0",
                customer_email="test@example.com",
                meta={"web_token": "tok123", "device_limit": 3},
                web_token="tok123",
            )
            order_pid = order["public_id"]

            # Test 1: waiting_payment renders without AttributeError or order_poll_script
            html_wp = checkout.render_order(headers={"Host": "preview.example.com"}, order=order).decode("utf-8")
            self.assertIn('"rawStatus": "waiting_payment"', html_wp)
            self.assertIn('"state": "waiting"', html_wp)
            self.assertIn('id="ordWait"', html_wp)
            self.assertNotIn("order_poll_script", html_wp)
            self.assertNotIn('http-equiv="refresh"', html_wp)

            # Test 2: provisioning renders v2.1 with state=provisioning, NO v1 refresh loop
            store.update_order_status(order_pid, "provisioning")
            prov_order = store.get_order(order_pid)
            html_prov = checkout.render_order(headers={"Host": "preview.example.com"}, order=prov_order).decode("utf-8")
            self.assertIn('"rawStatus": "provisioning"', html_prov)
            self.assertIn('"state": "provisioning"', html_prov)
            self.assertIn('id="ordProvisioning"', html_prov)
            self.assertNotIn('http-equiv="refresh"', html_prov)
            self.assertNotIn("Заказ обрабатывается", html_prov)


    def test_expiration_reminder_email_links_sanitize_and_no_name_error(self) -> None:
        from vpn_shop.mailer import render_expiration_reminder_email_html, render_expiration_reminder_email_text
        # 1. 24 hours reminder (1_day): strictly 'через 24 часа', no 'завтра', no confusing tech rows
        html_24h = render_expiration_reminder_email_html(
            customer_email="rem@example.com",
            reminder_kind="1_day",
            setup_url="https://sub.example.com/my-secret-sub/json/sub_rem_123",
        )
        self.assertIn('href="https://sub.example.com/my-secret-sub/import/sub_rem_123" class="btn"', html_24h)
        self.assertNotIn('href="https://sub.example.com/my-secret-sub/json/sub_rem_123" class="btn"', html_24h)
        self.assertIn('>https://sub.example.com/my-secret-sub/import/sub_rem_123<', html_24h)
        self.assertIn("через 24 часа", html_24h)
        self.assertNotIn("завтра", html_24h)
        self.assertNotIn("Конфигурации и ключи", html_24h)
        self.assertNotIn("Перенастройка устройств", html_24h)

        text_24h = render_expiration_reminder_email_text(
            customer_email="rem@example.com",
            reminder_kind="1_day",
            setup_url="https://sub.example.com/my-secret-sub/json/sub_rem_123",
        )
        self.assertIn("https://sub.example.com/my-secret-sub/import/sub_rem_123", text_24h)
        self.assertNotIn("/json/", text_24h)
        self.assertIn("через 24 часа", text_24h)
        self.assertNotIn("завтра", text_24h)

        # 2. 1 hour reminder (1_hour): urgent red, 'через 1 час'
        html_1h = render_expiration_reminder_email_html(
            customer_email="rem@example.com",
            reminder_kind="1_hour",
            setup_url="https://sub.example.com/my-secret-sub/json/sub_rem_123",
        )
        self.assertIn("#ef4444", html_1h)
        self.assertIn("через 1 час", html_1h)
        self.assertNotIn("завтра", html_1h)

        text_1h = render_expiration_reminder_email_text(
            customer_email="rem@example.com",
            reminder_kind="1_hour",
            setup_url="https://sub.example.com/my-secret-sub/json/sub_rem_123",
        )
        self.assertIn("через 1 час", text_1h)

        # 3. Expired subscription (expired): 'завершилось', 'Возобновить доступ'
        html_exp = render_expiration_reminder_email_html(
            customer_email="rem@example.com",
            reminder_kind="expired",
            setup_url="https://sub.example.com/my-secret-sub/json/sub_rem_123",
        )
        self.assertIn("Действие вашей подписки завершилось", html_exp)
        self.assertIn("Возобновить доступ на сайте", html_exp)
        self.assertNotIn("завтра", html_exp)

        text_exp = render_expiration_reminder_email_text(
            customer_email="rem@example.com",
            reminder_kind="expired",
            setup_url="https://sub.example.com/my-secret-sub/json/sub_rem_123",
        )
        self.assertIn("Возобновить доступ", text_exp)
        self.assertIn("подошёл к концу", text_exp)

    def test_otvet14_safe_improvements_indexes_magic_link_dow_and_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = pathlib.Path(tmpdir)
            shop_db = tmp_path / "otvet14_shop.db"
            store = Store(shop_db)
            store.init()

            # 1. Verify profile_email_changes table and new B-Tree indexes exist
            with store.read_connection() as rconn:
                tables = {r["name"] for r in rconn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
                indexes = {r["name"] for r in rconn.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()}
            self.assertIn("profile_email_changes", tables)
            for expected_idx in (
                "ix_profiles_status_awg_reset",
                "ix_profiles_xui_sub_id",
                "ix_profiles_xui_client_id",
                "ix_orders_customer_email_lower",
                "ix_orders_manager_msg",
                "ix_referral_attributions_referrer",
                "ix_referral_ledger_referrer_status",
                "ix_referral_payouts_referrer",
                "idx_email_changes_sub_time",
                "idx_email_changes_prof_time",
                "idx_email_changes_ip_time",
            ):
                self.assertIn(expected_idx, indexes)

            # 2. Verify consume_magic_link does NOT open write transaction on invalid token
            with patch.object(store, "transaction", wraps=store.transaction) as mock_tx:
                res = store.consume_magic_link("forged_invalid_token_xyz")
                self.assertIsNone(res)
                self.assertEqual(mock_tx.call_count, 0)

            # Valid magic link works for first and subsequent visits
            store.create_magic_link(email="safe@example.com", token="valid_tok_123", ttl_seconds=600, request_ip="127.0.0.1")
            self.assertEqual(store.consume_magic_link("valid_tok_123"), "safe@example.com")
            with patch.object(store, "transaction", wraps=store.transaction) as mock_tx2:
                self.assertEqual(store.consume_magic_link("valid_tok_123"), "safe@example.com")
                self.assertEqual(mock_tx2.call_count, 0)

            # 3. Verify _sub_profile_cache is bounded OrderedDict
            self.assertIsInstance(subjson_app._sub_profile_cache, subjson_app.collections.OrderedDict)
            self.assertEqual(subjson_app._PROFILE_CACHE_MAX_SIZE, 5000)


if __name__ == "__main__":
    unittest.main()
