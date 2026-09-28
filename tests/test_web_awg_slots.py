import json
import http.client
import os
import shutil
import sys
import tempfile
import threading
import unittest
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "vpn-shop") not in sys.path:
    sys.path.insert(0, str(ROOT / "vpn-shop"))
if str(ROOT / "subjson-service") not in sys.path:
    sys.path.insert(0, str(ROOT / "subjson-service"))

os.environ.setdefault("SERVER_PEPPER", "unit-test-pepper-0123456789abcdefghijklmnop")
os.environ.setdefault("SECRET_SEGMENT", "test-secret-sub")
os.environ.setdefault("CLUSTER_SYNC_SECRET", "test-cluster-sync-token-secret-999")

from vpn_shop.store import Store, AWG_TIER_QUOTAS_BYTES
from vpn_shop.config import Settings, load_settings
from vpn_shop.web import WebCheckout, RequestHandler, build_slot_conf


class TestWebAwgSlots(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = Path(tempfile.mkdtemp())
        db_path = cls.tmp_dir / "vpn_shop.db"
        cls.store = Store(db_path)
        cls.store.init()

        import dataclasses
        base_settings = load_settings(cls.tmp_dir)
        cls.settings = dataclasses.replace(
            base_settings,
            database_path=db_path,
            cluster_sync_secret="test-cluster-sync-token-secret-999",
            cf_turnstile_enabled=False,
            cf_turnstile_secret_key="",
            web_listen_host="127.0.0.1",
            web_listen_port=0,
        )
        cls.checkout = WebCheckout(cls.settings, cls.store)
        RequestHandler.checkout = cls.checkout

        # Start ephemeral HTTP server for endpoint tests
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), RequestHandler)
        cls.port = cls.server.server_address[1]
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        if cls.server:
            cls.server.shutdown()
            cls.server.server_close()
        shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def setUp(self):
        # Create a fresh profile for each test
        import uuid
        uid = uuid.uuid4().hex[:8]
        self.profile = self.store.create_profile(
            xui_inbound_id=1,
            transport="vless",
            profile_mode="individual",
            family_label=None,
            xui_email=f"sub_{uid}@domain.com",
            xui_client_id=str(uuid.uuid4()),
            expires_at=1800000000,
            device_limit=3,
        )
        self.sub_id = self.profile["public_id"]

    def _http_request(
        self,
        method: str,
        path: str,
        headers: dict | None = None,
        body: bytes | str | None = None,
    ) -> tuple[int, dict, bytes]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=35)
        req_headers = headers or {}
        if isinstance(body, str):
            body = body.encode("utf-8")
        conn.request(method, path, body=body, headers=req_headers)
        res = conn.getresponse()
        resp_headers = {k.lower(): v for k, v in res.getheaders()}
        resp_body = res.read()
        conn.close()
        return res.status, resp_headers, resp_body

    def test_01_ensure_awg_slot_and_idempotency(self):
        pid = self.profile["public_id"]
        slot1 = self.checkout.ensure_awg_slot(pid, 1, "Мой Ноутбук")
        self.assertIsNotNone(slot1)
        self.assertEqual(slot1["slot_index"], 1)
        self.assertEqual(slot1["slot_label"], "Мой Ноутбук")
        self.assertTrue(slot1["public_key"])
        self.assertTrue(slot1["client_ip"].startswith("10.8.1."))

        # Idempotent call must return the same slot
        slot1_again = self.checkout.ensure_awg_slot(pid, 1)
        self.assertEqual(slot1["id"], slot1_again["id"])
        self.assertEqual(slot1["public_key"], slot1_again["public_key"])

        # Slot index 4 exceeds limit of 3
        with self.assertRaises(ValueError):
            self.checkout.ensure_awg_slot(pid, 4)

        # Slot index 0 or negative
        with self.assertRaises(ValueError):
            self.checkout.ensure_awg_slot(pid, 0)

    def test_02_render_awg_slots_widget(self):
        pid = self.profile["public_id"]
        # Ensure 3 slots
        slots = self.checkout.ensure_awg_slots_for_profile(self.profile)
        self.assertEqual(len(slots), 3)

        html = self.checkout.render_awg_slots_widget(self.profile, self.sub_id)
        self.assertIn("Оставшийся трафик Amnezia:", html)
        self.assertIn("ГБ из", html)
        self.assertIn("Устройство 1", html)
        self.assertIn("Устройство 2", html)
        self.assertIn("Устройство 3", html)
        self.assertIn("awg-progress-track", html)
        self.assertIn("awg-action-btn", html)
        self.assertIn("openAwgQrModal", html)
        self.assertIn("renameAwgSlot", html)
        self.assertIn("Сброс квоты:", html)
        self.assertIn("Трафик в разделе", html)
        self.assertIn("🛡️ Основной", html)
        self.assertIn("setConnectionMode('standard')", html)
        self.assertIn("copyAwgKey", html)
        self.assertIn("openAwgSwitchModal", html)
        self.assertIn("Безлимитно", html)

    def test_03_get_slot_config_download(self):
        status, headers, body = self._http_request("GET", f"/sub/awg/{self.sub_id}/slot/1/config")
        self.assertEqual(status, HTTPStatus.OK)
        self.assertIn("application/x-wireguard-profile", headers.get("content-type", ""))
        self.assertIn("attachment;", headers.get("content-disposition", ""))
        self.assertIn(".conf", headers.get("content-disposition", ""))

        conf_text = body.decode("utf-8")
        self.assertIn("[Interface]", conf_text)
        self.assertIn("[Peer]", conf_text)
        self.assertIn("PrivateKey =", conf_text)
        self.assertIn("PublicKey =", conf_text)
        self.assertIn("Jc =", conf_text)
        self.assertIn("H1 =", conf_text)

    def test_03b_get_slot_config_text(self):
        status, headers, body = self._http_request("GET", f"/sub/awg/{self.sub_id}/slot/1/config_text")
        self.assertEqual(status, HTTPStatus.OK)
        self.assertIn("text/plain", headers.get("content-type", ""))
        conf_text = body.decode("utf-8")
        self.assertIn("[Interface]", conf_text)
        self.assertIn("[Peer]", conf_text)
        self.assertIn("PrivateKey =", conf_text)

    def test_04_get_slot_qr_code(self):
        status, headers, body = self._http_request("GET", f"/sub/awg/{self.sub_id}/slot/1/qr")
        self.assertEqual(status, HTTPStatus.OK)
        self.assertIn("image/png", headers.get("content-type", ""))
        self.assertGreater(len(body), 50)
        # PNG signature check
        self.assertEqual(body[:4], b"\x89PNG")

    def test_05_post_slot_rename(self):
        payload = json.dumps({"slot_label": "Рабочий Mac"}).encode("utf-8")
        status, headers, body = self._http_request(
            "POST",
            f"/sub/awg/{self.sub_id}/slot/2/rename",
            headers={"Content-Type": "application/json", "Content-Length": str(len(payload))},
            body=payload,
        )
        self.assertEqual(status, HTTPStatus.OK)
        data = json.loads(body.decode("utf-8"))
        self.assertTrue(data.get("ok"))
        self.assertEqual(data.get("slot_index"), 2)
        self.assertEqual(data.get("slot_label"), "Рабочий Mac")

        # Verify in store
        slot2 = self.store.get_awg_slot_by_index(self.profile["public_id"], 2)
        self.assertIsNotNone(slot2)
        self.assertEqual(slot2["slot_label"], "Рабочий Mac")

    def test_05b_post_slot_switch_country_and_verification_gate(self):
        # 1. Switch slot 1 from NL to PL
        payload = json.dumps({"country": "pl"}).encode("utf-8")
        status, headers, body = self._http_request(
            "POST",
            f"/sub/awg/{self.sub_id}/slot/1/switch_country",
            headers={"Content-Type": "application/json", "Content-Length": str(len(payload))},
            body=payload,
        )
        self.assertEqual(status, HTTPStatus.OK)
        data = json.loads(body.decode("utf-8"))
        self.assertTrue(data.get("ok"))
        self.assertEqual(data.get("server_code"), "pl")
        self.assertIn("Локация успешно переключена на Польша", data.get("message", ""))
        self.assertIn("приостановлено", data.get("message", ""))

        # Verify active in store
        active_slot = self.store.get_awg_slot_by_index(self.profile["public_id"], 1)
        self.assertEqual(active_slot["server_code"], "pl")
        self.assertEqual(active_slot["enabled"], 1)

        # Verify old NL slot config is preserved in DB (not deleted!)
        nl_slot = self.store.get_awg_slot_by_index(self.profile["public_id"], 1, server_code="nl")
        self.assertIsNotNone(nl_slot)
        self.assertEqual(nl_slot["enabled"], 0)

        # 2. Verification Gate Failure simulation: target server fails
        from unittest.mock import patch
        with patch("vpn_shop.awg_manager.add_slot_peer", return_value=False):
            payload_fi = json.dumps({"country": "fi"}).encode("utf-8")
            status, headers, body = self._http_request(
                "POST",
                f"/sub/awg/{self.sub_id}/slot/1/switch_country",
                headers={"Content-Type": "application/json", "Content-Length": str(len(payload_fi))},
                body=payload_fi,
            )
            self.assertEqual(status, HTTPStatus.BAD_REQUEST)
            fail_data = json.loads(body.decode("utf-8"))
            self.assertFalse(fail_data.get("ok"))
            self.assertIn("Не удалось активировать подключение к Финляндия", fail_data.get("error", ""))
            self.assertIn("сохранено и продолжает работать", fail_data.get("error", ""))

            # PL connection remains active and untouched
            current_active = self.store.get_awg_slot_by_index(self.profile["public_id"], 1)
            self.assertEqual(current_active["server_code"], "pl")
            self.assertEqual(current_active["enabled"], 1)

    def test_06_get_subscription_view(self):
        status, headers, body = self._http_request("GET", f"/sub/{self.sub_id}")
        self.assertEqual(status, HTTPStatus.OK)
        self.assertIn("text/html", headers.get("content-type", ""))
        html = body.decode("utf-8")
        self.assertIn("Подписка SilentConnect", html)
        self.assertIn("awg-quota-widget", html)
        self.assertIn("Оставшийся трафик Amnezia:", html)

    def test_07_post_traffic_sync_auth_and_deltas(self):
        # 1. Missing auth
        status, _, body = self._http_request(
            "POST",
            "/api/internal/awg/traffic-sync",
            headers={"Content-Type": "application/json"},
            body=b"{}",
        )
        self.assertEqual(status, HTTPStatus.UNAUTHORIZED)

        # 2. Invalid auth token
        status, _, body = self._http_request(
            "POST",
            "/api/internal/awg/traffic-sync",
            headers={"Content-Type": "application/json", "Authorization": "Bearer wrong-secret"},
            body=b"{}",
        )
        self.assertEqual(status, HTTPStatus.UNAUTHORIZED)

        # 3. Valid auth token
        slot = self.checkout.ensure_awg_slot(self.profile["public_id"], 1)
        pubkey = slot["public_key"]

        sync_payload = {
            "node_id": "nl-prod-01",
            "collected_at": 1758200000,
            "deltas": [
                {
                    "public_key": pubkey,
                    "delta_rx_bytes": 5000000,
                    "delta_tx_bytes": 10000000,
                }
            ],
        }
        body_bytes = json.dumps(sync_payload).encode("utf-8")
        status, _, body = self._http_request(
            "POST",
            "/api/internal/awg/traffic-sync",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.settings.cluster_sync_secret}",
                "Content-Length": str(len(body_bytes)),
            },
            body=body_bytes,
        )
        self.assertEqual(status, HTTPStatus.OK)
        res = json.loads(body.decode("utf-8"))
        self.assertEqual(res.get("status"), "ok")
        self.assertEqual(res.get("recorded_count"), 1)
        self.assertIn(self.profile["public_id"], res.get("affected_profiles", []))

        # Check quota in DB
        quota = self.store.get_awg_profile_quota(self.profile["public_id"])
        self.assertEqual(quota["awg_used_bytes"], 15000000)

    def test_08_post_traffic_sync_quota_exceeded_disables_peer(self):
        slot = self.checkout.ensure_awg_slot(self.profile["public_id"], 1)
        pubkey = slot["public_key"]

        # Delta that exceeds the 250 GB limit
        excessive_bytes = 260 * 1024 * 1024 * 1024
        sync_payload = {
            "node_id": "nl-prod-01",
            "deltas": [
                {
                    "public_key": pubkey,
                    "delta_rx_bytes": excessive_bytes // 2,
                    "delta_tx_bytes": excessive_bytes // 2,
                }
            ],
        }
        body_bytes = json.dumps(sync_payload).encode("utf-8")
        status, _, body = self._http_request(
            "POST",
            "/api/internal/awg/traffic-sync",
            headers={
                "Content-Type": "application/json",
                "X-Sync-Secret": "test-cluster-sync-token-secret-999",
                "Content-Length": str(len(body_bytes)),
            },
            body=body_bytes,
        )
        self.assertEqual(status, HTTPStatus.OK)
        res = json.loads(body.decode("utf-8"))
        self.assertEqual(res.get("status"), "ok")
        self.assertIn(pubkey, res.get("disable_peers", []))

        # Check slot in store is disabled
        slot_updated = self.store.get_awg_slot_by_public_key(pubkey)
        self.assertFalse(slot_updated["enabled"])

    def test_09_edge_cases_and_error_handling(self):
        # 1. Non-existent sub_id config -> 404
        status, _, body = self._http_request("GET", "/sub/awg/nonexistent-sub-id/slot/1/config")
        self.assertEqual(status, HTTPStatus.NOT_FOUND)

        # 2. Invalid slot index (non-integer) -> 400
        status, _, body = self._http_request("GET", f"/sub/awg/{self.sub_id}/slot/abc/config")
        self.assertEqual(status, HTTPStatus.BAD_REQUEST)

        # 3. Invalid slot index (exceeds device limit 3) -> 400
        status, _, body = self._http_request("GET", f"/sub/awg/{self.sub_id}/slot/4/config")
        self.assertEqual(status, HTTPStatus.BAD_REQUEST)

        # 4. Invalid JSON on sync -> 400
        status, _, body = self._http_request(
            "POST",
            "/api/internal/awg/traffic-sync",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.settings.cluster_sync_secret}",
            },
            body=b"not-json",
        )
        self.assertEqual(status, HTTPStatus.BAD_REQUEST)

    def test_10_boost_landing_page(self):
        status, headers, body = self._http_request("GET", "/boost")
        self.assertEqual(status, HTTPStatus.FOUND)
        self.assertEqual(headers.get("location"), "/")

        status_api, headers_api, _ = self._http_request("GET", "/api/boost")
        self.assertEqual(status_api, HTTPStatus.FOUND)
        self.assertEqual(headers_api.get("location"), "/")

    def test_11_qr_code_pure_python_fallback(self):
        from unittest.mock import patch
        import vpn_shop.web as web_mod
        with patch.object(web_mod, "qrcode", None):
            status, headers, body = self._http_request("GET", f"/sub/awg/{self.sub_id}/slot/1/qr")
            self.assertEqual(status, HTTPStatus.OK)
            self.assertIn("image/", headers.get("content-type", ""))
            # Must return valid PNG signature or SVG xml
            if "image/png" in headers.get("content-type", ""):
                self.assertEqual(body[:4], b"\x89PNG")
            else:
                self.assertTrue(body.startswith(b"<svg"))

    def test_12_slot_rename_with_quotes_and_special_chars(self):
        quote_label = "Bob's \"Mac\""
        payload = json.dumps({"slot_label": quote_label}).encode("utf-8")
        status, _, body = self._http_request(
            "POST",
            f"/sub/awg/{self.sub_id}/slot/3/rename",
            headers={"Content-Type": "application/json", "Content-Length": str(len(payload))},
            body=payload,
        )
        self.assertEqual(status, HTTPStatus.OK)
        data = json.loads(body.decode("utf-8"))
        # Store.sanitize_device_label strips quotes and special chars for injection safety
        self.assertEqual(data.get("slot_label"), "Bobs Mac")

        # Ensure widget HTML renders safely with data attributes
        html_widget = self.checkout.render_awg_slots_widget(self.profile, self.sub_id)
        self.assertIn("data-label=", html_widget)
        self.assertIn("Bobs Mac", html_widget)

    def test_13_cabinet_multi_profile_scoped_ids(self):
        import uuid
        uid2 = uuid.uuid4().hex[:8]
        profile2 = self.store.create_profile(
            xui_inbound_id=1,
            transport="vless",
            profile_mode="individual",
            family_label=None,
            xui_email=f"sub_{uid2}@domain.com",
            xui_client_id=str(uuid.uuid4()),
            expires_at=1800000000,
            device_limit=3,
        )
        # Render cabinet with both profiles - must be clean selection view without AWG widget clutter
        profiles_list = [
            {"public_id": self.profile["public_id"], "sub_id": self.profile["public_id"], "raw_profile": self.profile},
            {"public_id": profile2["public_id"], "sub_id": profile2["public_id"], "raw_profile": profile2},
        ]
        cabinet_bytes = self.checkout.render_cabinet("test@example.com", profiles_list)
        cabinet_html = cabinet_bytes.decode("utf-8")
        
        # Verify clean cabinet card structure
        self.assertIn("Подписка #1", cabinet_html)
        self.assertIn("Подписка #2", cabinet_html)
        self.assertIn(self.profile["public_id"], cabinet_html)
        self.assertIn(profile2["public_id"], cabinet_html)
        self.assertNotIn('<div class="awg-slots-hub">', cabinet_html)
        self.assertNotIn('<div class="awg-quota-widget">', cabinet_html)
        self.assertNotIn('class="awg-slot-card"', cabinet_html)
        self.assertNotIn('class="awg-modal-overlay"', cabinet_html)

        # Ensure DOM IDs in AWG widgets are uniquely scoped when rendered individually
        widget1 = self.checkout.render_awg_slots_widget(self.profile, self.profile["public_id"])
        widget2 = self.checkout.render_awg_slots_widget(profile2, profile2["public_id"])
        self.assertIn(f"awg-slot-{self.profile['public_id']}-1", widget1)
        self.assertIn(f"awg-slot-{profile2['public_id']}-1", widget2)
        self.assertNotEqual(
            f"awg-slot-{self.profile['public_id']}-1",
            f"awg-slot-{profile2['public_id']}-1",
        )


if __name__ == "__main__":
    unittest.main()
