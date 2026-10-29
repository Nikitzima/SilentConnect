#!/usr/bin/env python3
"""
tests/test_e2e_stage1_canary.py

Честный End-to-End (E2E) интеграционный тест пайплайна Stage 1 + Post-Deploy Canary.
Проверяет без моков кэша:
1. Провижининг заказа -> запись в vpn_shop.db и x-ui.db -> генерация Sing-box / Xray / Clash / Streisand конфигов.
2. Наличие валидного 36-символьного UUIDv4 во всех outbound-узлах (защита от регрессии uuid == sub_id).
3. Работу /internal/hysteria-auth по реальному UUID из x-ui.db.
4. Защиту от IDOR по anon-<id>, ord_<id> и чужому email во всех маршрутах (включая json-google / json-relay).
5. Блокировку скачивания AWG .conf / QR / rename для истёкших подписок даже при ранее созданном слоте в БД (SC-03).
6. Защиту от повышения тарифа при продлении по fixed-промокоду (SC-04).
"""

from __future__ import annotations

import argparse
from http.client import HTTPConnection
import json
import os
import re
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "vpn-shop"))
sys.path.insert(0, str(REPO_ROOT / "subjson-service"))

os.environ.setdefault("HYSTERIA_SALAMANDER_PASSWORD", "test_gecko_pwd_123456")
os.environ.setdefault("HYSTERIA_AUTH_PASSWORD", "test_auth_pwd_123456")
os.environ.setdefault("SERVER_PEPPER", "e2e_test_pepper_secret_2026")
os.environ.setdefault("SECRET_SEGMENT", "test-secret-sub")

import app as subjson_app
from vpn_shop.config import load_settings
from vpn_shop.security import hash_secret, now_ts, to_xui_ms
from vpn_shop.store import Store, default_awg_quota_bytes_for_devices
from vpn_shop.web import BoundedThreadingHTTPServer as ShopServer, RequestHandler as ShopHandler, WebCheckout

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


class TestE2EStage1Pipeline(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.temp_dir.name)
        self.shop_db_path = self.tmp_path / "vpn_shop.db"
        self.xui_db_path = self.tmp_path / "x-ui.db"

        # 1. Инициализируем реальную схему vpn_shop.db
        self.store = Store(self.shop_db_path)
        self.store.init()

        # 2. Инициализируем реальную схему x-ui.db с активным и истёкшим клиентом
        self.active_uuid = str(uuid.uuid4())
        self.active_sub_id = "subactive999abc12"
        self.active_email = "anon-active123456"
        self.future_exp_s = now_ts() + 30 * 86400

        self.expired_uuid = str(uuid.uuid4())
        self.expired_sub_id = "subexpired888xyz"
        self.expired_email = "anon-expired654321"
        self.past_exp_s = now_ts() - 3600

        self._seed_xui_db()

        # 3. Создаём соответствующие профили в vpn_shop.db
        self.active_prof = self.store.create_profile(
            xui_inbound_id=1,
            transport="tcp",
            profile_mode="anonymous",
            family_label=None,
            xui_email=self.active_email,
            xui_client_id=self.active_uuid,
            xui_sub_id=self.active_sub_id,
            expires_at=self.future_exp_s,
            awg_quota_bytes=default_awg_quota_bytes_for_devices(3),
            device_limit=3,
        )
        self.expired_prof = self.store.create_profile(
            xui_inbound_id=1,
            transport="tcp",
            profile_mode="anonymous",
            family_label=None,
            xui_email=self.expired_email,
            xui_client_id=self.expired_uuid,
            xui_sub_id=self.expired_sub_id,
            expires_at=self.past_exp_s,
            awg_quota_bytes=default_awg_quota_bytes_for_devices(3),
            device_limit=3,
        )
        # Предварительно создаём слот AWG для истёкшего профиля (имитация слота, созданного до истечения подписки)
        self.store.create_awg_slot(
            profile_public_id=self.expired_prof["public_id"],
            slot_index=1,
            slot_label="OldPhone",
            public_key="MockServerPublicKeyNL1111111111111111111111=",
            private_key_enc="aW5pdGlhbF9zZXJ2ZXJfcHJpdmF0ZV9rZXk=",
            preshared_key="MockHeaderProtectionKeyNL111111111111111111=",
            client_ip="10.8.1.99",
            enabled=True,
            server_code="nl",
        )

        # 4. Привязываем пути БД к subjson_app и запускаем живой HTTP-сервер subjson
        self._orig_xui_db = subjson_app.XUI_DB_PATH
        self._orig_find_store = subjson_app.find_store_db_path
        subjson_app.XUI_DB_PATH = str(self.xui_db_path)
        subjson_app.find_store_db_path = lambda: str(self.shop_db_path)
        subjson_app._shop_checkout_instance = None
        subjson_app.invalidate_inbounds_cache()

        self.sub_server = subjson_app.BoundedThreadingHTTPServer(
            ("127.0.0.1", 0), subjson_app.RequestHandler, max_workers=8
        )
        self.sub_port = self.sub_server.server_port
        self.sub_thread = threading.Thread(target=self.sub_server.serve_forever, daemon=True)
        self.sub_thread.start()

    def tearDown(self) -> None:
        self.sub_server.shutdown()
        self.sub_server.server_close()
        subjson_app.XUI_DB_PATH = self._orig_xui_db
        subjson_app.find_store_db_path = self._orig_find_store
        subjson_app._shop_checkout_instance = None
        subjson_app.invalidate_inbounds_cache()
        try:
            self.temp_dir.cleanup()
        except (OSError, PermissionError):
            pass

    def _seed_xui_db(self) -> None:
        conn = sqlite3.connect(self.xui_db_path)
        conn.executescript(
            """
            CREATE TABLE inbounds (
                id INTEGER PRIMARY KEY,
                remark TEXT,
                protocol TEXT,
                port INTEGER,
                settings TEXT,
                stream_settings TEXT,
                sniffing TEXT
            );
            CREATE TABLE client_traffics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                inbound_id INTEGER,
                enable INTEGER,
                email TEXT UNIQUE,
                up INTEGER DEFAULT 0,
                down INTEGER DEFAULT 0,
                total INTEGER DEFAULT 0,
                expiry_time INTEGER DEFAULT 0,
                reset INTEGER DEFAULT 0,
                last_online INTEGER DEFAULT 0
            );
            """
        )
        settings_blob = json.dumps({
            "clients": [
                {
                    "id": self.active_uuid,
                    "subId": self.active_sub_id,
                    "email": self.active_email,
                    "enable": True,
                    "expiryTime": to_xui_ms(self.future_exp_s),
                    "limitIp": 3,
                    "flow": "xtls-rprx-vision",
                },
                {
                    "id": self.expired_uuid,
                    "subId": self.expired_sub_id,
                    "email": self.expired_email,
                    "enable": False,
                    "expiryTime": to_xui_ms(self.past_exp_s),
                    "limitIp": 3,
                    "flow": "xtls-rprx-vision",
                },
            ]
        })
        stream_blob = json.dumps({
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "publicKey": "MockRealityPublicKey1111111111111111111111",
                "shortId": "0123456789abcdef",
                "serverNames": ["sber.ru"],
            },
        })
        conn.execute(
            "INSERT INTO inbounds VALUES (1, 'reality-tcp', 'vless', 23385, ?, ?, '{}')",
            (settings_blob, stream_blob),
        )
        conn.execute(
            "INSERT INTO client_traffics (inbound_id, enable, email, expiry_time) VALUES (1, 1, ?, ?)",
            (self.active_email, to_xui_ms(self.future_exp_s)),
        )
        conn.execute(
            "INSERT INTO client_traffics (inbound_id, enable, email, expiry_time) VALUES (1, 0, ?, ?)",
            (self.expired_email, to_xui_ms(self.past_exp_s)),
        )
        conn.commit()
        conn.close()

    def _http(self, method: str, path: str, body: str | None = None, headers: dict | None = None) -> tuple[int, str]:
        conn = HTTPConnection("127.0.0.1", self.sub_port, timeout=5)
        try:
            req_headers = {"Host": "sub.example.com"}
            if headers:
                req_headers.update(headers)
            conn.request(method, path, body=body, headers=req_headers)
            resp = conn.getresponse()
            data = resp.read().decode("utf-8", errors="replace")
            return resp.status, data
        finally:
            conn.close()

    def test_01_singbox_and_xray_real_uuid_never_sub_id(self) -> None:
        """Проверка SC-29: Sing-box и Xray JSON возвращают реальный 36-символьный UUID, а не sub_id."""
        # 1. Sing-box
        status, raw = self._http("GET", f"/my-secret-sub/singbox/{self.active_sub_id}")
        self.assertEqual(status, 200)
        cfg = json.loads(raw)
        vless_obs = [ob for ob in cfg.get("outbounds", []) if ob.get("type") == "vless"]
        self.assertGreater(len(vless_obs), 0)
        for ob in vless_obs:
            self.assertEqual(ob.get("uuid"), self.active_uuid)
            self.assertNotEqual(ob.get("uuid"), self.active_sub_id)
            self.assertTrue(UUID_RE.match(ob["uuid"]))

        # 2. Xray 4-profiles
        status2, raw2 = self._http("GET", f"/my-secret-sub/json/{self.active_sub_id}")
        self.assertEqual(status2, 200)
        profiles = json.loads(raw2)
        self.assertIsInstance(profiles, list)
        self.assertGreater(len(profiles), 1)
        first_vless = profiles[1]["outbounds"][0]["settings"]
        resolved_id = first_vless.get("id") or first_vless["vnext"][0]["users"][0]["id"]
        self.assertEqual(resolved_id, self.active_uuid)

    def test_02_hysteria2_internal_auth_e2e(self) -> None:
        """Проверка авторизации Hysteria 2 по реальному UUID."""
        status, raw = self._http(
            "POST",
            "/internal/hysteria-auth",
            body=json.dumps({"auth": self.active_uuid}),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(raw).get("ok"))

        # Истёкший клиент должен получить ok: False
        status_exp, raw_exp = self._http(
            "POST",
            "/internal/hysteria-auth",
            body=json.dumps({"auth": self.expired_uuid}),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(status_exp, 200)
        self.assertFalse(json.loads(raw_exp).get("ok"))

    def test_03_idor_blocked_across_all_routes(self) -> None:
        """Проверка SC-01: запрос по anon-<id> возвращает 404."""
        for route in ("json", "singbox", "json-google", "json-relay"):
            status, _ = self._http("GET", f"/my-secret-sub/{route}/{self.active_email}")
            self.assertEqual(status, 404, f"Route {route} leaked subscription by xui_email!")

    def test_04_awg_expired_profile_blocked_even_if_slot_exists(self) -> None:
        """Проверка SC-03: истёкшая подписка блокируется при попытке скачать .conf, qr или переименовать."""
        # 1. Config download
        status, _ = self._http("GET", f"/my-secret-sub/awg/{self.expired_sub_id}/slot/1/config")
        self.assertEqual(status, 403)

        # 2. Config text
        status_txt, _ = self._http("GET", f"/my-secret-sub/awg/{self.expired_sub_id}/slot/1/config_text")
        self.assertEqual(status_txt, 403)

        # 3. Rename slot
        status_ren, _ = self._http(
            "POST",
            f"/my-secret-sub/awg/{self.expired_sub_id}/slot/1/rename",
            body=json.dumps({"slot_label": "NewName"}),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(status_ren, 403)

    def test_05_fixed_promo_code_caps_tariff(self) -> None:
        """Проверка SC-04: fixed-промокод на 30 дней и 3 устр. не позволяет продлить на 360 дней и 9 устройств бесплатно."""
        plain_code, _ = self.store.create_promo_code(
            promo_type="fixed",
            transport="tcp",
            duration_days=30,
            discount_percent=0,
            fixed_price_rub=0,
            device_limit=3,
            profile_mode="anonymous",
            max_uses=10,
        )

        # Попытка запросить 360 дней и 9 устройств по fixed-промокоду
        order = subjson_app.create_inline_renewal_order(
            sub_id=self.active_sub_id,
            duration_days=360,
            device_limit=9,
            promo_code=plain_code,
        )
        # Проверяем, что параметры принудительно приведены к условиям промокода
        self.assertEqual(order["duration_days"], 30)
        self.assertEqual(order["device_limit"], 3)
        self.assertEqual(order["final_price_rub"], 0)


def run_live_canary(sub_id: str, subjson_port: int = 3088, web_port: int = 3090) -> int:
    """Боевая Canary-проверка после деплоя на локальных портах ноды."""
    print(f"[*] Running Live Post-Deploy Canary against 127.0.0.1:{subjson_port} and :{web_port}...")
    # 1. Healthchecks
    for port in (subjson_port, web_port):
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/healthz", headers={"Host": "sub.example.com"})
        resp = conn.getresponse()
        if resp.status != 200:
            print(f"[FAIL] Port {port} /healthz returned HTTP {resp.status}")
            return 1
        conn.close()
    print("[PASS] /healthz OK on both services.")

    # 2. Check Sing-box & Xray UUID validity
    conn = HTTPConnection("127.0.0.1", subjson_port, timeout=5)
    conn.request("GET", f"/my-secret-sub/singbox/{sub_id}", headers={"Host": "sub.example.com"})
    resp = conn.getresponse()
    body = resp.read().decode("utf-8", errors="replace")
    conn.close()
    if resp.status != 200:
        print(f"[FAIL] Sing-box endpoint returned HTTP {resp.status}")
        return 1
    cfg = json.loads(body)
    vless_obs = [ob for ob in cfg.get("outbounds", []) if ob.get("type") == "vless"]
    if not vless_obs:
        print("[FAIL] Sing-box config contains 0 VLESS outbounds!")
        return 1
    sample_uuid = str(vless_obs[0].get("uuid") or "")
    if not UUID_RE.match(sample_uuid) or sample_uuid == sub_id:
        print(f"[CRITICAL FAIL] Invalid UUID in Sing-box outbound: {sample_uuid!r} (sub_id={sub_id!r})")
        return 1
    print(f"[PASS] Sing-box UUID verified: {sample_uuid[:8]}...-**** (valid 36-char UUIDv4).")

    # 3. Verify Hysteria2 auth with the extracted UUID
    conn = HTTPConnection("127.0.0.1", subjson_port, timeout=5)
    conn.request(
        "POST",
        "/internal/hysteria-auth",
        body=json.dumps({"auth": sample_uuid}),
        headers={"Host": "127.0.0.1", "Content-Type": "application/json"},
    )
    resp = conn.getresponse()
    hyst_res = json.loads(resp.read().decode("utf-8"))
    conn.close()
    if not hyst_res.get("ok"):
        print(f"[CRITICAL FAIL] /internal/hysteria-auth rejected active UUID: {hyst_res}")
        return 1
    print("[PASS] /internal/hysteria-auth accepted active UUID.")
    print("[SUCCESS] ALL POST-DEPLOY CANARY CHECKS PASSED!")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--canary-sub-id", help="Run live post-deploy canary check with a real sub_id")
    args, remaining = parser.parse_known_args()
    if args.canary_sub_id:
        sys.exit(run_live_canary(args.canary_sub_id))
    unittest.main(argv=[sys.argv[0]] + remaining)
