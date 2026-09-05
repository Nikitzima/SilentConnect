#!/usr/bin/env python3
import threading
import time

QUIESCE_LOCK = threading.Lock()
QUIESCE_ACTIVE = False
QUIESCE_LEASE_UNTIL = 0.0

def is_quiesced() -> bool:
    global QUIESCE_ACTIVE
    with QUIESCE_LOCK:
        return bool(QUIESCE_ACTIVE)


import base64
import collections
import copy
import hashlib
import hmac
import html
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import secrets
import socket
import sqlite3
import ssl
import sys
import time
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

# Centralized pricing logic
_vpn_shop_path = str(Path(__file__).resolve().parent.parent / "vpn-shop")
if _vpn_shop_path not in sys.path:
    sys.path.insert(0, _vpn_shop_path)

try:
    from vpn_shop.catalog import calculate_renewal_price, quote_price
    from vpn_shop.security import hash_secret
    from vpn_shop.web import subscription_setup_url, verify_cf_turnstile
except ImportError:
    def quote_price(device_limit: int = 3, duration_days: int = 30, settings: Any = None) -> int:
        prices = {3: 100, 6: 150, 9: 200}
        monthly = prices.get(device_limit, 100)
        months = max(duration_days // 30, 1)
        discount = 0
        if duration_days >= 360:
            discount = 30
        elif duration_days >= 180:
            discount = 20
        elif duration_days >= 90:
            discount = 10
        raw = (monthly * months * (100 - discount)) // 100
        if raw <= 0:
            return 0
        return max(((raw + 5) // 10) * 10 - 1, 9)

    calculate_renewal_price = quote_price

    def hash_secret(value: str) -> str:
        effective_pepper = os.environ.get("SERVER_PEPPER", "silentconnect-pepper-secret-v1").encode("utf-8")
        return hmac.new(effective_pepper, value.encode("utf-8"), hashlib.sha256).hexdigest()

    def subscription_setup_url(subscription_url: str) -> str:
        return subscription_url.replace("/sub/json/", "/my-secret-sub/import/")

    def verify_cf_turnstile(secret_key: str, response_token: str, client_ip: str = "") -> bool:
        return True


LOGGER = logging.getLogger("subjson-service")


def get_env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if value is None or value == "":
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


LISTEN_HOST = get_env("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(get_env("LISTEN_PORT", "3088"))
SECRET_SEGMENT = get_env("SECRET_SEGMENT", "my-secret-sub").strip("/")  # PLACEHOLDER

DEFAULT_SECRET_SEGMENTS = {"my-secret-sub", "secret-sub", ""}

SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("Referrer-Policy", "no-referrer"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    (
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; "
        "frame-src https://challenges.cloudflare.com; connect-src 'self'; "
        "form-action 'self' https://t.me; base-uri 'self'; frame-ancestors 'none'",
    ),
)


def _verify_order_web_token(order_row: Any, token: str | None) -> bool:
    if not order_row or not token:
        return False
    # Check web_token_hash if column exists
    stored_hash = None
    try:
        if "web_token_hash" in order_row.keys():
            stored_hash = order_row["web_token_hash"]
    except Exception:
        pass
    eff_pepper = os.environ.get("SERVER_PEPPER", "").encode("utf-8") or SERVER_PEPPER
    if stored_hash:
        msg = f"order_web\x00{token}".encode("utf-8")
        expected_hash = hmac.new(eff_pepper, msg, hashlib.sha256).hexdigest()
        if hmac.compare_digest(str(stored_hash), expected_hash):
            return True
    # Fallback to meta_json['web_token']
    try:
        raw_meta = order_row["meta_json"] if "meta_json" in order_row.keys() else None
        if raw_meta:
            meta = json.loads(raw_meta) if isinstance(raw_meta, str) else raw_meta
            legacy = str(meta.get("web_token") or "")
            if legacy and hmac.compare_digest(legacy, token):
                return True
    except Exception:
        pass
    return False


def validate_production_secrets() -> None:
    is_prod = (
        os.environ.get("ENV", "").strip().lower() == "production"
        or os.environ.get("PRODUCTION", "").strip() in ("1", "true", "yes")
    )
    if is_prod:
        segment = os.environ.get("SECRET_SEGMENT", "").strip("/").strip()
        if not segment or segment in DEFAULT_SECRET_SEGMENTS:
            raise RuntimeError(
                "Production environment detected (ENV=production / PRODUCTION=1), "
                "but default or empty SECRET_SEGMENT is configured. "
                "A secure SECRET_SEGMENT must be set in production."
            )
        pepper = os.environ.get("SERVER_PEPPER", "").strip()
        if pepper == "silentconnect-pepper-secret-v1":
            raise RuntimeError(
                "Production environment detected (ENV=production / PRODUCTION=1), "
                "but default placeholder SERVER_PEPPER is configured. "
                "A secure SERVER_PEPPER must be set in production."
            )


validate_production_secrets()
PUBLIC_HOST = os.environ.get("PUBLIC_HOST", "").strip()
PUBLIC_SUBSCRIPTION_ORIGIN = os.environ.get("PUBLIC_SUBSCRIPTION_ORIGIN", "").strip().rstrip("/")
FALLBACK_SUBSCRIPTION_ORIGIN = os.environ.get("FALLBACK_SUBSCRIPTION_ORIGIN", "").strip().rstrip("/")
XUI_DB_PATH = get_env("XUI_DB_PATH", "/etc/x-ui/x-ui.db")
RELAY_PUBLIC_HOST = os.environ.get("RELAY_PUBLIC_HOST", "").strip()
RELAY_TCP_PORT = int(os.environ.get("RELAY_TCP_PORT", "443"))
RELAY_XHTTP_PORT = int(os.environ.get("RELAY_XHTTP_PORT", "8443"))
HAPP_PROVIDER_ID = os.environ.get("HAPP_PROVIDER_ID", "").strip()
HAPP_PROFILE_TITLE = os.environ.get("HAPP_PROFILE_TITLE", "SilentConnect").strip()[:25]
HAPP_SUPPORT_URL = os.environ.get("HAPP_SUPPORT_URL", "https://t.me/your_vpn_bot").strip()
HAPP_WEB_PAGE_URL = os.environ.get("HAPP_WEB_PAGE_URL", "https://silentconnect.net").strip()  # PLACEHOLDER
HAPP_RENEW_URL = os.environ.get("HAPP_RENEW_URL", "https://t.me/your_vpn_bot?start=open").strip()
HAPP_PROFILE_UPDATE_INTERVAL = os.environ.get("HAPP_PROFILE_UPDATE_INTERVAL", "1").strip()
HAPP_SERVER_DESCRIPTION = os.environ.get("HAPP_SERVER_DESCRIPTION", "Основной сервер").strip()[:30]
HAPP_SUB_INFO_ENABLED = os.environ.get("HAPP_SUB_INFO_ENABLED", "1").strip().lower() not in {"0", "false", "no", "off"}
HAPP_UNLIMITED_AFTER_DAYS = int(os.environ.get("HAPP_UNLIMITED_AFTER_DAYS", "3650"))
HAPP_RESOLVE_DNS_DOMAIN = os.environ.get("HAPP_RESOLVE_DNS_DOMAIN", "dns.google").strip()
HAPP_RESOLVE_DNS_IP = os.environ.get("HAPP_RESOLVE_DNS_IP", "8.8.8.8").strip()
HAPP_EXTRA_EXCLUDE_ROUTES = os.environ.get("HAPP_EXTRA_EXCLUDE_ROUTES", "").strip()
HAPP_HEADERS_ENABLED = os.environ.get("HAPP_HEADERS_ENABLED", "1").strip().lower() not in {"0", "false", "no", "off"}
EXTRA_OUTBOUNDS_PATH = os.environ.get("EXTRA_OUTBOUNDS_PATH", "").strip()
MULTI_CONFIGS_PATH = os.environ.get("MULTI_CONFIGS_PATH", "").strip()
STATIC_JSON_CONFIG_DIR = os.environ.get("STATIC_JSON_CONFIG_DIR", "").strip()
# Provisioning should set this to the flag matching the server's actual
# location (derived from its public IP) - defaults to NL since that's every
# existing server's actual location today.
SERVER_COUNTRY_FLAG = os.environ.get("SERVER_COUNTRY_FLAG", "\U0001f1f3\U0001f1f1").strip()
# Every non-NL server generates its own random Salamander password during
# provisioning (correctly, it's already in each server's own subjson.env) -
# but nothing here ever read it, so every Hysteria2 profile silently used
# NL's own password regardless of server. A client obfuscating with the
# wrong password is indistinguishable from the connection just hanging.
HYSTERIA_SALAMANDER_PASSWORD = get_env("HYSTERIA_SALAMANDER_PASSWORD")  # PLACEHOLDER
HYSTERIA_AUTH_PASSWORD = get_env("HYSTERIA_AUTH_PASSWORD")  # PLACEHOLDER
WS443_PUBLIC_HOST = os.environ.get("WS443_PUBLIC_HOST", "sub.example.com").strip()
WS443_PUBLIC_PORT = int(os.environ.get("WS443_PUBLIC_PORT", "443"))
WS443_PATH = os.environ.get("WS443_PATH", "/sc-ws-9c3d7f1e").strip() or "/sc-ws-9c3d7f1e"
INTERNAL_SECRET = os.environ.get("INTERNAL_SECRET", "").strip()  # PLACEHOLDER

# Rate limiting for subscription endpoints (FIX 2026-08-23, audit #10; upgraded to bounded LRU in Phase P2).
RATE_LIMIT_ENABLED = os.environ.get("RATE_LIMIT_ENABLED", "1").strip() == "1"
RATE_LIMIT_RPM = int(os.environ.get("RATE_LIMIT_RPM", "1200"))
RATE_LIMIT_MAX_ENTRIES = int(os.environ.get("RATE_LIMIT_MAX_ENTRIES", "10000"))
_rate_lock = threading.Lock()
_rate_map: collections.OrderedDict[str, list[float]] = collections.OrderedDict()


def _rate_gc(now: float) -> None:
    # Retained for interface compatibility; LRU bounds enforce max capacity automatically
    pass


def check_rate_limit(ip: str) -> bool:
    if not RATE_LIMIT_ENABLED or RATE_LIMIT_RPM <= 0:
        return True
    now = time.time()
    cutoff = now - 60.0
    with _rate_lock:
        if ip in _rate_map:
            _rate_map.move_to_end(ip)
            fresh = [t for t in _rate_map[ip] if t > cutoff]
        else:
            fresh = []

        if len(fresh) >= RATE_LIMIT_RPM:
            _rate_map[ip] = fresh
            return False

        fresh.append(now)
        _rate_map[ip] = fresh

        while len(_rate_map) > RATE_LIMIT_MAX_ENTRIES:
            _rate_map.popitem(last=False)

        return True
  # FIX 2026-08-22: was hardcoded, see AUDIT_REPORT

# Per-server REALITY identities (Классический/Быстрый share one TCP keypair;
# Запасной has its own gRPC keypair). Each new server generates its own keys
# server-side (xray x25519) and sets these here.
TCP_REALITY_PUBLIC_KEY = os.environ.get("TCP_REALITY_PUBLIC_KEY", "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA").strip()  # PLACEHOLDER 0000000000
TCP_REALITY_SHORT_ID = os.environ.get("TCP_REALITY_SHORT_ID", "0123456789abcdef").strip()  # PLACEHOLDER
TCP_REALITY_SNI_CLASSIC = os.environ.get("TCP_REALITY_SNI_CLASSIC", "sber.ru").strip()
TCP_REALITY_SNI_FAST = os.environ.get("TCP_REALITY_SNI_FAST", "st.kinopoisk.ru").strip()
GRPC_REALITY_PUBLIC_KEY = os.environ.get("GRPC_REALITY_PUBLIC_KEY", "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA").strip()  # PLACEHOLDER 0000000000
GRPC_REALITY_SHORT_ID = os.environ.get("GRPC_REALITY_SHORT_ID", "0123456789abcdef").strip()  # PLACEHOLDER
GRPC_REALITY_SNI = os.environ.get("GRPC_REALITY_SNI", "vk.com").strip()
GRPC_SERVICE_NAME = os.environ.get("GRPC_SERVICE_NAME", "grpc-maxru").strip()

FI_REALITY_SNI_CLASSIC = os.environ.get("FI_REALITY_SNI_CLASSIC", "sber.ru").strip()
FI_REALITY_SNI_FAST = os.environ.get("FI_REALITY_SNI_FAST", "sber.ru").strip()
FI_GRPC_REALITY_SNI = os.environ.get("FI_GRPC_REALITY_SNI", "sbercloud.ru").strip()
FI_XHTTP_REALITY_PUBLIC_KEY = os.environ.get("FI_XHTTP_REALITY_PUBLIC_KEY", "ASvvjJ4dOcHst5FWDJ9D562UQ0nN1pAw0l13Z58RNQA").strip()
FI_XHTTP_REALITY_SHORT_ID = os.environ.get("FI_XHTTP_REALITY_SHORT_ID", "a1b2c3d4e5f60718").strip()
FI_XHTTP_REALITY_SNI = os.environ.get("FI_XHTTP_REALITY_SNI", "sberauto.com").strip()
FI_XHTTP_REALITY_PORT = int(os.environ.get("FI_XHTTP_REALITY_PORT", "443"))
HYSTERIA_PORT = int(os.environ.get("HYSTERIA_PORT", "443"))

PL_STANDBY_HOST = os.environ.get("PL_STANDBY_HOST", "").strip()
PL_REALITY_PUBLIC_KEY = os.environ.get("PL_REALITY_PUBLIC_KEY", "hgj4G9HOJ_6OVYTkeha0vVdEcyuLVzR4Op2BV7CeIW8").strip()
PL_REALITY_SHORT_ID = os.environ.get("PL_REALITY_SHORT_ID", "9f4a1c7e2b8d0a35").strip()
PL_REALITY_SNI_CLASSIC = os.environ.get("PL_REALITY_SNI_CLASSIC", "swdist.apple.com").strip()
PL_REALITY_SNI_FAST = os.environ.get("PL_REALITY_SNI_FAST", "gateway.icloud.com").strip()
PL_XHTTP_REALITY_PORT = int(os.environ.get("PL_XHTTP_REALITY_PORT", "8443"))

HAPP_DOWNLOAD_URL = "https://www.happ.su/main"
HAPP_IOS_URL = "https://apps.apple.com/us/app/happ-proxy-utility/id6504287215"
HAPP_ANDROID_URL = "https://play.google.com/store/apps/details?id=com.happproxy"
HAPP_ANDROID_APK_URL = "https://github.com/Happ-proxy/happ-android/releases/latest/download/Happ.apk"
STREISAND_IOS_URL = "https://apps.apple.com/us/app/streisand/id6450534064"
STREISAND_MACOS_URL = "https://apps.apple.com/us/app/streisand/id6450534064"
V2RAYTUN_IOS_URL = "https://apps.apple.com/us/app/v2raytun/id6476628951"
V2RAYTUN_ANDROID_URL = "https://play.google.com/store/apps/details?id=com.v2raytun.android"
CLASH_DOWNLOAD_URL = "https://github.com/clash-verge-rev/clash-verge-rev/releases"
V2RAYN_DOWNLOAD_URL = "https://github.com/2dust/v2rayN/releases"
NEKOBOX_DOWNLOAD_URL = "https://github.com/MatsuriDayo/NekoBoxForAndroid/releases"
V2RAYNG_DOWNLOAD_URL = "https://github.com/2dust/v2rayNG/releases"
SINGBOX_IOS_URL = "https://apps.apple.com/app/sing-box/id6451272673"
SINGBOX_DOWNLOAD_URL = "https://github.com/SagerNet/sing-box/releases"

# --- 100% Official Authentic Original Application Icons ---
# Official authentic app icons encoded as self-contained base64 data-URIs
OFFICIAL_CLASH_ICON = "data:image/png;base64,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"

OFFICIAL_NEKOBOX_ICON = "data:image/png;base64,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"

OFFICIAL_V2RAYNG_ICON = "data:image/png;base64,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"

OFFICIAL_HAPP_ICON = "data:image/jpeg;base64,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"

OFFICIAL_STREISAND_ICON = "data:image/jpeg;base64,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"

OFFICIAL_V2RAYTUN_ICON = "data:image/jpeg;base64,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"


OFFICIAL_V2RAYN_ICON = "data:image/x-icon;base64,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Kv+zhiz/zJgy/8yZMqDNmTIBAAAAAAAAAADNmTI/zZky/LuMLv+qfyr/mnMl/5t8Pf//////qqih/yEaCf89Lg7/blMb/3VYHP91WBz/dVgc/3VYHP+AYB//jWki/5pyJf+qfyr/u4wu/82ZMvzNmTI/AAAAAAAAAADNmTK2yZYx/6yAKv+ieCf/jmoi/5F0Ov///////////6qoof8hGgn/PS4O/29TG/91WBz/dVgc/3VYHP91WBz/gGAf/45qIv+ieCf/rIAq/8mWMf/NmTK1zZkyAc2ZMhvNmTL4u4wu/6p+Kv+TbSP/iGUh/4ZsOP////////////////+qqKH/IRoJ/z4uDv9vUxv/dVgc/3VYHP91WBz/dVgc/4hlIf+TbiP/qn4q/7uMLv/NmTL4zZkyG82ZMlnNmTL/sYQr/6R6KP+OaiL/fV0e/4ZsOP//////////////////////qqih/yEaCf89Lg7/blMb/3VYHP91WBz/dVgc/31dHv+OaiL/pHoo/7GEK//NmTL/zJkyWc2ZMobLmDL/q4Aq/551Jv+NaSL/dlkd/4ZsOP///////////////////////////6qoof8hGgn/PS4O/29TG/91WBz/dVgc/3ZZHf+NaSL/nnUm/6uAKv/LmDL/zZkyhs2ZMpvJljH/qn8q/5pzJf+KZyH/dVgc/4ZsOP////////////////////////////////+qqKH/IRoJ/z4uDv9vUxv/dVgc/3VYHP+KZyH/mnMl/6p/Kv/JljH/zZkynM2ZMpvIljH/qn8q/5pzJf+KZyH/dVgc/4ZsOP///////////8bEvv/x8O3/////////////////qqih/yEaCf89Lg7/blMb/3VYHP+KZyH/mnMl/6p/Kv/JljH/zZkym82ZMobLmDL/q4Aq/551Jv+NaSL/dlkd/4ZsOP///////////56akv91ZEH/9fPv/////////////////6qoof8hGgn/PS4O/3BUG/+NaSL/nnUm/6uAKv/LlzL/zZkyhs2ZMlnNmTL/sYQr/6R6KP+OaiL/e1we/3BbMv///////////56akv9YQhX/kHhI//Xz7/////////////////+qqKH/IRoJ/0IyD/+GZCD/pHoo/7GEK//NmTL/zZkyWc2ZMhvNmTL4u4wu/6p+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/////////Pz8/25qX/8eFwb/LSIK/15GF/90Vxz/dVgc/3VYHP91WBz/dVgc/3VYHP+EYiD/jmoi/5t0Jv+qfyr/s4Ys/82ZMv/NmTLQzZkyA82ZMh/NmTL5ypcx/6yAKv+qfir/kWwj/41qIv95Wh3/dVgc/+jj2P///////////////////////Pz8/25qX/8eFwb/LSIK/15GF/90Vxz/dVgc/3VYHP91WBz/dVgc/3laHf+NaSL/kWwj/6p+Kv+rgCr/ypcx/82ZMvnNmTIfzZkyS82ZMv/DkjD/qn8q/6Z7KP+OaiL/iGYh/3VYHP91WBz/6OPY/////////////////////////////Pz8/25qX/8eFwb/LSIK/15GF/90Vxz/dVgc/3VYHP91WBz/dVgc/4lmIf+OaiL/pnsp/6p/Kv/DkjD/zZky/82ZMkvMmTJtzZky/76OL/+qfyr/oXgn/45qIv+DYiD/dVgc/3VYHP/o49j//////////////////////////////////Pz8/25qX/8eFwb/LSIK/15GF/90Vxz/dVgc/3VYHP91WBz/hGIg/41qIv+gdyf/qn8q/76OL//NmTL/zJkybM2ZMnzNmTL/vIwu/6p/Kv+edib/jmoi/4FgH/91WBz/dVgc/+jj2P///////////////////////////////////////Pz8/25qX/8eFwb/LSIK/15GF/90Vxz/dVgc/3VYHP+BYB//jmoi/552Jv+qfyr/vIwu/82ZMv/NmTJ9zZkyfM2ZMv+8jC7/qn8q/552Jv+OaiL/gWAf/3VYHP91WBz/6OPY////////////3dvY/+Xj3////////////////////////Pz8/25qX/8eFwb/LSIK/15GFv90Vxz/dVgc/4FgH/+OaiL/nnYm/6p/Kv+8jC7/zZky/82ZMnzMmTJszZky/76OLv+qfyr/oHcn/45qIv+DYiD/dVgc/3VYHP/o49j////////////HxcH/TkIq/+zp4v///////////////////////Pz8/25qX/8eFwb/LSIK/15GF/90Vxz/g2Ig/45qIv+heCf/qn8q/76OLv/NmTL/zJkybM2ZMkvNmTL/w5Iw/6p/Kv+meyn/jmoi/4lmIf91WBz/dFcc/+fi2P///////////8fFwf83KQ3/gmo3/+3q4v///////////////////////Pz8/25qX/8eFwb/LSIK/15GF/+HZSD/jmoi/6Z7KP+qfyr/w5Iw/82ZMv/NmTJLzZkyHs2ZMvnKlzH/rIAq/6p+Kv+RbCP/jWki/3dZHf9WQRX/4NzV////////////x8XB/zcpDf9xVRv/hm04/+7q4v///////////////////////Pz8/25qX/8eFwb/LyML/3BUG/+QayP/qn4q/6uAKv/KlzH/zZky+c2ZMh7NmTIDzZky0cyYMv+zhiz/qn8q/5x0Jv+OaiL/gGAf/zwtDv/b2NP////////////HxcH/NykN/3FVG/91WBz/hmw4/+7q4////////////////////////Pz8/25qX/8iGgf/OCkN/31eHv+pfin/s4Ys/82ZMv/NmTLQzZkyAwAAAADNmTJ8zZky/8GQL/+qfyr/qH0p/5BrI//MvJ7/2NXO//n49////////////9DMw/9TPhT/c1Yc/3VYHP91WBz/hmw4/+7q4v///////////////////////Pz8/4h9Zf9UPxT/eFkd/6R6KP/BkC//zZky/82ZMnwAAAAAAAAAAM2ZMh7NmTLyzJgy/7CDK/+qfyr/n3Yn/93Svf//////////////////////3NXG/3RXHP91WBz/dVgc/3VYHP91WBz/hmw4/+7q4////////////////////////v38/8CmdP+ofSn/sIMr/8yYMv/NmTLyzZkyHgAAAAAAAAAAAAAAAM2ZMo7NmTL/xJIw/6t/Kv+qfir/spRY/7Kaav+ymmr/qJJo/6KPZv+XgVT/dVgc/3VYHP91WBz/dVgc/3VYHP91WBz/hGo1/6KPZv+ok2j/sppq/7Kaav+8oW3/w6Zs/6yBLf/EkjD/zZky/82ZMo4AAAAAAAAAAAAAAAAAAAAAzZkyFM2ZMuDNmTL/u4wu/6p/Kv+qfin/mXIl/45qIv+NaSL/g2Ig/3laHf91WBz/dVgc/3VYHP91WBz/dVgc/3VYHP94Wh3/hGIg/41pIv+OaiL/mXIl/6l+Kf+rfyr/u4wu/82ZMv/NmTLfzZkyFAAAAAAAAAAAAAAAAAAAAAAAAAAAzZkyRc2ZMvfMmDL/uIkt/6p/Kv+qfir/nnYn/5BrI/+OaiL/jWki/4hmIf+DYiD/gGAf/4FgH/+DYiD/iGYh/41pIv+OaiL/kGsj/552J/+qfir/qn8q/7iJLf/MmDL/zZky982ZMkUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAzZkyaM2ZMvvMmTL/vIwu/6t/Kv+qfyr/qH0p/5x0Jv+RbCP/jmoi/45qIv+OaiL/jmoi/45qIv+OaiL/kWwj/5x0Jv+ofSn/qn8q/6t/Kv+7jC7/zJky/82ZMvvNmTJoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADNmTIBzZkyaM2ZMvfNmTL/xJIw/7CDK/+qfyr/qn8q/6p+Kv+meyn/oXgn/552Jv+edSb/oXgn/6Z7Kf+qfir/qn8q/6p/Kv+xhCv/xJIw/82ZMv/NmTL3zZkyaM2ZMgEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAzZkyRc2ZMuDNmTL/zJgy/8GQL/+zhiz/rIAq/6p/Kv+qfyr/qn8q/6p/Kv+qfyr/qn8q/6uAKv+zhiz/wZAv/8yYMv/NmTL/zZky4M2ZMkUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAzZkyFM2ZMo/NmTLyzZky/82ZMv/KlzH/w5Iw/76OL/+7jC7/vIwu/76OLv/DkjD/ypcx/82ZMv/NmTL/zZky8s2ZMo7NmTIUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM2ZMh7NmTJ8zZky0M2ZMvnNmTL/zZky/82ZMv/NmTL/zZky/82ZMv/NmTL6zZky0M2ZMnzNmTIeAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADNmTIDzZkyHs2ZMkvMmTJtzZkyfM2ZMnzMmTJszZkyS82ZMh7NmTIDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/4Af//4AB//4AAH/8AAA/8AAAD/AAAA/gAAAHwAAAA8AAAAOAAAABgAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAABgAAAAcAAAAPAAAAD4AAAB/AAAA/wAAAP/AAAP/4AAH//gAH//+AH/ygAAAAwAAAAYAAAAAEABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgIAAAP//AACAgIAA/wAAAMDAwACAAAAAgACAAP///wAAgAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAETMkUSQjAAAAAAAAAAAAAAAAAAAAAAIyRSEjJFEyMhAAAAAAAAAAAAAAAAAAASNFEkMUUkIyRUVAAAAAAAAAAAAAAAAFEjEjIxIyExExMhIyEAAAAAAAAAAAAAAkUUI0FFFBNCNCFFEkUQAAAAAAAAAAAAEyMjERMRMTETExMSRRITAAAAAAAAAAAFEkNBMTE2ERE2ERQxMSRSEAAAAAAAAAAkMjEjFhETFxMRExMRRREkUgAAAAAAAAITIUExYBcRERYTFhFxE0UTJDAAAAAAADRSRRMlaWEXFxMWMTERMRNBIyEAAAAAARITERE4UABpEWFhEWExFjEjFFJAAAAABSRRQxQ4hQaWFxMaFjlhExY0IyEwAAAAJDITITE4iFAAEBYREWMXERMRMUUhAAAAEyNBNBE4iIUGlhNjFxFhFjExQxJFAAABMkExETE4iIhQABAWEQE2MWERMjEyQAACMjI0MWE4iIiFBpYTYTFpFhMXEUMhMAABNBERETE4iIiIUAAQNhYTYxYRExJDIAAyMjRRNhY4iIiIhQaWERNhEQExNDEyNAASQxEUERE4iIiIiFAAGhaRYxEWERMkMgAyMkURMXE4iIiIiIUGlhNjFhcTETQTIwAkMRMTFhY4iIiIiIhQABYRY5FhFyExIQATJDFBETE4iIiIiIiFBpAxYRcTETQjRQAyMSMRcWE4iIiIiIiIUAYBMWEWExEyEgASQxQxERY4iIhYiIiIhQAQFxNjEUMUUQAyMjERNjE4iIiViIiIiFAAaRYRExIxIwAkNBNDEWE4iIhgWIiIiIUGlhMTYRFFJAATITERQTY4iIgDFYiIiIhQAGlhE0USEwAjI0IxMWE4iIgBAViIiIiFBpYxMRE0MgATQjEUETFoiIiWNhWIiIiIUAAWETEjIQABIxExMWY4iIhgEWNYiIiIhQaWMUVCMAACNFQhExMYiIgDFxEViIiIiFBgExEyEAABMhE0MYiIiIhpYRcTWIiIiIUWFjIUUAAAJFEREYiIiIg2EwEWFYiIiIhRMhRSAAAAEyRRRYiIiIgRFhNjE1iIiIiFFFIVAAAAAhURJzQTQxFxcRYRYRYWMRMScyNAAAAAAVQjESExEUMRFjFjFjExMUMTEkMgAAAAABI0URNBExEUMRYRcRERQTJDIxIAAAAAAAEyQxExNBExFDExETQxExESQyAAAAAAAAASMjFCETFBMREUMRETJDFRMgAAAAAAAAABVCMRMRMRExQxExQxEyQhIAAAAAAAAAAAEjRRRUEzQTERNBMkMTNFAAAAAAAAAAAAATIyETJBEyRREjETISEgAAAAAAAAAAAAABI0UhEyMRE0MUVCNFEAAAAAAAAAAAAAAAASNFQjFFEhIyEjEgAAAAAAAAAAAAAAAAAAEjI0IyRUMkUSAAAAAAAAAAAAAAAAAAAAAAEjEjEjITAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA////////AAD//8AD//8AAP/+AAB//wAA//gAAB//AAD/4AAAB/8AAP/AAAAD/wAA/4AAAAH/AAD/AAAAAP8AAP4AAAAAfwAA/AAAAAA/AAD4AAAAAB8AAPAAAAAADwAA8AAAAAAPAADgAAAAAAcAAOAAAAAABwAAwAAAAAADAADAAAAAAAMAAMAAAAAAAwAAgAAAAAABAACAAAAAAAEAAIAAAAAAAQAAgAAAAAABAACAAAAAAAEAAIAAAAAAAQAAgAAAAAABAACAAAAAAAEAAIAAAAAAAQAAgAAAAAABAACAAAAAAAEAAIAAAAAAAQAAwAAAAAADAADAAAAAAAMAAMAAAAAAAwAA4AAAAAAHAADgAAAAAAcAAPAAAAAADwAA8AAAAAAPAAD4AAAAAB8AAPwAAAAAPwAA/gAAAAB/AAD/AAAAAP8AAP+AAAAB/wAA/8AAAAP/AAD/4AAAB/8AAP/4AAAf/wAA//4AAH//AAD//8AD//8AAP///////wAAKAAAADAAAABgAAAAAQAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADNmTIAzJkyAMyYMgDKlzEAyJUxAMWTMADEkjAAw5IwAMSTMAC7jC4As4UsAK6CKwCrgCoAq38qAKp/KgCsgCoAy5gyAMuXMgC/ji8AsYQrAMGQLwCwgysAqn4qAKl9KQCnfCkApXsoAKZ8KQDJljEAtogtAKl+KQCjeSgAmnMmAJRuJACQayMAj2siAI5qIgCQbCMAonkoALWHLADGlDAAnnUmAJJtIwCNaiIAnnYmAK2BKgCheCcAjWkiAIpnIQCHZSEAhmQgAJpzJQCIZSEAf18fAHlaHQB2WB0AdVgcAMiWMQCWcCQAiGYhAHtcHgB2WBwAfFweAJdwJQCadS0AknArAJJvKgCRbyoAhmcoAHtfJQB7XiUAd1ofAHxfJQCsgjIArYMyAKuAKwCifTYA9vTwAPn39AD49/QAhWw3AHpeJQDVzLoA49W5AKyCMACvgysAl3UzAPz7+QD///8AhGs4AHRXHAB6XSQA1869AN/VwQCjfC8AqH0pAJZ1MwBnVTEAYEgXAHNWHADYz78Azsi8AGZPIQBlSxgAlW8kAL+PLwCQbCQAmoBMAG1fQQB/d2YAQzonAEY0EQBvUxsA1s68AMLAuwAzKRMALSEKADIlCwBZQxUAk24kAHZZHQBHNREAW1NBADw1JgBCMQ8AKCERAB8YBgApHgkARjQQAHhaHQByVRsAVkAVAG1gRwA8NiYAQjEQAMG/ugAnIBAAHhcGACIaBwBEMxAAi2ghALOGLACOelEAQTEPACEZBwA7LA4AaE4ZAK6BKwB5Wx0Al4FTAD02JgBzWCIAOSsNAMuXMQBIOBcA1c29ADorDQCLZyEARj8vAMbBtwByVhwAj2oiANXSywBgRxcAdVccAKZ7KAB8XR4AxZQwAIlmIQCBYB8An4ZVAH1eHgCieCcAqY5XAKmOWACBYR8AyMS8ACwkEQC0llsA29PDAE89GQAmHAgAsos9AJh1LwBLOBIAKyAKAIdlIACcdCYAXkYXAFE9EwC2hywAoHcnAH5eHwCugSoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAwEBAgMCAgMBAgIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAgMBAQIBAQEBAQECAQECAQIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgIBAQEBARE5KAcJKBwRAQIBAQEBAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAICAQEBAygKC8EODw4ODxCTCwoGAwECAQICAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgIBARITFA4PDw8PDw8PDw8PDw8OFGkRAQECAgAAAAAAAAAAAAAAAAAAAAAAAAADAQIDFS0fGQ8PDxcYG6UaGxgXDw8PDw9VFQMBAgIAAAAAAAAAAAAAAAAAAAAAAAECARy+Dr/ALxomM3ciJCQkoSIhMyYeDw8PDiccAQECAAAAAAAAAAAAAAAAAAAAAgEBKBYPD7u8vYGMKyQrJCQkJCQkKyQqKRgPDw8WKAECAgAAAAAAAAAAAAAAAAACAQEHLQ8Ptre4uYBjnS+MO7oyO50vJCQrJCouFw8PLQcBAQEAAAAAAAAAAAAAAAECASgtDw8esrO0tX+Lkj14ODg4OHiUNTskJCQkIB4PDy0oAQECAAAAAAAAAAAAAQIBHBYPDx46rliwsYmQkWJjODg4ODg4ODc+qCQkJDoeDw8WHAIBAQAAAAAAAAAAAQIDHQ8PHjokrlhYcn2JkJxioKQ4ODg4ODg4N68vJCQ6Hg8PHQEBAgAAAAAAAAABAQEVDg8PICQkrVhYWHKIiZCRYqA4ODg4ODg4ODirLyskMxcPDhUBAQEAAAAAAAACARIWDw8uJCQrqlhYWFiHiImQkWJjODg4ODg4ODg4qy8kJKwPDxYRAQIAAAAAAAEBAmkPDxgqJCSplVhYWFhYcn2JkJxioDg4ODg4ODg4OKkkJCoeDw5pAQECAAAAAAEBAxQPDywkK6g3lVhYWFhYWHKIiZCRYqA4ODg4ODg4OHg7JCQpDw8UEQIBAAAAAAICBg4PHiokJKY4lVhYWFhYWFiHiImQkWJjODg4ODg4ODimKyQqHg8OpwECAAAAAgEBCg8PJiQkOz04lVhYWFhYWFhYcn2JkJxioDg4ODg4ODg9OyQkHw8PCgEBAgAAAQEDCw8PMyQkNTg4lVhYWFhYWFhYWHKIiZCRYqA4ODg4ODg4NSQkMw8PCwIBAgAAAQERkw8XISQvlDg4lVhYWFhYWFhYWFiHiImQkWJjODg4ODg4lC8kIRcPDBEBAQAAAQEFDQ8YIiuMNzg4lVhYWFhYWFhYWFhYcn2JkJxioDg4ODg4N50rIhgPDjkBAQAAAgEGDg8ZIys0ODg4lVhYWFhYWFhYWFhYWHKIiZCRYqA4ODg4ODQkoRsPDgYBAgAAAQEHDw8aJCQyODg4lVhYWFhYWFhYWFhYWFiHiImQkWJjOKQ4ODIkJKUPDgcBAQAAAQIHDw8aJCQyODg4lVhYWFhYolhYWFhYWFhYcn2JkJyjYzg4ODIrJBoPDwcBAQAAAQEGDg8ZJCQ0ODg4lVhYWFhYnp9YWFhYWFhYWHKIiZCRYqA4ODQkoRsPDgYBAQAAAQEFDQ8YIiQwNzg4lVhYWFhYe5qbWFhYWFhYWFiHiImQnGJjN50kIh4PDgUBAQAAAQESkw8XISsvlDg4lVhYWFhYlnyXXFhYWFhYWFhYcn2JkJhiNy8kIRcPk5kBAQAAAQEDjQ8PMyQkNVpwjlhYWFhYe49wUVxYWFhYWFhYWHKIiZCRkjAkIA8PCwEBAQAAAQEBCg8PJiQkNIKDhFhYWFhYhYZwOFtkWFhYWFhYWFiHiImKi2OMJg8PCgEBAgAAAAECBg4PHiokL3h5elhYWFhYe3xwODhbXFhYWFhYWFhYcn1+f4CBGg8OBgIBAAAAAAEBAxQPDywkamtsbVhYWFhYbm9wODg4UXFYWFhYWFhYWHJzdHV2dxgUAwEBAAAAAAIBARMODxgqYFdYWFhYWFhYYWJjODg4OFtkWFhYWFhYWFhlZmc8aBhpAQEBAAAAAAABARJVDw8uVldYWFhYWFhYWVo4ODg4ODhbXFhYWFhYWFhYXV4ZX1UEAQEAAAAAAAABAQEVDg8PTE1OTk5PT09PUDg4ODg4ODg4UVJPT09OTk5OTlNUDhUBAQEAAAAAAAAAAQEDHQ8XF0BBQkNERUZGNzg4ODg4ODg4OEdGSERDQkFASUpLHQMBAQAAAAAAAAAAAQEBORYPDxg6JCQkOzw9ODg4ODg4ODg4ODg+NCskJD8YDw8WOQEBAQAAAAAAAAAAAAEBAigtDw8eMyQkKy80NTY3ODg4ODc2NTQvKyQjMx4PDy0oAQEBAAAAAAAAAAAAAAABAQEHLQ8PFy4qJCQkJC8wMTIyMTAvJCQkJCouDw8PLQgBAQEAAAAAAAAAAAAAAAAAAQEBKBYPDw8eKSokJCQrJCQkKyQkJCQqLBgPDw8WKAEBAQAAAAAAAAAAAAAAAAAAAAEBAhwdDg8PDx4fICEiIyQkIyUhICYeDw8PDiccAQEBAAAAAAAAAAAAAAAAAAAAAAABAQEDFRYODw8PDxcYGRoaGxgXDw8PDw8WFQMBAQEAAAAAAAAAAAAAAAAAAAAAAAAAAgEBARITFA4PDw8PDw8PDw8PDw8OFBMEAQEBAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBAQIBAwkKCwwNDg8PDhAMCwoGEQEBAQECAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQEBAQEBAwQFBgcIBgUEAwEBAQEBAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAQEBAQEBAQIBAQEBAQEBAQIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAgEBAgEBAQEBAQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD///////8AAP//wAP//wAA//4AAH//AAD/+AAAH/8AAP/gAAAH/wAA/8AAAAP/AAD/gAAAAf8AAP8AAAAA/wAA/gAAAAB/AAD8AAAAAD8AAPgAAAAAHwAA8AAAAAAPAADwAAAAAA8AAOAAAAAABwAA4AAAAAAHAADAAAAAAAMAAMAAAAAAAwAAwAAAAAADAACAAAAAAAEAAIAAAAAAAQAAgAAAAAABAACAAAAAAAEAAIAAAAAAAQAAgAAAAAABAACAAAAAAAEAAIAAAAAAAQAAgAAAAAABAACAAAAAAAEAAIAAAAAAAQAAgAAAAAABAADAAAAAAAMAAMAAAAAAAwAAwAAAAAADAADgAAAAAAcAAOAAAAAABwAA8AAAAAAPAADwAAAAAA8AAPgAAAAAHwAA/AAAAAA/AAD+AAAAAH8AAP8AAAAA/wAA/4AAAAH/AAD/wAAAA/8AAP/gAAAH/wAA//gAAB//AAD//gAAf/8AAP//wAP//wAA////////AAAoAAAAMAAAAGAAAAABACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAzZkyAc2ZMgbNmTIUzZkyKM2ZMjfNmTJAzZkyQM2ZMjjNmTInzZkyFM2ZMgbNmTIBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAzZkyAs2ZMhnNmTJUzJkylcyYMsfNmTLnzZky9MyZMvrMmDL8zJky/MyZMvrMmDL1zZky5syZMsfMmTKVzZkyVM2ZMhnNmTICAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM2ZMgbNmTI+zZkyocyZMufMmDL9zZky/82ZMv/MmTL/zZky/82ZMv/NmTL/zZky/82ZMv/NmTL/zJky/82ZMv/NmTL/zJky/M2ZMubMmTKhzZkyPs2ZMgYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADNmTIDzZkyP8yZMrbMmTL4zZky/82ZMv/NmTL/zZky/82ZMv/LmDL/yJYx/8aUMP/EkjD/xJMw/8aUMP/JljH/y5gy/82ZMv/MmTL/zZky/82ZMv/NmTL/zZky98yZMrfNmTI/zZkyAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM2ZMhnMmTKWzJky9M2ZMv/NmTL/zZky/8yYMv/GlDD/u4wu/7OFLP+ugSr/q38q/6p/Kv+rfyr/q38q/6p/Kv+sgCr/roEr/7OFLP+7jC7/xZMw/8yYMv/NmTL/zJky/82ZMv/MmTL0zJkyls2ZMhkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAzZkyPsyZMtLMmTL+zZky/82ZMv/LlzL/v44v/7GEK/+rfyr/qn8q/6p/Kv+qfyr/qn8q/6p/Kv+qfyr/qn8q/6p/Kv+qfyr/qn8q/6p/Kv+qfyr/q38q/7GEK/+/jy//y5gy/82ZMv/NmTL/zJky/syZMtLNmTI+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM2ZMgPNmTJczJgy7c2ZMv/MmTL/zJgy/8GQL/+tgSr/o3ko/6d8Kf+qfyr/qn8q/6p/Kv+qfir/qX0p/6Z8Kf+meyj/pXso/6Z8Kf+pfSn/qn4q/6p/Kv+qfyr/qn8q/6p/Kv+qfyr/r4Mr/8GQL//MmDL/zZky/8yZMv/MmTLtzZkyXM2ZMgMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAzZkyA82ZMmfNmTLzzJky/82ZMv/JljH/tocs/6t/Kv+gdyf/fl4f/41pIv+leyj/onko/5pzJf+TbiT/kGsj/45qIv+OaiL/jmoi/49qIv+QayP/lG4k/5pzJf+ieSj/qX4p/6p/Kv+qfyr/qn8q/6t/Kv+1hyz/yZYx/82ZMv/NmTL/zJky882ZMmjNmTIDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADNmTIBzZkyXMyZMvPNmTL/zZky/8aUMP+wgyv/qn8q/6p/Kv+cdCb/XkYX/1E9E/94Wh3/i2gh/41qIv+OaiL/jWoi/45qIv+OaiL/jmoi/45qIv+OaiL/jmoi/41qIv+OaiL/km0j/551Jv+pfSn/qn8q/6p/Kv+qfyr/sIMr/8aUMP/NmTL/zJky/8yZMvPNmTJdAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADNmTI+zJky7c2ZMv/NmTL/xJIw/62BKv+qfyr/qn8q/7KLPf+YdS//SzgS/ysgCv9GNBD/c1Yc/4tnIf+NaSL/i2gh/4hmIf+HZSD/hmQg/4hmIf+LZyH/jWki/45qIv+OaiL/jWoi/45qIv+SbSP/oXgn/6p+Kv+qfyr/qn8q/62BKv/EkjD/zZky/82ZMv/NmTLtzZkyPgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM2ZMhnNmTLSzJky/82ZMv/GlDD/rYEq/6p/Kv+qfyr/qX4p/7SWW//b08P/Tz0Z/yYcCP8pHgn/RDMQ/2hOGf92WBz/dlkd/3VYHP91WBz/dVgc/3VYHP92WR3/eVsd/39fH/+IZiH/jmoi/45qIv+OaiL/jmoi/5pzJv+pfin/qn8q/6p/Kv+tgSr/xpQw/82ZMv/NmTL/zJky0s2ZMhkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAzZkyBM2ZMpbMmTL+zZky/8mWMf+wgyv/qn8q/6p/Kv+pfin/lnAk/6mOWP//////yMS8/ywkEf8eFwb/IRkH/zssDv9gSBf/c1Yc/3VYHP91WBz/dVgc/3VYHP91WBz/dVgc/3VYHP92WB3/fFwe/4lmIf+OaiL/jmoi/45qIv+WcCT/qX4p/6p/Kv+qfyr/sIMr/8mWMf/MmTL/zZky/s2ZMpbNmTIDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAzZkyP82ZMvTMmTL/zJgy/7aILf+qfyr/qn8q/6l+Kf+WcCT/jmoi/6mOWP///////////8LAu/8oIRH/HhcG/yEZB/86Kw3/YEgX/3JWHP91Vxz/dVgc/3VYHP91WBz/dVgc/3VYHP91WBz/dVgc/3ZYHf+BYR//jWki/45qIv+OaiL/lnAk/6l+Kf+qfyr/qn8q/7aILf/NmTL/zZky/8yZMvTNmTI/AAAAAAAAAAAAAAAAAAAAAAAAAADNmTIFzZkyt82ZMv/NmTL/wZAv/6t/Kv+qfyr/qn8q/5pzJv+OaiL/jmoi/6mOV//////////////////CwLv/JyAQ/x4XBv8hGQf/OywO/2BIF/9yVhz/dVgc/3VYHP91WBz/dVgc/3VYHP91WBz/dVgc/3VYHP91WBz/fV4e/41pIv+NaiL/jmoi/5pzJf+qfir/qn8q/6t/Kv/BkC//zZky/82ZMv/NmTK3zZkyBQAAAAAAAAAAAAAAAAAAAADNmTI+zJky+M2ZMv/LlzL/sIMr/6p/Kv+qfyr/oXgn/45qIv+OaiL/jWoi/5+GVf//////////////////////wb+6/ycgEP8eFwb/IRkH/zssDv9gSBf/c1Yc/3VYHP91WBz/dVgc/3VYHP91WBz/dVgc/3VYHP91WBz/dVgc/31eHv+NaSL/jmoi/45qIv+ieCf/qn8q/6p/Kv+wgyv/y5gy/82ZMv/MmTL4zZkyPgAAAAAAAAAAAAAAAM2ZMgLNmTKhzZky/8yZMv+/jy//qn8q/6p/Kv+pfSn/km0j/45qIv+OaiL/gWAf/5eBU////////////////////////////8LAu/8oIRH/HhcG/yEZB/86Kw3/YEgX/3JWHP91WBz/dVgc/3VYHP91WBz/dVgc/3VYHP91WBz/dVgc/3VYHP+BYB//jmoi/45qIv+SbSP/qX4p/6p/Kv+rfyr/v48v/82ZMv/NmTL/zJkyoc2ZMgIAAAAAAAAAAM2ZMhnNmTLmzZky/8yYMv+xhCv/qn8q/6p/Kv+edib/jmoi/41qIv+JZiH/dlgd/5eBU//////////////////////////////////CwLv/JyAQ/x4XBv8hGQf/OywO/2BIF/9yVhz/dVgc/3VYHP91WBz/dVgc/3VYHP91WBz/dVgc/3VYHP92WR3/iGYh/45qIv+OaiL/nnUm/6p/Kv+qfyr/sYQr/8uYMv/MmTL/zZky582ZMhkAAAAAAAAAAM2ZMlPMmTL9zJky/8WTMP+rfyr/qn8q/6l+Kf+SbSP/jmoi/45qIv98XR7/dVgc/5eBU///////////////////////////////////////wb+6/ycgEP8eFwb/IRkH/zssDv9gSBf/c1Yc/3VYHP91WBz/dVgc/3VYHP91WBz/dVgc/3VYHP91WBz/fF0e/41qIv+OaiL/km0j/6l+Kf+qfyr/q38q/8WUMP/NmTL/zJky/M2ZMlMAAAAAzZkyAcyZMpbNmTL/zZky/7uMLv+qfyr/qn8q/6J5KP+OaiL/jmoi/4hmIf92WBz/dVgc/5eBU////////////////////////////////////////////8LAu/8oIRH/HhcG/yEZB/86Kw3/YEgX/3JWHP91WBz/dVgc/3VYHP91WBz/dVgc/3VYHP91WBz/dlgc/4hmIf+OaiL/jmoi/6N5KP+qfyr/qn8q/7uMLv/NmTL/zZky/8yZMpbNmTIBzZkyBs2ZMsfNmTL/zJgy/7OFLP+qfyr/qn8q/5pzJf+OaiL/jmoi/39fH/91WBz/dVgc/5eBU//////////////////////////////////////////////////CwLv/JyAQ/x4XBv8hGQf/OywO/2BIF/9yVhz/dVgc/3VYHP91WBz/dVgc/3VYHP91WBz/dVgc/39fH/+OaiL/jmoi/5pzJf+qfyr/qn8q/7OFLP/MmTL/zZky/8yZMsjNmTIGzZkyE82ZMufNmTL/y5gy/66BK/+qfyr/qn4q/5RuJP+OaiL/jWki/3lbHf91WBz/dVgc/5eBU///////////////////////////////////////////////////////wb+6/ycgEP8eFwb/IRkH/zssDv9gSBf/c1Yc/3VYHP91WBz/dVgc/3VYHP91WBz/dVgc/3lbHf+NaSL/jmoi/5RuJP+qfir/qn8q/66CK//LmDL/zZky/82ZMubNmTIUzZkyKM2ZMvXNmTL/yJUx/6uAKv+qfyr/qX0p/5BrI/+NaiL/i2gh/3ZYHf91WBz/dVgc/5eBU////////////////////////////////////////////////////////////8LAu/8oIRH/HhcG/yEZB/86Kw3/YEgX/3JWHP91WBz/dVgc/3VYHP91WBz/dVgc/3ZYHf+LZyH/jWoi/5BrI/+pfSn/qn8q/6t/Kv/IljH/zZky/82ZMvXNmTInzZkyN8yZMvrNmTL/xZMw/6t/Kv+qfyr/p3wp/49rIv+NaiL/iGUh/3VYHP91WBz/dVgc/5eBU//////////////////////////////////////////////////////////////////CwLv/JyAQ/x4XBv8hGQf/OywO/2BIF/9yVhz/dVgc/3VYHP91WBz/dVgc/3VYHP+IZSH/jmoi/49qIv+mfCn/qn8q/6t/Kv/FkzD/zZky/8yZMvrNmTI4zZkyP82ZMvzNmTL/xJIw/6p/Kv+qfyr/pXso/45qIv+OaiL/hmQg/3VYHP91WBz/dVgc/5eBU///////////////////////////////////////////////////////////////////////wb+6/ycgEP8eFwb/IRkH/zssDv9gSBf/c1Yc/3VYHP91Vxz/dVgc/3VYHP+GZCD/jmoi/45qIv+meyj/qn8q/6t/Kv/EkjD/zZky/82ZMvzNmTJAzZkyQM2ZMvzMmTL/xJIw/6p/Kv+qfyr/pXso/45qIv+OaiL/hmQg/3VYHP91WBz/dVgc/5eBU////////////////////////////9XSy////////////////////////////////////////////8LAu/8oIRH/HhcG/yEZB/86Kw3/YEcX/3NWHP91WBz/dVgc/3VYHP+GZCD/jWoi/45qIv+leyj/qn8q/6p/Kv/EkjD/zZky/82ZMvzNmTI/zZkyN82ZMvrNmTL/xZMw/6t/Kv+qfyr/p3wp/45qIv+OaiL/iGUh/3VYHP91WBz/dVgc/5eBU////////////////////////////0Y/L//Gwbf////////////////////////////////////////////CwLv/JyAQ/x4XBv8hGQf/OywO/2BIF/9yVhz/dVgc/3VYHP+IZSH/jmoi/49qIv+mfCn/qn8q/6t/Kv/FkzD/zZky/82ZMvrNmTI3zZkyKM2ZMvXNmTL/yJUx/6uAKv+qfyr/qX0p/5BrI/+OaiL/imch/3ZYHf91WBz/dVgc/5eBU////////////////////////////zw1Jv9IOBf/1c29////////////////////////////////////////////wb+6/ycgEP8eFwb/IRkH/zorDf9gSBf/c1Yc/3ZYHf+LZyH/jmoi/5BrI/+pfin/qn8q/6t/Kv/IlTH/zZky/82ZMvXNmTIozZkyE82ZMufNmTL/y5cy/66BK/+qfyr/qn4q/5RuJP+NaiL/jWki/3lbHf91WBz/dVgc/5eBU////////////////////////////z02Jv9CMQ//c1gi/9fOvf///////////////////////////////////////////8LAu/8oIRH/HhcG/yEZB/85Kw3/YEgX/3ZYHf+NaSL/jmoi/5RuJP+qfir/qn8q/66BK//LlzH/zZky/82ZMubNmTIUzZkyBs2ZMsjNmTL/zJgy/7OGLP+qfyr/qn8q/5pzJf+OaiL/jmoi/39fH/90Vxz/b1Mb/456Uf///////////////////////////zw1Jv9BMQ//b1Mb/3peJf/Xzr3////////////////////////////////////////////CwLv/JyAQ/x4XBv8hGQf/OywO/2hOGf+KZyH/jmoi/5pzJv+qfyr/qn8q/7OFLP/NmTL/zZky/82ZMsjNmTIGzZkyAc2ZMpXNmTL/zZky/7uMLv+qfyr/qn8q/6J5KP+OaiL/jmoi/4hlIf9yVRv/VkAV/21gR////////////////////////////zw2Jv9CMRD/b1Mb/3VYHP96XST/2M+/////////////////////////////////////////////wb+6/ycgEP8eFwb/IhoH/0QzEP9zVhz/i2gh/6J5KP+qfyr/qn8q/7uMLv/NmTL/zZky/8yZMpXNmTIBAAAAAM2ZMlTNmTL9zJky/8WTMP+rfyr/qn8q/6l+Kf+SbSP/jmoi/41pIv92WR3/RzUR/1tTQf///////////////////////////zw1Jv9CMQ//b1Mb/3VYHP91WBz/el0k/9fOvf///////////////////////////////////////////8LAu/8oIRH/HxgG/ykeCf9GNBD/eFod/6V7KP+qfyr/q38q/8WTMP/MmTL/zZky/c2ZMlQAAAAAAAAAAM2ZMhnNmTLmzZky/8yYMv+xhCv/qn8q/6p/Kv+edib/jmoi/5BsJP+agEz/bV9B/393Zv///////////////////////////0M6J/9GNBH/b1Mb/3VYHP91WBz/dVgc/3peJf/Wzrz////////////////////////////////////////////CwLv/MykT/y0hCv8yJQv/WUMV/5NuJP+pfSn/sYQr/8yYMv/NmTL/zZky582ZMhkAAAAAAAAAAM2ZMgLMmTKhzZky/82ZMv+/ji//q38q/6p/Kv+pfSn/km0j/5Z1M//8+/n//////////////////////////////////////2dVMf9gSBf/c1Yc/3VYHP91WBz/dVgc/3VYHP96XST/2M+/////////////////////////////////////////////zsi8/2ZPIf9lSxj/e1we/5VvJP+pfSn/v48v/82ZMv/NmTL/zZkyoM2ZMgIAAAAAAAAAAAAAAADNmTI+zZky+M2ZMv/LlzL/r4Mr/6p/Kv+qfyr/oXgn/5d1M//8+/n//////////////////////////////////////4RrOP90Vxz/dVgc/3VYHP91WBz/dVgc/3VYHP91WBz/el0k/9fOvf///////////////////////////////////////////9/Vwf+jfC//p3wp/6h9Kf+vgyv/ypcx/82ZMv/NmTL4zZkyPgAAAAAAAAAAAAAAAAAAAADNmTIFzZkyt82ZMv/NmTL/wZAv/6t/Kv+qfyr/qn8q/6J9Nv/29PD/+ff0//n39P/59/T/+Pf0//j39P/49/T/+Pf0/4VsN/91WBz/dVgc/3VYHP91WBz/dVgc/3VYHP91WBz/dVgc/3peJf/VzLr/+Pf0//j39P/49/T/+ff0//n39P/59/T/+ff0//n39P/j1bn/rIIw/6t/Kv/BkC//zZky/82ZMv/NmTK3zZkyBgAAAAAAAAAAAAAAAAAAAAAAAAAAzZkyPs2ZMvTNmTL/zJgy/7aILf+qfyr/qn4q/6p+Kv+adS3/knAr/5JvKv+Rbyr/hmco/3tfJf97XiX/e14l/3ZYHf91WBz/dVgc/3VYHP91WBz/dVgc/3VYHP91WBz/dVgc/3VYHP93Wh//e14l/3xfJf+GZyj/kW8q/5JvKv+ScCv/mnUt/6yCMv+tgzL/q4Ar/7aILf/MmDL/zZky/82ZMvXNmTI+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAzZkyA82ZMpbNmTL+zZky/8iWMf+wgyv/qn8q/6p/Kv+pfSn/lnAk/45qIv+OaiL/jmoi/4hmIf97XB7/dlgc/3VYHP91WBz/dVgc/3VYHP91WBz/dVgc/3VYHP91WBz/dVgc/3VYHP91WBz/fFwe/4hlIf+NaiL/jmoi/45qIv+XcCX/qX0p/6p/Kv+qfyr/sIMr/8iWMf/NmTL/zZky/s2ZMpbNmTIDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM2ZMhnNmTLSzZky/8yZMv/GlDD/rYEq/6p/Kv+qfyr/qX4p/5pzJf+OaiL/jmoi/41qIv+NaSL/iGUh/39fH/95Wh3/dlgd/3VYHP91WBz/dVgc/3VYHP92WB3/eVod/39fH/+IZSH/jWki/41qIv+OaiL/j2si/5pzJf+pfin/qn8q/6p/Kv+tgSr/xpQw/82ZMv/NmTL/zZky0s2ZMhkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADNmTI+zZky7c2ZMv/NmTL/xJIw/62BKv+qfyr/qn8q/6p+Kv+heCf/km0j/45qIv+OaiL/jmoi/45qIv+NaSL/imch/4dlIf+GZCD/hmQg/4dlIf+KZyH/jWki/45qIv+OaiL/jmoi/45qIv+SbSP/oXgn/6p/Kv+qfyr/qn8q/62BKv/DkjD/zZky/82ZMv/NmTLtzZkyPQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAzZkyXM2ZMvTNmTL/zZky/8aUMP+wgyv/qn8q/6p/Kv+qfyr/qX4p/551Jv+SbSP/jmoi/45qIv+OaiL/jWoi/45qIv+OaiL/jmoi/41qIv+OaiL/jmoi/45qIv+OaiL/km0j/552Jv+pfSn/qn8q/6p/Kv+qfyr/sIMr/8aUMP/NmTL/zZky/82ZMvTNmTJdzZkyAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAzZkyA82ZMmjNmTLzzZky/8yZMv/JljH/togt/6t/Kv+qfyr/qn8q/6p/Kv+pfin/o3ko/5pzJv+UbiT/kGsj/49rIv+OaiL/jmoi/49rIv+QbCP/lG4k/5pzJv+ieSj/qX4p/6p/Kv+qfyr/qn8q/6t/Kv+1hyz/yZYx/82ZMv/NmTL/zZky882ZMmjNmTICAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM2ZMgLNmTJczZky7c2ZMv/NmTL/zJgy/8GQL/+wgyv/q38q/6p/Kv+qfyr/qn8q/6p/Kv+qfir/qX0p/6d8Kf+leyj/pXso/6Z8Kf+pfSn/qn4q/6p/Kv+qfyr/qn8q/6p/Kv+qfyr/sIMr/8GQL//MmDL/zZky/82ZMv/NmTLtzZkyXM2ZMgIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAzZkyPsyZMtLNmTL+zZky/82ZMv/LlzL/v44v/7GEK/+rfyr/qn8q/6p/Kv+qfyr/qn8q/6p/Kv+qfyr/qn8q/6p/Kv+qfyr/qn8q/6p/Kv+qfyr/q38q/7GEK/+/ji//ypcx/82ZMv/NmTL/zZky/s2ZMtLNmTI+zZkyAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM2ZMhnNmTKWzZky9M2ZMv/MmTL/zZky/8yYMv/EkzD/u4wu/7OFLP+ugiv/q4Aq/6t/Kv+qfyr/qn8q/6t/Kv+sgCr/roIr/7OFLP+7jC7/xZMw/8uYMv/NmTL/zZky/82ZMv/NmTL0zJkyls2ZMhkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADNmTIDzZkyP82ZMrfNmTL4zZky/82ZMv/NmTL/zZky/8yYMv/KlzH/yJUx/8WTMP/EkjD/w5Iw/8WTMP/IlTH/ypcx/8yYMv/NmTL/zZky/82ZMv/NmTL/zZky+M2ZMrfNmTI+zZkyBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM2ZMgXNmTI9zJkyoc2ZMufNmTL9zZky/82ZMv/NmTL/zZky/82ZMv/MmTL/zZky/82ZMv/NmTL/zZky/82ZMv/NmTL/zZky/c2ZMufMmTKhzZkyPs2ZMgYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAzZkyAs2ZMhnNmTJTzZkylsyZMsjNmTLnzZky9cyZMvrNmTL8zZky/M2ZMvrNmTL1zZky5s2ZMsjNmTKVzZkyU82ZMhnNmTICAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAzZkyAc2ZMgbNmTITzZkyJ82ZMjfNmTI/zZkyQM2ZMjbNmTIozZkyE82ZMgbNmTIBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA///AA///AAD//gAAf/8AAP/4AAAf/wAA/+AAAAf/AAD/wAAAA/8AAP+AAAAB/wAA/gAAAAB/AAD8AAAAAD8AAPgAAAAAPwAA+AAAAAAfAADwAAAAAA8AAOAAAAAABwAA4AAAAAAHAADAAAAAAAMAAMAAAAAAAwAAgAAAAAABAACAAAAAAAEAAIAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAABAACAAAAAAAEAAIAAAAAAAQAAwAAAAAADAADAAAAAAAMAAOAAAAAABwAA4AAAAAAHAADwAAAAAA8AAPgAAAAAHwAA/AAAAAAfAAD8AAAAAD8AAP4AAAAAfwAA/4AAAAD/AAD/wAAAA/8AAP/gAAAH/wAA//gAAB//AAD//gAAf/8AAP//wAP//wAAKAAAAEAAAACAAAAAAQAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAzZkyAc2ZMgPNmTIHzZkyEM2ZMhPNmTIWzZkyFs2ZMhPNmTIOzZkyCc2ZMgPNmTIBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAzZkyAc2ZMgvNmTInzZkyUs2ZMoDMmTKozZkyxcyYMtXMmTLgzZky5s2ZMubMmTLgzJky1c2ZMsXMmTKnzZkygM2ZMlPNmTImzZkyCs2ZMgIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM2ZMgHNmTIKzZkyN82ZMoLNmTLCzJky7M2ZMvvMmDL+zZky/82ZMv/NmTL/zJky/8yZMv/NmTL/zJky/8yZMv/MmTL/zZky/82ZMv7MmDL8zZky7cuYMsPNmTKAzZkyN82ZMgrNmTIBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAzZkyAs2ZMhbNmTJgzZkyv8yZMvLMmDL+zJky/82ZMv/MmTL/zJky/8yZMv/MmTL/zJky/82ZMv/MmTL/zJky/8yZMv/NmTL/zJky/8yYMv/MmTL/zZky/82ZMv/NmTL/zZky/syZMvHMmTK+zZkyYc2ZMhfNmTIBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADNmTIBzZkyE82ZMmfNmTLRzJky+syZMv/MmTL/zZky/8yZMv/MmTL/zZky/82ZMv/NmTL/zJky/8yYMv/LlzL/ypcx/8qXMf/LlzL/y5gy/82ZMv/NmTL/zZky/8yZMv/MmTL/zZky/8yZMv/NmTL/zJky/8yZMvrMmTLPzZkyac2ZMhMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADNmTIHzZkySc2ZMsXMmDL6zJky/82ZMv/MmTL/zZky/82ZMv/NmTL/y5cy/8SSMP+9jS7/t4kt/7KFLP+vgiv/roIr/62BKv+tgSr/roIr/6+DK/+zhSz/togt/76OLv/FkzD/y5cy/8yZMv/NmTL/zJky/8yZMv/MmTL/zZky/8yZMvrMmTLFzZkySs2ZMgcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADNmTIZzZkykMyZMvLMmTL/zZky/8yZMv/NmTL/zJky/8uXMv/CkS//t4kt/6+CK/+rfyr/qn8q/6t/Kv+qfyr/qn8q/6p/Kv+qfyr/qn8q/6p/Kv+qfyr/qn8q/6p/Kv+qfyr/q38q/6+CK/+3iC3/wpEv/8uYMv/NmTL/zZky/8yYMv/MmTL/zZky/8yZMvHNmTKRzZkyGQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADNmTI2zZkyxsyYMv3MmTL/zZky/8yZMv/NmTL/yZYx/72NLv+wgyv/q38q/6p/Kv+qfyr/qn8q/6p/Kv+qfyr/qn8q/6p/Kv+qfyr/qn8q/6p/Kv+qfyr/qn8q/6p/Kv+qfyr/qn8q/6p/Kv+qfyr/qn8q/6t/Kv+wgyv/vo4u/8qXMf/NmTL/zZky/8yZMv/MmTL/zZky/cyZMsTNmTI2zZkyAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM2ZMgPNmTJTzJky4MyYMv/NmTL/zJky/8yZMv/MmDL/v48v/6yAKv+meyn/p3wp/6p/Kv+qfyr/qn8q/6p/Kv+qfyr/qn8q/6t/Kv+qfyr/qn4q/6p+Kv+pfin/qn4q/6p/Kv+qfyr/qn8q/6t/Kv+qfyr/qn8q/6p/Kv+qfyr/qn8q/6p/Kv+vgiv/v48v/8uYMv/NmTL/zJky/8yZMv/MmTL/zJky4M2ZMlHNmTIEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM2ZMgTNmTJezJky7MyZMv/MmTL/zJky/82ZMv/FkzD/s4Ys/6p/Kv+ieCj/j2sj/5RuJP+keij/qn8q/6p/Kv+pfin/pHoo/511Jv+YcSX/lW8k/5NtI/+SbSP/km0j/5NtI/+VbyT/mHEl/551J/+keij/qX4p/6p/Kv+qfyr/qn8q/6p/Kv+qfyr/qn8q/6p/Kv+0hiz/xZMw/82ZMv/MmTL/zZky/82ZMv/MmTLrzZkyYM2ZMgUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM2ZMgPNmTJhzJky78yZMv/NmTL/zJky/8yZMv++ji//rYEq/6p/Kv+qfir/mnMm/3FVG/9pTxr/jWki/551J/+YciX/kWwj/41qIv+NaiL/jmoi/41qIv+NaiL/jWoi/41qIv+NaiL/jWoi/41qIv+NaiL/jWoi/5BsI/+ZciX/o3ko/6p+Kv+qfyr/qn8q/6p/Kv+qfyr/qn8q/62AKv++ji//zJky/8yZMv/NmTL/zJky/8yYMu7NmTJhzZkyAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM2ZMgHNmTJRzJky7MyZMv/NmTL/zZky/8yYMv+5ii3/q38q/6p/Kv+qfyr/qn8q/5dxJf9jShj/QjEQ/1Q/FP92WB3/iGYh/41qIv+NaiL/jmoi/41qIv+NaiL/jWoi/41qIv+OaiL/jWoi/41qIv+OaiL/jWoi/41qIv+NaiL/jWoi/45qIv+TbiT/oHcn/6l+Kf+qfyr/qn8q/6p/Kv+qfyr/q38q/7mKLf/MmDL/zZky/8yZMv/NmTL/zJgy7M2ZMlHNmTIBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADNmTI2zJky4MyZMv/NmTL/zJky/8qXMf+2iC3/qn8q/6p/Kv+qfyr/qn8q/7CIOP+TbST/VUAU/y0hCv8zJgz/Uj0U/3VYHP+IZiH/jmoi/45qIv+OaiL/jWki/4xoIv+MaCL/i2ch/4xpIv+NaSL/jmoi/45qIv+OaiL/jmoi/41qIv+NaSL/jmoi/45qIv+UbyT/pHoo/6t/Kv+qfyr/qn8q/6p/Kv+qfyr/togt/8qXMf/NmTL/zJky/82ZMv/NmTLfzZkyNwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADNmTIZzZkyxsyYMv/NmTL/zJky/8uYMv+2iC3/qn8q/6p/Kv+qfyr/qn8q/6p+Kf/Zyq3/moNU/047E/8qHwn/JhwI/zIlC/9RPRP/c1Yc/4JhH/+AXx//fF0e/3haHf93WR3/dlkd/3dZHf93WR3/eFod/3tcHv+BYB//h2Uh/4xpIv+OaiL/jmoi/41qIv+NaiL/jmoi/49rI/+cdCb/qX4p/6p/Kv+qfyr/qn8q/6p/Kv+2iC3/y5gy/82ZMv/MmTL/zJgy/8yZMsTNmTIZAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADNmTIIzZkykM2ZMv3NmTL/zJky/8yZMv+6iy7/qn8q/6p/Kv+qfyr/qn8q/6l9Kf+XcCX/2Myz//n49v94aEj/KyAK/yMaB/8kGwj/LiIK/0Y0Ef9hSRf/clUb/3RXHP91WBz/dVgc/3VYHP91WBz/dFcc/3ZYHf91WBz/dVgc/3VYHP95Wx3/gGAf/4pnIf+OaiL/jmoi/41qIv+NaiL/jWoi/5dxJf+ofSn/qn8q/6p/Kv+qfyr/q38q/7mKLf/MmTL/zJky/82ZMv/MmDL9zZkykc2ZMgcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAzZkyScyZMvHMmTL/zJky/82ZMv++ji//q38q/6p/Kv+qfyr/q38q/6d8Kf+VbyT/jmoi/9jMs///////9fTz/1tUQ/8fGAb/HhcG/x4XBv8pHwn/QzIQ/2FJF/9yVRv/dFcc/3VYHP91WBz/dVgc/3VYHP91WBz/dVgc/3VYHP91WBz/dVgc/3VYHP93WR3/gGAf/4xoIv+OaiL/jWoi/45qIv+NaiL/lW8k/6d9Kf+qfyr/qn4q/6t/Kv+rfyr/vo4v/82ZMv/MmTL/zZky/8yZMvHNmTJKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAzZkyEs2ZMsXNmTL/zJky/82ZMv/FkzD/rYEq/6p+Kv+qfyr/qn8q/6l9Kf+UbiT/jWoi/45qIv/YzLP////////////09PP/U05B/x4XBv8eFwb/HhcG/ykfCf9DMhD/YUkX/3JVG/90Vxz/dVgc/3VYHP91WBz/dVgc/3VYHP91WBz/dVgc/3VYHP91WBz/dFcc/3ZYHf95Wh3/h2Uh/45qIv+NaiL/jWoi/45qIv+UbiT/qH0p/6p/Kv+qfyr/q38q/62BKv/FkzD/zZky/8yZMv/MmTL/zZkyxM2ZMhMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAzZkyAc2ZMmfMmTL6zJky/82ZMv/MmDL/s4Us/6p/Kv+qfyr/qn8q/6p+Kv+XcCX/jWoi/45qIv+NaiL/2Myz//////////////////T08/9TTkH/HhcG/x4XBv8eFwb/KR8J/0MyEP9hSRf/clUb/3RXHP91WBz/dlgd/3RXHP92WB3/dVgc/3VYHP91WBz/dVgc/3VYHP91WBz/dVgc/3dZHf+DYiD/jWoi/41qIv+NaiL/jmoi/5dxJf+qfin/qn8q/6p/Kv+qfyr/s4Ys/8uYMv/NmTL/zJky/8yZMvrNmTJpzZkyAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM2ZMhbNmTLRzJky/8yZMv/NmTL/vo4v/6t/Kv+qfyr/qn8q/6p/Kv+cdCb/jWoi/45qIv+NaiL/jmoi/9bKs///////////////////////9PTz/1NOQf8eFwb/HhcG/x4XBv8pHwn/QzIQ/2FJF/9yVRv/dFcc/3VYHP92WB3/dVgc/3VYHP91WBz/dVgc/3VYHP91WBz/dVgc/3VYHP91WBz/dVgc/4JhH/+NaiL/jWoi/41qIv+OaiL/nXUm/6p/Kv+qfyr/qn8q/6t/Kv++ji//zZky/8yZMv/NmTL/zZky0M2ZMhYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADNmTJhzJgy+s2ZMv/NmTL/yZYx/6+CK/+qfyr/qn8q/6p/Kv+keij/j2oi/45qIv+NaiL/jmoi/4NiIP/RxrH////////////////////////////09PP/U05B/x4XBv8eFwb/HhcG/ykfCf9DMhD/YUkX/3JVG/90Vxz/dVgc/3VYHP91WBz/dVgc/3VYHP91WBz/dVgc/3VYHP91WBz/dVgc/3VYHP92WB3/g2Ig/45qIv+NaiL/jWoi/49qIv+keij/qn8q/6p/Kv+qfyr/r4Ir/8qXMf/MmTL/zJky/8yZMvrNmTJgAAAAAAAAAAAAAAAAAAAAAAAAAADNmTILzZkyv82ZMv/NmTL/zJky/72OLv+qfyr/qn8q/6p/Kv+pfin/lW8k/45qIv+NaiL/jWoi/4hlIf92WR3/0Max//////////////////////////////////T08/9TTkH/HhcG/x4XBv8eFwb/KR8J/0MyEP9hSRf/clUb/3RXHP91WBz/dVgc/3VYHP91WBz/dVgc/3VYHP91WBz/dVgc/3VYHP91WBz/dVgc/3ZZHf+HZSH/jmoi/41qIv+OaiL/lW8k/6p+Kv+qfyr/q38q/6p/Kv+9jS7/zZky/82ZMv/NmTL/zZkyv82ZMgkAAAAAAAAAAAAAAAAAAAAAzZkyN82ZMvHMmTL/zJky/8uYMv+wgyv/qn8q/6p/Kv+qfyr/oXgn/45qIv+NaiL/jWoi/4xoIv95Wh3/dVgc/9HGsf//////////////////////////////////////9PTz/1NOQf8eFwb/HhcG/x4XBv8pHwn/QzIQ/2FJF/9yVRv/dFcc/3VYHP91WBz/dVgc/3VYHP91WBz/dVgc/3ZYHf91WBz/dVgc/3VYHP91WBz/eVsd/4xoIv+NaiL/jWoi/45qIv+gdyf/qn8q/6p/Kv+qfyr/sIMr/8uXMv/MmTL/zJky/8yZMvHNmTI3AAAAAAAAAAAAAAAAzZkyAc2ZMoLNmTL9zZky/8yZMv/BkC//q38q/6p/Kv+qfyr/qn4q/5NuJP+NaiL/jWoi/45qIv+BYB//dVgc/3VYHP/RxrH////////////////////////////////////////////09PP/U05B/x4XBv8eFwb/HhcG/ykfCf9DMhD/YUkX/3JVG/90Vxz/dlgd/3VYHP91WBz/dVgc/3VYHP91WBz/dVgc/3VYHP91WBz/dVgc/3VYHP+AYB//jmoi/41qIv+NaiL/k24k/6p+Kv+qfyr/qn8q/6t/Kv/BkC//zZky/8yZMv/NmTL+zZkygc2ZMgEAAAAAAAAAAM2ZMgrNmTLCzJky/8yZMv/NmTL/t4kt/6p/Kv+qfyr/qn8q/6N5KP+NaiL/jmoi/41qIv+LZyH/d1kd/3VYHP91WBz/0cax//////////////////////////////////////////////////T08/9TTkH/HhcG/x4XBv8eFwb/KR8J/0MyEP9hSRf/clUb/3RXHP91WBz/dVgc/3RXHP92WB3/dVgc/3VYHP91WBz/dVgc/3VYHP91WBz/dlkd/4tnIf+OaiL/jmoi/45qIv+ieSj/qn8q/6p/Kv+qfyr/t4kt/8yZMv/NmTL/zJky/8yZMsPNmTIKAAAAAAAAAADNmTIozJky7MyZMv/NmTL/ypcx/6+CK/+qfyr/qn8q/6p/Kv+ZciX/jmoi/41qIv+OaiL/gGAf/3VYHP91WBz/dVgc/9DGsf//////////////////////////////////////////////////////9PTz/1NOQf8eFwb/HhcG/x4XBv8pHwn/QzIQ/2FJF/9yVRv/dFcc/3ZYHf91WBz/dVgc/3VYHP91WBz/dVgc/3VYHP91WBz/dVgc/3VYHP+AYB//jWoi/45qIv+NaiL/mXIl/6p/Kv+qfyr/qn8q/66CK//LlzL/zJky/82ZMv/MmTLszZkyKAAAAAAAAAAAzZkyU82ZMvvNmTL/zZky/8STMP+rfyr/qn8q/6p/Kv+ofSn/kWwj/41qIv+OaiL/jGki/3haHf91WBz/dVgc/3VYHP/RxrH////////////////////////////////////////////////////////////09PP/U05B/x4XBv8eFwb/HhcG/ykfCf9DMhD/YUkX/3JVG/90Vxz/dVgc/3VYHP91WBz/dVgc/3VYHP91WBz/dVgc/3VYHP91WBz/eVod/4xpIv+NaiL/jWoi/5BsI/+pfin/qn8q/6p/Kv+rfyr/xJMw/8yZMv/MmTL/zJky/M2ZMlIAAAAAzZkyAc2ZMn/NmTL+zJky/8yZMv+9jS7/qn8q/6p/Kv+qfyr/pHoo/45qIv+NaiL/jWoi/4dkIP91WBz/dVgc/3VYHP91WBz/0Max//////////////////////////////////////////////////////////////////T08/9TTkH/HhcG/x4XBv8eFwb/KR8J/0MyEP9hSRf/clUb/3RXHP92WB3/dVgc/3VYHP92WB3/dVgc/3VYHP91WBz/dlgd/3VYHP+HZSH/jWoi/45qIv+OaiL/pHoo/6p/Kv+qfyr/qn8q/76OLv/NmTL/zJky/82ZMv7NmTJ/zZkyAc2ZMgLMmTKozZky/8yZMv/NmTL/t4kt/6p/Kv+rfyr/qn8q/511Jv+OaiL/jmoi/41qIv+AYB//dVgc/3VYHP91WBz/dVgc/9HGsf//////////////////////////////////////////////////////////////////////9PTz/1NOQf8eFwb/HhcG/x4XBv8pHwn/QzIQ/2FJF/9yVRv/dFcc/3VYHP91WBz/dVgc/3VYHP92WB3/dVgc/3RXHP91WBz/gGAf/45qIv+OaiL/jWoi/511Jv+qfyr/qn8q/6p/Kv+2iC3/zZky/82ZMv/NmTL/zJkyp82ZMgPNmTIJzZkyxcyZMv/NmTL/zJky/7KFLP+qfyr/qn8q/6p/Kv+ZciX/jWoi/41qIv+OaiL/e1we/3VYHP91WBz/dVgc/3VYHP/RxrH////////////////////////////////////////////////////////////////////////////09PP/U05B/x4XBv8eFwb/HhcG/ykfCf9DMhD/YUkX/3JVG/90Vxz/dVgc/3ZYHf91WBz/dVgc/3VYHP91WBz/dVgc/3tcHv+OaiL/jWoi/41qIv+YcSX/qn8q/6p/Kv+qfyr/s4Us/8yYMv/NmTL/zJky/8yZMsXNmTIHzZkyD8yZMtXNmTL/zJky/8uXMv+wgyv/qn8q/6p/Kv+qfyr/lW8k/41qIv+OaiL/jWki/3haHf91WBz/dVgc/3VYHP91WBz/0Max//////////////////////////////////////////////////////////////////////////////////T08/9TTkH/HhcG/x4XBv8eFwb/KR8J/0MyEP9hSRf/clUb/3RXHP91WBz/dVgc/3ZYHf91WBz/dVgc/3VYHP94Wh3/jWki/41qIv+NaiL/lW8k/6p+Kv+qfyr/qn8q/7CDK//LmDL/zJky/82ZMv/NmTLVzZkyEc2ZMhLNmTLizJky/8yZMv/KlzH/roIr/6p/Kv+qfir/qn4q/5NtI/+OaiL/jWoi/4xoIv93WR3/dVgc/3VYHP91WBz/dVgc/9HGsf//////////////////////////////////////////////////////////////////////////////////////9PTz/1NOQf8eFwb/HhcG/x4XBv8pHwn/QzIQ/2FJF/9yVRv/dVgc/3VYHP91WBz/dVgc/3VYHP91WBz/d1kd/4toIf+NaiL/jmoi/5NuJP+qfir/qn8q/6p/Kv+ugiv/ypcx/8yZMv/MmTL/zJky4c2ZMhPNmTIVzZky6MyZMv/NmTL/ypcx/62BKv+qfyr/qn8q/6p+Kv+SbSP/jWoi/45qIv+LZyH/dlkd/3VYHP91WBz/dVgc/3VYHP/RxrH////////////////////////////////////////////////////////////////////////////////////////////09PP/U05B/x4XBv8eFwb/HhcG/ykfCf9DMhD/YUkX/3JVG/90Vxz/dVgc/3VYHP91WBz/dVgc/3ZZHf+LZyH/jmoi/41qIv+SbSP/qX4p/6p/Kv+qfyr/rYEq/8mWMf/NmTL/zJky/82ZMujNmTIWzZkyFs2ZMufMmTL/zJky/8mWMf+tgSr/qn8q/6p/Kv+pfin/km0j/41qIv+NaiL/i2ch/3ZZHf91WBz/dVgc/3VYHP91WBz/0Max/////////////////////////////////+bk3v/+/v7///////////////////////////////////////////////////////T08/9TTkH/HhcG/x4XBv8eFwb/KR8J/0MyEP9hSBf/cVUb/3RXHP91WBz/dVgc/3VYHP92WB3/i2gh/41qIv+OaiL/km0j/6l+Kf+qfyr/qn8q/62BKv/KlzH/zJky/82ZMv/NmTLmzZkyFs2ZMhLMmTLhzZky/82ZMv/KlzH/roIr/6p/Kv+qfir/qn4q/5NuJP+OaiL/jWoi/4toIf93WR3/dVgc/3VYHP91WBz/dVgc/9HGsf////////////////////////////////+Pi4P/l5CB////////////////////////////////////////////////////////////9PTz/1NOQf8eFwb/HhcG/x4XBv8pHwn/RDMQ/2FIF/9yVRv/dFcc/3VYHP91WBz/d1kd/4toIf+OaiL/jWoi/5NtI/+qfir/qn8q/6p/Kv+ugiv/y5cy/82ZMv/MmTL/zJky4s2ZMhLNmTIQzJky1s2ZMv/MmTL/y5gy/6+CK/+qfyr/qn8q/6p+Kv+VbyT/jWoi/41qIv+NaSL/d1kd/3VYHP91WBz/dVgc/3VYHP/QxrH/////////////////////////////////j4uD/yUbCP+kmob////////////////////////////////////////////////////////////09PP/U05B/x4XBv8eFwb/HhcG/ykfCf9DMhD/YUkX/3JVG/90Vxz/dlgd/3haHf+MaSL/jWoi/41qIv+WcCT/qn4q/6p/Kv+qfyr/r4Mr/8uXMv/MmTL/zZky/82ZMtXNmTIQzZkyB8yZMsTNmTL/zJky/8yYMv+zhSz/qn8q/6p/Kv+qfyr/mXIl/45qIv+OaiL/jWoi/3tcHv91WBz/dVgc/3VYHP91WBz/0cax/////////////////////////////////4+Lg/8mHAj/STcR/7Wniv////////////////////////////////////////////////////////////T08/9TTkH/HhcG/x4XBv8eFwb/KR8J/0MyEP9iSRj/cVUb/3RXHP97XB7/jmoi/41qIv+OaiL/mXIl/6p/Kv+qfyr/qn8q/7KFLP/MmDL/zJky/82ZMv/MmTLFzZkyB82ZMgPMmTKozZky/82ZMv/NmTL/togt/6p/Kv+qfyr/qn8q/551J/+NaiL/jmoi/41qIv+BYB//dVgc/3VYHP91WBz/dVgc/9DGsf////////////////////////////////+Pi4P/Jh0I/0k3Ef9tUhr/uaqN////////////////////////////////////////////////////////////9PTz/1NOQf8eFwb/HhcG/x4XBv8pHwn/QzIQ/2JJGP9xVRv/gF8f/41qIv+OaiL/jmoi/511Jv+qfyr/qn8q/6p/Kv+2iC3/zZky/82ZMv/NmTL/zJkyp82ZMgPNmTIBzZkyf82ZMv7MmTL/zJky/72OLv+qfyr/qn8q/6p/Kv+keij/jmoi/41qIv+OaiL/hmQg/3VYHP91WBz/dFcc/3NWHP/QxbH/////////////////////////////////j4uD/yYcCP9JNxH/bVIa/3ZYHf+5qYv////////////////////////////////////////////////////////////09PP/U05B/x4XBv8eFwb/HxgG/ygeCf9DMhD/YkkY/4JhH/+NaiL/jWoi/45qIv+keij/qn8q/6p/Kv+qfyr/vo4u/8yZMv/MmTL/zZky/s2ZMoHNmTIBAAAAAM2ZMlTNmTL7zJky/8yZMv/EkzD/q38q/6p/Kv+qfyr/qX4p/5FsI/+OaiL/jWoi/4xoIv94Wh3/c1Yc/2lPGf9eRxf/x7+v/////////////////////////////////4+Lg/8mHAj/STcR/21RGv90Vxz/dFcc/7qrjf////////////////////////////////////////////////////////////T08/9TTkH/HhcG/x4XBv8eFwb/Kh8J/0Y0EP90Vxz/iGYh/41qIv+RbCP/qX4p/6p/Kv+qfyr/q38q/8STMP/MmTL/zJky/82ZMvzNmTJSAAAAAAAAAADNmTIlzZky7c2ZMv/NmTL/ypcx/6+CK/+qfyr/qn8q/6p/Kv+YcSX/jmoi/41qIv+OaiL/gF8f/3BUG/9YQRX/OywO/7m0qf////////////////////////////////+Pi4P/JhwI/0k3Ef9tUhr/dVgc/3VYHP91WBz/uauN////////////////////////////////////////////////////////////9PTz/1NOQf8eFwb/HhcG/x4XBv8vIwr/UDwT/3VXHP+JZiH/mHEl/6p/Kv+qfyr/qn8q/66CK//KlzH/zZky/82ZMv/MmTLszZkyJgAAAAAAAAAAzZkyCsyZMsTNmTL/zJgy/8yZMv+3iS3/qn8q/6p/Kv+qfyr/o3ko/45qIv+NaiL/jmoi/4pnIf9wVBv/TjoT/ygeCf+3sqf/////////////////////////////////j4uD/yYcCP9JNxH/bVEa/3VYHP91WBz/dVgc/3ZYHf+4qYv////////////////////////////////////////////////////////////09PP/U05B/x4XBv8eFwb/JRsI/zMmDP9QPBP/dlgc/511Jv+qfyr/qn8q/6p/Kv+2iC3/zJky/8yZMv/NmTL/zZkyws2ZMgsAAAAAAAAAAM2ZMgHNmTKCzZky/8yZMv/MmTL/wpEv/6t/Kv+qfyr/qn8q/6p+Kv+UbiT/jmoi/41qIv+NaiL/eVsd/1A8E/8oHgn/t7Kn/////////////////////////////////4+Lg/8mHQj/STYR/21SGv91WBz/dVgc/3VYHP91WBz/dVgc/7qrjf////////////////////////////////////////////////////////////T08/9TTkH/IRkH/yUbCP8mHQj/NCcM/1dBFf+NaSL/pXsp/6p/Kv+qfyr/wpEv/82ZMv/MmTL/zZky/s2ZMoHNmTIBAAAAAAAAAAAAAAAAzZkyN82ZMvLNmTL/zZky/8qXMf+xhCv/qn8q/6p/Kv+qfyr/oXgn/45qIv+NaiL/qY1V/83AqP+3sKD/rKec/+bj3f////////////////////////////////+XkYX/OCoN/1I+FP9vUxv/dFcc/3VYHP91WBz/dVgc/3VYHP91WBz/uaqL////////////////////////////////////////////////////////////9PTz/2ZcRv87LA7/OisN/zwtDv9UPxT/elsd/551J/+pfin/sYQr/8uXMv/MmDL/zZky/82ZMvHNmTI3AAAAAAAAAAAAAAAAAAAAAM2ZMgnMmTK/zZky/8yZMv/MmTL/vY0u/6t/Kv+qfyr/qn8q/6p+Kf+VbyT/jmoi/7qle///////////////////////////////////////////////////////q6CK/1xEFv9mTBn/c1Yc/3ZYHf90Vxz/dVgc/3VYHP92WB3/dVgc/3VYHP+5q43////////////////////////////////////////////////////////////19PP/inZO/2pQGv9vUxv/gmEg/49rI/+heCf/qn4q/72NLv/MmTL/zJky/82ZMv/NmTK/zZkyCQAAAAAAAAAAAAAAAAAAAAAAAAAAzZkyYM2ZMvvMmTL/zZky/8mWMf+vgiv/qn8q/6p/Kv+qfyr/pHoo/49rI/+6pXv//////////////////////////////////////////////////////7iqjf9zVhz/dFcc/3VYHP91WBz/dVgc/3RXHP91WBz/dVgc/3VYHP91WBz/dVgc/7mpi/////////////////////////////////////////////////////////////r38f+mjFf/oHcn/6Z7Kf+mfCn/qX4p/6+CK//JljH/zZky/82ZMv/MmTL6zZkyYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM2ZMhbNmTLQzZky/8yZMv/NmTL/vo4v/6t/Kv+qfyr/qn8q/6p/Kv+ddSb/u6Z8//////////////////////////////////////////////////////+6q47/dVgc/3VYHP91WBz/dVgc/3VYHP91WBz/dlgd/3VYHP91WBz/dVgc/3VYHP90Vxz/uquN/////////////////////////////////////////////////////////////Pny/7+eXv+qfyr/qn8q/6p/Kv+/jy//zJgy/8yZMv/NmTL/zJky0M2ZMhYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADNmTIBzZkyacyZMvrNmTL/zJky/8uYMv+zhSz/qn8q/6p/Kv+qfyr/qX4p/7SYYP/Xy7P/18uz/9fLs//Xy7P/1sqz/9DG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"
OFFICIAL_SINGBOX_ICON = "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjE0OCA5MCA3MjggODIwIj4KICA8ZGVmcz4KICAgIDxsaW5lYXJHcmFkaWVudCBpZD0iYmcyNSIgeDE9IjAiIHkxPSIwIiB4Mj0iMCIgeTI9IjEiPgogICAgICA8c3RvcCBvZmZzZXQ9IjAiIHN0b3AtY29sb3I9IiMyNDJGMzciLz4KICAgICAgPHN0b3Agb2Zmc2V0PSIxIiBzdG9wLWNvbG9yPSIjMEQxMzE3Ii8+CiAgICA8L2xpbmVhckdyYWRpZW50PgogICAgPHJhZGlhbEdyYWRpZW50IGlkPSJzcG90MjUiIGN4PSIwLjUiIGN5PSIwLjUiIHI9IjAuNSI+CiAgICAgIDxzdG9wIG9mZnNldD0iMCIgc3RvcC1jb2xvcj0iIzQ2NTY1RiIgc3RvcC1vcGFjaXR5PSIwLjQ1Ii8+CiAgICAgIDxzdG9wIG9mZnNldD0iMSIgc3RvcC1jb2xvcj0iIzQ2NTY1RiIgc3RvcC1vcGFjaXR5PSIwIi8+CiAgICA8L3JhZGlhbEdyYWRpZW50PgogICAgPGZpbHRlciBpZD0ic29mdDI1IiB4PSItNDAlIiB5PSItNDAlIiB3aWR0aD0iMTgwJSIgaGVpZ2h0PSIxODAlIj4KICAgICAgPGZlR2F1c3NpYW5CbHVyIHN0ZERldmlhdGlvbj0iMTgiLz4KICAgIDwvZmlsdGVyPgogICAgPGxpbmVhckdyYWRpZW50IGlkPSJ0b3AyNSIgZ3JhZGllbnRVbml0cz0idXNlclNwYWNlT25Vc2UiIHgxPSIzMzAiIHkxPSIzMjAiIHgyPSI3MDAiIHkyPSI0OTAiPgogICAgICA8c3RvcCBvZmZzZXQ9IjAiIHN0b3AtY29sb3I9IiM0NDU4NjMiLz4KICAgICAgPHN0b3Agb2Zmc2V0PSIxIiBzdG9wLWNvbG9yPSIjMzk0QzU3Ii8+CiAgICA8L2xpbmVhckdyYWRpZW50PgogICAgPGxpbmVhckdyYWRpZW50IGlkPSJsZWZ0MjUiIGdyYWRpZW50VW5pdHM9InVzZXJTcGFjZU9uVXNlIiB4MT0iMjY5LjUiIHkxPSI0ODAiIHgyPSI1MTIiIHkyPSI3MjAiPgogICAgICA8c3RvcCBvZmZzZXQ9IjAiIHN0b3AtY29sb3I9IiMyNjMyM0EiLz4KICAgICAgPHN0b3Agb2Zmc2V0PSIxIiBzdG9wLWNvbG9yPSIjMUYyQTMxIi8+CiAgICA8L2xpbmVhckdyYWRpZW50PgogICAgPGxpbmVhckdyYWRpZW50IGlkPSJyaWdodDI1IiBncmFkaWVudFVuaXRzPSJ1c2VyU3BhY2VPblVzZSIgeDE9IjUxMiIgeTE9IjY1MCIgeDI9Ijc1NC41IiB5Mj0iNTAwIj4KICAgICAgPHN0b3Agb2Zmc2V0PSIwIiBzdG9wLWNvbG9yPSIjMzA0MDRBIi8+CiAgICAgIDxzdG9wIG9mZnNldD0iMSIgc3RvcC1jb2xvcj0iIzM3NDg1NCIvPgogICAgPC9saW5lYXJHcmFkaWVudD4KICAgIDxmaWx0ZXIgaWQ9ImdyYWluMjUiIHg9IjAiIHk9IjAiIHdpZHRoPSIyODAiIGhlaWdodD0iMjgwIiBmaWx0ZXJVbml0cz0idXNlclNwYWNlT25Vc2UiPgogICAgICA8ZmVUdXJidWxlbmNlIHR5cGU9ImZyYWN0YWxOb2lzZSIgYmFzZUZyZXF1ZW5jeT0iMC4yMiIgbnVtT2N0YXZlcz0iNCIgc2VlZD0iMTciIHJlc3VsdD0ibiIvPgogICAgICA8ZmVDb2xvck1hdHJpeCBpbj0ibiIgdHlwZT0ibWF0cml4IiB2YWx1ZXM9IjAgMCAwIDAgMSAgMCAwIDAgMCAxICAwIDAgMCAwIDEgIDAuNDUgMCAwIDAgLTAuMSIvPgogICAgPC9maWx0ZXI+CiAgICA8ZmlsdGVyIGlkPSJncmFpbkQyNSIgeD0iMCIgeT0iMCIgd2lkdGg9IjI4MCIgaGVpZ2h0PSIyODAiIGZpbHRlclVuaXRzPSJ1c2VyU3BhY2VPblVzZSI+CiAgICAgIDxmZVR1cmJ1bGVuY2UgdHlwZT0iZnJhY3RhbE5vaXNlIiBiYXNlRnJlcXVlbmN5PSIwLjI4IiBudW1PY3RhdmVzPSI0IiBzZWVkPSI0MSIgcmVzdWx0PSJuIi8+CiAgICAgIDxmZUNvbG9yTWF0cml4IGluPSJuIiB0eXBlPSJtYXRyaXgiIHZhbHVlcz0iMCAwIDAgMCAwLjAyICAwIDAgMCAwIDAuMDUgIDAgMCAwIDAgMC4wNyAgMC40NSAwIDAgMCAtMC4xIi8+CiAgICA8L2ZpbHRlcj4KICAgIDxjbGlwUGF0aCBpZD0iY2xpcFRvcEQiPjxwYXRoIGQ9Ik01MTIgMjYyIDc1NC41IDQwMiA1MTIgNTQyIDI2OS41IDQwMloiLz48L2NsaXBQYXRoPgogICAgPGNsaXBQYXRoIGlkPSJjbGlwTGVmdEQiPjxwYXRoIGQ9Ik0yNjkuNSA0MDIgNTEyIDU0MiA1MTIgODEyIDI2OS41IDY3MloiLz48L2NsaXBQYXRoPgogICAgPGNsaXBQYXRoIGlkPSJjbGlwUmlnaHREIj48cGF0aCBkPSJNNTEyIDU0MiA3NTQuNSA0MDIgNzU0LjUgNjcyIDUxMiA4MTJaIi8+PC9jbGlwUGF0aD4KICA8L2RlZnM+CiAgPGcgdHJhbnNmb3JtPSJ0cmFuc2xhdGUoLTIyNS4yOCAtMjczLjI4KSBzY2FsZSgxLjQ0KSI+CjwhLS0gZGVlcCBjYXJkYm9hcmQgZmFjZXMgLS0+CiAgPHBhdGggZD0iTTUxMiAyNjIgNzU0LjUgNDAyIDUxMiA1NDIgMjY5LjUgNDAyWiIgZmlsbD0idXJsKCN0b3AyNSkiLz4KICA8cGF0aCBkPSJNMjY5LjUgNDAyIDUxMiA1NDIgNTEyIDgxMiAyNjkuNSA2NzJaIiBmaWxsPSJ1cmwoI2xlZnQyNSkiLz4KICA8cGF0aCBkPSJNNTEyIDU0MiA3NTQuNSA0MDIgNzU0LjUgNjcyIDUxMiA4MTJaIiBmaWxsPSJ1cmwoI3JpZ2h0MjUpIi8+CgogIDwhLS0gcGFwZXIgZ3JhaW4sIGZvcmVzaG9ydGVuZWQgcGVyIGZhY2UgLS0+CiAgPGcgY2xpcC1wYXRoPSJ1cmwoI2NsaXBUb3BEKSI+PGcgdHJhbnNmb3JtPSJtYXRyaXgoMC44NjYgMC41IDAuODY2IC0wLjUgMjY5LjUgNDAyKSI+CiAgICA8cmVjdCB3aWR0aD0iMjgwIiBoZWlnaHQ9IjI4MCIgZmlsdGVyPSJ1cmwoI2dyYWluMjUpIiBvcGFjaXR5PSIwLjMwIi8+CiAgICA8cmVjdCB3aWR0aD0iMjgwIiBoZWlnaHQ9IjI4MCIgZmlsdGVyPSJ1cmwoI2dyYWluRDI1KSIgb3BhY2l0eT0iMC4zOCIvPgogIDwvZz48L2c+CiAgPGcgY2xpcC1wYXRoPSJ1cmwoI2NsaXBMZWZ0RCkiPjxnIHRyYW5zZm9ybT0ibWF0cml4KDAuODY2IDAuNSAwIDAuOTY0MjggMjY5LjUgNDAyKSI+CiAgICA8cmVjdCB3aWR0aD0iMjgwIiBoZWlnaHQ9IjI4MCIgZmlsdGVyPSJ1cmwoI2dyYWluMjUpIiBvcGFjaXR5PSIwLjIwIi8+CiAgICA8cmVjdCB3aWR0aD0iMjgwIiBoZWlnaHQ9IjI4MCIgZmlsdGVyPSJ1cmwoI2dyYWluRDI1KSIgb3BhY2l0eT0iMC4zNCIvPgogIDwvZz48L2c+CiAgPGcgY2xpcC1wYXRoPSJ1cmwoI2NsaXBSaWdodEQpIj48ZyB0cmFuc2Zvcm09Im1hdHJpeCgwLjg2NiAtMC41IDAgMC45NjQyOCA1MTIgNTQyKSI+CiAgICA8cmVjdCB3aWR0aD0iMjgwIiBoZWlnaHQ9IjI4MCIgZmlsdGVyPSJ1cmwoI2dyYWluMjUpIiBvcGFjaXR5PSIwLjI1Ii8+CiAgICA8cmVjdCB3aWR0aD0iMjgwIiBoZWlnaHQ9IjI4MCIgZmlsdGVyPSJ1cmwoI2dyYWluRDI1KSIgb3BhY2l0eT0iMC4zNCIvPgogIDwvZz48L2c+CgogIDwhLS0gbGlkIGZsYXAgc2VhbTogdHdvIGxpZCBoYWx2ZXMsIHBhcGVyLWVkZ2UgY2F0Y2hsaWdodCAtLT4KICA8cGF0aCBkPSJNMzkwLjc1IDQ3MiA2MzMuMjUgMzMyIiBzdHJva2U9IiMxNDFFMjQiIHN0cm9rZS13aWR0aD0iNCIgZmlsbD0ibm9uZSIgb3BhY2l0eT0iMC45Ii8+CiAgPHBhdGggZD0iTTM5MC43NSA0NzIgNjMzLjI1IDMzMiIgc3Ryb2tlPSIjNkU4Nzk0IiBzdHJva2Utd2lkdGg9IjIiIGZpbGw9Im5vbmUiIG9wYWNpdHk9IjAuNyIgdHJhbnNmb3JtPSJ0cmFuc2xhdGUoMCAtMykiLz4KCiAgPCEtLSBzb2Z0IGFtYmllbnQgb2NjbHVzaW9uIGF0IGp1bmN0aW9ucyAtLT4KICA8cGF0aCBkPSJNMjY5LjUgNDAyIDUxMiA1NDIiIHN0cm9rZT0iIzBCMTQxQSIgc3Ryb2tlLXdpZHRoPSIxMCIgb3BhY2l0eT0iMC4yOCIgZmlsdGVyPSJ1cmwoI3NvZnQyNSkiIGZpbGw9Im5vbmUiLz4KICA8cGF0aCBkPSJNNTEyIDU0MiA3NTQuNSA0MDIiIHN0cm9rZT0iIzBCMTQxQSIgc3Ryb2tlLXdpZHRoPSIxMCIgb3BhY2l0eT0iMC4yMiIgZmlsdGVyPSJ1cmwoI3NvZnQyNSkiIGZpbGw9Im5vbmUiLz4KICA8cGF0aCBkPSJNNTEyIDU0MiA1MTIgODEyIiBzdHJva2U9IiMwNjBEMTEiIHN0cm9rZS13aWR0aD0iOSIgb3BhY2l0eT0iMC4zMCIgZmlsdGVyPSJ1cmwoI3NvZnQyNSkiIGZpbGw9Im5vbmUiLz4KCiAgPCEtLSBwYXBlci1lZGdlIGhpZ2hsaWdodHMgb24gdGhlIHRvcCBlZGdlcyAtLT4KICA8cGF0aCBkPSJNNTEyIDI2MiA3NTQuNSA0MDIiIHN0cm9rZT0iIzY2ODA4RCIgc3Ryb2tlLXdpZHRoPSIyLjUiIGZpbGw9Im5vbmUiLz4KICA8cGF0aCBkPSJNNTEyIDI2MiAyNjkuNSA0MDIiIHN0cm9rZT0iIzVBNzM3RiIgc3Ryb2tlLXdpZHRoPSIyLjUiIGZpbGw9Im5vbmUiLz4KICA8cGF0aCBkPSJNMjY5LjUgNDAyIDUxMiA1NDIgNzU0LjUgNDAyIiBzdHJva2U9IiM0RTY3NzMiIHN0cm9rZS13aWR0aD0iMiIgZmlsbD0ibm9uZSIgb3BhY2l0eT0iMC45Ii8+CiAgPHBhdGggZD0iTTUxMiA1NDIgNTEyIDgxMiIgc3Ryb2tlPSIjNDQ1OTYzIiBzdHJva2Utd2lkdGg9IjIiIGZpbGw9Im5vbmUiIG9wYWNpdHk9IjAuOSIvPgoKICA8IS0tIG9yaWdpbmFsIHR3by10b25lIHRhcGUsIGFsaWduZWQgdGFpbHMgLS0+CiAgPHBhdGggZD0iTTM1Ni44IDM1MS42IDM5MC43NSAzMzIgNjMzLjI1IDQ3MiA1OTkuMyA0OTEuNloiIGZpbGw9IiM5OUFBQjUiLz4KICA8cGF0aCBkPSJNMzkwLjc1IDMzMiA0MjQuNyAzMTIuNCA2NjcuMiA0NTIuNCA2MzMuMjUgNDcyWiIgZmlsbD0iI0UxRThFRCIvPgogIDxwYXRoIGQ9Ik01OTkuMyA0OTEuNiA2MzMuMjUgNDcyIDYzMy4yNSA1OTIgNTk5LjMgNjExLjZaIiBmaWxsPSIjODI5NkExIi8+CiAgPHBhdGggZD0iTTYzMy4yNSA0NzIgNjY3LjIgNDUyLjQgNjY3LjIgNTcyLjQgNjMzLjI1IDU5MloiIGZpbGw9IiNDQ0Q2REQiLz4KICA8IS0tIHRhcGUgc29mdCBzaGFkb3cgb250byB0aGUgcGFwZXIgLS0+CiAgPHBhdGggZD0iTTM2MCAzNTggNjAyLjUgNDk4IiBzdHJva2U9IiMwMDAwMDAiIG9wYWNpdHk9IjAuMjUiIHN0cm9rZS13aWR0aD0iNyIgZmlsdGVyPSJ1cmwoI3NvZnQyNSkiIGZpbGw9Im5vbmUiLz4KICA8L2c+Cjwvc3ZnPgo="


TRANSPORT_SETTING_KEYS = (
    "rawSettings",
    "tcpSettings",
    "xhttpSettings",
    "grpcSettings",
    "wsSettings",
    "httpupgradeSettings",
    "kcpSettings",
    "hysteriaSettings",
)


def parse_json_blob(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    parsed = json.loads(raw)
    if parsed is None:
        return {}
    if not isinstance(parsed, dict):
        raise ValueError("Expected JSON object in x-ui.db")
    return parsed


_inbounds_cache_lock = threading.Lock()
_inbounds_cache_mtime: tuple[float, float, int] | None = None
_cached_raw_rows: list[sqlite3.Row] = []
_cached_inbounds_parsed: list[tuple[sqlite3.Row, dict[str, Any], dict[str, Any], dict[str, Any], list[dict[str, Any]]]] = []
_cached_clients_index: dict[str, tuple[sqlite3.Row, dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]] = {}


def invalidate_inbounds_cache() -> None:
    global _inbounds_cache_mtime, _cached_raw_rows, _cached_inbounds_parsed, _cached_clients_index
    with _inbounds_cache_lock:
        _inbounds_cache_mtime = None
        _cached_raw_rows = []
        _cached_inbounds_parsed = []
        _cached_clients_index = {}


def _get_xui_db_mtime() -> tuple[float, float, int] | None:
    try:
        db_stat = os.stat(XUI_DB_PATH)
        db_mtime = db_stat.st_mtime
    except OSError:
        return None
    wal_path = f"{XUI_DB_PATH}-wal"
    wal_mtime = 0.0
    wal_size = 0
    try:
        wal_stat = os.stat(wal_path)
        wal_mtime = wal_stat.st_mtime
        wal_size = wal_stat.st_size
    except OSError:
        pass
    return (db_mtime, wal_mtime, wal_size)


def _ensure_inbounds_cache() -> None:
    global _inbounds_cache_mtime, _cached_raw_rows, _cached_inbounds_parsed, _cached_clients_index
    current_mtime = _get_xui_db_mtime()
    if current_mtime is None:
        invalidate_inbounds_cache()
        return

    with _inbounds_cache_lock:
        if _inbounds_cache_mtime is not None and _inbounds_cache_mtime == current_mtime:
            return

        db_uri = Path(XUI_DB_PATH).as_posix()
        try:
            conn = sqlite3.connect(f"file:{db_uri}?mode=ro", uri=True, timeout=30.0)
            conn.execute("PRAGMA busy_timeout = 30000;")
            conn.row_factory = sqlite3.Row
            try:
                rows = conn.execute(
                    """
                    SELECT id, remark, protocol, port, settings, stream_settings, sniffing
                    FROM inbounds
                    ORDER BY id
                    """
                ).fetchall()
            finally:
                conn.close()
        except sqlite3.Error:
            return

        new_parsed: list[tuple[sqlite3.Row, dict[str, Any], dict[str, Any], dict[str, Any], list[dict[str, Any]]]] = []
        new_index: dict[str, tuple[sqlite3.Row, dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]] = {}

        for row in rows:
            settings = parse_json_blob(row["settings"])
            stream_settings = parse_json_blob(row["stream_settings"])
            sniffing = parse_json_blob(row["sniffing"])
            clients = settings.get("clients") or []
            new_parsed.append((row, settings, stream_settings, sniffing, clients))
            for client in clients:
                c_sub = str(client.get("subId") or "").strip()
                c_email = str(client.get("email") or "").strip()
                c_id = str(client.get("id") or "").strip()
                match_tuple = (row, settings, stream_settings, sniffing, client)
                if c_sub and c_sub not in new_index:
                    new_index[c_sub] = match_tuple
                if c_email and c_email not in new_index:
                    new_index[c_email] = match_tuple
                if c_id and c_id not in new_index:
                    new_index[c_id] = match_tuple

        _cached_raw_rows = rows
        _cached_inbounds_parsed = new_parsed
        _cached_clients_index = new_index
        _inbounds_cache_mtime = current_mtime


def read_inbounds() -> list[sqlite3.Row]:
    _ensure_inbounds_cache()
    with _inbounds_cache_lock:
        if _cached_raw_rows:
            return list(_cached_raw_rows)
    db_uri = Path(XUI_DB_PATH).as_posix()
    conn = sqlite3.connect(f"file:{db_uri}?mode=ro", uri=True, timeout=30.0)
    conn.execute("PRAGMA busy_timeout = 30000;")
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(
            """
            SELECT id, remark, protocol, port, settings, stream_settings, sniffing
            FROM inbounds
            ORDER BY id
            """
        ).fetchall()
    finally:
        conn.close()


def find_store_db_path() -> str:
    env_path = os.environ.get("STORE_DB_PATH", "").strip()
    if env_path and Path(env_path).exists():
        return env_path
    p1 = Path("/root/vpn-shop/data-silentconnect/vpn_shop.db")
    if p1.exists():
        return str(p1)
    p2 = Path(__file__).resolve().parent.parent / "vpn-shop" / "data-silentconnect" / "vpn_shop.db"
    if p2.exists():
        return str(p2)
    p3 = Path("/root/vpn-shop/data/vpn_shop.db")
    if p3.exists():
        return str(p3)
    return "/root/vpn-shop/data-silentconnect/vpn_shop.db"


BIND_EMAIL_RATE_LIMIT_LOCK = threading.Lock()
BIND_EMAIL_RATE_LIMITS: collections.OrderedDict[str, list[float]] = collections.OrderedDict()
BIND_EMAIL_RATE_LIMIT_MAX_ENTRIES = 5000


def check_bind_email_rate_limit(client_ip: str, max_requests: int = 5, window_sec: int = 300) -> bool:
    if not client_ip or client_ip in ("127.0.0.1", "::1", "localhost", "::ffff:127.0.0.1"):
        return True
    now = time.time()
    with BIND_EMAIL_RATE_LIMIT_LOCK:
        history = [t for t in BIND_EMAIL_RATE_LIMITS.get(client_ip, []) if now - t < window_sec]
        if len(history) >= max_requests:
            return False
        history.append(now)
        BIND_EMAIL_RATE_LIMITS[client_ip] = history
        BIND_EMAIL_RATE_LIMITS.move_to_end(client_ip)
        while len(BIND_EMAIL_RATE_LIMITS) > BIND_EMAIL_RATE_LIMIT_MAX_ENTRIES:
            BIND_EMAIL_RATE_LIMITS.popitem(last=False)
        return True


def get_shop_settings() -> Any:
    env_paths = [
        "/root/vpn-shop/.env.silentconnect",
        "/root/vpn-shop/.env",
        str(Path(__file__).resolve().parent.parent / "vpn-shop" / ".env"),
        str(Path(__file__).resolve().parent.parent / ".env"),
    ]
    env_file = next((p for p in env_paths if os.path.exists(p)), None)
    try:
        from vpn_shop.config import load_settings
        root_dir = Path(__file__).resolve().parent.parent / "vpn-shop"
        if not root_dir.exists():
            root_dir = Path("/root/vpn-shop")
        return load_settings(root_dir=root_dir, env_file=Path(env_file) if env_file else None)
    except Exception as exc:
        LOGGER.warning("Could not load shop settings: %s", exc)
        return None


def mask_email(e: str) -> str:
    if not e or "@" not in e:
        return ""
    loc, dom = e.split("@", 1)
    if len(loc) <= 2:
        m_loc = loc[:1] + "***"
    else:
        m_loc = loc[:2] + "***"
    return f"{m_loc}@{dom}"


def find_store_linked_email(sub_id: str) -> str:
    try:
        target_sub = sub_id.strip().split("~")[0]
        row, _, _, _, client = find_subscription(target_sub)
        xui_email = str(client.get("email") or "").strip()
        if not xui_email:
            return ""
        db_path = find_store_db_path()
        if not Path(db_path).exists():
            return ""
        conn = sqlite3.connect(db_path, timeout=10.0)
        try:
            conn.row_factory = sqlite3.Row
            prof = conn.execute("SELECT id FROM profiles WHERE xui_email = ?", (xui_email,)).fetchone()
            if prof:
                ord_row = conn.execute(
                    "SELECT customer_email FROM orders WHERE provisioned_profile_id = ? AND customer_email != '' ORDER BY id DESC LIMIT 1",
                    (prof["id"],)
                ).fetchone()
                if ord_row and ord_row["customer_email"]:
                    return str(ord_row["customer_email"]).strip()
        finally:
            conn.close()
    except Exception:
        pass
    return ""


def bind_subscription_email(
    sub_id: str,
    customer_email: str,
    email_reminders: bool = True,
    turnstile_token: str = "",
    client_ip: str = "",
    headers: Any = None,
) -> dict[str, Any]:
    clean_email = str(customer_email or "").strip().lower()
    if not clean_email or "@" not in clean_email or "." not in clean_email.split("@")[-1]:
        raise ValueError("Пожалуйста, укажите корректный адрес электронной почты.")
    if len(clean_email) > 120 or len(clean_email.split("@")[0]) < 1:
        raise ValueError("Некорректный адрес электронной почты.")

    if not check_bind_email_rate_limit(client_ip):
        raise ValueError("Слишком много запросов на привязку почты. Пожалуйста, подождите несколько минут.")

    shop_settings = get_shop_settings()
    turnstile_secret = os.environ.get("CF_TURNSTILE_SECRET_KEY", "").strip()
    if not turnstile_secret and shop_settings:
        turnstile_secret = getattr(shop_settings, "cf_turnstile_secret_key", "").strip()

    if turnstile_secret:
        try:
            from vpn_shop.web import verify_cf_turnstile
            if not verify_cf_turnstile(turnstile_secret, turnstile_token, client_ip):
                raise ValueError("Пожалуйста, подтвердите проверку защиты от роботов (Cloudflare).")
        except ImportError:
            pass

    target_sub = sub_id.strip().split("~")[0]
    found_client = None
    try:
        row, _, _, _, client = find_subscription(target_sub)
        found_client = {"client": client, "inbound_id": row["id"]}
    except KeyError:
        pass

    if not found_client:
        raise ValueError("Подписка не найдена на сервере.")

    xui_email = str(found_client["client"].get("email") or "")
    db_path = find_store_db_path()
    conn_shop = sqlite3.connect(db_path, timeout=30.0)
    conn_shop.execute("PRAGMA busy_timeout = 30000;")
    conn_shop.row_factory = sqlite3.Row
    now = int(time.time())
    try:
        prof = conn_shop.execute("SELECT * FROM profiles WHERE xui_email = ?", (xui_email,)).fetchone()
        if not prof:
            pub_id = "prf_" + secrets.token_hex(6)
            expiry_ms = int(found_client["client"].get("expiryTime") or 0)
            expires_at = expiry_ms // 1000 if expiry_ms > 0 else (now + 30 * 86400)
            client_id = str(found_client["client"].get("id") or xui_email)
            mode = "family" if not xui_email.startswith("anon-") else "anonymous"
            conn_shop.execute(
                """
                INSERT INTO profiles(
                    public_id, xui_inbound_id, transport, profile_mode, family_label,
                    xui_email, xui_client_id, status, created_at, expires_at,
                    last_renewed_at, deleted_at, notes
                )
                VALUES(?, ?, 'tcp', ?, NULL, ?, ?, 'active', ?, ?, ?, NULL, 'auto_sync_from_xui')
                """,
                (pub_id, int(found_client["inbound_id"]), mode, xui_email, client_id, now, expires_at, now)
            )
            conn_shop.commit()
            prof = conn_shop.execute("SELECT * FROM profiles WHERE xui_email = ?", (xui_email,)).fetchone()

        if not prof or prof["status"] == "deleted":
            raise ValueError("Профиль подписки не найден или удалён.")

        prof_dict = dict(prof)
        profile_id = prof_dict["id"]
        profile_pub_id = prof_dict["public_id"]

        order_rows = conn_shop.execute(
            "SELECT * FROM orders WHERE provisioned_profile_id = ? ORDER BY id DESC",
            (profile_id,)
        ).fetchall()

        if order_rows:
            for ord_r in order_rows:
                meta = json.loads(ord_r["meta_json"]) if ord_r["meta_json"] else {}
                meta["customer_email"] = clean_email
                meta["email_reminders"] = email_reminders
                meta["bound_via"] = "lk_direct"
                conn_shop.execute(
                    "UPDATE orders SET customer_email = ?, meta_json = ?, updated_at = ? WHERE id = ?",
                    (clean_email, json.dumps(meta), now, ord_r["id"])
                )
            source_order = dict(order_rows[0])
            source_order["customer_email"] = clean_email
        else:
            ord_pub_id = "ord_" + secrets.token_hex(6)
            web_token = secrets.token_hex(12)
            meta = {
                "source": f"lk_bind_email_{sub_id}",
                "customer_email": clean_email,
                "email_reminders": email_reminders,
                "web": True,
                "web_token": web_token,
                "bound_via": "lk_direct",
                "device_limit": 3,
            }
            conn_shop.execute(
                """
                INSERT INTO orders(
                    public_id, kind, status, transport, duration_days, profile_mode, family_label,
                    base_price_rub, final_price_rub, promo_id, invite_id, customer_chat_id,
                    manager_chat_id, manager_message_id, privacy_ack, loss_policy_ack,
                    terms_version, provisioned_profile_id, customer_email, created_at, updated_at, closed_at, meta_json
                )
                VALUES(?, 'email_binding', 'delivered', ?, 0, ?, NULL, 0, 0, NULL, NULL, NULL, NULL, NULL, 1, 1, '2026-04-20', ?, ?, ?, ?, ?, ?)
                """,
                (
                    ord_pub_id,
                    str(prof_dict.get("transport") or "tcp"),
                    str(prof_dict.get("profile_mode") or "anonymous"),
                    profile_id,
                    clean_email,
                    now,
                    now,
                    now,
                    json.dumps(meta),
                )
            )
            source_order = {
                "public_id": ord_pub_id,
                "duration_days": 30,
                "meta_json": json.dumps(meta),
                "customer_email": clean_email,
            }
        conn_shop.commit()
    finally:
        conn_shop.close()

    try:
        if shop_settings and (getattr(shop_settings, "smtp_host", None) or getattr(shop_settings, "support_email", None)):
            from vpn_shop.mailer import send_subscription_email_async
            sub_url = public_subscription_url(headers, "json", sub_id)
            setup_url = subscription_setup_url(sub_url) if sub_url else f"{shop_settings.web_public_base_url}/my-secret-sub/import/{sub_id}"
            web_token = ""
            if source_order.get("meta_json"):
                try:
                    meta_parsed = json.loads(source_order["meta_json"]) if isinstance(source_order["meta_json"], str) else source_order["meta_json"]
                    web_token = meta_parsed.get("web_token", "")
                except Exception:
                    pass
            cabinet_url = f"{shop_settings.web_public_base_url}/order/{source_order['public_id']}/{web_token}" if (web_token and shop_settings.web_public_base_url) else f"{shop_settings.web_public_base_url}/cabinet"
            tg_claim_base = HAPP_SUPPORT_URL or "https://t.me/your_vpn_bot"
            bind_tg_url = f"{tg_claim_base}?start=claim_{source_order['public_id']}_{web_token}" if web_token else tg_claim_base

            send_subscription_email_async(
                shop_settings,
                customer_email=clean_email,
                order_public_id=str(source_order["public_id"]),
                plan_name="SilentConnect VPN (Привязка Email)",
                duration_days=int(source_order.get("duration_days") or 30),
                setup_url=setup_url,
                json_url=sub_url,
                cabinet_url=cabinet_url,
                bind_tg_url=bind_tg_url,
                expires_ts=prof_dict.get("expires_at"),
                subject=f"Подписка SilentConnect успешно привязана к почте! (#{source_order['public_id']})",
            )
    except Exception as mail_err:
        LOGGER.warning("Could not dispatch async confirmation email for bind_email: %s", mail_err)

    return {
        "ok": True,
        "customer_email": clean_email,
        "profile_public_id": profile_pub_id,
        "order_public_id": source_order["public_id"],
    }


def create_inline_renewal_order(
    sub_id: str,
    duration_days: int,
    device_limit: int = 3,
    promo_code: str = "",
    customer_email: str = "",
    email_reminders: bool = True,
) -> dict[str, Any]:
    db_path = find_store_db_path()

    target_sub = sub_id.strip().split("~")[0]
    found_client = None
    try:
        row, _, _, _, client = find_subscription(target_sub)
        found_client = {"client": client, "inbound_id": row["id"]}
    except KeyError:
        pass

    if not found_client:
        raise ValueError("Подписка не найдена на сервере.")

    email = str(found_client["client"].get("email") or "")

    # 2. Find profile & order in vpn_shop.db
    conn_shop = sqlite3.connect(db_path, timeout=30.0)
    conn_shop.execute("PRAGMA busy_timeout = 30000;")
    conn_shop.row_factory = sqlite3.Row
    try:
        prof = conn_shop.execute("SELECT * FROM profiles WHERE xui_email = ?", (email,)).fetchone()
        if not prof:
            pub_id = "prf_" + secrets.token_hex(6)
            now = int(time.time())
            expiry_ms = int(found_client["client"].get("expiryTime") or 0)
            expires_at = expiry_ms // 1000 if expiry_ms > 0 else (now + 30 * 86400)
            client_id = str(found_client["client"].get("id") or email)
            mode = "family" if not email.startswith("anon-") else "anonymous"
            conn_shop.execute(
                """
                INSERT INTO profiles(
                    public_id, xui_inbound_id, transport, profile_mode, family_label,
                    xui_email, xui_client_id, status, created_at, expires_at,
                    last_renewed_at, deleted_at, notes
                )
                VALUES(?, ?, 'tcp', ?, NULL, ?, ?, 'active', ?, ?, ?, NULL, 'auto_sync_from_xui')
                """,
                (pub_id, int(found_client["inbound_id"]), mode, email, client_id, now, expires_at, now)
            )
            conn_shop.commit()
            prof = conn_shop.execute("SELECT * FROM profiles WHERE xui_email = ?", (email,)).fetchone()

        if not prof or prof["status"] == "deleted":
            raise ValueError("Профиль подписки не найден или удалён.")

        notes = str(prof["notes"] or "").lower()
        if notes in {"public_trial_7d_auto_delete", "admin_test_24h_auto_delete", "admin_personal_long_lived"} or "trial" in notes or "test" in notes or "auto_delete" in notes:
            raise ValueError("Пробную подписку (7 дней) нельзя продлить. Пожалуйста, оформите новую подписку на главной странице.")

        prof_dict = dict(prof)

        order_row = conn_shop.execute(
            "SELECT * FROM orders WHERE provisioned_profile_id = ? ORDER BY id DESC LIMIT 1",
            (prof_dict["id"],)
        ).fetchone()

        source_meta = json.loads(order_row["meta_json"]) if order_row and order_row["meta_json"] else {}
        if device_limit not in {3, 6, 9}:
            device_limit = 3
        if duration_days not in {30, 90, 180, 360}:
            duration_days = 360

        transport = str(prof_dict.get("transport") or "tcp")

        # Centralized catalog pricing based on device limit & duration
        final_price = quote_price(device_limit, duration_days)
        months = max(duration_days // 30, 1)
        device_base_prices = {3: 100, 6: 150, 9: 200}
        base_price = device_base_prices.get(device_limit, 100) * months

        # Promo discount check
        discount_percent = 0
        promo_id = None
        if promo_code:
            code_hash = hash_secret(promo_code.strip().upper())
            now_ts = int(time.time())
            p_row = conn_shop.execute(
                """
                UPDATE promo_codes
                SET used_count = used_count + 1, last_used_at = ?
                WHERE code_hash = ?
                  AND enabled = 1
                  AND used_count < max_uses
                  AND (expires_at IS NULL OR expires_at > ?)
                RETURNING *
                """,
                (now_ts, code_hash, now_ts),
            ).fetchone()
            if p_row:
                discount_percent = int(p_row["discount_percent"] or 0)
                promo_id = p_row["id"]
                if discount_percent > 0:
                    final_price = max(final_price * (100 - discount_percent) // 100, 0)

        now = int(time.time())
        final_email = customer_email.strip() or str((order_row["customer_email"] if order_row else "") or "")

        # Cancel any existing open waiting_payment orders for this profile first
        conn_shop.execute(
            "UPDATE orders SET status = 'cancelled', updated_at = ?, closed_at = ? WHERE provisioned_profile_id = ? AND status = 'waiting_payment'",
            (now, now, prof_dict["id"])
        )
        conn_shop.commit()

        token = secrets.token_hex(12)
        order_pub_id = "ord_" + secrets.token_hex(6)

        customer_chat_id = str(order_row["customer_chat_id"]) if order_row and order_row["customer_chat_id"] else None
        if not customer_chat_id:
            owner_row = conn_shop.execute(
                "SELECT chat_id FROM profile_owners WHERE profile_public_id = ? LIMIT 1",
                (str(prof_dict["public_id"]),)
            ).fetchone()
            if owner_row and owner_row["chat_id"]:
                customer_chat_id = str(owner_row["chat_id"])

        meta = {
            "source": f"inline_renewal_{sub_id}",
            "device_limit": device_limit,
            "web": True,
            "web_token": token,
            "customer_email": final_email,
            "renewal_profile_public_id": str(prof_dict["public_id"]),
            "sub_id": sub_id,
            "email_reminders": email_reminders,
        }
        if source_meta.get("referrer_id"):
            meta["referrer_id"] = source_meta["referrer_id"]
        if source_meta.get("referrer_code"):
            meta["referrer_code"] = source_meta["referrer_code"]

        status = "waiting_payment" if final_price > 0 else "auto_provision"
        conn_shop.execute(
            """
            INSERT INTO orders(
                public_id, kind, status, transport, duration_days, profile_mode, family_label,
                base_price_rub, final_price_rub, promo_id, invite_id, customer_chat_id,
                manager_chat_id, manager_message_id, privacy_ack, loss_policy_ack,
                terms_version, provisioned_profile_id, customer_email, created_at, updated_at, closed_at, meta_json
            )
            VALUES(?, 'renewal', ?, ?, ?, ?, NULL, ?, ?, ?, NULL, ?, NULL, NULL, 1, 1, '2026-04-20', ?, ?, ?, ?, NULL, ?)
            """,
            (
                order_pub_id, status, transport, duration_days, str(prof_dict.get("profile_mode") or "anonymous"),
                base_price, final_price, promo_id, customer_chat_id, prof_dict["id"], final_email, now, now, json.dumps(meta)
            )
        )
        conn_shop.commit()

        # If free: renew immediately in x-ui & store
        if final_price == 0:
            cur_expiry_ms = int(found_client["client"].get("expiryTime") or 0)
            cur_expiry_s = cur_expiry_ms // 1000 if cur_expiry_ms > 0 else 0
            base_exp = max(now, int(prof_dict.get("expires_at") or 0), cur_expiry_s)
            new_exp_s = base_exp + duration_days * 86400
            new_exp_ms = new_exp_s * 1000

            try:
                # Update xui db
                xui_rw = sqlite3.connect(XUI_DB_PATH, timeout=30.0)
                xui_rw.execute("PRAGMA busy_timeout = 30000;")
                try:
                    inb = xui_rw.execute("SELECT settings FROM inbounds WHERE id = ?", (found_client["inbound_id"],)).fetchone()
                    if inb and inb[0]:
                        st = json.loads(inb[0])
                        for cl in st.get("clients") or []:
                            if str(cl.get("subId") or "") == sub_id:
                                cl["expiryTime"] = new_exp_ms
                                cl["enable"] = True
                                break
                        xui_rw.execute("UPDATE inbounds SET settings = ? WHERE id = ?", (json.dumps(st), found_client["inbound_id"]))
                        xui_rw.commit()
                finally:
                    xui_rw.close()
                    invalidate_inbounds_cache()

                # Update profiles & orders in shop db
                conn_shop.execute("UPDATE profiles SET expires_at = ?, last_renewed_at = ? WHERE id = ?", (new_exp_s, now, prof_dict["id"]))
                conn_shop.execute("UPDATE orders SET status = 'delivered', closed_at = ? WHERE public_id = ?", (now, order_pub_id))
                conn_shop.commit()
            except Exception as prov_err:
                LOGGER.exception("Failed to provision renewal order %s: %s", order_pub_id, prov_err)
                conn_shop.execute("UPDATE orders SET status = 'cancelled', updated_at = ?, closed_at = ? WHERE public_id = ?", (now, now, order_pub_id))
                if promo_id:
                    conn_shop.execute("UPDATE promo_codes SET used_count = MAX(0, used_count - 1) WHERE id = ?", (promo_id,))
                conn_shop.commit()
                raise
    finally:
        conn_shop.close()

    return {
        "public_id": order_pub_id,
        "final_price_rub": final_price,
        "status": status if final_price > 0 else "delivered",
        "web_token": token,
        "duration_days": duration_days,
        "customer_email": final_email,
    }


def render_payment_notice_html(order_data: Any, status_override: str | None = None) -> str:
    order = dict(order_data)
    meta = json.loads(order.get("meta_json") or "{}") if isinstance(order.get("meta_json"), str) else (order.get("meta_json") or {})
    order_id = str(order.get("public_id") or "")
    order_status = status_override or str(order.get("status") or "waiting_payment")
    customer_email = str(order.get("customer_email") or meta.get("customer_email") or "").strip()
    duration_days = int(order.get("duration_days") or 30)
    device_limit = int(meta.get("device_limit") or 3)
    reported_at = meta.get("web_paid_reported_at")

    token = str(meta.get("web_token") or "")
    token_query = f"?token={html.escape(token, quote=True)}" if token else ""
    token_input = f'<input type="hidden" name="web_token" value="{html.escape(token, quote=True)}"/>' if token else ""

    close_btn = f"""<button type="button" onclick="dismissPaymentNotice('{order_id}')" style="position:absolute; top:12px; right:12px; width:32px; height:32px; min-width:32px; min-height:32px; border-radius:50%; background:rgba(255,255,255,0.08); border:1px solid rgba(255,255,255,0.22); color:#fff; cursor:pointer; display:flex; align-items:center; justify-content:center; font-size:15px; font-weight:700; line-height:1; padding:0; outline:none; transition:all 0.2s;" onmouseover="this.style.background='rgba(255,255,255,0.22)'; this.style.transform='scale(1.08)';" onmouseout="this.style.background='rgba(255,255,255,0.08)'; this.style.transform='scale(1)';" title="Закрыть">✕</button>"""

    if order_status in ("paid", "delivered"):
        email_info = f" на почту <strong>{html.escape(customer_email)}</strong>" if customer_email else ""
        return f"""
        <section id="paymentNoticeCard" class="install" data-order-id="{order_id}" data-order-status="paid" style="position:relative; margin-bottom:24px; background:rgba(47,191,113,0.12); border:1px solid #2fbf71; border-radius:14px; padding:18px 20px; transition: all 0.3s ease;">
          {close_btn}
          <h2 id="noticeTitle" style="color:#2fbf71; margin:0 0 8px; font-size:18px; font-weight:700; display:flex; align-items:center; gap:8px;">✓ Оплата подтверждена!</h2>
          <p id="noticeBody" style="color:#fff; font-size:14.5px; margin:0; line-height:1.5; padding-right:32px;">Мы зачислили продление по заказу <strong>#{order_id}</strong>: <strong>+{duration_days} дн.</strong> (до {device_limit} устр.). Уведомление и чек отправлены{email_info}. Приятного пользования!</p>
        </section>
        """
    elif order_status in ("canceled", "cancelled"):
        support_link = os.environ.get("SUPPORT_URL", "https://t.me/SilentConnectSupport")
        return f"""
        <section id="paymentNoticeCard" class="install" data-order-id="{order_id}" data-order-status="canceled" style="position:relative; margin-bottom:24px; background:rgba(239,68,68,0.12); border:1px solid rgba(239,68,68,0.5); border-radius:14px; padding:18px 20px; transition: all 0.3s ease;">
          {close_btn}
          <h2 id="noticeTitle" style="color:#ef4444; margin:0 0 8px; font-size:18px; font-weight:700; display:flex; align-items:center; gap:8px;">✖ Заказ отменен</h2>
          <p id="noticeBody" style="color:#fff; font-size:14.5px; margin:0; line-height:1.5; padding-right:32px;">Заказ <strong>#{order_id}</strong> отменен администратором. Пожалуйста, попробуйте оформить заказ заново или <a href="{html.escape(support_link)}" target="_blank" style="color:#ef4444; text-decoration:underline; font-weight:600;">свяжитесь с поддержкой</a>.</p>
        </section>
        """
    elif reported_at:
        return f"""
        <section id="paymentNoticeCard" class="install" data-order-id="{order_id}" data-order-status="reported" style="position:relative; margin-bottom:24px; background:rgba(245,158,11,0.12); border:1px solid rgba(245,158,11,0.4); border-radius:14px; padding:18px 20px; transition: all 0.3s ease;">
          {close_btn}
          <h2 id="noticeTitle" style="color:#f59e0b; margin:0 0 8px; font-size:18px; font-weight:700; display:flex; align-items:center; gap:8px;">⏳ Уведомление об оплате отправлено!</h2>
          <p id="noticeBody" style="color:#fff; font-size:14.5px; margin:0; line-height:1.5; padding-right:32px;">Мы получили ваше уведомление по заказу <strong>#{order_id}</strong>. Менеджер проверяет зачисление. Ваша подписка продлится автоматически без изменения ссылок!</p>
          <div style="margin-top:14px; display:flex; align-items:center; gap:12px; flex-wrap:wrap;">
            <form method="post" action="/{SECRET_SEGMENT}/cancel/{order_id}{token_query}" style="margin:0;">
              {token_input}
              <button type="submit" class="button secondary" style="min-height:36px; padding:6px 14px; font-size:13px; font-weight:600; background:rgba(239,68,68,0.12); color:#ef4444; border:1px solid rgba(239,68,68,0.35); border-radius:8px; cursor:pointer; display:inline-flex; align-items:center; gap:6px; transition:all 0.2s;" onmouseover="this.style.background='rgba(239,68,68,0.22)';" onmouseout="this.style.background='rgba(239,68,68,0.12)';">Отменить заказ ✖</button>
            </form>
            <span style="color:var(--muted); font-size:12.5px;">Если передумали или ошиблись</span>
          </div>
        </section>
        """
    else:
        pay_link = os.environ.get("PAYMENT_TRANSFER_URL", "https://t.tb.ru/c2c-qr-choose-bank?requisiteNumber=+79990000000&bankCode=100000000004")
        sbp_phone = os.environ.get("PAYMENT_SBP_PHONE", "+79990000000")
        sbp_bank = os.environ.get("PAYMENT_SBP_BANK", "СБП")
        return f"""
        <section class="install" style="margin-bottom:24px; background:rgba(47,191,113,0.08); border:1px solid var(--green);">
          <div class="install-head" style="display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; margin-bottom:12px;">
            <h2 style="margin:0; font-size:20px; font-weight:700; color:#fff;">💳 Оплата продления #{order_id}</h2>
            <span style="background:rgba(245, 158, 11, 0.15); border:1px solid rgba(245, 158, 11, 0.4); color:#f59e0b; padding:4px 10px; border-radius:8px; font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:0.5px; display:inline-block;">Ожидает оплаты</span>
          </div>
          <div style="font-size:32px; font-weight:800; color:#fff; margin:10px 0 16px;">
            {order.get('final_price_rub', 0)} ₽ <span style="font-size:14px; color:var(--muted); font-weight:500;">({duration_days} дн.)</span>
          </div>
          <div style="background:rgba(0,0,0,0.3); border:1px solid var(--line); border-radius:12px; padding:16px; margin-bottom:16px;">
            <div style="color:var(--muted); font-size:14px; line-height:1.5;">
              Нажмите кнопку <strong>«Оплатить переводом»</strong>, переведите ровно <strong>{order.get('final_price_rub', 0)} ₽</strong> через СБП ({sbp_phone} / {sbp_bank}), после чего нажмите <strong>«Я оплатил(а)»</strong>.
            </div>
          </div>
          <div style="display:flex; gap:12px; flex-wrap:wrap; align-items:center;">
            <a href="{html.escape(pay_link, quote=True)}" target="_blank" rel="noopener" class="button" style="min-height:46px; font-weight:800; text-decoration:none; background:var(--green); color:#000; display:inline-flex; align-items:center; justify-content:center;">Оплатить переводом 💳</a>
            <form method="post" action="/{SECRET_SEGMENT}/paid/{order_id}{token_query}" style="margin:0;">
              {token_input}
              <button type="submit" class="button success" style="min-height:46px; font-weight:800; background:rgba(255,255,255,0.12); color:#fff; border:1px solid var(--line);">Я оплатил(а) ✓</button>
            </form>
            <a href="https://t.me/SilentConnectVPNBot?start=claim_{order_id}_{token}" target="_blank" class="button secondary" style="min-height:46px; font-weight:600; text-decoration:none; display:inline-flex; align-items:center;">Привязать в Telegram ✈️</a>
            <form method="post" action="/{SECRET_SEGMENT}/cancel/{order_id}{token_query}" style="margin:0;">
              {token_input}
              <button type="submit" class="button secondary" style="min-height:46px; font-weight:600; background:rgba(239,68,68,0.12); color:#ef4444; border:1px solid rgba(239,68,68,0.3);">Отменить ✖</button>
            </form>
          </div>
        </section>
        """


def check_pending_payment_card(sub_id: str) -> str:
    db_path = find_store_db_path()
    if not Path(db_path).exists():
        return ""
    try:
        conn = sqlite3.connect(db_path, timeout=30.0)
        conn.execute("PRAGMA busy_timeout = 30000;")
        conn.row_factory = sqlite3.Row
        try:
            target_sub = sub_id.strip().split("~")[0]
            row, _, _, _, client = find_subscription(target_sub)
            email = str(client.get("email") or "")
            prof = conn.execute("SELECT * FROM profiles WHERE xui_email = ?", (email,)).fetchone()
            if prof:
                order = conn.execute(
                    "SELECT * FROM orders WHERE provisioned_profile_id = ? ORDER BY id DESC LIMIT 1",
                    (prof["id"],)
                ).fetchone()
                if order:
                    now = int(time.time())
                    updated_at = order["updated_at"] or order["created_at"] or 0
                    if order["status"] in ("paid", "delivered") and (now - updated_at > 86400 * 5):
                        return ""
                    if order["status"] in ("canceled", "cancelled") and (now - updated_at > 86400 * 3):
                        return ""
                    return render_payment_notice_html(order)
        finally:
            conn.close()
    except Exception as e:
        LOGGER.debug("Error in check_pending_payment_card: %s", e)
    return ""



def handle_inline_order_paid(order_public_id: str, web_token: str | None = None) -> bool:
    db_path = find_store_db_path()
    if not Path(db_path).exists():
        return False

    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.execute("PRAGMA busy_timeout = 30000;")
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT * FROM orders WHERE public_id = ?", (order_public_id,)).fetchone()
        if not row:
            return False

        if web_token is not None and not _verify_order_web_token(row, web_token):
            LOGGER.warning("Unauthorized /paid attempt for order %s (invalid web token)", order_public_id)
            return False

        # Idempotent CAS: skip if already delivered or cancelled
        current_status = row["status"]
        if current_status in ("delivered", "cancelled"):
            conn.close()
            return True  # Already processed

        meta = json.loads(row["meta_json"]) if row["meta_json"] else {}
        meta["web_paid_reported_at"] = int(time.time())
        now = int(time.time())
        conn.execute("UPDATE orders SET meta_json = ?, updated_at = ? WHERE public_id = ?", (json.dumps(meta), now, order_public_id))
        conn.commit()

        # Record admin action
        conn.execute(
            """
            INSERT INTO admin_actions(action_type, target_type, target_public_id, actor, created_at, meta_json)
            VALUES('web_payment_reported_by_customer', 'order', ?, 'subjson_web', ?, ?)
            """,
            (order_public_id, now, json.dumps({"sub_id": meta.get("sub_id")}))
        )
        conn.commit()

        # Notify Telegram admins using active SilentConnect bot token (.env.silentconnect)
        bot_token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
        if not bot_token:
            for env_file in ["/root/vpn-shop/.env.silentconnect", "/root/vpn-shop/.env"]:
                env_path = Path(env_file)
                if env_path.exists():
                    for line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                        if line.startswith("TELEGRAM_BOT_TOKEN="):
                            val = line.split("=", 1)[1].strip()
                            if val:
                                bot_token = val
                                break
                if bot_token:
                    break

        if bot_token:
            admin_chats = []
            try:
                admin_rows = conn.execute("SELECT DISTINCT chat_id FROM chat_sessions WHERE scope = 'admin'").fetchall()
                admin_chats = [str(r["chat_id"]) for r in admin_rows if r["chat_id"]]
            except Exception:
                pass

            if not admin_chats:
                try:
                    admin_rows = conn.execute("SELECT DISTINCT actor FROM admin_actions WHERE actor LIKE 'tg:%' ORDER BY id DESC LIMIT 10").fetchall()
                    for r in admin_rows:
                        actor = str(r["actor"] or "")
                        if actor.startswith("tg:"):
                            cid = actor.split(":", 1)[1].strip()
                            if cid and cid not in admin_chats:
                                admin_chats.append(cid)
                except Exception:
                    pass

            env_admin_ids = os.environ.get("ADMIN_TG_IDS", "958026436").strip()
            if env_admin_ids:
                for cid in env_admin_ids.split(","):
                    cid = cid.strip()
                    if cid and cid not in admin_chats:
                        admin_chats.append(cid)

            if admin_chats:
                row_dict = dict(row)
                customer_email = str(row_dict.get("customer_email") or meta.get("customer_email") or "").strip()
                email_info = f"\n📧 Email: `{customer_email}`" if customer_email else ""
                msg_text = (
                    f"💳 **Покупатель с сайта сообщил об оплате**\n\n"
                    f"Заказ: `{order_public_id}`\n"
                    f"Тип: Продление подписки\n"
                    f"Срок: {row_dict.get('duration_days', 30)} дн.{email_info}\n"
                    f"Сумма: {row_dict.get('final_price_rub', 0)} RUB\n\n"
                    f"Проверьте зачисление по СБП и подтвердите оплату."
                )
                markup = {
                    "inline_keyboard": [
                        [
                            {"text": "✅ Подтвердить оплату", "callback_data": f"admin:confirm:{order_public_id}"},
                            {"text": "❌ Отменить", "callback_data": f"admin:cancel:{order_public_id}"},
                        ]
                    ]
                }
                for chat_id in admin_chats:
                    try:
                        payload = json.dumps({
                            "chat_id": chat_id,
                            "text": msg_text,
                            "parse_mode": "Markdown",
                            "reply_markup": markup,
                        }).encode("utf-8")
                        req = urllib.request.Request(
                            f"https://api.telegram.org/bot{bot_token}/sendMessage",
                            data=payload,
                            headers={"Content-Type": "application/json"}
                        )
                        urllib.request.urlopen(req, timeout=5)
                    except Exception:
                        pass

        return True
    finally:
        conn.close()


def handle_inline_order_cancel(order_public_id: str, web_token: str | None = None) -> str:
    db_path = find_store_db_path()
    if not Path(db_path).exists():
        return ""

    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.execute("PRAGMA busy_timeout = 30000;")
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT * FROM orders WHERE public_id = ?", (order_public_id,)).fetchone()
        if not row:
            return ""

        if web_token is not None and not _verify_order_web_token(row, web_token):
            LOGGER.warning("Unauthorized /cancel attempt for order %s (invalid web token)", order_public_id)
            return ""

        sub_id = ""
        profile_id = row["provisioned_profile_id"]
        if row["meta_json"]:
            try:
                meta = json.loads(row["meta_json"])
                sub_id = str(meta.get("sub_id") or "")
            except Exception:
                pass

        now = int(time.time())
        if profile_id:
            conn.execute(
                "UPDATE orders SET status = 'cancelled', updated_at = ?, closed_at = ? WHERE status = 'waiting_payment' AND provisioned_profile_id = ?",
                (now, now, profile_id)
            )
        if sub_id:
            conn.execute(
                "UPDATE orders SET status = 'cancelled', updated_at = ?, closed_at = ? WHERE status = 'waiting_payment' AND json_extract(meta_json, '$.sub_id') = ?",
                (now, now, sub_id)
            )
        conn.execute(
            "UPDATE orders SET status = 'cancelled', updated_at = ?, closed_at = ? WHERE public_id = ?",
            (now, now, order_public_id)
        )
        conn.commit()
        return sub_id
    finally:
        conn.close()


def resolve_public_host(headers) -> str:
    if PUBLIC_HOST:
        return PUBLIC_HOST

    forwarded_host = headers.get("X-Forwarded-Host", "").strip()
    if forwarded_host:
        return forwarded_host.split(",")[0].strip().split(":")[0]

    host = headers.get("Host", "").strip()
    if host:
        return host.split(":")[0]

    raise RuntimeError("Unable to resolve public host from PUBLIC_HOST or request headers")


def resolve_relay_public_host(headers) -> str:
    host = os.environ.get("RELAY_PUBLIC_HOST", "").strip() or RELAY_PUBLIC_HOST
    if host:
        return host
    return "relay.example.com"


def resolve_public_origin(headers) -> str:
    if PUBLIC_SUBSCRIPTION_ORIGIN:
        return PUBLIC_SUBSCRIPTION_ORIGIN
    if PUBLIC_HOST:
        host = PUBLIC_HOST
    else:
        forwarded_host = headers.get("X-Forwarded-Host", "").strip()
        host = forwarded_host.split(",")[0].strip() if forwarded_host else headers.get("Host", "").strip()
    host = host.strip()
    if not host:
        raise RuntimeError("Unable to resolve public origin")
    if host.startswith(("http://", "https://")):
        return host.rstrip("/")
    scheme = headers.get("X-Forwarded-Proto", "").split(",")[0].strip() or "https"
    return f"{scheme}://{host}".rstrip("/")


def public_subscription_url(headers, route: str, subscription_id: str) -> str:
    origin = resolve_public_origin(headers)
    return f"{origin}/{SECRET_SEGMENT}/{route}/{urllib.parse.quote(subscription_id, safe='')}"


def public_connection_page_url(headers, subscription_route: str, subscription_id: str) -> str:
    setup_url = public_subscription_url(headers, "import", subscription_id)
    subscription_url = public_subscription_url(headers, subscription_route, subscription_id)
    return f"{setup_url}?{urllib.parse.urlencode({'url': subscription_url})}"


def first_non_empty(values: list[Any] | tuple[Any, ...] | None) -> Any:
    for value in values or []:
        if value not in (None, ""):
            return value
    return None


def put_if_defined(target: dict[str, Any], key: str, value: Any) -> None:
    if value is None:
        return
    if isinstance(value, str) and value == "":
        return
    target[key] = value


def copy_defined(source: dict[str, Any], target: dict[str, Any], keys: tuple[str, ...]) -> None:
    for key in keys:
        put_if_defined(target, key, source.get(key))


def parse_csv_values(raw: str) -> list[str]:
    values: list[str] = []
    for chunk in raw.replace(";", ",").split(","):
        value = chunk.strip()
        if value:
            values.append(value)
    return values


def normalize_ipv4_route(value: str) -> str | None:
    clean = value.strip()
    if not clean:
        return None
    try:
        if "/" in clean:
            return str(ipaddress.ip_network(clean, strict=False))
        address = ipaddress.ip_address(clean)
    except ValueError:
        return None
    if address.version != 4:
        return None
    return f"{address}/32"


def resolve_ipv4_routes(host: str) -> list[str]:
    clean = host.strip().strip("[]")
    if not clean:
        return []

    direct = normalize_ipv4_route(clean)
    if direct:
        return [direct]

    routes: list[str] = []
    try:
        records = socket.getaddrinfo(clean, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror:
        LOGGER.warning("Unable to resolve Happ exclude route host: %s", clean)
        return []

    for record in records:
        route = normalize_ipv4_route(record[4][0])
        if route and route not in routes:
            routes.append(route)
    return routes



def sync_litestream_db_if_needed():
    try:
        import subprocess
        import shutil
        tmp_path = '/tmp/xui_sync.db'
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
        res = subprocess.run(['litestream', 'restore', '-o', tmp_path, '/etc/x-ui/x-ui.db'], capture_output=True, timeout=5)
        if os.path.exists(tmp_path) and os.path.getsize(tmp_path) > 0:
            shutil.move(tmp_path, '/etc/x-ui/x-ui.db')
            LOGGER.info("Successfully restored /etc/x-ui/x-ui.db from Litestream replica!")
    except Exception as e:
        LOGGER.warning("litestream restore error: %s", e)

def start_litestream_background_sync():
    # Restore last-good DB ONCE at startup (crash recovery only).
    # FIX 2026-08-22: previously this ran an infinite loop restoring the
    # LIVE /etc/x-ui/x-ui.db every 10 seconds, racing with x-ui writes
    # (see AUDIT_REPORT.md - Litestream restore-loop finding).
    try:
        sync_litestream_db_if_needed()
    except Exception:
        LOGGER.warning("startup litestream restore failed; continuing with current DB")

start_litestream_background_sync()

def find_subscription(subscription_id: str) -> tuple[sqlite3.Row, dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    # FIX 2026-08-22: removed automatic DB restore on lookup miss -
    # any unknown/brute-forced subscription ID must NOT rewrite the live DB.
    return _find_subscription_impl(subscription_id)

def _find_subscription_impl(subscription_id: str) -> tuple[sqlite3.Row, dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    target = subscription_id.strip()
    _ensure_inbounds_cache()
    with _inbounds_cache_lock:
        if target in _cached_clients_index:
            row, settings, stream_settings, sniffing, client = _cached_clients_index[target]
            return row, copy.deepcopy(settings), copy.deepcopy(stream_settings), copy.deepcopy(sniffing), copy.deepcopy(client)

    try:
        store_path = find_store_db_path()
        conn = sqlite3.connect(store_path, timeout=30.0)
        conn.execute("PRAGMA busy_timeout = 30000;")
        conn.row_factory = sqlite3.Row
        try:
            prof = conn.execute("SELECT xui_email FROM profiles WHERE public_id = ?", (target,)).fetchone()
        finally:
            conn.close()
        if prof and prof["xui_email"]:
            xemail = str(prof["xui_email"]).strip()
            with _inbounds_cache_lock:
                if xemail in _cached_clients_index:
                    row, settings, stream_settings, sniffing, client = _cached_clients_index[xemail]
                    return row, copy.deepcopy(settings), copy.deepcopy(stream_settings), copy.deepcopy(sniffing), copy.deepcopy(client)
    except Exception:
        pass

    raise KeyError(subscription_id)


def find_subscription_by_network(subscription_id: str, network: str = "tcp") -> tuple[sqlite3.Row, dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    target = subscription_id.strip()
    _ensure_inbounds_cache()
    with _inbounds_cache_lock:
        for row, settings, stream_settings, sniffing, clients in _cached_inbounds_parsed:
            for client in clients:
                c_sub = str(client.get("subId") or "").strip()
                c_email = str(client.get("email") or "").strip()
                c_id = str(client.get("id") or "").strip()
                if target in (c_sub, c_email, c_id):
                    if stream_settings.get("network", "tcp") == network:
                        return row, copy.deepcopy(settings), copy.deepcopy(stream_settings), copy.deepcopy(sniffing), copy.deepcopy(client)
    try:
        return find_subscription(subscription_id)
    except KeyError:
        raise KeyError(subscription_id)


def parse_hybrid_subscription_id(subscription_id: str) -> tuple[str, str]:
    if "~" in subscription_id:
        parts = [part.strip() for part in subscription_id.split("~", 1)]
        if len(parts) == 2 and parts[0] and parts[1]:
            return parts[0], parts[1]
    return subscription_id, subscription_id


def build_vnext_settings(protocol: str, settings: dict[str, Any], client: dict[str, Any], public_host: str, port: int) -> dict[str, Any]:
    user: dict[str, Any] = {}
    copy_defined(client, user, ("id", "email", "flow", "level", "alterId"))

    if protocol == "vless":
        user["encryption"] = settings.get("encryption", "none")
    else:
        user["security"] = client.get("security") or settings.get("security") or "auto"
        user.setdefault("alterId", 0)

    return {
        "vnext": [
            {
                "address": public_host,
                "port": port,
                "users": [user],
            }
        ]
    }


def build_trojan_settings(client: dict[str, Any], public_host: str, port: int) -> dict[str, Any]:
    server: dict[str, Any] = {
        "address": public_host,
        "port": port,
        "password": client["password"],
    }
    copy_defined(client, server, ("email", "flow", "level"))
    return {"servers": [server]}


def build_shadowsocks_settings(settings: dict[str, Any], client: dict[str, Any], public_host: str, port: int) -> dict[str, Any]:
    server: dict[str, Any] = {
        "address": public_host,
        "port": port,
        "method": settings["method"],
        "password": client.get("password", settings.get("password")),
    }
    copy_defined(client, server, ("email", "level", "uot"))
    if "ota" in settings:
        server["ota"] = settings["ota"]
    return {"servers": [server]}


def build_outbound_settings(protocol: str, settings: dict[str, Any], client: dict[str, Any], public_host: str, port: int) -> dict[str, Any]:
    if protocol in {"vless", "vmess"}:
        return build_vnext_settings(protocol, settings, client, public_host, port)
    if protocol == "trojan":
        return build_trojan_settings(client, public_host, port)
    if protocol == "shadowsocks":
        return build_shadowsocks_settings(settings, client, public_host, port)
    raise ValueError(f"Unsupported protocol for client translation: {protocol}")


def build_client_reality_settings(source: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    nested_settings = source.get("settings")
    inner = nested_settings if isinstance(nested_settings, dict) else {}

    server_name = inner.get("serverName") or first_non_empty(source.get("serverNames")) or TCP_REALITY_SNI_CLASSIC
    public_key = inner.get("publicKey") or source.get("publicKey") or source.get("password") or TCP_REALITY_PUBLIC_KEY
    short_id = inner.get("shortId") or first_non_empty(source.get("shortIds")) or TCP_REALITY_SHORT_ID
    fingerprint = inner.get("fingerprint") or source.get("fingerprint") or "chrome"
    if fingerprint == "chrome":
        fingerprint = "firefox"

    put_if_defined(result, "serverName", server_name)
    put_if_defined(result, "fingerprint", fingerprint)
    put_if_defined(result, "shortId", short_id)
    put_if_defined(result, "spiderX", inner.get("spiderX") or source.get("spiderX"))
    put_if_defined(result, "mldsa65Verify", inner.get("mldsa65Verify") or source.get("mldsa65Verify"))

    if not public_key:
        raise ValueError("REALITY public key is missing in x-ui.db stream_settings")

    # Keep both names for wider client compatibility.
    result["publicKey"] = public_key
    result["password"] = public_key
    return result


def build_client_tls_settings(source: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    copy_defined(
        source,
        result,
        (
            "serverName",
            "verifyPeerCertByName",
            "allowInsecure",
            "alpn",
            "minVersion",
            "maxVersion",
            "cipherSuites",
            "disableSystemRoot",
            "enableSessionResumption",
            "fingerprint",
            "pinnedPeerCertSha256",
            "echServerKeys",
            "echConfigList",
            "echForceQuery",
        ),
    )
    return result


def build_portable_stream_settings(stream_settings: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}

    network = stream_settings.get("network")
    security = stream_settings.get("security")
    put_if_defined(result, "network", network)
    put_if_defined(result, "security", security)

    if security == "reality":
        reality = stream_settings.get("realitySettings")
        if not isinstance(reality, dict):
            raise ValueError("REALITY stream_settings is not a JSON object")
        result["realitySettings"] = build_client_reality_settings(reality)
    elif security == "tls":
        tls_settings = stream_settings.get("tlsSettings")
        if isinstance(tls_settings, dict):
            result["tlsSettings"] = build_client_tls_settings(tls_settings)

    for key in TRANSPORT_SETTING_KEYS:
        value = stream_settings.get(key)
        if isinstance(value, dict) and value:
            result[key] = copy.deepcopy(value)

    return result


def build_local_inbound(protocol: str, port: int, tag: str, sniffing: dict[str, Any]) -> dict[str, Any]:
    inbound: dict[str, Any] = {
        "listen": "127.0.0.1",
        "port": port,
        "protocol": protocol,
        "tag": tag,
        "settings": {
            "auth": "noauth",
            "udp": True,
        },
    }
    if sniffing:
        inbound["sniffing"] = copy.deepcopy(sniffing)
    return inbound


FORCE_PROXY_DOMAINS = [
    "domain:speedtest.net",
    "domain:ooklaserver.net",
    "domain:speed.cloudflare.com",
    "keyword:speedtest",
    "domain:canva.com",
    "domain:instagram.com",
    "domain:cdninstagram.com",
    "domain:igcdn.com",
    "domain:fbcdn.net",
    "domain:spotify.com",
    "domain:scdn.co",
    "domain:spotifycdn.com",
    "domain:tiktok.com",
    "domain:tiktokcdn.com",
    "domain:tiktokv.com",
    "domain:byteoversea.com",
    "domain:bytedance.com",
    "domain:byteimg.com",
    "domain:openai.com",
    "domain:chatgpt.com",
    "domain:oaistatic.com",
    "domain:oaiusercontent.com",
    "domain:gemini.google.com",
    "domain:aistudio.google.com",
    "domain:generativelanguage.googleapis.com",
    "domain:play.google.com",
    "domain:play.googleapis.com",
    "domain:googleapis.com",
    "domain:googleplay.com",
    "domain:dl.google.com",
    "domain:gvt1.com",
    "domain:gvt2.com",
    "domain:gvt3.com",
    "domain:android.com"]


HEAVY_DOWNLOAD_DIRECT_DOMAINS = [
    "domain:steamcontent.com",
    "domain:steamserver.net",
    "domain:client-download.steampowered.com",
    "domain:steamcdn-a.akamaihd.net"]


APP_DOWNLOAD_DIRECT_DOMAINS = [
    "domain:appldnld.apple.com",
    "domain:swcdn.apple.com",
    "domain:updates-http.cdn-apple.com",
    "domain:iosapps.itunes.apple.com",
    "domain:osxapps.itunes.apple.com",
    "domain:dbankcdn.com"]


RU_DIRECT_DOMAINS = [
    "domain:ru",
    "domain:su",
    "domain:xn--p1ai",
    "domain:yandex.com",
    "domain:yandex.net",
    "domain:yastatic.net",
    "domain:vk.com",
    "domain:bedrive.ru",
    "domain:userapi.com",
    "domain:mycdn.me",
    "domain:2gis.com",
    "domain:sberbank.com",
    "domain:sberbank.ru",
    "domain:sber.ru",
    "domain:tbank.ru",
    "domain:tinkoff.ru",
    "domain:ozon.ru",
    "domain:ozonusercontent.com",
    "domain:wildberries.ru",
    "domain:wb.ru",
    "domain:wbstatic.net",
    "domain:avito.ru",
    "domain:avito.st",
    "domain:gosuslugi.ru",
    "domain:nalog.gov.ru",
    "domain:mironline.ru",
    "domain:gismeteo.ru",
    "domain:gismeteo.net",
    "domain:gismeteo.st",
    "domain:boosty.to"]


def build_routing(route_mode: str) -> dict[str, Any]:
    rules: list[dict[str, Any]] = [
        {
            "type": "field",
            "protocol": ["bittorrent"],
            "outboundTag": "block",
        },
        {
            "type": "field",
            "ip": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
            "outboundTag": "direct",
        },
        {
            "type": "field",
            "ip": [
                "1.1.1.1",
                "1.0.0.1",
                "8.8.8.8",
                "8.8.4.4",
                "9.9.9.9",
                "149.112.112.112"],
            "outboundTag": "direct",
        }]

    if route_mode == "split-ru":
        rules.extend(
            [
                {
                    "type": "field",
                    "domain": FORCE_PROXY_DOMAINS,
                    "outboundTag": "proxy",
                },
                {
                    "type": "field",
                    "domain": HEAVY_DOWNLOAD_DIRECT_DOMAINS,
                    "outboundTag": "direct",
                },
                {
                    "type": "field",
                    "domain": APP_DOWNLOAD_DIRECT_DOMAINS,
                    "outboundTag": "direct",
                },
                {
                    "type": "field",
                    "domain": RU_DIRECT_DOMAINS,
                    "outboundTag": "direct",
                }]
        )
    elif route_mode != "global":
        raise ValueError(f"Unsupported route mode: {route_mode}")

    return {
        "domainStrategy": "IPIfNonMatch",
        "rules": rules,
    }


def build_balanced_routing(
    route_mode: str,
    *,
    balancer_tag: str = "auto-proxy",
    fallback_tag: str = "proxy-tcp",
    selector: list[str] | None = None,
) -> dict[str, Any]:
    routing = build_routing(route_mode)
    rules: list[dict[str, Any]] = []
    for rule in routing["rules"]:
        balanced_rule = copy.deepcopy(rule)
        if balanced_rule.get("outboundTag") == "proxy":
            balanced_rule.pop("outboundTag", None)
            balanced_rule["balancerTag"] = balancer_tag
        rules.append(balanced_rule)

    # Keep IPIfNonMatch useful for geoip:ru: this catch-all only matches after
    # Xray has resolved unmatched domains to IPs.
    rules.append(
        {
            "type": "field",
            "ip": ["0.0.0.0/0", "::/0"],
            "balancerTag": balancer_tag,
        }
    )
    routing["rules"] = rules
    routing["balancers"] = [
        {
            "tag": balancer_tag,
            "selector": selector or ["proxy-"],
            "fallbackTag": fallback_tag,
            "strategy": {
                "type": "leastPing",
            },
        }
    ]
    return routing


def relay_public_port(stream_settings: dict[str, Any], fallback_port: int) -> int:
    network = str(stream_settings.get("network") or "").lower()
    if network == "xhttp":
        return RELAY_XHTTP_PORT
    return RELAY_TCP_PORT or fallback_port


def build_proxy_outbound(
    subscription_id: str,
    public_host: str,
    tag: str,
    *,
    relay: bool = False,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    network = "xhttp" if "xhttp" in tag else "tcp"
    row, settings, stream_settings, sniffing, client = find_subscription_by_network(subscription_id, network)
    if network == "tcp" and not relay:
        public_port = 443
    else:
        public_port = relay_public_port(stream_settings, int(row["port"])) if relay else int(row["port"])
    outbound_settings = build_outbound_settings(
        row["protocol"],
        settings,
        client,
        public_host,
        public_port,
    )
    outbound = {
        "tag": tag,
        "protocol": row["protocol"],
        "settings": outbound_settings,
        "streamSettings": build_portable_stream_settings(stream_settings),
    }
    return outbound, sniffing, client


def build_raw_client_config(subscription_id: str, public_host: str) -> dict[str, Any]:
    row, settings, stream_settings, sniffing, client = find_subscription(subscription_id)
    outbound_settings = build_outbound_settings(
        row["protocol"],
        settings,
        client,
        public_host,
        row["port"],
    )

    inbound = {
        "listen": "127.0.0.1",
        "port": 10808,
        "protocol": "socks",
        "settings": {
            "udp": True,
        },
        "sniffing": copy.deepcopy(sniffing),
    }

    outbound = {
        "protocol": row["protocol"],
        "settings": outbound_settings,
        "streamSettings": copy.deepcopy(stream_settings),
    }

    return {
        "inbounds": [inbound],
        "outbounds": [outbound],
    }


DNS_PRESETS: dict[str, list[Any]] = {
    "default": [
        {
            "address": "localhost",
            "domains": [
                "domain:silentconnect.net",  # PLACEHOLDER
                "domain:max.ru",
                "domain:kernel.org",
            ],
        },
        "1.1.1.1",
        "8.8.8.8",
        "localhost",
    ],
    "google": [
        "8.8.8.8",
        "8.8.4.4",
        "localhost",
    ],
}


def build_portable_client_config(
    subscription_id: str,
    public_host: str,
    route_mode: str,
    dns_preset: str = "default",
    *,
    relay: bool = False,
) -> dict[str, Any]:
    row, settings, stream_settings, sniffing, client = find_subscription_by_network(subscription_id, "tcp")
    public_port = relay_public_port(stream_settings, int(row["port"])) if relay else 443
    outbound_settings = build_outbound_settings(
        row["protocol"],
        settings,
        client,
        public_host,
        public_port,
    )

    outbound = {
        "tag": "proxy",
        "protocol": row["protocol"],
        "settings": outbound_settings,
        "streamSettings": build_portable_stream_settings(stream_settings),
    }

    remark = client.get("email") or row["remark"] or subscription_id

    return {
        "log": {
            "loglevel": "warning",
            "access": "none",
            "error": "",
            "dnsLog": False,
        },
        "dns": {
            "queryStrategy": "UseIPv4",
            "servers": copy.deepcopy(DNS_PRESETS[dns_preset]),
        },
        "inbounds": [
            build_local_inbound("socks", 10808, "socks-in", sniffing),
            build_local_inbound("http", 10809, "http-in", sniffing)],
        "outbounds": [
            outbound,
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {},
            },
            {
                "tag": "block",
                "protocol": "blackhole",
                "settings": {},
            }],
        "remarks": remark,
        "meta": build_happ_config_meta(subscription_id),
        "routing": build_routing(route_mode),
    }


def build_ws443_client_config(
    subscription_id: str,
    route_mode: str,
    dns_preset: str = "default",
    ws_host: str | None = None,
) -> dict[str, Any]:
    row, _settings, _stream_settings, sniffing, client = find_subscription_by_network(subscription_id, "ws")
    if row["protocol"] != "vless" or not client.get("id"):
        raise ValueError("WS 443 fallback supports only VLESS clients with UUID id")

    target_host = ws_host or WS443_PUBLIC_HOST
    
    # Resolve target_host to an IP address for the 'address' field to prevent routing loops in Windows TUN mode
    connect_address = target_host
    if not target_host.replace(".", "").isdigit():
        try:
            connect_address = socket.gethostbyname(target_host)
            LOGGER.info(f"Resolved {target_host} to {connect_address} for VLESS-WS outbound address")
        except Exception as e:
            LOGGER.error(f"Error resolving target_host {target_host} for address: {e}")

    remark = f"{client.get('email') or row['remark'] or subscription_id} Wi-Fi"
    user: dict[str, Any] = {
        "id": client["id"],
        "email": client.get("email") or remark,
        "encryption": "none",
    }

    outbound = {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": connect_address,
                    "port": WS443_PUBLIC_PORT,
                    "users": [user],
                }
            ]
        },
        "streamSettings": {
            "network": "ws",
            "security": "tls",
            "tlsSettings": {
                "serverName": target_host,
                "fingerprint": "chrome",
                "alpn": ["http/1.1"],
            },
            "wsSettings": {
                "path": WS443_PATH,
                "headers": {
                    "Host": target_host,
                },
            },
        },
    }

    return {
        "log": {
            "loglevel": "warning",
            "access": "none",
            "error": "",
            "dnsLog": False,
        },
        "dns": {
            "queryStrategy": "UseIPv4",
            "servers": copy.deepcopy(DNS_PRESETS[dns_preset]),
        },
        "inbounds": [
            build_local_inbound("socks", 10808, "socks-in", sniffing),
            build_local_inbound("http", 10809, "http-in", sniffing)],
        "outbounds": [
            outbound,
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {},
            },
            {
                "tag": "block",
                "protocol": "blackhole",
                "settings": {},
            }],
        "remarks": remark,
        "meta": build_happ_config_meta(subscription_id),
        "routing": build_routing(route_mode),
    }


def build_dual_test_client_configs(
    subscription_id: str,
    public_host: str,
    route_mode: str,
    dns_preset: str = "default",
) -> list[dict[str, Any]]:
    primary = build_portable_client_config(subscription_id, public_host, route_mode, dns_preset)
    base_remark = str(primary.get("remarks") or subscription_id)
    primary["remarks"] = f"{base_remark} 4G"
    primary_meta = primary.get("meta")
    if isinstance(primary_meta, dict):
        primary_meta["serverDescription"] = "4G / мобильная сеть"

    ws443 = build_ws443_client_config(subscription_id, route_mode, dns_preset)
    ws443_meta = ws443.get("meta")
    if isinstance(ws443_meta, dict):
        ws443_meta["serverDescription"] = "Wi-Fi / домашняя сеть"
    return [primary, ws443]


def build_ws443_host_test_client_config(
    subscription_id: str,
    route_mode: str,
    ws_host: str,
    label: str,
    dns_preset: str = "default",
) -> dict[str, Any]:
    payload = build_ws443_client_config(subscription_id, route_mode, dns_preset, ws_host=ws_host)
    base_remark = str(payload.get("remarks") or subscription_id)
    payload["remarks"] = f"{base_remark} {label}"
    meta = payload.get("meta")
    if isinstance(meta, dict):
        meta["serverDescription"] = f"Wi-Fi test: {label}"
    return payload


def build_dual_auto_test_client_config(
    subscription_id: str,
    public_host: str,
    route_mode: str,
    dns_preset: str = "default",
) -> dict[str, Any]:
    tcp_outbound, sniffing, tcp_client = build_proxy_outbound(subscription_id, public_host, "proxy-tcp")
    ws443_config = build_ws443_client_config(subscription_id, route_mode, dns_preset)
    ws443_outbound = copy.deepcopy(ws443_config["outbounds"][0])
    ws443_outbound["tag"] = "proxy-wifi"

    tcp_remark = tcp_client.get("email") or subscription_id
    meta = build_happ_config_meta(subscription_id)
    if isinstance(meta, dict):
        meta["serverDescription"] = "Авто: 4G + Wi-Fi"

    return {
        "log": {
            "loglevel": "warning",
            "access": "none",
            "error": "",
            "dnsLog": False,
        },
        "dns": {
            "queryStrategy": "UseIPv4",
            "servers": copy.deepcopy(DNS_PRESETS[dns_preset]),
        },
        "inbounds": [
            build_local_inbound("socks", 10808, "socks-in", sniffing),
            build_local_inbound("http", 10809, "http-in", sniffing)],
        "outbounds": [
            tcp_outbound,
            ws443_outbound,
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {},
            },
            {
                "tag": "block",
                "protocol": "blackhole",
                "settings": {},
            }],
        "remarks": f"{tcp_remark} Auto",
        "meta": meta,
        "routing": build_balanced_routing(route_mode),
        "observatory": {
            "subjectSelector": ["proxy-"],
            "probeUrl": "https://www.google.com/generate_204",
            "probeInterval": "1m",
            "enableConcurrency": True,
        },
    }


def build_dual_auto_wifi_first_test_client_config(
    subscription_id: str,
    public_host: str,
    route_mode: str,
    dns_preset: str = "default",
) -> dict[str, Any]:
    payload = build_dual_auto_test_client_config(subscription_id, public_host, route_mode, dns_preset)
    proxy_wi_fi = next(outbound for outbound in payload["outbounds"] if outbound.get("tag") == "proxy-wifi")
    proxy_tcp = next(outbound for outbound in payload["outbounds"] if outbound.get("tag") == "proxy-tcp")
    rest = [
        outbound
        for outbound in payload["outbounds"]
        if outbound.get("tag") not in {"proxy-wifi", "proxy-tcp"}
    ]
    payload["outbounds"] = [proxy_wi_fi, proxy_tcp, *rest]
    payload["routing"] = build_balanced_routing(route_mode, fallback_tag="proxy-wifi")
    payload["remarks"] = f"{payload.get('remarks') or subscription_id} Wi-Fi first"
    meta = payload.get("meta")
    if isinstance(meta, dict):
        meta["serverDescription"] = "Auto test: Wi-Fi first"
    observatory = payload.get("observatory")
    if isinstance(observatory, dict):
        observatory["probeInterval"] = "15s"
    return payload


def fetch_fi_internal_fragment(subscription_id: str) -> list[dict[str, Any]]:
    import urllib.request
    import json
    fi_host = os.environ.get("FI_STANDBY_HOST", "fi.silentconnect.net")  # PLACEHOLDER
    secret_segment = os.environ.get("SECRET_SEGMENT", "secret-sub")  # PLACEHOLDER
    url = f"https://{fi_host}/{secret_segment}/internal-fragment/{subscription_id}"
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={
        "X-Internal-Secret": INTERNAL_SECRET,
        "Host": fi_host
    })
    try:
        with urllib.request.urlopen(req, timeout=3.5, context=ctx) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode('utf-8'))
                if isinstance(data, list):
                    return data
    except Exception as e:
        LOGGER.warning(f"Failed to fetch FI internal fragment for {subscription_id}: {e}")
    return []

def dump_clash_yaml(doc: dict[str, Any]) -> str:
    try:
        import yaml
        return yaml.dump(doc, allow_unicode=True, sort_keys=False, default_flow_style=False)
    except Exception:
        pass

    def _dump_item(obj: Any, indent: int = 0) -> str:
        ind = "  " * indent
        if isinstance(obj, dict):
            lines = []
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    lines.append(f"{ind}{k}:")
                    lines.append(_dump_item(v, indent + 1))
                elif isinstance(v, bool):
                    lines.append(f"{ind}{k}: {'true' if v else 'false'}")
                elif isinstance(v, (int, float)):
                    lines.append(f"{ind}{k}: {v}")
                elif v is None:
                    lines.append(f"{ind}{k}: null")
                else:
                    s = str(v)
                    if any(c in s for c in ":#{}[]|>&*!%@`,'\"") or s.strip() != s or s.lower() in ("true", "false", "yes", "no", "null", "on", "off"):
                        lines.append(f'{ind}{k}: "{s}"')
                    else:
                        lines.append(f"{ind}{k}: {s}")
            return "\n".join(lines)
        elif isinstance(obj, list):
            lines = []
            for item in obj:
                if isinstance(item, dict):
                    first = True
                    for k, v in item.items():
                        prefix = f"{ind}- " if first else f"{ind}  "
                        first = False
                        if isinstance(v, (dict, list)):
                            lines.append(f"{prefix}{k}:")
                            lines.append(_dump_item(v, indent + 2))
                        elif isinstance(v, bool):
                            lines.append(f"{prefix}{k}: {'true' if v else 'false'}")
                        elif isinstance(v, (int, float)):
                            lines.append(f"{prefix}{k}: {v}")
                        elif v is None:
                            lines.append(f"{prefix}{k}: null")
                        else:
                            s = str(v)
                            if any(c in s for c in ":#{}[]|>&*!%@`,'\"") or s.strip() != s or s.lower() in ("true", "false", "yes", "no", "null", "on", "off"):
                                lines.append(f'{prefix}{k}: "{s}"')
                            else:
                                lines.append(f"{prefix}{k}: {s}")
                else:
                    s = str(item)
                    if any(c in s for c in ":#{}[]|>&*!%@`,'\"") or s.strip() != s or s.lower() in ("true", "false", "yes", "no", "null", "on", "off"):
                        lines.append(f'{ind}- "{s}"')
                    else:
                        lines.append(f"{ind}- {s}")
            return "\n".join(lines)
        return f"{ind}{obj}"

    return _dump_item(doc)


def build_singbox_smart_config(
    subscription_id: str,
    public_host: str = "",
    route_mode: str = "split-ru",
    dns_preset: str = "default",
    tag_style: str | None = None,
) -> dict[str, Any]:
    try:
        row, _, _, _, client = find_subscription(subscription_id)
        email = client.get("email") or subscription_id
        client_uuid = client.get("id") or subscription_id
    except Exception:
        email = subscription_id
        client_uuid = subscription_id

    summary = subscription_summary(subscription_id)
    if summary.get("status_kind") != "active":
        expired_dummy = build_expired_dummy_profile(email)
        return expired_dummy[0] if isinstance(expired_dummy, list) else expired_dummy

    fi_xhttp_pbk = FI_XHTTP_REALITY_PUBLIC_KEY
    fi_xhttp_sid = FI_XHTTP_REALITY_SHORT_ID
    nl_edge = os.environ.get("WS443_PUBLIC_HOST", "edge.silentconnect.net")  # PLACEHOLDER
    nl_sub = os.environ.get("PUBLIC_HOST", "sub.example.com")
    fi_edge = os.environ.get("FI_STANDBY_HOST", "fi.silentconnect.net")  # PLACEHOLDER

    outbounds = [
        # --- Tier 1: Parent Selector ---
        {
            "type": "selector",
            "tag": "proxy-selector",
            "outbounds": [
                "auto-urltest",
                "nl-classic-tcp",
                "nl-fast-tcp",
                "nl-speed-hysteria2",
                "nl-backup-grpc",
                "nl-stealth-xhttp",
                "fi-classic-tcp",
                "fi-fast-tcp",
                "fi-speed-hysteria2",
                "fi-backup-grpc",
                "fi-stealth-xhttp",
                "nl-ws443",
                "fi-ws443",
                "direct",
            ],
            "default": "auto-urltest",
        },
        # --- Tier 2: Auto URL-Test Pool ---
        {
            "type": "urltest",
            "tag": "auto-urltest",
            "outbounds": [
                "nl-classic-tcp",
                "nl-fast-tcp",
                "nl-speed-hysteria2",
                "nl-backup-grpc",
                "nl-stealth-xhttp",
                "fi-classic-tcp",
                "fi-fast-tcp",
                "fi-speed-hysteria2",
                "fi-backup-grpc",
                "fi-stealth-xhttp",
            ],
            "url": "https://cp.cloudflare.com/generate_204",
            "interval": "3m",
            "idle_timeout": "15m",
            "tolerance": 50,
            "interrupt_exist_connections": False,
        },
        # --- NL Protocol Nodes ---
        {
            "type": "vless",
            "tag": "nl-classic-tcp",
            "server": nl_edge,
            "server_port": 443,
            "uuid": client_uuid,
            "flow": "xtls-rprx-vision",
            "tls": {
                "enabled": True,
                "server_name": TCP_REALITY_SNI_CLASSIC,
                "utls": {"enabled": True, "fingerprint": "chrome"},
                "reality": {
                    "enabled": True,
                    "public_key": TCP_REALITY_PUBLIC_KEY,
                    "short_id": TCP_REALITY_SHORT_ID,
                },
            },
            "packet_encoding": "xudp",
        },
        {
            "type": "vless",
            "tag": "nl-fast-tcp",
            "server": nl_edge,
            "server_port": 443,
            "uuid": client_uuid,
            "flow": "xtls-rprx-vision",
            "tls": {
                "enabled": True,
                "server_name": TCP_REALITY_SNI_FAST,
                "utls": {"enabled": True, "fingerprint": "chrome"},
                "reality": {
                    "enabled": True,
                    "public_key": TCP_REALITY_PUBLIC_KEY,
                    "short_id": TCP_REALITY_SHORT_ID,
                },
            },
            "packet_encoding": "xudp",
        },
        {
            "type": "hysteria2",
            "tag": "nl-speed-hysteria2",
            "server": nl_sub,
            "server_ports": ["30000:40000"],
            "hop_interval": "30s",
            "password": client_uuid,
            "tls": {
                "enabled": True,
                "server_name": nl_sub,
                "alpn": ["h3"],
            },
            "obfs": {
                "type": "gecko",
                "password": HYSTERIA_SALAMANDER_PASSWORD,
                "min_packet_size": 512,
                "max_packet_size": 1000,
            },
        },
        {
            "type": "vless",
            "tag": "nl-backup-grpc",
            "server": nl_edge,
            "server_port": 29443,
            "uuid": client_uuid,
            "transport": {
                "type": "grpc",
                "service_name": GRPC_SERVICE_NAME,
                "idle_timeout": "15s",
                "ping_timeout": "15s",
            },
            "tls": {
                "enabled": True,
                "server_name": GRPC_REALITY_SNI,
                "utls": {"enabled": True, "fingerprint": "chrome"},
                "reality": {
                    "enabled": True,
                    "public_key": GRPC_REALITY_PUBLIC_KEY,
                    "short_id": GRPC_REALITY_SHORT_ID,
                },
            },
            "packet_encoding": "xudp",
        },
        {
            "type": "vless",
            "tag": "nl-stealth-xhttp",
            "server": nl_edge,
            "server_port": 443,
            "uuid": client_uuid,
            "transport": {
                "type": "http",
                "host": [nl_edge],
                "path": "/xh-mx-d1f7c0429d6a",
                "method": "POST",
            },
            "tls": {
                "enabled": True,
                "server_name": nl_edge,
                "alpn": ["h2", "http/1.1"],
                "utls": {"enabled": True, "fingerprint": "chrome"},
            },
            "packet_encoding": "xudp",
        },
        # --- FI Protocol Nodes ---
        {
            "type": "vless",
            "tag": "fi-classic-tcp",
            "server": fi_edge,
            "server_port": 443,
            "uuid": client_uuid,
            "flow": "xtls-rprx-vision",
            "tls": {
                "enabled": True,
                "server_name": FI_REALITY_SNI_CLASSIC,
                "utls": {"enabled": True, "fingerprint": "chrome"},
                "reality": {
                    "enabled": True,
                    "public_key": TCP_REALITY_PUBLIC_KEY,
                    "short_id": TCP_REALITY_SHORT_ID,
                },
            },
            "packet_encoding": "xudp",
        },
        {
            "type": "vless",
            "tag": "fi-fast-tcp",
            "server": fi_edge,
            "server_port": 443,
            "uuid": client_uuid,
            "flow": "xtls-rprx-vision",
            "tls": {
                "enabled": True,
                "server_name": FI_REALITY_SNI_FAST,
                "utls": {"enabled": True, "fingerprint": "chrome"},
                "reality": {
                    "enabled": True,
                    "public_key": TCP_REALITY_PUBLIC_KEY,
                    "short_id": TCP_REALITY_SHORT_ID,
                },
            },
            "packet_encoding": "xudp",
        },
        {
            "type": "hysteria2",
            "tag": "fi-speed-hysteria2",
            "server": fi_edge,
            "server_ports": ["30000:40000"],
            "hop_interval": "30s",
            "password": client_uuid,
            "tls": {
                "enabled": True,
                "server_name": fi_edge,
                "alpn": ["h3"],
            },
            "obfs": {
                "type": "gecko",
                "password": HYSTERIA_SALAMANDER_PASSWORD,
                "min_packet_size": 512,
                "max_packet_size": 1000,
            },
        },
        {
            "type": "vless",
            "tag": "fi-backup-grpc",
            "server": fi_edge,
            "server_port": 443,
            "uuid": client_uuid,
            "transport": {
                "type": "grpc",
                "service_name": GRPC_SERVICE_NAME,
                "idle_timeout": "15s",
                "ping_timeout": "15s",
            },
            "tls": {
                "enabled": True,
                "server_name": FI_GRPC_REALITY_SNI,
                "utls": {"enabled": True, "fingerprint": "chrome"},
                "reality": {
                    "enabled": True,
                    "public_key": GRPC_REALITY_PUBLIC_KEY,
                    "short_id": GRPC_REALITY_SHORT_ID,
                },
            },
            "packet_encoding": "xudp",
        },
        {
            "type": "vless",
            "tag": "fi-stealth-xhttp",
            "server": fi_edge,
            "server_port": FI_XHTTP_REALITY_PORT,
            "uuid": client_uuid,
            "transport": {
                "type": "http",
                "host": [fi_edge],
                "path": "/xh-mx-d1f7c0429d6a",
                "method": "POST",
            },
            "tls": {
                "enabled": True,
                "server_name": FI_XHTTP_REALITY_SNI,
                "utls": {"enabled": True, "fingerprint": "chrome"},
                "reality": {
                    "enabled": True,
                    "public_key": fi_xhttp_pbk,
                    "short_id": fi_xhttp_sid,
                },
            },
            "packet_encoding": "xudp",
        },
        # --- Fallback Nodes ---
        {
            "type": "vless",
            "tag": "nl-ws443",
            "server": nl_sub,
            "server_port": 443,
            "uuid": client_uuid,
            "transport": {
                "type": "ws",
                "path": WS443_PATH,
                "headers": {"Host": nl_sub},
            },
            "tls": {
                "enabled": True,
                "server_name": nl_sub,
                "utls": {"enabled": True, "fingerprint": "chrome"},
            },
            "packet_encoding": "xudp",
        },
        {
            "type": "vless",
            "tag": "fi-ws443",
            "server": fi_edge,
            "server_port": 443,
            "uuid": client_uuid,
            "transport": {
                "type": "ws",
                "path": WS443_PATH,
                "headers": {"Host": fi_edge},
            },
            "tls": {
                "enabled": True,
                "server_name": fi_edge,
                "utls": {"enabled": True, "fingerprint": "chrome"},
            },
            "packet_encoding": "xudp",
        },
        {"type": "direct", "tag": "direct"},
    ]

    route_rules = [
        {"action": "sniff"},
        {"protocol": "dns", "action": "hijack-dns"},
        {
            "domain": [
                "sub.silentconnect.net",  # PLACEHOLDER
                "edge.silentconnect.net",  # PLACEHOLDER
                "fi.silentconnect.net",  # PLACEHOLDER
            ],
            "outbound": "direct",
        },
        {"ip_is_private": True, "outbound": "direct"},
        {"protocol": "bittorrent", "outbound": "direct"},
    ]
    if route_mode == "split-ru":
        route_rules.extend([
            {
                "domain_suffix": [
                    "ru", "su", "xn--p1ai", "gosuslugi.ru", "sberbank.ru",
                    "tinkoff.ru", "yandex.ru", "vk.com", "avito.ru", "ozon.ru",
                    "wildberries.ru", "railnation.ru", "railnation-game.ru",
                    "silentconnect.net",  # PLACEHOLDER
                ],
                "outbound": "direct",
            },
        ])

    pl_edge = os.environ.get("PL_STANDBY_HOST", PL_STANDBY_HOST).strip()
    if pl_edge:
        for ob_group in outbounds:
            if ob_group.get("tag") == "proxy-selector":
                idx = ob_group["outbounds"].index("nl-ws443") if "nl-ws443" in ob_group["outbounds"] else len(ob_group["outbounds"])
                ob_group["outbounds"][idx:idx] = [
                    "pl-classic-tcp",
                    "pl-fast-tcp",
                    "pl-speed-hysteria2",
                    "pl-backup-grpc",
                    "pl-stealth-xhttp",
                ]
            elif ob_group.get("tag") == "auto-urltest":
                ob_group["outbounds"].extend([
                    "pl-classic-tcp",
                    "pl-fast-tcp",
                    "pl-speed-hysteria2",
                    "pl-backup-grpc",
                    "pl-stealth-xhttp",
                ])

        direct_idx = next((i for i, ob in enumerate(outbounds) if ob.get("tag") == "direct"), len(outbounds))
        pl_obs = [
            {
                "type": "vless",
                "tag": "pl-classic-tcp",
                "server": pl_edge,
                "server_port": 443,
                "uuid": client_uuid,
                "flow": "xtls-rprx-vision",
                "tls": {
                    "enabled": True,
                    "server_name": PL_REALITY_SNI_CLASSIC,
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "reality": {
                        "enabled": True,
                        "public_key": PL_REALITY_PUBLIC_KEY,
                        "short_id": PL_REALITY_SHORT_ID,
                    },
                },
                "packet_encoding": "xudp",
            },
            {
                "type": "vless",
                "tag": "pl-fast-tcp",
                "server": pl_edge,
                "server_port": 443,
                "uuid": client_uuid,
                "flow": "xtls-rprx-vision",
                "tls": {
                    "enabled": True,
                    "server_name": PL_REALITY_SNI_FAST,
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "reality": {
                        "enabled": True,
                        "public_key": PL_REALITY_PUBLIC_KEY,
                        "short_id": PL_REALITY_SHORT_ID,
                    },
                },
                "packet_encoding": "xudp",
            },
            {
                "type": "hysteria2",
                "tag": "pl-speed-hysteria2",
                "server": pl_edge,
                "server_ports": ["30000:40000"],
                "hop_interval": "30s",
                "password": client_uuid,
                "tls": {
                    "enabled": True,
                    "server_name": pl_edge,
                    "alpn": ["h3"],
                },
                "obfs": {
                    "type": "gecko",
                    "password": HYSTERIA_SALAMANDER_PASSWORD,
                    "min_packet_size": 512,
                    "max_packet_size": 1000,
                },
            },
            {
                "type": "vless",
                "tag": "pl-backup-grpc",
                "server": pl_edge,
                "server_port": 29443,
                "uuid": client_uuid,
                "transport": {
                    "type": "grpc",
                    "service_name": GRPC_SERVICE_NAME,
                },
                "tls": {
                    "enabled": True,
                    "server_name": PL_REALITY_SNI_CLASSIC,
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "reality": {
                        "enabled": True,
                        "public_key": PL_REALITY_PUBLIC_KEY,
                        "short_id": PL_REALITY_SHORT_ID,
                    },
                },
                "packet_encoding": "xudp",
            },
            {
                "type": "vless",
                "tag": "pl-stealth-xhttp",
                "server": pl_edge,
                "server_port": PL_XHTTP_REALITY_PORT,
                "uuid": client_uuid,
                "transport": {
                    "type": "http",
                    "path": "/xh-7m2q9r4k1v8p3s6",
                },
                "tls": {
                    "enabled": True,
                    "server_name": PL_REALITY_SNI_CLASSIC,
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "reality": {
                        "enabled": True,
                        "public_key": PL_REALITY_PUBLIC_KEY,
                        "short_id": PL_REALITY_SHORT_ID,
                    },
                },
                "packet_encoding": "xudp",
            },
        ]
        outbounds[direct_idx:direct_idx] = pl_obs

    if tag_style is None:
        tag_style = os.environ.get("SINGBOX_TAG_STYLE", "legacy")

    if tag_style == "happ":
        happ_tag_map = {
            "auto-urltest": "⚡ Авто-выбор (Лучший пинг)",
            "nl-classic-tcp": "🇳🇱 Classic (TCP Reality)",
            "nl-fast-tcp": "🇳🇱 Fast (TCP Reality)",
            "nl-speed-hysteria2": "🇳🇱 Скоростной (Hysteria 2)",
            "nl-backup-grpc": "🇳🇱 Резерв (gRPC)",
            "nl-stealth-xhttp": "🇳🇱 Стелс (XHTTP)",
            "fi-classic-tcp": "🇫🇮 Classic (TCP Reality)",
            "fi-fast-tcp": "🇫🇮 Fast (TCP Reality)",
            "fi-speed-hysteria2": "🇫🇮 Скоростной (Hysteria 2)",
            "fi-backup-grpc": "🇫🇮 Резерв (gRPC)",
            "fi-stealth-xhttp": "🇫🇮 Стелс (XHTTP)",
            "pl-classic-tcp": "🇵🇱 Classic (TCP Reality)",
            "pl-fast-tcp": "🇵🇱 Fast (TCP Reality)",
            "pl-speed-hysteria2": "🇵🇱 Скоростной (Hysteria 2)",
            "pl-backup-grpc": "🇵🇱 Резерв (gRPC)",
            "pl-stealth-xhttp": "🇵🇱 Стелс (XHTTP)",
            "nl-ws443": "🇳🇱 Резерв (WebSocket)",
            "fi-ws443": "🇫🇮 Резерв (WebSocket)",
            "direct": "🎯 Прямой трафик (Direct)",
        }
        for ob in outbounds:
            if "tag" in ob:
                ob["tag"] = happ_tag_map.get(ob["tag"], ob["tag"])
            if "outbounds" in ob and isinstance(ob["outbounds"], list):
                ob["outbounds"] = [happ_tag_map.get(t, t) for t in ob["outbounds"]]
            if "default" in ob and ob["default"] in happ_tag_map:
                ob["default"] = happ_tag_map[ob["default"]]
        for rule in route_rules:
            if "outbound" in rule and rule["outbound"] in happ_tag_map:
                rule["outbound"] = happ_tag_map[rule["outbound"]]

    meta = build_happ_config_meta(subscription_id)
    if meta is None:
        meta = {}
    meta["serverDescription"] = "✨ Умный автовыбор узла · 0ms переключение"

    config = {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": [
                {
                    "tag": "dns-remote",
                    "type": "https",
                    "server": "1.1.1.1",
                    "detour": "proxy-selector",
                },
                {
                    "tag": "dns-direct",
                    "type": "udp",
                    "server": "77.88.8.8",
                },
            ],
            "rules": [
                {
                    "domain": [
                        "sub.silentconnect.net",  # PLACEHOLDER
                        "edge.silentconnect.net",  # PLACEHOLDER
                        "fi.silentconnect.net",  # PLACEHOLDER
                    ],
                    "server": "dns-direct",
                },
                {
                    "domain_suffix": [
                        "ru", "su", "xn--p1ai", "yandex.ru", "vk.com", "gosuslugi.ru", "silentconnect.net",  # PLACEHOLDER
                    ],
                    "server": "dns-direct",
                },
            ],
            "final": "dns-remote",
            "strategy": "prefer_ipv4",
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "sing-tun",
                "address": ["172.19.0.1/30"],
                "auto_route": True,
                "strict_route": True,
                "stack": "mixed",
            }
        ],
        "outbounds": outbounds,
        "route": {
            "default_domain_resolver": "dns-direct",
            "auto_detect_interface": True,
            "rules": route_rules,
            "final": "proxy-selector",
        },
        "experimental": {
            "cache_file": {
                "enabled": True,
            }
        },
    }
    return config


def build_clash_meta_config(
    subscription_id: str,
    public_host: str = "",
    route_mode: str = "split-ru",
) -> str:
    try:
        row, _, _, _, client = find_subscription(subscription_id)
        email = client.get("email") or subscription_id
        client_uuid = client.get("id") or subscription_id
    except Exception:
        email = subscription_id
        client_uuid = subscription_id

    summary = subscription_summary(subscription_id)
    if summary.get("status_kind") != "active":
        expired_doc = {
            "port": 7890,
            "socks-port": 7891,
            "mode": "direct",
            "log-level": "warning",
            "proxies": [],
            "proxy-groups": [{"name": "🚀 PROXY", "type": "select", "proxies": ["DIRECT"]}],
            "rules": ["MATCH,DIRECT"],
        }
        return dump_clash_yaml(expired_doc)

    nl_edge = os.environ.get("WS443_PUBLIC_HOST", "edge.silentconnect.net")  # PLACEHOLDER
    nl_sub = os.environ.get("PUBLIC_HOST", "sub.example.com")
    fi_edge = os.environ.get("FI_STANDBY_HOST", "fi.silentconnect.net")  # PLACEHOLDER

    tcp_pk = TCP_REALITY_PUBLIC_KEY
    tcp_sid = TCP_REALITY_SHORT_ID
    grpc_pk = GRPC_REALITY_PUBLIC_KEY
    grpc_sid = GRPC_REALITY_SHORT_ID
    fi_xhttp_pk = FI_XHTTP_REALITY_PUBLIC_KEY
    fi_xhttp_sid = FI_XHTTP_REALITY_SHORT_ID
    salamander_pwd = HYSTERIA_SALAMANDER_PASSWORD

    proxies = [
        {
            "name": "🇳🇱 NL Classic Reality TCP",
            "type": "vless",
            "server": nl_edge,
            "port": 443,
            "uuid": client_uuid,
            "network": "tcp",
            "flow": "xtls-rprx-vision",
            "tls": True,
            "servername": TCP_REALITY_SNI_CLASSIC,
            "reality-opts": {
                "public-key": tcp_pk,
                "short-id": tcp_sid,
            },
            "client-fingerprint": "chrome",
            "udp": True,
        },
        {
            "name": "🇳🇱 NL Fast Reality TCP",
            "type": "vless",
            "server": nl_edge,
            "port": 443,
            "uuid": client_uuid,
            "network": "tcp",
            "flow": "xtls-rprx-vision",
            "tls": True,
            "servername": TCP_REALITY_SNI_FAST,
            "reality-opts": {
                "public-key": tcp_pk,
                "short-id": tcp_sid,
            },
            "client-fingerprint": "chrome",
            "udp": True,
        },
        {
            "name": "🇳🇱 NL Speed Hysteria2",
            "type": "hysteria2",
            "server": nl_sub,
            "port": 443,
            "password": client_uuid,
            "sni": nl_sub,
            "alpn": ["h3"],
            "obfs": "gecko",
            "obfs-password": salamander_pwd,
            "udp": True,
        },
        {
            "name": "🇳🇱 NL Backup Reality gRPC",
            "type": "vless",
            "server": nl_edge,
            "port": 29443,
            "uuid": client_uuid,
            "network": "grpc",
            "tls": True,
            "servername": GRPC_REALITY_SNI,
            "reality-opts": {
                "public-key": grpc_pk,
                "short-id": grpc_sid,
            },
            "grpc-opts": {"grpc-service-name": GRPC_SERVICE_NAME},
            "client-fingerprint": "chrome",
            "udp": True,
        },
        {
            "name": "🇳🇱 NL Stealth XHTTP",
            "type": "vless",
            "server": nl_edge,
            "port": 443,
            "uuid": client_uuid,
            "network": "http",
            "tls": True,
            "servername": nl_edge,
            "http-opts": {
                "path": ["/xh-mx-d1f7c0429d6a"],
                "headers": {"Host": [nl_edge]},
            },
            "client-fingerprint": "chrome",
            "udp": True,
        },
        {
            "name": "🇫🇮 FI Classic Reality TCP",
            "type": "vless",
            "server": fi_edge,
            "port": 443,
            "uuid": client_uuid,
            "network": "tcp",
            "flow": "xtls-rprx-vision",
            "tls": True,
            "servername": TCP_REALITY_SNI_CLASSIC,
            "reality-opts": {
                "public-key": tcp_pk,
                "short-id": tcp_sid,
            },
            "client-fingerprint": "chrome",
            "udp": True,
        },
        {
            "name": "🇫🇮 FI Fast Reality TCP",
            "type": "vless",
            "server": fi_edge,
            "port": 443,
            "uuid": client_uuid,
            "network": "tcp",
            "flow": "xtls-rprx-vision",
            "tls": True,
            "servername": TCP_REALITY_SNI_FAST,
            "reality-opts": {
                "public-key": tcp_pk,
                "short-id": tcp_sid,
            },
            "client-fingerprint": "chrome",
            "udp": True,
        },
        {
            "name": "🇫🇮 FI Speed Hysteria2",
            "type": "hysteria2",
            "server": fi_edge,
            "port": 443,
            "password": client_uuid,
            "sni": fi_edge,
            "alpn": ["h3"],
            "obfs": "gecko",
            "obfs-password": salamander_pwd,
            "udp": True,
        },
        {
            "name": "🇫🇮 FI Backup Reality gRPC",
            "type": "vless",
            "server": fi_edge,
            "port": 443,
            "uuid": client_uuid,
            "network": "grpc",
            "tls": True,
            "servername": FI_GRPC_REALITY_SNI,
            "reality-opts": {
                "public-key": grpc_pk,
                "short-id": grpc_sid,
            },
            "grpc-opts": {"grpc-service-name": GRPC_SERVICE_NAME},
            "client-fingerprint": "chrome",
            "udp": True,
        },
        {
            "name": "🇫🇮 FI Stealth XHTTP Reality",
            "type": "vless",
            "server": fi_edge,
            "port": FI_XHTTP_REALITY_PORT,
            "uuid": client_uuid,
            "network": "http",
            "tls": True,
            "servername": FI_XHTTP_REALITY_SNI,
            "reality-opts": {
                "public-key": fi_xhttp_pk,
                "short-id": fi_xhttp_sid,
            },
            "http-opts": {"path": ["/xh-mx-d1f7c0429d6a"]},
            "client-fingerprint": "chrome",
            "udp": True,
        },
    ]

    pl_edge = os.environ.get("PL_STANDBY_HOST", PL_STANDBY_HOST).strip()
    if pl_edge:
        proxies.extend([
            {
                "name": "🇵🇱 PL Classic Reality TCP",
                "type": "vless",
                "server": pl_edge,
                "port": 443,
                "uuid": client_uuid,
                "network": "tcp",
                "flow": "xtls-rprx-vision",
                "tls": True,
                "servername": PL_REALITY_SNI_CLASSIC,
                "reality-opts": {
                    "public-key": PL_REALITY_PUBLIC_KEY,
                    "short-id": PL_REALITY_SHORT_ID,
                },
                "client-fingerprint": "chrome",
                "udp": True,
            },
            {
                "name": "🇵🇱 PL Fast Reality TCP",
                "type": "vless",
                "server": pl_edge,
                "port": 443,
                "uuid": client_uuid,
                "network": "tcp",
                "flow": "xtls-rprx-vision",
                "tls": True,
                "servername": PL_REALITY_SNI_FAST,
                "reality-opts": {
                    "public-key": PL_REALITY_PUBLIC_KEY,
                    "short-id": PL_REALITY_SHORT_ID,
                },
                "client-fingerprint": "chrome",
                "udp": True,
            },
            {
                "name": "🇵🇱 PL Speed Hysteria2",
                "type": "hysteria2",
                "server": pl_edge,
                "port": 443,
                "auth": client_uuid,
                "obfs": "gecko",
                "obfs-password": salamander_pwd,
                "sni": pl_edge,
                "skip-cert-verify": False,
                "udp": True,
            },
            {
                "name": "🇵🇱 PL Backup Reality gRPC",
                "type": "vless",
                "server": pl_edge,
                "port": 29443,
                "uuid": client_uuid,
                "network": "grpc",
                "tls": True,
                "servername": PL_REALITY_SNI_CLASSIC,
                "reality-opts": {
                    "public-key": PL_REALITY_PUBLIC_KEY,
                    "short-id": PL_REALITY_SHORT_ID,
                },
                "grpc-opts": {"grpc-service-name": GRPC_SERVICE_NAME},
                "client-fingerprint": "chrome",
                "udp": True,
            },
            {
                "name": "🇵🇱 PL Stealth XHTTP Reality",
                "type": "vless",
                "server": pl_edge,
                "port": PL_XHTTP_REALITY_PORT,
                "uuid": client_uuid,
                "network": "http",
                "tls": True,
                "servername": PL_REALITY_SNI_CLASSIC,
                "reality-opts": {
                    "public-key": PL_REALITY_PUBLIC_KEY,
                    "short-id": PL_REALITY_SHORT_ID,
                },
                "http-opts": {"path": ["/xh-7m2q9r4k1v8p3s6"]},
                "client-fingerprint": "chrome",
                "udp": True,
            },
        ])

    all_proxy_names = [p["name"] for p in proxies]

    proxy_groups = [
        {
            "name": "🚀 PROXY",
            "type": "select",
            "proxies": ["⚡ Auto URL-Test", "🛡️ Priority Fallback"] + all_proxy_names + ["DIRECT"],
        },
        {
            "name": "⚡ Auto URL-Test",
            "type": "url-test",
            "proxies": all_proxy_names,
            "url": "https://cp.cloudflare.com/generate_204",
            "interval": 180,
            "tolerance": 50,
            "lazy": True,
            "expected-status": "204",
        },
        {
            "name": "🛡️ Priority Fallback",
            "type": "fallback",
            "proxies": [
                "🇳🇱 NL Classic Reality TCP",
                "🇫🇮 FI Classic Reality TCP",
                "🇳🇱 NL Fast Reality TCP",
                "🇫🇮 FI Fast Reality TCP",
                "🇳🇱 NL Backup Reality gRPC",
                "🇫🇮 FI Backup Reality gRPC",
                "🇳🇱 NL Stealth XHTTP",
                "🇫🇮 FI Stealth XHTTP Reality",
                "🇳🇱 NL Speed Hysteria2",
                "🇫🇮 FI Speed Hysteria2",
            ],
            "url": "https://cp.cloudflare.com/generate_204",
            "interval": 180,
            "lazy": True,
            "expected-status": "204",
        },
    ]

    rules = []
    if route_mode == "split-ru":
        rules.extend([
            "GEOIP,PRIVATE,DIRECT",
            "GEOSITE,category-ads-all,REJECT",
            "GEOIP,RU,DIRECT",
            "DOMAIN-SUFFIX,ru,DIRECT",
            "DOMAIN-SUFFIX,su,DIRECT",
            "DOMAIN-SUFFIX,xn--p1ai,DIRECT",
            "DOMAIN-SUFFIX,gosuslugi.ru,DIRECT",
            "DOMAIN-SUFFIX,sberbank.ru,DIRECT",
            "DOMAIN-SUFFIX,tinkoff.ru,DIRECT",
            "DOMAIN-SUFFIX,railnation-game.ru,DIRECT",
        ])
    else:
        rules.extend([
            "GEOIP,PRIVATE,DIRECT",
            "GEOSITE,category-ads-all,REJECT",
        ])
    rules.append("MATCH,🚀 PROXY")

    doc = {
        "port": 7890,
        "socks-port": 7891,
        "mixed-port": 7892,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "unified-delay": True,
        "tcp-concurrent": True,
        "find-process-mode": "strict",
        "ipv6": False,
        "dns": {
            "enable": True,
            "listen": "127.0.0.1:1053",
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "nameserver": ["77.88.8.8", "8.8.8.8"],
            "fallback": ["https://1.1.1.1/dns-query", "https://dns.google/dns-query"],
            "fallback-filter": {
                "geoip": True,
                "geoip-code": "RU",
                "ipcidr": ["240.0.0.0/4"],
            },
        },
        "proxies": proxies,
        "proxy-groups": proxy_groups,
        "rules": rules,
    }

    return dump_clash_yaml(doc)


def build_streisand_bundle(
    subscription_id: str,
    public_host: str = "",
) -> str:
    try:
        row, _, _, _, client = find_subscription(subscription_id)
        email = client.get("email") or subscription_id
        client_uuid = str(client.get("id") or subscription_id)
    except Exception:
        email = subscription_id
        client_uuid = str(subscription_id)

    summary = subscription_summary(subscription_id)
    if summary.get("status_kind") != "active":
        return base64.b64encode(b"").decode("ascii")

    nl_edge = os.environ.get("WS443_PUBLIC_HOST", "edge.silentconnect.net")  # PLACEHOLDER
    nl_sub = os.environ.get("PUBLIC_HOST", "sub.example.com")
    fi_edge = os.environ.get("FI_STANDBY_HOST", "fi.silentconnect.net")  # PLACEHOLDER

    tcp_pk = TCP_REALITY_PUBLIC_KEY
    tcp_sid = TCP_REALITY_SHORT_ID
    grpc_pk = GRPC_REALITY_PUBLIC_KEY
    grpc_sid = GRPC_REALITY_SHORT_ID
    fi_xhttp_pk = FI_XHTTP_REALITY_PUBLIC_KEY
    fi_xhttp_sid = FI_XHTTP_REALITY_SHORT_ID
    salamander_pwd = HYSTERIA_SALAMANDER_PASSWORD

    uris = [
        f"vless://{client_uuid}@{nl_edge}:443?type=tcp&security=reality&pbk={tcp_pk}&fp=chrome&sni={TCP_REALITY_SNI_CLASSIC}&sid={tcp_sid}&flow=xtls-rprx-vision#{urllib.parse.quote('🇳🇱 1. Классический TCP (NL)')}",
        f"vless://{client_uuid}@{nl_edge}:443?type=tcp&security=reality&pbk={tcp_pk}&fp=chrome&sni={TCP_REALITY_SNI_FAST}&sid={tcp_sid}&flow=xtls-rprx-vision#{urllib.parse.quote('🇳🇱 2. Быстрый TCP (NL)')}",
        f"hy2://{client_uuid}@{nl_sub}:443?sni={nl_sub}&alpn=h3&obfs=gecko&obfs-password={salamander_pwd}#{urllib.parse.quote('🇳🇱 3. Скоростной Hysteria2 (NL)')}",
        f"vless://{client_uuid}@{nl_edge}:29443?type=grpc&security=reality&pbk={grpc_pk}&fp=chrome&sni={GRPC_REALITY_SNI}&sid={grpc_sid}&serviceName={GRPC_SERVICE_NAME}#{urllib.parse.quote('🇳🇱 4. Запасной gRPC (NL)')}",
        f"vless://{client_uuid}@{nl_edge}:443?type=xhttp&security=tls&sni={nl_edge}&alpn=h2,http/1.1&path=%2Fxh-mx-d1f7c0429d6a&mode=packet-up#{urllib.parse.quote('🇳🇱 5. Незаметный XHTTP (NL)')}",
        f"vless://{client_uuid}@{fi_edge}:443?type=tcp&security=reality&pbk={tcp_pk}&fp=chrome&sni={TCP_REALITY_SNI_CLASSIC}&sid={tcp_sid}&flow=xtls-rprx-vision#{urllib.parse.quote('🇫🇮 6. Классический TCP (FI)')}",
        f"vless://{client_uuid}@{fi_edge}:443?type=tcp&security=reality&pbk={tcp_pk}&fp=chrome&sni={TCP_REALITY_SNI_FAST}&sid={tcp_sid}&flow=xtls-rprx-vision#{urllib.parse.quote('🇫🇮 7. Быстрый TCP (FI)')}",
        f"hy2://{client_uuid}@{fi_edge}:443?sni={fi_edge}&alpn=h3&obfs=gecko&obfs-password={salamander_pwd}#{urllib.parse.quote('🇫🇮 8. Скоростной Hysteria2 (FI)')}",
        f"vless://{client_uuid}@{fi_edge}:443?type=grpc&security=reality&pbk={grpc_pk}&fp=chrome&sni={FI_GRPC_REALITY_SNI}&sid={grpc_sid}&serviceName={GRPC_SERVICE_NAME}#{urllib.parse.quote('🇫🇮 9. Запасной gRPC (FI)')}",
        f"vless://{client_uuid}@{fi_edge}:{FI_XHTTP_REALITY_PORT}?type=xhttp&security=reality&pbk={fi_xhttp_pk}&fp=chrome&sni={FI_XHTTP_REALITY_SNI}&sid={fi_xhttp_sid}&path=%2Fxh-mx-d1f7c0429d6a&mode=packet-up#{urllib.parse.quote('🇫🇮 10. Незаметный XHTTP Reality (FI)')}",
    ]
    pl_edge = os.environ.get("PL_STANDBY_HOST", PL_STANDBY_HOST).strip()
    if pl_edge:
        uris.extend([
            f"vless://{client_uuid}@{pl_edge}:443?type=tcp&security=reality&pbk={PL_REALITY_PUBLIC_KEY}&fp=chrome&sni={PL_REALITY_SNI_CLASSIC}&sid={PL_REALITY_SHORT_ID}&flow=xtls-rprx-vision#{urllib.parse.quote('🇵🇱 11. Классический TCP (PL)')}",
            f"vless://{client_uuid}@{pl_edge}:443?type=tcp&security=reality&pbk={PL_REALITY_PUBLIC_KEY}&fp=chrome&sni={PL_REALITY_SNI_FAST}&sid={PL_REALITY_SHORT_ID}&flow=xtls-rprx-vision#{urllib.parse.quote('🇵🇱 12. Быстрый TCP (PL)')}",
            f"hy2://{client_uuid}@{pl_edge}:443?sni={pl_edge}&alpn=h3&obfs=gecko&obfs-password={salamander_pwd}#{urllib.parse.quote('🇵🇱 13. Скоростной Hysteria2 (PL)')}",
            f"vless://{client_uuid}@{pl_edge}:29443?type=grpc&security=reality&pbk={PL_REALITY_PUBLIC_KEY}&fp=chrome&sni={PL_REALITY_SNI_CLASSIC}&sid={PL_REALITY_SHORT_ID}&serviceName={GRPC_SERVICE_NAME}#{urllib.parse.quote('🇵🇱 14. Запасной gRPC (PL)')}",
            f"vless://{client_uuid}@{pl_edge}:{PL_XHTTP_REALITY_PORT}?type=xhttp&security=reality&pbk={PL_REALITY_PUBLIC_KEY}&fp=chrome&sni={PL_REALITY_SNI_CLASSIC}&sid={PL_REALITY_SHORT_ID}&path=%2Fxh-7m2q9r4k1v8p3s6&mode=packet-up#{urllib.parse.quote('🇵🇱 15. Незаметный XHTTP Reality (PL)')}",
        ])

    raw_bundle = "\n".join(uris)
    return base64.b64encode(raw_bundle.encode("utf-8")).decode("ascii")


def build_xray_auto_balancer_profile(
    subscription_id: str,
    public_host: str,
    route_mode: str = "split-ru",
    dns_preset: str = "default",
) -> dict[str, Any]:
    try:
        row, _, _, _, client = find_subscription(subscription_id)
        email = client.get("email") or subscription_id
        client_uuid = client.get("id") or subscription_id
    except Exception:
        email = subscription_id
        client_uuid = subscription_id

    summary = subscription_summary(subscription_id)
    if summary.get("status_kind") != "active":
        expired_dummy = build_expired_dummy_profile(email)
        return expired_dummy[0] if isinstance(expired_dummy, list) else expired_dummy

    nl_edge = os.environ.get("WS443_PUBLIC_HOST", "edge.silentconnect.net")  # PLACEHOLDER
    fi_edge = os.environ.get("FI_STANDBY_HOST", "fi.silentconnect.net")  # PLACEHOLDER

    nl_classic = {
        "protocol": "vless",
        "tag": "node-nl-classic",
        "streamSettings": {
            "network": "tcp",
            "realitySettings": {
                "fingerprint": "edge",
                "mldsa65Verify": "",
                "publicKey": TCP_REALITY_PUBLIC_KEY,
                "serverName": TCP_REALITY_SNI_CLASSIC,
                "shortId": TCP_REALITY_SHORT_ID,
                "show": False,
                "spiderX": "/"
            },
            "security": "reality",
            "tcpSettings": {"header": {"type": "none"}}
        },
        "settings": {
            "address": nl_edge,
            "encryption": "none",
            "flow": "xtls-rprx-vision",
            "id": client_uuid,
            "level": 8,
            "port": 443
        }
    }

    nl_fast = copy.deepcopy(nl_classic)
    nl_fast["tag"] = "node-nl-fast"
    nl_fast["streamSettings"]["realitySettings"]["serverName"] = TCP_REALITY_SNI_FAST

    nl_grpc = {
        "protocol": "vless",
        "tag": "node-nl-grpc",
        "settings": {
            "address": nl_edge,
            "encryption": "none",
            "flow": "",
            "id": client_uuid,
            "level": 8,
            "port": 29443
        },
        "streamSettings": {
            "network": "grpc",
            "security": "reality",
            "realitySettings": {
                "fingerprint": "edge",
                "mldsa65Verify": "",
                "publicKey": GRPC_REALITY_PUBLIC_KEY,
                "serverName": GRPC_REALITY_SNI,
                "shortId": GRPC_REALITY_SHORT_ID,
                "show": False,
                "spiderX": "/"
            },
            "grpcSettings": {
                "serviceName": GRPC_SERVICE_NAME,
                "multiMode": False
            }
        }
    }

    fi_classic = copy.deepcopy(nl_classic)
    fi_classic["tag"] = "node-fi-classic"
    fi_classic["settings"]["address"] = fi_edge

    fi_fast = copy.deepcopy(nl_fast)
    fi_fast["tag"] = "node-fi-fast"
    fi_fast["settings"]["address"] = fi_edge

    fi_grpc = copy.deepcopy(nl_grpc)
    fi_grpc["tag"] = "node-fi-grpc"
    fi_grpc["settings"]["address"] = fi_edge

    meta = build_happ_config_meta(subscription_id)
    if isinstance(meta, dict):
        meta["serverDescription"] = "Автовыбор · Самый быстрый и стабильный"

    return {
        "log": {"loglevel": "warning"},
        "dns": {
            "queryStrategy": "UseIPv4",
            "servers": copy.deepcopy(DNS_PRESETS[dns_preset]),
        },
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True, "userLevel": 8},
                "sniffing": {"destOverride": ["http", "tls", "quic"], "enabled": True},
                "tag": "socks"
            },
            {
                "listen": "127.0.0.1",
                "port": 10809,
                "protocol": "http",
                "settings": {"auth": "noauth", "userLevel": 8},
                "sniffing": {"destOverride": ["http", "tls", "quic"], "enabled": True},
                "tag": "http"
            }
        ],
        "observatory": {
            "subjectSelector": ["node-"],
            "probeUrl": "https://cp.cloudflare.com/generate_204",
            "probeInterval": "1m",
            "enableConcurrency": True
        },
        "outbounds": [
            nl_classic,
            nl_fast,
            nl_grpc,
            fi_classic,
            fi_fast,
            fi_grpc,
            {"protocol": "freedom", "tag": "direct", "settings": {}},
            {"protocol": "blackhole", "tag": "block", "settings": {}}
        ],
        "policy": {
            "levels": {"8": {"connIdle": 300, "downlinkOnly": 1, "handshake": 4, "uplinkOnly": 1}},
            "system": {"statsOutboundDownlink": True, "statsOutboundUplink": True}
        },
        "remarks": f"✨ Автоматический ({email})",
        "meta": meta,
        "routing": build_balanced_routing(route_mode, balancer_tag="auto-proxy", fallback_tag="node-nl-classic", selector=["node-"]),
        "stats": {}
    }


def build_four_profiles(
    subscription_id: str,
    public_host: str,
    route_mode: str = "split-ru",
    dns_preset: str = "default",
    *,
    enable_fragment: bool = False,
) -> list[dict[str, Any]]:
    try:
        row, _, _, _, client = find_subscription(subscription_id)
        email = client.get("email") or subscription_id
        client_uuid = client.get("id") or subscription_id
    except Exception:
        email = subscription_id
        client_uuid = subscription_id

    summary = subscription_summary(subscription_id)
    if summary.get("status_kind") != "active":
        return build_expired_dummy_profile(email)

    smart_cfg = build_xray_auto_balancer_profile(subscription_id, public_host, route_mode, dns_preset)

    nl_edge = os.environ.get("WS443_PUBLIC_HOST", "edge.silentconnect.net")  # PLACEHOLDER
    fi_edge = os.environ.get("FI_STANDBY_HOST", "fi.silentconnect.net")  # PLACEHOLDER

    # --- Profile 1: NL Sber.ru (Classic) ---
    sber_cfg = {
        "log": {"loglevel": "warning"},
        "dns": {
            "queryStrategy": "UseIPv4",
            "servers": copy.deepcopy(DNS_PRESETS[dns_preset]),
        },
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True, "userLevel": 8},
                "sniffing": {"destOverride": ["http", "tls", "quic"], "enabled": True},
                "tag": "socks"
            },
            {
                "listen": "127.0.0.1",
                "port": 10809,
                "protocol": "http",
                "settings": {"auth": "noauth", "userLevel": 8},
                "sniffing": {"destOverride": ["http", "tls", "quic"], "enabled": True},
                "tag": "http"
            }
        ],
        "outbounds": [
            {
                "protocol": "vless",
                "tag": "proxy",
                "streamSettings": {
                    "network": "tcp",
                    "realitySettings": {
                        "fingerprint": "edge",
                        "mldsa65Verify": "",
                        "publicKey": TCP_REALITY_PUBLIC_KEY,
                        "serverName": TCP_REALITY_SNI_CLASSIC,
                        "shortId": TCP_REALITY_SHORT_ID,
                        "show": False,
                        "spiderX": "/"
                    },
                    "security": "reality",
                    "tcpSettings": {
                        "header": {
                            "type": "none"
                        }
                    }
                },
                "settings": {
                    "address": nl_edge,
                    "encryption": "none",
                    "flow": "xtls-rprx-vision",
                    "id": client_uuid,
                    "level": 8,
                    "port": 443
                }
            },
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"}
        ],
        "policy": {
            "levels": {"8": {"connIdle": 300, "downlinkOnly": 1, "handshake": 4, "uplinkOnly": 1}},
            "system": {"statsOutboundDownlink": True, "statsOutboundUplink": True}
        },
        "remarks": f"🇳🇱 🛡️ Классический ({email})",
        "meta": build_happ_config_meta(subscription_id),
        "routing": build_routing(route_mode),
        "stats": {}
    }
    if sber_cfg["meta"]:
        sber_cfg["meta"]["serverDescription"] = "Классический · TCP Reality (NL)"

    # --- Profile 2: NL Kinopoisk (Fast) ---
    kino_cfg = copy.deepcopy(sber_cfg)
    kino_cfg["remarks"] = f"🇳🇱 ⚡ Быстрый ({email})"
    kino_cfg["outbounds"][0]["streamSettings"]["realitySettings"]["serverName"] = TCP_REALITY_SNI_FAST
    kino_cfg["meta"] = build_happ_config_meta(subscription_id)
    if kino_cfg["meta"]:
        kino_cfg["meta"]["serverDescription"] = "Быстрый · TCP Reality (NL)"

    # --- Profile 3: NL Hysteria 2 ---
    hyst_cfg = {
        "log": {"loglevel": "warning"},
        "dns": {
            "queryStrategy": "UseIPv4",
            "servers": copy.deepcopy(DNS_PRESETS[dns_preset]),
        },
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True, "userLevel": 8},
                "sniffing": {"destOverride": ["http", "tls", "quic"], "enabled": True},
                "tag": "socks"
            },
            {
                "listen": "127.0.0.1",
                "port": 10809,
                "protocol": "http",
                "settings": {"auth": "noauth", "userLevel": 8},
                "sniffing": {"destOverride": ["http", "tls", "quic"], "enabled": True},
                "tag": "http"
            }
        ],
        "outbounds": [
            {
                "protocol": "hysteria",
                "tag": "proxy",
                "obfs": {
                    "type": "gecko",
                    "password": HYSTERIA_SALAMANDER_PASSWORD,
                },
                "streamSettings": {
                    "finalmask": {
                        "udp": [
                            {"settings": {"password": HYSTERIA_SALAMANDER_PASSWORD}, "type": "gecko"}
                        ]
                    },
                    "hysteriaSettings": {
                        "auth": client_uuid,
                        "auth_str": client_uuid,
                        "authStr": client_uuid,
                        "password": client_uuid,
                        "obfs": {
                            "type": "gecko",
                            "password": HYSTERIA_SALAMANDER_PASSWORD,
                        },
                        "udpIdleTimeout": 60,
                        "version": 2,
                    },
                    "network": "hysteria",
                    "security": "tls",
                    "tlsSettings": {
                        "alpn": ["h3"],
                        "serverName": public_host,
                    },
                },
                "settings": {
                    "address": public_host,
                    "port": 443,
                    "version": 2,
                    "auth": client_uuid,
                    "auth_str": client_uuid,
                    "obfs": {
                        "type": "gecko",
                        "password": HYSTERIA_SALAMANDER_PASSWORD,
                    },
                },
            },
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"}
        ],
        "policy": {
            "levels": {"8": {"connIdle": 300, "downlinkOnly": 1, "handshake": 4, "uplinkOnly": 1}},
            "system": {"statsOutboundDownlink": True, "statsOutboundUplink": True}
        },
        "remarks": f"🇳🇱 🚀 Скоростной ({email})",
        "meta": build_happ_config_meta(subscription_id),
        "routing": build_routing(route_mode),
        "stats": {}
    }
    if hyst_cfg["meta"]:
        hyst_cfg["meta"]["serverDescription"] = "Скоростной · Hysteria 2 + UDP"

    # --- Profile 4: NL VLESS gRPC ---
    grpc_cfg = copy.deepcopy(sber_cfg)
    grpc_cfg["remarks"] = f"🇳🇱 🔐 Запасной ({email})"
    grpc_cfg["outbounds"][0]["settings"]["flow"] = ""
    grpc_cfg["outbounds"][0]["settings"]["port"] = 29443
    grpc_cfg["outbounds"][0]["streamSettings"]["network"] = "grpc"
    grpc_cfg["outbounds"][0]["streamSettings"]["grpcSettings"] = {
        "serviceName": GRPC_SERVICE_NAME,
        "multiMode": False
    }
    grpc_cfg["outbounds"][0]["streamSettings"]["security"] = "reality"
    grpc_cfg["outbounds"][0]["streamSettings"]["realitySettings"] = {
        "show": False,
        "fingerprint": "edge",
        "mldsa65Verify": "",
        "serverName": GRPC_REALITY_SNI,
        "publicKey": GRPC_REALITY_PUBLIC_KEY,
        "shortId": GRPC_REALITY_SHORT_ID,
        "spiderX": "/"
    }
    grpc_cfg["outbounds"][0]["streamSettings"].pop("tcpSettings", None)
    grpc_cfg["meta"] = build_happ_config_meta(subscription_id)
    if grpc_cfg["meta"]:
        grpc_cfg["meta"]["serverDescription"] = "Запасной · VLESS-gRPC-Reality (NL)"

    # --- Profile 5: NL VLESS XHTTP Reality ---
    xhttp_cfg = copy.deepcopy(sber_cfg)
    xhttp_cfg["remarks"] = f"🇳🇱 🌊 Незаметный ({email})"
    xhttp_cfg["outbounds"][0]["settings"]["flow"] = ""
    xhttp_cfg["outbounds"][0]["settings"]["port"] = int(os.environ.get("NL_XHTTP_REALITY_PORT", "39443"))
    xhttp_cfg["outbounds"][0]["streamSettings"]["network"] = "xhttp"
    xhttp_cfg["outbounds"][0]["streamSettings"].pop("tcpSettings", None)
    xhttp_cfg["outbounds"][0]["streamSettings"]["security"] = "reality"
    xhttp_cfg["outbounds"][0]["streamSettings"]["realitySettings"] = {
        "show": False,
        "fingerprint": "chrome",
        "serverName": TCP_REALITY_SNI_CLASSIC,
        "publicKey": TCP_REALITY_PUBLIC_KEY,
        "shortId": TCP_REALITY_SHORT_ID,
        "spiderX": "/",
    }
    xhttp_cfg["outbounds"][0]["streamSettings"]["xhttpSettings"] = {
        "path": "/xh-mx-d1f7c0429d6a",
        "mode": "packet-up"
    }
    xhttp_cfg["meta"] = build_happ_config_meta(subscription_id)
    if xhttp_cfg["meta"]:
        xhttp_cfg["meta"]["serverDescription"] = "Незаметный · VLESS-XHTTP-Reality (NL)"

    # --- Profile 6: FI Classic ---
    fi_sber = copy.deepcopy(sber_cfg)
    fi_sber["remarks"] = f"🇫🇮 🛡️ Классический ({email})"
    fi_sber["outbounds"][0]["settings"]["address"] = fi_edge
    fi_sber["outbounds"][0]["streamSettings"]["realitySettings"]["serverName"] = FI_REALITY_SNI_CLASSIC
    fi_sber["meta"] = build_happ_config_meta(subscription_id)
    if fi_sber["meta"]:
        fi_sber["meta"]["serverDescription"] = "Классический · TCP Reality (FI)"

    # --- Profile 7: FI Fast ---
    fi_kino = copy.deepcopy(kino_cfg)
    fi_kino["remarks"] = f"🇫🇮 ⚡ Быстрый ({email})"
    fi_kino["outbounds"][0]["settings"]["address"] = fi_edge
    fi_kino["outbounds"][0]["streamSettings"]["realitySettings"]["serverName"] = FI_REALITY_SNI_FAST
    fi_kino["meta"] = build_happ_config_meta(subscription_id)
    if fi_kino["meta"]:
        fi_kino["meta"]["serverDescription"] = "Быстрый · TCP Reality (FI)"

    # --- Profile 8: FI Hysteria 2 ---
    fi_hyst = copy.deepcopy(hyst_cfg)
    fi_hyst["remarks"] = f"🇫🇮 🚀 Скоростной ({email})"
    fi_hyst["outbounds"][0]["settings"]["address"] = fi_edge
    fi_hyst["outbounds"][0]["settings"]["port"] = 443
    fi_hyst["outbounds"][0]["streamSettings"]["tlsSettings"]["serverName"] = fi_edge
    fi_hyst["meta"] = build_happ_config_meta(subscription_id)
    if fi_hyst["meta"]:
        fi_hyst["meta"]["serverDescription"] = "Скоростной · Hysteria 2 + UDP (FI)"

    # --- Profile 9: FI VLESS gRPC ---
    fi_grpc = copy.deepcopy(grpc_cfg)
    fi_grpc["remarks"] = f"🇫🇮 🔐 Запасной ({email})"
    fi_grpc["outbounds"][0]["settings"]["address"] = fi_edge
    fi_grpc["outbounds"][0]["settings"]["port"] = 443
    fi_grpc["outbounds"][0]["streamSettings"]["realitySettings"]["serverName"] = FI_GRPC_REALITY_SNI
    fi_grpc["outbounds"][0]["streamSettings"]["realitySettings"]["shortId"] = "9a2f7c6d1e4b8a30"
    fi_grpc["meta"] = build_happ_config_meta(subscription_id)
    if fi_grpc["meta"]:
        fi_grpc["meta"]["serverDescription"] = "Запасной · VLESS-gRPC-Reality (FI)"

    # --- Profile 10: FI VLESS XHTTP Reality (Port 39443, Hetzner TSPU Bypass) ---
    fi_xhttp_pbk = FI_XHTTP_REALITY_PUBLIC_KEY
    fi_xhttp_sid = FI_XHTTP_REALITY_SHORT_ID

    fi_xhttp = copy.deepcopy(sber_cfg)
    fi_xhttp["remarks"] = f"🇫🇮 🌊 Незаметный ({email})"
    fi_xhttp["outbounds"][0]["settings"]["address"] = fi_edge
    fi_xhttp["outbounds"][0]["settings"]["port"] = FI_XHTTP_REALITY_PORT
    fi_xhttp["outbounds"][0]["settings"]["flow"] = ""
    fi_xhttp["outbounds"][0]["streamSettings"]["network"] = "xhttp"
    fi_xhttp["outbounds"][0]["streamSettings"].pop("tcpSettings", None)
    fi_xhttp["outbounds"][0]["streamSettings"]["security"] = "reality"
    fi_xhttp["outbounds"][0]["streamSettings"]["realitySettings"] = {
        "show": False,
        "fingerprint": "chrome",
        "mldsa65Verify": "",
        "serverName": FI_XHTTP_REALITY_SNI,
        "publicKey": fi_xhttp_pbk,
        "shortId": fi_xhttp_sid,
        "spiderX": "/"
    }
    fi_xhttp["outbounds"][0]["streamSettings"]["xhttpSettings"] = {
        "path": "/xh-mx-d1f7c0429d6a",
        "mode": "packet-up"
    }
    fi_xhttp["meta"] = build_happ_config_meta(subscription_id)
    if fi_xhttp["meta"]:
        fi_xhttp["meta"]["serverDescription"] = "Незаметный · VLESS-XHTTP Reality (FI)"

    profiles = [
        smart_cfg,
        sber_cfg,
        kino_cfg,
        hyst_cfg,
        grpc_cfg,
        xhttp_cfg,
        fi_sber,
        fi_kino,
        fi_hyst,
        fi_grpc,
        fi_xhttp,
    ]

    pl_edge = os.environ.get("PL_STANDBY_HOST", PL_STANDBY_HOST).strip()
    if pl_edge:
        # --- Profile 11: PL Classic ---
        pl_sber = copy.deepcopy(sber_cfg)
        pl_sber["remarks"] = f"🇵🇱 🛡️ Классический ({email})"
        pl_sber["outbounds"][0]["settings"]["address"] = pl_edge
        pl_sber["outbounds"][0]["streamSettings"]["realitySettings"]["publicKey"] = PL_REALITY_PUBLIC_KEY
        pl_sber["outbounds"][0]["streamSettings"]["realitySettings"]["shortId"] = PL_REALITY_SHORT_ID
        pl_sber["outbounds"][0]["streamSettings"]["realitySettings"]["serverName"] = PL_REALITY_SNI_CLASSIC
        pl_sber["meta"] = build_happ_config_meta(subscription_id)
        if pl_sber["meta"]:
            pl_sber["meta"]["serverDescription"] = "Классический · TCP Reality (PL)"

        # --- Profile 12: PL Fast ---
        pl_kino = copy.deepcopy(kino_cfg)
        pl_kino["remarks"] = f"🇵🇱 ⚡ Быстрый ({email})"
        pl_kino["outbounds"][0]["settings"]["address"] = pl_edge
        pl_kino["outbounds"][0]["streamSettings"]["realitySettings"]["publicKey"] = PL_REALITY_PUBLIC_KEY
        pl_kino["outbounds"][0]["streamSettings"]["realitySettings"]["shortId"] = PL_REALITY_SHORT_ID
        pl_kino["outbounds"][0]["streamSettings"]["realitySettings"]["serverName"] = PL_REALITY_SNI_FAST
        pl_kino["meta"] = build_happ_config_meta(subscription_id)
        if pl_kino["meta"]:
            pl_kino["meta"]["serverDescription"] = "Быстрый · TCP Reality (PL)"

        # --- Profile 13: PL Hysteria 2 ---
        pl_hyst = copy.deepcopy(hyst_cfg)
        pl_hyst["remarks"] = f"🇵🇱 🚀 Скоростной ({email})"
        pl_hyst["outbounds"][0]["settings"]["address"] = pl_edge
        pl_hyst["outbounds"][0]["streamSettings"]["tlsSettings"]["serverName"] = pl_edge
        pl_hyst["meta"] = build_happ_config_meta(subscription_id)
        if pl_hyst["meta"]:
            pl_hyst["meta"]["serverDescription"] = "Скоростной · Hysteria 2 + UDP (PL)"

        # --- Profile 14: PL VLESS gRPC ---
        pl_grpc = copy.deepcopy(grpc_cfg)
        pl_grpc["remarks"] = f"🇵🇱 🔐 Запасной ({email})"
        pl_grpc["outbounds"][0]["settings"]["address"] = pl_edge
        pl_grpc["outbounds"][0]["streamSettings"]["realitySettings"]["publicKey"] = PL_REALITY_PUBLIC_KEY
        pl_grpc["outbounds"][0]["streamSettings"]["realitySettings"]["shortId"] = PL_REALITY_SHORT_ID
        pl_grpc["outbounds"][0]["streamSettings"]["realitySettings"]["serverName"] = PL_REALITY_SNI_CLASSIC
        pl_grpc["meta"] = build_happ_config_meta(subscription_id)
        if pl_grpc["meta"]:
            pl_grpc["meta"]["serverDescription"] = "Запасной · VLESS-gRPC-Reality (PL)"

        # --- Profile 15: PL VLESS XHTTP Reality ---
        pl_xhttp = copy.deepcopy(sber_cfg)
        pl_xhttp["remarks"] = f"🇵🇱 🌊 Незаметный ({email})"
        pl_xhttp["outbounds"][0]["settings"]["address"] = pl_edge
        pl_xhttp["outbounds"][0]["settings"]["port"] = PL_XHTTP_REALITY_PORT
        pl_xhttp["outbounds"][0]["settings"]["flow"] = ""
        pl_xhttp["outbounds"][0]["streamSettings"]["network"] = "xhttp"
        pl_xhttp["outbounds"][0]["streamSettings"].pop("tcpSettings", None)
        pl_xhttp["outbounds"][0]["streamSettings"]["security"] = "reality"
        pl_xhttp["outbounds"][0]["streamSettings"]["realitySettings"] = {
            "show": False,
            "fingerprint": "chrome",
            "mldsa65Verify": "",
            "serverName": PL_REALITY_SNI_CLASSIC,
            "publicKey": PL_REALITY_PUBLIC_KEY,
            "shortId": PL_REALITY_SHORT_ID,
            "spiderX": "/"
        }
        pl_xhttp["outbounds"][0]["streamSettings"]["xhttpSettings"] = {
            "path": "/xh-7m2q9r4k1v8p3s6",
            "mode": "packet-up"
        }
        pl_xhttp["meta"] = build_happ_config_meta(subscription_id)
        if pl_xhttp["meta"]:
            pl_xhttp["meta"]["serverDescription"] = "Незаметный · VLESS-XHTTP Reality (PL)"

        profiles.extend([pl_sber, pl_kino, pl_hyst, pl_grpc, pl_xhttp])

    return profiles

def build_test_fp_profiles(
    subscription_id: str,
    public_host: str,
    route_mode: str = "split-ru",
    dns_preset: str = "default",
) -> list[dict[str, Any]]:
    try:
        row, _, _, _, client = find_subscription(subscription_id)
        email = client.get("email") or subscription_id
    except Exception:
        email = subscription_id

    profiles = []

    # 1. Direct Firefox FP
    firefox_direct = build_portable_client_config(subscription_id, public_host, route_mode, dns_preset, relay=False)
    firefox_direct["remarks"] = f"{email} NL TCP Firefox FP (Direct)"
    try:
        firefox_direct["outbounds"][0]["streamSettings"]["realitySettings"]["fingerprint"] = "firefox"
    except (KeyError, IndexError):
        pass
    if isinstance(firefox_direct.get("meta"), dict):
        firefox_direct["meta"]["serverDescription"] = "NL TCP (Firefox FP Direct)"
        firefox_direct["meta"]["sub-info-text"] = "Фингерпринт Firefox, прямой порт 24443."
    profiles.append(firefox_direct)

    # 2. Direct Edge FP
    edge_direct = build_portable_client_config(subscription_id, public_host, route_mode, dns_preset, relay=False)
    edge_direct["remarks"] = f"{email} NL TCP Edge FP (Direct)"
    try:
        edge_direct["outbounds"][0]["streamSettings"]["realitySettings"]["fingerprint"] = "edge"
    except (KeyError, IndexError):
        pass
    if isinstance(edge_direct.get("meta"), dict):
        edge_direct["meta"]["serverDescription"] = "NL TCP (Edge FP Direct)"
        edge_direct["meta"]["sub-info-text"] = "Фингерпринт Edge, прямой порт 24443."
    profiles.append(edge_direct)

    # If Relay public host is configured, add Relay configs as well
    if RELAY_PUBLIC_HOST:
        # 3. Relay Firefox FP
        firefox_relay = build_portable_client_config(subscription_id, RELAY_PUBLIC_HOST, route_mode, dns_preset, relay=True)
        firefox_relay["remarks"] = f"{email} NL TCP Firefox FP (Relay)"
        try:
            firefox_relay["outbounds"][0]["streamSettings"]["realitySettings"]["fingerprint"] = "firefox"
        except (KeyError, IndexError):
            pass
        if isinstance(firefox_relay.get("meta"), dict):
            firefox_relay["meta"]["serverDescription"] = "NL TCP (Firefox FP Relay)"
            firefox_relay["meta"]["sub-info-text"] = "Фингерпринт Firefox, порт Релея 443."
        profiles.append(firefox_relay)

        # 4. Relay Edge FP
        edge_relay = build_portable_client_config(subscription_id, RELAY_PUBLIC_HOST, route_mode, dns_preset, relay=True)
        edge_relay["remarks"] = f"{email} NL TCP Edge FP (Relay)"
        try:
            edge_relay["outbounds"][0]["streamSettings"]["realitySettings"]["fingerprint"] = "edge"
        except (KeyError, IndexError):
            pass
        if isinstance(edge_relay.get("meta"), dict):
            edge_relay["meta"]["serverDescription"] = "NL TCP (Edge FP Relay)"
            edge_relay["meta"]["sub-info-text"] = "Фингерпринт Edge, порт Релея 443."
        profiles.append(edge_relay)

    return profiles


def build_xhttp_test_profiles(
    subscription_id: str,
    public_host: str,
    dns_preset: str = "default",
) -> list[dict[str, Any]]:
    try:
        row, _, _, _, client = find_subscription(subscription_id)
        email = client.get("email") or subscription_id
        client_uuid = client.get("id")
    except Exception:
        email = subscription_id
        client_uuid = None

    if not client_uuid:
        return []

    # Check for expiration
    summary = subscription_summary(subscription_id)
    if summary.get("status_kind") != "active":
        return build_expired_dummy_profile(email)

    profiles = []

    # 1. NL XHTTP (max.ru) - Port 28443 (Standalone)
    nl_maxru_cfg = load_static_json_config("json-nl-maxru-xhttp")
    if nl_maxru_cfg:
        nl_maxru_cfg = copy.deepcopy(nl_maxru_cfg)
        nl_maxru_cfg["remarks"] = f"{email} NL XHTTP HTTP3 (28443)"
        try:
            nl_maxru_cfg["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"] = client_uuid
            nl_maxru_cfg["outbounds"][0]["settings"]["vnext"][0]["users"][0]["email"] = email
        except (KeyError, IndexError) as e:
            LOGGER.error(f"Error customizing NL XHTTP maxru profile: {e}")
        if isinstance(nl_maxru_cfg.get("meta"), dict):
            nl_maxru_cfg["meta"]["serverDescription"] = "NL XHTTP over HTTP/3 (QUIC)"
            nl_maxru_cfg["meta"]["sub-info-text"] = "NL VLESS over XHTTP (HTTP/3 / QUIC) on UDP port 28443. Self-signed TLS."
        profiles.append(nl_maxru_cfg)

    # 2. NL XHTTP (kernel.org) - Port 8443 (Main x-ui inbound)
    if nl_maxru_cfg:
        nl_kernel_cfg = copy.deepcopy(nl_maxru_cfg)
        nl_kernel_cfg["remarks"] = f"{email} NL XHTTP kernel.org (8443)"
        
        try:
            outbound = nl_kernel_cfg["outbounds"][0]
            outbound["settings"]["vnext"][0]["address"] = public_host
            outbound["settings"]["vnext"][0]["port"] = 8443
            outbound["settings"]["vnext"][0]["users"][0]["id"] = client_uuid
            outbound["settings"]["vnext"][0]["users"][0]["email"] = email
            outbound["settings"]["vnext"][0]["users"][0]["encryption"] = "none"
            
            # Safe check and initialization to avoid KeyError: 'realitySettings'
            stream_settings = outbound.setdefault("streamSettings", {})
            reality = stream_settings.setdefault("realitySettings", {})
            reality["serverName"] = "www.kernel.org"
            reality["publicKey"] = "324hJemHDtilNcnvMX8iNJzl2_ko0OVF9C_ggv_YlVw"
            reality["shortId"] = "d207"
            stream_settings.setdefault("xhttpSettings", {})["path"] = "/xh-7m2q9r4k1v8p3s6"
        except (KeyError, IndexError) as e:
            LOGGER.error(f"Error building NL kernel XHTTP profile: {e}")
            nl_kernel_cfg = None

        if nl_kernel_cfg:
            if isinstance(nl_kernel_cfg.get("meta"), dict):
                nl_kernel_cfg["meta"]["serverDescription"] = "NL XHTTP (kernel.org, 8443)"
                nl_kernel_cfg["meta"]["sub-info-text"] = "NL VLESS over XHTTP. Port: 8443, SNI: www.kernel.org. Dynamic personal config."
            profiles.append(nl_kernel_cfg)

    # 3. NL gRPC (max.ru) - Port 29443 (Standalone)
    if nl_maxru_cfg:
        nl_grpc_cfg = copy.deepcopy(nl_maxru_cfg)
        nl_grpc_cfg["remarks"] = f"{email} NL gRPC max.ru (29443)"
        try:
            outbound = nl_grpc_cfg["outbounds"][0]
            outbound["settings"]["vnext"][0]["port"] = 29443
            outbound["settings"]["vnext"][0]["users"][0]["id"] = client_uuid
            outbound["settings"]["vnext"][0]["users"][0]["email"] = email
            outbound["settings"]["vnext"][0]["users"][0]["encryption"] = "none"
            
            outbound["streamSettings"]["network"] = "grpc"
            outbound["streamSettings"]["grpcSettings"] = {
                "serviceName": "grpc-maxru",
                "multiMode": False
            }
            outbound["streamSettings"].pop("xhttpSettings", None)
            outbound["streamSettings"].pop("tlsSettings", None)
            outbound["streamSettings"]["security"] = "reality"
            outbound["streamSettings"]["realitySettings"] = {
                "show": False,
                "fingerprint": "chrome",
                "serverName": GRPC_REALITY_SNI,
                "publicKey": GRPC_REALITY_PUBLIC_KEY,
                "shortId": GRPC_REALITY_SHORT_ID,
                "spiderX": "/"
            }
        except (KeyError, IndexError) as e:
            LOGGER.error(f"Error building NL gRPC profile: {e}")
            nl_grpc_cfg = None
            
        if nl_grpc_cfg:
            if isinstance(nl_grpc_cfg.get("meta"), dict):
                nl_grpc_cfg["meta"]["serverDescription"] = "NL gRPC (vk.com, 29443)"
                nl_grpc_cfg["meta"]["sub-info-text"] = "NL VLESS over gRPC. Port: 29443, SNI: vk.com. Standalone test config."
            profiles.append(nl_grpc_cfg)

    # 4. Frankfurt XHTTP (kernel.org) - Port 8443 (Main Germany inbound)
    fk_xhttp_cfg = load_static_json_config("json-frankfurt-xhttp")
    if fk_xhttp_cfg:
        fk_xhttp_cfg = copy.deepcopy(fk_xhttp_cfg)
        fk_xhttp_cfg["remarks"] = f"{email} Frankfurt XHTTP kernel.org (8443)"
        try:
            outbound = fk_xhttp_cfg["outbounds"][0]
            outbound["settings"]["vnext"][0]["users"][0]["id"] = client_uuid
            outbound["settings"]["vnext"][0]["users"][0]["email"] = email
        except (KeyError, IndexError) as e:
            LOGGER.error(f"Error customizing Frankfurt XHTTP profile: {e}")
            
        if isinstance(fk_xhttp_cfg.get("meta"), dict):
            fk_xhttp_cfg["meta"]["serverDescription"] = "Frankfurt XHTTP (kernel.org, 8443)"
            fk_xhttp_cfg["meta"]["sub-info-text"] = "Frankfurt VLESS over XHTTP. Port: 8443, SNI: www.kernel.org. Dynamic personal config."
        profiles.append(fk_xhttp_cfg)

    # 5. Frankfurt gRPC (kernel.org) - Port 29443 (Main Germany inbound)
    if fk_xhttp_cfg:
        fk_grpc_cfg = copy.deepcopy(fk_xhttp_cfg)
        fk_grpc_cfg["remarks"] = f"{email} Frankfurt gRPC kernel.org (29443)"
        try:
            outbound = fk_grpc_cfg["outbounds"][0]
            outbound["settings"]["vnext"][0]["port"] = 29443
            outbound["settings"]["vnext"][0]["users"][0]["id"] = client_uuid
            outbound["settings"]["vnext"][0]["users"][0]["email"] = email
            
            outbound["streamSettings"]["network"] = "grpc"
            outbound["streamSettings"]["grpcSettings"] = {
                "serviceName": "grpc-kernel",
                "multiMode": False
            }
            outbound["streamSettings"].pop("xhttpSettings", None)
        except (KeyError, IndexError) as e:
            LOGGER.error(f"Error building Frankfurt gRPC profile: {e}")
            fk_grpc_cfg = None
            
        if fk_grpc_cfg:
            if isinstance(fk_grpc_cfg.get("meta"), dict):
                fk_grpc_cfg["meta"]["serverDescription"] = "Frankfurt gRPC (kernel.org, 29443)"
                fk_grpc_cfg["meta"]["sub-info-text"] = "Frankfurt VLESS over gRPC. Port: 29443, SNI: www.kernel.org. Dynamic personal config."
            profiles.append(fk_grpc_cfg)

    return profiles


def build_xhttp_tcp_caddy_test_profile(
    subscription_id: str,
    public_host: str,
    dns_preset: str = "default",
) -> dict[str, Any] | list[dict[str, Any]]:
    try:
        row, _, _, _, client = find_subscription(subscription_id)
        email = client.get("email") or subscription_id
        client_uuid = client.get("id")
    except Exception:
        email = subscription_id
        client_uuid = None

    if not client_uuid:
        return []

    summary = subscription_summary(subscription_id)
    if summary.get("status_kind") != "active":
        return build_expired_dummy_profile(email)

    cfg = load_static_json_config("json-nl-maxru-xhttp")
    if not cfg:
        return []

    cfg = copy.deepcopy(cfg)
    cfg["remarks"] = f"{email} XHTTP TCP Caddy test"

    try:
        outbound = cfg["outbounds"][0]
        vnext = outbound["settings"]["vnext"][0]
        user = vnext["users"][0]
        vnext["address"] = public_host
        vnext["port"] = 443
        user["id"] = client_uuid
        user["email"] = email
        user["flow"] = ""
        user["encryption"] = "none"

        stream_settings = outbound.setdefault("streamSettings", {})
        stream_settings["network"] = "xhttp"
        stream_settings["security"] = "tls"
        stream_settings["tlsSettings"] = {
            "serverName": public_host,
            "alpn": ["h2"],
        }
        stream_settings["xhttpSettings"] = {
            "path": "/xh-mx-d1f7c0429d6a",
            "host": public_host,
            "headers": {},
            "mode": "packet-up",
        }
    except (KeyError, IndexError) as e:
        LOGGER.error(f"Error building NL XHTTP TCP Caddy test profile: {e}")
        return []

    if isinstance(cfg.get("meta"), dict):
        cfg["meta"]["serverDescription"] = "XHTTP TCP Caddy test"
        cfg["meta"]["sub-info-text"] = "Isolated XHTTP TCP test via Caddy 443. Explicit XHTTP host, no Happ address pre-resolve."

    return cfg


def build_four_frankfurt_profiles(
    subscription_id: str,
    dns_preset: str = "default",
) -> list[dict[str, Any]]:
    try:
        row, _, _, _, client = find_subscription(subscription_id)
        email = client.get("email") or subscription_id
        client_uuid = client.get("id")
    except Exception:
        email = subscription_id
        client_uuid = None

    if not client_uuid:
        return []

    # Check for expiration
    summary = subscription_summary(subscription_id)
    if summary.get("status_kind") != "active":
        return build_expired_dummy_profile(email)

    # Build WebSocket (Wi-Fi) config
    try:
        wifi_cfg = build_ws443_client_config(
            subscription_id,
            route_mode="split-ru",
            dns_preset=dns_preset,
            ws_host=os.environ.get("FRANKFURT_WS_HOST", "de.example.com")
        )
        wifi_cfg["remarks"] = f"{email} Frankfurt Wi-Fi"
        if isinstance(wifi_cfg.get("meta"), dict):
            wifi_cfg["meta"]["serverDescription"] = "Wi-Fi: WebSocket (Frankfurt)"
            wifi_cfg["meta"]["sub-info-text"] = "Frankfurt Wi-Fi. WebSocket через Caddy (порт 443) для Wi-Fi."
    except Exception:
        wifi_cfg = None

    def make_auto_cfg(tcp_cfg, wifi_cfg, remarks, description, fingerprint):
        if not tcp_cfg or not wifi_cfg:
            return None
        auto_cfg = copy.deepcopy(tcp_cfg)
        auto_cfg["remarks"] = remarks
        
        tcp_outbound = copy.deepcopy(tcp_cfg["outbounds"][0])
        tcp_outbound["tag"] = "proxy-tcp"
        try:
            tcp_outbound["streamSettings"]["realitySettings"]["fingerprint"] = fingerprint
        except (KeyError, IndexError):
            pass
        
        wifi_outbound = copy.deepcopy(wifi_cfg["outbounds"][0])
        wifi_outbound["tag"] = "proxy-wifi"
        
        proxy_idx = -1
        for idx, o in enumerate(auto_cfg["outbounds"]):
            if o.get("tag") == "proxy":
                proxy_idx = idx
                break
        
        if proxy_idx != -1:
            auto_cfg["outbounds"] = (
                auto_cfg["outbounds"][:proxy_idx] +
                [tcp_outbound, wifi_outbound] +
                auto_cfg["outbounds"][proxy_idx+1:]
            )
            
        auto_cfg["routing"] = build_balanced_routing("split-ru")
        auto_cfg["observatory"] = {
            "subjectSelector": ["proxy-"],
            "probeUrl": "https://www.google.com/generate_204",
            "probeInterval": "15s",
            "enableConcurrency": True,
        }
        
        if isinstance(auto_cfg.get("meta"), dict):
            auto_cfg["meta"]["serverDescription"] = description
            auto_cfg["meta"]["sub-info-text"] = "Frankfurt Auto. Автовыбор между TCP и WebSocket."
        return auto_cfg

    # 1. Base Frankfurt 4G (Reality TCP with Firefox fingerprint)
    tcp_cfg = load_static_json_config("json-frankfurt-tcp")
    if tcp_cfg:
        tcp_cfg["remarks"] = f"{email} Frankfurt 4G"
        try:
            tcp_cfg["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"] = client_uuid
            tcp_cfg["outbounds"][0]["settings"]["vnext"][0]["users"][0]["email"] = email
            tcp_cfg["outbounds"][0]["streamSettings"]["realitySettings"]["fingerprint"] = "firefox"
        except (KeyError, IndexError):
            pass
        if isinstance(tcp_cfg.get("meta"), dict):
            tcp_cfg["meta"]["serverDescription"] = "4G: Reality TCP (Frankfurt)"
            tcp_cfg["meta"]["sub-info-text"] = "Frankfurt 4G. Чистый Reality TCP для мобильного интернета."

    # 2. Frankfurt Auto (f)
    auto_f = make_auto_cfg(tcp_cfg, wifi_cfg, f"{email} Frankfurt Auto (f)", "Auto: Wi-Fi + 4G (Frankfurt, F)", "firefox")

    # 3. Frankfurt Auto (e)
    auto_e = make_auto_cfg(tcp_cfg, wifi_cfg, f"{email} Frankfurt Auto (e)", "Auto: Wi-Fi + 4G (Frankfurt, E)", "edge")

    configs = []
    if auto_f:
        configs.append(auto_f)
    if auto_e:
        configs.append(auto_e)
    if tcp_cfg:
        configs.append(tcp_cfg)
    if wifi_cfg:
        configs.append(wifi_cfg)

    return configs



def build_hybrid_client_config(
    subscription_id: str,
    public_host: str,
    route_mode: str,
    dns_preset: str = "default",
    *,
    relay: bool = False,
) -> dict[str, Any]:
    tcp_sub_id, xhttp_sub_id = parse_hybrid_subscription_id(subscription_id)
    tcp_outbound, tcp_sniffing, tcp_client = build_proxy_outbound(tcp_sub_id, public_host, "proxy-tcp", relay=relay)
    xhttp_outbound, _xhttp_sniffing, xhttp_client = build_proxy_outbound(
        xhttp_sub_id,
        public_host,
        "proxy-xhttp",
        relay=relay,
    )
    ws443_config = build_ws443_client_config(tcp_sub_id, route_mode, dns_preset)
    ws443_outbound = copy.deepcopy(ws443_config["outbounds"][0])
    ws443_outbound["tag"] = "proxy-wifi"
    tcp_remark = tcp_client.get("email") or tcp_sub_id
    xhttp_remark = xhttp_client.get("email") or xhttp_sub_id

    return {
        "log": {
            "loglevel": "warning",
            "access": "none",
            "error": "",
            "dnsLog": False,
        },
        "dns": {
            "queryStrategy": "UseIPv4",
            "servers": copy.deepcopy(DNS_PRESETS[dns_preset]),
        },
        "inbounds": [
            build_local_inbound("socks", 10808, "socks-in", tcp_sniffing),
            build_local_inbound("http", 10809, "http-in", tcp_sniffing)],
        "outbounds": [
            tcp_outbound,
            xhttp_outbound,
            ws443_outbound,
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {},
            },
            {
                "tag": "block",
                "protocol": "blackhole",
                "settings": {},
            }],
        "remarks": f"SilentConnect Hybrid ({tcp_remark} + {xhttp_remark})",
        "meta": build_happ_config_meta(subscription_id),
        "routing": build_balanced_routing(route_mode),
        "observatory": {
            "subjectSelector": ["proxy-"],
            "probeUrl": "https://www.google.com/generate_204",
            "probeInterval": "1m",
            "enableConcurrency": True,
        },
    }


def load_extra_outbounds(subscription_id: str) -> list[dict[str, Any]]:
    if not EXTRA_OUTBOUNDS_PATH:
        return []

    path = Path(EXTRA_OUTBOUNDS_PATH)
    if not path.is_file():
        LOGGER.warning("Extra outbounds file is configured but missing: %s", path)
        return []

    data = json.loads(path.read_text(encoding="utf-8"))
    entry = data.get(subscription_id)
    if not entry:
        return []

    if isinstance(entry, dict):
        outbounds = entry.get("outbounds", [])
    else:
        outbounds = entry

    if not isinstance(outbounds, list):
        raise ValueError(f"Extra outbounds for {subscription_id} must be a list")

    for outbound in outbounds:
        if not isinstance(outbound, dict):
            raise ValueError(f"Extra outbound for {subscription_id} must be a JSON object")

    return copy.deepcopy(outbounds)


def append_extra_outbounds(payload: dict[str, Any], subscription_id: str, subscription_route: str) -> dict[str, Any]:
    if subscription_route == "raw":
        return payload

    extra_outbounds = load_extra_outbounds(subscription_id)
    if not extra_outbounds:
        return payload

    result = copy.deepcopy(payload)
    outbounds = result.get("outbounds")
    if not isinstance(outbounds, list):
        raise ValueError("Subscription payload does not contain an outbounds list")

    insert_at = len(outbounds)
    for index, outbound in enumerate(outbounds):
        if isinstance(outbound, dict) and outbound.get("tag") in {"direct", "block"}:
            insert_at = index
            break

    result["outbounds"] = outbounds[:insert_at] + extra_outbounds + outbounds[insert_at:]

    proxy_tags = [
        outbound.get("tag")
        for outbound in result["outbounds"]
        if isinstance(outbound, dict)
        and outbound.get("protocol") not in {"freedom", "blackhole"}
        and outbound.get("tag")
    ]
    if len(proxy_tags) > 1:
        balancer_tag = "auto-proxy"
        routing = result.setdefault("routing", {})
        rules = routing.setdefault("rules", [])

        for rule in rules:
            if not isinstance(rule, dict):
                continue
            if rule.get("outboundTag") in proxy_tags:
                rule.pop("outboundTag", None)
                rule["balancerTag"] = balancer_tag

        rules.append(
            {
                "type": "field",
                "ip": ["0.0.0.0/0", "::/0"],
                "balancerTag": balancer_tag,
            }
        )
        routing["balancers"] = [
            {
                "tag": balancer_tag,
                "selector": ["proxy"],
                "fallbackTag": proxy_tags[0],
                "strategy": {
                    "type": "leastPing",
                },
            }
        ]
        result["observatory"] = {
            "subjectSelector": ["proxy"],
            "probeUrl": "https://www.google.com/generate_204",
            "probeInterval": "1m",
            "enableConcurrency": True,
        }

    return result


def load_multi_configs(subscription_id: str) -> list[dict[str, Any]]:
    if not MULTI_CONFIGS_PATH:
        return []

    path = Path(MULTI_CONFIGS_PATH)
    if not path.is_file():
        LOGGER.warning("Multi-config file is configured but missing: %s", path)
        return []

    data = json.loads(path.read_text(encoding="utf-8"))
    entry = data.get(subscription_id)
    if not entry:
        return []

    if isinstance(entry, dict):
        configs = entry.get("configs", [])
    else:
        configs = entry

    if not isinstance(configs, list):
        raise ValueError(f"Multi-config entry for {subscription_id} must be a list")

    for config in configs:
        if not isinstance(config, dict):
            raise ValueError(f"Multi-config item for {subscription_id} must be a JSON object")

    return copy.deepcopy(configs)


def load_static_json_config(route_name: str) -> dict[str, Any] | None:
    if not STATIC_JSON_CONFIG_DIR:
        return None

    allowed_routes = {
        "json-frankfurt-xhttp",
        "json-frankfurt-tcp",
        "json-frankfurt-hybrid",
        "json-nl-maxru-tcp",
        "json-nl-maxru-xhttp",
        "json-nl-maxru-hybrid",
        "json-nl-ws443",
    }
    if route_name not in allowed_routes:
        return None

    path = Path(STATIC_JSON_CONFIG_DIR) / f"{route_name}.json"
    if not path.is_file():
        LOGGER.warning("Static JSON config is missing: %s", path)
        return None

    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Static JSON config must be an object: {path}")
    return payload


def build_multi_client_configs(
    subscription_id: str,
    public_host: str,
    route_mode: str,
    dns_preset: str = "default",
) -> list[dict[str, Any]]:
    configs = [build_portable_client_config(subscription_id, public_host, route_mode, dns_preset)]
    configs.extend(load_multi_configs(subscription_id))
    return configs


def encrypt_happ_link(subscription_url: str) -> str | None:
    payload = json.dumps({"url": subscription_url}, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        "https://crypto.happ.su/api-v2.php",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain;q=0.9, */*;q=0.8",
            "User-Agent": "subjson-service/3.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=6) as response:
            raw = response.read().decode("utf-8", errors="replace").strip()
    except Exception:
        LOGGER.exception("Failed to encrypt Happ link")
        return None

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = raw

    if isinstance(parsed, dict):
        for key in ("url", "link", "result", "data", "encrypted_link", "encrypted_url", "encrypted"):
            value = parsed.get(key)
            if isinstance(value, str) and value.startswith("happ://"):
                return value
        return None
    if isinstance(parsed, str) and parsed.startswith("happ://"):
        return parsed
    return None


def import_page_html(
    *,
    title: str,
    body: str,
    subscription_url: str,
    primary_label: str = "",
    primary_url: str | None = None,
    extra_buttons: list[tuple[str, str]] | None = None,
    auto_url: str | None = None,
    install_urls: dict[str, str] | None = None,
) -> bytes:
    escaped_title = html.escape(title)
    escaped_body = html.escape(body).replace("\n", "<br>")
    escaped_subscription = html.escape(subscription_url)
    primary_html = ""
    if primary_url:
        primary_html = f'<a class="button" href="{html.escape(primary_url, quote=True)}">{html.escape(primary_label)}</a>'
    extra_html = ""
    for label, url in extra_buttons or []:
        extra_html += f'<a class="button secondary" href="{html.escape(url, quote=True)}">{html.escape(label)}</a>'
    install_urls = install_urls or {}
    install_labels = {
        "ios": "Установить для iPhone / iPad",
        "android": "Установить для Android",
        "android_apk": "Скачать APK для Huawei / без Google Play",
        "windows": "Скачать для Windows",
        "fallback": "Открыть страницу загрузки",
    }
    install_html = ""
    install_keys = ("ios", "android", "android_apk", "windows", "fallback")
    for key in install_keys:
        url = install_urls.get(key)
        if url:
            install_html += f'<a class="button install" href="{html.escape(url, quote=True)}">{html.escape(install_labels[key])}</a>'
    if install_html:
        install_html = f'<p class="hint">Если приложение не установлено, откройте подходящую страницу загрузки.</p>{install_html}'
    auto_script = ""
    if auto_url:
        install_payload = {
            "ios": install_urls.get("ios", ""),
            "android": install_urls.get("android", ""),
            "android_apk": install_urls.get("android_apk", ""),
            "windows": install_urls.get("windows", ""),
            "fallback": install_urls.get("fallback", ""),
        }
        auto_script = f"""
  <script>
    var appOpened = false;
    var installUrls = {json.dumps(install_payload, ensure_ascii=False)};
    document.addEventListener("visibilitychange", function () {{
      if (document.hidden) {{
        appOpened = true;
      }}
    }});
    window.setTimeout(function () {{
      window.location.href = {json.dumps(auto_url, ensure_ascii=False)};
    }}, 700);
    window.setTimeout(function () {{
      if (appOpened || document.hidden) {{
        return;
      }}
      var ua = navigator.userAgent || "";
      var target = "";
      if (/iPad|iPhone|iPod/i.test(ua)) {{
        target = installUrls.ios;
      }} else if (/Android/i.test(ua)) {{
        target = installUrls.android || installUrls.android_apk;
      }} else if (/Windows/i.test(ua)) {{
        target = installUrls.windows;
      }}
      target = target || installUrls.fallback;
      if (target) {{
        window.location.href = target;
      }}
    }}, 3600);
  </script>"""
    return f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex,nofollow,noarchive">
  <title>{escaped_title} — SilentConnect</title>
  <style>
    body {{ margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #101418; color: #eef2f3; }}
    main {{ max-width: 720px; margin: 0 auto; padding: 32px 18px; }}
    .brand {{ font-size: 14px; font-weight: 700; letter-spacing: 0.05em; color: #38bdf8; text-transform: uppercase; margin-bottom: 8px; }}
    h1 {{ font-size: 28px; margin: 0 0 18px; }}
    p {{ line-height: 1.45; color: #cbd4d8; }}
    .button, button {{ display: block; width: 100%; box-sizing: border-box; margin: 12px 0; padding: 14px 16px; border: 0; border-radius: 8px; background: #1f7a4d; color: white; font-size: 17px; font-weight: 700; text-align: center; text-decoration: none; }}
    button.secondary {{ background: #2d5f88; }}
    .button.secondary {{ background: #2d5f88; }}
    .button.install {{ background: #4b5563; }}
    textarea {{ width: 100%; min-height: 118px; box-sizing: border-box; border-radius: 8px; border: 1px solid #364149; padding: 12px; color: #eef2f3; background: #151b20; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }}
    .hint {{ font-size: 14px; color: #9fb0b8; }}
  </style>
  {auto_script}
</head>
<body>
  <main>
    <div class="brand">SilentConnect</div>
    <h1>{escaped_title}</h1>
    <p>{escaped_body}</p>
    {primary_html}
    {extra_html}
    {install_html}
    <button class="secondary" onclick="navigator.clipboard.writeText(document.getElementById('sub').value).then(() => this.textContent='Скопировано')">Скопировать ссылку</button>
    <textarea id="sub" readonly>{escaped_subscription}</textarea>
    <p class="hint">Если автоматический импорт не открылся, скопируйте ссылку и добавьте её в приложении через импорт из буфера обмена.</p>
  </main>
</body>
</html>""".encode("utf-8")


def format_bytes(value: int | float | None) -> str:
    amount = float(value or 0)
    units = ["Б", "КБ", "МБ", "ГБ", "ТБ"]
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            if unit == "Б":
                return f"{int(amount)} {unit}"
            return f"{amount:.1f}".rstrip("0").rstrip(".") + f" {unit}"
        amount /= 1024
    return f"{amount:.1f} ТБ"


def format_expiry(expiry_ms: int | None) -> str:
    if not expiry_ms or int(expiry_ms) <= 0:
        return "без ограничения"
    if is_effectively_unlimited_expiry(expiry_ms):
        return "без ограничения"
    return time.strftime("%d.%m.%Y", time.localtime(int(expiry_ms) / 1000))


def is_effectively_unlimited_expiry(expiry_ms: int | None) -> bool:
    if not expiry_ms or int(expiry_ms) <= 0:
        return True
    seconds_left = int(expiry_ms) // 1000 - int(time.time())
    return seconds_left > max(HAPP_UNLIMITED_AFTER_DAYS, 1) * 86400


def format_expiry_hint(expiry_ms: int | None) -> str:
    if not expiry_ms or int(expiry_ms) <= 0:
        return "срок не ограничен"
    if is_effectively_unlimited_expiry(expiry_ms):
        return "срок не ограничен"
    seconds_left = int(expiry_ms) // 1000 - int(time.time())
    abs_seconds = abs(seconds_left)
    days = abs_seconds // 86400
    if seconds_left < 0:
        if days <= 0:
            return "истекла сегодня"
        return f"истекла {days} дн. назад"
    if days <= 0:
        hours = max(abs_seconds // 3600, 1)
        return f"осталось {hours} ч."
    return f"осталось {days} дн."


def client_traffic(email: str) -> dict[str, Any]:
    if not email:
        return {}
    db_uri = Path(XUI_DB_PATH).as_posix()
    try:
        conn = sqlite3.connect(f"file:{db_uri}?mode=ro", uri=True, timeout=30.0)
        conn.execute("PRAGMA busy_timeout = 30000;")
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                """
                SELECT email, up, down, total, expiry_time, enable, last_online
                FROM client_traffics
                WHERE email = ?
                """,
                (email,),
            ).fetchone()
            return dict(row) if row else {}
        finally:
            conn.close()
    except sqlite3.Error:
        return {}


def subscription_summary(subscription_id: str) -> dict[str, Any]:
    sub_ids = [subscription_id]
    if "~" in subscription_id:
        try:
            sub_ids = list(parse_hybrid_subscription_id(subscription_id))
        except ValueError:
            sub_ids = [subscription_id]

    clients: list[dict[str, Any]] = []
    traffics: list[dict[str, Any]] = []
    for sub_id in sub_ids:
        try:
            _, _, _, _, client = find_subscription(sub_id)
        except (KeyError, sqlite3.Error, json.JSONDecodeError, RuntimeError, ValueError):
            continue
        clients.append(client)
        traffics.append(client_traffic(str(client.get("email") or "")))

    if not clients:
        visible_id = subscription_id[:10] + ("..." if len(subscription_id) > 10 else "")
        return {
            "found": False,
            "title": "Подписка готова",
            "subtitle": "Выберите устройство и приложение ниже.",
            "identifier": visible_id,
            "status": "готова",
            "status_kind": "active",
            "expires": "не определено",
            "traffic": "не определён",
            "device_limit": "по тарифу",
            "expiry_ms": 0,
            "upload_bytes": 0,
            "download_bytes": 0,
            "total_bytes": 0,
        }

    expiry_values = []
    for client, traffic in zip(clients, traffics):
        raw_expiry = client.get("expiryTime") or traffic.get("expiry_time") or 0
        try:
            raw_expiry = int(raw_expiry)
        except (TypeError, ValueError):
            raw_expiry = 0
        if raw_expiry > 0:
            expiry_values.append(raw_expiry)
    expiry_ms = min(expiry_values) if expiry_values else 0
    now_ms = int(time.time() * 1000)

    enabled = all(bool(client.get("enable", True)) for client in clients)
    for traffic in traffics:
        if traffic and int(traffic.get("enable") or 0) == 0:
            enabled = False
    expired = bool(expiry_ms and expiry_ms < now_ms)
    status_kind = "active" if enabled and not expired else "inactive"
    status = "активна" if status_kind == "active" else ("истекла" if expired else "выключена")

    upload = sum(int((traffic or {}).get("up") or 0) for traffic in traffics)
    download = sum(int((traffic or {}).get("down") or 0) for traffic in traffics)
    used = upload + download
    totals = []
    for client, traffic in zip(clients, traffics):
        raw_total = client.get("totalGB") or traffic.get("total") or 0
        try:
            raw_total = int(raw_total)
        except (TypeError, ValueError):
            raw_total = 0
        if raw_total > 0:
            totals.append(raw_total)
    total = sum(totals) if totals else 0
    traffic_label = f"{format_bytes(used)} / {format_bytes(total)}" if total else f"{format_bytes(used)} / ∞"

    device_limits = []
    for client in clients:
        try:
            limit = int(client.get("limitIp") or 0)
        except (TypeError, ValueError):
            limit = 0
        if limit > 0:
            device_limits.append(limit)
    device_limit = min(device_limits) if device_limits else 0
    device_label = f"до {device_limit} устройств" if device_limit else "без лимита"

    email = str(clients[0].get("email") or "")
    identifier = email or (subscription_id[:10] + ("..." if len(subscription_id) > 10 else ""))
    return {
        "found": True,
        "title": "Подписка активна" if status_kind == "active" else "Подписка неактивна",
        "subtitle": format_expiry_hint(expiry_ms),
        "identifier": identifier,
        "status": status,
        "status_kind": status_kind,
        "expires": format_expiry(expiry_ms),
        "traffic": traffic_label,
        "device_limit": device_label,
        "expiry_ms": expiry_ms,
        "upload_bytes": upload,
        "download_bytes": download,
        "total_bytes": total,
    }


def nonnegative_int(value: Any) -> int:
    try:
        return max(int(value or 0), 0)
    except (TypeError, ValueError):
        return 0


def happ_subscription_userinfo(subscription_id: str) -> str:
    summary = subscription_summary(subscription_id)
    upload = nonnegative_int(summary.get("upload_bytes"))
    download = nonnegative_int(summary.get("download_bytes"))
    total = nonnegative_int(summary.get("total_bytes"))
    expiry_ms = nonnegative_int(summary.get("expiry_ms"))
    expire = 0 if is_effectively_unlimited_expiry(expiry_ms) else expiry_ms // 1000
    return f"upload={upload}; download={download}; total={total}; expire={expire}"


def build_expired_dummy_profile(email: str) -> list[dict[str, Any]]:
    meta: dict[str, Any] = {}
    if HAPP_SERVER_DESCRIPTION:
        meta["serverDescription"] = HAPP_SERVER_DESCRIPTION
    if HAPP_PROVIDER_ID and HAPP_SUB_INFO_ENABLED:
        meta["sub-info-color"] = "red"
        meta["sub-info-text"] = "❌ Подписка истекла. Пожалуйста, продлите её в Telegram-боте!"
        if HAPP_RENEW_URL:
            meta["sub-info-button-text"] = "Продлить"
            meta["sub-info-button-link"] = HAPP_RENEW_URL
            meta["sub-expire"] = "1"
            meta["sub-expire-button-link"] = HAPP_RENEW_URL

    dummy = {
        "log": {
            "loglevel": "warning",
            "access": "none",
            "error": "",
            "dnsLog": False
        },
        "dns": {
            "queryStrategy": "UseIPv4",
            "servers": ["8.8.8.8"]
        },
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
                "tag": "socks-in"
            }
        ],
        "outbounds": [
            {
                "protocol": "blackhole",
                "settings": {},
                "tag": "proxy"
            }
        ],
        "remarks": "⚠️ ПОДПИСКА ИСТЕКЛА - ПРОДЛИТЕ В БОТЕ",
        "meta": meta
    }
    return [dummy]


def build_happ_config_meta(subscription_id: str) -> dict[str, Any] | None:
    meta: dict[str, Any] = {}
    if HAPP_SERVER_DESCRIPTION:
        meta["serverDescription"] = HAPP_SERVER_DESCRIPTION

    if HAPP_PROVIDER_ID and HAPP_SUB_INFO_ENABLED:
        summary = subscription_summary(subscription_id)
        subtitle = str(summary.get("subtitle") or "срок не определён").strip().rstrip(".")
        
        if summary.get("status_kind") != "active":
            info_text = f"❌ Подписка ИСТЕКЛА ({subtitle}). Продлите её в Telegram!"
            meta["sub-info-color"] = "red"
        else:
            info_text = f"⏳ {subtitle}. Продление и поддержка — в Telegram."
            meta["sub-info-color"] = "blue"

        meta["sub-info-text"] = info_text[:200]
        if HAPP_RENEW_URL:
            meta["sub-info-button-text"] = "Продлить"
            meta["sub-info-button-link"] = HAPP_RENEW_URL
            meta["sub-expire"] = "1"
            meta["sub-expire-button-link"] = HAPP_RENEW_URL

    return meta or None


def setup_page_html(
    *,
    subscription_url: str,
    subscription_id: str,
    quoted_sub_id: str,
    import_query: str,
    customer_email: str = "",
    payment_card_html: str = "",
) -> bytes:
    fallback_links = {
        "happ": f"/{SECRET_SEGMENT}/import/happ/{quoted_sub_id}?{import_query}",
        "streisand": f"/{SECRET_SEGMENT}/import/streisand/{quoted_sub_id}?{import_query}",
        "v2raytun": f"/{SECRET_SEGMENT}/import/v2raytun/{quoted_sub_id}?{import_query}",
        "clash": f"/{SECRET_SEGMENT}/import/clash/{quoted_sub_id}?{import_query}",
        "v2rayn": f"/{SECRET_SEGMENT}/import/v2rayn/{quoted_sub_id}?{import_query}",
        "nekobox": f"/{SECRET_SEGMENT}/import/nekobox/{quoted_sub_id}?{import_query}",
        "v2rayng": f"/{SECRET_SEGMENT}/import/v2rayng/{quoted_sub_id}?{import_query}",
        "singbox": f"/{SECRET_SEGMENT}/import/singbox/{quoted_sub_id}?{import_query}",
    }
    happ_link = encrypt_happ_link(subscription_url) or fallback_links["happ"]
    apps = [
        {
            "id": "happ",
            "name": "Happ",
            "badge": "рекомендуем",
            "iconUrl": "https://is1-ssl.mzstatic.com/image/thumb/Purple221/v4/c4/bb/d1/c4bbd1c2-e4b0-4762-3b2e-add06ecb8415/AppIcon-0-0-1x_U007epad-0-0-0-1-0-0-sRGB-85-220.png/100x100bb.jpg",
            "platforms": ["ios", "android", "windows", "macos", "linux", "androidtv", "appletv"],
            "importUrl": happ_link,
            "description": "Флагманский клиент с поддержкой протоколов REALITY и XHTTP. Обеспечивает максимальную скорость и незаметность подключения на любых устройствах.",
            "downloads": {
                "ios": [{"label": "App Store", "url": HAPP_IOS_URL}],
                "android": [
                    {"label": "Google Play", "url": HAPP_ANDROID_URL},
                    {"label": "APK для Huawei / Android", "url": HAPP_ANDROID_APK_URL},
                ],
                "windows": [{"label": "Скачать для Windows", "url": HAPP_DOWNLOAD_URL}],
                "macos": [{"label": "Скачать для macOS", "url": HAPP_DOWNLOAD_URL}],
                "linux": [{"label": "Скачать для Linux", "url": HAPP_DOWNLOAD_URL}],
                "androidtv": [
                    {"label": "Google Play", "url": HAPP_ANDROID_URL},
                    {"label": "APK для Android TV", "url": HAPP_ANDROID_APK_URL},
                ],
                "appletv": [{"label": "App Store", "url": HAPP_IOS_URL}],
            },
        },
        {
            "id": "clash",
            "name": "Clash Meta / Mihomo",
            "badge": "авто-выбор",
            "iconUrl": OFFICIAL_CLASH_ICON,
            "platforms": ["windows", "macos", "android", "linux", "ios"],
            "importUrl": fallback_links["clash"],
            "description": "Мощный клиент с поддержкой умного авто-тестирования узлов и мгновенным переключением при сбоях.",
            "downloads": {
                "windows": [{"label": "Clash Verge Rev (Windows)", "url": CLASH_DOWNLOAD_URL}],
                "macos": [{"label": "Clash Verge Rev (macOS)", "url": CLASH_DOWNLOAD_URL}],
                "android": [{"label": "Clash Meta Android", "url": "https://github.com/MetaCubeX/ClashMetaForAndroid/releases"}],
                "linux": [{"label": "Clash Verge Rev (Linux)", "url": CLASH_DOWNLOAD_URL}],
                "ios": [{"label": "Sing-box (App Store)", "url": SINGBOX_IOS_URL}],
            },
        },
        {
            "id": "v2rayn",
            "name": "v2rayN",
            "badge": "windows xray",
            "iconUrl": OFFICIAL_V2RAYN_ICON,
            "platforms": ["windows"],
            "importUrl": fallback_links["v2rayn"],
            "description": "Популярный клиент для Windows с поддержкой Xray-ядра, автоматическим обновлением подписок и гибкой маршрутизацией.",
            "downloads": {
                "windows": [{"label": "Скачать v2rayN (GitHub)", "url": V2RAYN_DOWNLOAD_URL}],
            },
        },
        {
            "id": "nekobox",
            "name": "NekoBox",
            "badge": "android json",
            "iconUrl": OFFICIAL_NEKOBOX_ICON,
            "platforms": ["android"],
            "importUrl": fallback_links["nekobox"],
            "description": "Мощный и функциональный клиент для Android с поддержкой прямых JSON и Sing-box конфигураций.",
            "downloads": {
                "android": [{"label": "Скачать NekoBox (GitHub)", "url": NEKOBOX_DOWNLOAD_URL}],
            },
        },
        {
            "id": "v2rayng",
            "name": "v2rayNG",
            "badge": "android vless",
            "iconUrl": OFFICIAL_V2RAYNG_ICON,
            "platforms": ["android"],
            "importUrl": fallback_links["v2rayng"],
            "description": "Классический проверенный клиент для Android для прямого импорта VLESS-конфигураций.",
            "downloads": {
                "android": [{"label": "Скачать v2rayNG (GitHub)", "url": V2RAYNG_DOWNLOAD_URL}],
            },
        },
        {
            "id": "streisand",
            "name": "Streisand",
            "badge": "ios / macos",
            "iconUrl": "https://is1-ssl.mzstatic.com/image/thumb/Purple211/v4/fb/fd/e7/fbfde74a-55a9-6dc5-e0dc-38b927b0f46f/AppIcon-0-0-1x_U007epad-0-0-0-1-0-85-220.png/100x100bb.jpg",
            "platforms": ["ios", "macos"],
            "importUrl": fallback_links["streisand"],
            "description": "Легкий и быстрый open-source клиент, идеально оптимизированный под экосистемы iOS и macOS без расхода аккумулятора.",
            "downloads": {
                "ios": [{"label": "App Store", "url": STREISAND_IOS_URL}],
                "macos": [{"label": "App Store (macOS)", "url": STREISAND_MACOS_URL}],
            },
        },
        {
            "id": "v2raytun",
            "name": "V2RayTun",
            "badge": "запасной",
            "iconUrl": "https://is1-ssl.mzstatic.com/image/thumb/Purple211/v4/cb/70/4f/cb704f7a-9273-6ea7-dda8-a4a51bef7234/AppIcon-0-0-1x_U007epad-0-1-85-220.png/100x100bb.jpg",
            "platforms": ["ios", "android"],
            "importUrl": fallback_links["v2raytun"],
            "description": "Надежный резервный клиент для мобильных систем Android и iOS на случай недоступности основных магазинов приложений.",
            "downloads": {
                "ios": [{"label": "App Store", "url": V2RAYTUN_IOS_URL}],
                "android": [{"label": "Google Play", "url": V2RAYTUN_ANDROID_URL}],
            },
        },
        {
            "id": "singbox",
            "name": "Sing-box",
            "badge": "sing-box",
            "iconUrl": OFFICIAL_SINGBOX_ICON,
            "platforms": ["ios", "android", "windows", "macos", "linux"],
            "importUrl": fallback_links["singbox"],
            "description": "Универсальный сетевой клиент нового поколения с максимальной производительностью и нативной поддержкой Sing-box JSON.",
            "downloads": {
                "ios": [{"label": "App Store", "url": SINGBOX_IOS_URL}],
                "android": [{"label": "GitHub Releases", "url": SINGBOX_DOWNLOAD_URL}],
                "windows": [{"label": "GitHub Releases", "url": SINGBOX_DOWNLOAD_URL}],
                "macos": [{"label": "GitHub Releases", "url": SINGBOX_DOWNLOAD_URL}],
                "linux": [{"label": "GitHub Releases", "url": SINGBOX_DOWNLOAD_URL}],
            },
        },
    ]
    platforms = [
        ("ios", "iOS"),
        ("android", "Android"),
        ("windows", "Windows"),
        ("macos", "macOS"),
        ("linux", "Linux"),
        ("androidtv", "Android TV"),
        ("appletv", "Apple TV")]
    summary = subscription_summary(subscription_id)
    status_class = "status-good" if summary["status_kind"] == "active" else "status-warn"
    escaped_subscription = html.escape(subscription_url)
    platform_options_html = "".join(f'<option value="{html.escape(val)}">{html.escape(lbl)}</option>' for val, lbl in platforms)
    apps_json = json.dumps(apps, ensure_ascii=False)
    platform_labels_json = json.dumps(dict(platforms), ensure_ascii=False)
    support_url = html.escape(HAPP_SUPPORT_URL)
    title = html.escape(str(summary["title"]))
    subtitle = html.escape(str(summary["subtitle"]))
    device_limit = html.escape(str(summary["device_limit"]))
    identifier = html.escape(str(summary["identifier"]))
    status_str = html.escape(str(summary["status"]))
    expires_str = html.escape(str(summary["expires"]))
    traffic_str = html.escape(str(summary["traffic"]))

    template = """<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex,nofollow,noarchive">
  <title>Подключение SilentConnect</title>
  <link rel="icon" type="image/png" href="__WEB_PAGE_URL__/assets/telegram/avatar.png">
  <link rel="shortcut icon" type="image/png" href="__WEB_PAGE_URL__/assets/telegram/avatar.png">
  <link rel="apple-touch-icon" href="__WEB_PAGE_URL__/assets/telegram/avatar.png">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700;800&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
  <style>
    :root {
      color-scheme: dark;
      --bg:#050a08;
      --panel:rgba(20, 35, 28, 0.4);
      --panel-2:rgba(30, 50, 40, 0.6);
      --soft:rgba(255, 255, 255, 0.05);
      --line:rgba(255, 255, 255, 0.08);
      --text:#f4f7f5;
      --muted:#8ea89a;
      --green:#2fbf71;
      --green-glow:rgba(47, 191, 113, 0.3);
      --cyan:#2fbf71;
      --amber:#f59e0b;
      --red:#ef4444;
    }
    * { box-sizing:border-box; -webkit-tap-highlight-color:transparent; }
    html, body { overflow-x:hidden; }
    body {
      margin:0;
      min-height:100vh;
      font-family:'Inter', system-ui, -apple-system, sans-serif;
      color:var(--text);
      background-color: var(--bg);
      background-image: 
        radial-gradient(circle at 15% 50%, rgba(47, 191, 113, 0.08), transparent 25%),
        radial-gradient(circle at 85% 30%, rgba(59, 130, 246, 0.08), transparent 25%);
      background-attachment: fixed;
      line-height: 1.6;
    }
    main, .shell, main.shell {
      width: 100%;
      max-width: 860px;
      margin-left: auto;
      margin-right: auto;
      padding: 24px 16px 60px;
      box-sizing: border-box;
      display: grid;
      gap: 18px;
    }
    .shell > section, .shell > div { min-width: 0; max-width: 100%; }
    .top, .status, .install {
      background:var(--panel);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border:1px solid var(--line);
      border-radius:16px;
      box-shadow:0 12px 32px rgba(0,0,0,.3);
    }
    .top { min-height:64px; padding:0 20px; display:flex; align-items:center; justify-content:space-between; gap:16px; }
    .brand { min-width:0; display:flex; align-items:center; gap:12px; font-weight:800; font-size:20px; text-decoration:none; color:#fff; }
    .brand span { 
      background: linear-gradient(to right, #fff, #2fbf71);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .brand-logo { width:34px; height:34px; border-radius:9px; object-fit:cover; box-shadow:0 0 12px var(--green-glow); border:1px solid var(--line); }
    .top-actions { display:flex; align-items:center; gap:10px; }
    .top-btn {
      min-height:36px; padding:6px 14px; border-radius:8px; border:1px solid var(--line);
      background:rgba(255,255,255,0.08); color:#fff; font-size:13px; font-weight:600; text-decoration:none;
      display:inline-flex; align-items:center; gap:6px; cursor:pointer;
    }
    .top-btn:hover { background:rgba(255,255,255,0.15); border-color:rgba(255,255,255,0.2); }
    .status { padding:24px; }
    .status-head { display:flex; align-items:center; gap:16px; margin-bottom:18px; }
    .status-head > div:last-child { min-width:0; }
    .state-dot { width:44px; height:44px; border-radius:50%; display:grid; place-items:center; font-weight:900; font-size:20px; border:1px solid rgba(47, 191, 113, .6); color:#fff; background:rgba(47, 191, 113, .2); box-shadow:0 0 16px var(--green-glow); }
    .status-warn .state-dot { border-color:rgba(239,68,68,.6); color:#ffaaa8; background:rgba(239,68,68,.2); }
    h1 { margin:0; font-size:24px; line-height:1.2; letter-spacing:-0.3px; }
    h2 { margin:0; font-size:22px; letter-spacing:-0.3px; }
    h3 { margin:0; font-size:18px; letter-spacing:-0.2px; }
    p { margin:6px 0 0; color:var(--muted); line-height:1.5; }
    .summary { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:12px; }
    .metric { min-width:0; min-height:76px; padding:14px; border:1px solid var(--line); border-radius:12px; background:rgba(255,255,255,.03); }
    .metric strong { display:block; margin-top:4px; font-size:16px; color:#fff; }
    .metric span { color:var(--muted); font-size:13px; }
    .metric.good { border-color:rgba(47, 191, 113,.4); background:rgba(47, 191, 113,.08); }
    .status-warn .metric.good { border-color:rgba(239,68,68,.4); background:rgba(239,68,68,.08); }
    .metric.warn { border-color:rgba(245,158,11,.4); background:rgba(245,158,11,.08); }
    .install { padding:24px; }
    .install-head { min-width:0; display:flex; align-items:center; justify-content:space-between; gap:16px; margin-bottom:18px; }
    select { min-height:44px; min-width:170px; border:1px solid var(--line); border-radius:10px; background:#0a1410; color:var(--text); padding:0 14px; font-size:15px; cursor:pointer; }
    select:focus { outline:none; border-color:var(--green); }

    /* Platform Selector Card & Tabs */
    .platform-selector-card {
      background: rgba(10, 20, 15, 0.55);
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 16px 18px;
      margin-bottom: 22px;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.2);
    }
    .platform-bar-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 12px;
      flex-wrap: wrap;
    }
    .platform-bar-title {
      font-size: 14px;
      font-weight: 700;
      color: #fff;
      display: flex;
      align-items: center;
      gap: 8px;
      letter-spacing: -0.2px;
    }
    .platform-bar-hint {
      font-size: 12.5px;
      color: var(--muted);
    }
    .platform-bar-hint strong {
      color: var(--green);
      font-weight: 600;
    }
    .platform-nav-track {
      display: flex;
      gap: 6px;
      background: rgba(0, 0, 0, 0.35);
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 5px;
      overflow-x: auto;
      scrollbar-width: none;
      position: relative;
    }
    .platform-nav-track::-webkit-scrollbar {
      display: none;
    }
    .platform-tab {
      flex: 1 1 0px;
      min-width: 96px;
      min-height: 42px;
      border-radius: 9px;
      cursor: pointer;
      padding: 8px 12px;
      font-family: 'Outfit', sans-serif;
      font-size: 13.5px;
      font-weight: 600;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      transition: all 0.22s cubic-bezier(0.16, 1, 0.3, 1);
      user-select: none;
      white-space: nowrap;
      position: relative;
      z-index: 1;
      border: 1px solid transparent !important;
      background: transparent !important;
      color: var(--muted) !important;
      box-shadow: none !important;
    }
    .platform-tab svg {
      flex-shrink: 0;
      opacity: 0.7;
      transition: transform 0.22s ease, opacity 0.22s ease;
    }
    .platform-tab:hover {
      color: #fff !important;
      background: rgba(255, 255, 255, 0.07) !important;
      transform: translateY(-1px);
    }
    .platform-tab:hover svg {
      opacity: 1;
      transform: scale(1.08);
    }
    .platform-tab.active {
      color: #ffffff !important;
      background: rgba(47, 191, 113, 0.18) !important;
      border-color: rgba(47, 191, 113, 0.5) !important;
      box-shadow: 0 4px 16px rgba(47, 191, 113, 0.25), inset 0 0 10px rgba(47, 191, 113, 0.08) !important;
    }
    .platform-tab.active svg {
      color: var(--green);
      opacity: 1;
      transform: scale(1.08);
    }
    .visually-hidden {
      position: absolute !important;
      width: 1px !important;
      height: 1px !important;
      padding: 0 !important;
      margin: -1px !important;
      overflow: hidden !important;
      clip: rect(0, 0, 0, 0) !important;
      white-space: nowrap !important;
      border: 0 !important;
    }

    /* Client App Cards */
    .apps {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
      gap: 14px;
      margin-bottom: 24px;
    }
    .app-card {
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 14px 16px;
      cursor: pointer;
      text-align: left;
      transition: all 0.22s cubic-bezier(0.16, 1, 0.3, 1);
      position: relative;
      display: flex;
      align-items: center;
      gap: 12px;
      min-height: 68px;
      user-select: none;
      width: 100%;
      box-sizing: border-box;
    }
    .app-card:hover {
      background: rgba(255, 255, 255, 0.07);
      border-color: rgba(255, 255, 255, 0.2);
      transform: translateY(-2px);
    }
    .app-card.active {
      background: rgba(47, 191, 113, 0.12) !important;
      border-color: rgba(47, 191, 113, 0.5) !important;
      box-shadow: 0 4px 20px rgba(47, 191, 113, 0.2) !important;
    }
    .app-card .app-icon-img {
      width: 40px;
      height: 40px;
      border-radius: 10px;
      object-fit: cover;
      flex-shrink: 0;
      border: 1px solid var(--line);
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
      transition: transform 0.2s ease;
    }
    .app-card:hover .app-icon-img {
      transform: scale(1.05);
    }
    .app-card .app-info {
      display: flex;
      flex-direction: column;
      gap: 2px;
      min-width: 0;
      flex: 1;
    }
    .app-card .app-name-row {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }
    .app-card .app-name {
      font-size: 16px;
      font-weight: 700;
      color: #fff;
      letter-spacing: -0.2px;
    }
    .app-card .app-badge {
      font-size: 10px;
      font-weight: 700;
      padding: 2px 7px;
      border-radius: 6px;
      text-transform: uppercase;
      letter-spacing: 0.4px;
      display: inline-flex;
      align-items: center;
    }
    .app-badge.badge-recommended {
      background: rgba(47, 191, 113, 0.2);
      color: #2fbf71;
      border: 1px solid rgba(47, 191, 113, 0.4);
    }
    .app-badge.badge-backup {
      background: rgba(245, 158, 11, 0.15);
      color: #fbbf24;
      border: 1px solid rgba(245, 158, 11, 0.3);
    }
    .app-badge.badge-ios {
      background: rgba(59, 130, 246, 0.15);
      color: #60a5fa;
      border: 1px solid rgba(59, 130, 246, 0.3);
    }
    .app-badge.badge-auto {
      background: rgba(168, 85, 247, 0.15);
      color: #c084fc;
      border: 1px solid rgba(168, 85, 247, 0.3);
    }
    .app-badge.badge-windows {
      background: rgba(14, 165, 233, 0.15);
      color: #38bdf8;
      border: 1px solid rgba(14, 165, 233, 0.3);
    }
    .app-badge.badge-android {
      background: rgba(34, 197, 94, 0.15);
      color: #4ade80;
      border: 1px solid rgba(34, 197, 94, 0.3);
    }
    .app-badge.badge-singbox {
      background: rgba(249, 115, 22, 0.15);
      color: #fb923c;
      border: 1px solid rgba(249, 115, 22, 0.3);
    }
    .app-card .app-desc {
      font-size: 12px;
      color: var(--muted);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .app-card .app-check {
      width: 22px;
      height: 22px;
      border-radius: 50%;
      border: 1.5px solid var(--line);
      display: grid;
      place-items: center;
      font-size: 12px;
      color: transparent;
      flex-shrink: 0;
      transition: all 0.2s ease;
    }
    .app-card.active .app-check {
      background: var(--green);
      border-color: var(--green);
      color: #000;
      font-weight: 900;
    }

    .steps { display:grid; gap:0; margin-top:8px; }
    .step { position:relative; padding-left:54px; padding-bottom:28px; min-height:86px; }
    .step:before { content:attr(data-num); position:absolute; left:0; top:0; width:38px; height:38px; border-radius:50%; background:#101a14; border:1px solid var(--line); display:grid; place-items:center; font-weight:800; font-size:16px; color:#fff; z-index:2; box-shadow:0 0 12px rgba(0,0,0,.5); }
    .step.done:before { background:var(--green); color:#000; border-color:var(--green); box-shadow:0 0 16px var(--green-glow); }
    .step:not(:last-child):after { content:""; position:absolute; left:18px; top:38px; bottom:0; width:2px; background:linear-gradient(to bottom, rgba(47, 191, 113, .4), var(--line)); }
    .step.done:not(:last-child):after { background:var(--green); }
    .buttons { display:flex; gap:12px; flex-wrap:wrap; margin-top:14px; }
    .button, button {
      min-height:48px;
      padding:10px 20px;
      border-radius:12px;
      border:none;
      font-size:15px;
      font-weight:700;
      text-decoration:none;
      display:inline-flex;
      align-items:center;
      justify-content:center;
      gap:8px;
      transition:all .2s cubic-bezier(0.16, 1, 0.3, 1);
      cursor:pointer;
    }
    .button:hover, button:hover { transform:translateY(-2px); filter:brightness(1.1); }
    .button:active, button:active { transform:translateY(0); }
    .button.secondary, button.secondary {
      background:rgba(255,255,255,0.06);
      color:#fff;
      border:1px solid var(--line);
    }
    .button.secondary:hover, button.secondary:hover { background:rgba(255,255,255,0.12); border-color:rgba(255,255,255,0.25); }
    .button.success { background:linear-gradient(135deg,var(--green),#24a05d); color:#000; }
    .choice-box.active { border-color:var(--green) !important; background:rgba(47,191,113,0.16) !important; box-shadow:0 0 12px var(--green-glow) !important; }
    #renew-plan-selectors.dimmed {
      opacity: 0.35 !important;
      pointer-events: none !important;
      user-select: none !important;
      filter: grayscale(0.85);
    }
    #renew-plan-selectors.dimmed .choice-box.active {
      border-color: var(--line) !important;
      background: rgba(255,255,255,0.03) !important;
      box-shadow: none !important;
    }
    #renew-plan-selectors.dimmed .choice-box span {
      color: var(--muted) !important;
    }
    #renew-plan-selectors.dimmed .choice-box span[style*="background:#f59e0b"] {
      opacity: 0.25 !important;
      box-shadow: none !important;
    }
    textarea { width:100%; max-width:100%; box-sizing:border-box; min-height:94px; margin-top:14px; border:1px solid var(--line); border-radius:12px; background:rgba(0,0,0,0.3); color:var(--text); padding:14px; font:13px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace; resize:vertical; }
    textarea:focus { outline:none; border-color:var(--green); }
    footer { margin-top:30px; text-align:center; padding:24px 0; color:var(--muted); font-size:14px; border-top:1px solid var(--line); }
    footer a { color:var(--muted); text-decoration:none; margin:0 8px; }
    footer a:hover { color:#fff; text-decoration:underline; }
    @media (max-width:640px) {
      main, .shell, main.shell { width:100%; max-width:100%; padding:10px 8px 40px; gap:12px; }
      .shell > section, .shell > div { min-width:0; max-width:100%; }
      .top { padding:12px 14px; flex-direction:column; align-items:stretch; height:auto; gap:10px; }
      .top-actions { display:flex; width:100%; gap:6px; flex-wrap:wrap; }
      .top-btn { flex:1 1 auto; min-height:34px; padding:4px 8px; font-size:11.5px; justify-content:center; text-align:center; white-space:nowrap; }
      .brand { justify-content:center; }
      .brand span { font-size:18px; }
      .brand-logo { width:30px; height:30px; }
      .status { padding:16px; }
      .status-head { gap:12px; margin-bottom:14px; }
      .state-dot { width:36px; height:36px; font-size:16px; flex-shrink:0; }
      h1 { font-size:19px; }
      h2 { font-size:17px; }
      .summary { grid-template-columns:repeat(2,minmax(0,1fr)); gap:8px; }
      .metric { min-height:62px; padding:10px 12px; }
      .metric strong { font-size:14px; word-break:break-all; }
      .metric span { font-size:11px; }
      .install { padding:16px; }
      .install-head { align-items:stretch; flex-direction:column; gap:6px; }
      .platform-selector-card { padding: 12px; margin-bottom: 16px; }
      .platform-nav-track { padding: 4px; gap: 4px; }
      .platform-tab { flex: 0 0 auto; min-width: 76px; min-height: 36px; padding: 5px 8px; font-size: 12px; gap: 5px; }
      .platform-tab svg { width: 14px; height: 14px; }
      .apps { grid-template-columns: 1fr; gap: 10px; margin-bottom: 18px; }
      .app-card { padding: 10px 12px; min-height: 56px; }
      .app-card .app-icon-img { width: 32px; height: 32px; }
      .app-card .app-name { font-size: 14px; }
      .app-card .app-badge { font-size: 9px; padding: 1px 5px; }
      .buttons { display:flex; gap:8px; flex-wrap:wrap; }
      .buttons .button, .buttons button { width:100%; flex:1 1 100%; min-height:44px; font-size:14px; padding:8px 12px; box-sizing:border-box; }
      .step { padding-left:42px; min-height:68px; padding-bottom:18px; }
      .step:before { width:30px; height:30px; font-size:13px; }
      .step:not(:last-child):after { left:14px; top:32px; }
      .step h3 { font-size:15.5px; }
      .step p { font-size:13px; }
      #renew-header { padding: 14px 16px !important; }
      #renew-content { padding: 0 16px 16px 16px !important; }
    }
  </style>
</head>
<body>
  <main class="shell">
    <section class="top">
      <a class="brand" href="__WEB_PAGE_URL__"><img src="__WEB_PAGE_URL__/assets/telegram/avatar.png" alt="SilentConnect" class="brand-logo"><span>SilentConnect</span></a>
      <div class="top-actions">
        <a class="top-btn" href="__WEB_PAGE_URL__">← На сайт к тарифам</a>
        <a class="top-btn" href="__SUPPORT_URL__" target="_blank">Поддержка</a>
        <button class="top-btn" type="button" id="copy-top" title="Скопировать ссылку">Скопировать 🔗</button>
      </div>
    </section>

    <section class="status __STATUS_CLASS__">
      <div class="status-head">
        <div class="state-dot">✓</div>
        <div>
          <h1>__TITLE__</h1>
          <p>__SUBTITLE__ · __DEVICE_LIMIT__</p>
        </div>
      </div>
      <div class="summary">
        <div class="metric">
          <span>Профиль</span>
          <strong>__IDENTIFIER__</strong>
        </div>
        <div class="metric good">
          <span>Статус</span>
          <strong>__STATUS_STR__</strong>
        </div>
        <div class="metric">
          <span>Действует до</span>
          <strong>__EXPIRES_STR__</strong>
        </div>
        <div class="metric">
          <span>Трафик</span>
          <strong>__TRAFFIC_STR__</strong>
        </div>
      </div>
    </section>

    <div id="payment-card-slot">__PAYMENT_CARD_HTML__</div>

    <section class="install renewal-accordion" style="margin-bottom: 24px; background: rgba(47, 191, 113, 0.05); border: 1px solid rgba(47, 191, 113, 0.2); padding: 0;">
      <div id="renew-header" onclick="toggleRenewBuilder()" style="padding:18px 24px; cursor:pointer; display:flex; align-items:center; justify-content:space-between; user-select:none;">
        <h2 style="margin:0; font-size:20px; font-weight:700; display:flex; align-items:center; gap:8px;">⚡ Продлить подписку</h2>
        <span id="renew-arrow" style="font-size:16px; color:var(--green); transition:transform 0.32s cubic-bezier(0.16, 1, 0.3, 1);">▼</span>
      </div>
      
      <div id="renew-wrapper" style="display:grid; grid-template-rows:0fr; transition:grid-template-rows 0.32s cubic-bezier(0.16, 1, 0.3, 1);">
        <div style="overflow:hidden;">
          <div id="renew-content" style="padding:0 24px 24px 24px; border-top:1px solid rgba(255,255,255,0.06); opacity:0; transition:opacity 0.25s cubic-bezier(0.16, 1, 0.3, 1);">
            <p style="color:var(--muted); font-size:14px; margin-top:12px; margin-bottom:16px;">Выберите период продления. При оплате ваш текущий ключ доступа и настройки в приложении сразу продлятся.</p>
            
            __LINKED_EMAIL_BADGE__

            <form method="post" action="/__SECRET_SEGMENT__/renew/__SUB_ID__">
              <input type="hidden" name="device_limit" id="renew_device_limit" value="3">
              <input type="hidden" name="duration_days" id="renew_duration_days" value="360">

              <div class="bind-only-row" style="margin-bottom: 16px; background: rgba(255,255,255,0.03); border: 1px solid var(--line); border-radius: 12px; padding: 12px 14px; transition: all 0.2s ease;">
                <label style="display: flex; align-items: center; gap: 12px; cursor: pointer; user-select: none;">
                  <input type="checkbox" name="bind_email_only" id="bind_email_only" value="1" onchange="toggleBindEmailOnly(this.checked)" style="width: 18px; height: 18px; accent-color: var(--green); cursor: pointer;">
                  <div>
                    <div style="font-weight: 700; font-size: 14.5px; color: #fff;">Только привязать почту (без смены тарифа и оплаты)</div>
                    <div style="font-size: 12px; color: var(--muted); margin-top: 2px;">Для получения напоминаний об окончании за 24ч / 1ч и входа в личный кабинет</div>
                  </div>
                </label>
              </div>

              <div id="renew-plan-selectors" style="transition: opacity 0.25s ease, filter 0.25s ease;">
                <div style="color:var(--muted); font-size:12px; font-weight:600; margin-bottom:6px;">Устройства (одновременно)</div>
                <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap:10px; margin-bottom:16px;">
                  <div class="dev-box choice-box active" data-group="device_limit" data-value="3" onclick="setRenewChoice('device_limit', '3')" style="padding:12px 14px; border:1px solid var(--line); border-radius:10px; background:rgba(255,255,255,0.04); display:flex; align-items:center; justify-content:center; position:relative; min-height:48px; cursor:pointer;">
                    <span style="font-weight:700; font-size:15px; color:#fff;">3 устройства</span>
                  </div>
                  <div class="dev-box choice-box" data-group="device_limit" data-value="6" onclick="setRenewChoice('device_limit', '6')" style="padding:12px 14px; border:1px solid var(--line); border-radius:10px; background:rgba(255,255,255,0.04); display:flex; align-items:center; justify-content:center; position:relative; min-height:48px; cursor:pointer;">
                    <span style="font-weight:700; font-size:15px; color:#fff;">6 устройств</span>
                  </div>
                  <div class="dev-box choice-box" data-group="device_limit" data-value="9" onclick="setRenewChoice('device_limit', '9')" style="padding:12px 14px; border:1px solid var(--line); border-radius:10px; background:rgba(255,255,255,0.04); display:flex; align-items:center; justify-content:center; position:relative; min-height:48px; cursor:pointer;">
                    <span style="font-weight:700; font-size:15px; color:#fff;">9 устройств</span>
                  </div>
                </div>

                <div style="color:var(--muted); font-size:12px; font-weight:600; margin-bottom:6px;">Срок доступа</div>
                <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap:10px; margin-bottom:16px;">
                  <div class="dur-box choice-box" data-group="duration_days" data-value="30" onclick="setRenewChoice('duration_days', '30')" style="padding:10px 12px; border:1px solid var(--line); border-radius:10px; background:rgba(255,255,255,0.04); display:flex; flex-direction:column; justify-content:center; position:relative; cursor:pointer;">
                    <span style="font-weight:700; font-size:15px; color:#fff;">1 месяц</span>
                    <span style="font-size:12px; color:var(--muted);">помесячно</span>
                  </div>
                  <div class="dur-box choice-box" data-group="duration_days" data-value="90" onclick="setRenewChoice('duration_days', '90')" style="padding:10px 12px; border:1px solid var(--line); border-radius:10px; background:rgba(255,255,255,0.04); display:flex; flex-direction:column; justify-content:center; position:relative; cursor:pointer;">
                    <span style="position:absolute; top:-8px; right:-4px; background:#f59e0b; color:#fff; font-weight:800; font-size:10px; padding:2px 6px; border-radius:6px; box-shadow:0 2px 6px rgba(245,158,11,0.4);">−10%</span>
                    <span style="font-weight:700; font-size:15px; color:#fff;">3 месяца</span>
                    <span style="font-size:12px; color:var(--muted);">экономия</span>
                  </div>
                  <div class="dur-box choice-box" data-group="duration_days" data-value="180" onclick="setRenewChoice('duration_days', '180')" style="padding:10px 12px; border:1px solid var(--line); border-radius:10px; background:rgba(255,255,255,0.04); display:flex; flex-direction:column; justify-content:center; position:relative; cursor:pointer;">
                    <span style="position:absolute; top:-8px; right:-4px; background:#f59e0b; color:#fff; font-weight:800; font-size:10px; padding:2px 6px; border-radius:6px; box-shadow:0 2px 6px rgba(245,158,11,0.4);">−20%</span>
                    <span style="font-weight:700; font-size:15px; color:#fff;">6 месяцев</span>
                    <span style="font-size:12px; color:var(--muted);">выгодно</span>
                  </div>
                  <div class="dur-box choice-box active" data-group="duration_days" data-value="360" onclick="setRenewChoice('duration_days', '360')" style="padding:10px 12px; border:1px solid var(--line); border-radius:10px; background:rgba(255,255,255,0.04); display:flex; flex-direction:column; justify-content:center; position:relative; cursor:pointer;">
                    <span style="position:absolute; top:-8px; right:-4px; background:#f59e0b; color:#fff; font-weight:800; font-size:10px; padding:2px 6px; border-radius:6px; box-shadow:0 2px 6px rgba(245,158,11,0.4);">−30%</span>
                    <span style="font-weight:700; font-size:15px; color:#fff;">12 месяцев</span>
                    <span style="font-size:12px; color:var(--muted);">максимум</span>
                  </div>
                </div>
              </div>

              <div id="renew-price-card" style="background:rgba(0,0,0,0.25); border:1px solid var(--line); border-radius:12px; padding:14px; margin-bottom:16px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
                <span id="renew-price-label" style="color:var(--muted); font-size:14px;">Стоимость продления:</span>
                <strong id="renew-total-price" style="font-size:22px; font-weight:800; color:var(--green);">1 249 ₽ <span style="font-size:13px; color:var(--muted); font-weight:400;">(~104 ₽/мес)</span></strong>
              </div>

              <div style="margin-bottom: 12px;">
                <label style="color:var(--muted); font-size:12px; font-weight:600; display:block; margin-bottom:4px;">Электронная почта (для отправки чека и ссылок)</label>
                <input type="email" id="renew_customer_email" name="customer_email" placeholder="pochta@gmail.com" value="__CUSTOMER_EMAIL__" required autocomplete="email" style="width:100%; min-height:44px; background:rgba(0,0,0,0.3); border:1px solid var(--line); border-radius:10px; color:#fff; padding:10px 14px; font-size:15px;">
              </div>

              <div id="renew-promo-row" style="margin-bottom: 12px;">
                <input type="text" name="promo_code" placeholder="Промокод (если есть)" style="width:100%; min-height:40px; background:rgba(0,0,0,0.2); border:1px solid var(--line); border-radius:8px; color:#fff; padding:8px 12px; font-size:14px;">
              </div>

              <div style="font-size:12px; color:var(--muted); margin-bottom:14px; display:flex; flex-direction:column; gap:8px;">
                <label style="display:flex; align-items:center; gap:8px; cursor:pointer;">
                  <input type="checkbox" name="email_reminders" value="1" checked>
                  <span>Напоминать об окончании подписки за 24ч и 1ч на почту</span>
                </label>
                <label style="display:flex; align-items:center; gap:8px; cursor:pointer;">
                  <input type="checkbox" name="terms_ack" value="1" checked required>
                  <span>Согласен с <a href="__WEB_PAGE_URL__/legal/privacy" target="_blank" style="color:var(--green); text-decoration:underline;">политикой конфиденциальности</a> и <a href="__WEB_PAGE_URL__/legal/terms" target="_blank" style="color:var(--green); text-decoration:underline;">офертой</a></span>
                </label>
              </div>

              <div class="cf-turnstile" data-sitekey="0x4AAAAAAD_SNIC95jkFweEh" data-theme="dark" style="margin: 14px 0; display: flex; justify-content: center;"></div>
              <div id="renew-turnstile-error" style="margin: 10px 0; font-size: 13.5px; color: #ef4444; text-align: center; line-height: 1.4; display: none; font-weight: 600;"></div>
              <button type="submit" id="renew-submit-btn" class="button success" style="width:100%; min-height:48px; font-size:16px; font-weight:800; cursor:pointer;">Оплатить продление 💳</button>
            </form>
          </div>
        </div>
      </div>
    </section>

    <section class="install">
      <div class="install-head" style="margin-bottom: 16px;">
        <div>
          <h2>Мастер подключения</h2>
          <p style="margin: 4px 0 0; color: var(--muted); font-size: 14px;">Выберите ваше устройство и приложение для быстрой настройки защищенного доступа:</p>
        </div>
      </div>

      <div class="platform-selector-card">
        <div class="platform-bar-header">
          <div class="platform-bar-title">
            <span style="font-size:16px;">💻</span>
            <span>Операционная система</span>
          </div>
          <span class="platform-bar-hint">Автоопределение: <strong id="detected-platform-label">iOS</strong></span>
        </div>
        <div class="platform-nav-track" id="platform-tabs" role="tablist" aria-label="Выбор операционной системы"></div>
        <select id="platform" class="visually-hidden" aria-hidden="true" tabindex="-1">
          __PLATFORM_OPTIONS_HTML__
        </select>
      </div>

      <div style="margin-bottom: 12px; font-size: 13px; font-weight: 700; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px;">Доступные приложения:</div>
      <div class="apps" id="apps" role="region" aria-live="polite"></div>
      <div class="steps">
        <div class="step" data-num="1">
          <h3>1. Установка клиента</h3>
          <p id="install-text">Скачайте официальное приложение для вашей операционной системы по кнопкам ниже.</p>
          <div class="buttons" id="download-buttons"></div>
        </div>
        <div class="step" data-num="2">
          <h3>2. Автоматический импорт ключа</h3>
          <p>Нажмите «Добавить подписку». Приложение откроется автоматически и применит зашифрованный профиль SilentConnect.</p>
          <div class="buttons"><a class="button success" id="import-link" href="#">Добавить подписку ⚡</a></div>
        </div>
        <div class="step done" data-num="3">
          <h3>3. Активация соединения</h3>
          <p id="usage-text">Откройте приложение и нажмите главную кнопку включения на центральном экране.</p>
        </div>
        <div class="step" data-num="4">
          <h3>4. Резервный способ (ручной импорт)</h3>
          <p>Если бесшовный переход не сработал: скопируйте зашифрованную ссылку ниже в буфер обмена и выберите пункт «Импорт из буфера обмена» (Import from Clipboard) в настройках приложения.</p>
          <div class="buttons"><button class="secondary" type="button" id="copy-sub">Скопировать ссылку 🔗</button></div>
          <textarea id="sub" readonly>__ESCAPED_SUBSCRIPTION__</textarea>
        </div>
      </div>
    </section>

    <footer>
      SilentConnect · 
      <a href="__WEB_PAGE_URL__/about" target="_blank">О сервисе</a> · 
      <a href="__WEB_PAGE_URL__/contact" target="_blank">Контакты &amp; Поддержка</a> · 
      <a href="__WEB_PAGE_URL__/legal/privacy" target="_blank">Политика конфиденциальности</a> · 
      <a href="__WEB_PAGE_URL__/legal/terms" target="_blank">Пользовательское соглашение</a> · 
      <a href="__WEB_PAGE_URL__/legal/refund" target="_blank">Политика возвратов</a>
    </footer>
  </main>
  <script>
  (() => {
    const apps = __APPS_JSON__;
    const platformLabels = __PLATFORM_LABELS_JSON__;
    const platform = document.getElementById("platform");
    const appsBox = document.getElementById("apps");
    const importLink = document.getElementById("import-link");
    const downloadButtons = document.getElementById("download-buttons");
    const installText = document.getElementById("install-text");
    const usageText = document.getElementById("usage-text");
    let currentApp = "happ";

    const platformsData = [
      { id: "ios", label: "iOS", icon: '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 0.77-3.27 0.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5 0.87 3.29 0.87 0.78 0 2.26-1.07 3.81-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M15.97 6.37c.62-.75 1.04-1.8 0.92-2.85-.9.04-1.99.6-2.64 1.36-.57.65-1.07 1.72-.94 2.74 1.01.08 2.04-.5 2.66-1.25z"/></svg>' },
      { id: "android", label: "Android", icon: '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M17.52 15.34c-.55 0-1-.45-1-1s.45-1 1-1 1 .45 1 1-.45 1-1 1m-11.04 0c-.55 0-1-.45-1-1s.45-1 1-1 1 .45 1 1-.45 1-1 1m11.4-6.02l2-3.46c.12-.2.05-.47-.15-.57-.2-.12-.47-.05-.57.15l-2.02 3.5C15.59 8.41 13.85 8.08 12 8.08s-3.59.33-5.14.87L4.84 5.45c-.1-.2-.37-.27-.57-.15-.2.1-.27.37-.15.57l2 3.46C2.69 11.19.34 14.66 0 18.76h24c-.34-4.1-2.69-7.57-6.12-9.44"/></svg>' },
      { id: "windows", label: "Windows", icon: '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M0 3.45L9.75 2.1v9.45H0m10.95-9.6L24 0v11.4H10.95M0 12.6h9.75v9.45L0 20.7M10.95 12.6H24V24l-13.05-1.8"/></svg>' },
      { id: "macos", label: "macOS", icon: '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M20 18c1.1 0 1.99-.9 1.99-2L22 6c0-1.1-.9-2-2-2H4c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2H0v2h24v-2h-4zM4 6h16v10H4V6z"/></svg>' },
      { id: "linux", label: "Linux", icon: '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M12 2C9.5 2 7.5 4 7.5 6.5c0 .3.03.6.1.9C6.5 8.1 5.5 9.7 5.5 11.5c0 .4.05.7.1 1-1.4.7-2.6 2.2-2.6 4 0 2.2 1.8 4 4 4h.2c.2.6.5 1.3.8 2 0 1.9 2.2 3.5 5 3.5s5-1.6 5-3.5c.3-.7.6-1.4.8-2H19c2.2 0 4-1.8 4-4 0-1.8-1.2-3.3-2.6-4 .1-.3.1-.6.1-1 0-1.8-1-3.4-2.1-4.1.1-.3.1-.6.1-.9C18.5 4 16.5 2 12 2zm-2 7c.6 0 1 .4 1 1s-.4 1-1 1-1-.4-1-1 .4-1 1-1zm4 0c.6 0 1 .4 1 1s-.4 1-1 1-1-.4-1-1 .4-1 1-1zm-2 2.5c1.1 0 2 .5 2 1.2 0 .6-.9 1.3-2 1.3s-2-.7-2-1.3c0-.7.9-1.2 2-1.2z"/></svg>' },
      { id: "androidtv", label: "Android TV", icon: '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M21 3H3c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h5v2h8v-2h5c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm0 14H3V5h18v12z"/><circle cx="8" cy="11" r="1.2"/><circle cx="16" cy="11" r="1.2"/><path d="M10 8l-1.5-2m5.5 2l1.5-2"/></svg>' },
      { id: "appletv", label: "Apple TV", icon: '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M21 3H3c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h5v2h8v-2h5c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm0 14H3V5h18v12zm-8.8-3.3c-.6.8-1.2 1.6-2.1 1.6-.9 0-1.2-.5-2.2-.5-1 0-1.4.5-2.2.5-.9 0-1.6-.9-2.2-1.7-1.2-1.7-2.1-4.8-.9-6.9.6-1 1.7-1.7 2.8-1.7.9 0 1.7.6 2.3 0.6 0.5 0 1.5-.7 2.6-.6.4 0 1.7.2 2.5 1.3 -0.1 0.1 -1.5 0.9 -1.5 2.6 0 2.1 1.8 2.8 1.9 2.8 -0.1 0.1 -0.3 1 -0.8 1.9z"/></svg>' }
    ];

    function detectPlatform() {
      const ua = navigator.userAgent || "";
      const platformName = navigator.platform || "";
      if (/iPad|iPhone|iPod/i.test(ua)) return "ios";
      if (/Android/i.test(ua)) return /TV|AFT|BRAVIA|SMART-TV/i.test(ua) ? "androidtv" : "android";
      if (/Windows/i.test(ua)) return "windows";
      if (/Mac/i.test(platformName)) return "macos";
      if (/Linux/i.test(platformName)) return "linux";
      return "ios";
    }

    function appAvailable(app, value) {
      return app.platforms.indexOf(value) !== -1;
    }

    function preferredApp(value) {
      const current = apps.find((app) => app.id === currentApp);
      if (current && appAvailable(current, value)) return currentApp;
      const happ = apps.find((app) => app.id === "happ" && appAvailable(app, value));
      if (happ) return "happ";
      const first = apps.find((app) => appAvailable(app, value));
      return first ? first.id : "happ";
    }

    function renderPlatformTabs() {
      const track = document.getElementById("platform-tabs");
      if (!track) return;
      track.innerHTML = "";
      const currentVal = platform.value;
      platformsData.forEach((p) => {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "platform-tab" + (p.id === currentVal ? " active" : "");
        btn.setAttribute("role", "tab");
        btn.setAttribute("aria-selected", p.id === currentVal ? "true" : "false");
        btn.setAttribute("tabindex", p.id === currentVal ? "0" : "-1");
        btn.innerHTML = p.icon + '<span>' + p.label + '</span>';
        btn.addEventListener("click", () => {
          selectPlatform(p.id);
        });
        track.appendChild(btn);
      });
    }

    function selectPlatform(val) {
      platform.value = val;
      renderPlatformTabs();
      renderApps();
      const activeBtn = document.querySelector('.platform-tab.active');
      if (activeBtn) {
        activeBtn.scrollIntoView({ behavior: "smooth", inline: "center", block: "nearest" });
      }
    }

    function renderApps() {
      appsBox.innerHTML = "";
      const value = platform.value;
      currentApp = preferredApp(value);
      const availableApps = apps.filter((app) => appAvailable(app, value));
      availableApps.forEach((app) => {
        const card = document.createElement("button");
        card.type = "button";
        const isActive = app.id === currentApp;
        card.className = "app-card" + (isActive ? " active" : "");
        
        let badgeClass = "badge-recommended";
        const badgeLower = (app.badge || "").toLowerCase();
        if (badgeLower.includes("ios") || badgeLower.includes("macos")) badgeClass = "badge-ios";
        else if (badgeLower.includes("запас")) badgeClass = "badge-backup";
        else if (badgeLower.includes("авто")) badgeClass = "badge-auto";
        else if (badgeLower.includes("windows")) badgeClass = "badge-windows";
        else if (badgeLower.includes("android")) badgeClass = "badge-android";
        else if (badgeLower.includes("sing")) badgeClass = "badge-singbox";
        
        const badgeHtml = app.badge ? '<span class="app-badge ' + badgeClass + '">' + app.badge + '</span>' : '';
        
        card.innerHTML = 
          '<img class="app-icon-img" src="' + app.iconUrl + '" alt="' + app.name + '" />' +
          '<div class="app-info">' +
            '<div class="app-name-row">' +
              '<span class="app-name">' + app.name + '</span>' +
              badgeHtml +
            '</div>' +
          '</div>' +
          '<div class="app-check">' + (isActive ? '✓' : '') + '</div>';
          
        card.addEventListener("click", () => {
          currentApp = app.id;
          renderApps();
          renderSelected();
        });
        appsBox.appendChild(card);
      });
      renderSelected();
    }

    function renderSelected() {
      const value = platform.value;
      const app = apps.find((item) => item.id === currentApp) || apps[0];
      importLink.href = app.importUrl;
      installText.textContent = app.description + " Операционная система: " + (platformLabels[value] || value) + ".";
      const usageMap = {
        happ: "Запустите Happ и нажмите большую центральную кнопку включения. При первом запуске разрешите системе добавление сетевого профиля в появившемся запросе.",
        streisand: "Откройте Streisand, подтвердите добавление профиля SilentConnect и переключите верхний тумблер в активное состояние.",
        clash: "Откройте Clash / Mihomo, выберите профиль SilentConnect и включите системный прокси (System Proxy).",
        v2rayn: "Откройте v2rayN, вставьте ссылку подписки через «Подписка» → «Настройки подписок», нажмите «Обновить подписки» и выберите узел для подключения.",
        nekobox: "Откройте NekoBox, обновите подписку через меню и нажмите круглую кнопку запуска внизу экрана.",
        v2rayng: "Откройте v2rayNG, обновите подписку через верхнее меню и нажмите кнопку подключения с буквой V.",
        singbox: "Откройте Sing-box, импортируйте профиль SilentConnect и нажмите кнопку включения.",
        v2raytun: "Откройте V2RayTun, выберите профиль SilentConnect и нажмите значок подключения внизу экрана."
      };
      usageText.textContent = usageMap[app.id] || "Откройте приложение, добавьте подписку SilentConnect и нажмите кнопку подключения.";
      downloadButtons.innerHTML = "";
      (app.downloads[value] || []).forEach((item) => {
        const link = document.createElement("a");
        link.className = "button secondary";
        link.href = item.url;
        link.target = "_blank";
        link.rel = "noopener";
        link.textContent = item.label;
        downloadButtons.appendChild(link);
      });
      if (!downloadButtons.children.length) {
        const note = document.createElement("span");
        note.className = "button secondary";
        note.textContent = "Откройте страницу загрузки приложения";
        downloadButtons.appendChild(note);
      }
    }

    async function copySubscription(button) {
      await navigator.clipboard.writeText(document.getElementById("sub").value);
      const original = button.textContent;
      button.textContent = "Скопировано! ✓";
      window.setTimeout(() => button.textContent = original, 1600);
    }

    window.toggleRenewBuilder = function(forceOpen) {
      const wrapper = document.getElementById("renew-wrapper");
      const content = document.getElementById("renew-content");
      const arrow = document.getElementById("renew-arrow");
      if (!wrapper || !content || !arrow) return;
      const isOpen = wrapper.style.gridTemplateRows === "1fr";
      const shouldOpen = forceOpen !== undefined ? forceOpen : !isOpen;
      if (shouldOpen) {
        wrapper.style.gridTemplateRows = "1fr";
        content.style.opacity = "1";
        arrow.style.transform = "rotate(180deg)";
      } else {
        wrapper.style.gridTemplateRows = "0fr";
        content.style.opacity = "0";
        arrow.style.transform = "rotate(0deg)";
      }
    };

    window.setRenewChoice = function(group, val) {
      const input = document.getElementById("renew_" + group);
      if (input) {
        input.value = String(val);
      }
      const boxes = document.querySelectorAll('.choice-box[data-group="' + group + '"]');
      boxes.forEach((box) => {
        box.classList.toggle("active", box.dataset.value === String(val));
      });
      window.updateRenewPrice();
    };

    window.toggleBindEmailOnly = function(checked) {
      const selectors = document.getElementById("renew-plan-selectors");
      const promoRow = document.getElementById("renew-promo-row");
      const priceLabel = document.getElementById("renew-price-label");
      const priceBox = document.getElementById("renew-total-price");
      const submitBtn = document.getElementById("renew-submit-btn");

      if (selectors) {
        selectors.classList.toggle("dimmed", Boolean(checked));
      }
      if (promoRow) {
        promoRow.style.display = checked ? "none" : "block";
      }
      if (priceBox && priceLabel) {
        if (checked) {
          priceLabel.textContent = "Стоимость:";
          priceBox.innerHTML = '0 ₽ <span style="font-size:13px; color:var(--green); font-weight:600;">(Бесплатно)</span>';
        } else {
          priceLabel.textContent = "Стоимость продления:";
          window.updateRenewPrice();
        }
      }
      if (submitBtn) {
        submitBtn.innerHTML = checked ? "Привязать почту бесплатно ✉️" : "Оплатить продление 💳";
      }
    };

    window.updateRenewPrice = function() {
      const bindOnly = document.getElementById("bind_email_only");
      if (bindOnly && bindOnly.checked) {
        return;
      }
      const devInput = document.getElementById("renew_device_limit");
      const durInput = document.getElementById("renew_duration_days");
      if (!devInput || !durInput) return;
      const dev = parseInt(devInput.value, 10) || 3;
      const dur = parseInt(durInput.value, 10) || 360;
      const baseMonthly = dev === 9 ? 349 : (dev === 6 ? 249 : 149);
      const months = Math.max(Math.floor(dur / 30), 1);
      let discount = 0;
      if (dur === 90) discount = 10;
      else if (dur === 180) discount = 20;
      else if (dur === 360) discount = 30;
      const raw = Math.floor((baseMonthly * months * (100 - discount)) / 100);
      let finalPrice = raw <= 0 ? 0 : Math.max(Math.floor((raw + 5) / 10) * 10 - 1, 9);
      const perMonth = Math.round(finalPrice / months);
      const priceBox = document.getElementById("renew-total-price");
      if (priceBox) {
        priceBox.innerHTML = finalPrice.toLocaleString("ru-RU") + ' ₽ <span style="font-size:13px; color:var(--muted); font-weight:400;">(~' + perMonth + ' ₽/мес)</span>';
      }
    };

    document.addEventListener("submit", async function(event) {
      const form = event.target;
      if (!form || !form.action) return;
      const action = form.action;
      if (action.includes("/renew/") || action.includes("/paid/") || action.includes("/cancel/")) {
        if (action.includes("/renew/")) {
          const turnstileToken = (form.querySelector('[name="cf-turnstile-response"]') || {}).value || (window.turnstile ? window.turnstile.getResponse() : "");
          const errBox = document.getElementById("renew-turnstile-error");
          if (!turnstileToken) {
            event.preventDefault();
            if (errBox) {
              errBox.style.display = "block";
              errBox.textContent = "Пожалуйста, подтвердите, что вы человек (поставьте галочку Cloudflare).";
            }
            return false;
          }
          if (errBox) errBox.style.display = "none";
        }
        event.preventDefault();
        const btn = form.querySelector('button[type="submit"]');
        let oldText = "";
        if (btn) {
          oldText = btn.textContent;
          btn.disabled = true;
          btn.textContent = "Обработка...";
        }
        try {
          const res = await fetch(action, {
            method: "POST",
            headers: {
              "Accept": "application/json",
              "Content-Type": "application/x-www-form-urlencoded",
              "X-Requested-With": "XMLHttpRequest"
            },
            body: new URLSearchParams(new FormData(form))
          });
          const data = await res.json();
          if (data && data.html !== undefined) {
            const slot = document.getElementById("payment-card-slot");
            if (slot) {
              slot.innerHTML = data.html;
              if (data.html) {
                slot.scrollIntoView({ behavior: "smooth", block: "nearest" });
              }
              if (window.startOrderStatusPolling && !data.bind_email_only) {
                window.startOrderStatusPolling();
              }
            }
            if (data.bind_email_only && data.masked_email) {
              const badge = document.getElementById("linked-email-badge");
              const text = document.getElementById("linked-email-text");
              if (badge) badge.style.display = "flex";
              if (text) text.textContent = data.masked_email;
              const bindInput = document.getElementById("bind_email_only");
              if (bindInput) {
                bindInput.checked = false;
                window.toggleBindEmailOnly(false);
              }
              if (window.turnstile) {
                try { window.turnstile.reset(); } catch(e) {}
              }
            }
          }
        } catch (err) {
          form.submit();
        } finally {
          if (btn) {
            btn.disabled = false;
            btn.textContent = oldText;
          }
        }
      }
    });

    window.dismissPaymentNotice = function(orderId) {
      const card = document.getElementById("paymentNoticeCard");
      if (card) {
        card.style.opacity = "0";
        card.style.transform = "translateY(-6px)";
        setTimeout(() => { card.style.display = "none"; }, 250);
      }
      const currentStatus = card ? (card.getAttribute("data-order-status") || "dismissed") : "dismissed";
      try {
        localStorage.setItem("sc_dismissed_notice_" + orderId, currentStatus);
      } catch(e){}
    };

    function initNoticeState() {
      const card = document.getElementById("paymentNoticeCard");
      if (!card) return;
      const orderId = card.getAttribute("data-order-id");
      const currentStatus = card.getAttribute("data-order-status");
      try {
        const dismissedStatus = localStorage.getItem("sc_dismissed_notice_" + orderId);
        if (dismissedStatus === currentStatus) {
          card.style.display = "none";
        }
      } catch(e){}
    }

    let statusPollInterval = null;
    window.startOrderStatusPolling = function() {
      if (statusPollInterval) {
        clearInterval(statusPollInterval);
        statusPollInterval = null;
      }
      const card = document.getElementById("paymentNoticeCard");
      if (!card) return;
      const orderId = card.getAttribute("data-order-id");
      let status = card.getAttribute("data-order-status");
      if (!orderId || status === "paid" || status === "delivered" || status === "canceled") return;

      let pollCount = 0;
      statusPollInterval = setInterval(async () => {
        pollCount++;
        if (pollCount > 150) { clearInterval(statusPollInterval); return; }
        try {
          const res = await fetch("/__SECRET_SEGMENT__/order-status/" + orderId);
          if (!res.ok) return;
          const data = await res.json();
          if (!data || !data.ok) return;

          const currentCard = document.getElementById("paymentNoticeCard");
          if (!currentCard) return;

          if (data.status === "paid" || data.status === "delivered") {
            clearInterval(statusPollInterval);
            currentCard.setAttribute("data-order-status", "paid");
            currentCard.style.display = "block";
            currentCard.style.background = "rgba(47, 191, 113, 0.12)";
            currentCard.style.border = "1px solid #2fbf71";
            currentCard.style.opacity = "1";
            currentCard.style.transform = "none";

            const title = document.getElementById("noticeTitle");
            const body = document.getElementById("noticeBody");
            if (title) {
              title.style.color = "#2fbf71";
              title.innerHTML = "✓ Оплата подтверждена!";
            }
            if (body) {
              const emailInfo = data.customer_email ? " на почту <strong>" + data.customer_email + "</strong>" : "";
              body.innerHTML = "Мы зачислили продление по заказу <strong>#" + data.public_id + "</strong>: <strong>+" + data.duration_days + " дн.</strong> (до " + data.device_limit + " устр.). Уведомление и чек отправлены" + emailInfo + ". Приятного пользования!";
            }
          } else if (data.status === "canceled") {
            clearInterval(statusPollInterval);
            currentCard.setAttribute("data-order-status", "canceled");
            currentCard.style.display = "block";
            currentCard.style.background = "rgba(239, 68, 68, 0.12)";
            currentCard.style.border = "1px solid rgba(239, 68, 68, 0.5)";
            currentCard.style.opacity = "1";
            currentCard.style.transform = "none";

            const title = document.getElementById("noticeTitle");
            const body = document.getElementById("noticeBody");
            if (title) {
              title.style.color = "#ef4444";
              title.innerHTML = "✖ Заказ отменен";
            }
            if (body) {
              body.innerHTML = 'Заказ <strong>#' + data.public_id + '</strong> отменен администратором. Пожалуйста, попробуйте оформить заказ заново или <a href="' + '__SUPPORT_URL__' + '" target="_blank" style="color:#ef4444; text-decoration:underline; font-weight:600;">свяжитесь с поддержкой</a>.';
            }
          }
        } catch (err) {
          console.debug("Status poll error:", err);
        }
      }, 4000);
    };

    const track = document.getElementById("platform-tabs");
    if (track) {
      track.addEventListener("keydown", (e) => {
        const tabs = Array.from(track.querySelectorAll(".platform-tab"));
        const currentIdx = tabs.findIndex(t => t.classList.contains("active"));
        if (currentIdx === -1) return;
        let nextIdx = -1;
        if (e.key === "ArrowRight" || e.key === "ArrowDown") {
          e.preventDefault();
          nextIdx = (currentIdx + 1) % tabs.length;
        } else if (e.key === "ArrowLeft" || e.key === "ArrowUp") {
          e.preventDefault();
          nextIdx = (currentIdx - 1 + tabs.length) % tabs.length;
        } else if (e.key === "Home") {
          e.preventDefault();
          nextIdx = 0;
        } else if (e.key === "End") {
          e.preventDefault();
          nextIdx = tabs.length - 1;
        }
        if (nextIdx !== -1) {
          const targetPlatform = platformsData[nextIdx].id;
          selectPlatform(targetPlatform);
          const newActive = track.querySelectorAll(".platform-tab")[nextIdx];
          if (newActive) newActive.focus();
        }
      });
    }

    const detected = detectPlatform();
    platform.value = detected;
    const detectedLabel = document.getElementById("detected-platform-label");
    if (detectedLabel) {
      detectedLabel.textContent = platformLabels[detected] || detected;
    }
    platform.addEventListener("change", () => selectPlatform(platform.value));
    document.getElementById("copy-sub").addEventListener("click", (event) => copySubscription(event.currentTarget));
    document.getElementById("copy-top").addEventListener("click", (event) => copySubscription(event.currentTarget));
    renderPlatformTabs();
    renderApps();
    window.updateRenewPrice();
    initNoticeState();
    window.startOrderStatusPolling();
  })();
  </script>
</body>

</html>"""

    result = template.replace("__SUPPORT_URL__", support_url)
    result = result.replace("__STATUS_CLASS__", status_class)
    result = result.replace("__TITLE__", title)
    result = result.replace("__SUBTITLE__", subtitle)
    result = result.replace("__DEVICE_LIMIT__", device_limit)
    result = result.replace("__IDENTIFIER__", identifier)
    result = result.replace("__STATUS_STR__", status_str)
    result = result.replace("__EXPIRES_STR__", expires_str)
    result = result.replace("__TRAFFIC_STR__", traffic_str)
    result = result.replace("__PLATFORM_OPTIONS_HTML__", platform_options_html)
    result = result.replace("__ESCAPED_SUBSCRIPTION__", escaped_subscription)
    result = result.replace("__SUB_ID__", subscription_id)
    result = result.replace("__SECRET_SEGMENT__", SECRET_SEGMENT)
    masked_email = mask_email(customer_email) if customer_email else ""
    linked_badge_style = "display:flex;" if customer_email else "display:none;"
    linked_badge_html = f"""
    <div id="linked-email-badge" style="{linked_badge_style} background:rgba(47,191,113,0.08); border:1px solid rgba(47,191,113,0.25); border-radius:12px; padding:12px 16px; margin-bottom:14px; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:8px;">
      <span style="color:#fff; font-size:13.5px; font-weight:600; display:flex; align-items:center; gap:8px;">
        <span style="font-size:16px;">✅</span> Почта привязана: <strong id="linked-email-text" style="color:var(--green);">{html.escape(masked_email)}</strong>
      </span>
      <span style="color:var(--muted); font-size:12px;">Уведомления за 24ч/1ч и вход в кабинет активны</span>
    </div>
    """
    result = result.replace("__LINKED_EMAIL_BADGE__", linked_badge_html)
    result = result.replace("__CUSTOMER_EMAIL__", html.escape(customer_email))
    result = result.replace("__PAYMENT_CARD_HTML__", payment_card_html)
    result = result.replace("__APPS_JSON__", apps_json)
    result = result.replace("__PLATFORM_LABELS_JSON__", platform_labels_json)
    result = result.replace("__WEB_PAGE_URL__", HAPP_WEB_PAGE_URL)

    return result.encode("utf-8")


def legal_terms_html() -> bytes:
    updated_at = "26.04.2026"
    return f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex,nofollow,noarchive">
  <title>Пользовательское соглашение SilentConnect.net</title>
  <style>
    body {{ margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #0f1317; color: #eef2f3; overflow-x: hidden; }}
    main {{ max-width: 920px; margin: 0 auto; padding: 34px 18px 56px; box-sizing: border-box; }}
    h1, h2, p, li {{ overflow-wrap: break-word; word-wrap: break-word; }}
    h1 {{ font-size: clamp(20px, 5.5vw, 30px); line-height: 1.25; margin: 0 0 8px; }}
    h2 {{ font-size: 20px; margin: 28px 0 10px; }}
    p, li {{ line-height: 1.55; color: #cbd4d8; }}
    ul {{ padding-left: 22px; }}
    .meta {{ color: #8fa1aa; margin-bottom: 24px; }}
    .note {{ padding: 14px 16px; border: 1px solid #31404a; border-radius: 8px; background: #151c22; }}
    a {{ color: #8cc7ff; }}
  </style>
</head>
<body>
  <main>
    <h1>Пользовательское соглашение и политика конфиденциальности SilentConnect</h1>
    <p class="meta">Редакция от {updated_at}</p>
    <p class="note">Этот документ описывает условия использования сервиса SilentConnect, правила допустимого использования и подход к обработке данных. Если Вы не согласны с условиями, не используйте сервис.</p>

    <h2>1. Общие положения</h2>
    <p>SilentConnect предоставляет технический сервис защищённого сетевого подключения. Сервис предназначен для повышения приватности, безопасности соединения и доступа к легальным интернет-ресурсам.</p>
    <p>Используя бота, подписочную ссылку, конфигурацию или иную часть сервиса, пользователь подтверждает принятие настоящего соглашения.</p>

    <h2>2. Возраст и дееспособность</h2>
    <p>Нажимая кнопку подтверждения в боте или продолжая использовать сервис, пользователь подтверждает, что ему исполнилось 18 лет, он обладает необходимой дееспособностью и вправе самостоятельно принимать настоящие условия.</p>
    <p>Если пользователь не достиг 18 лет, использование сервиса допускается только с согласия и под ответственностью законного представителя, если это разрешено применимым правом.</p>

    <h2>3. Ответственность пользователя</h2>
    <p>Пользователь самостоятельно выбирает сайты, приложения, сервисы, файлы и иные ресурсы, к которым обращается через интернет, и самостоятельно несёт ответственность за законность своих действий.</p>
    <p>Сервис не инициирует передачу данных пользователя, не выбирает получателей трафика, не определяет цели действий пользователя и не одобряет незаконное использование интернета.</p>
    <p>Запрещается использовать SilentConnect для действий, нарушающих применимое законодательство, права третьих лиц или правила интернет-площадок, включая, но не ограничиваясь:</p>
    <ul>
      <li>мошенничество, фишинг, спам, распространение вредоносного ПО;</li>
      <li>несанкционированный доступ, атаки на сети, сканирование уязвимостей без разрешения;</li>
      <li>распространение запрещённых материалов или незаконного контента;</li>
      <li>нарушение авторских и смежных прав;</li>
      <li>действия, которые могут привести к блокировке, жалобам, ущербу сервису или третьим лицам.</li>
    </ul>
    <p>При признаках злоупотребления администрация вправе ограничить, приостановить или прекратить доступ к сервису без компенсации, если иное прямо не согласовано отдельно.</p>

    <h2>4. Ограничение ответственности сервиса</h2>
    <p>Сервис предоставляется «как есть». Мы стремимся поддерживать стабильность и качество подключения, но не гарантируем непрерывную доступность, определённую скорость, доступность конкретных сайтов или отсутствие ограничений со стороны третьих лиц.</p>
    <p>Администрация не несёт ответственность за действия пользователя в интернете, решения третьих сайтов и сервисов, блокировки аккаунтов пользователя, изменение правил сторонних площадок, работу интернет-провайдера пользователя, устройства или приложения-клиента.</p>

    <h2>5. Конфиденциальность и технические журналы</h2>
    <p>SilentConnect придерживается принципа минимизации данных. Мы не ведём журналы посещённых сайтов, истории браузинга, содержимого трафика, DNS-запросов пользователя и переписки пользователя в сторонних сервисах.</p>
    <p>В силу технической архитектуры мы не просматриваем содержимое пользовательского трафика и не ведём базу, позволяющую штатно восстановить, какие именно сайты или материалы посещал конкретный пользователь.</p>
    <p>При этом для работы сервиса могут обрабатываться служебные данные, необходимые для выдачи доступа, оплаты, поддержки и безопасности:</p>
    <ul>
      <li>Telegram user_id, chat_id, username и имя профиля, если они переданы Telegram;</li>
      <li>данные заказа, промокода, реферальной программы, статуса оплаты и срока доступа;</li>
      <li>идентификатор профиля, подписочная ссылка, технический идентификатор клиента и счётчики использования трафика;</li>
      <li>сообщения, скриншоты и иные сведения, которые пользователь добровольно отправляет в поддержку;</li>
      <li>технические события, необходимые для диагностики ошибок бота, панели, подписочного сервиса и инфраструктуры.</li>
    </ul>
    <p>Мы не продаём персональные данные пользователей и не используем историю интернет-активности для рекламы.</p>

    <h2>6. Обработка персональных данных</h2>
    <p>Обработка данных осуществляется для предоставления доступа, поддержки пользователей, выполнения договорённостей по оплате, предотвращения злоупотреблений, ведения учёта заказов и выполнения требований применимого законодательства.</p>
    <p>Данные хранятся не дольше, чем это необходимо для указанных целей, если более долгий срок хранения не требуется для защиты прав, разрешения споров, безопасности или исполнения закона.</p>
    <p>Пользователь может обратиться в поддержку для уточнения, удаления или ограничения обработки своих данных, если это технически возможно и не противоречит законным основаниям дальнейшего хранения.</p>
    <p>Для работы сервиса могут использоваться сторонние поставщики инфраструктуры и коммуникаций, включая Telegram, хостинг-провайдеров, платёжные и банковские сервисы, а также магазины приложений. Их обработка данных регулируется их собственными условиями и политиками.</p>

    <h2>7. Законные запросы и безопасность</h2>
    <p>Мы не создаём специальные журналы активности пользователей для последующей передачи третьим лицам. При законном и обязательном требовании компетентных органов администрация может предоставить только те данные, которые фактически имеются в распоряжении сервиса на момент запроса.</p>
    <p>Мы применяем разумные технические и организационные меры для защиты служебных данных, но ни один интернет-сервис не может гарантировать абсолютную безопасность.</p>

    <h2>8. Оплата, доступ и ссылки</h2>
    <p>Подписочная ссылка является персональным ключом доступа. Пользователь обязан хранить её аккуратно и не передавать третьим лицам, если отдельные условия доступа не предусматривают иное.</p>
    <p>Продление, восстановление, замена конфигураций, пробный период, промокоды и реферальная программа регулируются условиями, указанными в боте или согласованными с поддержкой.</p>

    <h2>9. Изменение условий</h2>
    <p>Администрация может обновлять настоящее соглашение. Новая редакция применяется после публикации на этой странице или уведомления в боте, если иное не указано в самой редакции.</p>

    <h2>10. Контакт</h2>
    <p>По вопросам доступа, конфиденциальности, удаления данных или жалоб на злоупотребления обращайтесь в службу поддержки.</p>
  </main>
</body>
</html>""".encode("utf-8")


def build_streisand_import_url(subscription_url: str, name: str = "SilentConnect") -> str:
    encoded_name = urllib.parse.quote(name, safe="")
    return f"streisand://import/{subscription_url}#{encoded_name}"


def build_v2raytun_import_url(subscription_url: str) -> str:
    return f"v2raytun://import/{subscription_url}"


def iter_config_payloads(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def iter_outbound_hosts(payload: Any) -> list[str]:
    hosts: list[str] = []
    for config in iter_config_payloads(payload):
        for outbound in config.get("outbounds") or []:
            if not isinstance(outbound, dict):
                continue
            settings = outbound.get("settings")
            if not isinstance(settings, dict):
                continue

            for vnext in settings.get("vnext") or []:
                if isinstance(vnext, dict):
                    address = str(vnext.get("address") or "").strip()
                    if address and address not in hosts:
                        hosts.append(address)

            for server in settings.get("servers") or []:
                if isinstance(server, dict):
                    address = str(server.get("address") or "").strip()
                    if address and address not in hosts:
                        hosts.append(address)
    return hosts


def happ_exclude_routes(payload: Any) -> list[str]:
    routes: list[str] = []

    for value in parse_csv_values(HAPP_EXTRA_EXCLUDE_ROUTES):
        route = normalize_ipv4_route(value)
        if route and route not in routes:
            routes.append(route)

    for host in iter_outbound_hosts(payload):
        for route in resolve_ipv4_routes(host):
            if route not in routes:
                routes.append(route)

    return routes


def build_happ_response_headers(
    payload: Any,
    *,
    subscription_id: str | None = None,
    profile_web_page_url: str | None = None,
    profile_title: str | None = None,
    server_address_resolve_enabled: bool = True,
    fragmentation_enabled: bool = True,
    include_exclude_routes: bool = False,
    fallback_url: str | None = None,
) -> dict[str, str]:
    if not HAPP_HEADERS_ENABLED:
        return {}
    configs = iter_config_payloads(payload)
    if not configs:
        return {}
    if any(not isinstance(config.get("outbounds"), list) or not isinstance(config.get("inbounds"), list) for config in configs):
        return {}

    headers: dict[str, str] = {}
    title = profile_title if profile_title is not None else HAPP_PROFILE_TITLE
    if title:
        headers["profile-title"] = title[:25]
    if HAPP_PROFILE_UPDATE_INTERVAL:
        headers["profile-update-interval"] = HAPP_PROFILE_UPDATE_INTERVAL
    if subscription_id:
        try:
            headers["subscription-userinfo"] = happ_subscription_userinfo(subscription_id)
        except Exception:
            LOGGER.warning("Unable to build Happ subscription-userinfo for %s", subscription_id, exc_info=True)
    if HAPP_SUPPORT_URL:
        headers["support-url"] = HAPP_SUPPORT_URL
    web_page_url = profile_web_page_url or HAPP_WEB_PAGE_URL
    if web_page_url:
        headers["profile-web-page-url"] = web_page_url

    if not HAPP_PROVIDER_ID:
        return headers

    headers.update(
        {
            "providerid": HAPP_PROVIDER_ID,
            "tun-enable": "1",
            "proxy-enable": "0",
            "server-address-resolve-enable": "1" if server_address_resolve_enabled else "0",
            "fragmentation-enable": "1" if fragmentation_enabled else "0",
            "per-app-proxy-mode": "off",
        }
    )
    if server_address_resolve_enabled:
        headers["server-address-resolve-dns-domain"] = HAPP_RESOLVE_DNS_DOMAIN
        headers["server-address-resolve-dns-ip"] = HAPP_RESOLVE_DNS_IP

    if include_exclude_routes:
        exclude_routes = happ_exclude_routes(payload)
        if exclude_routes:
            headers["exclude-routes"] = ",".join(exclude_routes)

    if fallback_url:
        headers["fallback-url"] = fallback_url

    return headers


def build_sosproxy_client_config(subscription_id: str, public_host: str) -> list[dict[str, Any]]:
    row, settings, stream_settings, sniffing, client = find_subscription_by_network(subscription_id, "tcp")
    user_id = client["id"]
    email = client.get("email") or "User"

    # 1. Kinopoisk TCP
    cfg1 = {
      "dns": {
        "queryStrategy": "UseIP",
        "servers": [{"address": "8.8.8.8", "skipFallback": False}],
        "tag": "dns_out"
      },
      "inbounds": [
        {
          "port": 10808,
          "protocol": "mixed",
          "settings": {"auth": "noauth", "udp": True, "userLevel": 8},
          "sniffing": {"destOverride": ["http", "tls", "quic", "fakedns"], "enabled": True},
          "tag": "mixed"
        },
        {
          "port": 10809,
          "protocol": "http",
          "settings": {"userLevel": 8},
          "tag": "http"
        }
      ],
      "log": {"loglevel": "warning"},
      "outbounds": [
        {
          "protocol": "vless",
          "tag": "proxy",
          "streamSettings": {
            "network": "tcp",
            "realitySettings": {
              "fingerprint": "edge",
              "mldsa65Verify": "",
              "publicKey": TCP_REALITY_PUBLIC_KEY,
              "serverName": TCP_REALITY_SNI_FAST,
              "shortId": TCP_REALITY_SHORT_ID,
              "show": False,
              "spiderX": "/"
            },
            "security": "reality",
            "tcpSettings": {"header": {"type": "none"}}
          },
          "settings": {
            "address": public_host,
            "encryption": "none",
            "flow": "xtls-rprx-vision",
            "id": user_id,
            "level": 8,
            "port": 443
          }
        },
        {"protocol": "freedom", "settings": {"domainStrategy": "AsIs", "noises": [], "redirect": ""}, "tag": "direct"},
        {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"}
      ],
      "policy": {
        "levels": {"8": {"connIdle": 300, "downlinkOnly": 1, "handshake": 4, "uplinkOnly": 1}},
        "system": {"statsOutboundDownlink": True, "statsOutboundUplink": True}
      },
      "remarks": f"🇳🇱 🎬 Kinopoisk TCP ({email})",
      "routing": {
        "domainStrategy": "AsIs",
        "rules": [
          {"domain": [], "outboundTag": "direct", "type": "field"},
          {"ip": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"], "outboundTag": "direct", "type": "field"},
          {"network": "tcp,udp", "outboundTag": "proxy", "type": "field"}
        ]
      },
      "stats": {}
    }

    # 2. Hysteria 2 Salamander
    cfg2 = {
      "dns": {
        "queryStrategy": "UseIP",
        "servers": [{"address": "8.8.8.8", "skipFallback": False}],
        "tag": "dns_out"
      },
      "inbounds": [
        {
          "port": 10808,
          "protocol": "mixed",
          "settings": {"auth": "noauth", "udp": True, "userLevel": 8},
          "sniffing": {"destOverride": ["http", "tls", "quic", "fakedns"], "enabled": True},
          "tag": "mixed"
        },
        {
          "port": 10809,
          "protocol": "http",
          "settings": {"userLevel": 8},
          "tag": "http"
        }
      ],
      "log": {"loglevel": "warning"},
      "outbounds": [
        {
          "protocol": "hysteria",
          "tag": "proxy",
          "streamSettings": {
            "finalmask": {
              "udp": [
                {"settings": {"password": HYSTERIA_SALAMANDER_PASSWORD}, "type": "gecko"}
              ]
            },
            "hysteriaSettings": {
              "auth": user_id,
              "auth_str": user_id,
              "authStr": user_id,
              "password": user_id,
              "udpIdleTimeout": 60,
              "version": 2
            },
            "network": "hysteria",
            "security": "tls",
            "tlsSettings": {
              "alpn": ["h3"],
              "fingerprint": "qq",
              "serverName": public_host or os.environ.get("DOMAIN_EDGE", "edge.silentconnect.net")  # PLACEHOLDER
            }
          },
          "settings": {
            "address": public_host,
            "port": HYSTERIA_PORT,
            "version": 2
          }
        },
        {"protocol": "freedom", "settings": {"domainStrategy": "AsIs", "noises": [], "redirect": ""}, "tag": "direct"},
        {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"}
      ],
      "policy": {
        "levels": {"8": {"connIdle": 300, "downlinkOnly": 1, "handshake": 4, "uplinkOnly": 1}},
        "system": {"statsOutboundDownlink": True, "statsOutboundUplink": True}
      },
      "remarks": f"🇳🇱 🚀 Hysteria Salamander ({email})",
      "routing": {
        "domainStrategy": "AsIs",
        "rules": [
          {"domain": [], "outboundTag": "direct", "type": "field"},
          {"ip": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"], "outboundTag": "direct", "type": "field"},
          {"network": "tcp,udp", "outboundTag": "proxy", "type": "field"}
        ]
      },
      "stats": {}
    }

    # 3. Sberbank TCP
    cfg3 = {
      "dns": {
        "queryStrategy": "UseIP",
        "servers": [{"address": "8.8.8.8", "skipFallback": False}],
        "tag": "dns_out"
      },
      "inbounds": [
        {
          "port": 10808,
          "protocol": "mixed",
          "settings": {"auth": "noauth", "udp": True, "userLevel": 8},
          "sniffing": {"destOverride": ["http", "tls", "quic", "fakedns"], "enabled": True},
          "tag": "mixed"
        },
        {
          "port": 10809,
          "protocol": "http",
          "settings": {"userLevel": 8},
          "tag": "http"
        }
      ],
      "log": {"loglevel": "warning"},
      "outbounds": [
        {
          "protocol": "vless",
          "tag": "proxy",
          "streamSettings": {
            "network": "tcp",
            "realitySettings": {
              "fingerprint": "edge",
              "mldsa65Verify": "",
              "publicKey": TCP_REALITY_PUBLIC_KEY,
              "serverName": TCP_REALITY_SNI_CLASSIC,
              "shortId": TCP_REALITY_SHORT_ID,
              "show": False,
              "spiderX": "/"
            },
            "security": "reality",
            "tcpSettings": {"header": {"type": "none"}}
          },
          "settings": {
            "address": public_host,
            "encryption": "none",
            "flow": "xtls-rprx-vision",
            "id": user_id,
            "level": 8,
            "port": 443
          }
        },
        {"protocol": "freedom", "settings": {"domainStrategy": "AsIs", "noises": [], "redirect": ""}, "tag": "direct"},
        {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"}
      ],
      "policy": {
        "levels": {"8": {"connIdle": 300, "downlinkOnly": 1, "handshake": 4, "uplinkOnly": 1}},
        "system": {"statsOutboundDownlink": True, "statsOutboundUplink": True}
      },
      "remarks": f"🇳🇱 🏦 Sberbank TCP ({email})",
      "routing": {
        "domainStrategy": "AsIs",
        "rules": [
          {"domain": [], "outboundTag": "direct", "type": "field"},
          {"ip": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"], "outboundTag": "direct", "type": "field"},
          {"network": "tcp,udp", "outboundTag": "proxy", "type": "field"}
        ]
      },
      "stats": {}
    }

    return [cfg1, cfg2, cfg3]


class RequestHandler(BaseHTTPRequestHandler):
    server_version = "subjson-service/3.0"
    timeout = 15.0

    def setup(self) -> None:
        if hasattr(self.request, "settimeout"):
            self.request.settimeout(15.0)
        super().setup()

    def do_GET(self) -> None:
        self._handle_request(include_body=True)

    def do_HEAD(self) -> None:
        self._handle_request(include_body=False)

    def _read_form(self) -> dict[str, str]:
        length = int(self.headers.get("Content-Length") or 0)
        raw_bytes = self.rfile.read(min(length, 65_536))
        content_type = self.headers.get("Content-Type", "")

        result: dict[str, str] = {}
        if "multipart/form-data" in content_type:
            boundary = ""
            for part in content_type.split(";"):
                part = part.strip()
                if part.startswith("boundary="):
                    boundary = part[len("boundary="):].strip('"\'')
            if boundary:
                b_boundary = f"--{boundary}".encode("ascii")
                parts = raw_bytes.split(b_boundary)
                for part in parts:
                    if not part or part in (b"--\r\n", b"--", b"\r\n", b"--\r\n\r\n"):
                        continue
                    if b"\r\n\r\n" in part:
                        header_part, body_part = part.split(b"\r\n\r\n", 1)
                        header_str = header_part.decode("utf-8", errors="replace")
                        m = re.search(r'name="([^"]+)"', header_str)
                        if m:
                            key = m.group(1)
                            val = body_part.decode("utf-8", errors="replace").strip()
                            result[key] = val
        if not result and "application/json" in content_type.lower():
            try:
                parsed_json = json.loads(raw_bytes.decode("utf-8"))
                if isinstance(parsed_json, dict):
                    result = {str(k): str(v) for k, v in parsed_json.items()}
            except Exception:
                pass
        if not result:
            raw_str = raw_bytes.decode("utf-8", errors="replace")
            parsed = urllib.parse.parse_qs(raw_str, keep_blank_values=True)
            result = {key: values[-1] if values else "" for key, values in parsed.items()}
        return result

    def _handle_internal_quiesce(self, action: str, include_body: bool = True) -> None:
        secret_header = self.headers.get("X-Internal-Secret", "")
        effective_secret = os.environ.get("INTERNAL_SECRET", "").strip() or INTERNAL_SECRET
        if not effective_secret or not hmac.compare_digest(secret_header.encode("utf-8"), effective_secret.encode("utf-8")):
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden", "status": "FORBIDDEN"}, include_body)
            return
        global QUIESCE_ACTIVE, QUIESCE_LEASE_UNTIL
        with QUIESCE_LOCK:
            if action in ("start", "quiesce"):
                QUIESCE_ACTIVE = True
                QUIESCE_LEASE_UNTIL = time.time() + 30.0
                self._send_json(HTTPStatus.OK, {
                    "status": "QUIESCED_ACK",
                    "ack": True,
                    "state": "RECOVERING_QUIESCE",
                    "lease_ttl": 30.0
                }, include_body)
                return
            elif action in ("lease", "heartbeat"):
                if QUIESCE_ACTIVE:
                    QUIESCE_LEASE_UNTIL = time.time() + 30.0
                    self._send_json(HTTPStatus.OK, {
                        "status": "QUIESCED_ACK",
                        "lease_extended": True,
                        "expires_in": 30.0
                    }, include_body)
                else:
                    self._send_json(HTTPStatus.BAD_REQUEST, {
                        "status": "NOT_QUIESCED",
                        "error": "not_quiesced"
                    }, include_body)
                return
            elif action in ("release", "unquiesce"):
                QUIESCE_ACTIVE = False
                QUIESCE_LEASE_UNTIL = 0.0
                self._send_json(HTTPStatus.OK, {
                    "status": "UNQUIESCED_ACK",
                    "quiesce_released": True
                }, include_body)
                return
            else:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown_quiesce_action"}, include_body)

    def do_POST(self) -> None:
        try:
            is_ajax = "application/json" in self.headers.get("Accept", "").lower() or self.headers.get("X-Requested-With") == "XMLHttpRequest"
            parsed_url = urllib.parse.urlsplit(self.path)
            path = [segment for segment in parsed_url.path.split("/") if segment]

            if len(path) == 3 and path[0] == SECRET_SEGMENT and path[1] == "internal-quiesce":
                self._handle_internal_quiesce(path[2], True)
                return

            if len(path) == 2 and path[0] == "internal" and path[1] == "hysteria-auth":
                client_ip = self.client_address[0]
                if client_ip not in ("127.0.0.1", "::1", "localhost", "::ffff:127.0.0.1"):
                    self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"}, True)
                    return
                length = int(self.headers.get("Content-Length") or 0)
                raw_bytes = self.rfile.read(min(length, 65_536))
                try:
                    req_data = json.loads(raw_bytes.decode("utf-8"))
                except Exception:
                    req_data = {}
                auth_token = str(req_data.get("auth") or "").strip()
                _ensure_inbounds_cache()
                with _inbounds_cache_lock:
                    matched = _cached_clients_index.get(auth_token)
                if matched:
                    row, settings, stream_settings, sniffing, client = matched
                    if client.get("enable", True):
                        self._send_json(HTTPStatus.OK, {"ok": True, "id": str(client.get("id") or auth_token)}, True)
                        return
                self._send_json(HTTPStatus.OK, {"ok": False, "error": "unauthorized"}, True)
                return

            if is_quiesced() and (self.command == "POST" or "bot" in self.path):
                self._send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "quiesce_merge_in_progress", "retry_after": 10}, True)
                return
            if len(path) == 3 and path[0] == SECRET_SEGMENT and path[1] in ("renew", "bind-email"):
                sub_id = path[2]
                form = self._read_form()
                LOGGER.info("READ FORM RESULT: %r, Content-Type: %r", form, self.headers.get("Content-Type"))
                bind_email_only = (
                    str(form.get("bind_email_only") or "").strip().lower() in ("1", "true", "yes", "on")
                    or path[1] == "bind-email"
                )

                if bind_email_only:
                    customer_email = form.get("customer_email", "").strip()
                    email_reminders = form.get("email_reminders") != "0"
                    turnstile_token = form.get("cf-turnstile-response", "").strip()
                    xff = self.headers.get("X-Forwarded-For")
                    if xff:
                        client_ip = xff.split(",")[-1].strip()
                    else:
                        client_ip = self.headers.get("CF-Connecting-IP") or (self.client_address[0] if self.client_address else "unknown")

                    res = bind_subscription_email(
                        sub_id=sub_id,
                        customer_email=customer_email,
                        email_reminders=email_reminders,
                        turnstile_token=turnstile_token,
                        client_ip=client_ip,
                        headers=self.headers,
                    )

                    success_card = f"""
                    <section class="install" style="margin-bottom:24px; background:rgba(47,191,113,0.12); border:1px solid var(--green);">
                      <div style="display:flex; align-items:center; gap:10px; margin-bottom:8px;">
                        <span style="font-size:24px;">🎉</span>
                        <h2 style="color:var(--green); margin:0; font-size:20px;">Почта успешно привязана!</h2>
                      </div>
                      <p style="color:#fff; font-size:15px; line-height:1.5; margin:0;">
                        Адрес <strong>{html.escape(res['customer_email'])}</strong> привязан к вашей подписке. 
                        Напоминания об окончании за 24ч и 1ч включены, а ссылки для подключения и входа в кабинет отправлены на вашу почту.
                      </p>
                    </section>
                    """

                    if is_ajax:
                        self._send_json(HTTPStatus.OK, {
                            "ok": True,
                            "bind_email_only": True,
                            "html": success_card,
                            "customer_email": res["customer_email"],
                            "masked_email": mask_email(res["customer_email"]),
                            "message": "Почта успешно привязана!",
                        }, include_body=True)
                        return

                    source_url = public_subscription_url(self.headers, "json", sub_id)
                    quoted_sub_id = urllib.parse.quote(sub_id, safe="")
                    import_query = urllib.parse.urlencode({"url": source_url})
                    generic_html = setup_page_html(
                        subscription_url=source_url,
                        subscription_id=sub_id,
                        quoted_sub_id=quoted_sub_id,
                        import_query=import_query,
                        customer_email=res["customer_email"],
                        payment_card_html=success_card,
                    )
                    self._send_html(HTTPStatus.OK, generic_html, include_body=True)
                    return

                duration_days = int(form.get("duration_days") or 360)
                device_limit = int(form.get("device_limit") or 3)
                customer_email = form.get("customer_email", "").strip()
                promo_code = form.get("promo_code", "").strip()
                email_reminders = form.get("email_reminders") != "0"

                res = create_inline_renewal_order(
                    sub_id=sub_id,
                    duration_days=duration_days,
                    device_limit=device_limit,
                    promo_code=promo_code,
                    customer_email=customer_email,
                    email_reminders=email_reminders,
                )

                source_url = public_subscription_url(self.headers, "json", sub_id)
                quoted_sub_id = urllib.parse.quote(sub_id, safe="")
                import_query = urllib.parse.urlencode({"url": source_url})

                if res["status"] == "delivered":
                    payment_card = """
                    <section class="install" style="margin-bottom:24px; background:rgba(47,191,113,0.12); border:1px solid var(--green);">
                      <h2 style="color:var(--green);">🎉 Подписка успешно продлена!</h2>
                      <p style="color:#fff; font-size:15px; margin-top:8px;">Ваш срок доступа увеличен на <strong>{} дн.</strong> Ключ подключения и настройки в приложении обновились автоматически.</p>
                    </section>
                    """.format(duration_days)
                else:
                    pay_link = os.environ.get("PAYMENT_TRANSFER_URL", "https://t.tb.ru/c2c-qr-choose-bank?requisiteNumber=+79990000000&bankCode=100000000004")
                    sbp_phone = os.environ.get("PAYMENT_SBP_PHONE", "+79990000000")
                    sbp_bank = os.environ.get("PAYMENT_SBP_BANK", "СБП")
                    tg_claim_base = HAPP_SUPPORT_URL or "https://t.me/your_vpn_bot"
                    payment_card = """
                    <section class="install" style="margin-bottom:24px; background:rgba(47,191,113,0.08); border:1px solid var(--green);">
                      <div class="install-head" style="display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; margin-bottom:12px;">
                        <h2 style="margin:0; font-size:20px; font-weight:700; color:#fff;">💳 Оплата продления #{public_id}</h2>
                        <span style="background:rgba(245, 158, 11, 0.15); border:1px solid rgba(245, 158, 11, 0.4); color:#f59e0b; padding:4px 10px; border-radius:8px; font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:0.5px; display:inline-block;">Ожидает оплаты</span>
                      </div>
                      <div style="font-size:32px; font-weight:800; color:#fff; margin:10px 0 16px;">
                        {price} ₽ <span style="font-size:14px; color:var(--muted); font-weight:500;">({days} дн.)</span>
                      </div>
                      <div style="background:rgba(0,0,0,0.3); border:1px solid var(--line); border-radius:12px; padding:16px; margin-bottom:16px;">
                        <div style="color:var(--muted); font-size:14px; line-height:1.5;">
                          Нажмите кнопку <strong>«Оплатить переводом»</strong>, переведите ровно <strong>{price} ₽</strong> через СБП ({phone} / {bank}), после чего нажмите <strong>«Я оплатил(а)»</strong>.
                        </div>
                      </div>
                      <div style="display:flex; gap:12px; flex-wrap:wrap; align-items:center;">
                        <a href="{pay_url}" target="_blank" rel="noopener" class="button" style="min-height:46px; font-weight:800; text-decoration:none; background:var(--green); color:#000; display:inline-flex; align-items:center; justify-content:center;">Оплатить переводом 💳</a>
                        <form method="post" action="/{segment}/paid/{public_id}" style="margin:0;">
                          <button type="submit" class="button success" style="min-height:46px; font-weight:800; background:rgba(255,255,255,0.12); color:#fff; border:1px solid var(--line);">Я оплатил(а) ✓</button>
                        </form>
                        <a href="{tg_claim_base}?start=claim_{public_id}_{token}" target="_blank" class="button secondary" style="min-height:46px; font-weight:600; text-decoration:none; display:inline-flex; align-items:center;">Привязать в Telegram ✈️</a>
                        <form method="post" action="/{segment}/cancel/{public_id}" style="margin:0;">
                          <button type="submit" class="button secondary" style="min-height:46px; font-weight:600; background:rgba(239,68,68,0.12); color:#ef4444; border:1px solid rgba(239,68,68,0.3);">Отменить ✖</button>
                        </form>
                      </div>
                    </section>
                    """.format(
                        public_id=res["public_id"],
                        price=res["final_price_rub"],
                        days=duration_days,
                        segment=SECRET_SEGMENT,
                        token=res["web_token"],
                        pay_url=html.escape(pay_link, quote=True),
                        phone=html.escape(sbp_phone),
                        bank=html.escape(sbp_bank),
                        tg_claim_base=html.escape(tg_claim_base, quote=True),
                    )

                if is_ajax:
                    self._send_json(HTTPStatus.OK, {"ok": True, "html": payment_card, "order_public_id": res["public_id"]}, include_body=True)
                    return

                generic_html = setup_page_html(
                    subscription_url=source_url,
                    subscription_id=sub_id,
                    quoted_sub_id=quoted_sub_id,
                    import_query=import_query,
                    customer_email=res.get("customer_email") or customer_email,
                    payment_card_html=payment_card,
                )
                self._send_html(HTTPStatus.OK, generic_html, include_body=True)
                return

            if len(path) == 3 and path[0] == SECRET_SEGMENT and path[1] in ("paid", "cancel"):
                order_public_id = path[2]
                form = self._read_form()
                req_token = query.get("token", [""])[0].strip() or form.get("web_token", "").strip() or self.headers.get("X-Web-Token", "").strip()
                if not req_token:
                    auth = self.headers.get("Authorization", "").strip()
                    if auth.startswith("Bearer "):
                        req_token = auth[7:].strip()

                db_path = find_store_db_path()
                order_row = None
                if Path(db_path).exists():
                    try:
                        conn = sqlite3.connect(db_path, timeout=30.0)
                        conn.execute("PRAGMA busy_timeout = 30000;")
                        conn.row_factory = sqlite3.Row
                        try:
                            order_row = conn.execute("SELECT * FROM orders WHERE public_id = ?", (order_public_id,)).fetchone()
                        finally:
                            conn.close()
                    except Exception:
                        pass

                if not order_row or not _verify_order_web_token(order_row, req_token):
                    self._send_json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "forbidden", "detail": "invalid_order_token"}, include_body=True)
                    return

                if path[1] == "paid":
                    handle_inline_order_paid(order_public_id, req_token)
                    payment_card = render_payment_notice_html(order_row, status_override="reported") if order_row else ""
                    if is_ajax:
                        self._send_json(HTTPStatus.OK, {"ok": True, "html": payment_card, "order_public_id": order_public_id}, include_body=True)
                        return

                    sub_id = "default"
                    source_url = public_subscription_url(self.headers, "json", sub_id)
                    quoted_sub_id = urllib.parse.quote(sub_id, safe="")
                    import_query = urllib.parse.urlencode({"url": source_url})

                    generic_html = setup_page_html(
                        subscription_url=source_url,
                        subscription_id=sub_id,
                        quoted_sub_id=quoted_sub_id,
                        import_query=import_query,
                        payment_card_html=payment_card,
                    )
                    self._send_html(HTTPStatus.OK, generic_html, include_body=True)
                    return

                if path[1] == "cancel":
                    sub_id = handle_inline_order_cancel(order_public_id, req_token)
                    if is_ajax:
                        self._send_json(HTTPStatus.OK, {"ok": True, "html": ""}, include_body=True)
                        return

                    target_sub = sub_id or "default"
                    self._redirect(f"/{SECRET_SEGMENT}/import/{target_sub}", include_body=True)
                    return

            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False}, include_body=True)
        except ValueError as exc:
            msg = str(exc)
            payment_card = """
            <section class="install" style="margin-bottom:24px; background:rgba(239,68,68,0.12); border:1px solid var(--red);">
              <h2 style="color:var(--red);">Ошибка</h2>
              <p style="color:#fff; font-size:15px; margin-top:8px;">{}</p>
            </section>
            """.format(html.escape(msg))
            if is_ajax:
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "html": payment_card, "error": msg}, include_body=True)
                return
            parsed_path = [segment for segment in urllib.parse.urlsplit(self.path).path.split("/") if segment]
            sub_id = parsed_path[2] if len(parsed_path) >= 3 and parsed_path[0] == SECRET_SEGMENT and parsed_path[1] in ("renew", "bind-email") else "default"
            source_url = public_subscription_url(self.headers, "json", sub_id)
            generic_html = setup_page_html(
                subscription_url=source_url,
                subscription_id=sub_id,
                quoted_sub_id=urllib.parse.quote(sub_id, safe=""),
                import_query="",
                payment_card_html=payment_card,
            )
            self._send_html(HTTPStatus.BAD_REQUEST, generic_html, include_body=True)
        except Exception:
            LOGGER.exception("POST failed in subjson-service")
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False}, include_body=True)

    def log_message(self, fmt: str, *args) -> None:
        # Bearer-style subscription URLs should not generate per-request access logs.
        return

    def version_string(self) -> str:
        return self.server_version

    def _handle_request(self, include_body: bool) -> None:
        try:
            parsed_url = urllib.parse.urlsplit(self.path)
            path = [segment for segment in parsed_url.path.split("/") if segment]
            query = urllib.parse.parse_qs(parsed_url.query)
            # Rate limit subscription endpoints (audit #10); healthz/internal exempt.
            if len(path) >= 2 and path[0] == SECRET_SEGMENT and not path[1].startswith("internal"):
                xff = self.headers.get("X-Forwarded-For", "").strip()
                if xff:
                    client_ip = xff.split(",")[-1].strip()
                else:
                    client_ip = self.client_address[0] if self.client_address else "unknown"
                if not check_rate_limit(client_ip):
                    self._send_json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "rate_limited", "detail": "too many requests, retry in a minute"}, include_body)
                    return

            if path == ["healthz"]:
                self._send_json(HTTPStatus.OK, {"ok": True}, include_body)
                return

            if len(path) == 3 and path[0] == SECRET_SEGMENT and path[1] == "internal-quiesce":
                self._handle_internal_quiesce(path[2], include_body)
                return

            if is_quiesced() and (self.command == "POST" or "bot" in self.path):
                self._send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "quiesce_merge_in_progress", "retry_after": 10}, include_body)
                return

            if path == ["favicon.ico"]:
                self._redirect(f"{HAPP_WEB_PAGE_URL}/assets/telegram/avatar.png", include_body)
                return

            if path == ["legal", "terms"] or path == [SECRET_SEGMENT, "legal", "terms"]:
                self._send_html(HTTPStatus.OK, legal_terms_html(), include_body)
                return

            if len(path) == 3 and path[0] == SECRET_SEGMENT:
                if path[1] == "internal-fragment":
                    secret_header = self.headers.get("X-Internal-Secret", "")
                    effective_secret = os.environ.get("INTERNAL_SECRET", "").strip() or INTERNAL_SECRET
                    if not effective_secret or not hmac.compare_digest(secret_header.encode("utf-8"), effective_secret.encode("utf-8")):
                        self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"}, include_body)
                        return
                    sub_id = path[2]
                    public_host = resolve_public_host(self.headers)
                    payload = build_four_profiles(sub_id, public_host, "split-ru")
                    self._send_json(HTTPStatus.OK, payload, include_body)
                    return
                public_host = resolve_public_host(self.headers)

                if path[1] in {"json-global", "sub-global", "happ-global"}:
                    payload = build_four_profiles(path[2], public_host, "global")
                    self._send_subscription_json(payload, include_body, subscription_route=path[1], subscription_id=path[2])
                    return

                if path[1] in {"json-relay-global", "sub-relay-global"}:
                    payload = build_portable_client_config(
                        path[2],
                        resolve_relay_public_host(self.headers),
                        "global",
                        relay=True,
                    )
                    self._send_subscription_json(payload, include_body, subscription_route=path[1], subscription_id=path[2])
                    return

                if path[1] in {"singbox", "sing-box", "sfa"}:
                    payload = build_singbox_smart_config(path[2], public_host, "split-ru", tag_style="happ")
                    self._send_json(HTTPStatus.OK, payload, include_body)
                    return

                if path[1] in {"singbox-global", "sing-box-global", "sfa-global"}:
                    payload = build_singbox_smart_config(path[2], public_host, "global", tag_style="happ")
                    self._send_json(HTTPStatus.OK, payload, include_body)
                    return

                user_agent = self.headers.get("User-Agent", "").lower()
                if ("sing-box" in user_agent or "sfa" in user_agent) and path[1] in {"json", "sub", "json-ru", "sub-ru"}:
                    payload = build_singbox_smart_config(path[2], public_host, "split-ru", tag_style="happ")
                    self._send_json(HTTPStatus.OK, payload, include_body)
                    return

                if path[1] in {"json", "sub", "json-ru", "sub-ru", "happ"}:
                    payload = build_four_profiles(path[2], public_host, "split-ru")
                    self._send_subscription_json(payload, include_body, subscription_route=path[1], subscription_id=path[2])
                    return

                if path[1] in {"clash", "meta", "clash-meta"}:
                    payload_yaml = build_clash_meta_config(path[2], public_host, "split-ru")
                    self._send_yaml(
                        HTTPStatus.OK,
                        payload_yaml,
                        include_body,
                        subscription_id=path[2],
                        profile_web_page_url=public_connection_page_url(self.headers, path[1], path[2]),
                        profile_title="SilentConnect Clash",
                    )
                    return

                if path[1] in {"clash-global", "meta-global"}:
                    payload_yaml = build_clash_meta_config(path[2], public_host, "global")
                    self._send_yaml(
                        HTTPStatus.OK,
                        payload_yaml,
                        include_body,
                        subscription_id=path[2],
                        profile_web_page_url=public_connection_page_url(self.headers, path[1], path[2]),
                        profile_title="SilentConnect Clash Global",
                    )
                    return

                if path[1] in {"streisand", "base64", "b64"}:
                    payload_b64 = build_streisand_bundle(path[2], public_host)
                    self._send_streisand(
                        HTTPStatus.OK,
                        payload_b64,
                        include_body,
                        subscription_id=path[2],
                        profile_web_page_url=public_connection_page_url(self.headers, path[1], path[2]),
                        profile_title="SilentConnect Streisand",
                    )
                    return

                if path[1] in {"legacy", "xray", "json-legacy", "sub-legacy"}:
                    payload = build_four_profiles(path[2], public_host, "split-ru")
                    self._send_subscription_json(payload, include_body, subscription_route=path[1], subscription_id=path[2])
                    return

                if path[1] in {"json-test-fragment", "sub-test-fragment"}:
                    payload = build_four_profiles(path[2], public_host, "split-ru", enable_fragment=True)
                    self._send_subscription_json(payload, include_body, subscription_route=path[1], subscription_id=path[2])
                    return

                if path[1] in {"json-multi", "sub-multi"}:
                    payload = build_multi_client_configs(path[2], public_host, "split-ru")
                    self._send_json(
                        HTTPStatus.OK,
                        payload,
                        include_body,
                        subscription_id=path[2],
                        profile_web_page_url=public_connection_page_url(self.headers, path[1], path[2]),
                    )
                    return

                if path[1] in {"json-ws-sub-test", "json-ws-sslip-test", "json-ws-nip-test"}:
                    nl_master_ip = os.environ.get("NL_MASTER_IP", "192.0.2.1")
                    ws_tests = {
                        "json-ws-sub-test": (WS443_PUBLIC_HOST, "sub", "SC WS sub test"),
                        "json-ws-sslip-test": (f"{nl_master_ip}.sslip.io", "sslip", "SC WS sslip test"),
                        "json-ws-nip-test": (f"{nl_master_ip}.nip.io", "nip", "SC WS nip test"),
                    }
                    ws_host, label, profile_title = ws_tests[path[1]]
                    payload = build_ws443_host_test_client_config(path[2], "split-ru", ws_host, label)
                    self._send_json(
                        HTTPStatus.OK,
                        payload,
                        include_body,
                        subscription_id=path[2],
                        profile_web_page_url=public_connection_page_url(self.headers, path[1], path[2]),
                        profile_title=profile_title,
                    )
                    return

                if path[1] in {"json-dual-test", "sub-dual-test"}:
                    payload = build_dual_test_client_configs(path[2], public_host, "split-ru")
                    self._send_json(
                        HTTPStatus.OK,
                        payload,
                        include_body,
                        subscription_id=path[2],
                        profile_web_page_url=public_connection_page_url(self.headers, path[1], path[2]),
                    )
                    return

                if path[1] in {"json-nl-test-fp", "sub-nl-test-fp"}:
                    payload = build_test_fp_profiles(path[2], public_host, "split-ru")
                    self._send_subscription_json(
                        payload,
                        include_body,
                        subscription_route=path[1],
                        subscription_id=path[2],
                    )
                    return

                if path[1] in {"json-xhttp-test", "sub-xhttp-test"}:
                    payload = build_xhttp_test_profiles(path[2], public_host)
                    self._send_subscription_json(
                        payload,
                        include_body,
                        subscription_route=path[1],
                        subscription_id=path[2],
                    )
                    return

                if path[1] in {"json-xhttp-tcp-caddy-test", "sub-xhttp-tcp-caddy-test"}:
                    payload = build_xhttp_tcp_caddy_test_profile(path[2], public_host)
                    self._send_json(
                        HTTPStatus.OK,
                        payload,
                        include_body,
                        subscription_id=path[2],
                        profile_web_page_url=public_connection_page_url(self.headers, path[1], path[2]),
                        profile_title="SilentConnect XHTTP TCP",
                        server_address_resolve_enabled=False,
                        fragmentation_enabled=False,
                        include_exclude_routes=False,
                    )
                    return

                if path[1] in {"json-dual-auto-test", "sub-dual-auto-test"}:
                    payload = build_dual_auto_test_client_config(path[2], public_host, "split-ru")
                    self._send_subscription_json(
                        payload,
                        include_body,
                        subscription_route=path[1],
                        subscription_id=path[2],
                    )
                    return

                if path[1] in {"json-auto-wifi-first-test", "sub-auto-wifi-first-test"}:
                    payload = build_dual_auto_wifi_first_test_client_config(path[2], public_host, "split-ru")
                    self._send_json(
                        HTTPStatus.OK,
                        payload,
                        include_body,
                        subscription_id=path[2],
                        profile_web_page_url=public_connection_page_url(self.headers, path[1], path[2]),
                        profile_title="SC Wi-Fi first test",
                    )
                    return

                # FIX 2026-08-23: legacy frankfurt routes removed -
                # they served configs pointing at a foreign/dead host (audit #16).

                if path[1] in {
                    "json-nl-maxru-tcp",
                    "json-nl-maxru-xhttp",
                    "json-nl-maxru-hybrid",
                    "json-nl-ws443",
                }:
                    payload = load_static_json_config(path[1])
                    if payload is None:
                        self._send_json(
                            HTTPStatus.NOT_FOUND,
                            {"error": "not_found", "detail": "static_config_not_found"},
                            include_body,
                        )
                        return
                    self._send_json(
                        HTTPStatus.OK,
                        payload,
                        include_body,
                        subscription_id=path[2],
                        profile_web_page_url=public_connection_page_url(self.headers, path[1], path[2]),
                    )
                    return


                if path[1] in {"json-sosproxy", "sub-sosproxy"}:
                    payload = build_sosproxy_client_config(path[2], public_host)
                    self._send_json(
                        HTTPStatus.OK,
                        payload,
                        include_body,
                        subscription_id=path[2],
                        profile_web_page_url=public_connection_page_url(self.headers, path[1], path[2]),
                        profile_title="SC Sosproxy",
                    )
                    return

                if path[1] in {"json-relay", "sub-relay", "json-ru-relay", "sub-ru-relay"}:
                    payload = build_portable_client_config(
                        path[2],
                        resolve_relay_public_host(self.headers),
                        "split-ru",
                        relay=True,
                    )
                    self._send_subscription_json(payload, include_body, subscription_route=path[1], subscription_id=path[2])
                    return

                if path[1] in {"json-google", "sub-google"}:
                    payload = build_portable_client_config(path[2], public_host, "global", "google")
                    self._send_subscription_json(payload, include_body, subscription_route=path[1], subscription_id=path[2])
                    return

                if path[1] in {"json-relay-google", "sub-relay-google"}:
                    payload = build_portable_client_config(
                        path[2],
                        resolve_relay_public_host(self.headers),
                        "global",
                        "google",
                        relay=True,
                    )
                    self._send_subscription_json(payload, include_body, subscription_route=path[1], subscription_id=path[2])
                    return

                if path[1] in {"json-ru-google", "sub-ru-google"}:
                    payload = build_portable_client_config(path[2], public_host, "split-ru", "google")
                    self._send_subscription_json(payload, include_body, subscription_route=path[1], subscription_id=path[2])
                    return

                if path[1] in {"json-ru-relay-google", "sub-ru-relay-google"}:
                    payload = build_portable_client_config(
                        path[2],
                        resolve_relay_public_host(self.headers),
                        "split-ru",
                        "google",
                        relay=True,
                    )
                    self._send_subscription_json(payload, include_body, subscription_route=path[1], subscription_id=path[2])
                    return

                if path[1] in {"json-hybrid", "sub-hybrid"}:
                    payload = build_hybrid_client_config(path[2], public_host, "split-ru")
                    self._send_subscription_json(payload, include_body, subscription_route=path[1], subscription_id=path[2])
                    return

                if path[1] in {"json-hybrid-relay", "sub-hybrid-relay"}:
                    payload = build_hybrid_client_config(
                        path[2],
                        resolve_relay_public_host(self.headers),
                        "split-ru",
                        relay=True,
                    )
                    self._send_subscription_json(payload, include_body, subscription_route=path[1], subscription_id=path[2])
                    return

                if path[1] in {"json-hybrid-google", "sub-hybrid-google"}:
                    payload = build_hybrid_client_config(path[2], public_host, "split-ru", "google")
                    self._send_subscription_json(payload, include_body, subscription_route=path[1], subscription_id=path[2])
                    return

                if path[1] in {"json-hybrid-relay-google", "sub-hybrid-relay-google"}:
                    payload = build_hybrid_client_config(
                        path[2],
                        resolve_relay_public_host(self.headers),
                        "split-ru",
                        "google",
                        relay=True,
                    )
                    self._send_subscription_json(payload, include_body, subscription_route=path[1], subscription_id=path[2])
                    return

                if path[1] == "raw":
                    payload = build_raw_client_config(path[2], public_host)
                    self._send_subscription_json(payload, include_body, subscription_route=path[1], subscription_id=path[2])
                    return

            if len(path) == 3 and path[0] == SECRET_SEGMENT and path[1] in {"order-status", "order-status-sub"}:
                lookup_val = path[2]
                db_path = find_store_db_path()
                if Path(db_path).exists():
                    try:
                        conn = sqlite3.connect(db_path, timeout=30.0)
                        conn.execute("PRAGMA busy_timeout = 30000;")
                        conn.row_factory = sqlite3.Row
                        try:
                            if path[1] == "order-status-sub":
                                target_sub = lookup_val.strip().split("~")[0]
                                row, _, _, _, client = find_subscription(target_sub)
                                email = str(client.get("email") or "")
                                prof = conn.execute("SELECT * FROM profiles WHERE xui_email = ?", (email,)).fetchone()
                                if prof:
                                    order_row = conn.execute("SELECT * FROM orders WHERE provisioned_profile_id = ? ORDER BY id DESC LIMIT 1", (prof["id"],)).fetchone()
                                else:
                                    order_row = None
                            else:
                                order_row = conn.execute("SELECT * FROM orders WHERE public_id = ?", (lookup_val,)).fetchone()

                            if order_row:
                                meta = json.loads(order_row["meta_json"]) if order_row["meta_json"] else {}
                                customer_email = str(order_row["customer_email"] or meta.get("customer_email") or "").strip()
                                def mask_email(e: str) -> str:
                                    if not e or "@" not in e:
                                        return ""
                                    loc, dom = e.split("@", 1)
                                    if len(loc) <= 2:
                                        m_loc = loc[:1] + "***"
                                    else:
                                        m_loc = loc[:2] + "***"
                                    return f"{m_loc}@{dom}"

                                data = {
                                    "ok": True,
                                    "public_id": order_row["public_id"],
                                    "status": order_row["status"],
                                    "duration_days": int(order_row["duration_days"] or 30),
                                    "device_limit": int(meta.get("device_limit") or 3),
                                    "customer_email": mask_email(customer_email),
                                    "final_price_rub": int(order_row["final_price_rub"] or 0),
                                    "web_paid_reported_at": meta.get("web_paid_reported_at", 0),
                                }
                                self._send_json(HTTPStatus.OK, data, include_body)
                                return
                        finally:
                            conn.close()
                    except Exception as e:
                        LOGGER.warning("Error fetching order status: %s", e)
                self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not_found"}, include_body)
                return

            if len(path) == 3 and path[0] == SECRET_SEGMENT and path[1] == "import":
                sub_id = path[2]
                source_url = first_non_empty(query.get("url")) or public_subscription_url(self.headers, "json", sub_id)
                quoted_sub_id = urllib.parse.quote(sub_id, safe="")
                import_query = urllib.parse.urlencode({"url": source_url})
                pending_card = check_pending_payment_card(sub_id)
                existing_email = find_store_linked_email(sub_id)
                generic_html = setup_page_html(
                    subscription_url=source_url,
                    subscription_id=sub_id,
                    quoted_sub_id=quoted_sub_id,
                    import_query=import_query,
                    customer_email=existing_email,
                    payment_card_html=pending_card,
                )
                self._send_html(HTTPStatus.OK, generic_html, include_body)
                return

            if len(path) == 4 and path[0] == SECRET_SEGMENT and path[1] == "import":
                target = path[2]
                sub_id = path[3]
                source_url = first_non_empty(query.get("url")) or public_subscription_url(self.headers, "json", sub_id)
                if target == "happ":
                    encrypted = encrypt_happ_link(source_url)
                    if encrypted:
                        page = import_page_html(
                            title="Открыть в Happ",
                            body=(
                                "Пробуем открыть Happ автоматически и передать защищённую ссылку подписки. "
                                "Если приложение не открылось само, нажмите кнопку ниже."
                            ),
                            subscription_url=source_url,
                            primary_label="Открыть в Happ (рекомендуем)",
                            primary_url=encrypted,
                            auto_url=encrypted,
                            install_urls={
                                "ios": HAPP_IOS_URL,
                                "android": HAPP_ANDROID_URL,
                                "android_apk": HAPP_ANDROID_APK_URL,
                                "windows": HAPP_DOWNLOAD_URL,
                                "fallback": HAPP_DOWNLOAD_URL,
                            },
                        )
                        self._send_html(HTTPStatus.OK, page, include_body)
                        return
                    page = import_page_html(
                        title="Открыть в Happ",
                        body="Не удалось подготовить защищённую ссылку Happ автоматически. Скопируйте подписку и добавьте её в Happ через импорт из буфера.",
                        subscription_url=source_url,
                        primary_label="",
                        install_urls={
                            "ios": HAPP_IOS_URL,
                            "android": HAPP_ANDROID_URL,
                            "android_apk": HAPP_ANDROID_APK_URL,
                            "windows": HAPP_DOWNLOAD_URL,
                            "fallback": HAPP_DOWNLOAD_URL,
                        },
                    )
                    self._send_html(HTTPStatus.OK, page, include_body)
                    return

                if target == "streisand":
                    import_url = build_streisand_import_url(source_url)
                    page = import_page_html(
                        title="Streisand (iPhone / iPad)",
                        body=(
                            "Пробуем открыть Streisand на iPhone / iPad автоматически и передать полную JSON-подписку. "
                            "Если приложение не открылось само, нажмите кнопку ниже. "
                            "Если импорт не сработал, скопируйте ссылку и добавьте её в Streisand через импорт из буфера."
                        ),
                        subscription_url=source_url,
                        primary_label="Открыть в Streisand (iPhone / iPad)",
                        primary_url=import_url,
                        auto_url=import_url,
                        install_urls={
                            "ios": STREISAND_IOS_URL,
                        },
                    )
                    self._send_html(HTTPStatus.OK, page, include_body)
                    return

                if target == "v2raytun":
                    import_url = build_v2raytun_import_url(source_url)
                    page = import_page_html(
                        title="V2RayTun",
                        body=(
                            "Пробуем открыть V2RayTun автоматически и передать полную ссылку подписки. "
                            "Если приложение не открылось само, нажмите кнопку ниже. "
                            "Если импорт не сработал, скопируйте ссылку и добавьте её через Import from URL."
                        ),
                        subscription_url=source_url,
                        primary_label="Открыть в V2RayTun",
                        primary_url=import_url,
                        auto_url=import_url,
                        install_urls={
                            "ios": V2RAYTUN_IOS_URL,
                            "android": V2RAYTUN_ANDROID_URL,
                        },
                    )
                    self._send_html(HTTPStatus.OK, page, include_body)
                    return

                if target in {"clash", "meta"}:
                    clash_sub_url = public_subscription_url(self.headers, "clash", sub_id)
                    import_url = f"clash://install-config?url={urllib.parse.quote(clash_sub_url, safe='')}"
                    page = import_page_html(
                        title="Clash Meta / Mihomo",
                        body=(
                            "Пробуем импортировать конфигурацию в Clash Meta / Mihomo автоматически. "
                            "Если приложение не открылось само, нажмите кнопку ниже или скопируйте ссылку подписки."
                        ),
                        subscription_url=clash_sub_url,
                        primary_label="Открыть в Clash Meta",
                        primary_url=import_url,
                        auto_url=import_url,
                        install_urls={
                            "windows": CLASH_DOWNLOAD_URL,
                            "macos": CLASH_DOWNLOAD_URL,
                            "android": "https://github.com/MetaCubeX/ClashMetaForAndroid/releases",
                            "linux": CLASH_DOWNLOAD_URL,
                            "fallback": CLASH_DOWNLOAD_URL,
                        },
                    )
                    self._send_html(HTTPStatus.OK, page, include_body)
                    return

                if target == "singbox":
                    singbox_sub_url = public_subscription_url(self.headers, "json", sub_id)
                    import_url = f"sing-box://import-remote-profile?url={urllib.parse.quote(singbox_sub_url, safe='')}#SilentConnect"
                    page = import_page_html(
                        title="Sing-box",
                        body=(
                            "Пробуем открыть Sing-box автоматически и передать полную JSON-конфигурацию. "
                            "Если приложение не открылось само, нажмите кнопку ниже или скопируйте ссылку подписки."
                        ),
                        subscription_url=singbox_sub_url,
                        primary_label="Открыть в Sing-box",
                        primary_url=import_url,
                        auto_url=import_url,
                        install_urls={
                            "ios": SINGBOX_IOS_URL,
                            "android": SINGBOX_DOWNLOAD_URL,
                            "windows": SINGBOX_DOWNLOAD_URL,
                            "macos": SINGBOX_DOWNLOAD_URL,
                            "linux": SINGBOX_DOWNLOAD_URL,
                            "fallback": SINGBOX_DOWNLOAD_URL,
                        },
                    )
                    self._send_html(HTTPStatus.OK, page, include_body)
                    return

                if target == "v2rayn":
                    b64_sub_url = public_subscription_url(self.headers, "streisand", sub_id)
                    page = import_page_html(
                        title="v2rayN (Windows)",
                        body=(
                            "Для добавления в v2rayN скопируйте ссылку подписки ниже, откройте v2rayN и выберите: "
                            "«Подписка» → «Настройки подписок» → «Добавить», вставьте ссылку и нажмите «Обновить подписки»."
                        ),
                        subscription_url=b64_sub_url,
                        primary_label="Скопировать подписку для v2rayN",
                        primary_url="",
                        install_urls={
                            "windows": V2RAYN_DOWNLOAD_URL,
                            "fallback": V2RAYN_DOWNLOAD_URL,
                        },
                    )
                    self._send_html(HTTPStatus.OK, page, include_body)
                    return

                if target in {"nekobox", "v2rayng"}:
                    b64_sub_url = public_subscription_url(self.headers, "streisand", sub_id)
                    client_name = "NekoBox" if target == "nekobox" else "v2rayNG"
                    download_url = NEKOBOX_DOWNLOAD_URL if target == "nekobox" else V2RAYNG_DOWNLOAD_URL
                    sub_for_client = source_url if target == "nekobox" else b64_sub_url
                    page = import_page_html(
                        title=f"{client_name} (Android)",
                        body=(
                            f"Для подключения в {client_name} скопируйте ссылку подписки ниже и добавьте её в приложении через меню «Импорт подписки»."
                        ),
                        subscription_url=sub_for_client,
                        primary_label=f"Скопировать для {client_name}",
                        primary_url="",
                        install_urls={
                            "android": download_url,
                            "fallback": download_url,
                        },
                    )
                    self._send_html(HTTPStatus.OK, page, include_body)
                    return

            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"}, include_body)
        except KeyError:
            self._send_json(
                HTTPStatus.NOT_FOUND,
                {"error": "subscription_not_found"},
                include_body,
            )
        except (sqlite3.Error, json.JSONDecodeError, RuntimeError, ValueError) as exc:
            LOGGER.exception("Failed to build config")
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "server_error", "detail": str(exc)},
                include_body,
            )
        except Exception:
            LOGGER.exception("Unhandled error")
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "server_error", "detail": "unexpected_error"},
                include_body,
            )

    def _send_yaml(
        self,
        status: HTTPStatus,
        yaml_text: str,
        include_body: bool,
        *,
        subscription_id: str | None = None,
        profile_web_page_url: str | None = None,
        profile_title: str | None = None,
    ) -> None:
        body = yaml_text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/yaml; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("X-Robots-Tag", "noindex, nofollow, noarchive")
        for name, value in SECURITY_HEADERS:
            self.send_header(name, value)
        if subscription_id:
            summary = subscription_summary(subscription_id)
            user_info = f"upload=0; download=0; total={summary.get('traffic_total_bytes', 0)}; expire={int(time.time() + 86400 * 30)}"
            self.send_header("Subscription-Userinfo", user_info)
            self.send_header("Profile-Update-Interval", "24")
            if profile_title:
                self.send_header("Profile-Title", profile_title)
            if profile_web_page_url:
                self.send_header("Profile-Web-Page-Url", profile_web_page_url)
        self.end_headers()
        if include_body:
            self.wfile.write(body)

    def _send_streisand(
        self,
        status: HTTPStatus,
        bundle_base64: str,
        include_body: bool,
        *,
        subscription_id: str | None = None,
        profile_web_page_url: str | None = None,
        profile_title: str | None = None,
    ) -> None:
        body = bundle_base64.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("X-Robots-Tag", "noindex, nofollow, noarchive")
        for name, value in SECURITY_HEADERS:
            self.send_header(name, value)
        if subscription_id:
            summary = subscription_summary(subscription_id)
            user_info = f"upload=0; download=0; total={summary.get('traffic_total_bytes', 0)}; expire={int(time.time() + 86400 * 30)}"
            self.send_header("Subscription-Userinfo", user_info)
            self.send_header("Profile-Update-Interval", "24")
            if profile_title:
                self.send_header("Profile-Title", profile_title)
            if profile_web_page_url:
                self.send_header("Profile-Web-Page-Url", profile_web_page_url)
        self.end_headers()
        if include_body:
            self.wfile.write(body)

    def _send_subscription_json(
        self,
        payload: dict[str, Any] | list[dict[str, Any]],
        include_body: bool,
        *,
        subscription_route: str,
        subscription_id: str,
    ) -> None:
        if isinstance(payload, list):
            payload = [
                append_extra_outbounds(p, subscription_id, subscription_route)
                for p in payload
            ]
        else:
            payload = append_extra_outbounds(payload, subscription_id, subscription_route)
        self._send_json(
            HTTPStatus.OK,
            payload,
            include_body,
            subscription_id=subscription_id,
            profile_web_page_url=public_connection_page_url(self.headers, subscription_route, subscription_id),
        )

    def _send_json(
        self,
        status: HTTPStatus,
        payload: Any,
        include_body: bool,
        *,
        subscription_id: str | None = None,
        profile_web_page_url: str | None = None,
        profile_title: str | None = None,
        server_address_resolve_enabled: bool = True,
        fragmentation_enabled: bool = True,
        include_exclude_routes: bool = False,
        fallback_url: str | None = None,
    ) -> None:
        if fallback_url is None and FALLBACK_SUBSCRIPTION_ORIGIN:
            parsed_url = urllib.parse.urlsplit(self.path)
            path_segments = [seg for seg in parsed_url.path.split("/") if seg]
            if len(path_segments) >= 3 and path_segments[0] == SECRET_SEGMENT:
                current_origin = resolve_public_origin(self.headers)
                if current_origin.rstrip("/") != FALLBACK_SUBSCRIPTION_ORIGIN.rstrip("/"):
                    fallback_url = f"{FALLBACK_SUBSCRIPTION_ORIGIN}/{'/'.join(path_segments)}"

        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("X-Robots-Tag", "noindex, nofollow, noarchive")
        for name, value in SECURITY_HEADERS:
            self.send_header(name, value)
        for name, value in build_happ_response_headers(
            payload,
            subscription_id=subscription_id,
            profile_web_page_url=profile_web_page_url,
            profile_title=profile_title,
            server_address_resolve_enabled=server_address_resolve_enabled,
            fragmentation_enabled=fragmentation_enabled,
            include_exclude_routes=include_exclude_routes,
            fallback_url=fallback_url,
        ).items():
            self.send_header(name, value)
        self.end_headers()
        if include_body:
            self.wfile.write(body)

    def _send_text(self, status: HTTPStatus, body_text: str, include_body: bool) -> None:
        body = body_text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("X-Robots-Tag", "noindex, nofollow, noarchive")
        for name, value in SECURITY_HEADERS:
            self.send_header(name, value)
        self.end_headers()
        if include_body:
            self.wfile.write(body)

    def _send_html(self, status: HTTPStatus, body: bytes | None, include_body: bool) -> None:
        body_bytes = body or b""
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("X-Robots-Tag", "noindex, nofollow, noarchive")
        for name, value in SECURITY_HEADERS:
            self.send_header(name, value)
        self.end_headers()
        if include_body and body_bytes:
            self.wfile.write(body_bytes)

    def _redirect(self, location: str, include_body: bool) -> None:
        body = b""
        self.send_response(HTTPStatus.FOUND)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        for name, value in SECURITY_HEADERS:
            self.send_header(name, value)
        self.end_headers()
        if include_body:
            self.wfile.write(body)


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), RequestHandler)
    LOGGER.info("Listening on %s:%s using DB %s", LISTEN_HOST, LISTEN_PORT, XUI_DB_PATH)
    server.serve_forever()


if __name__ == "__main__":
    main()
