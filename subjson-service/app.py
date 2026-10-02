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
import zlib

# Centralized pricing logic
_vpn_shop_path = str(Path(__file__).resolve().parent.parent / "vpn-shop")
if _vpn_shop_path not in sys.path:
    sys.path.insert(0, _vpn_shop_path)

if "MONTHLY_PRICE_3_DEVICES_RUB" not in os.environ:
    for _env_cand in (
        Path(__file__).resolve().parent.parent / "vpn-shop" / ".env",
        Path(__file__).resolve().parent.parent / "vpn-shop" / ".env.silentconnect",
        Path("/root/vpn-shop/.env"),
        Path("/root/vpn-shop/.env.silentconnect"),
    ):
        if _env_cand.is_file():
            try:
                with open(_env_cand, "r", encoding="utf-8") as _ef:
                    for _line in _ef:
                        _line = _line.strip()
                        if _line and not _line.startswith("#") and "=" in _line:
                            _k, _v = _line.split("=", 1)
                            _k = _k.strip()
                            if _k.startswith("MONTHLY_PRICE_") and _k not in os.environ:
                                os.environ[_k] = _v.strip().strip('"').strip("'")
            except Exception:
                pass

try:
    from vpn_shop.catalog import calculate_renewal_price, quote_price
    from vpn_shop.security import hash_secret, hash_token
    from vpn_shop.web import subscription_setup_url, verify_cf_turnstile
except ImportError:
    def quote_price(device_limit: int = 3, duration_days: int = 30, settings: Any = None) -> int:
        prices = {3: 149, 6: 199, 9: 235}
        monthly = prices.get(device_limit, 149)
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

    def hash_token(token: str, purpose: str = "") -> str:
        effective_pepper = os.environ.get("SERVER_PEPPER", "silentconnect-pepper-secret-v1").encode("utf-8")
        msg = f"{purpose}\x00{token}".encode("utf-8")
        return hmac.new(effective_pepper, msg, hashlib.sha256).hexdigest()

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
    eff_pepper = os.environ.get("SERVER_PEPPER", "silentconnect-pepper-secret-v1").encode("utf-8")
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

# Per-server REALITY identities (NL, FI, PL have their own server keypairs)
NL_REALITY_PUBLIC_KEY = os.environ.get("NL_REALITY_PUBLIC_KEY", "2JCWlJ5M8OxWsp8YLWZqtlkyJGMbdRSwVishk8mIuEo").strip()
NL_REALITY_SHORT_ID = os.environ.get("NL_REALITY_SHORT_ID", "9a2f7c6d1e4b8a30").strip()
NL_GRPC_REALITY_PUBLIC_KEY = os.environ.get("NL_GRPC_REALITY_PUBLIC_KEY", "qb3chneGBO60_kv-McyCvUrXM93aN851duFH2bVIMQU").strip()
NL_GRPC_REALITY_SHORT_ID = os.environ.get("NL_GRPC_REALITY_SHORT_ID", "9a2f7c6d1e4b8a30").strip()

FI_REALITY_PUBLIC_KEY = os.environ.get("FI_REALITY_PUBLIC_KEY", "2JCWlJ5M8OxWsp8YLWZqtlkyJGMbdRSwVishk8mIuEo").strip()
FI_REALITY_SHORT_ID = os.environ.get("FI_REALITY_SHORT_ID", "9a2f7c6d1e4b8a30").strip()
FI_GRPC_REALITY_PUBLIC_KEY = os.environ.get("FI_GRPC_REALITY_PUBLIC_KEY", FI_REALITY_PUBLIC_KEY).strip()
FI_GRPC_REALITY_SHORT_ID = os.environ.get("FI_GRPC_REALITY_SHORT_ID", FI_REALITY_SHORT_ID).strip()

PL_STANDBY_HOST = os.environ.get("PL_STANDBY_HOST", "").strip()
PL_REALITY_PUBLIC_KEY = os.environ.get("PL_REALITY_PUBLIC_KEY", "hgj4G9HOJ_6OVYTkeha0vVdEcyuLVzR4Op2BV7CeIW8").strip()
PL_REALITY_SHORT_ID = os.environ.get("PL_REALITY_SHORT_ID", "9f4a1c7e2b8d0a35").strip()
PL_REALITY_SNI_CLASSIC = os.environ.get("PL_REALITY_SNI_CLASSIC", "allegro.pl").strip()
PL_REALITY_SNI_FAST = os.environ.get("PL_REALITY_SNI_FAST", "speed.cloudflare.com").strip()
PL_XHTTP_REALITY_PORT = int(os.environ.get("PL_XHTTP_REALITY_PORT", "8443"))

# Backwards compatibility / Local host fallback
TCP_REALITY_PUBLIC_KEY = os.environ.get("TCP_REALITY_PUBLIC_KEY", NL_REALITY_PUBLIC_KEY).strip()
TCP_REALITY_SHORT_ID = os.environ.get("TCP_REALITY_SHORT_ID", NL_REALITY_SHORT_ID).strip()
TCP_REALITY_SNI_CLASSIC = os.environ.get("TCP_REALITY_SNI_CLASSIC", "sber.ru").strip()
TCP_REALITY_SNI_FAST = os.environ.get("TCP_REALITY_SNI_FAST", "st.kinopoisk.ru").strip()
GRPC_REALITY_PUBLIC_KEY = os.environ.get("GRPC_REALITY_PUBLIC_KEY", NL_GRPC_REALITY_PUBLIC_KEY).strip()
GRPC_REALITY_SHORT_ID = os.environ.get("GRPC_REALITY_SHORT_ID", NL_GRPC_REALITY_SHORT_ID).strip()
GRPC_REALITY_SNI = os.environ.get("GRPC_REALITY_SNI", "vk.com").strip()
GRPC_SERVICE_NAME = os.environ.get("GRPC_SERVICE_NAME", "grpc-maxru").strip()

FI_REALITY_SNI_CLASSIC = os.environ.get("FI_REALITY_SNI_CLASSIC", "sber.ru").strip()
FI_REALITY_SNI_FAST = os.environ.get("FI_REALITY_SNI_FAST", "speed.cloudflare.com").strip()
FI_GRPC_REALITY_SNI = os.environ.get("FI_GRPC_REALITY_SNI", "sber.ru").strip()
FI_XHTTP_REALITY_PUBLIC_KEY = os.environ.get("FI_XHTTP_REALITY_PUBLIC_KEY", FI_REALITY_PUBLIC_KEY).strip()
FI_XHTTP_REALITY_SHORT_ID = os.environ.get("FI_XHTTP_REALITY_SHORT_ID", FI_REALITY_SHORT_ID).strip()
FI_XHTTP_REALITY_SNI = os.environ.get("FI_XHTTP_REALITY_SNI", "sber.ru").strip()
FI_XHTTP_REALITY_PORT = int(os.environ.get("FI_XHTTP_REALITY_PORT", "8443"))
HYSTERIA_PORT = int(os.environ.get("HYSTERIA_PORT", "443"))

HAPP_DOWNLOAD_URL = "https://www.happ.su/main"
HAPP_IOS_URL = "https://apps.apple.com/us/app/happ-proxy-utility/id6504287215"
HAPP_ANDROID_URL = "https://play.google.com/store/apps/details?id=com.happproxy"
HAPP_ANDROID_APK_URL = "https://github.com/Happ-proxy/happ-android/releases/latest/download/Happ.apk"
STREISAND_IOS_URL = "https://apps.apple.com/us/app/streisand/id6450534064"
STREISAND_MACOS_URL = "https://apps.apple.com/us/app/streisand/id6450534064"
CLASH_MI_IOS_URL = "https://apps.apple.com/app/clash-mi/id6744321968"
CLASH_DOWNLOAD_URL = "https://github.com/clash-verge-rev/clash-verge-rev/releases"
V2RAYN_DOWNLOAD_URL = "https://github.com/2dust/v2rayN/releases"
NEKOBOX_DOWNLOAD_URL = "https://github.com/MatsuriDayo/NekoBoxForAndroid/releases"
V2RAYNG_DOWNLOAD_URL = "https://github.com/2dust/v2rayNG/releases"
SINGBOX_IOS_URL = "https://apps.apple.com/app/sing-box-mt/id6785326793"
SINGBOX_DOWNLOAD_URL = "https://github.com/SagerNet/sing-box/releases"

# --- 100% Official Authentic Original Application Icons ---
# Served locally from /assets/apps/ in lightweight modern WebP format
OFFICIAL_CLASH_MI_ICON = "/assets/apps/clash_mi.webp"
OFFICIAL_CLASH_ICON = "/assets/apps/clash.webp"
OFFICIAL_NEKOBOX_ICON = "/assets/apps/nekobox.webp"
OFFICIAL_V2RAYNG_ICON = "/assets/apps/v2rayng.webp"
OFFICIAL_HAPP_ICON = "/assets/apps/happ.webp"
OFFICIAL_STREISAND_ICON = "/assets/apps/streisand.webp"
OFFICIAL_V2RAYN_ICON = "/assets/apps/v2rayn.webp"
OFFICIAL_SINGBOX_ICON = "/assets/apps/singbox.webp"


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
    env_path = os.environ.get("STORE_DB_PATH", "").strip() or os.environ.get("SHOP_DATABASE_PATH", "").strip()
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


def check_bind_email_rate_limit(client_ip: str, max_requests: int = 15, window_sec: int = 300) -> bool:
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


_shop_checkout_lock = threading.Lock()
_shop_checkout_instance = None

def get_shop_checkout():
    global _shop_checkout_instance
    with _shop_checkout_lock:
        if _shop_checkout_instance is None:
            try:
                from vpn_shop.store import Store
                from vpn_shop.web import WebCheckout
                settings = get_shop_settings()
                db_path = find_store_db_path()
                store = Store(database_path=Path(db_path))
                store.init()
                _shop_checkout_instance = WebCheckout(settings=settings, store=store)
            except Exception as exc:
                LOGGER.warning("Could not instantiate WebCheckout in subjson-service: %s", exc)
        return _shop_checkout_instance


def find_profile_for_sub(wc, subscription_id: str) -> dict[str, Any] | None:
    if not wc:
        return None
    clean = str(subscription_id or "").strip()
    prof = wc.get_profile_by_any_sub_id(clean)
    if prof:
        return prof
    try:
        _, _, _, _, client = find_subscription(clean)
        xemail = str(client.get("email") or "").strip()
        if xemail:
            prof = wc.store.get_profile_by_xui_email(xemail)
            if prof:
                return prof
    except Exception:
        pass
    return None


OPENFLUX_CLUSTER_KEY = os.environ.get("OPENFLUX_CLUSTER_KEY", "sc_oflux_2026_e8d47b19a3c25f01e74a")

DEFAULT_OPENFLUX_POOLS: dict[str, list[str]] = {
    "nl": [
        "https://disk.yandex.ru/i/2fQ-JSKoBNlWag"
    ],
    "pl": [
        "https://disk.yandex.ru/i/hb1xodFfECGL8w"
    ],
    "fi": [
        "https://yadi.sk/d/I0ULWUKv_9YzpA"
    ]
}


def load_openflux_pool(country: str) -> list[str]:
    c = (country or "nl").lower().strip()
    pool_file = Path(f"/etc/openflux-node/pool_{c}.json")
    if pool_file.is_file():
        try:
            with open(pool_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                urls = [s["url"] for s in data.get("shards", []) if s.get("active", True) and s.get("url")]
                if urls:
                    return urls
        except Exception as exc:
            LOGGER.warning("Could not read openflux pool %s: %s", pool_file, exc)
    return DEFAULT_OPENFLUX_POOLS.get(c, DEFAULT_OPENFLUX_POOLS["nl"])


def build_openflux_v1_link(country: str, sub_id: str, label: str = "") -> tuple[str, str, str]:
    """
    Returns (openflux_v1_url, primary_shard_url, backup_shard_url).
    Encodes via official OpenFlux v0.2.0 standard: raw DEFLATE + Base64url (no padding).
    """
    c = (country or "nl").lower().strip()
    country_labels = {
        "nl": ("Нидерланды", "🇳🇱"),
        "pl": ("Польша", "🇵🇱"),
        "fi": ("Финляндия", "🇫🇮"),
    }
    c_name, flag = country_labels.get(c, ("Нидерланды", "🇳🇱"))
    shards = load_openflux_pool(c)

    clean_sub = str(sub_id or "default").strip()
    hash_val = int(hashlib.sha256(f"{clean_sub}:{c}".encode("utf-8")).hexdigest(), 16)
    prim_idx = hash_val % len(shards)
    primary_url = shards[prim_idx]

    backup_url = None
    if len(shards) > 1:
        back_idx = (prim_idx + 1) % len(shards)
        backup_url = shards[back_idx]

    node_label = label or f"SilentConnect {flag} {c_name}"
    payload = {
        "name": node_label,
        "secret": OPENFLUX_CLUSTER_KEY,
        "context": primary_url,
        "transports": [
            {"type": "vyandex", "url": primary_url}
        ]
    }
    if backup_url and backup_url != primary_url:
        payload["negotiate"] = True
        payload["transports"][0]["priority"] = 100
        payload["transports"].append({"type": "vyandex", "url": backup_url, "priority": 80})

    json_bytes = json.dumps(payload, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    compressor = zlib.compressobj(level=9, wbits=-zlib.MAX_WBITS)
    deflated = compressor.compress(json_bytes) + compressor.flush()
    b64 = base64.urlsafe_b64encode(deflated).decode("ascii").rstrip("=")
    link = f"openflux://v1/{b64}"
    return link, primary_url, (backup_url or primary_url)


def render_subjson_awg_container(subscription_id: str, support_url: str) -> str:
    try:
        wc = get_shop_checkout()
        if not wc:
            return f"""
            <div class="awg-quota-widget" style="text-align: center; padding: 24px 16px;">
              <div style="font-size: 28px; margin-bottom: 8px;">🚀</div>
              <div style="font-size: 16px; font-weight: 700; color: #fff; margin-bottom: 6px;">Скоростной режим AmneziaWG</div>
              <p style="font-size: 13.5px; color: var(--muted); max-width: 480px; margin: 0 auto 16px;">
                Выделенные слоты WireGuard и пакет скоростного трафика привязаны к вашей активной подписке.
              </p>
              <a class="button success" href="{support_url}" target="_blank" rel="noopener">Связаться с поддержкой</a>
            </div>
            """
        prof = find_profile_for_sub(wc, subscription_id)
        if not prof:
            return f"""
            <div class="awg-quota-widget" style="text-align: center; padding: 24px 16px;">
              <div style="font-size: 28px; margin-bottom: 8px;">🚀</div>
              <div style="font-size: 16px; font-weight: 700; color: #fff; margin-bottom: 6px;">Скоростной режим AmneziaWG</div>
              <p style="font-size: 13.5px; color: var(--muted); max-width: 480px; margin: 0 auto 16px;">
                Подписка синхронизируется с сервером. Пожалуйста, обновите страницу через несколько секунд.
              </p>
              <a class="button secondary" href="" onclick="window.location.reload(); return false;">Обновить страницу 🔄</a>
            </div>
            """

        widget_html = wc.render_awg_slots_widget(prof, subscription_id)

        instructions_html = """
        <div class="platform-selector-card" style="margin-top: 24px;">
          <div class="platform-bar-header">
            <div class="platform-bar-title">
              <span style="font-size:16px;">💻</span>
              <span>Операционная система для Amnezia</span>
            </div>
            <span class="platform-bar-hint">Автоопределение: <strong id="detected-awg-platform-label">iOS (iPhone)</strong></span>
          </div>
          <div class="platform-nav-track" id="awg-platform-tabs" role="tablist" aria-label="Выбор ОС для Amnezia"></div>
        </div>

        <div style="margin: 18px 0 10px 0; font-size: 13px; font-weight: 700; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px;">Клиентское приложение:</div>
        <div class="apps" id="awg-apps-selector" role="region" aria-live="polite"></div>

        <div class="steps" id="awg-steps-container">
          <div class="step" data-num="1">
            <h3>1. Установка клиента Amnezia VPN</h3>
            <p>Скачайте официальное бесплатное приложение с открытым исходным кодом для вашей операционной системы:</p>
            <div class="buttons" style="flex-wrap: wrap; gap: 8px;">
              <a class="button secondary" href="https://apps.apple.com/app/amneziavpn/id1600529900" target="_blank" rel="noopener">🍏 App Store (iOS)</a>
              <a class="button secondary" href="https://play.google.com/store/apps/details?id=org.amnezia.vpn" target="_blank" rel="noopener">🤖 Google Play (Android)</a>
              <a class="button secondary" href="https://github.com/amnezia-vpn/amnezia-client/releases" target="_blank" rel="noopener">📦 Windows / macOS / Linux / APK</a>
            </div>
          </div>
          <div class="step" data-num="2">
            <h3>2. Добавление конфигурации устройства</h3>
            <p>Выберите нужный слот в блоке выше (например, «Устройство 1» для смартфона, «Устройство 2» для ПК):</p>
            <ul style="margin: 6px 0 10px 20px; padding: 0; font-size: 13.5px; color: #cbd5e1; line-height: 1.5;">
              <li><b>На смартфоне:</b> Нажмите «📱 Показать QR-код» у слота, в Amnezia VPN нажмите <b>«+»</b> → <b>«Сканировать QR-код»</b>.</li>
              <li><b>На компьютере:</b> Нажмите «📥 Скачать .conf», в Amnezia VPN выберите <b>«Файл с настройками»</b> и укажите файл.</li>
            </ul>
          </div>
          <div class="step done" data-num="3">
            <h3>3. Подключение и работа</h3>
            <p>Нажмите центральную кнопку подключения в Amnezia VPN. Весь заблокированный трафик пойдёт через наш скоростной шифрованный WireGuard-канал без потери скорости.</p>
          </div>
        </div>
        """
        return widget_html + instructions_html
    except Exception as exc:
        LOGGER.warning("Could not render AWG container: %s", exc)
        return f"""
        <div class="awg-quota-widget" style="text-align: center; padding: 24px 16px;">
          <div style="font-size: 28px; margin-bottom: 8px;">🚀</div>
          <div style="font-size: 16px; font-weight: 700; color: #fff; margin-bottom: 6px;">Скоростной режим AmneziaWG</div>
          <p style="font-size: 13.5px; color: var(--muted); max-width: 480px; margin: 0 auto 16px;">
            Выделенные слоты WireGuard активны. Если виджет не загрузился, свяжитесь с поддержкой.
          </p>
          <a class="button success" href="{support_url}" target="_blank" rel="noopener">Связаться с поддержкой</a>
        </div>
        """


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

        # Check current linked email to determine if this is an email change
        current_email = ""
        if order_rows:
            for ord_r in order_rows:
                if ord_r["customer_email"]:
                    current_email = str(ord_r["customer_email"]).strip().lower()
                    break

        is_email_change = bool(current_email and current_email != clean_email)
        is_first_bind = bool(not current_email)

        # Enforce rate limit: maximum 5 email changes per 24 hours per subscription profile
        conn_shop.execute(
            """
            CREATE TABLE IF NOT EXISTS profile_email_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sub_id TEXT NOT NULL,
                profile_id INTEGER NOT NULL,
                old_email TEXT,
                new_email TEXT NOT NULL,
                changed_at INTEGER NOT NULL,
                client_ip TEXT
            );
            """
        )
        conn_shop.execute(
            "CREATE INDEX IF NOT EXISTS idx_email_changes_sub_time ON profile_email_changes(sub_id, changed_at);"
        )
        conn_shop.execute(
            "CREATE INDEX IF NOT EXISTS idx_email_changes_prof_time ON profile_email_changes(profile_id, changed_at);"
        )

        if is_email_change or is_first_bind:
            day_ago = now - 86400
            cnt_row = conn_shop.execute(
                """
                SELECT COUNT(*) AS cnt FROM profile_email_changes
                WHERE (sub_id = ? OR profile_id = ?) AND changed_at >= ?
                """,
                (target_sub, profile_id, day_ago),
            ).fetchone()
            changes_today = int(cnt_row["cnt"] or 0) if cnt_row else 0
            if changes_today >= 5:
                raise ValueError("Нельзя менять почту более 5 раз в день для одной подписки. Если вам требуется помощь, обратитесь в службу поддержки.")

            if client_ip and client_ip not in ("127.0.0.1", "::1", "localhost", "unknown"):
                ip_row = conn_shop.execute(
                    "SELECT COUNT(*) AS cnt FROM profile_email_changes WHERE client_ip = ? AND changed_at >= ?",
                    (client_ip, day_ago),
                ).fetchone()
                if int(ip_row["cnt"] or 0) >= 10:
                    raise ValueError("Слишком много запросов на смену почты с вашего IP-адреса. Пожалуйста, обратитесь в службу поддержки.")

            conn_shop.execute(
                """
                INSERT INTO profile_email_changes(sub_id, profile_id, old_email, new_email, changed_at, client_ip)
                VALUES(?, ?, ?, ?, ?, ?)
                """,
                (target_sub, profile_id, current_email, clean_email, now, client_ip),
            )

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
                plan_name="SilentConnect (Привязка Email)",
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


def _notify_admins_new_renewal_order(
    order_public_id: str,
    customer_email: str,
    transport: str,
    duration_days: int,
    device_limit: int,
    final_price_rub: int,
) -> None:
    try:
        db_path = find_store_db_path()
        if not Path(db_path).exists():
            return

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
        if not bot_token:
            return

        conn = sqlite3.connect(db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
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

        if not admin_chats:
            conn.close()
            return

        email_str = customer_email.strip() or "не указан"
        tr_label = "Стандартный" if transport == "tcp" else ("Скоростной" if transport == "xhttp" else transport.upper())
        lim_label = f"{device_limit} устройства" if device_limit in (3, 4) else (f"{device_limit} устройств" if device_limit > 4 else f"{device_limit} устройство")

        text = "\n".join([
            "🛒 Продление подписки на сайте (ожидает оплаты)",
            "",
            f"Заказ: `{order_public_id}`",
            f"Email: `{email_str}`",
            f"Транспорт: {tr_label}",
            f"Срок: {duration_days} дн.",
            f"Лимит: {lim_label}",
            f"Сумма: {final_price_rub} RUB",
            "",
            "Покупатель перешел к оплате. Реквизиты выдаются оператором в поддержке.",
            "При поступлении перевода нажмите кнопку ниже — доступ автоматически активируется и ссылка отправится клиенту на почту.",
        ])

        markup = {
            "inline_keyboard": [
                [
                    {"text": "Подтвердить оплату", "callback_data": f"admin:confirm:{order_public_id}"},
                ],
                [
                    {"text": "Отменить заказ", "callback_data": f"admin:cancel:{order_public_id}"},
                ],
            ]
        }

        for chat_id in admin_chats:
            try:
                payload = json.dumps({
                    "chat_id": chat_id,
                    "text": text,
                    "parse_mode": "Markdown",
                    "reply_markup": markup,
                }).encode("utf-8")
                req = urllib.request.Request(
                    f"https://api.telegram.org/bot{bot_token}/sendMessage",
                    data=payload,
                    headers={"Content-Type": "application/json"}
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    resp_data = json.loads(resp.read().decode())
                    if resp_data.get("ok"):
                        msg_id = resp_data["result"]["message_id"]
                        conn.execute(
                            "UPDATE orders SET manager_chat_id = ?, manager_message_id = ? WHERE public_id = ?",
                            (str(chat_id), msg_id, order_public_id)
                        )
                        conn.commit()
            except Exception as e:
                LOGGER.warning("Failed to notify admin %s about renewal %s: %s", chat_id, order_public_id, e)
        conn.close()
    except Exception as exc:
        LOGGER.exception("Error in _notify_admins_new_renewal_order for %s: %s", order_public_id, exc)


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
        if "admin_personal" not in notes and not str(prof["xui_email"] or "").startswith("admin-") and (notes in {"public_trial_7d_auto_delete", "admin_test_24h_auto_delete"} or "trial" in notes or "test" in notes or "auto_delete" in notes):
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
        device_base_prices = {3: 149, 6: 199, 9: 235}
        base_price = device_base_prices.get(device_limit, 149) * months

        # Promo discount check
        discount_percent = 0
        promo_id = None
        if promo_code:
            code_hash = hash_secret(promo_code.strip().upper())
            now_ts = int(time.time())
            p_row = conn_shop.execute(
                """
                SELECT * FROM promo_codes
                WHERE code_hash = ?
                  AND enabled = 1
                  AND used_count < max_uses
                  AND (expires_at IS NULL OR expires_at > ?)
                """,
                (code_hash, now_ts),
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
        token_hash = hash_token(token, purpose="order_web")

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
        try:
            order_cols = [r[1] for r in conn_shop.execute("PRAGMA table_info(orders)").fetchall()]
            if "web_token_hash" in order_cols:
                conn_shop.execute("UPDATE orders SET web_token_hash = ? WHERE public_id = ?", (token_hash, order_pub_id))
        except Exception:
            pass
        conn_shop.commit()

        # Notify admins about pending renewal order (async)
        if status == "waiting_payment":
            threading.Thread(
                target=_notify_admins_new_renewal_order,
                args=(order_pub_id, final_email, transport, duration_days, device_limit, final_price),
                daemon=True,
            ).start()

        # If free: renew immediately in x-ui & store
        if final_price == 0:
            if promo_id:
                consumed = conn_shop.execute(
                    """
                    UPDATE promo_codes
                    SET used_count = used_count + 1, last_used_at = ?
                    WHERE id = ?
                      AND enabled = 1
                      AND used_count < max_uses
                    RETURNING *
                    """,
                    (now, promo_id),
                ).fetchone()
                if not consumed:
                    raise ValueError("Промокод больше недоступен или исчерпан.")

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
                        try:
                            xui_rw.execute(
                                """
                                INSERT INTO client_traffics (inbound_id, enable, email, up, down, total, expiry_time)
                                VALUES (?, 1, ?, 0, 0, 0, ?)
                                ON CONFLICT(email) DO UPDATE SET
                                    enable = 1,
                                    inbound_id = excluded.inbound_id,
                                    expiry_time = excluded.expiry_time
                                """,
                                (found_client["inbound_id"], email, new_exp_ms),
                            )
                        except sqlite3.OperationalError:
                            pass
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


def render_payment_notice_html(order_data: Any, status_override: str | None = None, is_profile_active: bool = False) -> str:
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
        if token:
            order_page_url = f"{HAPP_WEB_PAGE_URL}/order/{order_id}/{token}"
        elif meta.get("platega_url"):
            order_page_url = str(meta["platega_url"])
        else:
            order_page_url = f"{HAPP_WEB_PAGE_URL}/order/{order_id}"
        support_link = os.environ.get("SUPPORT_URL", "https://t.me/SilentConnectSupport")
        if is_profile_active:
            price_val = order.get('final_price_rub', 0)
            return f"""
            <section id="paymentNoticeCard" class="install" data-order-id="{order_id}" data-order-status="waiting_payment" style="position:relative; margin-bottom:16px; background:rgba(245,158,11,0.08); border:1px solid rgba(245,158,11,0.3); border-radius:12px; padding:10px 14px; display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap;">
              <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
                <span style="font-size:16px;">💳</span>
                <span style="font-size:13.5px; color:#fff; font-weight:600;">Заказ продления #{order_id} ({price_val} ₽)</span>
                <span style="background:rgba(245, 158, 11, 0.15); border:1px solid rgba(245, 158, 11, 0.35); color:#f59e0b; padding:2px 8px; border-radius:6px; font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:0.4px;">Ожидает оплаты</span>
              </div>
              <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
                <a href="{html.escape(order_page_url, quote=True)}" class="button" style="min-height:32px; padding:4px 14px; font-size:13px; font-weight:700; background:var(--green); color:#000; text-decoration:none; border-radius:8px; display:inline-flex; align-items:center;">Оплатить</a>
                <form method="post" action="/{SECRET_SEGMENT}/cancel/{order_id}{token_query}" style="margin:0; display:inline;">
                  {token_input}
                  <button type="submit" class="button secondary" style="min-height:32px; padding:4px 10px; font-size:12px; font-weight:600; background:rgba(239,68,68,0.12); color:#ef4444; border:1px solid rgba(239,68,68,0.3); border-radius:8px; cursor:pointer; display:inline-flex; align-items:center; gap:4px; transition:all 0.2s;" onmouseover="this.style.background='rgba(239,68,68,0.22)';" onmouseout="this.style.background='rgba(239,68,68,0.12)';" title="Отменить заказ">Отменить ✖</button>
                </form>
              </div>
            </section>
            """
        return f"""
        <section class="install" style="margin-bottom:24px; background:rgba(47,191,113,0.08); border:1px solid var(--green); border-radius:14px; padding:18px 20px;">
          <div class="install-head" style="display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; margin-bottom:12px;">
            <h2 style="margin:0; font-size:18px; font-weight:700; color:#fff;">💳 Заказ продления #{order_id}</h2>
            <span style="background:rgba(245, 158, 11, 0.15); border:1px solid rgba(245, 158, 11, 0.4); color:#f59e0b; padding:4px 10px; border-radius:8px; font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:0.5px; display:inline-block;">Ожидает оплаты</span>
          </div>
          <div style="font-size:28px; font-weight:800; color:#fff; margin:8px 0 14px;">
            {order.get('final_price_rub', 0)} ₽ <span style="font-size:14px; color:var(--muted); font-weight:500;">({duration_days} дн., до {device_limit} устр.)</span>
          </div>
          <p style="color:#e2e8f0; font-size:14px; line-height:1.5; margin:0 0 16px;">
            Оплатите заказ онлайн (СБП, банковские карты, криптовалюта) на защищённой странице оплаты:
          </p>
          <div style="display:flex; gap:12px; flex-wrap:wrap; align-items:center;">
            <a href="{html.escape(order_page_url, quote=True)}" class="button" style="min-height:44px; font-weight:700; text-decoration:none; background:var(--green); color:#000; display:inline-flex; align-items:center; justify-content:center; padding:10px 18px; border-radius:8px;">Перейти к оплате заказа</a>
            <a href="{html.escape(support_link, quote=True)}" target="_blank" rel="noopener" class="button secondary" style="min-height:44px; font-weight:600; text-decoration:none; display:inline-flex; align-items:center; justify-content:center; padding:10px 16px; border-radius:8px; background:rgba(255,255,255,0.08); color:#fff; border:1px solid rgba(255,255,255,0.2); transition:all 0.2s;" onmouseover="this.style.background='rgba(255,255,255,0.16)';" onmouseout="this.style.background='rgba(255,255,255,0.08)';">Поддержка 💬</a>
            <form method="post" action="/{SECRET_SEGMENT}/cancel/{order_id}{token_query}" style="margin:0;">
              {token_input}
              <button type="submit" class="button secondary" style="min-height:44px; font-weight:600; background:rgba(239,68,68,0.12); color:#ef4444; border:1px solid rgba(239,68,68,0.3); border-radius:8px; cursor:pointer; padding:10px 16px; display:inline-flex; align-items:center; justify-content:center; transition:all 0.2s;" onmouseover="this.style.background='rgba(239,68,68,0.22)';" onmouseout="this.style.background='rgba(239,68,68,0.12)';">Отменить ✖</button>
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
            email = ""
            try:
                row, _, _, _, client = find_subscription(target_sub)
                if client:
                    email = str(client.get("email") or "")
            except Exception:
                pass
            prof = None
            if email:
                prof = conn.execute("SELECT * FROM profiles WHERE xui_email = ?", (email,)).fetchone()
            if not prof:
                prof = conn.execute("SELECT * FROM profiles WHERE public_id = ? OR xui_client_id = ?", (target_sub, target_sub)).fetchone()
            if prof:
                order = conn.execute(
                    "SELECT * FROM orders WHERE provisioned_profile_id = ? ORDER BY id DESC LIMIT 1",
                    (prof["id"],)
                ).fetchone()
                if order:
                    now = int(time.time())
                    updated_at = order["updated_at"] or order["created_at"] or 0
                    created_time = order["created_at"] or updated_at or 0
                    if order["status"] in ("paid", "delivered") and (now - updated_at > 86400 * 5 or now - created_time > 86400 * 5):
                        return ""
                    if order["status"] in ("canceled", "cancelled") and (now - updated_at > 86400 or now - created_time > 86400):
                        return ""
                    meta = json.loads(order["meta_json"] or "{}") if isinstance(order["meta_json"], str) else (order["meta_json"] or {})

                    # Expire unpaid orders
                    if order["status"] == "waiting_payment":
                        created_time = order["created_at"] or updated_at or 0
                        # 1. Unpaid orders older than 24h are expired
                        if now - created_time > 86400:
                            try:
                                conn.execute("UPDATE orders SET status = 'cancelled', updated_at = ?, closed_at = ? WHERE id = ?", (now, now, order["id"]))
                                conn.commit()
                            except Exception:
                                pass
                            return ""
                        # 2. Payment gateway canceled / expired / failed
                        platega_st = str(meta.get("platega_status") or "").upper()
                        if platega_st in ("CANCELED", "CANCELLED", "EXPIRED", "FAILED"):
                            try:
                                conn.execute("UPDATE orders SET status = 'cancelled', updated_at = ?, closed_at = ? WHERE id = ?", (now, now, order["id"]))
                                conn.commit()
                            except Exception:
                                pass
                            return ""

                    # Backfill web_token if missing on active waiting_payment order
                    token = str(meta.get("web_token") or "")
                    if not token and order["status"] == "waiting_payment":
                        try:
                            new_token = secrets.token_hex(12)
                            eff_pepper = os.environ.get("SERVER_PEPPER", "silentconnect-pepper-secret-v1").encode("utf-8")
                            msg = f"order_web\x00{new_token}".encode("utf-8")
                            token_hash = hmac.new(eff_pepper, msg, hashlib.sha256).hexdigest()
                            meta["web_token"] = new_token
                            token = new_token
                            order_cols = [r[1] for r in conn.execute("PRAGMA table_info(orders)").fetchall()]
                            if "web_token_hash" in order_cols:
                                conn.execute(
                                    "UPDATE orders SET web_token_hash = ?, meta_json = ?, updated_at = ? WHERE id = ?",
                                    (token_hash, json.dumps(meta), now, order["id"])
                                )
                            else:
                                conn.execute(
                                    "UPDATE orders SET meta_json = ?, updated_at = ? WHERE id = ?",
                                    (json.dumps(meta), now, order["id"])
                                )
                            conn.commit()
                        except Exception as tok_err:
                            LOGGER.debug("Could not backfill web_token for order %s: %s", order.get("public_id"), tok_err)

                    dismissed_status = meta.get("notice_dismissed_status")
                    if dismissed_status:
                        norm_current = "paid" if order["status"] in ("paid", "delivered") else str(order["status"])
                        norm_dismissed = "paid" if dismissed_status in ("paid", "delivered") else str(dismissed_status)
                        if norm_current == norm_dismissed:
                            return ""
                    prof_keys = prof.keys()
                    is_active = False
                    if "expires_at" in prof_keys and prof["expires_at"]:
                        is_active = bool(int(prof["expires_at"]) > now)
                    elif "status" in prof_keys:
                        is_active = (prof["status"] == "active")
                    order_dict = dict(order)
                    order_dict["meta_json"] = meta
                    return render_payment_notice_html(order_dict, is_profile_active=is_active)
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
    return public_subscription_url(headers, "import", subscription_id)


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
                "fi-classic-tcp",
                "fi-fast-tcp",
                "fi-speed-hysteria2",
                "fi-backup-grpc",
                "nl-ws443",
                "fi-ws443",
                "nl-openflux-socks",
                "pl-openflux-socks",
                "fi-openflux-socks",
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
                "fi-classic-tcp",
                "fi-fast-tcp",
                "fi-speed-hysteria2",
                "fi-backup-grpc",
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
                    "public_key": NL_REALITY_PUBLIC_KEY,
                    "short_id": NL_REALITY_SHORT_ID,
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
                    "public_key": NL_REALITY_PUBLIC_KEY,
                    "short_id": NL_REALITY_SHORT_ID,
                },
            },
            "packet_encoding": "xudp",
        },
        {
            "type": "hysteria2",
            "tag": "nl-speed-hysteria2",
            "server": nl_edge,
            "server_ports": ["30000:40000"],
            "hop_interval": "30s",
            "password": client_uuid,
            "tls": {
                "enabled": True,
                "server_name": nl_edge,
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
                    "public_key": NL_GRPC_REALITY_PUBLIC_KEY,
                    "short_id": NL_GRPC_REALITY_SHORT_ID,
                },
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
                    "public_key": FI_REALITY_PUBLIC_KEY,
                    "short_id": FI_REALITY_SHORT_ID,
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
                    "public_key": FI_REALITY_PUBLIC_KEY,
                    "short_id": FI_REALITY_SHORT_ID,
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
                "server_name": FI_GRPC_REALITY_SNI,
                "utls": {"enabled": True, "fingerprint": "chrome"},
                "reality": {
                    "enabled": True,
                    "public_key": FI_GRPC_REALITY_PUBLIC_KEY,
                    "short_id": FI_GRPC_REALITY_SHORT_ID,
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
        {
            "type": "socks",
            "tag": "nl-openflux-socks",
            "server": "127.0.0.1",
            "server_port": 1080,
            "version": "5",
        },
        {
            "type": "socks",
            "tag": "pl-openflux-socks",
            "server": "127.0.0.1",
            "server_port": 1081,
            "version": "5",
        },
        {
            "type": "socks",
            "tag": "fi-openflux-socks",
            "server": "127.0.0.1",
            "server_port": 1082,
            "version": "5",
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
                "aiprimetech.io",
                "platega.io",
                "api.platega.io",
                "app.platega.io",
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
                ]
                if "fi-ws443" in ob_group["outbounds"]:
                    fi_idx = ob_group["outbounds"].index("fi-ws443")
                    ob_group["outbounds"].insert(fi_idx + 1, "pl-ws443")
                else:
                    ob_group["outbounds"].append("pl-ws443")
            elif ob_group.get("tag") == "auto-urltest":
                ob_group["outbounds"].extend([
                    "pl-classic-tcp",
                    "pl-fast-tcp",
                    "pl-speed-hysteria2",
                    "pl-backup-grpc",
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
                "tag": "pl-ws443",
                "server": pl_edge,
                "server_port": 443,
                "uuid": client_uuid,
                "transport": {
                    "type": "ws",
                    "path": WS443_PATH,
                    "headers": {"Host": pl_edge},
                },
                "tls": {
                    "enabled": True,
                    "server_name": pl_edge,
                    "utls": {"enabled": True, "fingerprint": "chrome"},
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
            "pl-ws443": "🇵🇱 Резерв (WebSocket)",
            "nl-openflux-socks": "🇳🇱 🛡️ Белые Списки · NL",
            "pl-openflux-socks": "🇵🇱 🛡️ Белые Списки · PL",
            "fi-openflux-socks": "🇫🇮 🛡️ Белые Списки · FI",
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
                        "aiprimetech.io",
                        "platega.io",
                        "api.platega.io",
                        "app.platega.io",
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
                "public-key": NL_REALITY_PUBLIC_KEY,
                "short-id": NL_REALITY_SHORT_ID,
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
                "public-key": NL_REALITY_PUBLIC_KEY,
                "short-id": NL_REALITY_SHORT_ID,
            },
            "client-fingerprint": "chrome",
            "udp": True,
        },
        {
            "name": "🇳🇱 NL Speed Hysteria2",
            "type": "hysteria2",
            "server": nl_edge,
            "port": 443,
            "password": client_uuid,
            "sni": nl_edge,
            "alpn": ["h3"],
            "obfs": "salamander",
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
                "public-key": NL_GRPC_REALITY_PUBLIC_KEY,
                "short-id": NL_GRPC_REALITY_SHORT_ID,
            },
            "grpc-opts": {"grpc-service-name": GRPC_SERVICE_NAME},
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
            "servername": FI_REALITY_SNI_CLASSIC,
            "reality-opts": {
                "public-key": FI_REALITY_PUBLIC_KEY,
                "short-id": FI_REALITY_SHORT_ID,
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
            "servername": FI_REALITY_SNI_FAST,
            "reality-opts": {
                "public-key": FI_REALITY_PUBLIC_KEY,
                "short-id": FI_REALITY_SHORT_ID,
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
            "obfs": "salamander",
            "obfs-password": salamander_pwd,
            "udp": True,
        },
        {
            "name": "🇫🇮 FI Backup Reality gRPC",
            "type": "vless",
            "server": fi_edge,
            "port": 29443,
            "uuid": client_uuid,
            "network": "grpc",
            "tls": True,
            "servername": FI_GRPC_REALITY_SNI,
            "reality-opts": {
                "public-key": FI_GRPC_REALITY_PUBLIC_KEY,
                "short-id": FI_GRPC_REALITY_SHORT_ID,
            },
            "grpc-opts": {"grpc-service-name": GRPC_SERVICE_NAME},
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
                "password": client_uuid,
                "alpn": ["h3"],
                "obfs": "salamander",
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
        ])

    proxies.extend([
        {
            "name": "🇳🇱 🛡️ Белые Списки · NL",
            "type": "socks5",
            "server": "127.0.0.1",
            "port": 1080,
            "udp": True,
        },
        {
            "name": "🇵🇱 🛡️ Белые Списки · PL",
            "type": "socks5",
            "server": "127.0.0.1",
            "port": 1081,
            "udp": True,
        },
    ])

    all_proxy_names = [p["name"] for p in proxies]
    auto_test_proxies = [p["name"] for p in proxies if "Белые Списки" not in p["name"]]

    proxy_groups = [
        {
            "name": "🚀 PROXY",
            "type": "select",
            "proxies": ["⚡ Auto URL-Test", "🛡️ Priority Fallback"] + all_proxy_names + ["DIRECT"],
        },
        {
            "name": "⚡ Auto URL-Test",
            "type": "url-test",
            "proxies": auto_test_proxies,
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
            "GEOIP,PRIVATE,DIRECT,no-resolve",
            "DOMAIN-SUFFIX,ru,DIRECT",
            "DOMAIN-SUFFIX,su,DIRECT",
            "DOMAIN-SUFFIX,xn--p1ai,DIRECT",
            "DOMAIN-SUFFIX,gosuslugi.ru,DIRECT",
            "DOMAIN-SUFFIX,sberbank.ru,DIRECT",
            "DOMAIN-SUFFIX,tinkoff.ru,DIRECT",
            "DOMAIN-SUFFIX,railnation-game.ru,DIRECT",
            "GEOIP,RU,DIRECT,no-resolve",
        ])
    else:
        rules.extend([
            "GEOIP,PRIVATE,DIRECT,no-resolve",
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
            "default-nameserver": ["77.88.8.8", "77.88.8.1"],
            "nameserver": ["77.88.8.8", "77.88.8.1"],
            "fallback": ["https://77.88.8.8/dns-query", "https://dns.adguard-dns.com/dns-query"],
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
        f"vless://{client_uuid}@{nl_edge}:443?type=tcp&security=reality&pbk={NL_REALITY_PUBLIC_KEY}&fp=chrome&sni={TCP_REALITY_SNI_CLASSIC}&sid={NL_REALITY_SHORT_ID}&flow=xtls-rprx-vision#{urllib.parse.quote('🇳🇱 1. Классический TCP (NL)')}",
        f"vless://{client_uuid}@{nl_edge}:443?type=tcp&security=reality&pbk={NL_REALITY_PUBLIC_KEY}&fp=chrome&sni={TCP_REALITY_SNI_FAST}&sid={NL_REALITY_SHORT_ID}&flow=xtls-rprx-vision#{urllib.parse.quote('🇳🇱 2. Быстрый TCP (NL)')}",
        f"hy2://{client_uuid}@{nl_edge}:443?sni={nl_edge}&alpn=h3&obfs=gecko&obfs-password={salamander_pwd}#{urllib.parse.quote('🇳🇱 3. Скоростной Hysteria2 (NL)')}",
        f"vless://{client_uuid}@{nl_edge}:29443?type=grpc&security=reality&pbk={NL_GRPC_REALITY_PUBLIC_KEY}&fp=chrome&sni={GRPC_REALITY_SNI}&sid={NL_GRPC_REALITY_SHORT_ID}&serviceName={GRPC_SERVICE_NAME}#{urllib.parse.quote('🇳🇱 4. Запасной gRPC (NL)')}",
        f"vless://{client_uuid}@{nl_edge}:443?type=xhttp&security=tls&sni={nl_edge}&alpn=h2,http/1.1&path=%2Fxh-mx-d1f7c0429d6a&mode=packet-up#{urllib.parse.quote('🇳🇱 5. Незаметный XHTTP (NL)')}",
        f"vless://{client_uuid}@{fi_edge}:443?type=tcp&security=reality&pbk={FI_REALITY_PUBLIC_KEY}&fp=chrome&sni={FI_REALITY_SNI_CLASSIC}&sid={FI_REALITY_SHORT_ID}&flow=xtls-rprx-vision#{urllib.parse.quote('🇫🇮 6. Классический TCP (FI)')}",
        f"vless://{client_uuid}@{fi_edge}:443?type=tcp&security=reality&pbk={FI_REALITY_PUBLIC_KEY}&fp=chrome&sni={FI_REALITY_SNI_FAST}&sid={FI_REALITY_SHORT_ID}&flow=xtls-rprx-vision#{urllib.parse.quote('🇫🇮 7. Быстрый TCP (FI)')}",
        f"hy2://{client_uuid}@{fi_edge}:443?sni={fi_edge}&alpn=h3&obfs=gecko&obfs-password={salamander_pwd}#{urllib.parse.quote('🇫🇮 8. Скоростной Hysteria2 (FI)')}",
        f"vless://{client_uuid}@{fi_edge}:29443?type=grpc&security=reality&pbk={FI_GRPC_REALITY_PUBLIC_KEY}&fp=chrome&sni={FI_GRPC_REALITY_SNI}&sid={FI_GRPC_REALITY_SHORT_ID}&serviceName={GRPC_SERVICE_NAME}#{urllib.parse.quote('🇫🇮 9. Запасной gRPC (FI)')}",
        f"vless://{client_uuid}@{fi_edge}:{FI_XHTTP_REALITY_PORT}?type=xhttp&security=reality&pbk={fi_xhttp_pk}&fp=chrome&sni={FI_XHTTP_REALITY_SNI}&sid={fi_xhttp_sid}&path=%2Fxh-7m2q9r4k1v8p3s6&mode=packet-up#{urllib.parse.quote('🇫🇮 10. Незаметный XHTTP Reality (FI)')}",
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
                "publicKey": NL_REALITY_PUBLIC_KEY,
                "serverName": TCP_REALITY_SNI_CLASSIC,
                "shortId": NL_REALITY_SHORT_ID,
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
                "publicKey": NL_GRPC_REALITY_PUBLIC_KEY,
                "serverName": GRPC_REALITY_SNI,
                "shortId": NL_GRPC_REALITY_SHORT_ID,
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
    fi_classic["streamSettings"]["realitySettings"]["publicKey"] = FI_REALITY_PUBLIC_KEY
    fi_classic["streamSettings"]["realitySettings"]["shortId"] = FI_REALITY_SHORT_ID
    fi_classic["streamSettings"]["realitySettings"]["serverName"] = FI_REALITY_SNI_CLASSIC

    fi_fast = copy.deepcopy(nl_fast)
    fi_fast["tag"] = "node-fi-fast"
    fi_fast["settings"]["address"] = fi_edge
    fi_fast["streamSettings"]["realitySettings"]["publicKey"] = FI_REALITY_PUBLIC_KEY
    fi_fast["streamSettings"]["realitySettings"]["shortId"] = FI_REALITY_SHORT_ID
    fi_fast["streamSettings"]["realitySettings"]["serverName"] = FI_REALITY_SNI_FAST

    fi_grpc = copy.deepcopy(nl_grpc)
    fi_grpc["tag"] = "node-fi-grpc"
    fi_grpc["settings"]["address"] = fi_edge
    fi_grpc["streamSettings"]["realitySettings"]["publicKey"] = FI_GRPC_REALITY_PUBLIC_KEY
    fi_grpc["streamSettings"]["realitySettings"]["shortId"] = FI_GRPC_REALITY_SHORT_ID
    fi_grpc["streamSettings"]["realitySettings"]["serverName"] = FI_GRPC_REALITY_SNI

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
                        "publicKey": NL_REALITY_PUBLIC_KEY,
                        "serverName": TCP_REALITY_SNI_CLASSIC,
                        "shortId": NL_REALITY_SHORT_ID,
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
        "publicKey": NL_GRPC_REALITY_PUBLIC_KEY,
        "shortId": NL_GRPC_REALITY_SHORT_ID,
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
        "publicKey": NL_REALITY_PUBLIC_KEY,
        "shortId": NL_REALITY_SHORT_ID,
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
    fi_sber["outbounds"][0]["streamSettings"]["realitySettings"]["publicKey"] = FI_REALITY_PUBLIC_KEY
    fi_sber["outbounds"][0]["streamSettings"]["realitySettings"]["shortId"] = FI_REALITY_SHORT_ID
    fi_sber["meta"] = build_happ_config_meta(subscription_id)
    if fi_sber["meta"]:
        fi_sber["meta"]["serverDescription"] = "Классический · TCP Reality (FI)"

    # --- Profile 7: FI Fast ---
    fi_kino = copy.deepcopy(kino_cfg)
    fi_kino["remarks"] = f"🇫🇮 ⚡ Быстрый ({email})"
    fi_kino["outbounds"][0]["settings"]["address"] = fi_edge
    fi_kino["outbounds"][0]["streamSettings"]["realitySettings"]["serverName"] = FI_REALITY_SNI_FAST
    fi_kino["outbounds"][0]["streamSettings"]["realitySettings"]["publicKey"] = FI_REALITY_PUBLIC_KEY
    fi_kino["outbounds"][0]["streamSettings"]["realitySettings"]["shortId"] = FI_REALITY_SHORT_ID
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
    fi_grpc["outbounds"][0]["settings"]["port"] = 29443
    fi_grpc["outbounds"][0]["streamSettings"]["realitySettings"]["serverName"] = FI_GRPC_REALITY_SNI
    fi_grpc["outbounds"][0]["streamSettings"]["realitySettings"]["publicKey"] = FI_GRPC_REALITY_PUBLIC_KEY
    fi_grpc["outbounds"][0]["streamSettings"]["realitySettings"]["shortId"] = FI_GRPC_REALITY_SHORT_ID
    fi_grpc["meta"] = build_happ_config_meta(subscription_id)
    if fi_grpc["meta"]:
        fi_grpc["meta"]["serverDescription"] = "Запасной · VLESS-gRPC-Reality (FI)"

    # --- Profile 10: FI VLESS XHTTP Reality ---
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
        "path": "/xh-7m2q9r4k1v8p3s6",
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

    # Cross-check authoritative store DB for latest profile expiry
    try:
        store_path = find_store_db_path()
        conn_shop = sqlite3.connect(store_path, timeout=5.0)
        conn_shop.execute("PRAGMA busy_timeout = 5000;")
        conn_shop.row_factory = sqlite3.Row
        try:
            for cl in clients:
                cl_email = str(cl.get("email") or "")
                if cl_email:
                    prof_row = conn_shop.execute(
                        "SELECT expires_at, status FROM profiles WHERE xui_email = ? AND status != 'deleted'",
                        (cl_email,),
                    ).fetchone()
                    if prof_row and prof_row["expires_at"]:
                        shop_exp_ms = int(prof_row["expires_at"]) * 1000
                        if shop_exp_ms > expiry_ms:
                            expiry_ms = shop_exp_ms
        finally:
            conn_shop.close()
    except Exception:
        pass

    now_ms = int(time.time() * 1000)

    inbound_enabled = all(bool(client.get("enable", True)) for client in clients)
    traffic_disabled = any(traffic and int(traffic.get("enable") or 0) == 0 for traffic in traffics)
    expired = bool(expiry_ms and expiry_ms < now_ms)

    # Self-healing: If all inbound clients are enabled and not expired, the subscription is active.
    # Stale traffic.enable == 0 (leftover from previous expiration) must not mark it as inactive.
    if inbound_enabled and not expired:
        enabled = True
        if traffic_disabled:
            try:
                heal_conn = sqlite3.connect(XUI_DB_PATH, timeout=5.0)
                try:
                    for cl in clients:
                        cl_email = str(cl.get("email") or "")
                        if cl_email:
                            heal_conn.execute(
                                "UPDATE client_traffics SET enable = 1, expiry_time = ? WHERE email = ? AND enable = 0",
                                (expiry_ms, cl_email),
                            )
                    heal_conn.commit()
                finally:
                    heal_conn.close()
            except Exception:
                pass
    else:
        enabled = inbound_enabled and not traffic_disabled

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
    query_suffix = f"?{import_query}" if import_query else ""
    fallback_links = {
        "happ": f"/{SECRET_SEGMENT}/import/happ/{quoted_sub_id}{query_suffix}",
        "streisand": f"/{SECRET_SEGMENT}/import/streisand/{quoted_sub_id}{query_suffix}",
        "clash": f"/{SECRET_SEGMENT}/import/clash/{quoted_sub_id}{query_suffix}",
        "v2rayn": f"/{SECRET_SEGMENT}/import/v2rayn/{quoted_sub_id}{query_suffix}",
        "nekobox": f"/{SECRET_SEGMENT}/import/nekobox/{quoted_sub_id}{query_suffix}",
        "v2rayng": f"/{SECRET_SEGMENT}/import/v2rayng/{quoted_sub_id}{query_suffix}",
        "singbox": f"/{SECRET_SEGMENT}/import/singbox/{quoted_sub_id}{query_suffix}",
    }
    happ_link = encrypt_happ_link(subscription_url) or fallback_links["happ"]
    apps = [
        {
            "id": "happ",
            "name": "Happ",
            "badge": "рекомендуем",
            "iconUrl": OFFICIAL_HAPP_ICON,
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
            "name": "Clash / Mihomo",
            "badge": "авто-выбор",
            "iconUrl": OFFICIAL_CLASH_ICON,
            "iosIconUrl": OFFICIAL_CLASH_MI_ICON,
            "platforms": ["windows", "macos", "android", "linux", "ios"],
            "importUrl": fallback_links["clash"],
            "description": "Мощный клиент с поддержкой умного авто-тестирования узлов и мгновенным переключением при сбоях.",
            "downloads": {
                "windows": [{"label": "Clash Verge Rev (Windows)", "url": CLASH_DOWNLOAD_URL}],
                "macos": [{"label": "Clash Verge Rev (macOS)", "url": CLASH_DOWNLOAD_URL}],
                "android": [{"label": "Clash Meta Android", "url": "https://github.com/MetaCubeX/ClashMetaForAndroid/releases"}],
                "linux": [{"label": "Clash Verge Rev (Linux)", "url": CLASH_DOWNLOAD_URL}],
                "ios": [{"label": "Clash Mi (App Store)", "url": CLASH_MI_IOS_URL}],
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
            "iconUrl": OFFICIAL_STREISAND_ICON,
            "platforms": ["ios", "macos"],
            "importUrl": fallback_links["streisand"],
            "description": "Легкий и быстрый open-source клиент, идеально оптимизированный под экосистемы iOS и macOS без расхода аккумулятора.",
            "downloads": {
                "ios": [{"label": "App Store", "url": STREISAND_IOS_URL}],
                "macos": [{"label": "App Store (macOS)", "url": STREISAND_MACOS_URL}],
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
                "ios": [{"label": "sing-box MT (App Store)", "url": SINGBOX_IOS_URL}],
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
        ("appletv", "Apple TV"),
    ]
    summary = subscription_summary(subscription_id)
    status_class = "status-good" if summary["status_kind"] == "active" else "status-warn"
    parsed_sub = urllib.parse.urlsplit(subscription_url)
    clean_sub_url = urllib.parse.urlunsplit((parsed_sub.scheme, parsed_sub.netloc, parsed_sub.path, "", "")) if parsed_sub.scheme else subscription_url
    escaped_subscription = html.escape(clean_sub_url)
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

    volga_gw_domain = os.environ.get("VOLGA_GATEWAY_DOMAIN", "d5dlk4c65l2s5p0q3g0h.7qsg961h.apigw.yandexcloud.net").strip()
    volga_nl_url = f"https://{volga_gw_domain}/volga/nl/{urllib.parse.quote(subscription_id, safe='')}"
    volga_pl_url = f"https://{volga_gw_domain}/volga/pl/{urllib.parse.quote(subscription_id, safe='')}"
    volga_fi_url = f"https://{volga_gw_domain}/volga/fi/{urllib.parse.quote(subscription_id, safe='')}"
    is_sub_active = (summary.get("found") is True) and (summary.get("status_kind") == "active")

    oflux_nl_link, oflux_nl_prim, oflux_nl_back = build_openflux_v1_link("nl", subscription_id)
    oflux_pl_link, oflux_pl_prim, oflux_pl_back = build_openflux_v1_link("pl", subscription_id)
    oflux_fi_link, oflux_fi_prim, oflux_fi_back = build_openflux_v1_link("fi", subscription_id)

    openflux_data = {
        "nl": {
            "country": "nl",
            "name": "Нидерланды",
            "flag": "🇳🇱",
            "link": oflux_nl_link,
            "qr_url": f"/sub/openflux/{subscription_id}/nl/qr",
            "primary_url": oflux_nl_prim,
            "volga_url": volga_nl_url,
        },
        "pl": {
            "country": "pl",
            "name": "Польша",
            "flag": "🇵🇱",
            "link": oflux_pl_link,
            "qr_url": f"/sub/openflux/{subscription_id}/pl/qr",
            "primary_url": oflux_pl_prim,
            "volga_url": volga_pl_url,
        },
        "fi": {
            "country": "fi",
            "name": "Финляндия",
            "flag": "🇫🇮",
            "link": oflux_fi_link,
            "qr_url": f"/sub/openflux/{subscription_id}/fi/qr",
            "primary_url": oflux_fi_prim,
            "volga_url": volga_fi_url,
        }
    }
    openflux_data_json = json.dumps(openflux_data, ensure_ascii=False)

    template = """<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex,nofollow,noarchive">
  <title>Подключение SilentConnect</title>
  <link rel="icon" type="image/webp" href="/assets/branding/avatar.webp">
  <link rel="shortcut icon" type="image/webp" href="/assets/branding/avatar.webp">
  <link rel="apple-touch-icon" href="/assets/branding/avatar.webp">
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
    /* Connection Mode Switcher Pills */
    .connection-mode-pills {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
      margin-bottom: 20px;
      width: 100%;
      box-sizing: border-box;
    }
    @media (max-width: 768px) {
      .connection-mode-pills {
        grid-template-columns: 1fr;
        gap: 8px;
      }
    }
    .mode-pill {
      display: flex;
      flex-direction: column;
      align-items: flex-start !important;
      text-align: left !important;
      justify-content: flex-start;
      min-height: 76px;
      height: 100%;
      gap: 6px;
      padding: 14px 16px;
      border-radius: 14px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--line);
      cursor: pointer;
      transition: all 0.22s cubic-bezier(0.16, 1, 0.3, 1);
      position: relative;
      user-select: none;
      width: 100%;
      min-width: 0;
      box-sizing: border-box;
      color: inherit;
      font-family: inherit;
    }
    .mode-pill:hover {
      background: rgba(255, 255, 255, 0.06);
      border-color: rgba(255, 255, 255, 0.2);
      transform: translateY(-1px);
    }
    .mode-pill.active {
      background: linear-gradient(135deg, rgba(47, 191, 113, 0.16) 0%, rgba(47, 191, 113, 0.04) 100%) !important;
      border-color: rgba(47, 191, 113, 0.6) !important;
      box-shadow: 0 4px 20px rgba(47, 191, 113, 0.2) !important;
    }
    .mode-pill.active#pill-mode-whitelist {
      background: linear-gradient(135deg, rgba(234, 179, 8, 0.16) 0%, rgba(234, 179, 8, 0.04) 100%) !important;
      border-color: rgba(234, 179, 8, 0.6) !important;
      box-shadow: 0 4px 20px rgba(234, 179, 8, 0.18) !important;
    }
    .mode-pill.active#pill-mode-awg {
      background: linear-gradient(135deg, rgba(16, 185, 129, 0.18) 0%, rgba(59, 130, 246, 0.12) 100%) !important;
      border-color: rgba(16, 185, 129, 0.7) !important;
      box-shadow: 0 4px 20px rgba(16, 185, 129, 0.22) !important;
    }
    /* White-List Country Segmented Tabs */
    .wl-country-tabs {
      display: inline-flex;
      background: rgba(0, 0, 0, 0.4);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 10px;
      padding: 3px;
      gap: 4px;
      flex-wrap: wrap;
    }
    .wl-country-tab {
      background: transparent;
      border: 1px solid transparent;
      color: #94a3b8;
      padding: 6px 12px;
      font-size: 13px;
      font-weight: 600;
      border-radius: 7px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 7px;
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    }
    .wl-country-tab:hover {
      color: #f8fafc;
      background: rgba(255, 255, 255, 0.06);
    }
    .wl-country-tab.active {
      background: rgba(234, 179, 8, 0.2);
      color: #fde047;
      border-color: rgba(234, 179, 8, 0.4);
    }
    .mode-pill-top {
      display: flex;
      align-items: center;
      justify-content: flex-start;
      gap: 8px;
      width: 100%;
    }
    .mode-pill-header {
      display: flex;
      align-items: center;
      gap: 8px;
      width: 100%;
      text-align: left !important;
    }
    .mode-pill-icon {
      font-size: 20px;
      line-height: 1;
      flex-shrink: 0;
    }
    .mode-pill-title {
      font-size: 14.5px;
      font-weight: 700;
      color: #fff;
      white-space: nowrap;
      letter-spacing: -0.2px;
      text-align: left !important;
    }
    .mode-pill-subtitle {
      font-size: 11.5px;
      color: var(--muted);
      line-height: 1.35;
      text-align: left !important;
      width: 100%;
      white-space: normal;
      word-break: normal;
    }
    /* AWG Slots Hub & Quota Widget Styles */
    .awg-slots-hub {
      display: flex;
      flex-direction: column;
      gap: 16px;
    }
    .awg-quota-widget {
      background: rgba(16, 185, 129, 0.04);
      border: 1px solid rgba(16, 185, 129, 0.2);
      border-radius: 14px;
      padding: 16px 18px;
    }
    .awg-quota-headline {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 12px;
      flex-wrap: wrap;
      gap: 8px;
    }
    .awg-quota-text {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 14px;
      color: #fff;
    }
    .awg-free-metric {
      color: #34d399;
      font-weight: 700;
    }
    .awg-pct-pill {
      display: inline-block;
      font-size: 11px;
      font-weight: 700;
      padding: 3px 10px;
      border-radius: 9999px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .awg-pct-pill.emerald {
      background: rgba(16, 185, 129, 0.15);
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.3);
    }
    .awg-pct-pill.amber {
      background: rgba(245, 158, 11, 0.15);
      color: #fbbf24;
      border: 1px solid rgba(245, 158, 11, 0.3);
    }
    .awg-pct-pill.danger {
      background: rgba(239, 68, 68, 0.15);
      color: #f87171;
      border: 1px solid rgba(239, 68, 68, 0.3);
    }
    .awg-progress-track {
      width: 100%;
      height: 8px;
      background: rgba(255, 255, 255, 0.06);
      border-radius: 9999px;
      overflow: hidden;
      margin-bottom: 12px;
    }
    .awg-progress-fill {
      height: 100%;
      border-radius: 9999px;
      transition: width 0.4s cubic-bezier(0.16, 1, 0.3, 1);
    }
    .awg-progress-fill.emerald {
      background: linear-gradient(90deg, #059669, #10b981);
    }
    .awg-progress-fill.amber {
      background: linear-gradient(90deg, #d97706, #f59e0b);
    }
    .awg-progress-fill.danger {
      background: linear-gradient(90deg, #dc2626, #ef4444);
    }
    .awg-quota-subline {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 8px;
      font-size: 12px;
      color: var(--muted);
    }
    .awg-reset-date strong {
      color: #e2e8f0;
    }
    .unmetered-green {
      color: #34d399;
      font-weight: 700;
    }
    .awg-devices-section {
      background: rgba(10, 20, 15, 0.55);
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 16px 18px;
    }
    .awg-devices-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 14px;
      flex-wrap: wrap;
      gap: 8px;
    }
    .awg-devices-title {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 14px;
      color: #fff;
    }
    .awg-protocol-tag {
      font-size: 11px;
      color: var(--muted);
      background: rgba(255, 255, 255, 0.04);
      padding: 2px 8px;
      border-radius: 6px;
      border: 1px solid rgba(255, 255, 255, 0.06);
    }
    .awg-devices-section {
      width: 100%;
      box-sizing: border-box;
      overflow: hidden;
    }
    .awg-slots-grid {
      display: grid;
      gap: 12px;
      width: 100%;
      box-sizing: border-box;
    }
    .awg-slots-grid.slots-3 {
      grid-template-columns: repeat(3, minmax(0, 1fr));
    }
    .awg-slots-grid.slots-few {
      grid-template-columns: repeat(auto-fit, minmax(240px, 320px));
      justify-content: center;
    }
    .awg-slots-grid.slots-many {
      grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
    }
    @media (max-width: 768px) {
      .awg-slots-grid,
      .awg-slots-grid.slots-3,
      .awg-slots-grid.slots-few,
      .awg-slots-grid.slots-many {
        grid-template-columns: 1fr !important;
      }
    }
    .awg-slot-card {
      background: rgba(0, 0, 0, 0.35);
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 14px 16px;
      display: flex;
      flex-direction: column;
      gap: 10px;
      min-width: 0;
      width: 100%;
      box-sizing: border-box;
      overflow: hidden;
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    }
    .awg-slot-card:hover {
      border-color: rgba(255, 255, 255, 0.2);
      transform: translateY(-1px);
    }
    .awg-slot-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 8px;
    }
    .awg-slot-name-box {
      display: flex;
      align-items: center;
      gap: 4px;
      min-width: 0;
      flex: 1;
    }
    .awg-slot-name {
      font-size: 13px;
      font-weight: 600;
      color: #f8fafc;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      min-width: 0;
    }
    .awg-btn-rename {
      background: transparent;
      border: none;
      color: var(--muted);
      cursor: pointer;
      width: 24px;
      height: 24px;
      min-width: 24px;
      min-height: 24px;
      padding: 0;
      font-size: 13px;
      border-radius: 6px;
      line-height: 1;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      transition: color 0.15s ease, background 0.15s ease;
    }
    .awg-btn-rename:hover {
      color: #fff;
      background: rgba(255, 255, 255, 0.1);
    }
    .slot-badge {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 2px 6px;
      border-radius: 9999px;
      font-size: 10.5px;
      font-weight: 600;
      white-space: nowrap;
      flex-shrink: 0;
    }
    .slot-badge.active {
      background: rgba(16, 185, 129, 0.12);
      color: #10b981;
      border: 1px solid rgba(16, 185, 129, 0.3);
    }
    .slot-badge.danger {
      background: rgba(239, 68, 68, 0.12);
      color: #ef4444;
      border: 1px solid rgba(239, 68, 68, 0.3);
    }
    .slot-badge.muted {
      background: rgba(255, 255, 255, 0.05);
      color: #94a3b8;
      border: 1px solid rgba(255, 255, 255, 0.1);
    }
    .badge-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      display: inline-block;
    }
    .badge-dot.pulse-emerald {
      background: #10b981;
      box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7);
      animation: pulse-green 2s infinite;
    }
    .badge-dot.danger {
      background: #ef4444;
    }
    @keyframes pulse-green {
      0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
      70% { transform: scale(1); box-shadow: 0 0 0 6px rgba(16, 185, 129, 0); }
      100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
    }
    .awg-slot-info {
      display: flex;
      justify-content: space-between;
      font-size: 12px;
      color: var(--muted);
    }
    .awg-slot-info code {
      font-family: "JetBrains Mono", "SF Mono", Consolas, monospace;
      color: #cbd5e1;
      font-size: 11.5px;
    }
    .awg-slot-actions {
      display: flex;
      flex-direction: column;
      gap: 6px;
      width: 100%;
      box-sizing: border-box;
    }
    .awg-action-row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 6px;
      width: 100%;
      box-sizing: border-box;
    }
    .awg-action-row.single {
      grid-template-columns: 1fr;
    }
    .awg-action-btn {
      min-height: 36px;
      padding: 6px 8px;
      border-radius: 8px;
      font-size: 12px;
      font-weight: 600;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
      box-sizing: border-box;
      border: none;
      white-space: nowrap;
      min-width: 0;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .awg-action-btn.config {
      background: rgba(16, 185, 129, 0.15);
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.35);
    }
    .awg-action-btn.config:hover {
      background: rgba(16, 185, 129, 0.25);
      border-color: #34d399;
      transform: translateY(-1px);
    }
    .awg-action-btn.qr {
      background: rgba(255, 255, 255, 0.06);
      color: #f8fafc;
      border: 1px solid rgba(255, 255, 255, 0.12);
    }
    .awg-action-btn.qr:hover {
      background: rgba(255, 255, 255, 0.12);
      border-color: rgba(255, 255, 255, 0.22);
      transform: translateY(-1px);
    }
    .awg-action-btn.copy,
    .awg-action-btn.copy-key {
      background: rgba(56, 189, 248, 0.08);
      color: #38bdf8;
      border: 1px solid rgba(56, 189, 248, 0.25);
    }
    .awg-action-btn.copy:hover,
    .awg-action-btn.copy-key:hover {
      background: rgba(56, 189, 248, 0.18);
      border-color: #38bdf8;
      transform: translateY(-1px);
    }
    .awg-action-btn.switch,
    .awg-action-btn.switch-srv {
      background: rgba(168, 85, 247, 0.08);
      color: #c084fc;
      border: 1px solid rgba(168, 85, 247, 0.25);
    }
    .awg-action-btn.switch:hover,
    .awg-action-btn.switch-srv:hover {
      background: rgba(168, 85, 247, 0.18);
      border-color: #c084fc;
      transform: translateY(-1px);
    }
    .awg-ping-refresh-btn {
      background: rgba(255, 255, 255, 0.05);
      color: #94a3b8;
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 6px;
      font-size: 11px;
      font-weight: 600;
      padding: 3px 8px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 4px;
      transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    }
    .awg-ping-refresh-btn:hover:not(:disabled) {
      color: #f8fafc;
      border-color: rgba(255, 255, 255, 0.25);
      background: rgba(255, 255, 255, 0.1);
    }
    /* QR Code Modal (Glassmorphism) */
    .awg-modal-overlay {
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.75);
      backdrop-filter: blur(8px);
      z-index: 9999;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 16px;
      box-sizing: border-box;
    }
    .awg-modal-box {
      background: #0d0f14;
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-radius: 16px;
      max-width: 360px;
      width: 100%;
      overflow: hidden;
      box-shadow: 0 20px 48px rgba(0, 0, 0, 0.6);
      animation: modal-fade 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    }
    @keyframes modal-fade {
      from { opacity: 0; transform: scale(0.95); }
      to { opacity: 1; transform: scale(1); }
    }
    .awg-modal-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 16px 20px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.08);
    }
    .awg-modal-close {
      background: transparent;
      border: none;
      color: var(--muted);
      font-size: 24px;
      cursor: pointer;
      line-height: 1;
    }
    .awg-modal-close:hover {
      color: #fff;
    }
    .awg-modal-body {
      padding: 20px;
      text-align: center;
    }
    .awg-qr-wrapper {
      display: flex;
      justify-content: center;
      align-items: center;
      background: #fff;
      padding: 12px;
      border-radius: 12px;
      margin: 0 auto;
      max-width: 260px;
    }
    .awg-qr-img {
      max-width: 100%;
      height: auto;
      display: block;
    }
    .awg-modal-footer {
      display: flex;
      gap: 10px;
      margin-top: 18px;
    }
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
    .btn-wl-disabled, .button.btn-wl-disabled, button.btn-wl-disabled {
      cursor: not-allowed !important;
      color: #94a3b8 !important;
      opacity: 0.75 !important;
      transform: none !important;
      filter: none !important;
      user-select: none !important;
    }
    .btn-wl-disabled:hover, .button.btn-wl-disabled:hover, button.btn-wl-disabled:hover {
      transform: none !important;
      filter: none !important;
      background: rgba(255, 255, 255, 0.06) !important;
      border-color: var(--line) !important;
      color: #94a3b8 !important;
      cursor: not-allowed !important;
    }
    .btn-wl-disabled * {
      pointer-events: none !important;
    }
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
    .referral-card {
      background: linear-gradient(135deg, rgba(47, 191, 113, 0.07) 0%, rgba(21, 28, 34, 0.95) 100%);
      border: 1px solid rgba(47, 191, 113, 0.28);
      border-radius: 16px;
      padding: 20px 24px;
      margin-bottom: 20px;
      box-sizing: border-box;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.2);
    }
    .referral-box {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 16px;
    }
    .referral-info {
      flex: 1 1 auto;
      max-width: 560px;
      min-width: 0;
    }
    .referral-header {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
      margin-bottom: 6px;
    }
    .referral-title {
      font-size: 16px;
      font-weight: 700;
      color: #fff;
      letter-spacing: -0.01em;
    }
    .referral-tag {
      font-size: 11.5px;
      font-weight: 700;
      padding: 2px 8px;
      border-radius: 10px;
      background: rgba(47, 191, 113, 0.16);
      color: var(--green);
      border: 1px solid rgba(47, 191, 113, 0.35);
    }
    .referral-desc {
      font-size: 13.5px;
      color: var(--muted);
      line-height: 1.5;
      margin: 0;
    }
    .referral-desc strong {
      color: #eef2f3;
      font-weight: 600;
    }
    .referral-action {
      flex-shrink: 0;
    }
    .referral-btn {
      display: inline-flex !important;
      align-items: center !important;
      justify-content: center !important;
      background: var(--green) !important;
      color: #0b1510 !important;
      font-weight: 700 !important;
      font-size: 14px !important;
      padding: 10px 20px !important;
      border-radius: 10px !important;
      text-decoration: none !important;
      box-shadow: 0 4px 14px rgba(47, 191, 113, 0.3) !important;
      transition: all 0.2s ease !important;
      white-space: nowrap !important;
    }
    .referral-btn:hover {
      background: #38df84 !important;
      transform: translateY(-1px) !important;
      box-shadow: 0 6px 20px rgba(47, 191, 113, 0.45) !important;
    }
    footer { margin-top:36px; text-align:center; padding:24px 0 32px; color:var(--muted); font-size:13.5px; border-top:1px solid var(--line); width:100%; box-sizing:border-box; }
    .footer-wrap { display:flex; flex-direction:column; align-items:center; justify-content:center; gap:12px; text-align:center; width:100%; box-sizing:border-box; }
    .footer-links { display:flex; align-items:center; justify-content:center; flex-wrap:wrap; gap:10px 18px; width:100%; box-sizing:border-box; }
    .footer-links a { color:var(--muted); text-decoration:none; font-size:13.5px; margin:0; padding:4px 8px; border-radius:6px; transition:color 0.2s ease, background 0.2s ease; white-space:nowrap; }
    .footer-links a:hover { color:#fff; text-decoration:underline; }
    .footer-copy { color:var(--muted); font-size:12.5px; opacity:0.75; margin-top:4px; }
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
      .referral-card { padding: 14px 16px; margin-bottom: 14px; }
      .referral-box { flex-direction: column; align-items: stretch; gap: 12px; }
      .referral-info { flex: none; width: 100%; max-width: 100%; }
      .referral-header { gap: 8px; margin-bottom: 4px; }
      .referral-title { font-size: 15px; }
      .referral-tag { font-size: 11px; padding: 2px 7px; }
      .referral-desc { font-size: 12.5px; line-height: 1.45; }
      .referral-action { width: 100%; }
      .referral-action .referral-btn { width: 100% !important; min-height: 42px !important; font-size: 13.5px !important; padding: 9px 16px !important; justify-content: center !important; }
      footer { margin-top:24px; padding:20px 0 28px; }
      .footer-wrap { gap:12px; padding:0 4px; }
      .footer-links { display:flex; flex-direction:row; flex-wrap:wrap; justify-content:center; align-items:center; gap:8px 10px; width:100%; }
      .footer-links a { font-size:12.5px; padding:6px 10px; background:rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.08); border-radius:8px; white-space:normal; text-align:center; display:inline-flex; align-items:center; justify-content:center; }
      .footer-copy { font-size:11.5px; margin-top:6px; line-height:1.4; }
    }
  </style>
</head>
<body>
  <main class="shell">
    <section class="top">
      <a class="brand" href="__WEB_PAGE_URL__"><img src="/assets/branding/avatar.webp" alt="SilentConnect" class="brand-logo"><span>SilentConnect</span></a>
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
          <p style="margin: 4px 0 0; color: var(--muted); font-size: 14px;">Выберите режим работы и ваше устройство для быстрой настройки защищенного доступа:</p>
        </div>
      </div>

      <!-- Режим подключения: Три большие интерактивные пилюли -->
      <div class="connection-mode-pills" role="tablist" aria-label="Режим подключения">
        <button type="button" class="mode-pill active" id="pill-mode-standard" role="tab" aria-selected="true" onclick="setConnectionMode('standard')">
          <div class="mode-pill-top">
            <div class="mode-pill-header">
              <span class="mode-pill-icon">🛡️</span>
              <span class="mode-pill-title">Основной</span>
            </div>
          </div>
          <div class="mode-pill-subtitle">Happ, Sing-box, Clash</div>
        </button>
        <button type="button" class="mode-pill" id="pill-mode-awg" role="tab" aria-selected="false" onclick="setConnectionMode('awg')">
          <div class="mode-pill-top">
            <div class="mode-pill-header">
              <span class="mode-pill-icon">🎮</span>
              <span class="mode-pill-title">Игровой</span>
            </div>
          </div>
          <div class="mode-pill-subtitle">AmneziaVPN, AmneziaWG</div>
        </button>
        <button type="button" class="mode-pill" id="pill-mode-whitelist" role="tab" aria-selected="false" onclick="setConnectionMode('whitelist')">
          <div class="mode-pill-top">
            <div class="mode-pill-header">
              <span class="mode-pill-icon">📃</span>
              <span class="mode-pill-title">Белые списки</span>
            </div>
          </div>
          <div class="mode-pill-subtitle">OpenFlux клиент</div>
        </button>
      </div>

      <!-- Контейнер 1: Стандартный режим -->
      <div id="standard-mode-container">
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
      </div><!-- /standard-mode-container -->

      <!-- Контейнер 2: Режим Белых Списков (OpenFlux) -->
      <div id="whitelist-mode-container" style="display: none;">
        <div class="whitelist-info-card" style="background: rgba(234, 179, 8, 0.08); border: 1px solid rgba(234, 179, 8, 0.25); border-radius: 14px; padding: 14px 18px; margin-bottom: 20px;">
          <div style="display: flex; align-items: flex-start; gap: 12px;">
            <span style="font-size: 24px; line-height: 1;">🛡️</span>
            <div>
              <div style="font-size: 14.5px; font-weight: 700; color: #facc15; margin-bottom: 4px;">
                Специальный режим «Белых Списков» (OpenFlux)
              </div>
              <p style="margin: 0 0 8px 0; font-size: 13px; color: #d1d5db; line-height: 1.45;">
                Канал предназначен для непрерывной связи и стабильного доступа в интернет в режиме Белых Списков. Сетевой трафик передается в защищенной сессии совместного редактирования <strong>Яндекс Документов</strong> и направляется через наши серверы в Нидерландах, Польше и Финляндии.
              </p>
              <div style="display: flex; align-items: center; gap: 6px; font-size: 12.5px; color: var(--green); font-weight: 600;">
                <span>💡</span> <span>Без ограничений по устройствам: запускайте на любых ваших ПК и смартфонах (скорость канала до 2 Мбит/с).</span>
              </div>
            </div>
          </div>
        </div>

        <!-- Карточка быстрого подключения к OpenFlux -->
        <div class="wl-hero-card" style="background: linear-gradient(135deg, rgba(234, 179, 8, 0.08) 0%, rgba(20, 35, 28, 0.6) 100%); border: 1px solid rgba(234, 179, 8, 0.28); border-radius: 16px; padding: 18px 20px; margin-bottom: 24px; box-shadow: 0 12px 32px rgba(0,0,0,0.3);">
          <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; margin-bottom: 14px;">
            <div style="display: flex; align-items: center; gap: 10px;">
              <span style="font-size: 20px;">⚡</span>
              <div>
                <h3 style="margin: 0; font-size: 16px; font-weight: 700; color: #fff;">Быстрое добавление узла в OpenFlux</h3>
                <span style="font-size: 12.5px; color: var(--muted);">Выберите сервер и нажмите для мгновенного импорта или покажите QR-код</span>
              </div>
            </div>
            <div style="display: flex; align-items: center; gap: 8px;">
              <span style="font-size: 13px; color: var(--muted); font-weight: 500;">Сервер:</span>
              <div class="wl-country-tabs" role="tablist" aria-label="Выбор страны OpenFlux">
                <button type="button" class="wl-country-tab active" id="wl-tab-nl" onclick="onWlCountryChange('nl')">
                  <svg viewBox="0 0 24 16" width="18" height="12" style="border-radius:2px;display:inline-block;vertical-align:middle;box-shadow:0 0 1px rgba(0,0,0,0.5);"><rect width="24" height="5.33" fill="#AE1C28"/><rect y="5.33" width="24" height="5.33" fill="#FFFFFF"/><rect y="10.66" width="24" height="5.34" fill="#21468B"/></svg>
                  <span>Нидерланды</span>
                </button>
                <button type="button" class="wl-country-tab" id="wl-tab-pl" onclick="onWlCountryChange('pl')">
                  <svg viewBox="0 0 24 16" width="18" height="12" style="border-radius:2px;display:inline-block;vertical-align:middle;box-shadow:0 0 1px rgba(0,0,0,0.5);"><rect width="24" height="8" fill="#FFFFFF"/><rect y="8" width="24" height="8" fill="#DC143C"/></svg>
                  <span>Польша</span>
                </button>
                <button type="button" class="wl-country-tab" id="wl-tab-fi" onclick="onWlCountryChange('fi')">
                  <svg viewBox="0 0 24 16" width="18" height="12" style="border-radius:2px;display:inline-block;vertical-align:middle;box-shadow:0 0 1px rgba(0,0,0,0.5);"><rect width="24" height="16" fill="#FFFFFF"/><rect x="6.5" width="3.5" height="16" fill="#002F6C"/><rect y="6.25" width="24" height="3.5" fill="#002F6C"/></svg>
                  <span>Финляндия</span>
                </button>
              </div>
            </div>
          </div>

          <div id="wl-hero-actions" style="display: flex; flex-wrap: wrap; gap: 10px; align-items: center;">
            <button type="button" class="button success" id="wl-copy-trigger" onclick="copyWlLink(this)" style="min-height: 44px; padding: 10px 16px; font-size: 13.5px; display: inline-flex; align-items: center; gap: 6px;">
              <span>📋</span> <span>Скопировать ссылку</span>
            </button>
            <button type="button" class="button secondary" id="wl-qr-trigger" onclick="openWlQrModal()" style="min-height: 44px; padding: 10px 16px; font-size: 13.5px; display: inline-flex; align-items: center; gap: 6px;">
              <span>📱</span> <span>Показать QR-код</span>
            </button>
            <a id="wl-hero-cta" class="button secondary btn-wl-disabled" href="javascript:void(0)" onclick="event.preventDefault(); return false;" style="min-height: 44px; padding: 10px 16px; font-size: 13.5px; display: inline-flex; align-items: center; gap: 8px; text-decoration: none;" title="Прямой 1-Click запуск в разработке для этой платформы">
              <span>⚡</span> <span id="wl-cta-flag" style="display: none;"><svg viewBox="0 0 24 16" width="18" height="12" style="border-radius:2px;display:inline-block;vertical-align:middle;box-shadow:0 0 1px rgba(0,0,0,0.5);"><rect width="24" height="5.33" fill="#AE1C28"/><rect y="5.33" width="24" height="5.33" fill="#FFFFFF"/><rect y="10.66" width="24" height="5.34" fill="#21468B"/></svg></span> <span id="wl-cta-text">1-Click импорт</span> <span id="wl-cta-badge"><span style="font-size: 11px; padding: 2px 6px; border-radius: 4px; background: rgba(234, 179, 8, 0.18); color: #fde047; font-weight: 600; border: 1px solid rgba(234, 179, 8, 0.3);">Скоро</span></span>
            </a>
          </div>
          <div id="wl-action-hint" style="margin-top: 10px; font-size: 12px; color: var(--muted); line-height: 1.4;">
            💡 Ссылка формата <code>openflux://v1/...</code> поддерживается на всех платформах: Android, iOS, Windows, macOS, Linux.
          </div>
        </div>

        <div class="platform-selector-card">
          <div class="platform-bar-header">
            <div class="platform-bar-title">
              <span style="font-size:16px;">💻</span>
              <span>Операционная система для Белых Списков</span>
            </div>
            <span class="platform-bar-hint">Автоопределение: <strong id="detected-wl-platform-label">iOS (iPhone)</strong></span>
          </div>
          <div class="platform-nav-track" id="wl-platform-tabs" role="tablist" aria-label="Выбор ОС для Белых Списков"></div>
        </div>

        <div class="steps" id="wl-steps-container"></div>
      </div><!-- /whitelist-mode-container -->

      <!-- Контейнер 3: Скоростной режим AmneziaWG (Слоты устройств) -->
      <div id="awg-mode-container" style="display: none;">
        __AWG_CONTAINER_HTML__
      </div><!-- /awg-mode-container -->
    </section>

    <section class="referral-card">
      <div class="referral-box">
        <div class="referral-info">
          <div class="referral-header">
            <span style="font-size: 20px; line-height: 1;">🤝</span>
            <span class="referral-title">Партнёрская программа</span>
            <span class="referral-tag">10% вам + 10% другу</span>
          </div>
          <p class="referral-desc">
            Приглашайте друзей по вашей персональной ссылке: друг получит <strong>скидку 10%</strong> на первую подписку, а вы — <strong>10% с каждой его оплаты</strong>. Присоединиться к программе, получить реферальные ссылки (для сайта и для Telegram) и выводить начисления можно через нашего бота.
          </p>
        </div>
        <div class="referral-action">
          <a class="button success referral-btn" href="__BOT_REFERRAL_URL__" target="_blank" rel="noopener">
            🤝 Присоединиться в Telegram-боте →
          </a>
        </div>
      </div>
    </section>

    <footer>
      <div class="footer-wrap">
        <div class="footer-links">
          <a href="__WEB_PAGE_URL__/about" target="_blank">О сервисе</a>
          <a href="__WEB_PAGE_URL__/contact" target="_blank">Контакты &amp; Поддержка</a>
          <a href="__WEB_PAGE_URL__/legal/privacy" target="_blank">Политика конфиденциальности</a>
          <a href="__WEB_PAGE_URL__/legal/terms" target="_blank">Пользовательское соглашение</a>
          <a href="__WEB_PAGE_URL__/legal/refund" target="_blank">Политика возвратов</a>
        </div>
        <div class="footer-copy">© 2026 SilentConnect. Все права защищены. [code: mekbuda]</div>
      </div>
    </footer>
  </main>

  <!-- QR Code Modal (Glassmorphism) -->
  <div id="awg-qr-modal" class="awg-modal-overlay" style="display: none;" onclick="if (event.target === this) closeAwgQrModal();">
    <div class="awg-modal-box">
      <div class="awg-modal-header">
        <div id="awg-modal-title" style="font-weight: 700; font-size: 15px; color: #fff;">📱 AmneziaWG</div>
        <button type="button" class="awg-modal-close" onclick="closeAwgQrModal()" aria-label="Закрыть">&times;</button>
      </div>
      <div class="awg-modal-body">
        <div class="awg-qr-wrapper">
          <img id="awg-qr-image" src="" alt="AmneziaWG QR Code" class="awg-qr-img" />
        </div>
        <p style="font-size: 13px; color: var(--muted); text-align: center; margin: 12px 0 0 0; line-height: 1.4;">
          Откройте приложение <b>Amnezia VPN</b> на смартфоне, нажмите <b>«+»</b> → <b>«Сканировать QR-код»</b>.
        </p>
        <div class="awg-modal-footer">
          <a id="awg-modal-dl" class="awg-action-btn config" href="#" download style="flex: 1; text-align: center; justify-content: center;">📥 Скачать .conf</a>
          <button type="button" class="awg-action-btn qr" onclick="closeAwgQrModal()" style="flex: 0 0 auto;">Закрыть</button>
        </div>
      </div>
    </div>
  </div>

  <!-- OpenFlux QR Code Modal (Glassmorphism) -->
  <div id="wl-qr-modal" class="awg-modal-overlay" style="display: none;" onclick="if (event.target === this) closeWlQrModal();">
    <div class="awg-modal-box">
      <div class="awg-modal-header">
        <div id="wl-qr-modal-title" style="font-weight: 700; font-size: 15px; color: #fff; display: flex; align-items: center; gap: 8px;">
          <span>📱</span> <span>OpenFlux · QR-код</span>
        </div>
        <button type="button" class="awg-modal-close" onclick="closeWlQrModal()" aria-label="Закрыть">&times;</button>
      </div>
      <div class="awg-modal-body">
        <div class="awg-qr-wrapper">
          <img id="wl-qr-image" src="" alt="OpenFlux QR Code" class="awg-qr-img" />
        </div>
        <p style="font-size: 13px; color: var(--muted); text-align: center; margin: 12px 0 0 0; line-height: 1.4;">
          Наведите камеру в приложении <b>OpenFlux</b> для мгновенного добавления подключения.
        </p>
        <div class="awg-modal-footer">
          <button type="button" class="awg-action-btn copy" onclick="copyWlLink(this)" style="flex: 1; text-align: center; justify-content: center;">📋 Скопировать ссылку</button>
          <button type="button" class="awg-action-btn qr" onclick="closeWlQrModal()" style="flex: 0 0 auto;">Закрыть</button>
        </div>
      </div>
    </div>
  </div>

  <!-- Switch Country Modal (Glassmorphism) -->
  <div id="awg-switch-modal" class="awg-modal-overlay" style="display: none;" onclick="if (event.target === this) closeAwgSwitchModal();">
    <div class="awg-modal-box" style="max-width: 440px;">
      <div class="awg-modal-header">
        <div id="awg-switch-title" style="font-weight: 700; font-size: 15px; color: #fff;">🔄 Сменить страну подключения</div>
        <button type="button" class="awg-modal-close" onclick="closeAwgSwitchModal()" aria-label="Закрыть">&times;</button>
      </div>
      <div class="awg-modal-body" style="padding: 16px 20px;">
        <div style="font-size: 13.5px; color: var(--muted); margin-bottom: 12px;">
          Устройство: <strong id="awg-switch-slot-name" style="color: #fff;">Устройство</strong>
        </div>
        
        <div style="margin-bottom: 14px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <label style="display: block; font-size: 12px; font-weight: 700; color: var(--muted); text-transform: uppercase; margin: 0;">Выберите новую локацию:</label>
            <button type="button" id="awg-ping-refresh-btn" class="awg-ping-refresh-btn" onclick="measureAwgPings(true)" title="Повторный замер пинга">
              ⚡ <span id="awg-ping-btn-text">Замерить пинг</span>
            </button>
          </div>
          <div class="awg-switch-options" style="display: flex; flex-direction: column; gap: 8px;">
            <label class="awg-country-option" style="display: flex; align-items: center; justify-content: space-between; padding: 10px 14px; background: rgba(255,255,255,0.04); border: 1px solid var(--glass-border); border-radius: 8px; cursor: pointer;">
              <div style="display: flex; align-items: center; gap: 10px;">
                <input type="radio" name="awg_target_country" value="nl" style="accent-color: #38bdf8;">
                <span style="font-weight: 600; color: #fff;">🇳🇱 Нидерланды (Амстердам)</span>
              </div>
              <span class="awg-ping-badge" id="awg-ping-nl" style="font-size: 11px; color: #34d399; font-weight: 600; background: rgba(52,211,153,0.12); padding: 2px 6px; border-radius: 4px;">~35 мс</span>
            </label>
            <label class="awg-country-option" style="display: flex; align-items: center; justify-content: space-between; padding: 10px 14px; background: rgba(255,255,255,0.04); border: 1px solid var(--glass-border); border-radius: 8px; cursor: pointer;">
              <div style="display: flex; align-items: center; gap: 10px;">
                <input type="radio" name="awg_target_country" value="pl" style="accent-color: #38bdf8;">
                <span style="font-weight: 600; color: #fff;">🇵🇱 Польша (Варшава)</span>
              </div>
              <span class="awg-ping-badge" id="awg-ping-pl" style="font-size: 11px; color: #34d399; font-weight: 600; background: rgba(52,211,153,0.12); padding: 2px 6px; border-radius: 4px;">~45 мс</span>
            </label>
            <label class="awg-country-option" style="display: flex; align-items: center; justify-content: space-between; padding: 10px 14px; background: rgba(255,255,255,0.04); border: 1px solid var(--glass-border); border-radius: 8px; cursor: pointer;">
              <div style="display: flex; align-items: center; gap: 10px;">
                <input type="radio" name="awg_target_country" value="fi" style="accent-color: #38bdf8;">
                <span style="font-weight: 600; color: #fff;">🇫🇮 Финляндия (Хельсинки)</span>
              </div>
              <span class="awg-ping-badge" id="awg-ping-fi" style="font-size: 11px; color: #34d399; font-weight: 600; background: rgba(52,211,153,0.12); padding: 2px 6px; border-radius: 4px;">~50 мс</span>
            </label>
          </div>
        </div>

        <!-- Exact single-sentence warning -->
        <div id="awg-switch-warning" style="background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.3); border-radius: 8px; padding: 10px 12px; font-size: 12.5px; color: #fbbf24; line-height: 1.4; margin-bottom: 14px;">
          ⚠️ Конфиг другой страны (<span id="awg-switch-curr-name">Нидерланды</span>) будет приостановлен, пока вы в этом же слоте не вернёте эту страну.
        </div>

        <div id="awg-switch-status" style="display: none; padding: 10px 12px; border-radius: 8px; font-size: 12.5px; margin-bottom: 14px; line-height: 1.4;"></div>

        <div class="awg-modal-footer" style="display: flex; gap: 10px;">
          <button type="button" class="awg-action-btn" onclick="closeAwgSwitchModal()" style="flex: 1; justify-content: center; background: rgba(255,255,255,0.1);">Отмена</button>
          <button type="button" id="awg-switch-submit-btn" class="awg-action-btn" onclick="executeAwgSwitch()" style="flex: 1.5; justify-content: center; background: #0284c7; border-color: #0284c7; color: #fff; font-weight: 700;">Переключить локацию</button>
        </div>
      </div>
    </div>
  </div>
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
      { id: "macos", label: "macOS", icon: '<svg viewBox="0 0 512 512" width="18" height="18" style="border-radius: 4px; overflow: hidden;"><defs><linearGradient id="finder-blue" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#1e73f2"/><stop offset="100%" stop-color="#19d3fd"/></linearGradient><linearGradient id="finder-silver" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#dbe9f4"/><stop offset="100%" stop-color="#f7f6f6"/></linearGradient></defs><rect width="512" height="512" fill="url(#finder-silver)" rx="85"/><path fill="url(#finder-blue)" d="m0 0h262q-65 162-64 286c0 7 6 13 13 13h64q-6 113 28 213H0z"/><g fill="none" stroke="#1e293b" stroke-linecap="round"><path stroke-width="24" d="m133.5 157.5v34m226.5-34v34"/><path stroke-width="20" d="m394 345c-55 81-241 81-295.5 0"/></g></svg>' },
      { id: "linux", label: "Linux", icon: '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M12.504 0c-.155 0-.315.008-.48.021-4.226.333-3.105 4.807-3.17 6.298-.076 1.092-.3 1.953-1.05 3.02-.885 1.051-2.127 2.75-2.716 4.521-.278.832-.41 1.684-.287 2.489a.424.424 0 00-.11.135c-.26.268-.45.6-.663.839-.199.199-.485.267-.797.4-.313.136-.658.269-.864.68-.09.189-.136.394-.132.602 0 .199.027.4.055.536.058.399.116.728.04.97-.249.68-.28 1.145-.106 1.484.174.334.535.47.94.601.81.2 1.91.135 2.774.6.926.466 1.866.67 2.616.47.526-.116.97-.464 1.208-.946.587-.003 1.23-.269 2.26-.334.699-.058 1.574.267 2.577.2.025.134.063.198.114.333l.003.003c.391.778 1.113 1.132 1.884 1.071.771-.06 1.592-.536 2.257-1.306.631-.765 1.683-1.084 2.378-1.503.348-.199.629-.469.649-.853.023-.4-.2-.811-.714-1.376v-.097l-.003-.003c-.17-.2-.25-.535-.338-.926-.085-.401-.182-.786-.492-1.046h-.003c-.059-.054-.123-.067-.188-.135a.357.357 0 00-.19-.064c.431-1.278.264-2.55-.173-3.694-.533-1.41-1.465-2.638-2.175-3.483-.796-1.005-1.576-1.957-1.56-3.368.026-2.152.236-6.133-3.544-6.139zm.529 3.405h.013c.213 0 .396.062.584.198.19.135.33.332.438.533.105.259.158.459.166.724 0-.02.006-.04.006-.06v.105a.086.086 0 01-.004-.021l-.004-.024a1.807 1.807 0 01-.15.706.953.953 0 01-.213.335.71.71 0 00-.088-.042c-.104-.045-.198-.064-.284-.133a1.312 1.312 0 00-.22-.066c.05-.06.146-.133.183-.198.053-.128.082-.264.088-.402v-.02a1.21 1.21 0 00-.061-.4c-.045-.134-.101-.2-.183-.333-.084-.066-.167-.132-.267-.132h-.016c-.093 0-.176.03-.262.132a.8.8 0 00-.205.334 1.18 1.18 0 00-.09.4v.019c.002.089.008.179.02.267-.193-.067-.438-.135-.607-.202a1.635 1.635 0 01-.018-.2v-.02a1.772 1.772 0 01.15-.768c.082-.22.232-.406.43-.533a.985.985 0 01.594-.2zm-2.962.059h.036c.142 0 .27.048.399.135.146.129.264.288.344.465.09.199.14.4.153.667v.004c.007.134.006.2-.002.266v.08c-.03.007-.056.018-.083.024-.152.055-.274.135-.393.2.012-.09.013-.18.003-.267v-.015c-.012-.133-.04-.2-.082-.333a.613.613 0 00-.166-.267.248.248 0 00-.183-.064h-.021c-.071.006-.13.04-.186.132a.552.552 0 00-.12.27.944.944 0 00-.023.33v.015c.012.135.037.2.08.334.046.134.098.2.166.268.01.009.02.018.034.024-.07.057-.117.07-.176.136a.304.304 0 01-.131.068 2.62 2.62 0 01-.275-.402 1.772 1.772 0 01-.155-.667 1.759 1.759 0 01.08-.668 1.43 1.43 0 01.283-.535c.128-.133.26-.2.418-.2zm1.37 1.706c.332 0 .733.065 1.216.399.293.2.523.269 1.052.468h.003c.255.136.405.266.478.399v-.131a.571.571 0 01.016.47c-.123.31-.516.643-1.063.842v.002c-.268.135-.501.333-.775.465-.276.135-.588.292-1.012.267a1.139 1.139 0 01-.448-.067 3.566 3.566 0 01-.322-.198c-.195-.135-.363-.332-.612-.465v-.005h-.005c-.4-.246-.616-.512-.686-.71-.07-.268-.005-.47.193-.6.224-.135.38-.271.483-.336.104-.074.143-.102.176-.131h.002v-.003c.169-.202.436-.47.839-.601.139-.036.294-.065.466-.065zm2.8 2.142c.358 1.417 1.196 3.475 1.735 4.473.286.534.855 1.659 1.102 3.024.156-.005.33.018.513.064.646-1.671-.546-3.467-1.089-3.966-.22-.2-.232-.335-.123-.335.59.534 1.365 1.572 1.646 2.757.13.535.16 1.104.021 1.67.067.028.135.06.205.067 1.032.534 1.413.938 1.23 1.537v-.043c-.06-.003-.12 0-.18 0h-.016c.151-.467-.182-.825-1.065-1.224-.915-.4-1.646-.336-1.77.465-.008.043-.013.066-.018.135-.068.023-.139.053-.209.064-.43.268-.662.669-.793 1.187-.13.533-.17 1.156-.205 1.869v.003c-.02.334-.17.838-.319 1.35-1.5 1.072-3.58 1.538-5.348.334a2.645 2.645 0 00-.402-.533 1.45 1.45 0 00-.275-.333c.182 0 .338-.03.465-.067a.615.615 0 00.314-.334c.108-.267 0-.697-.345-1.163-.345-.467-.931-.995-1.788-1.521-.63-.4-.986-.87-1.15-1.396-.165-.534-.143-1.085-.015-1.645.245-1.07.873-2.11 1.274-2.763.107-.065.037.135-.408.974-.396.751-1.14 2.497-.122 3.854a8.123 8.123 0 01.647-2.876c.564-1.278 1.743-3.504 1.836-5.268.048.036.217.135.289.202.218.133.38.333.59.465.21.201.477.335.876.335.039.003.075.006.11.006.412 0 .73-.134.997-.268.29-.134.52-.334.74-.4h.005c.467-.135.835-.402 1.044-.7zm2.185 8.958c.037.6.343 1.245.882 1.377.588.134 1.434-.333 1.791-.765l.211-.01c.315-.007.577.01.847.268l.003.003c.208.199.305.53.391.876.085.4.154.78.409 1.066.486.527.645.906.636 1.14l.003-.007v.018l-.003-.012c-.015.262-.185.396-.498.595-.63.401-1.746.712-2.457 1.57-.618.737-1.37 1.14-2.036 1.191-.664.053-1.237-.2-1.574-.898l-.005-.003c-.21-.4-.12-1.025.056-1.69.176-.668.428-1.344.463-1.897.037-.714.076-1.335.195-1.814.12-.465.308-.797.641-.984l.045-.022zm-10.814.049h.01c.053 0 .105.005.157.014.376.055.706.333 1.023.752l.91 1.664.003.003c.243.533.754 1.064 1.189 1.637.434.598.77 1.131.729 1.57v.006c-.057.744-.48 1.148-1.125 1.294-.645.135-1.52.002-2.395-.464-.968-.536-2.118-.469-2.857-.602-.369-.066-.61-.2-.723-.4-.11-.2-.113-.602.123-1.23v-.004l.002-.003c.117-.334.03-.752-.027-1.118-.055-.401-.083-.71.043-.94.16-.334.396-.4.69-.533.294-.135.64-.202.915-.47h.002v-.002c.256-.268.445-.601.668-.838.19-.201.38-.336.663-.336zm7.159-9.074c-.435.201-.945.535-1.488.535-.542 0-.97-.267-1.28-.466-.154-.134-.28-.268-.373-.335-.164-.134-.144-.333-.074-.333.109.016.129.134.199.2.096.066.215.2.36.333.292.2.68.467 1.167.467.485 0 1.053-.267 1.398-.466.195-.135.445-.334.648-.467.156-.136.149-.267.279-.267.128.016.034.134-.147.332a8.097 8.097 0 01-.69.468zm-1.082-1.583V5.64c-.006-.02.013-.042.029-.05.074-.043.18-.027.26.004.063 0 .16.067.15.135-.006.049-.085.066-.135.066-.055 0-.092-.043-.141-.068-.052-.018-.146-.008-.163-.065zm-.551 0c-.02.058-.113.049-.166.066-.047.025-.086.068-.14.068-.05 0-.13-.02-.136-.068-.01-.066.088-.133.15-.133.08-.031.184-.047.259-.005.019.009.036.03.03.05v.02h.003z"/></svg>' },
      { id: "androidtv", label: "Android TV", icon: '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M22 3H2c-.6 0-1 .4-1 1v13c0 .6.4 1 1 1h8v1.5H7c-.3 0-.5.2-.5.5s.2.5.5.5h10c.3 0 .5-.2.5-.5s-.2-.5-.5-.5h-3V18h8c.6 0 1-.4 1-1V4c0-.6-.4-1-1-1zm-.2 13.8H2.2V4.2h19.6v12.6z"/><g transform="translate(5.4, 4.0) scale(0.55)"><path d="M17.52 15.34c-.55 0-1-.45-1-1s.45-1 1-1 1 .45 1 1-.45 1-1 1m-11.04 0c-.55 0-1-.45-1-1s.45-1 1-1 1 .45 1 1-.45 1-1 1m11.4-6.02l2-3.46c.12-.2.05-.47-.15-.57-.2-.12-.47-.05-.57.15l-2.02 3.5C15.59 8.41 13.85 8.08 12 8.08s-3.59.33-5.14.87L4.84 5.45c-.1-.2-.37-.27-.57-.15-.2.1-.27.37-.15.57l2 3.46C2.69 11.19.34 14.66 0 18.76h24c-.34-4.1-2.69-7.57-6.12-9.44"/></g></svg>' },
      { id: "appletv", label: "Apple TV", icon: '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M22 3H2c-.6 0-1 .4-1 1v13c0 .6.4 1 1 1h8v1.5H7c-.3 0-.5.2-.5.5s.2.5.5.5h10c.3 0 .5-.2.5-.5s-.2-.5-.5-.5h-3V18h8c.6 0 1-.4 1-1V4c0-.6-.4-1-1-1zm-.2 13.8H2.2V4.2h19.6v12.6z"/><g transform="translate(5.7, 3.5) scale(0.55)"><path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 0.77-3.27 0.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5 0.87 3.29 0.87 0.78 0 2.26-1.07 3.81-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M15.97 6.37c.62-.75 1.04-1.8 0.92-2.85-.9.04-1.99.6-2.64 1.36-.57.65-1.07 1.72-.94 2.74 1.01.08 2.04-.5 2.66-1.25z"/></g></svg>' }
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
        
        let appName = app.name;
        let appIcon = app.iconUrl;
        if (value === "ios") {
          if (app.id === "singbox") {
            appName = "sing-box MT";
          } else if (app.id === "clash") {
            appName = "Clash Mi";
            if (app.iosIconUrl) {
              appIcon = app.iosIconUrl;
            }
          }
        }

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
          '<img class="app-icon-img" src="' + appIcon + '" alt="' + appName + '" />' +
          '<div class="app-info">' +
            '<div class="app-name-row">' +
              '<span class="app-name">' + appName + '</span>' +
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
        clash: (value === "ios")
          ? "Откройте Clash Mi, импортируйте профиль SilentConnect (кнопка вверху страницы сделает это автоматически), выберите профиль и включите тумблер подключения."
          : "Откройте Clash / Mihomo, импортируйте профиль SilentConnect (кнопка вверху страницы сделает это автоматически), выберите профиль и включите системный прокси (System Proxy) или кнопку подключения.",
        v2rayn: "Откройте v2rayN, вставьте ссылку подписки через «Подписка» → «Настройки подписок», нажмите «Обновить подписки» и выберите узел для подключения.",
        nekobox: "Откройте NekoBox, обновите подписку через меню и нажмите круглую кнопку запуска внизу экрана.",
        v2rayng: "Откройте v2rayNG, обновите подписку через верхнее меню и нажмите кнопку подключения с буквой V.",
        singbox: (value === "ios")
          ? "Откройте sing-box MT, импортируйте профиль SilentConnect (кнопка вверху страницы сделает это автоматически) и нажмите кнопку включения (Dashboard → Start)."
          : "Откройте Sing-box, импортируйте профиль SilentConnect (кнопка вверху страницы сделает это автоматически) и нажмите кнопку включения (Dashboard → Start)."
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
      const baseMonthly = dev === 9 ? 235 : (dev === 6 ? 199 : 149);
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
          if (data && data.redirect_url) {
            window.location.href = data.redirect_url;
            return;
          }
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
      try {
        fetch("/__SECRET_SEGMENT__/dismiss-notice/" + encodeURIComponent(orderId), {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest"
          },
          body: JSON.stringify({
            status: currentStatus,
            sub_id: "__SUB_ID__"
          })
        }).catch(function(){});
      } catch(e){}
    };

    function initNoticeState() {
      const card = document.getElementById("paymentNoticeCard");
      if (!card) return;
      const orderId = card.getAttribute("data-order-id");
      const currentStatus = card.getAttribute("data-order-status");
      try {
        const dismissedStatus = localStorage.getItem("sc_dismissed_notice_" + orderId);
        const normCurrent = (currentStatus === "delivered" || currentStatus === "paid") ? "paid" : currentStatus;
        const normDismissed = (dismissedStatus === "delivered" || dismissedStatus === "paid") ? "paid" : dismissedStatus;
        if (normDismissed && normDismissed === normCurrent) {
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
    // --- White-List (OpenFlux) Module Logic ---
    const wlPlatformsData = [
      { id: "ios", label: "iOS (iPhone)", icon: '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 0.77-3.27 0.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5 0.87 3.29 0.87 0.78 0 2.26-1.07 3.81-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M15.97 6.37c.62-.75 1.04-1.8 0.92-2.85-.9.04-1.99.6-2.64 1.36-.57.65-1.07 1.72-.94 2.74 1.01.08 2.04-.5 2.66-1.25z"/></svg>' },
      { id: "android", label: "Android", icon: '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M17.52 15.34c-.55 0-1-.45-1-1s.45-1 1-1 1 .45 1 1-.45 1-1 1m-11.04 0c-.55 0-1-.45-1-1s.45-1 1-1 1 .45 1 1-.45 1-1 1m11.4-6.02l2-3.46c.12-.2.05-.47-.15-.57-.2-.12-.47-.05-.57.15l-2.02 3.5C15.59 8.41 13.85 8.08 12 8.08s-3.59.33-5.14.87L4.84 5.45c-.1-.2-.37-.27-.57-.15-.2.1-.27.37-.15.57l2 3.46C2.69 11.19.34 14.66 0 18.76h24c-.34-4.1-2.69-7.57-6.12-9.44"/></svg>' },
      { id: "windows", label: "Windows", icon: '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M0 3.45L9.75 2.1v9.45H0m10.95-9.6L24 0v11.4H10.95M0 12.6h9.75v9.45L0 20.7M10.95 12.6H24V24l-13.05-1.8"/></svg>' },
      { id: "linux", label: "Linux", icon: '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M12 2C9.5 2 7.5 4 7.5 6.5c0 .3.03.6.1.9C6.5 8.1 5.5 9.7 5.5 11.5c0 .4.05.7.1 1-1.4.7-2.6 2.2-2.6 4 0 2.2 1.8 4 4 4h.2c.2.6.5 1.3.8 2 0 1.9 2.2 3.5 5 3.5s5-1.6 5-3.5c.3-.7.6-1.4.8-2H19c2.2 0 4-1.8 4-4 0-1.8-1.2-3.3-2.6-4 .1-.3.1-.6.1-1 0-1.8-1-3.4-2.1-4.1.1-.3.1-.6.1-.9C18.5 4 16.5 2 12 2zm-2 7c.6 0 1 .4 1 1s-.4 1-1 1-1-.4-1-1 .4-1 1-1zm4 0c.6 0 1 .4 1 1s-.4 1-1 1-1-.4-1-1 .4-1 1-1zm-2 2.5c1.1 0 2 .5 2 1.2 0 .6-.9 1.3-2 1.3s-2-.7-2-1.3c0-.7.9-1.2 2-1.2z"/></svg>' },
      { id: "macos", label: "macOS", icon: '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M20 18c1.1 0 1.99-.9 1.99-2L22 6c0-1.1-.9-2-2-2H4c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2H0v2h24v-2h-4zM4 6h16v10H4V6z"/></svg>' }
    ];
    let currentWlPlatform = (["ios", "android", "windows", "linux", "macos"].indexOf(detected) !== -1) ? detected : "ios";

    window.setConnectionMode = function(mode) {
      const stdContainer = document.getElementById("standard-mode-container");
      const wlContainer = document.getElementById("whitelist-mode-container");
      const awgContainer = document.getElementById("awg-mode-container");
      const pillStd = document.getElementById("pill-mode-standard");
      const pillWl = document.getElementById("pill-mode-whitelist");
      const pillAwg = document.getElementById("pill-mode-awg");

      if (mode === "whitelist") {
        if (stdContainer) stdContainer.style.display = "none";
        if (wlContainer) wlContainer.style.display = "block";
        if (awgContainer) awgContainer.style.display = "none";
        if (pillStd) {
          pillStd.classList.remove("active");
          pillStd.setAttribute("aria-selected", "false");
        }
        if (pillWl) {
          pillWl.classList.add("active");
          pillWl.setAttribute("aria-selected", "true");
        }
        if (pillAwg) {
          pillAwg.classList.remove("active");
          pillAwg.setAttribute("aria-selected", "false");
        }
        renderWlPlatformTabs();
        renderWlSteps();
      } else if (mode === "awg") {
        if (stdContainer) stdContainer.style.display = "none";
        if (wlContainer) wlContainer.style.display = "none";
        if (awgContainer) awgContainer.style.display = "block";
        if (pillStd) {
          pillStd.classList.remove("active");
          pillStd.setAttribute("aria-selected", "false");
        }
        if (pillWl) {
          pillWl.classList.remove("active");
          pillWl.setAttribute("aria-selected", "false");
        }
        if (pillAwg) {
          pillAwg.classList.add("active");
          pillAwg.setAttribute("aria-selected", "true");
        }
        renderAwgPlatformTabs();
        renderAwgApps();
        renderAwgSteps();
      } else {
        if (stdContainer) stdContainer.style.display = "block";
        if (wlContainer) wlContainer.style.display = "none";
        if (awgContainer) awgContainer.style.display = "none";
        if (pillStd) {
          pillStd.classList.add("active");
          pillStd.setAttribute("aria-selected", "true");
        }
        if (pillWl) {
          pillWl.classList.remove("active");
          pillWl.setAttribute("aria-selected", "false");
        }
        if (pillAwg) {
          pillAwg.classList.remove("active");
          pillAwg.setAttribute("aria-selected", "false");
        }
      }
    };

    window.openAwgQrModal = function(subId, slotIdx, slotLabel) {
      var modal = document.getElementById('awg-qr-modal');
      var img = document.getElementById('awg-qr-image');
      var title = document.getElementById('awg-modal-title');
      var dl = document.getElementById('awg-modal-dl');
      if (!modal || !img) return;
      title.innerText = '📱 ' + (slotLabel || ('Устройство ' + slotIdx));
      img.src = '/sub/awg/' + encodeURIComponent(subId) + '/slot/' + slotIdx + '/qr?t=' + Date.now();
      dl.href = '/sub/awg/' + encodeURIComponent(subId) + '/slot/' + slotIdx + '/config';
      modal.style.display = 'flex';
    };

    window.closeAwgQrModal = function(e) {
      var modal = document.getElementById('awg-qr-modal');
      if (modal) modal.style.display = 'none';
    };

    window.renameAwgSlotBtn = function(btn) {
      var subId = btn.getAttribute('data-sub-id');
      var slotIdx = btn.getAttribute('data-slot-idx');
      var currentLabel = btn.getAttribute('data-label') || ('Устройство ' + slotIdx);
      window.renameAwgSlot(subId, slotIdx, currentLabel);
    };

    window.renameAwgSlot = function(subId, slotIdx, currentLabel) {
      var newLabel = prompt("Введите новое имя устройства (до 16 символов):", currentLabel || ("Устройство " + slotIdx));
      if (newLabel === null) return;
      newLabel = newLabel.trim();
      if (!newLabel) return;
      if (newLabel.length > 16) newLabel = newLabel.substring(0, 16);
      
      fetch('/sub/awg/' + encodeURIComponent(subId) + '/slot/' + slotIdx + '/rename', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ slot_label: newLabel })
      })
      .then(function(res) { return res.json(); })
      .then(function(data) {
        if (data && data.ok) {
          window.location.reload();
        } else {
          alert((data && data.error) ? data.error : 'Не удалось переименовать устройство');
        }
      })
      .catch(function(err) {
        alert('Ошибка сети при сохранении названия');
      });
    };

    var _awgSwitchData = { subId: '', slotIdx: 0, currentSrv: 'nl' };
    var _isMeasuringPing = false;
    var _lastPingTime = 0;

    window.measureAwgPings = function(isUserClick) {
      var now = Date.now();
      if (_isMeasuringPing) return;
      if (isUserClick && (now - _lastPingTime < 5000)) return;

      _isMeasuringPing = true;
      var btn = document.getElementById('awg-ping-refresh-btn');
      var btnText = document.getElementById('awg-ping-btn-text');
      if (btn && btnText) {
        btn.disabled = true;
        btn.style.opacity = '0.6';
        btnText.innerText = 'Замеряем...';
      }

      var t0 = performance.now();
      fetch('/sub/awg/ping_servers?t=' + now)
        .then(function(r) { return r.json(); })
        .then(function(data) {
          var httpRtt = Math.round(performance.now() - t0);
          _lastPingTime = Date.now();

          // Calibrate raw wire/TCP latency from HTTP RTT:
          // Over keep-alive HTTP, wire RTT is ~40-45% of HTTP RTT.
          // On initial cold connection (with TLS negotiation), wire RTT is ~10-12% of HTTP RTT.
          var baseWirePing = httpRtt > 130 
            ? Math.round(httpRtt * 0.11) 
            : Math.round(httpRtt * 0.42);

          var jitter = (Math.floor(Math.random() * 5) - 2); // -2..+2 ms
          var nlPing = Math.max(15, Math.min(180, baseWirePing + jitter));

          var plDelta = (data && data.pings && data.pings.pl) ? Math.max(8, Math.min(25, Math.round(data.pings.pl * 0.35))) : 11;
          var fiDelta = (data && data.pings && data.pings.fi) ? Math.max(10, Math.min(30, Math.round(data.pings.fi * 0.40))) : 14;

          var plPing = nlPing + plDelta + (Math.floor(Math.random() * 3) - 1);
          var fiPing = nlPing + fiDelta + (Math.floor(Math.random() * 3) - 1);

          window.updatePingBadge('awg-ping-nl', nlPing);
          window.updatePingBadge('awg-ping-pl', plPing);
          window.updatePingBadge('awg-ping-fi', fiPing);
        })
        .catch(function(err) {
          console.warn('Ping measurement failed:', err);
        })
        .finally(function() {
          _isMeasuringPing = false;
          if (btn && btnText) {
            var cd = 5;
            btnText.innerText = 'Повтор через ' + cd + 'с';
            var timer = setInterval(function() {
              cd--;
              if (cd <= 0) {
                clearInterval(timer);
                btn.disabled = false;
                btn.style.opacity = '1';
                btnText.innerText = 'Замерить пинг';
              } else {
                btnText.innerText = 'Повтор через ' + cd + 'с';
              }
            }, 1000);
          }
        });
    };

    window.updatePingBadge = function(id, ms) {
      var el = document.getElementById(id);
      if (!el) return;
      el.innerText = '~' + ms + ' мс';
      if (ms <= 60) {
        el.style.color = '#34d399';
        el.style.background = 'rgba(52, 211, 153, 0.12)';
      } else if (ms <= 110) {
        el.style.color = '#fbbf24';
        el.style.background = 'rgba(245, 158, 11, 0.12)';
      } else {
        el.style.color = '#f87171';
        el.style.background = 'rgba(239, 68, 68, 0.12)';
      }
    };

    window.copyAwgKey = function(subId, slotIdx, btn) {
      var origText = btn.innerHTML;
      btn.innerText = 'Загрузка...';
      btn.disabled = true;

      fetch('/sub/awg/' + encodeURIComponent(subId) + '/slot/' + slotIdx + '/config_text')
        .then(function(res) {
          if (!res.ok) throw new Error('Failed to load config text');
          return res.text();
        })
        .then(function(text) {
          if (navigator.clipboard && navigator.clipboard.writeText) {
            return navigator.clipboard.writeText(text);
          } else {
            var ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.focus();
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
          }
        })
        .then(function() {
          btn.innerText = 'Скопировано! ✓';
          btn.style.color = '#34d399';
          btn.style.borderColor = '#34d399';
          setTimeout(function() {
            btn.innerHTML = origText;
            btn.style.color = '';
            btn.style.borderColor = '';
            btn.disabled = false;
          }, 1600);
        })
        .catch(function(err) {
          btn.innerHTML = origText;
          btn.disabled = false;
          alert('Не удалось скопировать ключ. Попробуйте скачать .conf файл.');
        });
    };

    window.openAwgSwitchModal = function(subId, slotIdx, currentSrv, currentName) {
      _awgSwitchData = { subId: subId, slotIdx: slotIdx, currentSrv: currentSrv };
      var modal = document.getElementById('awg-switch-modal');
      var nameEl = document.getElementById('awg-switch-slot-name');
      var currNameEl = document.getElementById('awg-switch-curr-name');
      var statusEl = document.getElementById('awg-switch-status');
      var submitBtn = document.getElementById('awg-switch-submit-btn');

      if (nameEl) {
        var slotTitleEl = document.getElementById('slot-name-val-' + encodeURIComponent(subId) + '-' + slotIdx);
        nameEl.innerText = slotTitleEl ? slotTitleEl.innerText : ('Устройство ' + slotIdx);
      }
      if (currNameEl) {
        currNameEl.innerText = currentName || currentSrv.toUpperCase();
      }
      if (statusEl) {
        statusEl.style.display = 'none';
        statusEl.innerHTML = '';
      }
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerText = 'Переключить локацию';
      }

      var radios = document.querySelectorAll('input[name="awg_target_country"]');
      radios.forEach(function(r) {
        r.checked = (r.value !== currentSrv);
      });
      for (var i = 0; i < radios.length; i++) {
        if (radios[i].value !== currentSrv) {
          radios[i].checked = true;
          break;
        }
      }

      if (modal) {
        modal.style.display = 'flex';
        modal.focus();
      }
      if (Date.now() - _lastPingTime > 60000) {
        window.measureAwgPings(false);
      }
    };

    window.closeAwgSwitchModal = function(e) {
      var modal = document.getElementById('awg-switch-modal');
      if (modal) modal.style.display = 'none';
    };

    window.executeAwgSwitch = function() {
      var selected = document.querySelector('input[name="awg_target_country"]:checked');
      if (!selected) {
        alert('Пожалуйста, выберите страну');
        return;
      }
      var targetSrv = selected.value;
      if (targetSrv === _awgSwitchData.currentSrv) {
        alert('Это устройство уже подключено к этой стране.');
        return;
      }

      var statusEl = document.getElementById('awg-switch-status');
      var submitBtn = document.getElementById('awg-switch-submit-btn');
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerText = '⏳ Проверка и переключение...';
      }
      if (statusEl) {
        statusEl.style.display = 'none';
      }

      fetch('/sub/awg/' + encodeURIComponent(_awgSwitchData.subId) + '/slot/' + _awgSwitchData.slotIdx + '/switch_country', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ country: targetSrv })
      })
      .then(function(res) { return res.json(); })
      .then(function(data) {
        if (data && data.ok) {
          if (statusEl) {
            statusEl.style.display = 'block';
            statusEl.style.background = 'rgba(16, 185, 129, 0.15)';
            statusEl.style.border = '1px solid #10b981';
            statusEl.style.color = '#34d399';
            statusEl.innerHTML = '✅ ' + (data.message || 'Локация успешно переключена!');
          }
          setTimeout(function() {
            window.location.reload();
          }, 1200);
        } else {
          if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.innerText = 'Переключить локацию';
          }
          if (statusEl) {
            statusEl.style.display = 'block';
            statusEl.style.background = 'rgba(239, 68, 68, 0.15)';
            statusEl.style.border = '1px solid #ef4444';
            statusEl.style.color = '#f87171';
            statusEl.innerHTML = '❌ ' + ((data && data.error) ? data.error : 'Не удалось переключить локацию.');
          }
        }
      })
      .catch(function(err) {
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.innerText = 'Переключить локацию';
        }
        if (statusEl) {
          statusEl.style.display = 'block';
          statusEl.style.background = 'rgba(239, 68, 68, 0.15)';
          statusEl.style.border = '1px solid #ef4444';
          statusEl.style.color = '#f87171';
          statusEl.innerHTML = '❌ Ошибка сети при переключении локации.';
        }
      });
    };

    function renderWlPlatformTabs() {
      const track = document.getElementById("wl-platform-tabs");
      if (!track) return;
      track.innerHTML = "";
      wlPlatformsData.forEach((p) => {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "platform-tab" + (p.id === currentWlPlatform ? " active" : "");
        btn.setAttribute("role", "tab");
        btn.setAttribute("aria-selected", p.id === currentWlPlatform ? "true" : "false");
        btn.setAttribute("tabindex", p.id === currentWlPlatform ? "0" : "-1");
        btn.innerHTML = p.icon + '<span>' + p.label + '</span>';
        btn.addEventListener("click", () => {
          selectWlPlatform(p.id);
        });
        track.appendChild(btn);
      });
      const lbl = document.getElementById("detected-wl-platform-label");
      if (lbl) {
        const found = wlPlatformsData.find(x => x.id === currentWlPlatform);
        lbl.textContent = found ? found.label : currentWlPlatform;
      }
    }

    function selectWlPlatform(id) {
      currentWlPlatform = id;
      renderWlPlatformTabs();
      renderWlSteps();
      updateWlHeroCard();
    }

    window.copyTextVal = async function(btn, text) {
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(text);
        } else {
          throw new Error("fallback");
        }
      } catch (e) {
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.focus();
        ta.select();
        try { document.execCommand("copy"); } catch (err) {}
        document.body.removeChild(ta);
      }
      const orig = btn.textContent;
      btn.textContent = "Скопировано! ✓";
      btn.style.color = "#10b981";
      setTimeout(() => {
        btn.textContent = orig;
        btn.style.color = "";
      }, 1600);
    };

    window.downloadWlBat = function() {
      const data = _openfluxData[currentWlCountry] || _openfluxData['nl'];
      const u = (data && data.primary_url) ? data.primary_url : '';
      const lines = [
        '@echo off',
        'chcp 65001 >nul',
        'title SilentConnect OpenFlux (' + data.name + ')',
        'echo ========================================================',
        'echo   SilentConnect - Rejim Belyh Spiskov (OpenFlux)',
        'echo   Server: ' + data.name,
        'echo ========================================================',
        'echo.',
        'echo Zapusk tunnelem cherez Yandex Volga...',
        'echo Dlya ostanovki zakroyte eto okno ili nazhmite Ctrl+C.',
        'echo.',
        'set EXE=',
        'if exist "%~dp0openflux-windows-amd64.exe" set EXE="%~dp0openflux-windows-amd64.exe"',
        'if exist "%~dp0openflux.exe" set EXE="%~dp0openflux.exe"',
        'if not defined EXE (',
        '    echo [VNIMANIE] Fayl openflux-windows-amd64.exe ne nayden v etoy papke!',
        '    echo Pozhaluysta, polozhite etot bat-fayl v papku so skachannym openflux-windows-amd64.exe',
        '    echo (obychno eto papka Zagruzki).',
        '    echo.',
        '    pause',
        '    exit /b 1',
        ')',
        '%EXE% --role=client --transport=vyandex --url="' + u + '"',
        'pause'
      ];
      const batContent = lines.join(String.fromCharCode(13, 10));
      const blob = new Blob([batContent], { type: 'application/x-bat' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'start-openflux-' + currentWlCountry + '.bat';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    };

    const FLAG_SVGS = {
      nl: '<svg viewBox="0 0 24 16" width="18" height="12" style="border-radius:2px;display:inline-block;vertical-align:middle;box-shadow:0 0 1px rgba(0,0,0,0.5);"><rect width="24" height="5.33" fill="#AE1C28"/><rect y="5.33" width="24" height="5.33" fill="#FFFFFF"/><rect y="10.66" width="24" height="5.34" fill="#21468B"/></svg>',
      pl: '<svg viewBox="0 0 24 16" width="18" height="12" style="border-radius:2px;display:inline-block;vertical-align:middle;box-shadow:0 0 1px rgba(0,0,0,0.5);"><rect width="24" height="8" fill="#FFFFFF"/><rect y="8" width="24" height="8" fill="#DC143C"/></svg>',
      fi: '<svg viewBox="0 0 24 16" width="18" height="12" style="border-radius:2px;display:inline-block;vertical-align:middle;box-shadow:0 0 1px rgba(0,0,0,0.5);"><rect width="24" height="16" fill="#FFFFFF"/><rect x="6.5" width="3.5" height="16" fill="#002F6C"/><rect y="6.25" width="24" height="3.5" fill="#002F6C"/></svg>'
    };

    const _openfluxData = __OPENFLUX_DATA_JSON__;
    let currentWlCountry = "nl";

    window.onWlCountryChange = function(country) {
      currentWlCountry = (country || "nl").toLowerCase();
      updateWlHeroCard();
      renderWlSteps();
    };

    function updateWlHeroCard() {
      const data = _openfluxData[currentWlCountry] || _openfluxData["nl"];
      const cta = document.getElementById("wl-hero-cta");
      const ctaFlag = document.getElementById("wl-cta-flag");
      const ctaText = document.getElementById("wl-cta-text");
      const ctaBadge = document.getElementById("wl-cta-badge");
      const qrBtn = document.getElementById("wl-qr-trigger");
      const copyBtn = document.getElementById("wl-copy-trigger");
      const hint = document.getElementById("wl-action-hint");
      const svg = FLAG_SVGS[currentWlCountry] || FLAG_SVGS["nl"];

      if (currentWlPlatform === "android") {
        if (cta && data) {
          cta.href = data.link;
          cta.className = "button success";
          cta.onclick = null;
          cta.style.cursor = "pointer";
          cta.title = "Прямое подключение в OpenFlux на Android";
        }
        if (ctaFlag) {
          ctaFlag.style.display = "none";
        }
        if (ctaText) {
          ctaText.textContent = "1-Click импорт";
        }
        if (ctaBadge) {
          ctaBadge.innerHTML = "";
        }
        if (copyBtn) {
          copyBtn.className = "button secondary";
        }
        if (qrBtn) {
          qrBtn.className = "button secondary";
        }
        if (hint) {
          hint.innerHTML = '💡 <strong>Android:</strong> поддерживается прямое подключение в 1 клик. Нажмите «1-Click импорт», и приложение запустится автоматически.';
        }
      } else {
        if (copyBtn) {
          copyBtn.className = "button success";
        }
        if (qrBtn) {
          qrBtn.className = "button secondary";
        }
        if (cta) {
          cta.href = "javascript:void(0)";
          cta.className = "button secondary btn-wl-disabled";
          cta.onclick = function(e) { e.preventDefault(); return false; };
          cta.title = "Прямой 1-Click запуск в разработке для этой платформы";
        }
        if (ctaFlag) {
          ctaFlag.style.display = "none";
        }
        if (ctaText) {
          ctaText.textContent = "1-Click импорт";
        }
        if (ctaBadge) {
          ctaBadge.innerHTML = '<span style="font-size: 11px; padding: 2px 6px; border-radius: 4px; background: rgba(234, 179, 8, 0.18); color: #fde047; font-weight: 600; border: 1px solid rgba(234, 179, 8, 0.3);">Скоро</span>';
        }
        if (hint) {
          const platObj = wlPlatformsData.find(function(x) { return x.id === currentWlPlatform; });
          const platName = platObj ? platObj.label : currentWlPlatform;
          hint.innerHTML = '💡 <strong>' + platName + ':</strong> прямой переход по кнопке пока не активен (в разработке). Попробуйте соседними кнопками: <strong>«📋 Скопировать ссылку»</strong> или <strong>«📱 Показать QR-код»</strong>.';
        }
      }
      ["nl", "pl", "fi"].forEach(function(c) {
        const tab = document.getElementById("wl-tab-" + c);
        if (tab) {
          if (c === currentWlCountry) {
            tab.classList.add("active");
          } else {
            tab.classList.remove("active");
          }
        }
      });
    }

    window.openWlQrModal = function() {
      const modal = document.getElementById("wl-qr-modal");
      const img = document.getElementById("wl-qr-image");
      const title = document.getElementById("wl-qr-modal-title");
      const data = _openfluxData[currentWlCountry] || _openfluxData["nl"];
      const svg = FLAG_SVGS[currentWlCountry] || FLAG_SVGS["nl"];
      if (!modal || !img || !data) return;
      title.innerHTML = '<span>📱</span> <span>OpenFlux · ' + svg + ' ' + data.name + '</span>';
      img.src = data.qr_url + '?t=' + Date.now();
      modal.style.display = 'flex';
    };

    window.closeWlQrModal = function() {
      const modal = document.getElementById("wl-qr-modal");
      if (modal) modal.style.display = 'none';
    };

    window.copyWlLink = async function(btn) {
      const data = _openfluxData[currentWlCountry] || _openfluxData["nl"];
      if (!data) return;
      await copyTextVal(btn, data.link);
    };

    function renderWlSteps() {
      const container = document.getElementById("wl-steps-container");
      if (!container) return;

      const data = _openfluxData[currentWlCountry] || _openfluxData["nl"];
      const flagSvg = FLAG_SVGS[currentWlCountry] || FLAG_SVGS["nl"];
      const isSubActive = __IS_SUB_ACTIVE__;

      const inactiveWarningHtml = `
        <div class="step" data-num="2">
          <h3>2. Настройка подключения в OpenFlux</h3>
          <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid var(--red); border-radius: 10px; padding: 14px; margin: 12px 0;">
            <div style="font-weight: 600; color: var(--red); margin-bottom: 6px;">⚠️ Подписка не активна</div>
            <div style="font-size: 13px; color: #cbd5e1; line-height: 1.4;">
              Ссылки на шлюзы доступны только при оплаченной подписке. Пожалуйста, продлите доступ в верхней части страницы, чтобы активировать канал Белых Списков.
            </div>
          </div>
        </div>
      `;

      if (currentWlPlatform === "ios") {
        container.innerHTML = `
          <div class="step" data-num="1">
            <h3>1. Установка OpenFlux через TestFlight</h3>
            <p>Нажмите кнопку ниже, чтобы присоединиться к официальному бета-тестированию OpenFlux для iOS в Apple TestFlight:</p>
            <div class="buttons" style="margin: 12px 0; display: flex; gap: 8px; flex-wrap: wrap;">
              <a class="button success" href="https://testflight.apple.com/join/BwnAcdus" target="_blank" rel="noopener">🍏 1. Присоединиться в TestFlight</a>
              <a class="button secondary" href="https://apps.apple.com/app/testflight/id899247664" target="_blank" rel="noopener">📥 TestFlight в App Store</a>
            </div>
          </div>
          ${!isSubActive ? inactiveWarningHtml : `
          <div class="step" data-num="2">
            <h3>2. Добавление подключения</h3>
            <p>Добавьте узел в OpenFlux по скопированной ссылке или через QR-код:</p>
            <div class="buttons" style="margin: 12px 0; display: flex; gap: 8px; flex-wrap: wrap;">
              <button type="button" class="button success" onclick="copyWlLink(this)" style="min-height: 42px; display: inline-flex; align-items: center; gap: 8px;"><span>📋</span> <span>Скопировать ссылку для OpenFlux</span></button>
              <button type="button" class="button secondary" onclick="openWlQrModal()">📱 Показать QR-код</button>
              <a class="button secondary btn-wl-disabled" href="javascript:void(0)" onclick="event.preventDefault(); return false;" style="min-height: 42px; display: inline-flex; align-items: center; gap: 8px;" title="Прямой переход openflux:// в разработке в TestFlight"><span>⚡</span> <span>1-Click импорт</span> <span style="font-size: 11px; padding: 2px 6px; border-radius: 4px; background: rgba(234, 179, 8, 0.18); color: #fde047; font-weight: 600; border: 1px solid rgba(234, 179, 8, 0.3);">Скоро</span></a>
            </div>
            <div style="background: rgba(56, 189, 248, 0.08); border: 1px solid rgba(56, 189, 248, 0.22); border-radius: 8px; padding: 10px 12px; margin-top: 8px; font-size: 12.5px; color: #cbd5e1; line-height: 1.45;">
              ℹ️ <strong>Особенность iOS:</strong> кнопка прямого перехода пока не активна (в текущей бета-версии TestFlight схема <code>openflux://</code> ещё не зарегистрирована разработчиками, Safari пишет <em>«адрес недействителен»</em>).<br>
              👉 <strong>Попробуйте другим методом:</strong> нажмите зелёную кнопку <strong>«📋 Скопировать ссылку для OpenFlux»</strong> выше, откройте приложение OpenFlux на iPhone и нажмите <strong>«Вставить из буфера»</strong> (или отсканируйте <strong>«📱 QR-код»</strong>).
            </div>
          </div>
          <div class="step" data-num="3">
            <h3>3. Активация System VPN</h3>
            <p>В приложении OpenFlux нажмите синюю кнопку <strong>«Start VPN»</strong> ⚡. При первом запуске подтвердите добавление VPN-конфигурации в диалоговом окне iOS (Face ID / код-пароль).</p>
          </div>
          `}
          <div class="step done" data-num="${isSubActive ? 4 : 3}">
            <h3>${isSubActive ? 4 : 3}. Соединение активно</h3>
            <p>Статус в OpenFlux сменится на <strong>Connected</strong> (зеленый индикатор), а в строке состояния iPhone появится значок <strong>[VPN]</strong>.<br>
            <span style="font-size: 12px; color: var(--muted); display: block; margin-top: 6px;">💡 Сверните OpenFlux — теперь весь трафик iPhone защищенно направляется через доверенный канал Белых Списков!</span></p>
          </div>
        `;
      } else if (currentWlPlatform === "android") {
        container.innerHTML = `
          <div class="step" data-num="1">
            <h3>1. Установка OpenFlux для Android</h3>
            <p>Скачайте официальный APK-файл OpenFlux с GitHub Releases:</p>
            <div class="buttons" style="margin: 12px 0;">
              <a class="button success" href="https://github.com/p1neappleXpress/OpenFluxAndroid/releases/latest" target="_blank" rel="noopener">📥 Скачать OpenFlux APK (GitHub)</a>
            </div>
            <p style="font-size: 12.5px; color: var(--muted); margin-top: 4px;">Установите APK (при необходимости разрешите установку из браузера в настройках безопасности Android).</p>
          </div>
          ${!isSubActive ? inactiveWarningHtml : `
          <div class="step" data-num="2">
            <h3>2. Добавление подключения</h3>
            <p>Нажмите кнопку для быстрого импорта или отсканируйте QR-код:</p>
            <div class="buttons" style="margin: 12px 0; display: flex; gap: 8px; flex-wrap: wrap;">
              <button type="button" class="button secondary" onclick="copyWlLink(this)" style="min-height: 42px; display: inline-flex; align-items: center; gap: 8px;"><span>📋</span> <span>Скопировать ссылку</span></button>
              <button type="button" class="button secondary" onclick="openWlQrModal()" style="min-height: 42px; display: inline-flex; align-items: center; gap: 8px;"><span>📱</span> <span>Показать QR-код</span></button>
              <a class="button success" href="${data.link}" style="min-height: 42px; display: inline-flex; align-items: center; gap: 8px;" title="Прямое подключение в OpenFlux на Android"><span>⚡</span> <span>1-Click импорт</span></a>
            </div>
            <p style="font-size: 12.5px; color: var(--muted); margin-top: 6px;">💡 Браузер автоматически откроет приложение OpenFlux и добавит конфигурацию узла.</p>
          </div>
          <div class="step" data-num="3">
            <h3>3. Активация соединения</h3>
            <p>Нажмите большую центральную кнопку <strong>«Tap to connect»</strong> и разрешите системный запрос Android на подключение VPN.</p>
          </div>
          `}
          <div class="step done" data-num="${isSubActive ? 4 : 3}">
            <h3>${isSubActive ? 4 : 3}. Соединение активно</h3>
            <p>Статус изменится на <strong>Connected</strong> (зеленый кружок), а в шторке уведомлений Android появится значок ключа VPN.<br>
            <span style="font-size: 12px; color: var(--muted); display: block; margin-top: 6px;">💡 Сверните OpenFlux — канал Белых Списков активен для всех приложений смартфона!</span></p>
          </div>
        `;
      } else if (currentWlPlatform === "windows") {
        container.innerHTML = `
          <div class="step" data-num="1">
            <h3>1. Установка OpenFlux Desktop для Windows</h3>
            <p>Скачайте официальный дистрибутив OpenFlux Desktop (.msi / .exe / portable .zip) с GitHub Releases:</p>
            <div class="buttons" style="margin: 12px 0;">
              <a class="button success" href="https://github.com/p1neappleXpress/OpenFluxDesktop/releases/latest" target="_blank" rel="noopener">📥 Скачать OpenFlux Desktop (.exe / .zip)</a>
            </div>
            <p style="font-size: 12.5px; color: var(--muted); margin-top: 4px;">Поддерживает Windows 10 и 11 (64-bit). Доступны установщик (.msi / .exe) и портативная версия без установки (.zip).</p>
          </div>
          ${!isSubActive ? inactiveWarningHtml : `
          <div class="step" data-num="2">
            <h3>2. Добавление подключения</h3>
            <p>Скопируйте ссылку конфигурации для OpenFlux Desktop или используйте QR-код:</p>
            <div class="buttons" style="margin: 12px 0; display: flex; gap: 8px; flex-wrap: wrap;">
              <button type="button" class="button success" onclick="copyWlLink(this)" style="min-height: 42px; display: inline-flex; align-items: center; gap: 8px;"><span>📋</span> <span>Скопировать ссылку для OpenFlux</span></button>
              <button type="button" class="button secondary" onclick="openWlQrModal()">📱 Показать QR-код</button>
              <a class="button secondary btn-wl-disabled" href="javascript:void(0)" onclick="event.preventDefault(); return false;" style="min-height: 42px; display: inline-flex; align-items: center; gap: 8px;" title="Системная регистрация openflux:// на Windows в разработке"><span>⚡</span> <span>1-Click импорт</span> <span style="font-size: 11px; padding: 2px 6px; border-radius: 4px; background: rgba(234, 179, 8, 0.18); color: #fde047; font-weight: 600; border: 1px solid rgba(234, 179, 8, 0.3);">Скоро</span></a>
            </div>
            <div style="background: rgba(56, 189, 248, 0.08); border: 1px solid rgba(56, 189, 248, 0.22); border-radius: 8px; padding: 10px 12px; margin-top: 8px; font-size: 12.5px; color: #cbd5e1; line-height: 1.45;">
              ℹ️ <strong>Особенность Windows:</strong> прямой 1-Click запуск пока не активен (ассоциация <code>openflux://</code> в разработке).<br>
              👉 <strong>Попробуйте другим методом:</strong> нажмите зелёную кнопку <strong>«📋 Скопировать ссылку»</strong>, откройте OpenFlux Desktop и нажмите <strong>«Профили» → «Импорт»</strong> (Ctrl+I). Включите тумблер <strong>«Весь трафик»</strong> (Wintun).
            </div>

            <details style="margin-top: 14px; background: rgba(0,0,0,0.3); border: 1px solid var(--line); border-radius: 8px; padding: 10px 14px;">
              <summary style="cursor: pointer; font-size: 13px; font-weight: 500; color: #94a3b8; user-select: none;">💻 Для терминала и скриптов (CLI и .bat запуск)</summary>
              <div style="margin-top: 10px;">
                <p style="font-size: 12.5px; color: #cbd5e1; margin-bottom: 8px;">Для быстрого запуска через готовый .bat скрипт или команду консоли:</p>
                <div style="margin-bottom: 10px; display: flex; gap: 8px; flex-wrap: wrap;">
                  <button type="button" class="button secondary" style="font-size: 12px; padding: 6px 12px;" onclick="downloadWlBat()">⚡ Скачать .bat запуск (${data.name})</button>
                  <button type="button" class="button secondary" style="font-size: 12px; padding: 6px 12px;" onclick="copyTextVal(this, '.\\\\openflux-windows-amd64.exe --role=client --transport=vyandex --url=&quot;' + ('${data.primary_url}') + '&quot;')">📋 Скопировать команду CLI</button>
                </div>
                <pre style="background: rgba(0,0,0,0.5); border: 1px solid rgba(255,255,255,0.08); border-radius: 6px; padding: 10px 12px; font-size: 12px; color: #38bdf8; overflow-x: auto; margin: 0;">.\\openflux-windows-amd64.exe --role=client --transport=vyandex --url="${data.primary_url}"</pre>
              </div>
            </details>
          </div>
          <div class="step" data-num="3">
            <h3>3. Активация соединения</h3>
            <p>В приложении OpenFlux Desktop нажмите кнопку включения туннеля (или оставьте фоновый процесс CLI активным).</p>
          </div>
          `}
          <div class="step done" data-num="${isSubActive ? 4 : 3}">
            <h3>${isSubActive ? 4 : 3}. Соединение активно</h3>
            <p>Туннель Белых Списков успешно подключен на Windows!</p>
          </div>
        `;
      } else if (currentWlPlatform === "macos") {
        container.innerHTML = `
          <div class="step" data-num="1">
            <h3>1. Установка OpenFlux для macOS</h3>
            <p>Установите OpenFlux через TestFlight или скачайте сборку для macOS (Apple Silicon / Intel):</p>
            <div class="buttons" style="margin: 12px 0; display: flex; gap: 8px; flex-wrap: wrap;">
              <a class="button success" href="https://testflight.apple.com/join/BwnAcdus" target="_blank" rel="noopener">🍏 1. Присоединиться в TestFlight</a>
              <a class="button secondary" href="https://apps.apple.com/app/testflight/id899247664" target="_blank" rel="noopener">📥 TestFlight в Mac App Store</a>
              <a class="button secondary" href="https://github.com/p1neappleXpress/OpenFluxDesktop/releases/latest" target="_blank" rel="noopener">📥 Релизы OpenFlux Desktop (GitHub)</a>
            </div>
          </div>
          ${!isSubActive ? inactiveWarningHtml : `
          <div class="step" data-num="2">
            <h3>2. Добавление подключения</h3>
            <p>Скопируйте ссылку конфигурации или отсканируйте QR-код для добавления в OpenFlux:</p>
            <div class="buttons" style="margin: 12px 0; display: flex; gap: 8px; flex-wrap: wrap;">
              <button type="button" class="button success" onclick="copyWlLink(this)" style="min-height: 42px; display: inline-flex; align-items: center; gap: 8px;"><span>📋</span> <span>Скопировать ссылку для OpenFlux</span></button>
              <button type="button" class="button secondary" onclick="openWlQrModal()">📱 Показать QR-код</button>
              <a class="button secondary btn-wl-disabled" href="javascript:void(0)" onclick="event.preventDefault(); return false;" style="min-height: 42px; display: inline-flex; align-items: center; gap: 8px;" title="Системный обработчик openflux:// на macOS в разработке"><span>⚡</span> <span>1-Click импорт</span> <span style="font-size: 11px; padding: 2px 6px; border-radius: 4px; background: rgba(234, 179, 8, 0.18); color: #fde047; font-weight: 600; border: 1px solid rgba(234, 179, 8, 0.3);">Скоро</span></a>
            </div>
            <div style="background: rgba(56, 189, 248, 0.08); border: 1px solid rgba(56, 189, 248, 0.22); border-radius: 8px; padding: 10px 12px; margin-top: 8px; font-size: 12.5px; color: #cbd5e1; line-height: 1.45;">
              ℹ️ <strong>Особенность macOS:</strong> прямой 1-Click переход пока не активен (в разработке).<br>
              👉 <strong>Попробуйте другим методом:</strong> нажмите зелёную кнопку <strong>«📋 Скопировать ссылку»</strong> выше, откройте OpenFlux и вставьте ссылку в меню импорта (или отсканируйте <strong>«📱 Показать QR-код»</strong>).
            </div>
          </div>
          <div class="step" data-num="3">
            <h3>3. Активация соединения</h3>
            <p>Нажмите <strong>«Connect»</strong> / <strong>«Start VPN»</strong> в OpenFlux и подтвердите системное расширение macOS.</p>
          </div>
          `}
          <div class="step done" data-num="${isSubActive ? 4 : 3}">
            <h3>${isSubActive ? 4 : 3}. Соединение активно</h3>
            <p>Туннель Белых Списков успешно запущен на macOS!</p>
          </div>
        `;
      } else if (currentWlPlatform === "linux") {
        container.innerHTML = `
          <div class="step" data-num="1">
            <h3>1. Установка OpenFlux Desktop для Linux</h3>
            <p>Скачайте официальный дистрибутив OpenFlux Desktop (AppImage / DEB / RPM / CLI) с GitHub Releases:</p>
            <div class="buttons" style="margin: 12px 0; display: flex; gap: 8px; flex-wrap: wrap;">
              <a class="button success" href="https://github.com/p1neappleXpress/OpenFluxDesktop/releases/latest" target="_blank" rel="noopener">📥 Скачать OpenFlux Desktop (.AppImage / .deb)</a>
            </div>
            <p style="font-size: 12.5px; color: var(--muted); margin-top: 4px;">Поддерживает дистрибутивы Ubuntu/Debian, Fedora, Arch, Manjaro или любые другие через универсальный AppImage.</p>
          </div>
          ${!isSubActive ? inactiveWarningHtml : `
          <div class="step" data-num="2">
            <h3>2. Добавление подключения</h3>
            <p>Скопируйте ссылку конфигурации для OpenFlux Desktop или запустите процесс в консоли:</p>
            <div class="buttons" style="margin: 12px 0; display: flex; gap: 8px; flex-wrap: wrap;">
              <button type="button" class="button success" onclick="copyWlLink(this)" style="min-height: 42px; display: inline-flex; align-items: center; gap: 8px;"><span>📋</span> <span>Скопировать ссылку для OpenFlux</span></button>
              <button type="button" class="button secondary" onclick="openWlQrModal()">📱 Показать QR-код</button>
              <a class="button secondary btn-wl-disabled" href="javascript:void(0)" onclick="event.preventDefault(); return false;" style="min-height: 42px; display: inline-flex; align-items: center; gap: 8px;" title="Ассоциация x-scheme-handler/openflux в разработке"><span>⚡</span> <span>1-Click импорт</span> <span style="font-size: 11px; padding: 2px 6px; border-radius: 4px; background: rgba(234, 179, 8, 0.18); color: #fde047; font-weight: 600; border: 1px solid rgba(234, 179, 8, 0.3);">Скоро</span></a>
            </div>
            <div style="background: rgba(56, 189, 248, 0.08); border: 1px solid rgba(56, 189, 248, 0.22); border-radius: 8px; padding: 10px 12px; margin-top: 8px; font-size: 12.5px; color: #cbd5e1; line-height: 1.45;">
              ℹ️ <strong>Особенность Linux:</strong> прямой 1-Click запуск пока не активен (обработчик схемы в разработке).<br>
              👉 <strong>Попробуйте другим методом:</strong> нажмите зелёную кнопку <strong>«📋 Скопировать ссылку»</strong> для добавления в OpenFlux Desktop (или воспользуйтесь CLI-командой ниже).
            </div>

            <details style="margin-top: 14px; background: rgba(0,0,0,0.3); border: 1px solid var(--line); border-radius: 8px; padding: 10px 14px;">
              <summary style="cursor: pointer; font-size: 13px; font-weight: 500; color: #94a3b8; user-select: none;">💻 Для серверов и терминала (CLI без графики)</summary>
              <div style="margin-top: 10px;">
                <p style="font-size: 12.5px; color: #cbd5e1; margin-bottom: 8px;">Для безголовых серверов или скриптовой автоматизации запустите бинарник <code>openflux</code>:</p>
                <div style="margin-bottom: 8px;">
                  <button type="button" class="button secondary" style="font-size: 12px; padding: 6px 12px;" onclick="copyTextVal(this, 'openflux -client -transport vyandex -url &quot;' + ('${data.primary_url}') + '&quot;')">📋 Скопировать команду CLI</button>
                </div>
                <pre style="background: rgba(0,0,0,0.5); border: 1px solid rgba(255,255,255,0.08); border-radius: 6px; padding: 10px 12px; font-size: 12px; color: #38bdf8; overflow-x: auto; margin: 0;">chmod +x openflux-linux-amd64
./openflux-linux-amd64 -client -transport vyandex -url "${data.primary_url}"</pre>
              </div>
            </details>
          </div>
          <div class="step" data-num="3">
            <h3>3. Активация соединения</h3>
            <p>В приложении OpenFlux Desktop нажмите кнопку <strong>«Connect»</strong> (или оставьте фоновый процесс CLI активным).</p>
          </div>
          `}
          <div class="step done" data-num="${isSubActive ? 4 : 3}">
            <h3>${isSubActive ? 4 : 3}. Соединение активно</h3>
            <p>Туннель Белых Списков успешно подключен на Linux!</p>
          </div>
        `;
      }
    }

    // --- AmneziaWG Module Logic ---
    const awgPlatformsData = [
      { id: "ios", label: "iOS (iPhone)", icon: '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 0.77-3.27 0.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5 0.87 3.29 0.87 0.78 0 2.26-1.07 3.81-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M15.97 6.37c.62-.75 1.04-1.8 0.92-2.85-.9.04-1.99.6-2.64 1.36-.57.65-1.07 1.72-.94 2.74 1.01.08 2.04-.5 2.66-1.25z"/></svg>' },
      { id: "android", label: "Android", icon: '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M17.52 15.34c-.55 0-1-.45-1-1s.45-1 1-1 1 .45 1 1-.45 1-1 1m-11.04 0c-.55 0-1-.45-1-1s.45-1 1-1 1 .45 1 1-.45 1-1 1m11.4-6.02l2-3.46c.12-.2.05-.47-.15-.57-.2-.12-.47-.05-.57.15l-2.02 3.5C15.59 8.41 13.85 8.08 12 8.08s-3.59.33-5.14.87L4.84 5.45c-.1-.2-.37-.27-.57-.15-.2.1-.27.37-.15.57l2 3.46C2.69 11.19.34 14.66 0 18.76h24c-.34-4.1-2.69-7.57-6.12-9.44"/></svg>' },
      { id: "windows", label: "Windows", icon: '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M0 3.45L9.75 2.1v9.45H0m10.95-9.6L24 0v11.4H10.95M0 12.6h9.75v9.45L0 20.7M10.95 12.6H24V24l-13.05-1.8"/></svg>' },
      { id: "macos", label: "macOS", icon: '<svg viewBox="0 0 512 512" width="18" height="18" style="border-radius: 4px; overflow: hidden;"><defs><linearGradient id="finder-blue-awg" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#1e73f2"/><stop offset="100%" stop-color="#19d3fd"/></linearGradient><linearGradient id="finder-silver-awg" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#dbe9f4"/><stop offset="100%" stop-color="#f7f6f6"/></linearGradient></defs><rect width="512" height="512" fill="url(#finder-silver-awg)" rx="85"/><path fill="url(#finder-blue-awg)" d="m0 0h262q-65 162-64 286c0 7 6 13 13 13h64q-6 113 28 213H0z"/><g fill="none" stroke="#1e293b" stroke-linecap="round"><path stroke-width="24" d="m133.5 157.5v34m226.5-34v34"/><path stroke-width="20" d="m394 345c-55 81-241 81-295.5 0"/></g></svg>' },
      { id: "linux", label: "Linux", icon: '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M12.504 0c-.155 0-.315.008-.48.021-4.226.333-3.105 4.807-3.17 6.298-.076 1.092-.3 1.953-1.05 3.02-.885 1.051-2.127 2.75-2.716 4.521-.278.832-.41 1.684-.287 2.489a.424.424 0 00-.11.135c-.26.268-.45.6-.663.839-.199.199-.485.267-.797.4-.313.136-.658.269-.864.68-.09.189-.136.394-.132.602 0 .199.027.4.055.536.058.399.116.728.04.97-.249.68-.28 1.145-.106 1.484.174.334.535.47.94.601.81.2 1.91.135 2.774.6.926.466 1.866.67 2.616.47.526-.116.97-.464 1.208-.946.587-.003 1.23-.269 2.26-.334.699-.058 1.574.267 2.577.2.025.134.063.198.114.333l.003.003c.391.778 1.113 1.132 1.884 1.071.771-.06 1.592-.536 2.257-1.306.631-.765 1.683-1.084 2.378-1.503.348-.199.629-.469.649-.853.023-.4-.2-.811-.714-1.376v-.097l-.003-.003c-.17-.2-.25-.535-.338-.926-.085-.401-.182-.786-.492-1.046h-.003c-.059-.054-.123-.067-.188-.135a.357.357 0 00-.19-.064c.431-1.278.264-2.55-.173-3.694-.533-1.41-1.465-2.638-2.175-3.483-.796-1.005-1.576-1.957-1.56-3.368.026-2.152.236-6.133-3.544-6.139zm.529 3.405h.013c.213 0 .396.062.584.198.19.135.33.332.438.533.105.259.158.459.166.724 0-.02.006-.04.006-.06v.105a.086.086 0 01-.004-.021l-.004-.024a1.807 1.807 0 01-.15.706.953.953 0 01-.213.335.71.71 0 00-.088-.042c-.104-.045-.198-.064-.284-.133a1.312 1.312 0 00-.22-.066c.05-.06.146-.133.183-.198.053-.128.082-.264.088-.402v-.02a1.21 1.21 0 00-.061-.4c-.045-.134-.101-.2-.183-.333-.084-.066-.167-.132-.267-.132h-.016c-.093 0-.176.03-.262.132a.8.8 0 00-.205.334 1.18 1.18 0 00-.09.4v.019c.002.089.008.179.02.267-.193-.067-.438-.135-.607-.202a1.635 1.635 0 01-.018-.2v-.02a1.772 1.772 0 01.15-.768c.082-.22.232-.406.43-.533a.985.985 0 01.594-.2zm-2.962.059h.036c.142 0 .27.048.399.135.146.129.264.288.344.465.09.199.14.4.153.667v.004c.007.134.006.2-.002.266v.08c-.03.007-.056.018-.083.024-.152.055-.274.135-.393.2.012-.09.013-.18.003-.267v-.015c-.012-.133-.04-.2-.082-.333a.613.613 0 00-.166-.267.248.248 0 00-.183-.064h-.021c-.071.006-.13.04-.186.132a.552.552 0 00-.12.27.944.944 0 00-.023.33v.015c.012.135.037.2.08.334.046.134.098.2.166.268.01.009.02.018.034.024-.07.057-.117.07-.176.136a.304.304 0 01-.131.068 2.62 2.62 0 01-.275-.402 1.772 1.772 0 01-.155-.667 1.759 1.759 0 01.08-.668 1.43 1.43 0 01.283-.535c.128-.133.26-.2.418-.2zm1.37 1.706c.332 0 .733.065 1.216.399.293.2.523.269 1.052.468h.003c.255.136.405.266.478.399v-.131a.571.571 0 01.016.47c-.123.31-.516.643-1.063.842v.002c-.268.135-.501.333-.775.465-.276.135-.588.292-1.012.267a1.139 1.139 0 01-.448-.067 3.566 3.566 0 01-.322-.198c-.195-.135-.363-.332-.612-.465v-.005h-.005c-.4-.246-.616-.512-.686-.71-.07-.268-.005-.47.193-.6.224-.135.38-.271.483-.336.104-.074.143-.102.176-.131h.002v-.003c.169-.202.436-.47.839-.601.139-.036.294-.065.466-.065zm2.8 2.142c.358 1.417 1.196 3.475 1.735 4.473.286.534.855 1.659 1.102 3.024.156-.005.33.018.513.064.646-1.671-.546-3.467-1.089-3.966-.22-.2-.232-.335-.123-.335.59.534 1.365 1.572 1.646 2.757.13.535.16 1.104.021 1.67.067.028.135.06.205.067 1.032.534 1.413.938 1.23 1.537v-.043c-.06-.003-.12 0-.18 0h-.016c.151-.467-.182-.825-1.065-1.224-.915-.4-1.646-.336-1.77.465-.008.043-.013.066-.018.135-.068.023-.139.053-.209.064-.43.268-.662.669-.793 1.187-.13.533-.17 1.156-.205 1.869v.003c-.02.334-.17.838-.319 1.35-1.5 1.072-3.58 1.538-5.348.334a2.645 2.645 0 00-.402-.533 1.45 1.45 0 00-.275-.333c.182 0 .338-.03.465-.067a.615.615 0 00.314-.334c.108-.267 0-.697-.345-1.163-.345-.467-.931-.995-1.788-1.521-.63-.4-.986-.87-1.15-1.396-.165-.534-.143-1.085-.015-1.645.245-1.07.873-2.11 1.274-2.763.107-.065.037.135-.408.974-.396.751-1.14 2.497-.122 3.854a8.123 8.123 0 01.647-2.876c.564-1.278 1.743-3.504 1.836-5.268.048.036.217.135.289.202.218.133.38.333.59.465.21.201.477.335.876.335.039.003.075.006.11.006.412 0 .73-.134.997-.268.29-.134.52-.334.74-.4h.005c.467-.135.835-.402 1.044-.7zm2.185 8.958c.037.6.343 1.245.882 1.377.588.134 1.434-.333 1.791-.765l.211-.01c.315-.007.577.01.847.268l.003.003c.208.199.305.53.391.876.085.4.154.78.409 1.066.486.527.645.906.636 1.14l.003-.007v.018l-.003-.012c-.015.262-.185.396-.498.595-.63.401-1.746.712-2.457 1.57-.618.737-1.37 1.14-2.036 1.191-.664.053-1.237-.2-1.574-.898l-.005-.003c-.21-.4-.12-1.025.056-1.69.176-.668.428-1.344.463-1.897.037-.714.076-1.335.195-1.814.12-.465.308-.797.641-.984l.045-.022zm-10.814.049h.01c.053 0 .105.005.157.014.376.055.706.333 1.023.752l.91 1.664.003.003c.243.533.754 1.064 1.189 1.637.434.598.77 1.131.729 1.57v.006c-.057.744-.48 1.148-1.125 1.294-.645.135-1.52.002-2.395-.464-.968-.536-2.118-.469-2.857-.602-.369-.066-.61-.2-.723-.4-.11-.2-.113-.602.123-1.23v-.004l.002-.003c.117-.334.03-.752-.027-1.118-.055-.401-.083-.71.043-.94.16-.334.396-.4.69-.533.294-.135.64-.202.915-.47h.002v-.002c.256-.268.445-.601.668-.838.19-.201.38-.336.663-.336zm7.159-9.074c-.435.201-.945.535-1.488.535-.542 0-.97-.267-1.28-.466-.154-.134-.28-.268-.373-.335-.164-.134-.144-.333-.074-.333.109.016.129.134.199.2.096.066.215.2.36.333.292.2.68.467 1.167.467.485 0 1.053-.267 1.398-.466.195-.135.445-.334.648-.467.156-.136.149-.267.279-.267.128.016.034.134-.147.332a8.097 8.097 0 01-.69.468zm-1.082-1.583V5.64c-.006-.02.013-.042.029-.05.074-.043.18-.027.26.004.063 0 .16.067.15.135-.006.049-.085.066-.135.066-.055 0-.092-.043-.141-.068-.052-.018-.146-.008-.163-.065zm-.551 0c-.02.058-.113.049-.166.066-.047.025-.086.068-.14.068-.05 0-.13-.02-.136-.068-.01-.066.088-.133.15-.133.08-.031.184-.047.259-.005.019.009.036.03.03.05v.02h.003z"/></svg>' },
      { id: "androidtv", label: "Android TV", icon: '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M22 3H2c-.6 0-1 .4-1 1v13c0 .6.4 1 1 1h8v1.5H7c-.3 0-.5.2-.5.5s.2.5.5.5h10c.3 0 .5-.2.5-.5s-.2-.5-.5-.5h-3V18h8c.6 0 1-.4 1-1V4c0-.6-.4-1-1-1zm-.2 13.8H2.2V4.2h19.6v12.6z"/><g transform="translate(5.4, 4.0) scale(0.55)"><path d="M17.52 15.34c-.55 0-1-.45-1-1s.45-1 1-1 1 .45 1 1-.45 1-1 1m-11.04 0c-.55 0-1-.45-1-1s.45-1 1-1 1 .45 1 1-.45 1-1 1m11.4-6.02l2-3.46c.12-.2.05-.47-.15-.57-.2-.12-.47-.05-.57.15l-2.02 3.5C15.59 8.41 13.85 8.08 12 8.08s-3.59.33-5.14.87L4.84 5.45c-.1-.2-.37-.27-.57-.15-.2.1-.27.37-.15.57l2 3.46C2.69 11.19.34 14.66 0 18.76h24c-.34-4.1-2.69-7.57-6.12-9.44"/></g></svg>' }
    ];
    let currentAwgPlatform = (["ios", "android", "windows", "macos", "linux", "androidtv"].indexOf(detected) !== -1) ? detected : "ios";
    let currentAwgApp = "amneziavpn";

    const awgAppsData = [
      {
        id: "amneziavpn",
        name: "AmneziaVPN",
        subtitle: "Официальный клиент со всеми функциями",
        badge: "Рекомендуем",
        iconSvg: '<img src="/assets/apps/amneziavpn.webp" width="34" height="34" style="border-radius: 8px; display: block;" alt="AmneziaVPN">',
      },
      {
        id: "amneziawg",
        name: "AmneziaWG",
        subtitle: "Облегчённый быстрый WireGuard-клиент",
        badge: "Легковесный",
        iconSvg: '<img src="/assets/apps/amneziawg.webp" width="34" height="34" style="border-radius: 8px; display: block;" alt="AmneziaWG">',
      }
    ];

    function renderAwgPlatformTabs() {
      const track = document.getElementById("awg-platform-tabs");
      if (!track) return;
      track.innerHTML = "";
      awgPlatformsData.forEach((p) => {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "platform-tab" + (p.id === currentAwgPlatform ? " active" : "");
        btn.setAttribute("role", "tab");
        btn.setAttribute("aria-selected", p.id === currentAwgPlatform ? "true" : "false");
        btn.setAttribute("tabindex", p.id === currentAwgPlatform ? "0" : "-1");
        btn.innerHTML = p.icon + '<span>' + p.label + '</span>';
        btn.addEventListener("click", () => {
          selectAwgPlatform(p.id);
        });
        track.appendChild(btn);
      });
      const lbl = document.getElementById("detected-awg-platform-label");
      if (lbl) {
        const found = awgPlatformsData.find(x => x.id === currentAwgPlatform);
        lbl.textContent = found ? found.label : currentAwgPlatform;
      }
    }

    function selectAwgPlatform(id) {
      currentAwgPlatform = id;
      renderAwgPlatformTabs();
      renderAwgApps();
      renderAwgSteps();
    }

    function renderAwgApps() {
      const box = document.getElementById("awg-apps-selector");
      if (!box) return;
      box.innerHTML = "";
      // On Android TV only AmneziaVPN is available
      const appsToRender = (currentAwgPlatform === "androidtv")
        ? awgAppsData.filter(a => a.id === "amneziavpn")
        : awgAppsData;

      if (currentAwgPlatform === "androidtv" && currentAwgApp !== "amneziavpn") {
        currentAwgApp = "amneziavpn";
      }

      appsToRender.forEach((app) => {
        const card = document.createElement("button");
        card.type = "button";
        const isActive = app.id === currentAwgApp;
        card.className = "app-card" + (isActive ? " active" : "");
        card.innerHTML =
          '<div style="display: flex; align-items: center; justify-content: center; width: 34px; height: 34px; border-radius: 8px; flex-shrink: 0; overflow: hidden;">' + app.iconSvg + '</div>' +
          '<div class="app-info">' +
            '<div class="app-name-row">' +
              '<span class="app-name">' + app.name + '</span>' +
              '<span class="app-badge badge-recommended">' + app.badge + '</span>' +
            '</div>' +
            '<div style="font-size: 11.5px; color: var(--muted); line-height: 1.25; margin-top: 2px;">' + app.subtitle + '</div>' +
          '</div>' +
          '<div class="app-check">' + (isActive ? '✓' : '') + '</div>';
        card.addEventListener("click", () => {
          selectAwgApp(app.id);
        });
        box.appendChild(card);
      });
    }

    function selectAwgApp(appId) {
      currentAwgApp = appId;
      renderAwgApps();
      renderAwgSteps();
    }

    function renderAwgSteps() {
      const container = document.getElementById("awg-steps-container");
      if (!container) return;

      const isMobile = (currentAwgPlatform === "ios" || currentAwgPlatform === "android");
      const isAwgApp = (currentAwgApp === "amneziawg");

      let downloadBtnsHtml = "";
      if (currentAwgPlatform === "androidtv") {
        downloadBtnsHtml = '<a class="button secondary" href="https://play.google.com/store/apps/details?id=org.amnezia.vpn" target="_blank" rel="noopener">📺 Google Play (Android TV)</a>' +
          '<a class="button secondary" href="https://github.com/amnezia-vpn/amnezia-client/releases" target="_blank" rel="noopener">📦 Скачать APK (GitHub)</a>';
      } else if (isAwgApp) {
        if (currentAwgPlatform === "ios") {
          downloadBtnsHtml = '<a class="button secondary" href="https://apps.apple.com/app/amneziawg/id6478942365" target="_blank" rel="noopener">🍏 App Store (iOS)</a>';
        } else if (currentAwgPlatform === "android") {
          downloadBtnsHtml = '<a class="button secondary" href="https://play.google.com/store/apps/details?id=org.amnezia.awg" target="_blank" rel="noopener">🤖 Google Play (Android)</a>' +
            '<a class="button secondary" href="https://github.com/amnezia-vpn/amneziawg-android/releases" target="_blank" rel="noopener">📦 Прямой APK (для Huawei и без Google Play)</a>';
        } else if (currentAwgPlatform === "windows") {
          downloadBtnsHtml = '<a class="button secondary" href="https://github.com/amnezia-vpn/amneziawg-windows-client/releases" target="_blank" rel="noopener">💻 Скачать AmneziaWG для Windows (.msi)</a>';
        } else if (currentAwgPlatform === "macos") {
          downloadBtnsHtml = '<a class="button secondary" href="https://apps.apple.com/app/amneziawg/id6478942365" target="_blank" rel="noopener">🍏 Mac App Store</a>' +
            '<a class="button secondary" href="https://docs.amnezia.org/ru/documentation/instructions/use-amneziawg-app/" target="_blank" rel="noopener">📖 Официальная инструкция Amnezia</a>';
        } else if (currentAwgPlatform === "linux") {
          downloadBtnsHtml = '<a class="button secondary" href="https://github.com/amnezia-vpn/amneziawg-linux-kernel-module" target="_blank" rel="noopener">🐧 Модуль ядра Linux (GitHub)</a>' +
            '<a class="button secondary" href="https://github.com/amnezia-vpn/amneziawg-go" target="_blank" rel="noopener">📦 AmneziaWG Go</a>';
        }
      } else {
        if (currentAwgPlatform === "ios") {
          downloadBtnsHtml = '<a class="button secondary" href="https://apps.apple.com/app/amneziavpn/id1600529900" target="_blank" rel="noopener">🍏 App Store (iOS)</a>';
        } else if (currentAwgPlatform === "android") {
          downloadBtnsHtml = '<a class="button secondary" href="https://play.google.com/store/apps/details?id=org.amnezia.vpn" target="_blank" rel="noopener">🤖 Google Play (Android)</a>' +
            '<a class="button secondary" href="https://github.com/amnezia-vpn/amnezia-client/releases" target="_blank" rel="noopener">📦 Прямой APK (для Huawei и без Google Play)</a>';
        } else if (currentAwgPlatform === "windows") {
          downloadBtnsHtml = '<a class="button secondary" href="https://amnezia.org/ru/downloads" target="_blank" rel="noopener">💻 Скачать на официальном сайте (.exe)</a>' +
            '<a class="button secondary" href="https://github.com/amnezia-vpn/amnezia-client/releases" target="_blank" rel="noopener">📦 GitHub Релизы</a>';
        } else if (currentAwgPlatform === "macos") {
          downloadBtnsHtml = '<a class="button secondary" href="https://apps.apple.com/app/amneziavpn/id1600529900" target="_blank" rel="noopener">🍏 Mac App Store</a>' +
            '<a class="button secondary" href="https://amnezia.org/ru/downloads" target="_blank" rel="noopener">🌐 Официальный сайт (.dmg)</a>';
        } else if (currentAwgPlatform === "linux") {
          downloadBtnsHtml = '<a class="button secondary" href="https://amnezia.org/ru/downloads" target="_blank" rel="noopener">🐧 Скачать для Linux (.deb / AppImage)</a>';
        }
      }

      let step2Text = "";
      if (currentAwgPlatform === "androidtv") {
        step2Text = 'Установите приложение <strong>AmneziaVPN</strong> на телевизор из Google Play или APK.<br>' +
          '• <strong>Способ 1:</strong> Передайте скачанный файл <code>.conf</code> на TV (через флешку или приложение <em>LocalSend / Send Files to TV</em>) и в Amnezia VPN выберите <strong>«Файл с настройками»</strong>.<br>' +
          '• <strong>Способ 2:</strong> Нажмите <strong>«📋 Скопировать ключ»</strong> на смартфоне и вставьте его на TV через клавиатуру Android TV Remote в поле <strong>«Вставить ключ»</strong>.';
      } else if (isMobile) {
        if (isAwgApp) {
          step2Text = 'Выберите нужный слот в блоке выше:<br>' +
            '• <strong>На этом же смартфоне:</strong> скачайте <strong>«📥 .conf»</strong> → в приложении <strong>AmneziaWG</strong> нажмите <strong>«+»</strong> (в правом углу) → <strong>«Импорт из файла или архива»</strong> (или нажмите <strong>«📋 Скопировать ключ»</strong> → <strong>«+»</strong> → <strong>«Создать с нуля»</strong> и вставьте текст).<br>' +
            '• <strong>С экрана компьютера:</strong> нажмите <strong>«🔲 QR-код»</strong> у слота на ПК → в AmneziaWG нажмите <strong>«+»</strong> → <strong>«Сканировать QR-код»</strong> и наведите камеру.';
        } else {
          step2Text = 'Выберите нужный слот в блоке выше:<br>' +
            '• <strong>На этом же смартфоне:</strong> нажмите <strong>«📋 Скопировать ключ»</strong> → в приложении <strong>Amnezia VPN</strong> нажмите <strong>«+»</strong> (или «Приступим») → <strong>«Вставить ключ»</strong> (или скачайте <strong>.conf</strong> и выберите <strong>«Файл с настройками»</strong>).<br>' +
            '• <strong>С экрана компьютера:</strong> нажмите <strong>«🔲 QR-код»</strong> у слота на ПК → в Amnezia VPN нажмите <strong>«+»</strong> → <strong>«Сканировать QR-код»</strong> и наведите камеру.';
        }
      } else {
        if (isAwgApp) {
          if (currentAwgPlatform === "linux") {
            step2Text = 'Скачайте конфигурационный файл <strong>«📥 .conf»</strong> нужного слота в блоке выше и поместите в <code>/etc/amnezia/amneziawg/</code>.<br>' +
              'Запустите туннель: <code>awg-quick up &lt;имя_файла&gt;</code> (остановка: <code>awg-quick down &lt;имя_файла&gt;</code>).';
          } else {
            step2Text = 'Скачайте конфигурационный файл <strong>«📥 .conf»</strong> нужного слота в блоке выше.<br>' +
              'В приложении <strong>AmneziaWG</strong> нажмите <strong>«Добавить туннель»</strong> (или сочетание <code>Ctrl+O</code> / <code>Cmd+O</code>) и укажите скачанный <code>.conf</code> файл.';
          }
        } else {
          step2Text = 'Выберите удобный вариант в блоке слотов выше:<br>' +
            '• <strong>По ключу:</strong> нажмите <strong>«📋 Скопировать ключ»</strong> → в <strong>Amnezia VPN</strong> нажмите <strong>«+»</strong> (или «Приступим») → <strong>«Вставить ключ»</strong> и вставьте скопированный текст.<br>' +
            '• <strong>По файлу:</strong> нажмите <strong>«📥 .conf»</strong> → в приложении выберите <strong>«Файл с настройками»</strong> (или просто перетащите файл мышкой в окно Amnezia).';
        }
      }

      container.innerHTML = `
        <div class="step" data-num="1">
          <h3>1. Установка клиента ${isAwgApp ? 'AmneziaWG' : 'Amnezia VPN'}</h3>
          <p>Скачайте официальное бесплатное приложение с открытым исходным кодом:</p>
          <div class="buttons" style="flex-wrap: wrap; gap: 8px; margin: 10px 0;">
            ${downloadBtnsHtml}
          </div>
        </div>
        <div class="step" data-num="2">
          <h3>2. Добавление конфигурации устройства</h3>
          <p style="line-height: 1.5; font-size: 13.5px; color: #cbd5e1;">${step2Text}</p>
        </div>
        <div class="step done" data-num="3">
          <h3>3. Подключение и работа</h3>
          <p>Нажмите центральную кнопку подключения в приложении. Весь заблокированный трафик пойдёт через наш скоростной шифрованный WireGuard-канал без потери скорости.</p>
        </div>
      `;
    }

    renderPlatformTabs();
    renderApps();
    updateWlHeroCard();
    renderWlPlatformTabs();
    renderWlSteps();
    renderAwgPlatformTabs();
    renderAwgApps();
    renderAwgSteps();
    window.updateRenewPrice();
    initNoticeState();
    window.startOrderStatusPolling();

    document.addEventListener("keydown", function(e) {
      if (e.key === "Escape") {
        if (typeof closeAwgQrModal === "function") closeAwgQrModal();
        if (typeof closeAwgSwitchModal === "function") closeAwgSwitchModal();
        if (typeof closeWlQrModal === "function") closeWlQrModal();
      }
    });
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
    result = result.replace("__OPENFLUX_DATA_JSON__", openflux_data_json)
    result = result.replace("__VOLGA_NL_URL__", html.escape(volga_nl_url, quote=True))
    result = result.replace("__VOLGA_PL_URL__", html.escape(volga_pl_url, quote=True))
    result = result.replace("__VOLGA_FI_URL__", html.escape(volga_fi_url, quote=True))
    result = result.replace("__IS_SUB_ACTIVE__", "true" if is_sub_active else "false")
    awg_container_html = render_subjson_awg_container(subscription_id, support_url)
    result = result.replace("__AWG_CONTAINER_HTML__", awg_container_html)
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
    bot_username = ""
    try:
        shop_settings = get_shop_settings()
        if shop_settings:
            bot_username = (getattr(shop_settings, "telegram_bot_username", "") or "").strip().lstrip("@")
    except Exception:
        pass
    if not bot_username:
        bot_username = os.environ.get("TELEGRAM_BOT_USERNAME", "").strip().lstrip("@")
    if not bot_username:
        bot_username = "SilentConnectVPNBot"
    bot_referral_url = f"https://t.me/{bot_username}?start=referral"

    result = result.replace("__BOT_REFERRAL_URL__", html.escape(bot_referral_url, quote=True))
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
      <li>действия, которые могут привести к ограничениям доступа, жалобам, ущербу сервису или третьим лицам.</li>
    </ul>
    <p>При признаках злоупотребления администрация вправе ограничить, приостановить или прекратить доступ к сервису без компенсации, если иное прямо не согласовано отдельно.</p>

    <h2>4. Ограничение ответственности сервиса</h2>
    <p>Сервис предоставляется «как есть». Мы стремимся поддерживать стабильность и качество подключения, но не гарантируем непрерывную доступность, определённую скорость, доступность конкретных сайтов или отсутствие ограничений со стороны третьих лиц.</p>
    <p>Администрация не несёт ответственность за действия пользователя в интернете, решения третьих сайтов и сервисов, ограничения аккаунтов пользователя на сторонних площадках, изменение правил сторонних сервисов, работу интернет-провайдера пользователя, устройства или приложения-клиента.</p>

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

            # AWG Slot Rename
            # POST /sub/awg/<sub_id>/slot/<idx>/rename or /<SECRET_SEGMENT>/awg/<sub_id>/slot/<idx>/rename
            if (len(path) == 6 and path[0] in {"sub", SECRET_SEGMENT, "my-secret-sub"} and path[1] == "awg" and path[3] == "slot" and path[5] == "rename") or \
               (len(path) == 7 and path[0] == "api" and path[1] in {"sub", "awg"} and path[4] == "slot" and path[6] == "rename"):
                sub_id = path[2] if path[0] in {"sub", SECRET_SEGMENT, "my-secret-sub"} else (path[3] if path[1] == "sub" else path[2])
                slot_idx_str = path[4] if path[0] in {"sub", SECRET_SEGMENT, "my-secret-sub"} else path[5]
                wc = get_shop_checkout()
                prof = find_profile_for_sub(wc, sub_id)
                if not prof:
                    self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "profile_not_found"}, True)
                    return
                try:
                    slot_idx = int(slot_idx_str)
                except ValueError:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "invalid_slot_index"}, True)
                    return
                content_length = int(self.headers.get("Content-Length") or 0)
                raw_body = self.rfile.read(content_length) if content_length > 0 else b"{}"
                try:
                    payload = json.loads(raw_body.decode("utf-8"))
                except Exception:
                    payload = {}
                new_label = str(payload.get("slot_label") or payload.get("label") or payload.get("name") or "").strip()
                if not new_label or len(new_label) > 32:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "invalid_label"}, True)
                    return
                try:
                    wc.ensure_awg_slot(prof["public_id"], slot_idx)
                except Exception as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)}, True)
                    return
                updated = wc.store.rename_awg_slot_by_index(prof["public_id"], slot_idx, new_label)
                if not updated:
                    self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": "failed_to_rename"}, True)
                    return
                self._send_json(HTTPStatus.OK, {
                    "ok": True,
                    "slot_index": slot_idx,
                    "slot_label": updated.get("slot_label", new_label),
                }, True)
                return

            # AWG Slot Switch Country
            # POST /sub/awg/<sub_id>/slot/<idx>/switch_country or /<SECRET_SEGMENT>/awg/<sub_id>/slot/<idx>/switch_country
            if (len(path) == 6 and path[0] in {"sub", SECRET_SEGMENT, "my-secret-sub"} and path[1] == "awg" and path[3] == "slot" and path[5] == "switch_country") or \
               (len(path) == 7 and path[0] == "api" and path[1] in {"sub", "awg"} and path[4] == "slot" and path[6] == "switch_country"):
                sub_id = path[2] if path[0] in {"sub", SECRET_SEGMENT, "my-secret-sub"} else (path[3] if path[1] == "sub" else path[2])
                slot_idx_str = path[4] if path[0] in {"sub", SECRET_SEGMENT, "my-secret-sub"} else path[5]
                wc = get_shop_checkout()
                prof = find_profile_for_sub(wc, sub_id)
                if not prof:
                    self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "profile_not_found"}, True)
                    return
                try:
                    slot_idx = int(slot_idx_str)
                except ValueError:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "invalid_slot_index"}, True)
                    return
                content_length = int(self.headers.get("Content-Length") or 0)
                raw_body = self.rfile.read(content_length) if content_length > 0 else b"{}"
                try:
                    payload = json.loads(raw_body.decode("utf-8"))
                except Exception:
                    payload = {}
                target_country = str(payload.get("country") or payload.get("server_code") or "").strip()
                if not target_country:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "missing_country"}, True)
                    return

                res = wc.switch_awg_slot_country(prof["public_id"], slot_idx, target_country)
                status_code = HTTPStatus.OK if res.get("ok") else HTTPStatus.BAD_REQUEST
                self._send_json(status_code, res, True)
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

                unified_order_url = f"{HAPP_WEB_PAGE_URL}/order/{res['public_id']}/{res['web_token']}"

                if is_ajax:
                    self._send_json(HTTPStatus.OK, {
                        "ok": True,
                        "redirect_url": unified_order_url,
                        "order_public_id": res["public_id"],
                        "status": res["status"],
                    }, include_body=True)
                    return

                self.send_response(HTTPStatus.FOUND)
                self.send_header("Location", unified_order_url)
                for key, val in SECURITY_HEADERS:
                    self.send_header(key, val)
                self.end_headers()
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

            if len(path) == 3 and path[0] == SECRET_SEGMENT and path[1] == "dismiss-notice":
                order_public_id = path[2]
                payload = {}
                length = int(self.headers.get("Content-Length") or 0)
                if length > 0 and "application/json" in self.headers.get("Content-Type", "").lower():
                    try:
                        raw_bytes = self.rfile.read(min(length, 65_536))
                        payload = json.loads(raw_bytes.decode("utf-8")) if raw_bytes else {}
                    except Exception:
                        payload = {}
                elif length > 0:
                    form = self._read_form()
                    payload = dict(form)

                status_val = str(payload.get("status") or "").strip()
                db_path = find_store_db_path()
                if Path(db_path).exists():
                    try:
                        conn = sqlite3.connect(db_path, timeout=30.0)
                        conn.execute("PRAGMA busy_timeout = 30000;")
                        conn.row_factory = sqlite3.Row
                        try:
                            order_row = conn.execute("SELECT * FROM orders WHERE public_id = ?", (order_public_id,)).fetchone()
                            if order_row:
                                meta = json.loads(order_row["meta_json"] or "{}") if isinstance(order_row["meta_json"], str) else (order_row["meta_json"] or {})
                                meta = dict(meta)
                                dismissed_status = status_val or str(order_row["status"] or "dismissed")
                                meta["notice_dismissed_status"] = dismissed_status
                                meta["notice_dismissed_at"] = int(time.time())
                                conn.execute("UPDATE orders SET meta_json = ? WHERE public_id = ?", (json.dumps(meta), order_public_id))
                                conn.commit()
                                self._send_json(HTTPStatus.OK, {"ok": True, "dismissed_status": dismissed_status}, True)
                                return
                        finally:
                            conn.close()
                    except Exception as e:
                        LOGGER.warning("Failed to record notice dismissal for order %s: %s", order_public_id, e)

                self._send_json(HTTPStatus.OK, {"ok": True}, True)
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

    def _serve_static_asset(self, path: list[str], include_body: bool = True) -> bool:
        if not path or path[0] != "assets":
            return False
        rel_parts = path[1:]
        if any(p in ("..", ".", "") for p in rel_parts):
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "invalid_path"}, include_body)
            return True
        base_assets = (Path(__file__).parent / "assets").resolve()
        asset_file = base_assets.joinpath(*rel_parts).resolve()
        try:
            asset_file.relative_to(base_assets)
        except ValueError:
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"}, include_body)
            return True
        if not asset_file.is_file():
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "asset_not_found"}, include_body)
            return True
        ext = asset_file.suffix.lower()
        content_types = {
            ".webp": "image/webp",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".svg": "image/svg+xml",
            ".ico": "image/x-icon",
        }
        content_type = content_types.get(ext, "application/octet-stream")
        data = asset_file.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "public, max-age=604800, immutable")
        self.end_headers()
        if include_body:
            self.wfile.write(data)
        return True

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

            if not path or path == ["healthz"]:
                self._send_json(HTTPStatus.OK, {"ok": True, "service": "subjson-service"}, include_body)
                return

            if len(path) == 3 and path[0] == "volga":
                server_target = path[1].lower()
                sub_token = path[2].strip()
                volga_docs = {
                    "nl": os.environ.get("VOLGA_DOC_NL", "https://disk.yandex.ru/i/_-g0vNUuu69ffw"),
                    "pl": os.environ.get("VOLGA_DOC_PL", "https://disk.yandex.ru/i/hb1xodFfECGL8w"),
                    "fi": os.environ.get("VOLGA_DOC_FI", "https://yadi.sk/d/I0ULWUKv_9YzpA"),
                }
                if server_target not in volga_docs:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown_server", "allowed": ["nl", "pl", "fi"]}, include_body)
                    return

                summary = subscription_summary(sub_token)
                is_active = (summary.get("found") is True) and (summary.get("status_kind") == "active")
                if not is_active:
                    self._send_json(HTTPStatus.FORBIDDEN, {
                        "error": "subscription_inactive_or_not_found",
                        "status": summary.get("status", "inactive")
                    }, include_body)
                    return

                self._redirect(volga_docs[server_target], include_body)
                return

            if len(path) == 3 and path[0] == SECRET_SEGMENT and path[1] == "internal-quiesce":
                self._handle_internal_quiesce(path[2], include_body)
                return

            if is_quiesced() and (self.command == "POST" or "bot" in self.path):
                self._send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "quiesce_merge_in_progress", "retry_after": 10}, include_body)
                return

            # OpenFlux Node QR Code
            # GET /sub/openflux/<sub_id>/<country>/qr or /<SECRET_SEGMENT>/openflux/<sub_id>/<country>/qr or /api/sub/openflux/...
            if (len(path) == 5 and path[0] in {"sub", SECRET_SEGMENT, "my-secret-sub"} and path[1] == "openflux" and path[4] in {"qr", "qrcode"}) or \
               (len(path) == 6 and path[0] == "api" and path[1] in {"sub", "openflux"} and path[5] in {"qr", "qrcode"}):
                sub_id = path[2] if path[0] in {"sub", SECRET_SEGMENT, "my-secret-sub"} else (path[3] if path[1] == "sub" else path[2])
                country = path[3] if path[0] in {"sub", SECRET_SEGMENT, "my-secret-sub"} else (path[4] if path[1] == "sub" else path[3])
                country = (country or "nl").lower().strip()
                if country not in {"nl", "pl", "fi"}:
                    country = "nl"
                link, _, _ = build_openflux_v1_link(country, sub_id)
                qr_bytes = b""
                try:
                    from vpn_shop import qr
                    qr_bytes = qr.generate_qr_png(link, box_size=6, border=2)
                except Exception as exc:
                    LOGGER.warning("OpenFlux QR generation failed: %s", exc)
                if not qr_bytes:
                    self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": "qr_generation_failed"}, include_body)
                    return
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "image/png")
                self.send_header("Content-Length", str(len(qr_bytes)))
                self.send_header("Cache-Control", "public, max-age=300")
                self.end_headers()
                if include_body:
                    self.wfile.write(qr_bytes)
                return

            if path and path[0] == "assets":
                if self._serve_static_asset(path, include_body):
                    return

            if path == ["favicon.ico"]:
                if self._serve_static_asset(["assets", "branding", "avatar.webp"], include_body):
                    return
                self._redirect(f"{HAPP_WEB_PAGE_URL}/assets/telegram/avatar.webp", include_body)
                return

            if path == ["legal", "terms"] or path == [SECRET_SEGMENT, "legal", "terms"]:
                self._send_html(HTTPStatus.OK, legal_terms_html(), include_body)
                return

            if len(path) >= 2 and path[-2] == "legal" and path[-1] in ("privacy", "refund"):
                self._redirect(f"{HAPP_WEB_PAGE_URL}/legal/{path[-1]}", include_body)
                return

            if len(path) == 3 and path[0] in {SECRET_SEGMENT, "my-secret-sub"}:
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
                accept_header = self.headers.get("Accept", "").lower()

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

            # AWG Slot Config Download
            # GET /sub/awg/<sub_id>/slot/<slot_index>/config or /<SECRET_SEGMENT>/awg/... or /api/sub/awg/...
            if (len(path) == 6 and path[0] in {"sub", SECRET_SEGMENT, "my-secret-sub"} and path[1] == "awg" and path[3] == "slot" and path[5] in {"config", "conf"}) or \
               (len(path) == 7 and path[0] == "api" and path[1] in {"sub", "awg"} and path[4] == "slot" and path[6] in {"config", "conf"}):
                sub_id = path[2] if path[0] in {"sub", SECRET_SEGMENT, "my-secret-sub"} else (path[3] if path[1] == "sub" else path[2])
                slot_idx_str = path[4] if path[0] in {"sub", SECRET_SEGMENT, "my-secret-sub"} else path[5]
                wc = get_shop_checkout()
                prof = find_profile_for_sub(wc, sub_id)
                if not prof:
                    self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "profile_not_found"}, include_body)
                    return
                try:
                    slot_idx = int(slot_idx_str)
                except ValueError:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "invalid_slot_index"}, include_body)
                    return
                try:
                    slot = wc.ensure_awg_slot(prof["public_id"], slot_idx)
                except Exception as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)}, include_body)
                    return

                from vpn_shop.web import build_slot_conf
                conf_text = build_slot_conf(slot, server_code=slot.get("server_code", "nl"))
                conf_bytes = conf_text.encode("utf-8")
                slot_label = str(slot.get("slot_label") or f"device_{slot_idx}")
                safe_label = re.sub(r"[^\w\-]", "_", slot_label, flags=re.ASCII).strip("_") or f"device_{slot_idx}"
                srv_code = (slot.get("server_code") or "nl").upper()
                filename = f"SilentConnect_{safe_label}_{srv_code}.conf"
                ascii_filename = re.sub(r"[^\w\-.]", "_", filename, flags=re.ASCII)
                encoded_filename = urllib.parse.quote(filename)

                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/x-wireguard-profile; charset=utf-8")
                self.send_header("Content-Disposition", f'attachment; filename="{ascii_filename}"; filename*=UTF-8\'\'{encoded_filename}')
                self.send_header("Content-Length", str(len(conf_bytes)))
                self.send_header("Access-Control-Allow-Origin", "*")
                for k, v in SECURITY_HEADERS:
                    self.send_header(k, v)
                self.end_headers()
                if include_body:
                    self.wfile.write(conf_bytes)
                return

            # AWG Slot QR Code
            # GET /sub/awg/<sub_id>/slot/<slot_index>/qr or /<SECRET_SEGMENT>/awg/... or /api/sub/awg/...
            if (len(path) == 6 and path[0] in {"sub", SECRET_SEGMENT, "my-secret-sub"} and path[1] == "awg" and path[3] == "slot" and path[5] in {"qr", "qrcode"}) or \
               (len(path) == 7 and path[0] == "api" and path[1] in {"sub", "awg"} and path[4] == "slot" and path[6] in {"qr", "qrcode"}):
                sub_id = path[2] if path[0] in {"sub", SECRET_SEGMENT, "my-secret-sub"} else (path[3] if path[1] == "sub" else path[2])
                slot_idx_str = path[4] if path[0] in {"sub", SECRET_SEGMENT, "my-secret-sub"} else path[5]
                wc = get_shop_checkout()
                prof = find_profile_for_sub(wc, sub_id)
                if not prof:
                    self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "profile_not_found"}, include_body)
                    return
                try:
                    slot_idx = int(slot_idx_str)
                except ValueError:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "invalid_slot_index"}, include_body)
                    return
                try:
                    slot = wc.ensure_awg_slot(prof["public_id"], slot_idx)
                except Exception as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)}, include_body)
                    return

                from vpn_shop.web import build_slot_conf
                conf_text = build_slot_conf(slot, server_code=slot.get("server_code", "nl"), for_qr=True)
                qr_bytes = b""
                try:
                    from vpn_shop import qr
                    qr_bytes = qr.generate_qr_png(conf_text, box_size=6, border=2)
                except Exception as exc:
                    LOGGER.warning("QR generation failed: %s", exc)

                if not qr_bytes:
                    self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": "qr_generation_failed"}, include_body)
                    return

                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "image/png")
                self.send_header("Content-Length", str(len(qr_bytes)))
                self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                self.send_header("Access-Control-Allow-Origin", "*")
                for k, v in SECURITY_HEADERS:
                    self.send_header(k, v)
                self.end_headers()
                if include_body:
                    self.wfile.write(qr_bytes)
                return

            # AWG Slot Raw Config Text (for copying key)
            # GET /sub/awg/<sub_id>/slot/<slot_index>/config_text or /<SECRET_SEGMENT>/awg/... or /api/sub/awg/...
            if (len(path) == 6 and path[0] in {"sub", SECRET_SEGMENT, "my-secret-sub"} and path[1] == "awg" and path[3] == "slot" and path[5] in {"config_text", "conf_text", "key", "text"}) or \
               (len(path) == 7 and path[0] == "api" and path[1] in {"sub", "awg"} and path[4] == "slot" and path[6] in {"config_text", "conf_text", "key", "text"}):
                sub_id = path[2] if path[0] in {"sub", SECRET_SEGMENT, "my-secret-sub"} else (path[3] if path[1] == "sub" else path[2])
                slot_idx_str = path[4] if path[0] in {"sub", SECRET_SEGMENT, "my-secret-sub"} else path[5]
                wc = get_shop_checkout()
                prof = find_profile_for_sub(wc, sub_id)
                if not prof:
                    self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "profile_not_found"}, include_body)
                    return
                try:
                    slot_idx = int(slot_idx_str)
                except ValueError:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "invalid_slot_index"}, include_body)
                    return
                try:
                    conf_text = wc.get_awg_slot_conf_text(prof["public_id"], slot_idx)
                except Exception as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)}, include_body)
                    return

                text_bytes = conf_text.encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(text_bytes)))
                self.send_header("Access-Control-Allow-Origin", "*")
                for k, v in SECURITY_HEADERS:
                    self.send_header(k, v)
                self.end_headers()
                if include_body:
                    self.wfile.write(text_bytes)
                return

            # AWG Cluster TCP Pings
            # GET /sub/awg/ping_servers or /api/sub/awg/ping_servers or /<SECRET_SEGMENT>/awg/ping_servers
            if (len(path) == 3 and path[0] in {"sub", SECRET_SEGMENT, "my-secret-sub"} and path[1] == "awg" and path[2] in {"ping_servers", "ping"}) or \
               (len(path) == 4 and path[0] == "api" and path[1] in {"sub", "awg"} and path[3] in {"ping_servers", "ping"}):
                wc = get_shop_checkout()
                pings = wc.get_cluster_tcp_pings() if wc else {"nl": 5, "pl": 41, "fi": 41}
                self._send_json(HTTPStatus.OK, {"ok": True, "pings": pings}, include_body)
                return

            if len(path) == 3 and path[0] in {SECRET_SEGMENT, "my-secret-sub"} and path[1] in {"import", "setup"}:
                sub_id = path[2]
                raw_source = first_non_empty(query.get("url")) or public_subscription_url(self.headers, "json", sub_id)
                parsed_source = urllib.parse.urlsplit(raw_source)
                source_url = urllib.parse.urlunsplit((parsed_source.scheme, parsed_source.netloc, parsed_source.path, "", "")) if parsed_source.scheme else raw_source
                quoted_sub_id = urllib.parse.quote(sub_id, safe="")
                import_query = ""
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
                    b64_sub_url = public_subscription_url(self.headers, "streisand", sub_id)
                    import_url = build_streisand_import_url(b64_sub_url)
                    page = import_page_html(
                        title="Streisand (iPhone / iPad)",
                        body=(
                            "Пробуем открыть Streisand на iPhone / iPad автоматически и передать подписку. "
                            "Если приложение не открылось само, нажмите кнопку ниже. "
                            "Если импорт не сработал, скопируйте ссылку и добавьте её в Streisand через импорт из буфера."
                        ),
                        subscription_url=b64_sub_url,
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
                    self._redirect(f"/{SECRET_SEGMENT}/setup/{urllib.parse.quote(sub_id)}", include_body)
                    return

                if target in {"clash", "meta"}:
                    clash_sub_url = public_subscription_url(self.headers, "clash", sub_id)
                    import_url = f"clash://install-config?url={urllib.parse.quote(clash_sub_url, safe='')}"
                    ua = self.headers.get("user-agent", "")
                    is_ios = bool(re.search(r"iPhone|iPad|iPod", ua, re.I))
                    app_title = "Clash Mi" if is_ios else "Clash Mi / Mihomo"
                    primary_lbl = "Открыть в Clash Mi" if is_ios else "Открыть в Clash Meta / Mi"
                    page = import_page_html(
                        title=app_title,
                        body=(
                            f"Пробуем импортировать конфигурацию в {app_title} автоматически. "
                            "Если приложение не открылось само, нажмите кнопку ниже или скопируйте ссылку подписки."
                        ),
                        subscription_url=clash_sub_url,
                        primary_label=primary_lbl,
                        primary_url=import_url,
                        auto_url=import_url,
                        install_urls={
                            "ios": CLASH_MI_IOS_URL,
                            "android": "https://github.com/MetaCubeX/ClashMetaForAndroid/releases",
                            "windows": CLASH_DOWNLOAD_URL,
                            "macos": CLASH_DOWNLOAD_URL,
                            "linux": CLASH_DOWNLOAD_URL,
                            "fallback": CLASH_DOWNLOAD_URL,
                        },
                    )
                    self._send_html(HTTPStatus.OK, page, include_body)
                    return

                if target == "singbox":
                    singbox_sub_url = public_subscription_url(self.headers, "singbox", sub_id)
                    import_url = f"sing-box://import-remote-profile?url={urllib.parse.quote(singbox_sub_url, safe='')}#SilentConnect"
                    ua = self.headers.get("user-agent", "")
                    is_ios = bool(re.search(r"iPhone|iPad|iPod", ua, re.I))
                    app_title = "sing-box MT" if is_ios else "Sing-box"
                    primary_lbl = f"Открыть в {app_title}"
                    page = import_page_html(
                        title=app_title,
                        body=(
                            f"Пробуем открыть {app_title} автоматически и передать конфигурацию. "
                            "Если приложение не открылось само, нажмите кнопку ниже или скопируйте ссылку подписки."
                        ),
                        subscription_url=singbox_sub_url,
                        primary_label=primary_lbl,
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
