#!/usr/bin/env python3
import copy
import html
import ipaddress
import json
import logging
import os
import socket
import sqlite3
import time
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


LOGGER = logging.getLogger("subjson-service")


def get_env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if value is None or value == "":
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


LISTEN_HOST = get_env("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(get_env("LISTEN_PORT", "3088"))
SECRET_SEGMENT = get_env("SECRET_SEGMENT", "my-secret-sub").strip("/")  # PLACEHOLDER
PUBLIC_HOST = os.environ.get("PUBLIC_HOST", "").strip()
PUBLIC_SUBSCRIPTION_ORIGIN = os.environ.get("PUBLIC_SUBSCRIPTION_ORIGIN", "").strip().rstrip("/")
XUI_DB_PATH = get_env("XUI_DB_PATH", "/etc/x-ui/x-ui.db")
RELAY_PUBLIC_HOST = os.environ.get("RELAY_PUBLIC_HOST", "").strip()
RELAY_TCP_PORT = int(os.environ.get("RELAY_TCP_PORT", "443"))
RELAY_XHTTP_PORT = int(os.environ.get("RELAY_XHTTP_PORT", "8443"))
HAPP_PROVIDER_ID = os.environ.get("HAPP_PROVIDER_ID", "").strip()
HAPP_PROFILE_TITLE = os.environ.get("HAPP_PROFILE_TITLE", "SilentConnect").strip()[:25]
HAPP_SUPPORT_URL = os.environ.get("HAPP_SUPPORT_URL", "https://t.me/your_vpn_bot").strip()
HAPP_WEB_PAGE_URL = os.environ.get("HAPP_WEB_PAGE_URL", "https://example.com").strip()
HAPP_RENEW_URL = os.environ.get("HAPP_RENEW_URL", "https://t.me/your_vpn_bot?start=open").strip()
HAPP_PROFILE_UPDATE_INTERVAL = os.environ.get("HAPP_PROFILE_UPDATE_INTERVAL", "1").strip()
HAPP_SERVER_DESCRIPTION = os.environ.get("HAPP_SERVER_DESCRIPTION", "Основной сервер").strip()[:30]
HAPP_SUB_INFO_ENABLED = os.environ.get("HAPP_SUB_INFO_ENABLED", "1").strip().lower() not in {"0", "false", "no", "off"}
HAPP_UNLIMITED_AFTER_DAYS = int(os.environ.get("HAPP_UNLIMITED_AFTER_DAYS", "3650"))
HAPP_RESOLVE_DNS_DOMAIN = os.environ.get("HAPP_RESOLVE_DNS_DOMAIN", "https://dns.google/dns-query").strip()
HAPP_RESOLVE_DNS_IP = os.environ.get("HAPP_RESOLVE_DNS_IP", "8.8.8.8").strip()
HAPP_EXTRA_EXCLUDE_ROUTES = os.environ.get("HAPP_EXTRA_EXCLUDE_ROUTES", "").strip()
HAPP_HEADERS_ENABLED = os.environ.get("HAPP_HEADERS_ENABLED", "1").strip().lower() not in {"0", "false", "no", "off"}
EXTRA_OUTBOUNDS_PATH = os.environ.get("EXTRA_OUTBOUNDS_PATH", "").strip()
MULTI_CONFIGS_PATH = os.environ.get("MULTI_CONFIGS_PATH", "").strip()
STATIC_JSON_CONFIG_DIR = os.environ.get("STATIC_JSON_CONFIG_DIR", "").strip()
WS443_PUBLIC_HOST = os.environ.get("WS443_PUBLIC_HOST", "sub.example.com").strip()
WS443_PUBLIC_PORT = int(os.environ.get("WS443_PUBLIC_PORT", "443"))
WS443_PATH = os.environ.get("WS443_PATH", "/sc-ws-9c3d7f1e").strip() or "/sc-ws-9c3d7f1e"

HAPP_DOWNLOAD_URL = "https://www.happ.su/main"
HAPP_IOS_URL = "https://apps.apple.com/us/app/happ-proxy-utility/id6504287215"
HAPP_ANDROID_URL = "https://play.google.com/store/apps/details?id=com.happproxy"
HAPP_ANDROID_APK_URL = "https://github.com/Happ-proxy/happ-android/releases/latest/download/Happ.apk"
STREISAND_IOS_URL = "https://apps.apple.com/us/app/streisand/id6450534064"
V2RAYTUN_IOS_URL = "https://apps.apple.com/us/app/v2raytun/id6476628951"
V2RAYTUN_ANDROID_URL = "https://play.google.com/store/apps/details?id=com.v2raytun.android"

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


def read_inbounds() -> list[sqlite3.Row]:
    db_uri = Path(XUI_DB_PATH).as_posix()
    conn = sqlite3.connect(f"file:{db_uri}?mode=ro", uri=True)
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
    if RELAY_PUBLIC_HOST:
        return RELAY_PUBLIC_HOST
    raise RuntimeError("RELAY_PUBLIC_HOST is not configured")


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


def parse_json_blob(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}

    parsed = json.loads(raw)
    if parsed is None:
        return {}
    if not isinstance(parsed, dict):
        raise ValueError("Expected JSON object in x-ui.db")
    return parsed


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


def find_subscription(subscription_id: str) -> tuple[sqlite3.Row, dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    for row in read_inbounds():
        settings = parse_json_blob(row["settings"])
        stream_settings = parse_json_blob(row["stream_settings"])
        sniffing = parse_json_blob(row["sniffing"])
        for client in settings.get("clients") or []:
            if client.get("subId") == subscription_id:
                return row, settings, stream_settings, sniffing, client
    raise KeyError(subscription_id)


def parse_hybrid_subscription_id(subscription_id: str) -> tuple[str, str]:
    parts = [part.strip() for part in subscription_id.split("~", 1)]
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError("hybrid subscription id must be tcp_subid~xhttp_subid")
    return parts[0], parts[1]


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

    server_name = inner.get("serverName") or first_non_empty(source.get("serverNames"))
    public_key = inner.get("publicKey") or source.get("publicKey") or source.get("password")
    short_id = inner.get("shortId") or first_non_empty(source.get("shortIds"))
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
]


HEAVY_DOWNLOAD_DIRECT_DOMAINS = [
    "domain:steamcontent.com",
    "domain:steamserver.net",
    "domain:client-download.steampowered.com",
    "domain:steamcdn-a.akamaihd.net",
]


APP_DOWNLOAD_DIRECT_DOMAINS = [
    "domain:dl.google.com",
    "domain:gvt1.com",
    "domain:gvt2.com",
    "domain:appldnld.apple.com",
    "domain:swcdn.apple.com",
    "domain:updates-http.cdn-apple.com",
    "domain:iosapps.itunes.apple.com",
    "domain:osxapps.itunes.apple.com",
    "domain:dbankcdn.com",
]


RU_DIRECT_DOMAINS = [
    "geosite:category-ru",
    "geosite:category-gov-ru",
    "domain:ru",
    "domain:su",
    "domain:xn--p1ai",
    "domain:yandex.com",
    "domain:yandex.net",
    "domain:yastatic.net",
    "domain:vk.com",
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
    "domain:boosty.to",
]


def build_routing(route_mode: str) -> dict[str, Any]:
    rules: list[dict[str, Any]] = [
        {
            "type": "field",
            "protocol": ["bittorrent"],
            "outboundTag": "block",
        },
        {
            "type": "field",
            "ip": ["geoip:private"],
            "outboundTag": "direct",
        },
    ]

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
                },
                {
                    "type": "field",
                    "ip": ["geoip:ru"],
                    "outboundTag": "direct",
                },
            ]
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
            "selector": ["proxy-"],
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
    row, settings, stream_settings, sniffing, client = find_subscription(subscription_id)
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


DNS_PRESETS: dict[str, list[str]] = {
    "default": [
        "https://1.1.1.1/dns-query",
        "https://1.0.0.1/dns-query",
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
    row, settings, stream_settings, sniffing, client = find_subscription(subscription_id)
    public_port = relay_public_port(stream_settings, int(row["port"])) if relay else int(row["port"])
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
            build_local_inbound("http", 10809, "http-in", sniffing),
        ],
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
            },
        ],
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
    row, _settings, _stream_settings, sniffing, client = find_subscription(subscription_id)
    if row["protocol"] != "vless" or not client.get("id"):
        raise ValueError("WS 443 fallback supports only VLESS clients with UUID id")

    target_host = ws_host or WS443_PUBLIC_HOST
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
                    "address": target_host,
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
                "allowInsecure": False,
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
            build_local_inbound("http", 10809, "http-in", sniffing),
        ],
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
            },
        ],
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
            build_local_inbound("http", 10809, "http-in", sniffing),
        ],
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
            },
        ],
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


def build_four_profiles(
    subscription_id: str,
    public_host: str,
    route_mode: str,
    dns_preset: str = "default",
) -> list[dict[str, Any]]:
    row, _, _, _, client = find_subscription(subscription_id)
    email = client.get("email") or subscription_id

    # Check for expiration
    summary = subscription_summary(subscription_id)
    if summary.get("status_kind") != "active":
        return build_expired_dummy_profile(email)

    # 1. Auto (f) - Wi-Fi first, fallback to TCP (Firefox fingerprint)
    auto_f = build_dual_auto_wifi_first_test_client_config(subscription_id, public_host, route_mode, dns_preset)
    auto_f["remarks"] = f"{email} Auto (f)"
    if isinstance(auto_f.get("meta"), dict):
        auto_f["meta"]["serverDescription"] = "Auto: Wi-Fi + 4G (F)"

    # 2. Auto (e) - Wi-Fi first, fallback to TCP (Edge fingerprint)
    auto_e = build_dual_auto_wifi_first_test_client_config(subscription_id, public_host, route_mode, dns_preset)
    auto_e["remarks"] = f"{email} Auto (e)"
    try:
        for outbound in auto_e["outbounds"]:
            if outbound.get("tag") == "proxy-tcp":
                outbound["streamSettings"]["realitySettings"]["fingerprint"] = "edge"
    except (KeyError, IndexError):
        pass
    if isinstance(auto_e.get("meta"), dict):
        auto_e["meta"]["serverDescription"] = "Auto: Wi-Fi + 4G (E)"

    # 3. 4G - Reality TCP (Firefox fingerprint)
    tcp_cfg = build_portable_client_config(subscription_id, public_host, route_mode, dns_preset)
    tcp_cfg["remarks"] = f"{email} 4G"
    if isinstance(tcp_cfg.get("meta"), dict):
        tcp_cfg["meta"]["serverDescription"] = "4G: Reality (F)"

    # 4. Wi-Fi - WebSocket
    wifi_cfg = build_ws443_client_config(subscription_id, route_mode, dns_preset)
    wifi_cfg["remarks"] = f"{email} Wi-Fi"
    if isinstance(wifi_cfg.get("meta"), dict):
        wifi_cfg["meta"]["serverDescription"] = "Wi-Fi: WebSocket"

    return [auto_f, auto_e, tcp_cfg, wifi_cfg]


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


def build_three_frankfurt_profiles(
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

    # 1. Build Frankfurt 4G (Reality TCP)
    tcp_cfg = load_static_json_config("json-frankfurt-tcp")
    if tcp_cfg:
        tcp_cfg["remarks"] = f"{email} Frankfurt 4G"
        try:
            tcp_cfg["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"] = client_uuid
            tcp_cfg["outbounds"][0]["settings"]["vnext"][0]["users"][0]["email"] = email
        except (KeyError, IndexError):
            pass
        if isinstance(tcp_cfg.get("meta"), dict):
            tcp_cfg["meta"]["serverDescription"] = "4G: Reality TCP (Frankfurt)"
            tcp_cfg["meta"]["sub-info-text"] = "Frankfurt 4G. Чистый Reality TCP для мобильного интернета."

    # 2. Build Frankfurt Wi-Fi (WebSocket over TLS on port 443)
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

    # 3. Build Frankfurt Auto (Balances TCP and WebSocket)
    auto_cfg = None
    if tcp_cfg and wifi_cfg:
        auto_cfg = copy.deepcopy(tcp_cfg)
        auto_cfg["remarks"] = f"{email} Frankfurt Auto"
        
        tcp_outbound = copy.deepcopy(tcp_cfg["outbounds"][0])
        tcp_outbound["tag"] = "proxy-tcp"
        
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
            auto_cfg["meta"]["serverDescription"] = "Auto: Wi-Fi + 4G (Frankfurt)"
            auto_cfg["meta"]["sub-info-text"] = "Frankfurt Auto. Автовыбор между TCP и WebSocket."

    return [cfg for cfg in [auto_cfg, tcp_cfg, wifi_cfg] if cfg is not None]



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
            build_local_inbound("http", 10809, "http-in", tcp_sniffing),
        ],
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
            },
        ],
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
    primary_label: str,
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
  <title>{escaped_title}</title>
  <style>
    body {{ margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #101418; color: #eef2f3; }}
    main {{ max-width: 720px; margin: 0 auto; padding: 32px 18px; }}
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
        conn = sqlite3.connect(f"file:{db_uri}?mode=ro", uri=True)
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


def legacy_setup_page_html(*, subscription_url: str, subscription_id: str, quoted_sub_id: str, import_query: str) -> bytes:
    links = {
        "happ": f"/{SECRET_SEGMENT}/import/happ/{quoted_sub_id}?{import_query}",
        "streisand": f"/{SECRET_SEGMENT}/import/streisand/{quoted_sub_id}?{import_query}",
        "v2raytun": f"/{SECRET_SEGMENT}/import/v2raytun/{quoted_sub_id}?{import_query}",
    }
    direct_links = {
        "happ": encrypt_happ_link(subscription_url) or links["happ"],
        "streisand": build_streisand_import_url(subscription_url),
        "v2raytun": build_v2raytun_import_url(subscription_url),
    }
    platforms = [
        ("ios", "iOS"),
        ("android", "Android"),
        ("windows", "Windows"),
        ("macos", "macOS"),
        ("linux", "Linux"),
        ("androidtv", "Android TV"),
        ("appletv", "Apple TV"),
    ]
    apps = [
        {
            "id": "happ",
            "name": "Happ",
            "badge": "рекомендуем",
            "platforms": ["ios", "android", "windows", "macos", "linux", "androidtv", "appletv"],
            "importUrl": links["happ"],
            "description": "Самый универсальный вариант для нашей подписки.",
            "downloads": {
                "ios": [{"label": "App Store", "url": HAPP_IOS_URL}],
                "android": [
                    {"label": "Google Play", "url": HAPP_ANDROID_URL},
                    {"label": "APK для Huawei / без Google Play", "url": HAPP_ANDROID_APK_URL},
                ],
                "windows": [{"label": "Страница загрузки Happ", "url": HAPP_DOWNLOAD_URL}],
                "macos": [{"label": "Страница загрузки Happ", "url": HAPP_DOWNLOAD_URL}],
                "linux": [{"label": "Страница загрузки Happ", "url": HAPP_DOWNLOAD_URL}],
                "androidtv": [
                    {"label": "Google Play", "url": HAPP_ANDROID_URL},
                    {"label": "APK", "url": HAPP_ANDROID_APK_URL},
                ],
                "appletv": [{"label": "App Store", "url": HAPP_IOS_URL}],
            },
        },
        {
            "id": "streisand",
            "name": "Streisand",
            "badge": "iPhone / iPad",
            "platforms": ["ios"],
            "importUrl": links["streisand"],
            "description": "Запасной вариант для iOS, если Вы уже пользуетесь Streisand.",
            "downloads": {"ios": [{"label": "App Store", "url": STREISAND_IOS_URL}]},
        },
        {
            "id": "v2raytun",
            "name": "V2RayTun",
            "badge": "запасной",
            "platforms": ["ios", "android"],
            "importUrl": links["v2raytun"],
            "description": "Дополнительный клиент для iOS и Android.",
            "downloads": {
                "ios": [{"label": "App Store", "url": V2RAYTUN_IOS_URL}],
                "android": [{"label": "Google Play", "url": V2RAYTUN_ANDROID_URL}],
            },
        },
    ]
    escaped_subscription = html.escape(subscription_url)
    return f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex,nofollow,noarchive">
  <title>Подключение SilentConnect</title>
  <style>
    :root {{ color-scheme: dark; --bg:#0f151b; --card:#171e27; --muted:#98a4b1; --line:#2a3542; --cyan:#36d1e8; --green:#28b26f; }}
    * {{ box-sizing: border-box; }}
    body {{ margin:0; min-height:100vh; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; color:#eef5f8; background:
      linear-gradient(rgba(255,255,255,.035) 1px, transparent 1px),
      linear-gradient(90deg, rgba(255,255,255,.035) 1px, transparent 1px),
      radial-gradient(circle at 70% 15%, rgba(54,209,232,.12), transparent 28%), var(--bg);
      background-size: 64px 64px, 64px 64px, auto; }}
    main {{ width:min(760px, calc(100% - 28px)); margin:0 auto; padding:28px 0 44px; }}
    .top, .card {{ background:rgba(23,30,39,.92); border:1px solid var(--line); border-radius:18px; box-shadow:0 16px 40px rgba(0,0,0,.22); }}
    .top {{ padding:18px 20px; display:flex; align-items:center; justify-content:space-between; gap:14px; margin-bottom:20px; }}
    .brand {{ font-size:22px; font-weight:800; }}
    .quick {{ display:flex; gap:10px; }}
    .iconbtn {{ width:44px; height:44px; border-radius:10px; border:1px solid var(--line); background:#121922; color:#eaf7fb; text-decoration:none; display:grid; place-items:center; font-size:20px; }}
    .status {{ padding:22px; margin-bottom:22px; }}
    .ok {{ width:44px; height:44px; border-radius:50%; display:grid; place-items:center; background:rgba(40,178,111,.16); border:1px solid rgba(40,178,111,.55); color:#70f0ae; font-weight:900; }}
    h1 {{ margin:0 0 4px; font-size:24px; }}
    p {{ color:var(--muted); line-height:1.48; margin:8px 0 0; }}
    .install {{ padding:24px; }}
    .install-head {{ display:flex; justify-content:space-between; align-items:center; gap:14px; margin-bottom:16px; }}
    h2 {{ margin:0; font-size:24px; }}
    select {{ min-height:42px; border-radius:10px; border:1px solid var(--line); background:#111821; color:#eef5f8; padding:0 12px; font-size:16px; }}
    .apps {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(155px,1fr)); gap:10px; margin-bottom:22px; }}
    .app {{ min-height:58px; border-radius:12px; border:1px solid var(--line); color:#eef5f8; background:#202734; font-weight:800; text-align:left; padding:12px 14px; cursor:pointer; position:relative; overflow:hidden; }}
    .app.active {{ border-color:var(--cyan); box-shadow:0 0 0 1px rgba(54,209,232,.35) inset, 0 0 22px rgba(54,209,232,.16); color:#76eeff; }}
    .app .badge {{ display:block; color:#ffd52e; font-size:12px; font-weight:700; margin-top:3px; }}
    .steps {{ border-left:2px solid rgba(54,209,232,.8); margin-left:22px; padding-left:28px; display:grid; gap:22px; }}
    .step {{ position:relative; }}
    .step:before {{ content:attr(data-num); position:absolute; left:-52px; top:0; width:38px; height:38px; border-radius:50%; display:grid; place-items:center; background:#102833; border:1px solid var(--cyan); color:#78efff; font-weight:800; }}
    .step.done:before {{ content:"✓"; background:rgba(40,178,111,.18); border-color:var(--green); color:#74efb2; }}
    .step h3 {{ margin:0 0 6px; font-size:18px; }}
    .buttons {{ display:flex; gap:10px; flex-wrap:wrap; margin-top:12px; }}
    .button, button {{ min-height:44px; border:0; border-radius:10px; padding:11px 15px; color:#061216; background:var(--cyan); font-weight:800; text-decoration:none; cursor:pointer; }}
    .button.secondary, button.secondary {{ color:#eaf7fb; background:#213242; }}
    textarea {{ width:100%; min-height:104px; margin-top:14px; border-radius:12px; border:1px solid var(--line); background:#101720; color:#eaf7fb; padding:12px; font-family:ui-monospace,SFMono-Regular,Consolas,monospace; }}
    .hidden {{ display:none !important; }}
    @media (max-width:620px) {{ .top, .install-head {{ align-items:flex-start; flex-direction:column; }} .apps {{ grid-template-columns:1fr; }} .buttons {{ display:grid; }} .button, button {{ width:100%; }} }}
  </style>
</head>
<body>
  <main>
    <section class="top">
      <div class="brand">SilentConnect</div>
      <div class="quick">
        <button class="iconbtn" type="button" id="copy-top" title="Скопировать ссылку">⛓</button>
      </div>
    </section>
    <section class="card status">
      <div style="display:flex; gap:14px; align-items:center">
        <div class="ok">✓</div>
        <div>
          <h1>Подписка готова</h1>
          <p>Выберите систему и приложение. Happ рекомендуем как основной вариант.</p>
        </div>
      </div>
    </section>
    <section class="card install">
      <div class="install-head">
        <h2>Установка</h2>
        <select id="platform">
          {''.join(f'<option value="{html.escape(value)}">{html.escape(label)}</option>' for value, label in platforms)}
        </select>
      </div>
      <div class="apps" id="apps"></div>
      <div class="steps">
        <div class="step" data-num="1">
          <h3>Установка приложения</h3>
          <p id="install-text">Скачайте приложение для вашей системы.</p>
          <div class="buttons" id="download-buttons"></div>
        </div>
        <div class="step" data-num="2">
          <h3>Добавление подписки</h3>
          <p>Нажмите кнопку ниже. Приложение откроется, и подписка добавится автоматически.</p>
          <div class="buttons"><a class="button" id="import-link" href="#">Добавить подписку</a></div>
        </div>
        <div class="step" data-num="3">
          <h3>Если подписка не добавилась</h3>
          <p>Скопируйте ссылку и импортируйте её в приложении вручную из буфера обмена.</p>
          <div class="buttons"><button class="secondary" type="button" id="copy-sub">Скопировать ссылку</button></div>
          <textarea id="sub" readonly>{escaped_subscription}</textarea>
        </div>
        <div class="step done" data-num="4">
          <h3>Подключение</h3>
          <p id="usage-text">Откройте приложение и нажмите кнопку включения VPN.</p>
        </div>
      </div>
    </section>
  </main>
  <script>
  (() => {{
    const apps = {json.dumps(apps, ensure_ascii=False)};
    const platformLabels = {json.dumps(dict(platforms), ensure_ascii=False)};
    const platform = document.getElementById("platform");
    const appsBox = document.getElementById("apps");
    const importLink = document.getElementById("import-link");
    const downloadButtons = document.getElementById("download-buttons");
    const installText = document.getElementById("install-text");
    const usageText = document.getElementById("usage-text");
    let currentApp = "happ";

    function detectPlatform() {{
      const ua = navigator.userAgent || "";
      const platformName = navigator.platform || "";
      if (/iPad|iPhone|iPod/i.test(ua)) return "ios";
      if (/Android/i.test(ua)) return /TV|AFT|BRAVIA|SMART-TV/i.test(ua) ? "androidtv" : "android";
      if (/Windows/i.test(ua)) return "windows";
      if (/Mac/i.test(platformName)) return "macos";
      if (/Linux/i.test(platformName)) return "linux";
      return "android";
    }}

    function appAvailable(app, value) {{
      return app.platforms.indexOf(value) !== -1;
    }}

    function preferredApp(value) {{
      const current = apps.find((app) => app.id === currentApp);
      if (current && appAvailable(current, value)) return currentApp;
      const happ = apps.find((app) => app.id === "happ" && appAvailable(app, value));
      if (happ) return "happ";
      const first = apps.find((app) => appAvailable(app, value));
      return first ? first.id : "happ";
    }}

    function renderApps() {{
      appsBox.innerHTML = "";
      const value = platform.value;
      currentApp = preferredApp(value);
      apps.filter((app) => appAvailable(app, value)).forEach((app) => {{
        const button = document.createElement("button");
        button.type = "button";
        button.className = "app" + (app.id === currentApp ? " active" : "");
        button.innerHTML = app.name + (app.badge ? '<span class="badge">' + app.badge + '</span>' : "");
        button.addEventListener("click", () => {{
          currentApp = app.id;
          renderApps();
          renderSelected();
        }});
        appsBox.appendChild(button);
      }});
      renderSelected();
    }}

    function renderSelected() {{
      const value = platform.value;
      const app = apps.find((item) => item.id === currentApp) || apps[0];
      importLink.href = app.importUrl;
      installText.textContent = app.description + " Система: " + platformLabels[value] + ".";
      usageText.textContent = app.id === "happ"
        ? "Откройте Happ и нажмите большую кнопку включения в центре."
        : "Откройте приложение, выберите добавленную подписку и включите VPN.";
      downloadButtons.innerHTML = "";
      (app.downloads[value] || []).forEach((item) => {{
        const link = document.createElement("a");
        link.className = "button secondary";
        link.href = item.url;
        link.textContent = item.label;
        downloadButtons.appendChild(link);
      }});
      if (!downloadButtons.children.length) {{
        const note = document.createElement("span");
        note.className = "button secondary";
        note.textContent = "Откройте страницу загрузки приложения";
        downloadButtons.appendChild(note);
      }}
    }}

    async function copySubscription(button) {{
      await navigator.clipboard.writeText(document.getElementById("sub").value);
      button.textContent = "Скопировано";
      window.setTimeout(() => button.textContent = button.id === "copy-top" ? "⛓" : "Скопировать ссылку", 1600);
    }}

    platform.value = detectPlatform();
    platform.addEventListener("change", renderApps);
    document.getElementById("copy-sub").addEventListener("click", (event) => copySubscription(event.currentTarget));
    document.getElementById("copy-top").addEventListener("click", (event) => copySubscription(event.currentTarget));
    renderApps();
  }})();
  </script>
</body>
</html>""".encode("utf-8")


def setup_page_html(*, subscription_url: str, subscription_id: str, quoted_sub_id: str, import_query: str) -> bytes:
    fallback_links = {
        "happ": f"/{SECRET_SEGMENT}/import/happ/{quoted_sub_id}?{import_query}",
        "streisand": f"/{SECRET_SEGMENT}/import/streisand/{quoted_sub_id}?{import_query}",
        "v2raytun": f"/{SECRET_SEGMENT}/import/v2raytun/{quoted_sub_id}?{import_query}",
    }
    happ_link = encrypt_happ_link(subscription_url) or fallback_links["happ"]
    apps = [
        {
            "id": "happ",
            "name": "Happ",
            "badge": "рекомендуем",
            "platforms": ["ios", "android", "windows", "macos", "linux", "androidtv", "appletv"],
            "importUrl": happ_link,
            "description": "Основной клиент для SilentConnect. Подходит почти для всех устройств.",
            "downloads": {
                "ios": [{"label": "App Store", "url": HAPP_IOS_URL}],
                "android": [
                    {"label": "Google Play", "url": HAPP_ANDROID_URL},
                    {"label": "APK для Huawei", "url": HAPP_ANDROID_APK_URL},
                ],
                "windows": [{"label": "Скачать Happ", "url": HAPP_DOWNLOAD_URL}],
                "macos": [{"label": "Скачать Happ", "url": HAPP_DOWNLOAD_URL}],
                "linux": [{"label": "Скачать Happ", "url": HAPP_DOWNLOAD_URL}],
                "androidtv": [
                    {"label": "Google Play", "url": HAPP_ANDROID_URL},
                    {"label": "APK", "url": HAPP_ANDROID_APK_URL},
                ],
                "appletv": [{"label": "App Store", "url": HAPP_IOS_URL}],
            },
        },
        {
            "id": "streisand",
            "name": "Streisand",
            "badge": "iPhone / iPad",
            "platforms": ["ios"],
            "importUrl": build_streisand_import_url(subscription_url),
            "description": "Вариант для iPhone и iPad, если Streisand уже установлен.",
            "downloads": {"ios": [{"label": "App Store", "url": STREISAND_IOS_URL}]},
        },
        {
            "id": "v2raytun",
            "name": "V2RayTun",
            "badge": "запасной",
            "platforms": ["ios", "android"],
            "importUrl": build_v2raytun_import_url(subscription_url),
            "description": "Запасной клиент для iOS и Android.",
            "downloads": {
                "ios": [{"label": "App Store", "url": V2RAYTUN_IOS_URL}],
                "android": [{"label": "Google Play", "url": V2RAYTUN_ANDROID_URL}],
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
    escaped_subscription = html.escape(subscription_url)
    return f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex,nofollow,noarchive">
  <title>Подключение SilentConnect</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg:#0d1217;
      --panel:#141c24;
      --panel-2:#18222c;
      --soft:#202b36;
      --line:#263542;
      --text:#eef6f7;
      --muted:#93a3ad;
      --cyan:#35cfe3;
      --cyan-soft:rgba(53,207,227,.13);
      --green:#36c27d;
      --amber:#e6b94d;
      --red:#ef6f6c;
    }}
    * {{ box-sizing:border-box; }}
    html, body {{ overflow-x:hidden; }}
    body {{
      margin:0;
      min-height:100vh;
      font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;
      color:var(--text);
      background:
        linear-gradient(rgba(255,255,255,.026) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255,255,255,.026) 1px, transparent 1px),
        linear-gradient(135deg, #0d1217 0%, #101722 52%, #0d1b20 100%);
      background-size:64px 64px,64px 64px,auto;
    }}
    main {{ width:calc(100vw - 28px); max-width:820px; margin:0 auto; padding:18px 0 42px; }}
    .shell {{ display:grid; gap:14px; }}
    .top, .status, .install {{
      background:rgba(20,28,36,.94);
      border:1px solid var(--line);
      border-radius:12px;
      box-shadow:0 18px 40px rgba(0,0,0,.24);
    }}
    .top {{ min-height:58px; padding:0 16px; display:flex; align-items:center; justify-content:space-between; gap:12px; overflow:hidden; }}
    .brand {{ min-width:0; display:flex; align-items:center; gap:10px; font-weight:850; letter-spacing:0; }}
    .brand span {{ min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
    .mark {{ width:28px; height:28px; border-radius:8px; display:grid; place-items:center; color:#061116; background:linear-gradient(135deg,var(--cyan),var(--green)); font-weight:900; }}
    .copy-mini {{ flex:0 0 auto; min-width:42px; min-height:38px; border:1px solid var(--line); border-radius:9px; background:#111922; color:var(--text); cursor:pointer; font-weight:800; }}
    .status {{ padding:18px; }}
    .status-head {{ display:flex; align-items:center; gap:14px; margin-bottom:14px; }}
    .status-head > div:last-child {{ min-width:0; }}
    .state-dot {{ width:42px; height:42px; border-radius:50%; display:grid; place-items:center; font-weight:900; border:1px solid rgba(54,194,125,.55); color:#7af0b4; background:rgba(54,194,125,.14); }}
    .status-warn .state-dot {{ border-color:rgba(239,111,108,.62); color:#ffaaa8; background:rgba(239,111,108,.13); }}
    h1 {{ margin:0; font-size:22px; line-height:1.15; letter-spacing:0; overflow-wrap:anywhere; }}
    h2 {{ margin:0; font-size:22px; letter-spacing:0; overflow-wrap:anywhere; }}
    h3 {{ overflow-wrap:anywhere; }}
    p {{ margin:6px 0 0; color:var(--muted); line-height:1.45; overflow-wrap:anywhere; }}
    .summary {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:10px; }}
    .metric {{ min-width:0; min-height:72px; padding:12px; border:1px solid var(--line); border-radius:10px; background:rgba(24,34,44,.76); }}
    .metric strong {{ display:block; margin-top:5px; font-size:15px; overflow-wrap:anywhere; }}
    .metric span {{ color:var(--muted); font-size:13px; }}
    .metric.good {{ border-color:rgba(54,194,125,.38); background:rgba(54,194,125,.08); }}
    .status-warn .metric.good {{ border-color:rgba(239,111,108,.38); background:rgba(239,111,108,.08); }}
    .metric.warn {{ border-color:rgba(230,185,77,.38); background:rgba(230,185,77,.08); }}
    .install {{ padding:18px; }}
    .install-head {{ min-width:0; display:flex; align-items:center; justify-content:space-between; gap:14px; margin-bottom:14px; }}
    select {{ min-height:40px; min-width:160px; border:1px solid var(--line); border-radius:9px; background:#111922; color:var(--text); padding:0 12px; font-size:15px; }}
    .apps {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:10px; margin-bottom:18px; }}
    .app {{ min-width:0; min-height:56px; border:1px solid var(--line); border-radius:10px; background:var(--soft); color:var(--text); cursor:pointer; text-align:left; padding:10px 12px; font-weight:850; position:relative; overflow:hidden; }}
    .app:after {{ content:attr(data-watermark); position:absolute; right:10px; top:2px; font-size:42px; color:rgba(255,255,255,.06); font-weight:900; pointer-events:none; }}
    .app.active {{ border-color:rgba(53,207,227,.9); background:linear-gradient(135deg,rgba(53,207,227,.14),rgba(32,43,54,.94)); box-shadow:0 0 0 1px rgba(53,207,227,.18) inset; }}
    .app .badge {{ display:block; margin-top:3px; color:#ffd84e; font-size:11px; font-weight:800; }}
    .steps {{ display:grid; gap:0; margin-top:4px; }}
    .step {{ min-width:0; position:relative; min-height:76px; padding:0 0 24px 56px; }}
    .step:last-child {{ padding-bottom:0; }}
    .step:before {{ content:attr(data-num); position:absolute; left:0; top:0; width:34px; height:34px; border-radius:50%; display:grid; place-items:center; border:1px solid rgba(53,207,227,.8); color:#82effb; background:#102632; font-weight:900; z-index:1; }}
    .step:not(:last-child):after {{ content:""; position:absolute; left:16px; top:36px; bottom:-2px; width:2px; background:linear-gradient(var(--cyan), rgba(53,207,227,.18)); }}
    .step.done:before {{ content:"✓"; border-color:rgba(54,194,125,.75); color:#86f4bc; background:rgba(54,194,125,.16); }}
    .step h3 {{ margin:0; font-size:17px; letter-spacing:0; }}
    .buttons {{ display:flex; gap:10px; flex-wrap:wrap; margin-top:12px; }}
    .button, button {{
      max-width:100%;
      min-height:42px;
      border:0;
      border-radius:9px;
      padding:10px 14px;
      background:var(--cyan);
      color:#061216;
      font-weight:850;
      text-decoration:none;
      cursor:pointer;
      display:inline-flex;
      align-items:center;
      justify-content:center;
      gap:8px;
      overflow-wrap:anywhere;
    }}
    .button.secondary, button.secondary {{ background:#243443; color:var(--text); }}
    .button.success {{ background:linear-gradient(135deg,var(--green),var(--cyan)); }}
    textarea {{ width:100%; min-height:94px; margin-top:12px; border:1px solid var(--line); border-radius:10px; background:#0f1720; color:var(--text); padding:12px; font:13px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace; resize:vertical; }}
    .hidden {{ display:none !important; }}
    @media (max-width:640px) {{
      main {{ width:100%; max-width:none; padding:10px; }}
      .shell {{ width:100%; }}
      .top, .status, .install {{ width:100%; }}
      .top {{ border-radius:10px; }}
      .summary {{ grid-template-columns:1fr; }}
      .install-head {{ align-items:flex-start; flex-direction:column; }}
      select {{ width:100%; }}
      .apps {{ grid-template-columns:1fr; }}
      .buttons {{ display:grid; }}
      .buttons .button, .buttons button {{ width:100%; }}
      .step {{ padding-left:48px; }}
      .step:not(:last-child):after {{ left:16px; }}
    }}
  </style>
</head>
<body>
  <main class="shell">
    <section class="top">
      <div class="brand"><div class="mark">S</div><span>SilentConnect</span></div>
      <button class="copy-mini" type="button" id="copy-top" title="Скопировать ссылку">⛓</button>
    </section>

    <section class="status {status_class}">
      <div class="status-head">
        <div class="state-dot">✓</div>
        <div>
          <h1>{html.escape(str(summary["title"]))}</h1>
          <p>{html.escape(str(summary["subtitle"]))} · {html.escape(str(summary["device_limit"]))}</p>
        </div>
      </div>
      <div class="summary">
        <div class="metric">
          <span>Профиль</span>
          <strong>{html.escape(str(summary["identifier"]))}</strong>
        </div>
        <div class="metric good">
          <span>Статус</span>
          <strong>{html.escape(str(summary["status"]))}</strong>
        </div>
        <div class="metric">
          <span>Действует до</span>
          <strong>{html.escape(str(summary["expires"]))}</strong>
        </div>
        <div class="metric warn">
          <span>Трафик</span>
          <strong>{html.escape(str(summary["traffic"]))}</strong>
        </div>
      </div>
    </section>

    <section class="install">
      <div class="install-head">
        <h2>Подключение</h2>
        <select id="platform">
          {''.join(f'<option value="{html.escape(value)}">{html.escape(label)}</option>' for value, label in platforms)}
        </select>
      </div>
      <div class="apps" id="apps"></div>
      <div class="steps">
        <div class="step" data-num="1">
          <h3>Установите приложение</h3>
          <p id="install-text">Выберите подходящую версию и установите приложение.</p>
          <div class="buttons" id="download-buttons"></div>
        </div>
        <div class="step" data-num="2">
          <h3>Добавьте подписку</h3>
          <p>Нажмите кнопку ниже. Если приложение уже установлено, оно откроется сразу.</p>
          <div class="buttons"><a class="button success" id="import-link" href="#">Добавить подписку</a></div>
        </div>
        <div class="step done" data-num="3">
          <h3>Включите VPN</h3>
          <p id="usage-text">Откройте приложение и нажмите кнопку включения.</p>
        </div>
        <div class="step" data-num="4">
          <h3>Если не сработало</h3>
          <p>Скопируйте ссылку и импортируйте её в приложении вручную из буфера обмена.</p>
          <div class="buttons"><button class="secondary" type="button" id="copy-sub">Скопировать ссылку</button></div>
          <textarea id="sub" readonly>{escaped_subscription}</textarea>
        </div>
      </div>
    </section>
  </main>
  <script>
  (() => {{
    const apps = {json.dumps(apps, ensure_ascii=False)};
    const platformLabels = {json.dumps(dict(platforms), ensure_ascii=False)};
    const platform = document.getElementById("platform");
    const appsBox = document.getElementById("apps");
    const importLink = document.getElementById("import-link");
    const downloadButtons = document.getElementById("download-buttons");
    const installText = document.getElementById("install-text");
    const usageText = document.getElementById("usage-text");
    let currentApp = "happ";

    function detectPlatform() {{
      const ua = navigator.userAgent || "";
      const platformName = navigator.platform || "";
      if (/iPad|iPhone|iPod/i.test(ua)) return "ios";
      if (/Android/i.test(ua)) return /TV|AFT|BRAVIA|SMART-TV/i.test(ua) ? "androidtv" : "android";
      if (/Windows/i.test(ua)) return "windows";
      if (/Mac/i.test(platformName)) return "macos";
      if (/Linux/i.test(platformName)) return "linux";
      return "android";
    }}

    function appAvailable(app, value) {{
      return app.platforms.indexOf(value) !== -1;
    }}

    function preferredApp(value) {{
      const current = apps.find((app) => app.id === currentApp);
      if (current && appAvailable(current, value)) return currentApp;
      const happ = apps.find((app) => app.id === "happ" && appAvailable(app, value));
      if (happ) return "happ";
      const first = apps.find((app) => appAvailable(app, value));
      return first ? first.id : "happ";
    }}

    function appInitial(app) {{
      if (app.id === "happ") return "H";
      if (app.id === "streisand") return "S";
      return "V";
    }}

    function renderApps() {{
      appsBox.innerHTML = "";
      const value = platform.value;
      currentApp = preferredApp(value);
      apps.filter((app) => appAvailable(app, value)).forEach((app) => {{
        const button = document.createElement("button");
        button.type = "button";
        button.className = "app" + (app.id === currentApp ? " active" : "");
        button.setAttribute("data-watermark", appInitial(app));
        button.innerHTML = app.name + (app.badge ? '<span class="badge">' + app.badge + '</span>' : "");
        button.addEventListener("click", () => {{
          currentApp = app.id;
          renderApps();
          renderSelected();
        }});
        appsBox.appendChild(button);
      }});
      renderSelected();
    }}

    function renderSelected() {{
      const value = platform.value;
      const app = apps.find((item) => item.id === currentApp) || apps[0];
      importLink.href = app.importUrl;
      installText.textContent = app.description + " Система: " + platformLabels[value] + ".";
      usageText.textContent = app.id === "happ"
        ? "Откройте Happ и нажмите большую кнопку включения в центре."
        : "Откройте выбранное приложение, выберите добавленную подписку и включите VPN.";
      downloadButtons.innerHTML = "";
      (app.downloads[value] || []).forEach((item) => {{
        const link = document.createElement("a");
        link.className = "button secondary";
        link.href = item.url;
        link.target = "_blank";
        link.rel = "noopener";
        link.textContent = item.label;
        downloadButtons.appendChild(link);
      }});
      if (!downloadButtons.children.length) {{
        const note = document.createElement("span");
        note.className = "button secondary";
        note.textContent = "Откройте страницу загрузки приложения";
        downloadButtons.appendChild(note);
      }}
    }}

    async function copySubscription(button) {{
      await navigator.clipboard.writeText(document.getElementById("sub").value);
      const original = button.textContent;
      button.textContent = "Скопировано";
      window.setTimeout(() => button.textContent = original, 1600);
    }}

    platform.value = detectPlatform();
    platform.addEventListener("change", renderApps);
    document.getElementById("copy-sub").addEventListener("click", (event) => copySubscription(event.currentTarget));
    document.getElementById("copy-top").addEventListener("click", (event) => copySubscription(event.currentTarget));
    renderApps();
  }})();
  </script>
</body>
</html>""".encode("utf-8")


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
    body {{ margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #0f1317; color: #eef2f3; }}
    main {{ max-width: 920px; margin: 0 auto; padding: 34px 18px 56px; }}
    h1 {{ font-size: 30px; margin: 0 0 8px; }}
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
    <h1>Пользовательское соглашение и политика конфиденциальности SilentConnect.net</h1>
    <p class="meta">Редакция от {updated_at}</p>
    <p class="note">Этот документ описывает условия использования сервиса SilentConnect.net, правила допустимого использования и подход к обработке данных. Если Вы не согласны с условиями, не используйте сервис.</p>

    <h2>1. Общие положения</h2>
    <p>SilentConnect.net предоставляет технический сервис защищённого сетевого подключения. Сервис предназначен для повышения приватности, безопасности соединения и доступа к легальным интернет-ресурсам.</p>
    <p>Используя бота, подписочную ссылку, конфигурацию или иную часть сервиса, пользователь подтверждает принятие настоящего соглашения.</p>

    <h2>2. Возраст и дееспособность</h2>
    <p>Нажимая кнопку подтверждения в боте или продолжая использовать сервис, пользователь подтверждает, что ему исполнилось 18 лет, он обладает необходимой дееспособностью и вправе самостоятельно принимать настоящие условия.</p>
    <p>Если пользователь не достиг 18 лет, использование сервиса допускается только с согласия и под ответственностью законного представителя, если это разрешено применимым правом.</p>

    <h2>3. Ответственность пользователя</h2>
    <p>Пользователь самостоятельно выбирает сайты, приложения, сервисы, файлы и иные ресурсы, к которым обращается через интернет, и самостоятельно несёт ответственность за законность своих действий.</p>
    <p>Сервис не инициирует передачу данных пользователя, не выбирает получателей трафика, не определяет цели действий пользователя и не одобряет незаконное использование интернета.</p>
    <p>Запрещается использовать SilentConnect.net для действий, нарушающих применимое законодательство, права третьих лиц или правила интернет-площадок, включая, но не ограничиваясь:</p>
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
    <p>SilentConnect.net придерживается принципа минимизации данных. Мы не ведём журналы посещённых сайтов, истории браузинга, содержимого трафика, DNS-запросов пользователя и переписки пользователя в сторонних сервисах.</p>
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
    <p>По вопросам доступа, конфиденциальности, удаления данных или жалоб на злоупотребления обращайтесь в поддержку: <a href="https://t.me/SilentConnectHelp">@SilentConnectHelp</a>.</p>
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
            "server-address-resolve-enable": "1",
            "server-address-resolve-dns-domain": HAPP_RESOLVE_DNS_DOMAIN,
            "server-address-resolve-dns-ip": HAPP_RESOLVE_DNS_IP,
            "fragmentation-enable": "0",
            "per-app-proxy-mode": "off",
        }
    )

    exclude_routes = happ_exclude_routes(payload)
    if exclude_routes:
        headers["exclude-routes"] = ",".join(exclude_routes)

    return headers


class RequestHandler(BaseHTTPRequestHandler):
    server_version = "subjson-service/3.0"

    def do_GET(self) -> None:
        self._handle_request(include_body=True)

    def do_HEAD(self) -> None:
        self._handle_request(include_body=False)

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

            if path == ["healthz"]:
                self._send_json(HTTPStatus.OK, {"ok": True}, include_body)
                return

            if path == ["legal", "terms"] or path == [SECRET_SEGMENT, "legal", "terms"]:
                self._send_html(HTTPStatus.OK, legal_terms_html(), include_body)
                return

            if len(path) == 3 and path[0] == SECRET_SEGMENT:
                public_host = resolve_public_host(self.headers)

                if path[1] in {"json-global", "sub-global"}:
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

                if path[1] in {"json", "sub", "json-ru", "sub-ru"}:
                    payload = build_four_profiles(path[2], public_host, "split-ru")
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

                if path[1] in {
                    "json-frankfurt-tcp",
                    "sub-frankfurt-tcp",
                    "json-frankfurt-xhttp",
                    "sub-frankfurt-xhttp",
                    "json-frankfurt-hybrid",
                    "sub-frankfurt-hybrid",
                }:
                    payload = build_three_frankfurt_profiles(path[2])
                    if not payload:
                        self._send_json(
                            HTTPStatus.NOT_FOUND,
                            {"error": "not_found", "detail": "static_config_not_found"},
                            include_body,
                        )
                        return
                    self._send_subscription_json(
                        payload,
                        include_body,
                        subscription_route=path[1],
                        subscription_id=path[2],
                    )
                    return

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

            if len(path) == 3 and path[0] == SECRET_SEGMENT and path[1] == "import":
                sub_id = path[2]
                source_url = first_non_empty(query.get("url")) or public_subscription_url(self.headers, "json", sub_id)
                quoted_sub_id = urllib.parse.quote(sub_id, safe="")
                import_query = urllib.parse.urlencode({"url": source_url})
                generic_html = setup_page_html(
                    subscription_url=source_url,
                    subscription_id=sub_id,
                    quoted_sub_id=quoted_sub_id,
                    import_query=import_query,
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
    ) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Robots-Tag", "noindex, nofollow, noarchive")
        for name, value in build_happ_response_headers(
            payload,
            subscription_id=subscription_id,
            profile_web_page_url=profile_web_page_url,
            profile_title=profile_title,
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
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Robots-Tag", "noindex, nofollow, noarchive")
        self.end_headers()
        if include_body:
            self.wfile.write(body)

    def _send_html(self, status: HTTPStatus, body: bytes, include_body: bool) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Robots-Tag", "noindex, nofollow,noarchive")
        self.end_headers()
        if include_body:
            self.wfile.write(body)

    def _redirect(self, location: str, include_body: bool) -> None:
        body = b""
        self.send_response(HTTPStatus.FOUND)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Referrer-Policy", "no-referrer")
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
