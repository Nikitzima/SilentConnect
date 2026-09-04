"""
Unit and E2E Test Suite for SilentConnect Client Formats:
- Clash Meta / V2RayTun / Mihomo YAML Subscription Format
- Streisand Base64 URI List Bundle & Deep-Link Import Format
- Cross-Format Protocol Parity across NL & FI Nodes
"""

import base64
import copy
import json
import os
import sys
import unittest
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple
import yaml

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from tests.test_smart_selector import build_authoritative_singbox_smart_config

# Shared Authoritative Constants
CONSTANTS = {
    "TCP_REALITY_PUBLIC_KEY": "2JCWlJ5M8OxWsp8YLWZqtlkyJGMbdRSwVishk8mIuEo",
    "TCP_REALITY_SHORT_ID": "9a2f7c6d1e4b8a30",
    "TCP_REALITY_SNI_CLASSIC": "sber.ru",
    "TCP_REALITY_SNI_FAST": "st.kinopoisk.ru",
    "GRPC_REALITY_PUBLIC_KEY": "qb3chneGBO60_kv-McyCvUrXM93aN851duFH2bVIMQU",
    "GRPC_REALITY_SHORT_ID": "9a2f7c6d1e4b8a30",
    "GRPC_REALITY_SNI": "vk.com",
    "GRPC_SERVICE_NAME": "grpc-maxru",
    "FI_XHTTP_REALITY_PUBLIC_KEY": "ASvvjJ4dOcHst5FWDJ9D562UQ0nN1pAw0l13Z58RNQA",
    "FI_XHTTP_REALITY_SHORT_ID": "a1b2c3d4e5f60718",
    "FI_XHTTP_REALITY_SNI": "sber.ru",
    "FI_XHTTP_REALITY_PORT": 39443,
    "HYSTERIA_SALAMANDER_PASSWORD": "485a96779d1ad79d0fa80ca0",
    "HTTP_204_CLOUDFLARE": "https://cp.cloudflare.com/generate_204",
    "NL_HOST": "edge.example.com",
    "NL_SUB_HOST": "sub.example.com",
    "FI_HOST": "fi.example.com",
    "TEST_UUID": "9c3d7f1e-4b8a-4c2d-9e1f-8a2b3c4d5e6f",
    "WS_PATH": "/sc-ws-9c3d7f1e",
}


def build_authoritative_clash_meta_dict(
    client_uuid: str = CONSTANTS["TEST_UUID"],
    healthcheck_url: str = CONSTANTS["HTTP_204_CLOUDFLARE"],
) -> Dict[str, Any]:
    """Generates the authoritative reference Clash Meta configuration dictionary."""
    return {
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
        "proxies": [
            {
                "name": "🇳🇱 NL Classic Reality TCP",
                "type": "vless",
                "server": CONSTANTS["NL_HOST"],
                "port": 443,
                "uuid": client_uuid,
                "network": "tcp",
                "flow": "xtls-rprx-vision",
                "tls": True,
                "servername": CONSTANTS["TCP_REALITY_SNI_CLASSIC"],
                "reality-opts": {
                    "public-key": CONSTANTS["TCP_REALITY_PUBLIC_KEY"],
                    "short-id": CONSTANTS["TCP_REALITY_SHORT_ID"],
                },
                "client-fingerprint": "chrome",
                "udp": True,
            },
            {
                "name": "🇳🇱 NL Fast Reality TCP",
                "type": "vless",
                "server": CONSTANTS["NL_HOST"],
                "port": 443,
                "uuid": client_uuid,
                "network": "tcp",
                "flow": "xtls-rprx-vision",
                "tls": True,
                "servername": CONSTANTS["TCP_REALITY_SNI_FAST"],
                "reality-opts": {
                    "public-key": CONSTANTS["TCP_REALITY_PUBLIC_KEY"],
                    "short-id": CONSTANTS["TCP_REALITY_SHORT_ID"],
                },
                "client-fingerprint": "chrome",
                "udp": True,
            },
            {
                "name": "🇳🇱 NL Speed Hysteria2",
                "type": "hysteria2",
                "server": CONSTANTS["NL_SUB_HOST"],
                "port": 443,
                "password": client_uuid,
                "sni": CONSTANTS["NL_SUB_HOST"],
                "alpn": ["h3"],
                "obfs": "gecko",
                "obfs-password": CONSTANTS["HYSTERIA_SALAMANDER_PASSWORD"],
                "udp": True,
            },
            {
                "name": "🇳🇱 NL Backup Reality gRPC",
                "type": "vless",
                "server": CONSTANTS["NL_HOST"],
                "port": 29443,
                "uuid": client_uuid,
                "network": "grpc",
                "tls": True,
                "servername": CONSTANTS["GRPC_REALITY_SNI"],
                "reality-opts": {
                    "public-key": CONSTANTS["GRPC_REALITY_PUBLIC_KEY"],
                    "short-id": CONSTANTS["GRPC_REALITY_SHORT_ID"],
                },
                "grpc-opts": {"grpc-service-name": CONSTANTS["GRPC_SERVICE_NAME"]},
                "client-fingerprint": "chrome",
                "udp": True,
            },
            {
                "name": "🇳🇱 NL Stealth XHTTP",
                "type": "vless",
                "server": CONSTANTS["NL_HOST"],
                "port": 443,
                "uuid": client_uuid,
                "network": "http",
                "tls": True,
                "servername": CONSTANTS["NL_HOST"],
                "http-opts": {
                    "path": ["/xh-mx-d1f7c0429d6a"],
                    "headers": {"Host": [CONSTANTS["NL_HOST"]]},
                },
                "client-fingerprint": "chrome",
                "udp": True,
            },
            {
                "name": "🇫🇮 FI Classic Reality TCP",
                "type": "vless",
                "server": CONSTANTS["FI_HOST"],
                "port": 443,
                "uuid": client_uuid,
                "network": "tcp",
                "flow": "xtls-rprx-vision",
                "tls": True,
                "servername": CONSTANTS["TCP_REALITY_SNI_CLASSIC"],
                "reality-opts": {
                    "public-key": CONSTANTS["TCP_REALITY_PUBLIC_KEY"],
                    "short-id": CONSTANTS["TCP_REALITY_SHORT_ID"],
                },
                "client-fingerprint": "chrome",
                "udp": True,
            },
            {
                "name": "🇫🇮 FI Fast Reality TCP",
                "type": "vless",
                "server": CONSTANTS["FI_HOST"],
                "port": 443,
                "uuid": client_uuid,
                "network": "tcp",
                "flow": "xtls-rprx-vision",
                "tls": True,
                "servername": CONSTANTS["TCP_REALITY_SNI_FAST"],
                "reality-opts": {
                    "public-key": CONSTANTS["TCP_REALITY_PUBLIC_KEY"],
                    "short-id": CONSTANTS["TCP_REALITY_SHORT_ID"],
                },
                "client-fingerprint": "chrome",
                "udp": True,
            },
            {
                "name": "🇫🇮 FI Speed Hysteria2",
                "type": "hysteria2",
                "server": CONSTANTS["FI_HOST"],
                "port": 443,
                "password": client_uuid,
                "sni": CONSTANTS["FI_HOST"],
                "alpn": ["h3"],
                "obfs": "gecko",
                "obfs-password": CONSTANTS["HYSTERIA_SALAMANDER_PASSWORD"],
                "udp": True,
            },
            {
                "name": "🇫🇮 FI Backup Reality gRPC",
                "type": "vless",
                "server": CONSTANTS["FI_HOST"],
                "port": 29443,
                "uuid": client_uuid,
                "network": "grpc",
                "tls": True,
                "servername": CONSTANTS["GRPC_REALITY_SNI"],
                "reality-opts": {
                    "public-key": CONSTANTS["GRPC_REALITY_PUBLIC_KEY"],
                    "short-id": CONSTANTS["GRPC_REALITY_SHORT_ID"],
                },
                "grpc-opts": {"grpc-service-name": CONSTANTS["GRPC_SERVICE_NAME"]},
                "client-fingerprint": "chrome",
                "udp": True,
            },
            {
                "name": "🇫🇮 FI Stealth XHTTP Reality",
                "type": "vless",
                "server": CONSTANTS["FI_HOST"],
                "port": CONSTANTS["FI_XHTTP_REALITY_PORT"],
                "uuid": client_uuid,
                "network": "http",
                "tls": True,
                "servername": CONSTANTS["FI_XHTTP_REALITY_SNI"],
                "reality-opts": {
                    "public-key": CONSTANTS["FI_XHTTP_REALITY_PUBLIC_KEY"],
                    "short-id": CONSTANTS["FI_XHTTP_REALITY_SHORT_ID"],
                },
                "http-opts": {"path": ["/xh-mx-d1f7c0429d6a"]},
                "client-fingerprint": "chrome",
                "udp": True,
            },
        ],
        "proxy-groups": [
            {
                "name": "🚀 PROXY",
                "type": "select",
                "proxies": [
                    "⚡ Auto URL-Test",
                    "🛡️ Priority Fallback",
                    "🇳🇱 NL Classic Reality TCP",
                    "🇳🇱 NL Fast Reality TCP",
                    "🇳🇱 NL Speed Hysteria2",
                    "🇳🇱 NL Backup Reality gRPC",
                    "🇳🇱 NL Stealth XHTTP",
                    "🇫🇮 FI Classic Reality TCP",
                    "🇫🇮 FI Fast Reality TCP",
                    "🇫🇮 FI Speed Hysteria2",
                    "🇫🇮 FI Backup Reality gRPC",
                    "🇫🇮 FI Stealth XHTTP Reality",
                    "DIRECT",
                ],
            },
            {
                "name": "⚡ Auto URL-Test",
                "type": "url-test",
                "proxies": [
                    "🇳🇱 NL Classic Reality TCP",
                    "🇳🇱 NL Fast Reality TCP",
                    "🇳🇱 NL Speed Hysteria2",
                    "🇳🇱 NL Backup Reality gRPC",
                    "🇳🇱 NL Stealth XHTTP",
                    "🇫🇮 FI Classic Reality TCP",
                    "🇫🇮 FI Fast Reality TCP",
                    "🇫🇮 FI Speed Hysteria2",
                    "🇫🇮 FI Backup Reality gRPC",
                    "🇫🇮 FI Stealth XHTTP Reality",
                ],
                "url": healthcheck_url,
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
                "url": healthcheck_url,
                "interval": 180,
                "lazy": True,
                "expected-status": "204",
            },
        ],
        "rules": [
            "GEOIP,PRIVATE,DIRECT",
            "GEOSITE,category-ads-all,REJECT",
            "GEOSITE,ru,DIRECT",
            "GEOIP,RU,DIRECT",
            "DOMAIN-SUFFIX,ru,DIRECT",
            "DOMAIN-SUFFIX,su,DIRECT",
            "DOMAIN-SUFFIX,xn--p1ai,DIRECT",
            "DOMAIN-SUFFIX,gosuslugi.ru,DIRECT",
            "DOMAIN-SUFFIX,sberbank.ru,DIRECT",
            "DOMAIN-SUFFIX,tinkoff.ru,DIRECT",
            "DOMAIN-SUFFIX,railnation-game.ru,DIRECT",
            "MATCH,🚀 PROXY",
        ],
    }


def build_authoritative_streisand_bundle_text(
    client_uuid: str = CONSTANTS["TEST_UUID"],
) -> str:
    """Generates the authoritative newline-separated Streisand URI list."""
    uris = [
        f"vless://{client_uuid}@{CONSTANTS['NL_HOST']}:443?type=tcp&security=reality&pbk={CONSTANTS['TCP_REALITY_PUBLIC_KEY']}&fp=chrome&sni={CONSTANTS['TCP_REALITY_SNI_CLASSIC']}&sid={CONSTANTS['TCP_REALITY_SHORT_ID']}&flow=xtls-rprx-vision#{urllib.parse.quote('🇳🇱 1. Классический TCP (NL)')}",
        f"vless://{client_uuid}@{CONSTANTS['NL_HOST']}:443?type=tcp&security=reality&pbk={CONSTANTS['TCP_REALITY_PUBLIC_KEY']}&fp=chrome&sni={CONSTANTS['TCP_REALITY_SNI_FAST']}&sid={CONSTANTS['TCP_REALITY_SHORT_ID']}&flow=xtls-rprx-vision#{urllib.parse.quote('🇳🇱 2. Быстрый TCP (NL)')}",
        f"hy2://{client_uuid}@{CONSTANTS['NL_SUB_HOST']}:443?sni={CONSTANTS['NL_SUB_HOST']}&alpn=h3&obfs=gecko&obfs-password={CONSTANTS['HYSTERIA_SALAMANDER_PASSWORD']}#{urllib.parse.quote('🇳🇱 3. Скоростной Hysteria2 (NL)')}",
        f"vless://{client_uuid}@{CONSTANTS['NL_HOST']}:29443?type=grpc&security=reality&pbk={CONSTANTS['GRPC_REALITY_PUBLIC_KEY']}&fp=chrome&sni={CONSTANTS['GRPC_REALITY_SNI']}&sid={CONSTANTS['GRPC_REALITY_SHORT_ID']}&serviceName={CONSTANTS['GRPC_SERVICE_NAME']}#{urllib.parse.quote('🇳🇱 4. Запасной gRPC (NL)')}",
        f"vless://{client_uuid}@{CONSTANTS['NL_HOST']}:443?type=xhttp&security=tls&sni={CONSTANTS['NL_HOST']}&alpn=h2,http/1.1&path=%2Fxh-mx-d1f7c0429d6a&mode=packet-up#{urllib.parse.quote('🇳🇱 5. Незаметный XHTTP (NL)')}",
        f"vless://{client_uuid}@{CONSTANTS['FI_HOST']}:443?type=tcp&security=reality&pbk={CONSTANTS['TCP_REALITY_PUBLIC_KEY']}&fp=chrome&sni={CONSTANTS['TCP_REALITY_SNI_CLASSIC']}&sid={CONSTANTS['TCP_REALITY_SHORT_ID']}&flow=xtls-rprx-vision#{urllib.parse.quote('🇫🇮 6. Классический TCP (FI)')}",
        f"vless://{client_uuid}@{CONSTANTS['FI_HOST']}:443?type=tcp&security=reality&pbk={CONSTANTS['TCP_REALITY_PUBLIC_KEY']}&fp=chrome&sni={CONSTANTS['TCP_REALITY_SNI_FAST']}&sid={CONSTANTS['TCP_REALITY_SHORT_ID']}&flow=xtls-rprx-vision#{urllib.parse.quote('🇫🇮 7. Быстрый TCP (FI)')}",
        f"hy2://{client_uuid}@{CONSTANTS['FI_HOST']}:443?sni={CONSTANTS['FI_HOST']}&alpn=h3&obfs=gecko&obfs-password={CONSTANTS['HYSTERIA_SALAMANDER_PASSWORD']}#{urllib.parse.quote('🇫🇮 8. Скоростной Hysteria2 (FI)')}",
        f"vless://{client_uuid}@{CONSTANTS['FI_HOST']}:29443?type=grpc&security=reality&pbk={CONSTANTS['GRPC_REALITY_PUBLIC_KEY']}&fp=chrome&sni={CONSTANTS['GRPC_REALITY_SNI']}&sid={CONSTANTS['GRPC_REALITY_SHORT_ID']}&serviceName={CONSTANTS['GRPC_SERVICE_NAME']}#{urllib.parse.quote('🇫🇮 9. Запасной gRPC (FI)')}",
        f"vless://{client_uuid}@{CONSTANTS['FI_HOST']}:{CONSTANTS['FI_XHTTP_REALITY_PORT']}?type=xhttp&security=reality&pbk={CONSTANTS['FI_XHTTP_REALITY_PUBLIC_KEY']}&fp=chrome&sni={CONSTANTS['FI_XHTTP_REALITY_SNI']}&sid={CONSTANTS['FI_XHTTP_REALITY_SHORT_ID']}&path=%2Fxh-mx-d1f7c0429d6a&mode=packet-up#{urllib.parse.quote('🇫🇮 10. Незаметный XHTTP Reality (FI)')}",
    ]
    return "\n".join(uris)


def validate_clash_meta_schema(data: Dict[str, Any]) -> List[str]:
    """Validates Clash Meta / Mihomo configuration dictionary against specifications."""
    errors = []

    for req_key in ("proxies", "proxy-groups", "rules"):
        if req_key not in data:
            errors.append(f"Missing required root key: '{req_key}'")

    if errors:
        return errors

    proxies = data.get("proxies", [])
    if not isinstance(proxies, list) or len(proxies) < 10:
        errors.append(f"'proxies' must contain at least 10 active proxies, found {len(proxies)}")

    proxy_names = set()
    for idx, p in enumerate(proxies):
        if not isinstance(p, dict):
            errors.append(f"Proxy at index {idx} is not an object")
            continue
        p_name = p.get("name")
        if not p_name:
            errors.append(f"Proxy at index {idx} missing 'name'")
        elif p_name in proxy_names:
            errors.append(f"Duplicate proxy name: '{p_name}'")
        else:
            proxy_names.add(p_name)

        p_type = p.get("type")
        if p_type not in ("vless", "hysteria2", "vmess", "shadowsocks", "trojan"):
            errors.append(f"Invalid proxy type '{p_type}' in proxy '{p_name}'")

    # Proxy groups validation
    groups = data.get("proxy-groups", [])
    if not isinstance(groups, list):
        errors.append("'proxy-groups' must be a list")
        return errors

    group_map = {g.get("name"): g for g in groups if isinstance(g, dict) and g.get("name")}

    # Assert 🚀 PROXY
    if "🚀 PROXY" not in group_map:
        errors.append("Missing '🚀 PROXY' select group")
    else:
        select_grp = group_map["🚀 PROXY"]
        if select_grp.get("type") != "select":
            errors.append(f"'🚀 PROXY' type must be 'select', got '{select_grp.get('type')}'")
        proxies_in_select = select_grp.get("proxies", [])
        if "⚡ Auto URL-Test" not in proxies_in_select:
            errors.append("'⚡ Auto URL-Test' must be in '🚀 PROXY.proxies'")
        if "🛡️ Priority Fallback" not in proxies_in_select:
            errors.append("'🛡️ Priority Fallback' must be in '🚀 PROXY.proxies'")

    # Assert ⚡ Auto URL-Test
    if "⚡ Auto URL-Test" not in group_map:
        errors.append("Missing '⚡ Auto URL-Test' group")
    else:
        urltest_grp = group_map["⚡ Auto URL-Test"]
        if urltest_grp.get("type") != "url-test":
            errors.append(f"'⚡ Auto URL-Test' type must be 'url-test', got '{urltest_grp.get('type')}'")
        if urltest_grp.get("url") != CONSTANTS["HTTP_204_CLOUDFLARE"]:
            errors.append(f"'⚡ Auto URL-Test.url' expected Cloudflare 204, got '{urltest_grp.get('url')}'")
        if urltest_grp.get("interval") != 180:
            errors.append(f"'⚡ Auto URL-Test.interval' expected 180s, got {urltest_grp.get('interval')}")
        if urltest_grp.get("tolerance") != 50:
            errors.append(f"'⚡ Auto URL-Test.tolerance' expected 50, got {urltest_grp.get('tolerance')}")
        if urltest_grp.get("lazy") is not True:
            errors.append(f"'⚡ Auto URL-Test.lazy' expected True, got {urltest_grp.get('lazy')}")

    # Assert 🛡️ Priority Fallback
    if "🛡️ Priority Fallback" not in group_map:
        errors.append("Missing '🛡️ Priority Fallback' group")
    else:
        fallback_grp = group_map["🛡️ Priority Fallback"]
        if fallback_grp.get("type") != "fallback":
            errors.append(f"'🛡️ Priority Fallback' type must be 'fallback', got '{fallback_grp.get('type')}'")
        if fallback_grp.get("interval") != 180:
            errors.append(f"'🛡️ Priority Fallback.interval' expected 180s, got {fallback_grp.get('interval')}")
        if fallback_grp.get("lazy") is not True:
            errors.append(f"'🛡️ Priority Fallback.lazy' expected True, got {fallback_grp.get('lazy')}")

    # Assert rules
    rules = data.get("rules", [])
    if not isinstance(rules, list) or not rules:
        errors.append("'rules' must be a non-empty list")
    elif not any("MATCH,🚀 PROXY" in r for r in rules):
        errors.append("Missing 'MATCH,🚀 PROXY' final catch-all rule")

    return errors


def parse_and_validate_streisand_bundle(encoded_bundle: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Decodes a Base64 Streisand bundle and returns parsed node descriptions and any errors."""
    errors = []
    nodes = []

    # 1. Base64 Decode with padding normalization
    cleaned = encoded_bundle.strip()
    missing_padding = len(cleaned) % 4
    if missing_padding:
        cleaned += "=" * (4 - missing_padding)

    try:
        raw_text = base64.b64decode(cleaned).decode("utf-8")
    except Exception as e:
        return [], [f"Base64 decoding failed: {e}"]

    lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
    if len(lines) < 10:
        errors.append(f"Streisand bundle must contain at least 10 active server URIs, found {len(lines)}")

    for idx, uri_str in enumerate(lines):
        try:
            parsed = urllib.parse.urlparse(uri_str)
            scheme = parsed.scheme.lower()
            if scheme not in ("vless", "hy2", "hysteria2", "vmess", "trojan", "ss"):
                errors.append(f"Line {idx+1}: Unsupported URI scheme '{scheme}'")
                continue

            user_part = parsed.username or (parsed.netloc.split("@")[0] if "@" in parsed.netloc else "")
            host = parsed.hostname or ""
            port = parsed.port or (443 if scheme in ("vless", "hy2") else None)
            params = urllib.parse.parse_qs(parsed.query)
            remark = urllib.parse.unquote(parsed.fragment)

            node_info = {
                "line": idx + 1,
                "scheme": scheme,
                "uuid": user_part,
                "host": host,
                "port": port,
                "params": params,
                "remark": remark,
            }
            nodes.append(node_info)

            # Strict protocol validations
            if scheme == "vless":
                sec = params.get("security", [""])[0]
                if sec == "reality":
                    if not params.get("pbk"):
                        errors.append(f"Line {idx+1}: Missing 'pbk' (Reality Public Key)")
                    if not params.get("sid"):
                        errors.append(f"Line {idx+1}: Missing 'sid' (Reality Short ID)")
                    if not params.get("sni"):
                        errors.append(f"Line {idx+1}: Missing 'sni' in Reality node")
            elif scheme in ("hy2", "hysteria2"):
                if params.get("obfs", [""])[0] in ("salamander", "gecko"):
                    if not params.get("obfs-password"):
                        errors.append(f"Line {idx+1}: Missing 'obfs-password' for Salamander")

        except Exception as e:
            errors.append(f"Line {idx+1}: Failed to parse URI '{uri_str[:30]}...': {e}")

    return nodes, errors


class TestClashMetaYamlSchema(unittest.TestCase):
    """Tier 1 & Tier 2: Clash Meta YAML Schema & Proxy Group Hierarchy Tests."""

    def setUp(self):
        self.clash_dict = build_authoritative_clash_meta_dict()
        self.clash_yaml_str = yaml.dump(self.clash_dict, sort_keys=False, allow_unicode=True)

    def test_clash_yaml_roundtrip_and_schema(self):
        """Verify YAML dump and strict schema validation."""
        parsed = yaml.safe_load(self.clash_yaml_str)
        errors = validate_clash_meta_schema(parsed)
        self.assertEqual(errors, [], f"Clash Meta schema validation errors: {errors}")

    def test_proxy_groups_presence_and_types(self):
        """Feature 3, 4, 5: Verify select, url-test, and fallback proxy groups."""
        groups = {g["name"]: g for g in self.clash_dict["proxy-groups"]}

        self.assertIn("🚀 PROXY", groups)
        self.assertEqual(groups["🚀 PROXY"]["type"], "select")
        self.assertEqual(groups["🚀 PROXY"]["proxies"][0], "⚡ Auto URL-Test")
        self.assertEqual(groups["🚀 PROXY"]["proxies"][1], "🛡️ Priority Fallback")

        self.assertIn("⚡ Auto URL-Test", groups)
        self.assertEqual(groups["⚡ Auto URL-Test"]["type"], "url-test")
        self.assertEqual(groups["⚡ Auto URL-Test"]["interval"], 180)
        self.assertEqual(groups["⚡ Auto URL-Test"]["tolerance"], 50)
        self.assertTrue(groups["⚡ Auto URL-Test"]["lazy"])

        self.assertIn("🛡️ Priority Fallback", groups)
        self.assertEqual(groups["🛡️ Priority Fallback"]["type"], "fallback")
        self.assertEqual(groups["🛡️ Priority Fallback"]["interval"], 180)
        self.assertTrue(groups["🛡️ Priority Fallback"]["lazy"])

    def test_all_10_protocols_in_proxies_list(self):
        """Verify all 10 active protocol proxies across NL and FI are configured."""
        proxies = {p["name"]: p for p in self.clash_dict["proxies"]}
        self.assertEqual(len(proxies), 10)

        # NL Reality TCP
        nl_tcp = proxies["🇳🇱 NL Classic Reality TCP"]
        self.assertEqual(nl_tcp["type"], "vless")
        self.assertEqual(nl_tcp["servername"], CONSTANTS["TCP_REALITY_SNI_CLASSIC"])
        self.assertEqual(nl_tcp["reality-opts"]["public-key"], CONSTANTS["TCP_REALITY_PUBLIC_KEY"])
        self.assertEqual(nl_tcp["flow"], "xtls-rprx-vision")

        # FI XHTTP Reality
        fi_xhttp = proxies["🇫🇮 FI Stealth XHTTP Reality"]
        self.assertEqual(fi_xhttp["port"], CONSTANTS["FI_XHTTP_REALITY_PORT"])
        self.assertEqual(fi_xhttp["servername"], CONSTANTS["FI_XHTTP_REALITY_SNI"])
        self.assertEqual(fi_xhttp["reality-opts"]["public-key"], CONSTANTS["FI_XHTTP_REALITY_PUBLIC_KEY"])

        # NL Hysteria2
        nl_hy2 = proxies["🇳🇱 NL Speed Hysteria2"]
        self.assertEqual(nl_hy2["type"], "hysteria2")
        self.assertEqual(nl_hy2["obfs"], "gecko")
        self.assertEqual(nl_hy2["obfs-password"], CONSTANTS["HYSTERIA_SALAMANDER_PASSWORD"])

    def test_fallback_group_priority_order(self):
        """Feature 4: Verify Priority Fallback list begins with NL Classic and cascades cleanly."""
        groups = {g["name"]: g for g in self.clash_dict["proxy-groups"]}
        fallback_list = groups["🛡️ Priority Fallback"]["proxies"]

        self.assertEqual(fallback_list[0], "🇳🇱 NL Classic Reality TCP")
        self.assertEqual(fallback_list[1], "🇫🇮 FI Classic Reality TCP")
        self.assertIn("🇳🇱 NL Speed Hysteria2", fallback_list)
        self.assertIn("🇫🇮 FI Stealth XHTTP Reality", fallback_list)

    def test_clash_dns_settings(self):
        """Verify fake-ip DNS mode and fallback filter rules."""
        dns = self.clash_dict["dns"]
        self.assertTrue(dns["enable"])
        self.assertEqual(dns["enhanced-mode"], "fake-ip")
        self.assertIn("77.88.8.8", dns["nameserver"])
        self.assertTrue(dns["fallback-filter"]["geoip"])
        self.assertEqual(dns["fallback-filter"]["geoip-code"], "RU")

    def test_clash_core_options(self):
        """Verify core tuning options (unified-delay, tcp-concurrent, find-process-mode)."""
        self.assertTrue(self.clash_dict.get("unified-delay"))
        self.assertTrue(self.clash_dict.get("tcp-concurrent"))
        self.assertEqual(self.clash_dict.get("find-process-mode"), "strict")
        self.assertFalse(self.clash_dict.get("ipv6"))


class TestStreisandBase64Bundle(unittest.TestCase):
    """Tier 1, Tier 2, Tier 4: Streisand Base64 Decode & URI Bundle Parsing."""

    def setUp(self):
        self.raw_uris = build_authoritative_streisand_bundle_text()
        self.encoded_bundle = base64.b64encode(self.raw_uris.encode("utf-8")).decode("utf-8")

    def test_streisand_bundle_decode_and_node_count(self):
        """Feature 5: Verify Base64 decoding produces 10 active server URIs."""
        nodes, errors = parse_and_validate_streisand_bundle(self.encoded_bundle)
        self.assertEqual(errors, [], f"Bundle parsing errors: {errors}")
        self.assertEqual(len(nodes), 10)

    def test_streisand_deep_link_generation(self):
        """Feature 5 & Scenario 3: Verify 1-click streisand:// import link structure."""
        sub_url = "https://sub.example.com/my-secret/streisand/user-sub-123"
        encoded_name = urllib.parse.quote("SilentConnect Smart")
        deep_link = f"streisand://import/{sub_url}#{encoded_name}"

        parsed = urllib.parse.urlparse(deep_link)
        self.assertEqual(parsed.scheme, "streisand")
        self.assertEqual(parsed.netloc, "import")
        self.assertIn("my-secret/streisand/user-sub-123", parsed.path)
        self.assertEqual(urllib.parse.unquote(parsed.fragment), "SilentConnect Smart")

    def test_v2raytun_deep_link_generation(self):
        """Feature 8: Verify 1-click v2raytun:// import link structure."""
        sub_url = "https://sub.example.com/my-secret/json/user-sub-123"
        deep_link = f"v2raytun://import/{sub_url}"

        parsed = urllib.parse.urlparse(deep_link)
        self.assertEqual(parsed.scheme, "v2raytun")
        self.assertEqual(parsed.netloc, "import")
        self.assertIn("my-secret/json/user-sub-123", parsed.path)

    def test_streisand_fi_xhttp_reality_node_parameters(self):
        """Feature 7 in Streisand: Verify FI XHTTP Reality URI has port 39443 and Reality parameters."""
        nodes, errors = parse_and_validate_streisand_bundle(self.encoded_bundle)
        self.assertEqual(errors, [])

        fi_xhttp_node = next(n for n in nodes if "FI" in n["remark"] and "XHTTP" in n["remark"])
        self.assertEqual(fi_xhttp_node["scheme"], "vless")
        self.assertEqual(fi_xhttp_node["host"], CONSTANTS["FI_HOST"])
        self.assertEqual(fi_xhttp_node["port"], 39443)
        self.assertEqual(fi_xhttp_node["params"]["security"][0], "reality")
        self.assertEqual(fi_xhttp_node["params"]["pbk"][0], CONSTANTS["FI_XHTTP_REALITY_PUBLIC_KEY"])
        self.assertEqual(fi_xhttp_node["params"]["sid"][0], CONSTANTS["FI_XHTTP_REALITY_SHORT_ID"])
        self.assertEqual(fi_xhttp_node["params"]["sni"][0], CONSTANTS["FI_XHTTP_REALITY_SNI"])

    def test_streisand_unpadded_base64_resilience(self):
        """Tier 5: Verify decoder gracefully handles unpadded Base64 strings."""
        unpadded = self.encoded_bundle.rstrip("=")
        nodes, errors = parse_and_validate_streisand_bundle(unpadded)
        self.assertEqual(errors, [])
        self.assertEqual(len(nodes), 10)

    def test_streisand_remarks_encoding_and_flags(self):
        """Tier 5: Verify remarks correctly preserve emoji flags and Cyrillic annotations."""
        nodes, errors = parse_and_validate_streisand_bundle(self.encoded_bundle)
        self.assertEqual(errors, [])
        remarks = [n["remark"] for n in nodes]
        self.assertTrue(any("🇳🇱 1. Классический TCP" in r for r in remarks))
        self.assertTrue(any("🇫🇮 6. Классический TCP" in r for r in remarks))


class TestCrossFormatProtocolParity(unittest.TestCase):
    """Tier 3: Combinatorial Protocol & Node Parity Across Sing-box, Clash Meta, and Streisand."""

    def test_protocol_matrix_node_counts(self):
        """Verify each format represents exactly 5 protocols × 2 nodes = 10 endpoints."""
        singbox_cfg = build_authoritative_singbox_smart_config()
        clash_dict = build_authoritative_clash_meta_dict()
        streisand_nodes, _ = parse_and_validate_streisand_bundle(
            base64.b64encode(build_authoritative_streisand_bundle_text().encode("utf-8")).decode("utf-8")
        )

        sb_proxies = [o for o in singbox_cfg["outbounds"] if o["type"] in ("vless", "hysteria2")]
        clash_proxies = clash_dict["proxies"]

        self.assertGreaterEqual(len(sb_proxies), 10)
        self.assertEqual(len(clash_proxies), 10)
        self.assertEqual(len(streisand_nodes), 10)

    def test_nl_fi_reality_public_key_parity(self):
        """Verify Reality keys and short IDs match exactly across formats."""
        singbox_cfg = build_authoritative_singbox_smart_config()
        clash_dict = build_authoritative_clash_meta_dict()

        sb_nl_tcp = next(o for o in singbox_cfg["outbounds"] if o["tag"] == "nl-classic-tcp")
        clash_nl_tcp = next(p for p in clash_dict["proxies"] if p["name"] == "🇳🇱 NL Classic Reality TCP")

        self.assertEqual(
            sb_nl_tcp["tls"]["reality"]["public_key"],
            clash_nl_tcp["reality-opts"]["public-key"],
        )
        self.assertEqual(
            sb_nl_tcp["tls"]["reality"]["short_id"],
            clash_nl_tcp["reality-opts"]["short-id"],
        )

    def test_fi_xhttp_reality_parity_across_all_three_formats(self):
        """Feature 7: Cross-format verification of FI XHTTP Reality on port 39443."""
        singbox_cfg = build_authoritative_singbox_smart_config()
        clash_dict = build_authoritative_clash_meta_dict()
        streisand_nodes, _ = parse_and_validate_streisand_bundle(
            base64.b64encode(build_authoritative_streisand_bundle_text().encode("utf-8")).decode("utf-8")
        )

        # 1. Sing-box
        sb_fi_xhttp = next(o for o in singbox_cfg["outbounds"] if o["tag"] == "fi-stealth-xhttp")
        self.assertEqual(sb_fi_xhttp["server_port"], 39443)
        self.assertEqual(sb_fi_xhttp["tls"]["reality"]["public_key"], CONSTANTS["FI_XHTTP_REALITY_PUBLIC_KEY"])
        self.assertEqual(sb_fi_xhttp["tls"]["reality"]["short_id"], CONSTANTS["FI_XHTTP_REALITY_SHORT_ID"])

        # 2. Clash Meta
        clash_fi_xhttp = next(p for p in clash_dict["proxies"] if "FI Stealth XHTTP" in p["name"])
        self.assertEqual(clash_fi_xhttp["port"], 39443)
        self.assertEqual(clash_fi_xhttp["reality-opts"]["public-key"], CONSTANTS["FI_XHTTP_REALITY_PUBLIC_KEY"])
        self.assertEqual(clash_fi_xhttp["reality-opts"]["short-id"], CONSTANTS["FI_XHTTP_REALITY_SHORT_ID"])

        # 3. Streisand
        st_fi_xhttp = next(n for n in streisand_nodes if "FI" in n["remark"] and "XHTTP" in n["remark"])
        self.assertEqual(st_fi_xhttp["port"], 39443)
        self.assertEqual(st_fi_xhttp["params"]["pbk"][0], CONSTANTS["FI_XHTTP_REALITY_PUBLIC_KEY"])
        self.assertEqual(st_fi_xhttp["params"]["sid"][0], CONSTANTS["FI_XHTTP_REALITY_SHORT_ID"])


class TestAdversarialClientFormatEdgeCases(unittest.TestCase):
    """Tier 5: Adversarial edge cases, invalid combinations, and corrupt inputs."""

    def test_corrupt_yaml_detection(self):
        """Assert validator detects corrupt / missing proxy group in Clash Meta."""
        bad_clash = build_authoritative_clash_meta_dict()
        bad_clash["proxy-groups"] = [g for g in bad_clash["proxy-groups"] if g["name"] != "⚡ Auto URL-Test"]
        errors = validate_clash_meta_schema(bad_clash)
        self.assertTrue(any("⚡ Auto URL-Test" in e for e in errors))

    def test_invalid_streisand_uri_detection(self):
        """Assert validator detects missing Reality PBK in Streisand VLESS URI."""
        bad_raw = "vless://user@edge.example.com:443?type=tcp&security=reality#CorruptNode\n"
        encoded = base64.b64encode(bad_raw.encode("utf-8")).decode("utf-8")
        _, errors = parse_and_validate_streisand_bundle(encoded)
        self.assertTrue(any("Missing 'pbk'" in e for e in errors))

    def test_duplicate_proxy_names_in_clash(self):
        """Assert validator flags duplicate proxy names in Clash Meta."""
        bad_clash = build_authoritative_clash_meta_dict()
        bad_clash["proxies"].append(copy.deepcopy(bad_clash["proxies"][0]))
        errors = validate_clash_meta_schema(bad_clash)
        self.assertTrue(any("Duplicate proxy name" in e for e in errors))

    def test_streisand_missing_salamander_password(self):
        """Assert validator flags missing Salamander password in Streisand hy2 URI."""
        bad_raw = "hy2://user@sub.example.com:443?sni=sub.example.com&alpn=h3&obfs=salamander#BadHy2\n"
        encoded = base64.b64encode(bad_raw.encode("utf-8")).decode("utf-8")
        _, errors = parse_and_validate_streisand_bundle(encoded)
        self.assertTrue(any("Missing 'obfs-password'" in e for e in errors))

    def test_clash_missing_final_match_rule(self):
        """Assert validator flags missing MATCH rule in Clash Meta rules list."""
        bad_clash = build_authoritative_clash_meta_dict()
        bad_clash["rules"] = [r for r in bad_clash["rules"] if not r.startswith("MATCH")]
        errors = validate_clash_meta_schema(bad_clash)
        self.assertTrue(any("MATCH,🚀 PROXY" in e for e in errors))


if __name__ == "__main__":
    unittest.main(verbosity=2)
