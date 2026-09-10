"""
Unit and E2E Test Suite for SilentConnect Smart Auto-Selector and Sing-box Configurations.
Validates Sing-box 1.8+ schema compliance, two-tier proxy group hierarchy,
HTTP 204 healthchecks, and protocol definitions across NL and FI nodes.
"""

import copy
import ipaddress
import json
import os
import sys
import unittest
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Authoritative Protocol and Key Constants
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
    "HTTP_204_GOOGLE": "https://www.google.com/generate_204",
    "HEALTHCHECK_INTERVAL": "3m",
    "HEALTHCHECK_IDLE_TIMEOUT": "15m",
    "HEALTHCHECK_TOLERANCE": 50,
    "NL_HOST": "edge.example.com",
    "NL_SUB_HOST": "sub.example.com",
    "FI_HOST": "fi.example.com",
    "TEST_UUID": "9c3d7f1e-4b8a-4c2d-9e1f-8a2b3c4d5e6f",
    "WS_PATH": "/sc-ws-9c3d7f1e",
}


def build_authoritative_singbox_smart_config(
    client_uuid: str = CONSTANTS["TEST_UUID"],
    healthcheck_url: str = CONSTANTS["HTTP_204_CLOUDFLARE"],
    route_mode: str = "split-ru",
) -> Dict[str, Any]:
    """Generates the reference authoritative Sing-box smart auto-selector config."""
    route_rules = [
        {"protocol": "dns", "outbound": "dns-out"},
        {"ip_is_private": True, "outbound": "direct"},
        {"protocol": "bittorrent", "outbound": "direct"},
    ]
    if route_mode == "split-ru":
        route_rules.extend(
            [
                {
                    "domain_suffix": [
                        "ru",
                        "su",
                        "xn--p1ai",
                        "gosuslugi.ru",
                        "sberbank.ru",
                        "tinkoff.ru",
                        "yandex.ru",
                        "vk.com",
                        "avito.ru",
                        "ozon.ru",
                        "wildberries.ru",
                        "railnation.ru",
                        "railnation-game.ru",
                    ],
                    "outbound": "direct",
                },
                {"geoip": "ru", "outbound": "direct"},
            ]
        )

    return {
        "log": {
            "level": "warn",
            "timestamp": True,
        },
        "dns": {
            "servers": [
                {
                    "tag": "dns-remote",
                    "address": "https://1.1.1.1/dns-query",
                    "address_resolver": "dns-direct",
                    "strategy": "prefer_ipv4",
                    "detour": "proxy-selector",
                },
                {
                    "tag": "dns-direct",
                    "address": "https://77.88.8.8/dns-query",
                    "strategy": "prefer_ipv4",
                    "detour": "direct",
                },
                {
                    "tag": "dns-block",
                    "address": "rcode://success",
                },
            ],
            "rules": [
                {"outbound": "any", "server": "dns-direct"},
                {"clash_mode": "Direct", "server": "dns-direct"},
                {"clash_mode": "Global", "server": "dns-remote"},
                {"geosite": "category-ads-all", "server": "dns-block"},
                {"geosite": "ru", "server": "dns-direct"},
            ],
            "final": "dns-remote",
            "strategy": "prefer_ipv4",
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "sing-tun",
                "inet4_address": "172.19.0.1/30",
                "auto_route": True,
                "strict_route": True,
                "stack": "mixed",
                "sniff": True,
                "sniff_override_destination": True,
            },
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 20808,
                "sniff": True,
            },
        ],
        "outbounds": [
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
                "url": healthcheck_url,
                "interval": CONSTANTS["HEALTHCHECK_INTERVAL"],
                "idle_timeout": CONSTANTS["HEALTHCHECK_IDLE_TIMEOUT"],
                "tolerance": CONSTANTS["HEALTHCHECK_TOLERANCE"],
                "interrupt_exist_connections": False,
            },
            {
                "type": "vless",
                "tag": "nl-classic-tcp",
                "server": CONSTANTS["NL_HOST"],
                "server_port": 443,
                "uuid": client_uuid,
                "flow": "xtls-rprx-vision",
                "tls": {
                    "enabled": True,
                    "server_name": CONSTANTS["TCP_REALITY_SNI_CLASSIC"],
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "reality": {
                        "enabled": True,
                        "public_key": CONSTANTS["TCP_REALITY_PUBLIC_KEY"],
                        "short_id": CONSTANTS["TCP_REALITY_SHORT_ID"],
                    },
                },
                "packet_encoding": "xudp",
            },
            {
                "type": "vless",
                "tag": "nl-fast-tcp",
                "server": CONSTANTS["NL_HOST"],
                "server_port": 443,
                "uuid": client_uuid,
                "flow": "xtls-rprx-vision",
                "tls": {
                    "enabled": True,
                    "server_name": CONSTANTS["TCP_REALITY_SNI_FAST"],
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "reality": {
                        "enabled": True,
                        "public_key": CONSTANTS["TCP_REALITY_PUBLIC_KEY"],
                        "short_id": CONSTANTS["TCP_REALITY_SHORT_ID"],
                    },
                },
                "packet_encoding": "xudp",
            },
            {
                "type": "hysteria2",
                "tag": "nl-speed-hysteria2",
                "server": CONSTANTS["NL_SUB_HOST"],
                "server_port": 443,
                "password": client_uuid,
                "tls": {
                    "enabled": True,
                    "server_name": CONSTANTS["NL_SUB_HOST"],
                    "alpn": ["h3"],
                },
                "obfs": {
                    "type": "salamander",
                    "password": CONSTANTS["HYSTERIA_SALAMANDER_PASSWORD"],
                },
            },
            {
                "type": "vless",
                "tag": "nl-backup-grpc",
                "server": CONSTANTS["NL_HOST"],
                "server_port": 29443,
                "uuid": client_uuid,
                "transport": {
                    "type": "grpc",
                    "service_name": CONSTANTS["GRPC_SERVICE_NAME"],
                    "idle_timeout": "15s",
                    "ping_timeout": "15s",
                },
                "tls": {
                    "enabled": True,
                    "server_name": CONSTANTS["GRPC_REALITY_SNI"],
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "reality": {
                        "enabled": True,
                        "public_key": CONSTANTS["GRPC_REALITY_PUBLIC_KEY"],
                        "short_id": CONSTANTS["GRPC_REALITY_SHORT_ID"],
                    },
                },
                "packet_encoding": "xudp",
            },
            {
                "type": "vless",
                "tag": "nl-stealth-xhttp",
                "server": CONSTANTS["NL_HOST"],
                "server_port": 443,
                "uuid": client_uuid,
                "transport": {
                    "type": "http",
                    "host": [CONSTANTS["NL_HOST"]],
                    "path": "/xh-mx-d1f7c0429d6a",
                    "method": "POST",
                },
                "tls": {
                    "enabled": True,
                    "server_name": CONSTANTS["NL_HOST"],
                    "alpn": ["h2", "http/1.1"],
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                },
                "packet_encoding": "xudp",
            },
            {
                "type": "vless",
                "tag": "fi-classic-tcp",
                "server": CONSTANTS["FI_HOST"],
                "server_port": 443,
                "uuid": client_uuid,
                "flow": "xtls-rprx-vision",
                "tls": {
                    "enabled": True,
                    "server_name": CONSTANTS["TCP_REALITY_SNI_CLASSIC"],
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "reality": {
                        "enabled": True,
                        "public_key": CONSTANTS["TCP_REALITY_PUBLIC_KEY"],
                        "short_id": CONSTANTS["TCP_REALITY_SHORT_ID"],
                    },
                },
                "packet_encoding": "xudp",
            },
            {
                "type": "vless",
                "tag": "fi-fast-tcp",
                "server": CONSTANTS["FI_HOST"],
                "server_port": 443,
                "uuid": client_uuid,
                "flow": "xtls-rprx-vision",
                "tls": {
                    "enabled": True,
                    "server_name": CONSTANTS["TCP_REALITY_SNI_FAST"],
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "reality": {
                        "enabled": True,
                        "public_key": CONSTANTS["TCP_REALITY_PUBLIC_KEY"],
                        "short_id": CONSTANTS["TCP_REALITY_SHORT_ID"],
                    },
                },
                "packet_encoding": "xudp",
            },
            {
                "type": "hysteria2",
                "tag": "fi-speed-hysteria2",
                "server": CONSTANTS["FI_HOST"],
                "server_port": 443,
                "password": client_uuid,
                "tls": {
                    "enabled": True,
                    "server_name": CONSTANTS["FI_HOST"],
                    "alpn": ["h3"],
                },
                "obfs": {
                    "type": "salamander",
                    "password": CONSTANTS["HYSTERIA_SALAMANDER_PASSWORD"],
                },
            },
            {
                "type": "vless",
                "tag": "fi-backup-grpc",
                "server": CONSTANTS["FI_HOST"],
                "server_port": 29443,
                "uuid": client_uuid,
                "transport": {
                    "type": "grpc",
                    "service_name": CONSTANTS["GRPC_SERVICE_NAME"],
                    "idle_timeout": "15s",
                    "ping_timeout": "15s",
                },
                "tls": {
                    "enabled": True,
                    "server_name": CONSTANTS["GRPC_REALITY_SNI"],
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "reality": {
                        "enabled": True,
                        "public_key": CONSTANTS["GRPC_REALITY_PUBLIC_KEY"],
                        "short_id": CONSTANTS["GRPC_REALITY_SHORT_ID"],
                    },
                },
                "packet_encoding": "xudp",
            },
            {
                "type": "vless",
                "tag": "fi-stealth-xhttp",
                "server": CONSTANTS["FI_HOST"],
                "server_port": CONSTANTS["FI_XHTTP_REALITY_PORT"],
                "uuid": client_uuid,
                "transport": {
                    "type": "http",
                    "host": [CONSTANTS["FI_HOST"]],
                    "path": "/xh-mx-d1f7c0429d6a",
                    "method": "POST",
                },
                "tls": {
                    "enabled": True,
                    "server_name": CONSTANTS["FI_XHTTP_REALITY_SNI"],
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "reality": {
                        "enabled": True,
                        "public_key": CONSTANTS["FI_XHTTP_REALITY_PUBLIC_KEY"],
                        "short_id": CONSTANTS["FI_XHTTP_REALITY_SHORT_ID"],
                    },
                },
                "packet_encoding": "xudp",
            },
            {
                "type": "vless",
                "tag": "nl-ws443",
                "server": CONSTANTS["NL_SUB_HOST"],
                "server_port": 443,
                "uuid": client_uuid,
                "transport": {
                    "type": "ws",
                    "path": CONSTANTS["WS_PATH"],
                    "headers": {"Host": CONSTANTS["NL_SUB_HOST"]},
                },
                "tls": {
                    "enabled": True,
                    "server_name": CONSTANTS["NL_SUB_HOST"],
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                },
                "packet_encoding": "xudp",
            },
            {
                "type": "vless",
                "tag": "fi-ws443",
                "server": CONSTANTS["FI_HOST"],
                "server_port": 443,
                "uuid": client_uuid,
                "transport": {
                    "type": "ws",
                    "path": CONSTANTS["WS_PATH"],
                    "headers": {"Host": CONSTANTS["FI_HOST"]},
                },
                "tls": {
                    "enabled": True,
                    "server_name": CONSTANTS["FI_HOST"],
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                },
                "packet_encoding": "xudp",
            },
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
            {"type": "dns", "tag": "dns-out"},
        ],
        "route": {
            "auto_detect_interface": True,
            "rules": route_rules,
            "final": "proxy-selector",
        },
        "experimental": {
            "cache_file": {
                "enabled": True,
                "path": "cache.db",
                "store_fakeip": False,
            }
        },
    }


def validate_singbox_schema(config: Dict[str, Any]) -> List[str]:
    """Strict schema validator for Sing-box smart auto-selector configuration.
    Returns a list of validation error descriptions (empty if valid)."""
    errors = []

    # 1. Required top-level keys
    for req_key in ("log", "dns", "inbounds", "outbounds", "route"):
        if req_key not in config:
            errors.append(f"Missing required root key: '{req_key}'")

    if errors:
        return errors

    # 2. Outbounds list checks
    outbounds = config.get("outbounds")
    if not isinstance(outbounds, list):
        errors.append("'outbounds' must be a list")
        return errors

    outbound_tags = {o.get("tag"): o for o in outbounds if isinstance(o, dict) and o.get("tag")}
    if len(outbound_tags) != len(outbounds):
        errors.append("Duplicate or missing 'tag' found in outbounds list")

    # 3. Assert proxy-selector group
    selector = outbound_tags.get("proxy-selector")
    if not selector:
        errors.append("Missing 'proxy-selector' outbound")
    else:
        if selector.get("type") != "selector":
            errors.append(f"'proxy-selector' must be of type 'selector', got '{selector.get('type')}'")
        if selector.get("default") != "auto-urltest":
            errors.append(f"'proxy-selector' default must be 'auto-urltest', got '{selector.get('default')}'")
        selector_outbounds = selector.get("outbounds", [])
        if not isinstance(selector_outbounds, list) or not selector_outbounds:
            errors.append("'proxy-selector.outbounds' must be a non-empty list")
        elif selector_outbounds[0] != "auto-urltest":
            errors.append(f"First item in 'proxy-selector.outbounds' must be 'auto-urltest', got '{selector_outbounds[0]}'")

    # 4. Assert auto-urltest group
    urltest = outbound_tags.get("auto-urltest")
    if not urltest:
        errors.append("Missing 'auto-urltest' outbound")
    else:
        if urltest.get("type") != "urltest":
            errors.append(f"'auto-urltest' must be of type 'urltest', got '{urltest.get('type')}'")
        url = urltest.get("url", "")
        if not url.startswith("https://") or "generate_204" not in url:
            errors.append(f"'auto-urltest.url' must be an HTTP 204 endpoint, got '{url}'")
        if urltest.get("interval") not in ("3m", "180s", "180"):
            errors.append(f"'auto-urltest.interval' expected '3m', got '{urltest.get('interval')}'")
        if urltest.get("idle_timeout") not in ("15m", "900s", "900"):
            errors.append(f"'auto-urltest.idle_timeout' expected '15m', got '{urltest.get('idle_timeout')}'")
        if urltest.get("tolerance") != 50:
            errors.append(f"'auto-urltest.tolerance' expected 50, got '{urltest.get('tolerance')}'")
        if urltest.get("interrupt_exist_connections") is not False:
            errors.append(f"'auto-urltest.interrupt_exist_connections' expected False, got '{urltest.get('interrupt_exist_connections')}'")

        pool = urltest.get("outbounds", [])
        if not isinstance(pool, list) or len(pool) < 2:
            errors.append(f"'auto-urltest.outbounds' must contain at least 2 node tags, found {len(pool)}")
        for member_tag in pool:
            if member_tag not in outbound_tags:
                errors.append(f"'auto-urltest' references undefined outbound tag: '{member_tag}'")

    # 5. Assert Protocol Nodes
    expected_protocols = [
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
    ]
    for proto_tag in expected_protocols:
        if proto_tag not in outbound_tags:
            errors.append(f"Missing expected protocol node outbound: '{proto_tag}'")

    # 6. Route checks
    route = config.get("route", {})
    if route.get("final") != "proxy-selector":
        errors.append(f"'route.final' must route to 'proxy-selector', got '{route.get('final')}'")

    return errors


class TestSingboxSmartSelectorSchema(unittest.TestCase):
    """Tier 1 & Tier 2: Sing-box JSON Schema and Smart Selector Hierarchy Tests."""

    def setUp(self):
        self.config = build_authoritative_singbox_smart_config()

    def test_schema_passes_strict_validation(self):
        """Verify that authoritative smart selector config passes all validation rules."""
        errors = validate_singbox_schema(self.config)
        self.assertEqual(errors, [], f"Schema validation failed: {errors}")

    def test_proxy_selector_group_hierarchy(self):
        """Feature 2: Verify selector group properties and default auto-urltest."""
        outbounds = {o["tag"]: o for o in self.config["outbounds"]}
        selector = outbounds["proxy-selector"]

        self.assertEqual(selector["type"], "selector")
        self.assertEqual(selector["default"], "auto-urltest")
        self.assertIn("auto-urltest", selector["outbounds"])
        self.assertEqual(selector["outbounds"][0], "auto-urltest")
        self.assertIn("nl-classic-tcp", selector["outbounds"])
        self.assertIn("fi-classic-tcp", selector["outbounds"])
        self.assertIn("direct", selector["outbounds"])

    def test_auto_urltest_parameters(self):
        """Feature 1 & Feature 6: Verify urltest group healthcheck parameters."""
        outbounds = {o["tag"]: o for o in self.config["outbounds"]}
        urltest = outbounds["auto-urltest"]

        self.assertEqual(urltest["type"], "urltest")
        self.assertEqual(urltest["url"], CONSTANTS["HTTP_204_CLOUDFLARE"])
        self.assertEqual(urltest["interval"], "3m")
        self.assertEqual(urltest["idle_timeout"], "15m")
        self.assertEqual(urltest["tolerance"], 50)
        self.assertFalse(urltest.get("interrupt_exist_connections", True))
        self.assertGreaterEqual(len(urltest["outbounds"]), 10)

    def test_fi_xhttp_reality_port_and_security(self):
        """Feature 7: Verify FI XHTTP Reality on Port 39443 to bypass TSPU throttling."""
        outbounds = {o["tag"]: o for o in self.config["outbounds"]}
        fi_xhttp = outbounds["fi-stealth-xhttp"]

        self.assertEqual(fi_xhttp["type"], "vless")
        self.assertEqual(fi_xhttp["server"], CONSTANTS["FI_HOST"])
        self.assertEqual(fi_xhttp["server_port"], 39443)
        self.assertTrue(fi_xhttp["tls"]["enabled"])
        self.assertEqual(fi_xhttp["tls"]["server_name"], CONSTANTS["FI_XHTTP_REALITY_SNI"])
        self.assertTrue(fi_xhttp["tls"]["reality"]["enabled"])
        self.assertEqual(fi_xhttp["tls"]["reality"]["public_key"], CONSTANTS["FI_XHTTP_REALITY_PUBLIC_KEY"])
        self.assertEqual(fi_xhttp["tls"]["reality"]["short_id"], CONSTANTS["FI_XHTTP_REALITY_SHORT_ID"])
        self.assertEqual(fi_xhttp["transport"]["type"], "http")
        self.assertEqual(fi_xhttp["transport"]["path"], "/xh-mx-d1f7c0429d6a")

    def test_nl_xhttp_caddy_tls(self):
        """Verify NL XHTTP configuration over standard Caddy TLS on Port 443."""
        outbounds = {o["tag"]: o for o in self.config["outbounds"]}
        nl_xhttp = outbounds["nl-stealth-xhttp"]

        self.assertEqual(nl_xhttp["type"], "vless")
        self.assertEqual(nl_xhttp["server"], CONSTANTS["NL_HOST"])
        self.assertEqual(nl_xhttp["server_port"], 443)
        self.assertTrue(nl_xhttp["tls"]["enabled"])
        self.assertEqual(nl_xhttp["tls"]["server_name"], CONSTANTS["NL_HOST"])
        self.assertIn("h2", nl_xhttp["tls"]["alpn"])
        self.assertEqual(nl_xhttp["transport"]["path"], "/xh-mx-d1f7c0429d6a")

    def test_reality_tcp_classic_and_fast_nodes(self):
        """Verify Reality TCP Classic (sber.ru) and Fast (st.kinopoisk.ru) for NL and FI."""
        outbounds = {o["tag"]: o for o in self.config["outbounds"]}

        # NL Classic
        nl_classic = outbounds["nl-classic-tcp"]
        self.assertEqual(nl_classic["flow"], "xtls-rprx-vision")
        self.assertEqual(nl_classic["tls"]["server_name"], "sber.ru")
        self.assertEqual(nl_classic["tls"]["reality"]["public_key"], CONSTANTS["TCP_REALITY_PUBLIC_KEY"])

        # NL Fast
        nl_fast = outbounds["nl-fast-tcp"]
        self.assertEqual(nl_fast["flow"], "xtls-rprx-vision")
        self.assertEqual(nl_fast["tls"]["server_name"], "st.kinopoisk.ru")

        # FI Classic
        fi_classic = outbounds["fi-classic-tcp"]
        self.assertEqual(fi_classic["server"], CONSTANTS["FI_HOST"])
        self.assertEqual(fi_classic["tls"]["server_name"], "sber.ru")

        # FI Fast
        fi_fast = outbounds["fi-fast-tcp"]
        self.assertEqual(fi_fast["server"], CONSTANTS["FI_HOST"])
        self.assertEqual(fi_fast["tls"]["server_name"], "st.kinopoisk.ru")

    def test_hysteria2_with_salamander_obfs(self):
        """Verify Hysteria 2 UDP protocol with Salamander obfuscation on NL and FI."""
        outbounds = {o["tag"]: o for o in self.config["outbounds"]}

        for tag, expected_host in [("nl-speed-hysteria2", CONSTANTS["NL_SUB_HOST"]), ("fi-speed-hysteria2", CONSTANTS["FI_HOST"])]:
            hy2 = outbounds[tag]
            self.assertEqual(hy2["type"], "hysteria2")
            self.assertEqual(hy2["server"], expected_host)
            self.assertEqual(hy2["server_port"], 443)
            self.assertEqual(hy2["tls"]["alpn"], ["h3"])
            self.assertEqual(hy2["obfs"]["type"], "salamander")
            self.assertEqual(hy2["obfs"]["password"], CONSTANTS["HYSTERIA_SALAMANDER_PASSWORD"])

    def test_reality_grpc_nodes(self):
        """Verify Reality gRPC configurations on port 29443 for NL and FI."""
        outbounds = {o["tag"]: o for o in self.config["outbounds"]}

        for tag, expected_host in [("nl-backup-grpc", CONSTANTS["NL_HOST"]), ("fi-backup-grpc", CONSTANTS["FI_HOST"])]:
            grpc_node = outbounds[tag]
            self.assertEqual(grpc_node["server"], expected_host)
            self.assertEqual(grpc_node["server_port"], 29443)
            self.assertEqual(grpc_node["transport"]["type"], "grpc")
            self.assertEqual(grpc_node["transport"]["service_name"], "grpc-maxru")
            self.assertEqual(grpc_node["tls"]["server_name"], "vk.com")
            self.assertEqual(grpc_node["tls"]["reality"]["public_key"], CONSTANTS["GRPC_REALITY_PUBLIC_KEY"])

    def test_ws443_fallback_nodes(self):
        """Verify WS443 WebSocket fallback configurations for NL and FI."""
        outbounds = {o["tag"]: o for o in self.config["outbounds"]}

        self.assertIn("nl-ws443", outbounds)
        self.assertIn("fi-ws443", outbounds)

        nl_ws = outbounds["nl-ws443"]
        self.assertEqual(nl_ws["transport"]["type"], "ws")
        self.assertEqual(nl_ws["transport"]["path"], CONSTANTS["WS_PATH"])
        self.assertEqual(nl_ws["server_port"], 443)

        fi_ws = outbounds["fi-ws443"]
        self.assertEqual(fi_ws["transport"]["type"], "ws")
        self.assertEqual(fi_ws["transport"]["path"], CONSTANTS["WS_PATH"])
        self.assertEqual(fi_ws["server"], CONSTANTS["FI_HOST"])

    def test_inbounds_structure(self):
        """Verify TUN and mixed inbounds are properly declared without port collision."""
        inbounds = self.config["inbounds"]
        inbound_types = [ib["type"] for ib in inbounds]
        self.assertIn("tun", inbound_types)
        self.assertIn("mixed", inbound_types)

        tun_ib = next(ib for ib in inbounds if ib["type"] == "tun")
        self.assertTrue(tun_ib.get("auto_route"))
        self.assertTrue(tun_ib.get("strict_route"))
        self.assertEqual(tun_ib.get("stack"), "mixed")

    def test_dns_and_route_rules(self):
        """Verify DNS detours and split-routing rules."""
        dns = self.config["dns"]
        remote_dns = next(s for s in dns["servers"] if s["tag"] == "dns-remote")
        self.assertEqual(remote_dns["detour"], "proxy-selector")

        route = self.config["route"]
        self.assertEqual(route["final"], "proxy-selector")

        # Verify RU bypass domains exist in rules
        rules = route["rules"]
        direct_rules = [r for r in rules if r.get("outbound") == "direct"]
        self.assertTrue(any("ru" in r.get("domain_suffix", []) for r in direct_rules))
        self.assertTrue(any(r.get("geoip") == "ru" for r in direct_rules))
        self.assertTrue(any(r.get("ip_is_private") is True for r in direct_rules))

    def test_global_route_mode(self):
        """Tier 4: Verify Global route mode omits RU bypass rules and routes all traffic to proxy."""
        global_cfg = build_authoritative_singbox_smart_config(route_mode="global")
        rules = global_cfg["route"]["rules"]
        direct_rules = [r for r in rules if r.get("outbound") == "direct"]
        self.assertFalse(any("ru" in r.get("domain_suffix", []) for r in direct_rules))
        self.assertEqual(global_cfg["route"]["final"], "proxy-selector")

    def test_cache_file_experimental_settings(self):
        """Verify experimental cache_file configuration for Sing-box."""
        exp = self.config.get("experimental", {})
        cache = exp.get("cache_file", {})
        self.assertTrue(cache.get("enabled"))
        self.assertEqual(cache.get("path"), "cache.db")
        self.assertFalse(cache.get("store_fakeip"))


class TestSingboxBoundaryAndAdversarial(unittest.TestCase):
    """Tier 2 & Tier 5: Boundary Values, Mutation Testing, and Error Detection."""

    def test_detect_missing_required_root_keys(self):
        """Assert validator catches missing root keys."""
        for key in ("log", "dns", "inbounds", "outbounds", "route"):
            bad_cfg = build_authoritative_singbox_smart_config()
            del bad_cfg[key]
            errors = validate_singbox_schema(bad_cfg)
            self.assertTrue(any(key in e for e in errors), f"Failed to detect missing root key: {key}")

    def test_detect_missing_proxy_selector(self):
        """Assert validator catches missing or invalid proxy-selector."""
        bad_cfg = build_authoritative_singbox_smart_config()
        bad_cfg["outbounds"] = [o for o in bad_cfg["outbounds"] if o["tag"] != "proxy-selector"]
        errors = validate_singbox_schema(bad_cfg)
        self.assertTrue(any("proxy-selector" in e for e in errors))

    def test_detect_invalid_urltest_interval(self):
        """Assert validator rejects improper interval formats."""
        bad_cfg = build_authoritative_singbox_smart_config()
        for o in bad_cfg["outbounds"]:
            if o["tag"] == "auto-urltest":
                o["interval"] = "invalid_interval"
        errors = validate_singbox_schema(bad_cfg)
        self.assertTrue(any("interval" in e for e in errors))

    def test_detect_invalid_tolerance(self):
        """Assert validator rejects tolerance outside expected 50ms."""
        bad_cfg = build_authoritative_singbox_smart_config()
        for o in bad_cfg["outbounds"]:
            if o["tag"] == "auto-urltest":
                o["tolerance"] = 9999
        errors = validate_singbox_schema(bad_cfg)
        self.assertTrue(any("tolerance" in e for e in errors))

    def test_detect_non_204_healthcheck_url(self):
        """Assert validator rejects non-204 URLs (e.g. standard html page)."""
        bad_cfg = build_authoritative_singbox_smart_config()
        for o in bad_cfg["outbounds"]:
            if o["tag"] == "auto-urltest":
                o["url"] = "https://example.com/index.html"
        errors = validate_singbox_schema(bad_cfg)
        self.assertTrue(any("HTTP 204" in e for e in errors))

    def test_detect_dangling_outbound_reference(self):
        """Assert validator detects when urltest points to an undefined outbound tag."""
        bad_cfg = build_authoritative_singbox_smart_config()
        for o in bad_cfg["outbounds"]:
            if o["tag"] == "auto-urltest":
                o["outbounds"].append("ghost-node-404")
        errors = validate_singbox_schema(bad_cfg)
        self.assertTrue(any("ghost-node-404" in e for e in errors))

    def test_duplicate_outbound_tags_rejected(self):
        """Assert duplicate tags in outbounds list are flagged as errors."""
        bad_cfg = build_authoritative_singbox_smart_config()
        bad_cfg["outbounds"].append(copy.deepcopy(bad_cfg["outbounds"][2]))
        errors = validate_singbox_schema(bad_cfg)
        self.assertTrue(any("Duplicate" in e for e in errors))

    def test_missing_protocol_node_detection(self):
        """Assert validator flags when an active protocol node is missing from outbounds."""
        bad_cfg = build_authoritative_singbox_smart_config()
        bad_cfg["outbounds"] = [o for o in bad_cfg["outbounds"] if o["tag"] != "fi-stealth-xhttp"]
        errors = validate_singbox_schema(bad_cfg)
        self.assertTrue(any("fi-stealth-xhttp" in e for e in errors))

    def test_non_list_outbounds_rejected(self):
        """Assert validator rejects outbounds field if it is not a list."""
        bad_cfg = build_authoritative_singbox_smart_config()
        bad_cfg["outbounds"] = {"invalid": "dict_instead_of_list"}
        errors = validate_singbox_schema(bad_cfg)
        self.assertTrue(any("must be a list" in e for e in errors))


class TestHTTP204EndpointValidation(unittest.TestCase):
    """Feature 6 & Tier 4: Real and Mock HTTP 204 Healthcheck Endpoint Validation."""

    def test_cloudflare_and_google_204_url_formats(self):
        """Verify URL string and scheme properties."""
        cf_url = CONSTANTS["HTTP_204_CLOUDFLARE"]
        gg_url = CONSTANTS["HTTP_204_GOOGLE"]

        parsed_cf = urllib.parse.urlparse(cf_url)
        self.assertEqual(parsed_cf.scheme, "https")
        self.assertEqual(parsed_cf.netloc, "cp.cloudflare.com")
        self.assertEqual(parsed_cf.path, "/generate_204")

        parsed_gg = urllib.parse.urlparse(gg_url)
        self.assertEqual(parsed_gg.scheme, "https")
        self.assertEqual(parsed_gg.netloc, "www.google.com")
        self.assertEqual(parsed_gg.path, "/generate_204")

    @patch("urllib.request.urlopen")
    def test_http_204_mock_success_response(self, mock_urlopen):
        """Simulate HTTP 204 response parsing."""
        mock_resp = MagicMock()
        mock_resp.status = 204
        mock_resp.read.return_value = b""
        mock_resp.getcode.return_value = 204
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        req = urllib.request.Request(
            CONSTANTS["HTTP_204_CLOUDFLARE"],
            headers={"User-Agent": "SilentConnect-HealthCheck/1.0"},
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            self.assertEqual(resp.getcode(), 204)
            self.assertEqual(resp.read(), b"")

    @patch("urllib.request.urlopen")
    def test_http_204_mock_error_handling(self, mock_urlopen):
        """Simulate network timeout or HTTP 500 failure during healthcheck."""
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url=CONSTANTS["HTTP_204_CLOUDFLARE"],
            code=503,
            msg="Service Unavailable",
            hdrs={},
            fp=None,
        )

        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(CONSTANTS["HTTP_204_CLOUDFLARE"], timeout=3)
        self.assertEqual(cm.exception.code, 503)

    @patch("urllib.request.urlopen")
    def test_http_204_google_endpoint(self, mock_urlopen):
        """Verify Google 204 endpoint alternative."""
        mock_resp = MagicMock()
        mock_resp.status = 204
        mock_resp.read.return_value = b""
        mock_resp.getcode.return_value = 204
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        req = urllib.request.Request(
            CONSTANTS["HTTP_204_GOOGLE"],
            headers={"User-Agent": "SilentConnect-HealthCheck/1.0"},
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            self.assertEqual(resp.getcode(), 204)


class TestHappHeadersAndMeta(unittest.TestCase):
    """Tier 4 & Tier 5: Happ Subscription Headers & Response Metadata."""

    def test_happ_headers_structure(self):
        """Verify headers required by Happ iOS/Android clients."""
        headers = {
            "profile-title": "SilentConnect",
            "profile-update-interval": "1",
            "subscription-userinfo": "upload=1024; download=2048; total=536870912000; expire=1790000000",
            "profile-web-page-url": "https://example.com",
            "tun-enable": "1",
            "server-address-resolve-enable": "1",
            "fragmentation-enable": "1",
            "per-app-proxy-mode": "off",
        }

        self.assertEqual(headers["profile-title"], "SilentConnect")
        self.assertEqual(headers["profile-update-interval"], "1")
        self.assertEqual(headers["tun-enable"], "1")
        self.assertIn("total=", headers["subscription-userinfo"])
        self.assertIn("expire=", headers["subscription-userinfo"])

    def test_happ_userinfo_quota_parsing(self):
        """Verify subscription-userinfo header byte conversion and formatting."""
        raw_userinfo = "upload=1073741824; download=5368709120; total=536870912000; expire=1790000000"
        parts = dict(item.split("=") for item in raw_userinfo.split("; "))
        self.assertEqual(int(parts["upload"]), 1073741824)
        self.assertEqual(int(parts["download"]), 5368709120)
        self.assertEqual(int(parts["total"]), 500 * 1024 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main(verbosity=2)
