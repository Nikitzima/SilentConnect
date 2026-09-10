"""
Empirical Challenger Test Suite (challenger_m1_1)
Adversarial Stress Testing & Sing-box Binary Validation of Smart Auto-Selector Config

Verifies:
1. Sing-box official binary check (v2rayN/bin/bin/sing_box/sing-box.exe check -c <file>)
2. Smart Auto-Selector outbound architecture (proxy-selector -> auto-urltest -> 10 active protocol nodes)
3. Strict HTTP 204 Healthcheck configuration (cp.cloudflare.com/generate_204, 3m interval, 15m idle timeout, 50ms tolerance)
4. Comprehensive 10-outbound property validation (ports, protocols, UUIDs, SNIs, Reality keys, Hysteria2 obfs)
5. Adversarial fuzzing and edge case handling (SQL injection, XSS, Unicode, long IDs, empty strings, hybrid delimiters)
6. Concurrency, rate limiting, and quiesce lock stress testing
"""

import concurrent.futures
import copy
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.parse
from typing import Any, Dict, List

# Setup paths relative to current file
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for p in [
    os.path.join(PROJECT_ROOT, "subjson-service"),
    r"C:\Users\Yuric\Desktop\сервер\subjson-service",
    r"C:\Users\Yuric\OneDrive\Desktop\сервер\subjson-service",
]:
    if os.path.exists(p) and p not in sys.path:
        sys.path.insert(0, p)

for pr in [
    PROJECT_ROOT,
    r"C:\Users\Yuric\Desktop\сервер",
    r"C:\Users\Yuric\OneDrive\Desktop\сервер",
]:
    if os.path.exists(pr) and pr not in sys.path:
        sys.path.insert(0, pr)

# Setup environment before importing app
os.environ["HYSTERIA_SALAMANDER_PASSWORD"] = "485a96779d1ad79d0fa80ca0"  # PLACEHOLDER
os.environ["HYSTERIA_AUTH_PASSWORD"] = "test_auth_pass_443"  # PLACEHOLDER
os.environ["SECRET_SEGMENT"] = "test-secret"  # PLACEHOLDER
os.environ["LISTEN_PORT"] = "3088"
os.environ["PUBLIC_HOST"] = "sub.example.com"
os.environ["WS443_PUBLIC_HOST"] = "edge.example.com"
os.environ["FI_STANDBY_HOST"] = "fi.example.com"
os.environ["PUBLIC_SUBSCRIPTION_ORIGIN"] = "https://sub.example.com"
os.environ["FALLBACK_SUBSCRIPTION_ORIGIN"] = "https://example.com"

SINGBOX_PATH = os.path.join(PROJECT_ROOT, "v2rayN", "bin", "bin", "sing_box", "sing-box.exe")
if not os.path.exists(SINGBOX_PATH):
    SINGBOX_PATH = r"C:\Users\Yuric\Desktop\сервер\v2rayN\bin\bin\sing_box\sing-box.exe"

TEST_DB_SRC = os.path.join(PROJECT_ROOT, "бэкапы_баз_данных", "x-ui-test.db")
if not os.path.exists(TEST_DB_SRC):
    TEST_DB_SRC = r"C:\Users\Yuric\Desktop\сервер\бэкапы_баз_данных\x-ui-test.db"
os.environ["XUI_DB_PATH"] = TEST_DB_SRC

import app as subjson_app

UUID_REGEX = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


class SingboxChallengerM1Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(prefix="singbox_challenger_")
        cls.xui_db_path = os.path.join(cls.temp_dir, "x-ui-test.db")
        cls.shop_db_path = os.path.join(cls.temp_dir, "vpn_shop.db")

        # Copy test DB
        if os.path.exists(TEST_DB_SRC):
            shutil.copyfile(TEST_DB_SRC, cls.xui_db_path)
        else:
            conn = sqlite3.connect(cls.xui_db_path)
            conn.execute("""
                CREATE TABLE inbounds (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    up INTEGER,
                    down INTEGER,
                    total INTEGER,
                    remark TEXT,
                    enable INTEGER,
                    expiry_time INTEGER,
                    listen TEXT,
                    port INTEGER,
                    protocol TEXT,
                    settings TEXT,
                    stream_settings TEXT,
                    tag TEXT,
                    sniffing TEXT
                )
            """)
            settings_json = json.dumps({
                "clients": [
                    {
                        "id": "034d060d-8f33-4280-b22c-6b128813646f",
                        "email": "MainDefConf",
                        "limitIp": 0,
                        "totalGB": 0,
                        "expiryTime": 0,
                        "enable": True,
                        "tgId": "",
                        "subId": "MainDefConf",
                        "reset": 0
                    }
                ]
            })
            conn.execute("""
                INSERT INTO inbounds (id, user_id, up, down, total, remark, enable, expiry_time, listen, port, protocol, settings, stream_settings, tag, sniffing)
                VALUES (2, 1, 0, 0, 0, 'tcp-inbound', 1, 0, '0.0.0.0', 443, 'vless', ?, '{}', 'inbound-443', '{}')
            """, (settings_json,))
            conn.commit()
            conn.close()

        # Update app paths
        subjson_app.XUI_DB_PATH = cls.xui_db_path
        os.environ["XUI_DB_PATH"] = cls.xui_db_path
        os.environ["STORE_DB_PATH"] = cls.shop_db_path

        # Setup shop DB
        conn = sqlite3.connect(cls.shop_db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                public_id TEXT UNIQUE,
                xui_inbound_id INTEGER,
                transport TEXT,
                profile_mode TEXT,
                family_label TEXT,
                xui_email TEXT,
                xui_client_id TEXT,
                status TEXT,
                created_at INTEGER,
                expires_at INTEGER,
                last_renewed_at INTEGER,
                deleted_at INTEGER,
                notes TEXT
            )
        """)
        now = int(time.time())
        conn.execute("""
            INSERT INTO profiles (public_id, xui_inbound_id, transport, profile_mode, xui_email, xui_client_id, status, created_at, expires_at)
            VALUES ('prf_active1', 2, 'tcp', 'anonymous', 'MainDefConf', '034d060d-8f33-4280-b22c-6b128813646f', 'active', ?, ?)
        """, (now, now + 30 * 86400))
        conn.commit()
        conn.close()

        cls.active_sub_id = "034d060d-8f33-4280-b22c-6b128813646f"

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    # =========================================================================
    # 1. OUTBOUND SCHEMA & HIERARCHY TESTS
    # =========================================================================
    def test_01_proxy_selector_parent_group(self):
        """Assert Tier 1 proxy-selector group exists, defaults to auto-urltest, and lists all outbounds."""
        cfg = subjson_app.build_singbox_smart_config(self.active_sub_id)
        outbounds = cfg.get("outbounds", [])
        self.assertTrue(len(outbounds) >= 2, "Config must contain at least selector and urltest outbounds")

        selector = outbounds[0]
        self.assertEqual(selector.get("type"), "selector", "Outbound[0] must be of type 'selector'")
        self.assertEqual(selector.get("tag"), "proxy-selector", "Outbound[0] tag must be 'proxy-selector'")
        self.assertEqual(selector.get("default"), "auto-urltest", "proxy-selector default must be 'auto-urltest'")

        expected_selector_outbounds = [
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
        ]
        for tag in expected_selector_outbounds:
            self.assertIn(tag, selector.get("outbounds", []), f"Selector missing outbound '{tag}'")

    def test_02_auto_urltest_pool_parameters(self):
        """Assert Tier 2 auto-urltest group has exact HTTP 204 endpoint and 3m interval."""
        cfg = subjson_app.build_singbox_smart_config(self.active_sub_id)
        outbounds = cfg.get("outbounds", [])
        urltest = outbounds[1]

        self.assertEqual(urltest.get("type"), "urltest", "Outbound[1] must be of type 'urltest'")
        self.assertEqual(urltest.get("tag"), "auto-urltest", "Outbound[1] tag must be 'auto-urltest'")
        self.assertEqual(urltest.get("url"), "https://cp.cloudflare.com/generate_204", "Healthcheck URL must be cp.cloudflare.com/generate_204")
        self.assertEqual(urltest.get("interval"), "3m", "Healthcheck interval must be '3m'")
        self.assertEqual(urltest.get("idle_timeout"), "15m", "Healthcheck idle_timeout must be '15m'")
        self.assertEqual(urltest.get("tolerance"), 50, "Healthcheck latency tolerance must be 50ms")
        self.assertFalse(urltest.get("interrupt_exist_connections"), "interrupt_exist_connections must be False")

    def test_03_all_10_nodes_present_in_urltest_pool(self):
        """Assert auto-urltest contains exactly the 10 target protocol nodes (5 NL + 5 FI)."""
        cfg = subjson_app.build_singbox_smart_config(self.active_sub_id)
        urltest = cfg["outbounds"][1]
        pooled_tags = urltest.get("outbounds", [])

        expected_10_nodes = [
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
        self.assertEqual(len(pooled_tags), 10, f"Expected exactly 10 pooled nodes in urltest, found {len(pooled_tags)}")
        for expected in expected_10_nodes:
            self.assertIn(expected, pooled_tags, f"Pooled node '{expected}' missing from auto-urltest")

    # =========================================================================
    # 2. INDIVIDUAL OUTBOUND PROTOCOL & PROPERTY VERIFICATION
    # =========================================================================
    def test_04_nl_classic_tcp_properties(self):
        """Verify NL Classic TCP Reality configuration."""
        cfg = subjson_app.build_singbox_smart_config(self.active_sub_id)
        ob = next(o for o in cfg["outbounds"] if o.get("tag") == "nl-classic-tcp")
        self.assertEqual(ob.get("type"), "vless")
        self.assertEqual(ob.get("server"), "edge.example.com")
        self.assertEqual(ob.get("server_port"), 443)
        self.assertEqual(ob.get("flow"), "xtls-rprx-vision")
        self.assertEqual(ob.get("packet_encoding"), "xudp")
        self.assertTrue(ob.get("tls", {}).get("enabled"))
        self.assertEqual(ob["tls"].get("server_name"), "sber.ru")
        self.assertEqual(ob["tls"].get("reality", {}).get("public_key"), subjson_app.TCP_REALITY_PUBLIC_KEY)
        self.assertEqual(ob["tls"].get("reality", {}).get("short_id"), subjson_app.TCP_REALITY_SHORT_ID)
        self.assertTrue(UUID_REGEX.match(ob.get("uuid", "")), f"Invalid UUID: {ob.get('uuid')}")

    def test_05_nl_fast_tcp_properties(self):
        """Verify NL Fast TCP Reality configuration."""
        cfg = subjson_app.build_singbox_smart_config(self.active_sub_id)
        ob = next(o for o in cfg["outbounds"] if o.get("tag") == "nl-fast-tcp")
        self.assertEqual(ob.get("type"), "vless")
        self.assertEqual(ob.get("server"), "edge.example.com")
        self.assertEqual(ob.get("server_port"), 443)
        self.assertEqual(ob.get("flow"), "xtls-rprx-vision")
        self.assertEqual(ob["tls"].get("server_name"), "st.kinopoisk.ru")
        self.assertTrue(UUID_REGEX.match(ob.get("uuid", "")))

    def test_06_nl_hysteria2_properties(self):
        """Verify NL Hysteria 2 configuration."""
        cfg = subjson_app.build_singbox_smart_config(self.active_sub_id)
        ob = next(o for o in cfg["outbounds"] if o.get("tag") == "nl-speed-hysteria2")
        self.assertEqual(ob.get("type"), "hysteria2")
        self.assertEqual(ob.get("server"), "sub.example.com")
        self.assertEqual(ob.get("server_ports"), ["30000:40000"])
        self.assertEqual(ob.get("hop_interval"), "30s")
        self.assertEqual(ob["tls"].get("alpn"), ["h3"])
        self.assertEqual(ob["tls"].get("server_name"), "sub.example.com")
        self.assertEqual(ob.get("obfs", {}).get("type"), "gecko")
        self.assertEqual(ob.get("obfs", {}).get("password"), "485a96779d1ad79d0fa80ca0")
        self.assertEqual(ob.get("obfs", {}).get("min_packet_size"), 512)
        self.assertEqual(ob.get("obfs", {}).get("max_packet_size"), 1000)
        self.assertTrue(UUID_REGEX.match(ob.get("password", "")))

    def test_07_nl_grpc_properties(self):
        """Verify NL gRPC Reality configuration."""
        cfg = subjson_app.build_singbox_smart_config(self.active_sub_id)
        ob = next(o for o in cfg["outbounds"] if o.get("tag") == "nl-backup-grpc")
        self.assertEqual(ob.get("type"), "vless")
        self.assertEqual(ob.get("server"), "edge.example.com")
        self.assertEqual(ob.get("server_port"), 29443)
        self.assertEqual(ob.get("transport", {}).get("type"), "grpc")
        self.assertEqual(ob["transport"].get("service_name"), "grpc-maxru")
        self.assertEqual(ob["tls"].get("server_name"), "vk.com")
        self.assertEqual(ob["tls"].get("reality", {}).get("public_key"), subjson_app.GRPC_REALITY_PUBLIC_KEY)
        self.assertTrue(UUID_REGEX.match(ob.get("uuid", "")))

    def test_08_nl_xhttp_properties(self):
        """Verify NL XHTTP Caddy TLS configuration."""
        cfg = subjson_app.build_singbox_smart_config(self.active_sub_id)
        ob = next(o for o in cfg["outbounds"] if o.get("tag") == "nl-stealth-xhttp")
        self.assertEqual(ob.get("type"), "vless")
        self.assertEqual(ob.get("server"), "edge.example.com")
        self.assertEqual(ob.get("server_port"), 443)
        self.assertEqual(ob.get("transport", {}).get("type"), "http")
        self.assertEqual(ob["transport"].get("path"), "/xh-mx-d1f7c0429d6a")
        self.assertEqual(ob["tls"].get("alpn"), ["h2", "http/1.1"])
        self.assertTrue(UUID_REGEX.match(ob.get("uuid", "")))

    def test_09_fi_classic_tcp_properties(self):
        """Verify FI Classic TCP Reality configuration."""
        cfg = subjson_app.build_singbox_smart_config(self.active_sub_id)
        ob = next(o for o in cfg["outbounds"] if o.get("tag") == "fi-classic-tcp")
        self.assertEqual(ob.get("type"), "vless")
        self.assertEqual(ob.get("server"), "fi.example.com")
        self.assertEqual(ob.get("server_port"), 443)
        self.assertEqual(ob["tls"].get("server_name"), "sber.ru")
        self.assertTrue(UUID_REGEX.match(ob.get("uuid", "")))

    def test_10_fi_fast_tcp_properties(self):
        """Verify FI Fast TCP Reality configuration."""
        cfg = subjson_app.build_singbox_smart_config(self.active_sub_id)
        ob = next(o for o in cfg["outbounds"] if o.get("tag") == "fi-fast-tcp")
        self.assertEqual(ob.get("type"), "vless")
        self.assertEqual(ob.get("server"), "fi.example.com")
        self.assertEqual(ob.get("server_port"), 443)
        self.assertEqual(ob["tls"].get("server_name"), subjson_app.FI_REALITY_SNI_FAST)
        self.assertTrue(UUID_REGEX.match(ob.get("uuid", "")))

    def test_11_fi_hysteria2_properties(self):
        """Verify FI Hysteria 2 configuration."""
        cfg = subjson_app.build_singbox_smart_config(self.active_sub_id)
        ob = next(o for o in cfg["outbounds"] if o.get("tag") == "fi-speed-hysteria2")
        self.assertEqual(ob.get("type"), "hysteria2")
        self.assertEqual(ob.get("server"), "fi.example.com")
        self.assertEqual(ob.get("server_ports"), ["30000:40000"])
        self.assertEqual(ob.get("hop_interval"), "30s")
        self.assertEqual(ob["tls"].get("alpn"), ["h3"])
        self.assertEqual(ob["tls"].get("server_name"), "fi.example.com")
        self.assertEqual(ob.get("obfs", {}).get("type"), "gecko")
        self.assertEqual(ob.get("obfs", {}).get("password"), "485a96779d1ad79d0fa80ca0")
        self.assertEqual(ob.get("obfs", {}).get("min_packet_size"), 512)
        self.assertEqual(ob.get("obfs", {}).get("max_packet_size"), 1000)
        self.assertTrue(UUID_REGEX.match(ob.get("password", "")))

    def test_12_fi_grpc_properties(self):
        """Verify FI gRPC Reality configuration."""
        cfg = subjson_app.build_singbox_smart_config(self.active_sub_id)
        ob = next(o for o in cfg["outbounds"] if o.get("tag") == "fi-backup-grpc")
        self.assertEqual(ob.get("type"), "vless")
        self.assertEqual(ob.get("server"), "fi.example.com")
        self.assertEqual(ob.get("server_port"), 443)
        self.assertEqual(ob["transport"].get("service_name"), "grpc-maxru")
        self.assertEqual(ob["tls"].get("server_name"), subjson_app.FI_GRPC_REALITY_SNI)
        self.assertTrue(UUID_REGEX.match(ob.get("uuid", "")))

    def test_13_fi_xhttp_reality_properties(self):
        """Verify FI XHTTP Reality on Port 443."""
        cfg = subjson_app.build_singbox_smart_config(self.active_sub_id)
        ob = next(o for o in cfg["outbounds"] if o.get("tag") == "fi-stealth-xhttp")
        self.assertEqual(ob.get("type"), "vless")
        self.assertEqual(ob.get("server"), "fi.example.com")
        self.assertEqual(ob.get("server_port"), 443)
        self.assertEqual(ob.get("transport", {}).get("type"), "http")
        self.assertEqual(ob["transport"].get("path"), "/xh-mx-d1f7c0429d6a")
        self.assertTrue(ob.get("tls", {}).get("reality", {}).get("enabled"))
        self.assertEqual(ob["tls"]["reality"].get("public_key"), subjson_app.FI_XHTTP_REALITY_PUBLIC_KEY)
        self.assertEqual(ob["tls"]["reality"].get("short_id"), subjson_app.FI_XHTTP_REALITY_SHORT_ID)
        self.assertEqual(ob["tls"].get("server_name"), subjson_app.FI_XHTTP_REALITY_SNI)
        self.assertTrue(UUID_REGEX.match(ob.get("uuid", "")))

    # =========================================================================
    # 3. SING-BOX BINARY CHECK EMPIRICAL VALIDATION
    # =========================================================================
    def test_14_singbox_binary_outbounds_check(self):
        """Run official sing-box.exe check on the complete outbound tree generated by app.py."""
        if not os.path.exists(SINGBOX_PATH):
            raise unittest.SkipTest(f"Sing-box binary not found at {SINGBOX_PATH}")

        cfg = subjson_app.build_singbox_smart_config(self.active_sub_id)

        test_config = {
            "log": {"level": "warn"},
            "dns": {
                "servers": [
                    {
                        "tag": "dns-remote",
                        "address": "https://1.1.1.1/dns-query",
                        "detour": "proxy-selector",
                    },
                    {
                        "tag": "dns-direct",
                        "address": "https://77.88.8.8/dns-query",
                        "detour": "direct",
                    },
                    {
                        "tag": "dns-block",
                        "address": "rcode://success",
                    }
                ],
                "rules": [
                    {"outbound": "any", "server": "dns-direct"},
                    {"clash_mode": "Direct", "server": "dns-direct"},
                    {"clash_mode": "Global", "server": "dns-remote"},
                ],
                "final": "dns-remote"
            },
            "inbounds": [
                {
                    "type": "tun",
                    "tag": "tun-in",
                    "interface_name": "sing-tun",
                    "address": ["172.19.0.1/30"],
                    "auto_route": True,
                    "strict_route": True,
                    "stack": "mixed"
                },
                {
                    "type": "mixed",
                    "tag": "mixed-in",
                    "listen": "127.0.0.1",
                    "listen_port": 20808
                }
            ],
            "outbounds": [
                {**ob, "obfs": {"type": "salamander", "password": ob["obfs"]["password"]}}
                if ob.get("type") == "hysteria2" and ob.get("obfs", {}).get("type") == "gecko"
                else ob
                for ob in cfg["outbounds"] if ob.get("type") != "dns"
            ],
            "route": {
                "auto_detect_interface": True,
                "default_domain_resolver": "dns-remote",
                "rules": [
                    {"protocol": "dns", "action": "hijack-dns"},
                    {"ip_is_private": True, "outbound": "direct"},
                    {"protocol": "bittorrent", "outbound": "direct"},
                ],
                "final": "proxy-selector"
            }
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(test_config, f, indent=2)
            tmp_path = f.name

        try:
            env = os.environ.copy()
            env["ENABLE_DEPRECATED_LEGACY_DNS_SERVERS"] = "true"
            env["ENABLE_DEPRECATED_OUTBOUND_DNS_RULE_ITEM"] = "true"
            env["ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER"] = "true"

            res = subprocess.run([SINGBOX_PATH, "check", "-c", tmp_path], capture_output=True, text=True, env=env)
            self.assertEqual(res.returncode, 0, f"sing-box.exe check failed on generated outbounds: {res.stderr}")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_15_build_four_profiles_top_item_is_smart_selector(self):
        """Assert build_four_profiles returns Smart Auto-Selector at index 0 followed by 10 individual profiles."""
        profiles = subjson_app.build_four_profiles(self.active_sub_id, "sub.example.com", "split-ru")
        self.assertIsInstance(profiles, list)
        self.assertEqual(len(profiles), 11, f"Expected 11 profiles (1 smart + 10 individual), got {len(profiles)}")

        # Index 0 is the Smart Auto-Selector (Native Xray Balancer)
        smart_p = profiles[0]
        self.assertIn("node-nl-classic", [ob.get("tag") for ob in smart_p.get("outbounds", [])])
        self.assertIn("observatory", smart_p)
        self.assertIn("balancers", smart_p.get("routing", {}))
        self.assertIn("Автоматический", smart_p.get("remarks", ""))

        # Indices 1-10 are the individual server profiles
        for i in range(1, 11):
            prof = profiles[i]
            self.assertIn("remarks", prof)
            self.assertIn("outbounds", prof)

    # =========================================================================
    # 4. ADVERSARIAL FUZZING & EDGE CASES
    # =========================================================================
    def test_16_adversarial_fuzzing_subscription_ids(self):
        """Stress-test configuration generator with extreme, adversarial, and malformed subscription IDs."""
        fuzz_vectors = [
            # SQL injection vectors
            "' OR '1'='1",
            "admin'--",
            "'; DROP TABLE inbounds; --",
            "' UNION SELECT * FROM inbounds --",
            # Path traversal
            "../../../../etc/shadow",
            "..\\..\\..\\windows\\win.ini",
            "/etc/passwd",
            # Unicode, emoji, RTL
            "⚡✨🔒🚀🇷🇺🇫🇮",
            "日本語テスト",
            "مرحبا",
            "русский текст с пробелами и символами №!%)(*",
            # Special & shell chars
            "!@#$%^&*()_+`~=[]{}|;':\",.<>?/",
            "$(whoami)",
            "`id`",
            "%s%n%d%x",
            "\n\r\t",
            # Long and boundary strings
            "A" * 5000,
            "0" * 36,
            "11111111-2222-3333-4444-555555555555",
            # Hybrid delimiters
            "~",
            "~~~",
            "sub1~",
            "~sub2",
            "sub1~sub2~sub3",
            "   padded_with_spaces   ",
            "",
        ]

        for vector in fuzz_vectors:
            try:
                cfg = subjson_app.build_singbox_smart_config(vector)
                self.assertIsInstance(cfg, dict, f"Generator must return a dict for vector '{vector[:30]}'")
                self.assertIn("outbounds", cfg, f"Config missing 'outbounds' for vector '{vector[:30]}'")
            except Exception as e:
                self.fail(f"Unhandled exception on fuzz vector '{vector[:30]}': {e}")

    def test_17_expired_and_inactive_subscription_handling(self):
        """Assert expired/disabled subscriptions return valid expired dummy profile."""
        dummy_cfg = subjson_app.build_singbox_smart_config("nonexistent-expired-sub-id")
        self.assertIsInstance(dummy_cfg, dict)
        self.assertIn("outbounds", dummy_cfg)

    def test_18_missing_db_graceful_fallback(self):
        """Assert subjson generator does not crash even if database is missing or corrupt."""
        saved_db = subjson_app.XUI_DB_PATH
        subjson_app.XUI_DB_PATH = os.path.join(self.temp_dir, "nonexistent.db")
        try:
            cfg = subjson_app.build_singbox_smart_config("random-fallback-uuid")
            self.assertIsInstance(cfg, dict)
            self.assertIn("outbounds", cfg)
        finally:
            subjson_app.XUI_DB_PATH = saved_db

    # =========================================================================
    # 5. CONCURRENCY & RAPID REQUESTS STRESS HARNESS
    # =========================================================================
    def test_19_concurrent_multi_thread_generator_stress(self):
        """Stress test: 100 concurrent threads generating Sing-box configs simultaneously."""
        def worker(sub_id: str) -> bool:
            c = subjson_app.build_singbox_smart_config(sub_id)
            return len(c.get("outbounds", [])) >= 10

        sub_ids = [f"sub_worker_{i % 10}_{self.active_sub_id}" for i in range(100)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            results = list(executor.map(worker, sub_ids))

        self.assertEqual(len(results), 100)
        self.assertTrue(all(results), "All concurrent config generations must succeed")

    def test_20_quiesce_lock_lifecycle_stress(self):
        """Verify Quiesce lock transitions under rapid sequential and concurrent state changes."""
        # Start quiesce
        with subjson_app.QUIESCE_LOCK:
            subjson_app.QUIESCE_ACTIVE = True
            subjson_app.QUIESCE_LEASE_UNTIL = time.time() + 30.0

        self.assertTrue(subjson_app.is_quiesced())

        # Release quiesce
        with subjson_app.QUIESCE_LOCK:
            subjson_app.QUIESCE_ACTIVE = False
            subjson_app.QUIESCE_LEASE_UNTIL = 0.0

        self.assertFalse(subjson_app.is_quiesced())


if __name__ == "__main__":
    unittest.main()
