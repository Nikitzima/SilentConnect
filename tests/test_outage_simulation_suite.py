"""
tests/test_outage_simulation_suite.py

Unit and Integration Test Suite for Outage Simulation & Failover Verification Harness.
Validates:
- MockHttpProxyServer state machine (active, dropped, restored, request metrics, exit IP header)
- TcpBridgeServer forwarding and fault injection
- HTTP proxy probing and RTT / header extraction
- Sing-box & Clash Meta test config synthesizers
- OutageSimulationRunner execution, < 3.0s failover threshold, exit IP transition, and recovery.
"""

import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from typing import Any, Dict, List

# Ensure project root and scripts are in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPTS_DIR = os.path.join(PROJECT_ROOT, "scripts")
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from scripts.test_outage_simulation import (
    DEFAULT_PROXY_PORT,
    DEFAULT_TARGET_URL,
    MockHttpProxyServer,
    OutageSimulationRunner,
    TcpBridgeServer,
    find_available_port,
    find_binary,
    find_free_port,
    generate_clash_test_config,
    generate_singbox_test_config,
    probe_http_via_proxy,
    wait_for_port_free,
    wait_for_proxy_port,
)


class TestMockHttpProxyServer(unittest.TestCase):
    """Test the in-process mock HTTP proxy server."""

    def setUp(self):
        self.port = find_free_port()
        self.server = MockHttpProxyServer(
            port=self.port,
            node_name="NL_Test_Node",
            exit_ip="192.0.2.1",
            latency=0.005,
        )
        self.server.start()
        time.sleep(0.05)

    def tearDown(self):
        if self.server:
            self.server.stop()

    def test_mock_proxy_204_response_and_headers(self):
        ok, code, rtt, err, headers = probe_http_via_proxy(
            target_url="http://cp.cloudflare.com/generate_204",
            proxy_port=self.port,
            timeout=1.0,
        )
        self.assertTrue(ok, f"Probe failed: {err}")
        self.assertEqual(code, 204)
        self.assertEqual(headers.get("x-node"), "NL_Test_Node")
        self.assertEqual(headers.get("x-exit-ip"), "192.0.2.1")
        self.assertGreater(self.server.request_count, 0)

    def test_mock_proxy_drop_and_restore(self):
        # Initial probe succeeds
        ok1, code1, _, _, _ = probe_http_via_proxy(
            target_url="http://cp.cloudflare.com/generate_204",
            proxy_port=self.port,
            timeout=0.5,
        )
        self.assertTrue(ok1)

        # Drop server
        self.server.drop()
        ok2, _, _, _, _ = probe_http_via_proxy(
            target_url="http://cp.cloudflare.com/generate_204",
            proxy_port=self.port,
            timeout=0.2,
        )
        self.assertFalse(ok2, "Probe should fail when server is dropped")

        # Restore server
        self.server.restore()
        time.sleep(0.05)
        ok3, code3, _, _, headers3 = probe_http_via_proxy(
            target_url="http://cp.cloudflare.com/generate_204",
            proxy_port=self.port,
            timeout=0.5,
        )
        self.assertTrue(ok3, "Probe should succeed after restore")
        self.assertEqual(code3, 204)
        self.assertEqual(headers3.get("x-exit-ip"), "192.0.2.1")


class TestTcpBridgeServer(unittest.TestCase):
    """Test the TCP forwarding bridge and fault injection."""

    def setUp(self):
        self.backend_port = find_free_port()
        self.bridge_port = find_free_port()

        # Start a simple echo backend
        self.backend_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.backend_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.backend_sock.bind(("127.0.0.1", self.backend_port))
        self.backend_sock.listen(10)

        self.backend_running = True

        def echo_loop():
            while self.backend_running:
                try:
                    cs, _ = self.backend_sock.accept()
                    data = cs.recv(1024)
                    if data:
                        cs.sendall(data)
                    cs.close()
                except Exception:
                    break

        self.backend_thread = threading.Thread(target=echo_loop, daemon=True)
        self.backend_thread.start()

        # Start bridge pointing to backend
        self.bridge = TcpBridgeServer(
            listen_port=self.bridge_port,
            target_host="127.0.0.1",
            target_port=self.backend_port,
            name="TestBridge",
        )
        self.bridge.start()
        time.sleep(0.05)

    def tearDown(self):
        self.backend_running = False
        if self.backend_sock:
            try:
                self.backend_sock.close()
            except Exception:
                pass
        if self.bridge:
            self.bridge.stop()

    def test_bridge_forwarding_and_sever(self):
        # 1. Forwarding works
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect(("127.0.0.1", self.bridge_port))
        s.sendall(b"PING")
        resp = s.recv(1024)
        s.close()
        self.assertEqual(resp, b"PING")

        # 2. Sever connection
        self.bridge.drop()
        time.sleep(0.05)
        with self.assertRaises(Exception):
            s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s2.settimeout(0.2)
            s2.connect(("127.0.0.1", self.bridge_port))
            s2.sendall(b"PING")
            data = s2.recv(1024)
            s2.close()
            if not data:
                raise ConnectionResetError("Connection severed")


class TestConfigSynthesizers(unittest.TestCase):
    """Test configuration synthesizer generators for Sing-box and Clash Meta."""

    def test_singbox_test_config_schema(self):
        cfg = generate_singbox_test_config(
            sub_id="test-sub-123",
            primary_port=24001,
            secondary_port=24002,
            proxy_port=20808,
            probe_url="http://cp.cloudflare.com/generate_204",
            urltest_interval="1s",
            urltest_tolerance=50,
        )
        self.assertIn("inbounds", cfg)
        self.assertIn("outbounds", cfg)
        self.assertIn("route", cfg)

        outbounds = {ob["tag"]: ob for ob in cfg["outbounds"]}
        self.assertIn("proxy-selector", outbounds)
        self.assertIn("auto-urltest", outbounds)
        self.assertIn("nl-primary-node", outbounds)
        self.assertIn("fi-secondary-node", outbounds)

        urltest = outbounds["auto-urltest"]
        self.assertEqual(urltest["type"], "urltest")
        self.assertEqual(urltest["url"], "http://cp.cloudflare.com/generate_204")
        self.assertEqual(urltest["tolerance"], 50)
        self.assertFalse(urltest["interrupt_exist_connections"])

    def test_clash_test_config_schema(self):
        cfg = generate_clash_test_config(
            sub_id="test-sub-123",
            primary_port=24001,
            secondary_port=24002,
            proxy_port=20808,
            probe_url="http://cp.cloudflare.com/generate_204",
            interval_sec=1,
            tolerance_ms=50,
        )
        self.assertEqual(cfg["mixed-port"], 20808)
        self.assertEqual(len(cfg["proxies"]), 2)

        group_names = [g["name"] for g in cfg["proxy-groups"]]
        self.assertIn("⚡ Auto URL-Test", group_names)
        self.assertIn("🛡️ Priority Fallback", group_names)
        self.assertIn("🚀 PROXY", group_names)


class TestOutageSimulationRunnerExecution(unittest.TestCase):
    """Test full OutageSimulationRunner execution with real binary."""

    def test_singbox_outage_simulation_lifecycle(self):
        runner = OutageSimulationRunner(
            engine="sing-box",
            proxy_port=20815,
            poll_interval=0.05,
            max_failover_sec=3.0,
            verbose=False,
        )
        metrics = runner.run_simulation()

        self.assertTrue(metrics["baseline_success"], "Baseline connectivity failed")
        self.assertTrue(metrics["failover_success"], "Failover assertion failed")
        self.assertLess(metrics["failover_time_s"], 3.0, f"Failover time {metrics['failover_time_s']}s >= 3.0s")
        self.assertTrue(metrics["recovery_success"], "Recovery failed")
        self.assertTrue(metrics["exit_ip_switched"], "Exit IP did not switch from NL to FI")
        self.assertEqual(metrics["baseline_exit_ip"], "192.0.2.1")
        self.assertEqual(metrics["failover_exit_ip"], "198.51.100.1")


if __name__ == "__main__":
    unittest.main()
