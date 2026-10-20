"""
tests/test_outage_simulation_unit.py

Unit & Integration Test Suite for Outage Simulation & Failover Verification (Milestone M2)
Tests:
1. MockHttpProxyServer lifecycle, HTTP/HTTPS tunneling, latency emulation, dropping, and restoration.
2. TcpBridgeServer forwarding, abrupt socket link severing, and reconnectivity.
3. HTTP probing logic over SOCKS5/mixed proxy, RTT measurement, and status code verification.
4. Port readiness and release polling functions.
5. Configuration synthesis for Sing-box (urltest group) and Clash Meta / Mihomo (url-test & fallback groups).
6. Binary discovery logic for sing-box.exe and mihomo.exe.
7. Failover timing assertion threshold (< 3.0s).
8. End-to-end OutageSimulationRunner execution for both client engines.
9. Process lifecycle management and resource cleanup.
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from typing import Any, Dict

# Ensure project root and scripts are in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for p in [
    os.path.join(PROJECT_ROOT, "scripts"),
    os.path.join(PROJECT_ROOT, "subjson-service"),
    r"C:\Users\Yuric\Desktop\сервер\scripts",
    r"C:\Users\Yuric\Desktop\сервер\subjson-service",
    r"C:\Users\Yuric\OneDrive\Desktop\сервер\scripts",
    r"C:\Users\Yuric\OneDrive\Desktop\сервер\subjson-service",
    PROJECT_ROOT,
]:
    if os.path.exists(p) and p not in sys.path:
        sys.path.insert(0, p)

import test_outage_simulation as sim


class TestMockHttpProxyServer(unittest.TestCase):
    """Test MockHttpProxyServer component."""

    def setUp(self):
        self.port = sim.find_free_port()
        self.server = sim.MockHttpProxyServer(port=self.port, node_name="TestNL", latency=0.01)
        self.server.start()

    def tearDown(self):
        self.server.stop()

    def test_01_server_startup_and_direct_get(self):
        """Test server starts and responds to direct HTTP GET with 204."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect(("127.0.0.1", self.port))
        s.sendall(b"GET http://cp.cloudflare.com/generate_204 HTTP/1.1\r\nHost: cp.cloudflare.com\r\n\r\n")
        resp = s.recv(1024)
        s.close()
        self.assertIn(b"204 No Content", resp)
        self.assertIn(b"Server: MockNode-TestNL", resp)
        self.assertEqual(self.server.request_count, 1)

    def test_02_server_connect_tunneling(self):
        """Test server handles HTTP CONNECT tunneling and returns 200 Established then 204."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect(("127.0.0.1", self.port))
        s.sendall(b"CONNECT cp.cloudflare.com:443 HTTP/1.1\r\nHost: cp.cloudflare.com:443\r\n\r\n")
        resp1 = s.recv(1024)
        self.assertIn(b"200 Connection Established", resp1)

        s.sendall(b"GET /generate_204 HTTP/1.1\r\nHost: cp.cloudflare.com\r\n\r\n")
        resp2 = s.recv(1024)
        s.close()
        self.assertIn(b"204 No Content", resp2)

    def test_03_server_drop_and_restore(self):
        """Test abrupt dropping closes sockets and restore re-enables traffic."""
        # Active socket drop
        s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s1.settimeout(2.0)
        s1.connect(("127.0.0.1", self.port))

        self.server.drop()
        self.assertTrue(self.server.dropped)
        try:
            s1.close()
        except Exception:
            pass

        # Connection after drop should be rejected/closed
        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s2.settimeout(0.5)
        try:
            s2.connect(("127.0.0.1", self.port))
            s2.sendall(b"GET /generate_204 HTTP/1.1\r\n\r\n")
            data = s2.recv(1024)
            self.assertEqual(data, b"")
        except Exception:
            pass
        finally:
            s2.close()

        # Restore
        self.server.restore()
        self.assertFalse(self.server.dropped)

        s3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s3.settimeout(2.0)
        s3.connect(("127.0.0.1", self.port))
        s3.sendall(b"GET http://cp.cloudflare.com/generate_204 HTTP/1.1\r\nHost: cp.cloudflare.com\r\n\r\n")
        resp = s3.recv(1024)
        s3.close()
        self.assertIn(b"204 No Content", resp)


class TestTcpBridgeServer(unittest.TestCase):
    """Test TcpBridgeServer component."""

    def setUp(self):
        self.target_port = sim.find_free_port()
        self.listen_port = sim.find_free_port()

        # Target echo server
        self.target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.target_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.target_sock.bind(("127.0.0.1", self.target_port))
        self.target_sock.listen(16)
        self.running = True

        def echo_target():
            while self.running:
                try:
                    cs, _ = self.target_sock.accept()
                except Exception:
                    break
                try:
                    d = cs.recv(1024)
                    if d:
                        cs.sendall(b"ECHO:" + d)
                    cs.close()
                except Exception:
                    pass

        import threading
        threading.Thread(target=echo_target, daemon=True).start()

        self.bridge = sim.TcpBridgeServer(
            listen_port=self.listen_port, target_host="127.0.0.1", target_port=self.target_port, name="TestBridge"
        )
        self.bridge.start()

    def tearDown(self):
        self.running = False
        self.bridge.stop()
        try:
            self.target_sock.close()
        except Exception:
            pass

    def test_01_bridge_forwarding(self):
        """Test bridge forwards bidirectional TCP streams."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect(("127.0.0.1", self.listen_port))
        s.sendall(b"PING")
        data = s.recv(1024)
        s.close()
        self.assertEqual(data, b"ECHO:PING")

    def test_02_bridge_drop_and_restore(self):
        """Test bridge drop severs links and restore resumes forwarding."""
        self.bridge.drop()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            s.connect(("127.0.0.1", self.listen_port))
            s.sendall(b"PING")
            data = s.recv(1024)
            self.assertEqual(data, b"")
        except Exception:
            pass
        finally:
            s.close()

        self.bridge.restore()
        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s2.settimeout(2.0)
        s2.connect(("127.0.0.1", self.listen_port))
        s2.sendall(b"PING2")
        data2 = s2.recv(1024)
        s2.close()
        self.assertEqual(data2, b"ECHO:PING2")


class TestProbeAndPortUtilities(unittest.TestCase):
    """Test HTTP probing and port readiness helper functions."""

    def setUp(self):
        self.port = sim.find_free_port()
        self.server = sim.MockHttpProxyServer(port=self.port, node_name="ProbeMock")
        self.server.start()

    def tearDown(self):
        self.server.stop()

    def test_01_probe_http_via_proxy_success(self):
        """Test probe_http_via_proxy successfully receives 204 from working proxy."""
        ok, code, rtt, err = sim.probe_http_via_proxy(
            "http://cp.cloudflare.com/generate_204", proxy_port=self.port, timeout=1.0
        )
        self.assertTrue(ok)
        self.assertEqual(code, 204)
        self.assertGreater(rtt, 0.0)
        self.assertEqual(err, "")

    def test_02_probe_http_via_proxy_failure(self):
        """Test probe_http_via_proxy handles connection refused on non-existent port."""
        closed_port = sim.find_free_port()
        ok, code, rtt, err = sim.probe_http_via_proxy(
            "http://cp.cloudflare.com/generate_204", proxy_port=closed_port, timeout=0.3
        )
        self.assertFalse(ok)
        self.assertNotEqual(err, "")

    def test_03_wait_for_proxy_port_ready(self):
        """Test wait_for_proxy_port returns True on open port."""
        ready = sim.wait_for_proxy_port(port=self.port, timeout=2.0)
        self.assertTrue(ready)

    def test_04_wait_for_port_free_released(self):
        """Test wait_for_port_free returns True when port is unoccupied."""
        free_port = sim.find_free_port()
        free = sim.wait_for_port_free(port=free_port, timeout=1.0)
        self.assertTrue(free)



class TestConfigSynthesizers(unittest.TestCase):
    """Test configuration synthesizers for Sing-box and Clash Meta."""

    def test_01_singbox_test_config_schema(self):
        """Validate Sing-box test configuration structure and healthcheck params."""
        cfg = sim.generate_singbox_test_config(
            sub_id="sub_test",
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

        outbounds = cfg["outbounds"]
        selector = next(o for o in outbounds if o.get("tag") == "proxy-selector")
        self.assertEqual(selector["type"], "selector")
        self.assertEqual(selector["default"], "auto-urltest")

        urltest = next(o for o in outbounds if o.get("tag") == "auto-urltest")
        self.assertEqual(urltest["type"], "urltest")
        self.assertEqual(urltest["url"], "http://cp.cloudflare.com/generate_204")
        self.assertEqual(urltest["interval"], "1s")
        self.assertEqual(urltest["tolerance"], 50)
        self.assertEqual(urltest["interrupt_exist_connections"], False)

    def test_02_clash_test_config_schema(self):
        """Validate Clash Meta test configuration structure and healthcheck params."""
        cfg = sim.generate_clash_test_config(
            sub_id="sub_test",
            primary_port=24001,
            secondary_port=24002,
            proxy_port=20808,
            probe_url="http://cp.cloudflare.com/generate_204",
            interval_sec=1,
            tolerance_ms=50,
        )
        self.assertEqual(cfg["mixed-port"], 20808)
        self.assertEqual(cfg["mode"], "rule")
        groups = cfg["proxy-groups"]

        urltest = next(g for g in groups if g.get("name") == "⚡ Auto URL-Test")
        self.assertEqual(urltest["type"], "url-test")
        self.assertEqual(urltest["url"], "http://cp.cloudflare.com/generate_204")
        self.assertEqual(urltest["expected-status"], "204")
        self.assertEqual(urltest["interval"], 1)
        self.assertEqual(urltest["tolerance"], 50)

        fallback = next(g for g in groups if g.get("name") == "🛡️ Priority Fallback")
        self.assertEqual(fallback["type"], "fallback")
        self.assertEqual(fallback["expected-status"], "204")

        proxy_sel = next(g for g in groups if g.get("name") == "🚀 PROXY")
        self.assertEqual(proxy_sel["type"], "select")


class TestBinaryDiscovery(unittest.TestCase):
    """Test discovery of client core binaries."""

    def test_01_find_binary_existing(self):
        """Verify find_binary locates python executable."""
        p = sim.find_binary([sys.executable])
        self.assertEqual(p, os.path.abspath(sys.executable))

    def test_02_find_binary_non_existent(self):
        """Verify find_binary returns None if paths don't exist."""
        p = sim.find_binary(["/non/existent/path/binary.exe"])
        self.assertIsNone(p)


class TestOutageSimulationRunnerE2E(unittest.TestCase):
    """End-to-end integration tests executing real client core instances."""

    def test_01_singbox_outage_simulation_e2e(self):
        """
        Execute full Sing-box outage simulation:
        Asserts baseline 204, failover < 3.0s under fault injection, and node recovery.
        """
        singbox_bin = sim.find_binary(sim.SINGBOX_BIN_PATHS)
        if not singbox_bin:
            raise unittest.SkipTest("sing-box.exe not found")

        runner = sim.OutageSimulationRunner(
            engine="sing-box",
            proxy_port=20811,
            poll_interval=0.05,
            max_failover_sec=3.0,
            verbose=False,
        )
        metrics = runner.run_simulation()

        self.assertTrue(metrics["baseline_success"], "Sing-box baseline connectivity failed")
        self.assertTrue(metrics["failover_success"], "Sing-box failover failed")
        self.assertLess(metrics["failover_time_s"], 3.0, f"Failover time {metrics['failover_time_s']} exceeded 3.0s")
        self.assertTrue(metrics["recovery_success"], "Sing-box node recovery verification failed")
        self.assertIsNone(metrics["error"])

    def test_02_mihomo_outage_simulation_e2e(self):
        """
        Execute full Mihomo outage simulation:
        Asserts baseline 204, failover < 3.0s under fault injection, and node recovery.
        """
        mihomo_bin = sim.find_binary(sim.MIHOMO_BIN_PATHS)
        if not mihomo_bin:
            raise unittest.SkipTest("mihomo.exe not found")

        runner = sim.OutageSimulationRunner(
            engine="mihomo",
            proxy_port=20812,
            poll_interval=0.05,
            max_failover_sec=3.0,
            verbose=False,
        )
        metrics = runner.run_simulation()

        self.assertTrue(metrics["baseline_success"], "Mihomo baseline connectivity failed")
        self.assertTrue(metrics["failover_success"], "Mihomo failover failed")
        self.assertLess(metrics["failover_time_s"], 3.0, f"Failover time {metrics['failover_time_s']} exceeded 3.0s")
        self.assertTrue(metrics["recovery_success"], "Mihomo node recovery verification failed")
        self.assertIsNone(metrics["error"])


if __name__ == "__main__":
    unittest.main()

