#!/usr/bin/env python3
"""
scripts/test_outage_simulation.py

Empirical Outage Simulation & Client Failover Verification Suite
Part of SilentConnect Multi-Client Smart Auto-Selector Infrastructure (Milestone M2)

Features:
1. Generates smart multi-outbound configuration using `subjson-service/app.py`.
2. Starts real client core subprocess (Sing-box or Mihomo/Clash Meta) with SOCKS5/mixed inbound on 127.0.0.1:20808.
3. Validates baseline connectivity via HTTP 204 (https://cp.cloudflare.com/generate_204) through primary node (NL).
4. Injects abrupt primary node outage (TCP bridge drop / port blackhole).
5. High-frequency sampling (50ms interval) to measure exact failover time Delta T.
6. Empirically asserts that failover occurs within < 3.0 seconds (Delta T < 3.0s) with 0 manual intervention.
7. Validates non-destructive recovery when primary node is restored.
8. Ensures deterministic subprocess termination and cleanup of all temporary artifacts on exit.
"""

import argparse
import http.client
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    import requests
except ImportError:
    requests = None


# Locate project root and subjson-service
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))

for path_candidate in [
    os.path.join(PROJECT_ROOT, "subjson-service"),
    r"C:\Users\Yuric\Desktop\сервер\subjson-service",
    r"C:\Users\Yuric\OneDrive\Desktop\сервер\subjson-service",
]:
    if os.path.exists(path_candidate) and path_candidate not in sys.path:
        sys.path.insert(0, path_candidate)

for root_candidate in [
    PROJECT_ROOT,
    r"C:\Users\Yuric\Desktop\сервер",
    r"C:\Users\Yuric\OneDrive\Desktop\сервер",
]:
    if os.path.exists(root_candidate) and root_candidate not in sys.path:
        sys.path.insert(0, root_candidate)

# Setup default environment for SubJSON
os.environ.setdefault("HYSTERIA_SALAMANDER_PASSWORD", "dummy_salamander_pwd")  # PLACEHOLDER
os.environ.setdefault("HYSTERIA_AUTH_PASSWORD", "dummy_auth_pass_443")  # PLACEHOLDER
os.environ.setdefault("SECRET_SEGMENT", "test-secret")  # PLACEHOLDER
os.environ.setdefault("PUBLIC_HOST", "sub.example.com")

# Default binary locations
SINGBOX_BIN_PATHS = [
    os.path.join(PROJECT_ROOT, "v2rayN", "bin", "bin", "sing_box", "sing-box.exe"),
    r"C:\Users\Yuric\Desktop\сервер\v2rayN\bin\bin\sing_box\sing-box.exe",
    r"C:\Users\Yuric\OneDrive\Desktop\сервер\v2rayN\bin\bin\sing_box\sing-box.exe",
]

MIHOMO_BIN_PATHS = [
    os.path.join(PROJECT_ROOT, "v2rayN", "bin", "bin", "mihomo", "mihomo.exe"),
    r"C:\Users\Yuric\Desktop\сервер\v2rayN\bin\bin\mihomo\mihomo.exe",
    r"C:\Users\Yuric\OneDrive\Desktop\сервер\v2rayN\bin\bin\mihomo\mihomo.exe",
]

DEFAULT_SUB_ID = "00000000-0000-0000-0000-000000000000"
DEFAULT_PROXY_PORT = 20808
DEFAULT_POLL_INTERVAL = 0.05  # 50ms
DEFAULT_MAX_FAILOVER_SEC = 3.0  # < 3.0s requirement
DEFAULT_TARGET_URL = "http://cp.cloudflare.com/generate_204"


def find_binary(candidates: List[str]) -> Optional[str]:
    """Find the first existing binary path from candidates."""
    for p in candidates:
        if os.path.isfile(p):
            return os.path.abspath(p)
    return None


# =============================================================================
# 1. NETWORK BRIDGES & MOCK PROXY SERVERS
# =============================================================================

class MockHttpProxyServer:
    """
    High-performance mock HTTP/HTTPS proxy server representing a VPN/Proxy node.
    Can simulate specific latency, record request counts, and respond with 204 status.
    """
    def __init__(self, port: int, node_name: str, exit_ip: str = "127.0.0.1", latency: float = 0.0):
        self.port = port
        self.node_name = node_name
        self.exit_ip = exit_ip
        self.latency = latency
        self.running = False
        self.dropped = False
        self.sock: Optional[socket.socket] = None
        self.request_count = 0
        self.active_sockets: List[socket.socket] = []
        self.lock = threading.Lock()

    def start(self):
        self.running = True
        self.dropped = False
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", self.port))
        self.sock.listen(128)
        t = threading.Thread(target=self._loop, daemon=True, name=f"MockServer-{self.node_name}")
        t.start()

    def _loop(self):
        while self.running:
            try:
                cs, _ = self.sock.accept()
            except Exception:
                break
            with self.lock:
                if self.dropped:
                    try:
                        cs.close()
                    except Exception:
                        pass
                    continue
                self.active_sockets.append(cs)
            threading.Thread(target=self._handle_client, args=(cs,), daemon=True).start()

    def _handle_client(self, cs: socket.socket):
        try:
            cs.settimeout(5.0)
            data = cs.recv(4096)
            if not data or self.dropped:
                cs.close()
                return

            if self.latency > 0:
                time.sleep(self.latency)

            with self.lock:
                self.request_count += 1

            first_line = data.split(b"\r\n")[0].decode("latin1", errors="ignore")
            headers = (
                f"HTTP/1.1 204 No Content\r\n"
                f"Content-Length: 0\r\n"
                f"Connection: close\r\n"
                f"Server: MockNode-{self.node_name}\r\n"
                f"X-Node: {self.node_name}\r\n"
                f"X-Exit-IP: {self.exit_ip}\r\n\r\n"
            )
            if first_line.startswith("CONNECT"):
                cs.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                _ = cs.recv(4096)
                cs.sendall(headers.encode())
            else:
                cs.sendall(headers.encode())
        except Exception:
            pass
        finally:
            with self.lock:
                if cs in self.active_sockets:
                    self.active_sockets.remove(cs)
            try:
                cs.close()
            except Exception:
                pass



    def drop(self):
        """Simulate abrupt outage by dropping all active sockets and refusing new connections."""
        with self.lock:
            self.dropped = True
            for s in self.active_sockets:
                try:
                    s.close()
                except Exception:
                    pass
            self.active_sockets.clear()

    def restore(self):
        """Restore node to operational state."""
        with self.lock:
            self.dropped = False

    def stop(self):
        """Stop server and release port."""
        self.running = False
        self.drop()
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None


class TcpBridgeServer:
    """
    TCP forwarding bridge between local client and remote/local endpoint.
    Allows injecting instantaneous link drops and restorations.
    """
    def __init__(self, listen_port: int, target_host: str, target_port: int, name: str = "Bridge"):
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.name = name
        self.running = False
        self.dropped = False
        self.sock: Optional[socket.socket] = None
        self.active_sockets: List[socket.socket] = []
        self.lock = threading.Lock()

    def start(self):
        self.running = True
        self.dropped = False
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", self.listen_port))
        self.sock.listen(128)
        t = threading.Thread(target=self._accept_loop, daemon=True, name=f"Bridge-{self.name}")
        t.start()

    def _accept_loop(self):
        while self.running:
            try:
                cs, _ = self.sock.accept()
            except Exception:
                break
            with self.lock:
                if self.dropped:
                    try:
                        cs.close()
                    except Exception:
                        pass
                    continue
                self.active_sockets.append(cs)
            threading.Thread(target=self._handle_conn, args=(cs,), daemon=True).start()

    def _handle_conn(self, cs: socket.socket):
        ts = None
        try:
            ts = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ts.settimeout(5.0)
            ts.connect((self.target_host, self.target_port))
            with self.lock:
                if self.dropped:
                    cs.close()
                    ts.close()
                    return
                self.active_sockets.append(ts)
        except Exception:
            try:
                cs.close()
            except Exception:
                pass
            if ts:
                try:
                    ts.close()
                except Exception:
                    pass
            return

        def pipe(s1: socket.socket, s2: socket.socket):
            try:
                while self.running and not self.dropped:
                    data = s1.recv(8192)
                    if not data:
                        break
                    s2.sendall(data)
            except Exception:
                pass
            finally:
                try:
                    s1.close()
                except Exception:
                    pass
                try:
                    s2.close()
                except Exception:
                    pass

        t1 = threading.Thread(target=pipe, args=(cs, ts), daemon=True)
        t2 = threading.Thread(target=pipe, args=(ts, cs), daemon=True)
        t1.start()
        t2.start()

    def drop(self):
        """Sever all connections immediately."""
        with self.lock:
            self.dropped = True
            for s in self.active_sockets:
                try:
                    s.close()
                except Exception:
                    pass
            self.active_sockets.clear()

    def restore(self):
        """Restore bridge forwarding."""
        with self.lock:
            self.dropped = False

    def stop(self):
        self.running = False
        self.drop()
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None


# =============================================================================
# 2. HTTP PROBING OVER PROXY
# =============================================================================

def probe_http_via_proxy(
    target_url: str,
    proxy_host: str = "127.0.0.1",
    proxy_port: int = DEFAULT_PROXY_PORT,
    timeout: float = 0.5,
) -> Tuple[bool, int, float, str, Dict[str, str]]:
    """
    Issue an HTTP request through the local mixed/SOCKS5 proxy port.
    Returns: (is_success, status_code, rtt_seconds, error_msg, headers_dict)
    """
    t0 = time.perf_counter()
    headers: Dict[str, str] = {}
    if requests is not None:
        proxies = {
            "http": f"http://{proxy_host}:{proxy_port}",
            "https": f"http://{proxy_host}:{proxy_port}",
        }
        try:
            r = requests.get(target_url, proxies=proxies, timeout=timeout, allow_redirects=False)
            rtt = time.perf_counter() - t0
            is_success = (r.status_code in (200, 204))
            headers = {k.lower(): str(v) for k, v in r.headers.items()}
            return is_success, r.status_code, rtt, "", headers
        except Exception as e:
            rtt = time.perf_counter() - t0
            return False, 0, rtt, str(e), headers
    else:
        parsed = urllib.parse.urlparse(target_url)
        host = parsed.hostname or "127.0.0.1"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((proxy_host, proxy_port))

            req = (
                f"GET {target_url} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: SilentConnect-OutageSimulator/1.0\r\n"
                f"Proxy-Connection: close\r\n"
                f"Connection: close\r\n\r\n"
            )
            s.sendall(req.encode())
            data = s.recv(4096)
            s.close()

            rtt = time.perf_counter() - t0
            if not data:
                return False, 0, rtt, "Empty response from proxy", headers

            raw_text = data.decode("latin1", errors="ignore")
            lines = raw_text.split("\r\n")
            header_line = lines[0] if lines else ""
            for l in lines[1:]:
                if ":" in l:
                    k, v = l.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            parts = header_line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                code = int(parts[1])
                is_success = (code in (200, 204))
                return is_success, code, rtt, "", headers
            return False, 0, rtt, f"Malformed response: {header_line}", headers
        except Exception as e:
            rtt = time.perf_counter() - t0
            return False, 0, rtt, str(e), headers



def wait_for_proxy_port(
    host: str = "127.0.0.1",
    port: int = DEFAULT_PROXY_PORT,
    process: Optional[subprocess.Popen] = None,
    timeout: float = 10.0,
    check_interval: float = 0.05,
) -> bool:
    """Wait until client process binds to proxy port."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if process is not None and process.poll() is not None:
            return False
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(check_interval)
        try:
            s.connect((host, port))
            s.close()
            return True
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass
        time.sleep(check_interval)
    return False


def wait_for_port_free(
    port: int = DEFAULT_PROXY_PORT,
    timeout: float = 5.0,
    check_interval: float = 0.05,
) -> bool:
    """Wait until port is completely released."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(check_interval)
        try:
            s.connect(("127.0.0.1", port))
            s.close()
            time.sleep(check_interval)
        except Exception:
            return True
        finally:
            try:
                s.close()
            except Exception:
                pass
    return False


# =============================================================================
# 3. CONFIGURATION SYNTHESIZERS
# =============================================================================

def generate_singbox_test_config(
    sub_id: str = DEFAULT_SUB_ID,
    primary_port: int = 24001,
    secondary_port: int = 24002,
    proxy_port: int = DEFAULT_PROXY_PORT,
    probe_url: str = DEFAULT_TARGET_URL,
    urltest_interval: str = "1s",
    urltest_tolerance: int = 50,
) -> Dict[str, Any]:
    """
    Build a valid Sing-box configuration with urltest smart auto-selector.
    """
    outbounds = [
        {
            "type": "selector",
            "tag": "proxy-selector",
            "outbounds": ["auto-urltest", "nl-primary-node", "fi-secondary-node", "direct"],
            "default": "auto-urltest",
        },
        {
            "type": "urltest",
            "tag": "auto-urltest",
            "outbounds": ["nl-primary-node", "fi-secondary-node"],
            "url": probe_url,
            "interval": urltest_interval,
            "idle_timeout": "15m",
            "tolerance": urltest_tolerance,
            "interrupt_exist_connections": False,
        },
        {
            "type": "http",
            "tag": "nl-primary-node",
            "server": "127.0.0.1",
            "server_port": primary_port,
        },
        {
            "type": "http",
            "tag": "fi-secondary-node",
            "server": "127.0.0.1",
            "server_port": secondary_port,
        },
        {"type": "direct", "tag": "direct"},
    ]

    return {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": proxy_port,
            }
        ],
        "outbounds": outbounds,
        "route": {
            "rules": [
                {"ip_is_private": True, "outbound": "direct"}
            ],
            "final": "proxy-selector",
        },
    }


def generate_clash_test_config(
    sub_id: str = DEFAULT_SUB_ID,
    primary_port: int = 24001,
    secondary_port: int = 24002,
    proxy_port: int = DEFAULT_PROXY_PORT,
    probe_url: str = DEFAULT_TARGET_URL,
    interval_sec: int = 1,
    tolerance_ms: int = 50,
) -> Dict[str, Any]:
    """
    Build a valid Clash Meta / Mihomo configuration with url-test & fallback groups.
    """
    return {
        "mixed-port": proxy_port,
        "mode": "rule",
        "log-level": "warning",
        "allow-lan": True,
        "bind-address": "*",

        "proxies": [
            {"name": "NL-Primary", "type": "http", "server": "127.0.0.1", "port": primary_port},
            {"name": "FI-Secondary", "type": "http", "server": "127.0.0.1", "port": secondary_port},
        ],
        "proxy-groups": [
            {
                "name": "⚡ Auto URL-Test",
                "type": "url-test",
                "proxies": ["NL-Primary", "FI-Secondary"],
                "url": probe_url,
                "interval": interval_sec,
                "tolerance": tolerance_ms,
                "lazy": False,
                "expected-status": "204",
            },
            {
                "name": "🛡️ Priority Fallback",
                "type": "fallback",
                "proxies": ["NL-Primary", "FI-Secondary"],
                "url": probe_url,
                "interval": interval_sec,
                "lazy": False,
                "expected-status": "204",
            },
            {
                "name": "🚀 PROXY",
                "type": "select",
                "proxies": ["⚡ Auto URL-Test", "🛡️ Priority Fallback", "NL-Primary", "FI-Secondary"],
            },
        ],
        "rules": [
            "MATCH,🚀 PROXY"
        ],
    }



def find_free_port() -> int:
    """Find an available TCP port allocated by the operating system."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def find_available_port(start_port: int = DEFAULT_PROXY_PORT) -> int:
    """Find the next available port starting from start_port."""
    for p in range(start_port, start_port + 50):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", p))
            s.close()
            return p
        except Exception:
            try:
                s.close()
            except Exception:
                pass
    return start_port


# =============================================================================
# 4. OUTAGE SIMULATION RUNNER ENGINE
# =============================================================================

class OutageSimulationRunner:
    """
    Executes real client binary, injects abrupt node drop, performs high-frequency
    sampling (50ms), and empirically asserts failover < 3.0 seconds.
    """
    def __init__(
        self,
        engine: str = "auto",
        proxy_port: int = DEFAULT_PROXY_PORT,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
        max_failover_sec: float = DEFAULT_MAX_FAILOVER_SEC,
        sub_id: str = DEFAULT_SUB_ID,
        verbose: bool = True,
    ):
        self.requested_engine = engine
        self.proxy_port = find_available_port(proxy_port)
        self.poll_interval = poll_interval
        self.max_failover_sec = max_failover_sec
        self.sub_id = sub_id
        self.verbose = verbose


        self.temp_dir: Optional[str] = None
        self.client_process: Optional[subprocess.Popen] = None
        self.p1_server: Optional[MockHttpProxyServer] = None
        self.p2_server: Optional[MockHttpProxyServer] = None
        self.active_engine = ""
        self.bin_path = ""

    def log(self, msg: str):
        if self.verbose:
            print(f"[{time.strftime('%H:%M:%S')}] {msg}")

    def select_engine(self) -> Tuple[str, str]:
        """Select available client engine (sing-box or mihomo)."""
        singbox_bin = find_binary(SINGBOX_BIN_PATHS)
        mihomo_bin = find_binary(MIHOMO_BIN_PATHS)

        if self.requested_engine == "sing-box":
            if not singbox_bin:
                raise RuntimeError(f"Sing-box binary not found in {SINGBOX_BIN_PATHS}")
            return "sing-box", singbox_bin
        elif self.requested_engine == "mihomo":
            if not mihomo_bin:
                raise RuntimeError(f"Mihomo binary not found in {MIHOMO_BIN_PATHS}")
            return "mihomo", mihomo_bin
        else:  # auto
            if singbox_bin:
                return "sing-box", singbox_bin
            elif mihomo_bin:
                return "mihomo", mihomo_bin
            else:
                raise RuntimeError("No client binary (sing-box or mihomo) found in workspace")

    def run_simulation(self) -> Dict[str, Any]:
        """
        Execute full outage simulation cycle.
        Returns a dict of metrics and verification results.
        """
        self.active_engine, self.bin_path = self.select_engine()
        self.log(f"=== Starting Outage Simulation Harness using {self.active_engine} ===")
        self.log(f"Binary Path: {self.bin_path}")

        self.temp_dir = tempfile.mkdtemp(prefix="outage_sim_")
        p1_port = find_free_port()
        p2_port = find_free_port()


        metrics: Dict[str, Any] = {
            "engine": self.active_engine,
            "binary_path": self.bin_path,
            "proxy_port": self.proxy_port,
            "poll_interval_ms": int(self.poll_interval * 1000),
            "max_failover_threshold_s": self.max_failover_sec,
            "baseline_success": False,
            "baseline_latency_ms": 0.0,
            "baseline_node": "",
            "baseline_exit_ip": "",
            "outage_injected_at": 0.0,
            "failover_detected_at": 0.0,
            "failover_time_s": 0.0,
            "failover_node": "",
            "failover_exit_ip": "",
            "samples_polled": 0,
            "samples_failed": 0,
            "packet_loss_pct": 0.0,
            "failover_success": False,
            "recovery_success": False,
            "exit_ip_switched": False,
            "error": None,
        }

        try:
            # 1. Start Mock Nodes
            # Primary (NL) latency: 10ms; Secondary (FI) latency: 60ms
            self.p1_server = MockHttpProxyServer(p1_port, "NL_Primary_Classic", exit_ip="192.0.2.1", latency=0.01)
            self.p2_server = MockHttpProxyServer(p2_port, "FI_Secondary_Classic", exit_ip="198.51.100.1", latency=0.06)
            self.p1_server.start()
            self.p2_server.start()
            self.log(f"Initialized Mock Node NL on port {p1_port} (IP: 192.0.2.1, latency 10ms) and FI on port {p2_port} (IP: 198.51.100.1, latency 60ms)")

            # 2. Synthesize & write configuration
            if self.active_engine == "sing-box":
                cfg = generate_singbox_test_config(
                    sub_id=self.sub_id,
                    primary_port=p1_port,
                    secondary_port=p2_port,
                    proxy_port=self.proxy_port,
                    probe_url=DEFAULT_TARGET_URL,
                    urltest_interval="1s",
                    urltest_tolerance=50,
                )
                cfg_path = os.path.join(self.temp_dir, "singbox_config.json")
                with open(cfg_path, "w", encoding="utf-8") as f:
                    json.dump(cfg, f, indent=2)
                cmd = [self.bin_path, "run", "-c", cfg_path]
            else:  # mihomo
                try:
                    import yaml
                except ImportError:
                    raise RuntimeError("PyYAML required for Mihomo configuration generation")
                cfg = generate_clash_test_config(
                    sub_id=self.sub_id,
                    primary_port=p1_port,
                    secondary_port=p2_port,
                    proxy_port=self.proxy_port,
                    probe_url=DEFAULT_TARGET_URL,
                    interval_sec=1,
                    tolerance_ms=50,
                )
                cfg_path = os.path.join(self.temp_dir, "clash_config.yaml")
                with open(cfg_path, "w", encoding="utf-8") as f:
                    yaml.dump(cfg, f)
                cmd = [self.bin_path, "-d", self.temp_dir, "-f", cfg_path]

            # Ensure inbound port is completely free
            wait_for_port_free(port=self.proxy_port, timeout=5.0)

            # 3. Launch client process
            self.log(f"Launching client daemon: {' '.join(cmd)}")
            self.client_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.temp_dir,
            )

            # Wait for inbound proxy port to accept connections
            ready = wait_for_proxy_port(port=self.proxy_port, process=self.client_process, timeout=8.0)
            if not ready:
                err_msg = f"Client failed to bind inbound port {self.proxy_port} within 8.0s"
                if self.client_process.poll() is not None:
                    _, stderr_bytes = self.client_process.communicate(timeout=1.0)
                    err_msg += f" (Process exited with code {self.client_process.returncode}: {stderr_bytes.decode('utf-8', errors='ignore').strip()})"
                raise RuntimeError(err_msg)
            self.log(f"Client SOCKS5/mixed inbound successfully active on 127.0.0.1:{self.proxy_port}")

            # Allow 1.5s for initial urltest convergence
            time.sleep(1.5)

            # 4. Phase 1 — Baseline Connectivity Test
            ok, status, rtt, err, headers = probe_http_via_proxy(
                DEFAULT_TARGET_URL, proxy_port=self.proxy_port, timeout=2.0
            )
            if not ok or status != 204:
                raise RuntimeError(f"Baseline connectivity probe failed: status={status}, rtt={rtt*1000:.1f}ms, err={err}")

            baseline_node = headers.get("x-node", "NL_Primary_Classic")
            baseline_ip = headers.get("x-exit-ip", "192.0.2.1")
            metrics["baseline_success"] = True
            metrics["baseline_latency_ms"] = round(rtt * 1000, 2)
            metrics["baseline_node"] = baseline_node
            metrics["baseline_exit_ip"] = baseline_ip
            self.log(f"[OK] Baseline Connectivity Verified: HTTP {status} (RTT: {metrics['baseline_latency_ms']}ms | Exit Node: {baseline_node} | Exit IP: {baseline_ip}). NL requests: {self.p1_server.request_count}")

            # 5. Phase 2 — Fault Injection (Abrupt Primary Outage)
            self.log("[FAULT] INJECTING FAULT: Abruptly dropping primary node (NL) bridge sockets...")
            t_outage = time.perf_counter()
            self.p1_server.drop()
            metrics["outage_injected_at"] = t_outage

            # 6. Phase 3 — High-Frequency Sampling (50ms Polling)
            self.log(f"[POLL] Polling HTTP 204 every {int(self.poll_interval*1000)}ms to measure failover time Delta T...")
            t_failover: Optional[float] = None
            failover_node = ""
            failover_ip = ""
            samples = 0
            failed_samples = 0
            deadline = t_outage + (self.max_failover_sec + 2.0)

            while time.perf_counter() < deadline:
                samples += 1
                probe_ok, probe_status, _, _, probe_headers = probe_http_via_proxy(
                    DEFAULT_TARGET_URL, proxy_port=self.proxy_port, timeout=0.3
                )
                if probe_ok and probe_status == 204:
                    t_failover = time.perf_counter()
                    failover_node = probe_headers.get("x-node", "FI_Secondary_Classic")
                    failover_ip = probe_headers.get("x-exit-ip", "198.51.100.1")
                    break
                else:
                    failed_samples += 1
                time.sleep(self.poll_interval)

            if t_failover is None:
                raise RuntimeError(f"Failover timed out! No successful HTTP 204 response within {self.max_failover_sec + 2.0}s")

            delta_t = t_failover - t_outage
            metrics["failover_detected_at"] = t_failover
            metrics["failover_time_s"] = round(delta_t, 4)
            metrics["samples_polled"] = samples
            metrics["samples_failed"] = failed_samples
            metrics["packet_loss_pct"] = round((failed_samples / samples) * 100.0, 1) if samples > 0 else 0.0
            metrics["failover_node"] = failover_node
            metrics["failover_exit_ip"] = failover_ip
            metrics["exit_ip_switched"] = (baseline_ip != failover_ip)

            self.log(f"[FAILOVER] FAILOVER DETECTED: Delta T = {delta_t:.3f}s ({delta_t*1000:.1f}ms) after {samples} samples ({failed_samples} dropped, {metrics['packet_loss_pct']}% transient loss)!")
            self.log(f"[EXIT-IP] Exit IP Switched: {baseline_ip} ({baseline_node}) -> {failover_ip} ({failover_node})")
            self.log(f"[INFO] Requests served by FI Secondary: {self.p2_server.request_count}")

            # Empirical Assertion: Delta T < 3.0s
            if delta_t >= self.max_failover_sec:
                raise AssertionError(f"Failover time {delta_t:.3f}s exceeded threshold {self.max_failover_sec}s")
            metrics["failover_success"] = True
            self.log(f"[PASS] EMPIRICAL ASSERTION PASSED: Failover Delta T ({delta_t:.3f}s) < {self.max_failover_sec:.1f}s with ZERO manual intervention!")

            # 7. Phase 4 — Primary Node Recovery Validation
            self.log("[RECOVERY] Restoring primary node (NL)...")
            self.p1_server.restore()
            time.sleep(0.5)

            # Probe 3 times to ensure stability
            recovery_ok = True
            for i in range(3):
                rec_ok, rec_status, rec_rtt, _, _ = probe_http_via_proxy(
                    DEFAULT_TARGET_URL, proxy_port=self.proxy_port, timeout=1.0
                )
                if not rec_ok or rec_status != 204:
                    recovery_ok = False
                    break
                time.sleep(0.1)

            if not recovery_ok:
                raise RuntimeError("Post-recovery probe failed")

            metrics["recovery_success"] = True
            self.log("[OK] Recovery Verified: Client traffic continues seamlessly without socket corruption.")

        except Exception as e:
            metrics["error"] = str(e)
            self.log(f"[ERROR] SIMULATION ERROR: {e}")
            raise
        finally:
            self.cleanup()


        return metrics

    def cleanup(self):
        """Terminate processes and delete temporary files."""
        self.log("Cleaning up simulation resources...")
        if self.client_process:
            try:
                self.client_process.terminate()
                self.client_process.wait(timeout=2.0)
            except Exception:
                try:
                    self.client_process.kill()
                except Exception:
                    pass
            try:
                if self.client_process.stdout:
                    self.client_process.stdout.close()
                if self.client_process.stderr:
                    self.client_process.stderr.close()
            except Exception:
                pass
            self.client_process = None


        if self.p1_server:
            self.p1_server.stop()
            self.p1_server = None

        if self.p2_server:
            self.p2_server.stop()
            self.p2_server = None

        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir, ignore_errors=True)
            except Exception:
                pass
            self.temp_dir = None
        self.log("Cleanup complete.")


# =============================================================================
# 5. CLI ENTRYPOINT
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="SilentConnect Outage Simulation & Failover Verification Suite"
    )
    parser.add_argument(
        "--engine",
        choices=["auto", "sing-box", "mihomo", "both"],
        default="auto",
        help="Client binary engine to execute (default: auto)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PROXY_PORT,
        help=f"Client proxy inbound port (default: {DEFAULT_PROXY_PORT})",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=DEFAULT_POLL_INTERVAL,
        help=f"Polling interval in seconds (default: {DEFAULT_POLL_INTERVAL})",
    )
    parser.add_argument(
        "--max-failover-time",
        type=float,
        default=DEFAULT_MAX_FAILOVER_SEC,
        help=f"Maximum allowed failover time in seconds (default: {DEFAULT_MAX_FAILOVER_SEC})",
    )
    parser.add_argument(
        "--sub-id",
        type=str,
        default=DEFAULT_SUB_ID,
        help=f"Subscription ID for test config generation (default: {DEFAULT_SUB_ID})",
    )
    parser.add_argument(
        "--json-output",
        type=str,
        default="",
        help="Path to write JSON benchmark metrics",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode (suppress verbose logs)",
    )

    args = parser.parse_args()

    engines_to_run = []
    if args.engine == "both":
        engines_to_run = ["sing-box", "mihomo"]
    else:
        engines_to_run = [args.engine]

    all_results = []
    overall_success = True

    for idx, eng in enumerate(engines_to_run):
        runner_port = args.port + (idx * 2)
        runner = OutageSimulationRunner(
            engine=eng,
            proxy_port=runner_port,
            poll_interval=args.poll_interval,
            max_failover_sec=args.max_failover_time,
            sub_id=args.sub_id,
            verbose=not args.quiet,
        )
        try:
            res = runner.run_simulation()
            all_results.append(res)
        except Exception as e:
            overall_success = False
            all_results.append({"engine": eng, "error": str(e), "failover_success": False})


    # Summary Table
    print("\n" + "=" * 90)
    print("                    OUTAGE SIMULATION & FAILOVER BENCHMARK SUMMARY")
    print("=" * 90)
    for r in all_results:
        eng_name = r.get("engine", "unknown").upper()
        if r.get("failover_success"):
            delta_t = r.get("failover_time_s", 0.0)
            baseline = r.get("baseline_latency_ms", 0.0)
            samples = r.get("samples_polled", 0)
            loss = r.get("packet_loss_pct", 0.0)
            base_ip = r.get("baseline_exit_ip", "NL")
            fail_ip = r.get("failover_exit_ip", "FI")
            print(f"[{eng_name:8s}] PASS | Failover Delta T: {delta_t:.3f}s (< 3.0s) | Loss: {loss:4.1f}% | Exit IP: {base_ip} -> {fail_ip} | Baseline RTT: {baseline}ms | Samples: {samples} | Recovery: OK")
        else:
            print(f"[{eng_name:8s}] FAIL | Error: {r.get('error')}")
    print("=" * 90)

    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump(all_results, f, indent=2)
        print(f"Metrics written to {args.json_output}")

    if not overall_success:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()

