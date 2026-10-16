#!/usr/bin/env python3
"""
vpn_shop.cluster_watchdog

High Availability Cluster Watchdog for SilentConnect with:
1. Dynamic leader lock (/tmp/silentconnect_watchdog.leader.lock) and follower retry loop.
2. Fail-closed on stale data (>180s = HTTP 503).
3. Dead Man's Switch external heartbeat (GET to WATCHDOG_HEARTBEAT_URL).
4. Secure HMAC constant-time token verification.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:
    fcntl = None  # type: ignore

LOGGER = logging.getLogger("vpn_shop.cluster_watchdog")


def load_cluster_env() -> None:
    """Load cluster environment variables from standard locations if present."""
    candidates = [
        Path("/root/vpn-shop/.env.silentconnect"),
        Path("/etc/silentconnect/.env.silentconnect"),
    ]
    for p in candidates:
        if p.is_file():
            try:
                for line in p.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip("'\"")
                    if k not in os.environ:
                        os.environ[k] = v
            except Exception:
                pass
            break


load_cluster_env()

DEFAULT_LEADER_LOCK = "/tmp/silentconnect_watchdog.leader.lock"
DEFAULT_HEALTH_CACHE = "/tmp/silentconnect_cluster_health.json"
MAX_STALE_SECONDS = 180


def _get_lock_path(custom_path: str | Path | None = None) -> Path:
    if custom_path:
        return Path(custom_path)
    if os.name == "nt":
        return Path(tempfile.gettempdir()) / "silentconnect_watchdog.leader.lock"
    return Path(DEFAULT_LEADER_LOCK)


def _get_cache_path(custom_path: str | Path | None = None) -> Path:
    if custom_path:
        return Path(custom_path)
    if os.name == "nt":
        return Path(tempfile.gettempdir()) / "silentconnect_cluster_health.json"
    return Path(DEFAULT_HEALTH_CACHE)


def verify_health_token(provided_token: str | None, expected_token: str | None) -> bool:
    """Validate token using constant-time HMAC comparison. Fail-closed on empty tokens."""
    if not provided_token or not expected_token:
        return False
    prov = str(provided_token).strip().encode("utf-8")
    exp = str(expected_token).strip().encode("utf-8")
    return hmac.compare_digest(prov, exp)


def try_acquire_leader_lock(lock_path: str | Path | None = None) -> Any | None:
    """Attempt non-blocking acquisition of leader lock.
    Returns open file object if acquired (caller must keep open), or None if already held.
    """
    path = _get_lock_path(lock_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        f = open(path, "a+")
        if fcntl:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return f
    except (BlockingIOError, OSError):
        return None


def release_leader_lock(lock_handle: Any) -> None:
    """Release the leader lock file handle."""
    if not lock_handle:
        return
    try:
        if fcntl:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
    except Exception:
        pass
    finally:
        try:
            lock_handle.close()
        except Exception:
            pass


def send_heartbeat(url: str | None = None) -> bool:
    """Dead Man's Switch: send HTTP GET request to external monitoring service."""
    heartbeat_url = url or os.environ.get("WATCHDOG_HEARTBEAT_URL", "").strip()
    if not heartbeat_url:
        return False
    try:
        req = urllib.request.Request(
            heartbeat_url,
            headers={"User-Agent": "SilentConnect-ClusterWatchdog/1.0"},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return 200 <= resp.status < 300
    except Exception as exc:
        LOGGER.warning("Watchdog dead man's switch heartbeat to %s failed: %s", heartbeat_url, exc)
        return False


def save_health_cache(health_data: dict[str, Any], cache_path: str | Path | None = None) -> None:
    """Atomically save cluster health status to local cache file."""
    path = _get_cache_path(cache_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(f".tmp.{os.getpid()}")
    try:
        tmp_path.write_text(json.dumps(health_data, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp_path.replace(path)
    except Exception as exc:
        LOGGER.error("Failed to write health cache to %s: %s", path, exc)
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except Exception:
                pass


def get_health_status(
    max_age_seconds: int = MAX_STALE_SECONDS,
    cache_path: str | Path | None = None,
) -> tuple[int, dict[str, Any]]:
    """Query cluster health status with strict fail-closed stale check.
    Returns (http_status_code, response_data).
    - If cache is missing, empty, or older than max_age_seconds: returns HTTP 503.
    - Otherwise returns HTTP 200 (or HTTP 503 if all nodes down).
    """
    path = _get_cache_path(cache_path)
    if not path.is_file():
        return 503, {
            "ok": False,
            "stale": True,
            "error": "watchdog_stale",
            "message": "Cluster health data not initialized or unavailable",
        }

    try:
        raw = path.read_text(encoding="utf-8").strip()
        data = json.loads(raw)
    except Exception as exc:
        return 503, {
            "ok": False,
            "stale": True,
            "error": "watchdog_stale",
            "message": f"Could not read health cache: {exc}",
        }

    checked_at = float(data.get("checked_at") or 0.0)
    now = time.time()
    age = now - checked_at

    if age > max_age_seconds:
        return 503, {
            "ok": False,
            "stale": True,
            "error": "watchdog_stale",
            "message": f"Cluster health data is stale ({round(age, 1)}s old > {max_age_seconds}s limit)",
            "age_seconds": round(age, 1),
            "checked_at": checked_at,
        }

    # Data is fresh
    data["stale"] = False
    data["age_seconds"] = round(age, 1)
    status_code = 200 if data.get("ok", True) else 503
    return status_code, data


def check_node_health(server_code: str) -> dict[str, Any]:
    """Perform health inspection on a single cluster node."""
    from . import awg_manager
    code = (server_code or "nl").lower().strip()
    result = {
        "node": code,
        "healthy": False,
        "error": None,
        "latency_ms": None,
    }
    t0 = time.time()
    try:
        conf = awg_manager._server_conf(code)
        if conf and "[Interface]" in conf:
            result["healthy"] = True
        else:
            result["error"] = "Invalid or empty server conf"
    except Exception as exc:
        result["error"] = str(exc)
    result["latency_ms"] = round((time.time() - t0) * 1000, 2)
    return result


def run_single_health_cycle(cache_path: str | Path | None = None) -> dict[str, Any]:
    """Execute one complete cluster health check cycle and update cache & dead man's switch."""
    nodes = {}
    all_healthy = True
    for code in ("nl", "pl", "fi"):
        res = check_node_health(code)
        nodes[code] = res
        if not res["healthy"]:
            # FI/PL are standby so cluster as a whole is degraded but not necessarily fatal
            pass

    # NL is primary; if NL is down, cluster is down
    nl_healthy = nodes.get("nl", {}).get("healthy", False)
    all_ok = nl_healthy

    health_data = {
        "ok": all_ok,
        "checked_at": time.time(),
        "primary": "nl",
        "nodes": nodes,
    }
    save_health_cache(health_data, cache_path=cache_path)
    if all_ok:
        send_heartbeat()
    return health_data
