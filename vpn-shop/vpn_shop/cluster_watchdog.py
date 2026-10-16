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
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:
    fcntl = None  # type: ignore

try:
    import msvcrt
except ImportError:
    msvcrt = None  # type: ignore

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
        elif msvcrt:
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
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
        elif msvcrt:
            try:
                lock_handle.seek(0)
                msvcrt.locking(lock_handle.fileno(), msvcrt.LK_UNLCK, 1)
            except Exception:
                pass
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

    checked_at = float(data.get("last_successful_check_at") or data.get("checked_at") or 0.0)
    now = time.time()
    age = now - checked_at if checked_at > 0 else float("inf")

    if checked_at == 0.0 or age > max_age_seconds:
        return 503, {
            "ok": False,
            "stale": True,
            "error": "watchdog_stale",
            "message": f"Cluster health data is stale ({round(age, 1) if checked_at > 0 else 'never'}s old > {max_age_seconds}s limit)",
            "age_seconds": round(age, 1) if checked_at > 0 else None,
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
    """Execute one complete cluster health check cycle and update cache & dead man's switch.
    Stale timestamp 'checked_at' is recorded ONLY from successful checks to ensure fail-closed
    behavior if monitoring attempts repeatedly fail.
    """
    path = _get_cache_path(cache_path)
    prev_last_success: float = 0.0
    if path.is_file():
        try:
            prev_data = json.loads(path.read_text(encoding="utf-8"))
            prev_last_success = float(prev_data.get("last_successful_check_at") or prev_data.get("checked_at") or 0.0)
        except Exception:
            pass

    nodes = {}
    for code in ("nl", "pl", "fi"):
        res = check_node_health(code)
        nodes[code] = res

    # NL is primary; if NL is down, cluster is down
    nl_healthy = nodes.get("nl", {}).get("healthy", False)
    all_ok = nl_healthy

    now = time.time()
    last_successful_check_at = now if all_ok else prev_last_success

    health_data = {
        "ok": all_ok,
        "checked_at": last_successful_check_at,
        "last_successful_check_at": last_successful_check_at,
        "last_attempt_at": now,
        "primary": "nl",
        "nodes": nodes,
    }
    save_health_cache(health_data, cache_path=cache_path)
    if all_ok:
        send_heartbeat()
    return health_data


def run_watchdog_daemon(
    check_interval: int = 30,
    retry_leader_interval: int = 30,
    max_iterations: int | None = None,
    stop_event: threading.Event | None = None,
    cache_path: str | Path | None = None,
    lock_path: str | Path | None = None,
) -> None:
    """Run watchdog daemon with dynamic leader election and follower retry loop.
    - If leader: runs health cycles every `check_interval` seconds.
    - If follower: standby loop retrying leader lock every `retry_leader_interval` seconds.
    - If leader terminates, follower seamlessly takes over leadership.
    """
    iteration = 0
    leader_handle: Any | None = None

    LOGGER.info("Starting cluster watchdog process (PID %s)...", os.getpid())

    try:
        while True:
            if stop_event and stop_event.is_set():
                break
            if max_iterations is not None and iteration >= max_iterations:
                break

            # 1. Try to acquire leader lock if not currently holding it
            if leader_handle is None:
                leader_handle = try_acquire_leader_lock(lock_path)
                if leader_handle:
                    LOGGER.info(
                        "[LEADER] Successfully acquired leader lock. Process %s is now cluster watchdog leader.",
                        os.getpid(),
                    )
                else:
                    LOGGER.info(
                        "[FOLLOWER] Leader lock held by another process. Entering standby retry loop (every %ds)...",
                        retry_leader_interval,
                    )
                    if stop_event:
                        stop_event.wait(timeout=retry_leader_interval)
                    else:
                        time.sleep(retry_leader_interval)
                    iteration += 1
                    continue

            # 2. As leader: run single health cycle
            try:
                cycle_data = run_single_health_cycle(cache_path=cache_path)
                LOGGER.info("[CYCLE %d] Health cycle completed: ok=%s", iteration + 1, cycle_data.get("ok"))
            except Exception as exc:
                LOGGER.error("Health check cycle encountered error: %s", exc)

            iteration += 1
            if max_iterations is not None and iteration >= max_iterations:
                break

            if stop_event:
                stop_event.wait(timeout=check_interval)
            else:
                time.sleep(check_interval)
    finally:
        if leader_handle is not None:
            LOGGER.info("Releasing leader lock on shutdown...")
            release_leader_lock(leader_handle)


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="SilentConnect High Availability Cluster Watchdog Daemon")
    parser.add_argument("--once", action="store_true", help="Run a single health check cycle and exit")
    parser.add_argument("--interval", type=int, default=30, help="Check interval in seconds for leader (default: 30)")
    parser.add_argument("--leader-retry", type=int, default=30, help="Follower leader lock retry interval (default: 30)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    if args.once:
        data = run_single_health_cycle()
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return 0 if data.get("ok") else 1

    run_watchdog_daemon(check_interval=args.interval, retry_leader_interval=args.leader_retry)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
