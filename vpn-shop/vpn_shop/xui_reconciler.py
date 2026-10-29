from __future__ import annotations

import json
import logging
import os
import signal
import sqlite3
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:
    fcntl = None  # type: ignore

from .config import Settings, load_settings
from .provisioning import PUBLIC_TRIAL_PROFILE_NOTES, TEST_PROFILE_NOTES
from .security import now_ts, to_xui_ms
from .store import Store
from .xui_api import XuiApiClient, XuiApiError
from .xui_db import XuiDatabase

LOGGER = logging.getLogger("vpn_shop.xui_reconciler")

LOCK_FILE_PATH = (
    Path(tempfile.gettempdir()) / "silentconnect_xui_reconcile.lock"
    if os.name == "nt"
    else Path("/tmp/silentconnect_xui_reconcile.lock")
)
PID_FILE_PATH = (
    Path(tempfile.gettempdir()) / "silentconnect_xui_reconcile.pid"
    if os.name == "nt"
    else Path("/tmp/silentconnect_xui_reconcile.pid")
)


def _extract_sub_id_for_profile(prof: dict[str, Any], order_meta: dict[str, Any] | None = None) -> str:
    """Resolve deterministic subId for profile across all cluster nodes."""
    sub_id = str(prof.get("xui_sub_id") or "").strip()
    if sub_id:
        return sub_id
    if order_meta:
        transport = str(prof.get("transport") or "tcp")
        if transport == "xhttp" and order_meta.get("xhttp_sub_id"):
            return str(order_meta["xhttp_sub_id"]).strip()
        if order_meta.get("tcp_sub_id"):
            return str(order_meta["tcp_sub_id"]).strip()
        if order_meta.get("sub_id"):
            return str(order_meta["sub_id"]).strip()
    # Deterministic fallback: public_id without prefix or public_id itself
    pub = str(prof.get("public_id") or "").strip()
    return pub


def _inbound_needs_vision_flow(inbound_row: dict[str, Any]) -> bool:
    """Return True if this VLESS inbound uses TCP + Reality/TLS with xtls-rprx-vision."""
    stream = inbound_row.get("stream_settings") or {}
    network = str(stream.get("network") or "tcp").lower()
    if network not in ("tcp", "raw"):
        return False
    port = int(inbound_row.get("port") or 0)
    if port in (23385, 24443, 443):
        return True
    settings = inbound_row.get("settings") or {}
    for cl in settings.get("clients") or []:
        if cl.get("flow") == "xtls-rprx-vision":
            return True
    return False


class XuiReconciler:
    """Autonomous Zero-Downtime 3X-UI Pull Reconciler."""

    def __init__(self, settings: Settings, store: Store) -> None:
        self.settings = settings
        self.store = store
        self.xui_db = XuiDatabase(settings.xui_db_path)
        self.xui_api = XuiApiClient(
            panel_url=settings.xui_panel_url,
            username=settings.xui_username,
            password=settings.xui_password,
            verify_tls=settings.xui_verify_tls,
        )
        self._wake_event = threading.Event()

    def trigger_wake(self) -> None:
        self._wake_event.set()

    def _load_shop_profiles(self) -> list[dict[str, Any]]:
        """Load all non-empty profiles from local Turso replica along with order sub_id metadata."""
        if getattr(self.store, "_replica_mgr", None) is not None:
            self.store._replica_mgr.sync_if_stale()

        with self.store.connection() as conn:
            cols = {str(r["name"]) for r in conn.execute("PRAGMA table_info(profiles)").fetchall()}
            has_sub_col = "xui_sub_id" in cols
            sub_select = "p.xui_sub_id," if has_sub_col else "NULL AS xui_sub_id,"
            dev_select = "p.device_limit," if "device_limit" in cols else "3 AS device_limit,"
            rows = conn.execute(
                f"""
                SELECT p.id, p.public_id, p.xui_inbound_id, p.transport, p.profile_mode,
                       p.family_label, p.xui_email, p.xui_client_id, {sub_select}
                       p.status, p.expires_at, p.notes, {dev_select}
                       o.meta_json AS order_meta_json
                FROM profiles p
                LEFT JOIN orders o ON o.provisioned_profile_id = p.id
                ORDER BY p.id ASC, o.id DESC
                """
            ).fetchall()

        by_email: dict[str, dict[str, Any]] = {}
        for r in rows:
            d = dict(r)
            email = str(d.get("xui_email") or "").strip()
            if not email or email in by_email:
                continue
            meta = {}
            if d.get("order_meta_json"):
                try:
                    meta = json.loads(d["order_meta_json"]) if isinstance(d["order_meta_json"], str) else d["order_meta_json"]
                except Exception:
                    meta = {}
            d["resolved_sub_id"] = _extract_sub_id_for_profile(d, meta)
            by_email[email] = d
        return list(by_email.values())

    def _backfill_missing_sub_ids_from_local_xui(
        self,
        profiles: list[dict[str, Any]],
        local_clients_by_email: dict[str, dict[str, Any]],
    ) -> None:
        """One-time self-healing: if local x-ui.db has subId that is missing in Turso profiles, persist it."""
        updates: list[tuple[str, str]] = []
        for prof in profiles:
            email = str(prof["xui_email"])
            db_sub_id = str(prof.get("xui_sub_id") or "").strip()
            if not db_sub_id and email in local_clients_by_email:
                local_sub = str(local_clients_by_email[email].get("subId") or "").strip()
                if local_sub:
                    prof["xui_sub_id"] = local_sub
                    prof["resolved_sub_id"] = local_sub
                    updates.append((local_sub, str(prof["public_id"])))

        if updates:
            try:
                with self.store.transaction() as conn:
                    for sub_val, pub_id in updates:
                        conn.execute(
                            "UPDATE profiles SET xui_sub_id = ? WHERE public_id = ? AND (xui_sub_id IS NULL OR xui_sub_id = '')",
                            (sub_val, pub_id),
                        )
                LOGGER.info("Backfilled %d missing xui_sub_id values into Turso profiles", len(updates))
            except Exception as exc:
                LOGGER.debug("Could not backfill xui_sub_id: %s", exc)

    def reconcile_once(self, *, dry_run: bool = False) -> dict[str, Any]:
        """Run a single autonomous reconciliation pass."""
        t0 = time.perf_counter()
        LOCK_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
        lock_file = open(LOCK_FILE_PATH, "a+")
        try:
            if fcntl:
                try:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    return {"ok": True, "skipped": "lock_busy"}

            if not self.settings.xui_db_path.exists():
                return {"ok": False, "error": f"xui_db_not_found: {self.settings.xui_db_path}"}

            profiles = self._load_shop_profiles()
            if not profiles:
                # Zero-Profiles Circuit Breaker
                LOGGER.warning("Turso returned 0 profiles; aborting reconciliation (circuit breaker)")
                return {"ok": True, "skipped": "zero_profiles_circuit_breaker"}

            # Read current local x-ui.db inbounds in RO mode
            self.xui_db.invalidate_cache()
            self.xui_db._ensure_cache()
            inbounds = [
                ib for ib in self.xui_db._inbounds_cached
                if str(ib.get("protocol") or "").lower() == "vless"
            ]
            if not inbounds:
                return {"ok": False, "error": "no_vless_inbounds_in_xui_db"}

            # Map existing clients across all local VLESS inbounds
            local_by_email: dict[str, dict[str, Any]] = {}
            inbound_clients_map: dict[int, dict[str, dict[str, Any]]] = {}
            for ib in inbounds:
                ib_id = int(ib["id"])
                cl_map: dict[str, dict[str, Any]] = {}
                for cl in (ib.get("settings") or {}).get("clients") or []:
                    em = str(cl.get("email") or "").strip()
                    uid = str(cl.get("id") or "").strip()
                    if em:
                        cl_map[em] = cl
                        if em not in local_by_email:
                            local_by_email[em] = cl
                    if uid:
                        cl_map[uid] = cl
                inbound_clients_map[ib_id] = cl_map

            # Backfill xui_sub_id if this node (e.g. NL) has existing subIds not yet in Turso
            if not dry_run:
                self._backfill_missing_sub_ids_from_local_xui(profiles, local_by_email)

            now_s = now_ts()
            added_count = 0
            updated_count = 0
            disabled_count = 0
            deleted_count = 0
            errors: list[str] = []
            db_direct_fixes: list[tuple[dict[str, Any], bool, int, str, int]] = []

            for prof in profiles:
                email = str(prof["xui_email"]).strip()
                uuid = str(prof["xui_client_id"]).strip()
                if not email or not uuid or len(uuid) < 16:
                    continue

                status = str(prof.get("status") or "active")
                expires_at_s = int(prof.get("expires_at") or 0)
                is_expired = 0 < expires_at_s <= now_s
                should_enable = (status == "active") and not is_expired
                exp_ms = to_xui_ms(expires_at_s) if expires_at_s > 0 else 0
                dev_limit = max(int(prof.get("device_limit") or self.settings.default_device_limit or 3), 0)

                existing_local = local_by_email.get(email)
                sub_id = str(prof.get("resolved_sub_id") or "").strip()
                if existing_local and existing_local.get("subId") and (not prof.get("xui_sub_id")):
                    sub_id = str(existing_local["subId"]).strip()
                if not sub_id:
                    sub_id = str(prof["public_id"])

                # Case 1: Deleted profile (or expired auto-delete trial)
                notes = str(prof.get("notes") or "")
                should_purge = (status == "deleted") or (
                    is_expired and notes in {TEST_PROFILE_NOTES, PUBLIC_TRIAL_PROFILE_NOTES}
                )
                if should_purge:
                    if email in local_by_email or uuid in local_by_email:
                        if not dry_run:
                            for ib in inbounds:
                                ib_id = int(ib["id"])
                                if email in inbound_clients_map[ib_id] or uuid in inbound_clients_map[ib_id]:
                                    try:
                                        self.xui_api.delete_client(ib_id, email)
                                    except Exception:
                                        try:
                                            self.xui_api.delete_client(ib_id, uuid)
                                        except Exception as exc:
                                            LOGGER.debug("Delete client %s (%s) on inbound %d failed: %s", email, uuid, ib_id, exc)
                        deleted_count += 1
                    continue

                # Case 2: Active or Expired profile — check if missing or out-of-sync on ANY VLESS inbound
                needs_add_inbounds: list[dict[str, Any]] = []
                needs_update_inbounds: list[dict[str, Any]] = []

                for ib in inbounds:
                    ib_id = int(ib["id"])
                    cl_map = inbound_clients_map[ib_id]
                    cur_cl = cl_map.get(email) or cl_map.get(uuid)
                    if cur_cl is None:
                        if should_enable:
                            needs_add_inbounds.append(ib)
                    else:
                        cur_en = bool(cur_cl.get("enable", True))
                        cur_exp = int(cur_cl.get("expiryTime") or 0)
                        cur_sub = str(cur_cl.get("subId") or "").strip()
                        cur_lim = int(cur_cl.get("limitIp") or 0)
                        if (
                            cur_en != should_enable
                            or cur_exp != exp_ms
                            or (sub_id and cur_sub != sub_id)
                            or (should_enable and dev_limit > 0 and cur_lim != dev_limit)
                        ):
                            needs_update_inbounds.append(ib)

                if not needs_add_inbounds and not needs_update_inbounds:
                    continue

                if dry_run:
                    if needs_add_inbounds:
                        added_count += 1
                    elif not should_enable:
                        disabled_count += 1
                    else:
                        updated_count += 1
                    continue

                # Apply changes via local 3X-UI API (zero-downtime in-memory Xray update)
                api_ok = True
                for ib in needs_add_inbounds:
                    ib_id = int(ib["id"])
                    flow = "xtls-rprx-vision" if _inbound_needs_vision_flow(ib) else ""
                    client_payload = {
                        "id": uuid,
                        "email": email,
                        "enable": should_enable,
                        "flow": flow,
                        "limitIp": dev_limit,
                        "totalGB": 0,
                        "expiryTime": exp_ms,
                        "tgId": 0,
                        "subId": sub_id,
                        "reset": 0,
                        "comment": "",
                    }
                    try:
                        self.xui_api.add_client(ib_id, client_payload)
                    except XuiApiError as exc:
                        # If already exists in `clients` table, fallback to update_client
                        try:
                            self.xui_api.update_client(ib_id, uuid, client_payload)
                        except Exception as u_exc:
                            api_ok = False
                            errors.append(f"add {email} ib={ib_id}: {u_exc}")

                for ib in needs_update_inbounds:
                    ib_id = int(ib["id"])
                    flow = "xtls-rprx-vision" if _inbound_needs_vision_flow(ib) else ""
                    client_payload = {
                        "id": uuid,
                        "email": email,
                        "enable": should_enable,
                        "flow": flow,
                        "limitIp": dev_limit,
                        "totalGB": 0,
                        "expiryTime": exp_ms,
                        "tgId": 0,
                        "subId": sub_id,
                        "reset": 0,
                        "comment": "",
                    }
                    try:
                        self.xui_api.update_client(ib_id, uuid, client_payload)
                    except Exception as exc:
                        api_ok = False
                        errors.append(f"update {email} ib={ib_id}: {exc}")

                db_direct_fixes.append((prof, should_enable, exp_ms, sub_id, dev_limit))
                if needs_add_inbounds:
                    added_count += 1
                    LOGGER.info("Zero-downtime client %s (%s) ADDED across %d inbound(s)", email, uuid, len(needs_add_inbounds))
                elif not should_enable:
                    disabled_count += 1
                    LOGGER.info("Zero-downtime client %s DISABLED (expired/revoked)", email)
                else:
                    updated_count += 1
                    LOGGER.info("Zero-downtime client %s UPDATED (exp=%d, limit=%d)", email, exp_ms, dev_limit)

            # Ensure SQLite tables (`inbounds.settings`, `clients`, `client_traffics`, `client_inbounds`)
            # are 100% aligned for subjson-service and Hysteria2 auth
            if db_direct_fixes and not dry_run:
                self._align_local_xui_sqlite(db_direct_fixes)
                self._sync_local_ws443_if_present()

            if not dry_run:
                self._reconcile_local_awg_and_traffic()

            elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
            return {
                "ok": len(errors) == 0,
                "dry_run": dry_run,
                "profiles_checked": len(profiles),
                "added": added_count,
                "updated": updated_count,
                "disabled": disabled_count,
                "deleted": deleted_count,
                "errors": errors,
                "elapsed_ms": elapsed_ms,
            }
        finally:
            if fcntl:
                try:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
                except Exception:
                    pass
            lock_file.close()

    def _align_local_xui_sqlite(
        self,
        fixes: list[tuple[dict[str, Any], bool, int, str, int]],
    ) -> None:
        """Align inbounds.settings, clients, client_traffics, and client_inbounds in local x-ui.db."""
        conn = sqlite3.connect(self.settings.xui_db_path, timeout=30.0)
        conn.execute("PRAGMA busy_timeout = 30000;")
        try:
            now_ms = int(time.time() * 1000)
            inbounds_rows = conn.execute(
                "SELECT id, tag, protocol, port, settings, stream_settings FROM inbounds WHERE LOWER(protocol) = 'vless'"
            ).fetchall()

            for prof, should_enable, exp_ms, sub_id, dev_limit in fixes:
                email = str(prof["xui_email"]).strip()
                uuid = str(prof["xui_client_id"]).strip()

                # 1. Align `clients` table if present
                try:
                    cur = conn.execute(
                        "UPDATE clients SET enable = ?, expiry_time = ?, sub_id = ?, limit_ip = ?, updated_at = ? WHERE email = ? OR uuid = ?",
                        (int(should_enable), exp_ms, sub_id, dev_limit, now_ms, email, uuid),
                    )
                    if cur.rowcount == 0 and should_enable:
                        conn.execute(
                            """
                            INSERT OR IGNORE INTO clients (
                                email, sub_id, uuid, password, auth, flow, security, reverse,
                                wg_private_key, wg_public_key, wg_allowed_ips, wg_pre_shared_key,
                                wg_keep_alive, secret, ad_tag, limit_ip, total_gb, expiry_time,
                                enable, tg_id, group_name, comment, reset, created_at, updated_at
                            ) VALUES (?, ?, ?, '', '', 'xtls-rprx-vision', 'auto', '', '', '', '', '', 0, '', '', ?, 0, ?, ?, 0, '', '', 0, ?, ?)
                            """,
                            (email, sub_id, uuid, dev_limit, exp_ms, int(should_enable), now_ms, now_ms),
                        )
                except sqlite3.OperationalError:
                    pass

                # 2. Align `inbounds.settings` JSON
                for ib_id, tag, proto, port, settings_raw, stream_raw in inbounds_rows:
                    if not settings_raw:
                        continue
                    try:
                        st = json.loads(settings_raw)
                        stream_st = json.loads(stream_raw) if stream_raw else {}
                        ib_dict = {"id": ib_id, "port": port, "settings": st, "stream_settings": stream_st}
                        flow = "xtls-rprx-vision" if _inbound_needs_vision_flow(ib_dict) else ""
                        clients_list = st.setdefault("clients", [])
                        found_cl = None
                        for cl in clients_list:
                            if cl.get("email") == email or cl.get("id") == uuid:
                                found_cl = cl
                                break
                        if found_cl is None and should_enable:
                            clients_list.append({
                                "id": uuid,
                                "email": email,
                                "subId": sub_id,
                                "enable": should_enable,
                                "expiryTime": exp_ms,
                                "totalGB": 0,
                                "limitIp": dev_limit,
                                "flow": flow,
                                "tgId": 0,
                                "reset": 0,
                                "comment": "",
                            })
                            conn.execute("UPDATE inbounds SET settings = ? WHERE id = ?", (json.dumps(st, ensure_ascii=False), ib_id))
                        elif found_cl is not None:
                            if (
                                found_cl.get("enable") != should_enable
                                or found_cl.get("expiryTime") != exp_ms
                                or found_cl.get("subId") != sub_id
                                or found_cl.get("limitIp") != dev_limit
                            ):
                                found_cl["enable"] = should_enable
                                found_cl["expiryTime"] = exp_ms
                                found_cl["subId"] = sub_id
                                found_cl["limitIp"] = dev_limit
                                conn.execute("UPDATE inbounds SET settings = ? WHERE id = ?", (json.dumps(st, ensure_ascii=False), ib_id))
                    except Exception:
                        pass

                # 3. Align `client_traffics`
                try:
                    default_ib_id = int(inbounds_rows[0][0]) if inbounds_rows else self.settings.xui_tcp_inbound_id
                    conn.execute(
                        """
                        INSERT INTO client_traffics (inbound_id, enable, email, up, down, total, expiry_time)
                        VALUES (?, ?, ?, 0, 0, 0, ?)
                        ON CONFLICT(email) DO UPDATE SET
                            enable = excluded.enable,
                            expiry_time = excluded.expiry_time
                        """,
                        (default_ib_id, int(should_enable), email, exp_ms),
                    )
                except sqlite3.OperationalError:
                    pass

                # 4. Align `client_inbounds` for 3x-ui v2.4+
                try:
                    cl_row = conn.execute("SELECT id FROM clients WHERE email = ? OR uuid = ?", (email, uuid)).fetchone()
                    if cl_row:
                        cid = int(cl_row[0])
                        for ib_id, tag, proto, port, settings_raw, stream_raw in inbounds_rows:
                            stream_st = json.loads(stream_raw) if stream_raw else {}
                            ib_dict = {"id": ib_id, "port": port, "stream_settings": stream_st}
                            flow = "xtls-rprx-vision" if _inbound_needs_vision_flow(ib_dict) else ""
                            conn.execute(
                                "INSERT OR IGNORE INTO client_inbounds (client_id, inbound_id, flow_override, created_at) VALUES (?, ?, ?, ?)",
                                (cid, int(ib_id), flow, now_ms),
                            )
                except sqlite3.OperationalError:
                    pass

            conn.commit()
            self.xui_db.invalidate_cache()
        finally:
            conn.close()

    @staticmethod
    def _sync_local_ws443_if_present() -> None:
        """If xray-ws443 config exists locally on this node, update its client list."""
        ws_cfg_path = Path("/usr/local/etc/xray-ws443/config.json")
        if not ws_cfg_path.exists():
            return
        sync_script = Path("/root/subjson-service/sync-xray-ws443-clients.py")
        if sync_script.exists():
            try:
                subprocess.run(["python3", str(sync_script), "--local-only"], timeout=10, check=False)
            except Exception:
                pass

    def _reconcile_local_awg_and_traffic(self) -> None:
        """Автономная локальная синхронизация пиров и трафика AmneziaWG без SSH."""
        from . import awg_manager
        from .awg_traffic import AwgTrafficCollector, process_cluster_traffic_sync

        try:
            local_node = awg_manager.get_current_node_code()
        except Exception:
            return

        # 1. Локальная реконсиляция пиров этой ноды из Turso (без SSH!)
        try:
            awg_manager.reconcile_awg_peers(
                server_code=local_node,
                dry_run=False,
                allow_empty=False,
                db_path=self.settings.database_path,
            )
        except awg_manager.ReconciliationAbortedError:
            pass
        except Exception as exc:
            LOGGER.debug("Local AWG reconcile skipped on %s: %s", local_node, exc)

        # 2. Локальный сбор дельт трафика и прямая запись в Turso (без HTTP-пуша на NL!)
        try:
            collector = AwgTrafficCollector(
                interface="awg0",
                node_id=local_node,
                command_runner=lambda cmd: awg_manager._dex(cmd, server_code=local_node),
            )
            deltas = collector.collect_node_deltas()
            if deltas:
                payload = {
                    "node_id": local_node,
                    "collected_at": int(time.time()),
                    "deltas": [d.to_dict() for d in deltas],
                }
                process_cluster_traffic_sync(
                    self.store,
                    payload,
                    kernel_peer_remover=lambda srv, pub: awg_manager.remove_slot_peer(local_node, pub),
                )
        except Exception as exc:
            LOGGER.debug("Local AWG traffic collection skipped on %s: %s", local_node, exc)

    def run_daemon(self, interval_seconds: float = 60.0) -> None:
        """Run continuous reconciliation loop with instant SIGUSR1 wake support."""
        try:
            PID_FILE_PATH.write_text(str(os.getpid()), encoding="utf-8")
        except Exception:
            pass

        if hasattr(signal, "SIGUSR1"):
            signal.signal(signal.SIGUSR1, lambda signum, frame: self.trigger_wake())

        LOGGER.info("Starting XuiReconciler daemon (interval=%.1fs, pid=%d)", interval_seconds, os.getpid())
        while True:
            try:
                res = self.reconcile_once(dry_run=False)
                if res.get("added") or res.get("updated") or res.get("disabled") or res.get("deleted"):
                    LOGGER.info("Reconcile cycle applied changes: %s", res)
            except Exception as exc:
                LOGGER.exception("Reconcile cycle error: %s", exc)

            self._wake_event.wait(timeout=interval_seconds)
            self._wake_event.clear()


def notify_local_reconciler() -> bool:
    """Send SIGUSR1 to local xui_reconciler daemon if running for <100ms instant provisioning."""
    if not PID_FILE_PATH.exists() or not hasattr(signal, "SIGUSR1"):
        return False
    try:
        pid = int(PID_FILE_PATH.read_text(encoding="utf-8").strip())
        if pid <= 0:
            return False
        cmdline_path = Path(f"/proc/{pid}/cmdline")
        if not cmdline_path.exists():
            return False
        try:
            cmdline = cmdline_path.read_bytes().decode("utf-8", errors="replace").lower()
        except OSError:
            return False
        if not ("reconcile-xui" in cmdline or "xui_reconciler" in cmdline):
            return False
        os.kill(pid, signal.SIGUSR1)
        return True
    except Exception:
        return False
