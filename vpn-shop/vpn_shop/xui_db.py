from __future__ import annotations

from contextlib import contextmanager
import copy
import json
import os
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any, Iterator


class XuiDatabase:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._cache_lock = threading.Lock()
        self._cached_mtime: tuple[float, float, int] | None = None
        self._by_email: dict[str, dict[str, Any]] = {}
        self._by_sub_id: dict[str, dict[str, Any]] = {}
        self._inbounds_cached: list[dict[str, Any]] = []

    def invalidate_cache(self) -> None:
        with self._cache_lock:
            self._cached_mtime = None
            self._by_email.clear()
            self._by_sub_id.clear()
            self._inbounds_cached.clear()

    def _get_mtime(self) -> tuple[float, float, int] | None:
        try:
            db_stat = os.stat(self.path)
            db_mtime = db_stat.st_mtime
        except OSError:
            return None
        wal_path = Path(f"{self.path}-wal")
        wal_mtime = 0.0
        wal_size = 0
        try:
            wal_stat = os.stat(wal_path)
            wal_mtime = wal_stat.st_mtime
            wal_size = wal_stat.st_size
        except OSError:
            pass
        return (db_mtime, wal_mtime, wal_size)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        db_uri = self.path.as_posix()
        conn = sqlite3.connect(f"file:{db_uri}?mode=ro", uri=True, timeout=30.0)
        conn.execute("PRAGMA busy_timeout = 30000;")
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    @staticmethod
    def _parse_settings(raw: str | None) -> dict[str, Any]:
        if not raw:
            return {}
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError("Unexpected x-ui JSON structure")
        return parsed

    def _ensure_cache(self) -> None:
        current_mtime = self._get_mtime()
        if current_mtime is None:
            self.invalidate_cache()
            return

        with self._cache_lock:
            if self._cached_mtime is not None and self._cached_mtime == current_mtime:
                return

            try:
                with self._connect() as conn:
                    rows = conn.execute(
                        """
                        SELECT id, remark, protocol, port, settings, stream_settings, sniffing
                        FROM inbounds
                        ORDER BY id
                        """
                    ).fetchall()
            except sqlite3.Error:
                return

            new_by_email: dict[str, dict[str, Any]] = {}
            new_by_sub_id: dict[str, dict[str, Any]] = {}
            new_inbounds: list[dict[str, Any]] = []

            for row in rows:
                settings = self._parse_settings(row["settings"])
                stream_settings = self._parse_settings(row["stream_settings"])
                sniffing = self._parse_settings(row["sniffing"])
                row_dict = {
                    "id": row["id"],
                    "remark": row["remark"],
                    "protocol": row["protocol"],
                    "port": row["port"],
                    "settings": settings,
                    "stream_settings": stream_settings,
                    "sniffing": sniffing,
                }
                new_inbounds.append(row_dict)

                for client in settings.get("clients") or []:
                    rec = {
                        "inbound_id": row["id"],
                        "remark": row["remark"],
                        "protocol": row["protocol"],
                        "port": row["port"],
                        "client": client,
                        "settings": settings,
                        "stream_settings": stream_settings,
                        "sniffing": sniffing,
                    }
                    email = client.get("email")
                    if email and str(email) not in new_by_email:
                        new_by_email[str(email)] = rec
                    sub_id = client.get("subId")
                    if sub_id and str(sub_id) not in new_by_sub_id:
                        new_by_sub_id[str(sub_id)] = rec

            self._by_email = new_by_email
            self._by_sub_id = new_by_sub_id
            self._inbounds_cached = new_inbounds
            self._cached_mtime = current_mtime

    def find_client_by_email(self, email: str) -> dict[str, Any] | None:
        self._ensure_cache()
        with self._cache_lock:
            rec = self._by_email.get(str(email))
            if rec is not None:
                return copy.deepcopy(rec)
            if self._cached_mtime is None:
                try:
                    with self._connect() as conn:
                        rows = conn.execute(
                            """
                            SELECT id, remark, protocol, port, settings, stream_settings, sniffing
                            FROM inbounds
                            ORDER BY id
                            """
                        ).fetchall()
                    for row in rows:
                        settings = self._parse_settings(row["settings"])
                        for client in settings.get("clients") or []:
                            if client.get("email") == email:
                                return {
                                    "inbound_id": row["id"],
                                    "remark": row["remark"],
                                    "protocol": row["protocol"],
                                    "port": row["port"],
                                    "client": client,
                                    "settings": settings,
                                    "stream_settings": self._parse_settings(row["stream_settings"]),
                                    "sniffing": self._parse_settings(row["sniffing"]),
                                }
                except sqlite3.Error:
                    return None
            return None

    def find_client_by_sub_id(self, sub_id: str) -> dict[str, Any] | None:
        self._ensure_cache()
        with self._cache_lock:
            rec = self._by_sub_id.get(str(sub_id))
            if rec is not None:
                return copy.deepcopy(rec)
            if self._cached_mtime is None:
                try:
                    with self._connect() as conn:
                        rows = conn.execute(
                            """
                            SELECT id, remark, protocol, port, settings, stream_settings, sniffing
                            FROM inbounds
                            ORDER BY id
                            """
                        ).fetchall()
                    for row in rows:
                        settings = self._parse_settings(row["settings"])
                        for client in settings.get("clients") or []:
                            if client.get("subId") == sub_id:
                                return {
                                    "inbound_id": row["id"],
                                    "remark": row["remark"],
                                    "protocol": row["protocol"],
                                    "port": row["port"],
                                    "client": client,
                                    "settings": settings,
                                    "stream_settings": self._parse_settings(row["stream_settings"]),
                                    "sniffing": self._parse_settings(row["sniffing"]),
                                }
                except sqlite3.Error:
                    return None
            return None

    def get_client_traffic(self, email: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT inbound_id, email, up, down, total, expiry_time, enable, last_online
                FROM client_traffics
                WHERE email = ?
                """,
                (email,),
            ).fetchone()
        return dict(row) if row else None

    def list_client_traffic(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT inbound_id, email, up, down, total, expiry_time, enable, last_online
                FROM client_traffics
                ORDER BY (COALESCE(up, 0) + COALESCE(down, 0)) DESC
                LIMIT ?
                """,
                (max(int(limit), 1),),
            ).fetchall()
        return [dict(row) for row in rows]

    def update_client_expiry_direct(self, inbound_id: int, email: str, new_expiry_ms: int, enable: bool = True, device_limit: int | None = None) -> bool:
        # Incident 2026-08-22 & 2026-10-02:
        # Multi-inbound and 3x-ui v2.4+ synchronization:
        # 1. Update the `clients` table (enable, expiry_time, limit_ip, updated_at).
        # 2. Update ALL inbounds in `inbounds.settings` that contain this client (by email).
        # 3. Update `client_traffics` so subjson and telemetry stay in sync.
        # 4. Ensure `client_inbounds` mapping exists for 3x-ui v2.4+.
        conn = sqlite3.connect(self.path, timeout=30.0)
        conn.execute("PRAGMA busy_timeout = 30000;")
        try:
            now_ms = int(time.time() * 1000)

            # 1. Update clients table
            try:
                if device_limit is not None:
                    conn.execute(
                        "UPDATE clients SET enable = ?, expiry_time = ?, limit_ip = ?, updated_at = ? WHERE email = ?",
                        (int(enable), new_expiry_ms, max(int(device_limit), 0), now_ms, email),
                    )
                else:
                    conn.execute(
                        "UPDATE clients SET enable = ?, expiry_time = ?, updated_at = ? WHERE email = ?",
                        (int(enable), new_expiry_ms, now_ms, email),
                    )
            except sqlite3.OperationalError:
                pass

            # 2. Update ALL inbounds that contain this client
            inbounds_rows = conn.execute("SELECT id, settings FROM inbounds").fetchall()
            any_inbound_updated = False
            for ib_id, settings_raw in inbounds_rows:
                if not settings_raw:
                    continue
                try:
                    st = json.loads(settings_raw)
                    ib_changed = False
                    for cl in st.get("clients") or []:
                        if str(cl.get("email") or "") == email:
                            cl["expiryTime"] = new_expiry_ms
                            cl["enable"] = enable
                            if device_limit is not None:
                                cl["limitIp"] = max(int(device_limit), 0)
                            ib_changed = True
                    if ib_changed:
                        conn.execute("UPDATE inbounds SET settings = ? WHERE id = ?", (json.dumps(st, ensure_ascii=False), ib_id))
                        any_inbound_updated = True
                except Exception:
                    pass

            # 3. Keep client_traffics consistent - subjson reads enable/expiry from here
            try:
                conn.execute(
                    """
                    INSERT INTO client_traffics (inbound_id, enable, email, up, down, total, expiry_time)
                    VALUES (?, ?, ?, 0, 0, 0, ?)
                    ON CONFLICT(email) DO UPDATE SET
                        enable = excluded.enable,
                        inbound_id = excluded.inbound_id,
                        expiry_time = excluded.expiry_time
                    """,
                    (inbound_id, int(enable), email, new_expiry_ms),
                )
            except sqlite3.OperationalError:
                pass

            # 4. Ensure client_inbounds table mapping exists for 3x-ui v2.4+
            try:
                cl_row = conn.execute("SELECT id FROM clients WHERE email = ?", (email,)).fetchone()
                if cl_row:
                    cid = cl_row[0]
                    for ib_id, _ in inbounds_rows:
                        conn.execute(
                            "INSERT OR IGNORE INTO client_inbounds (client_id, inbound_id, flow_override, created_at) VALUES (?, ?, '', ?)",
                            (cid, ib_id, now_ms),
                        )
            except sqlite3.OperationalError:
                pass

            conn.commit()
            self.invalidate_cache()
            return True
        finally:
            conn.close()

