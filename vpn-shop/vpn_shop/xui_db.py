from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


class XuiDatabase:
    def __init__(self, path: Path):
        self.path = Path(path)

    def _connect(self) -> sqlite3.Connection:
        db_uri = self.path.as_posix()
        conn = sqlite3.connect(f"file:{db_uri}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _parse_settings(raw: str | None) -> dict[str, Any]:
        if not raw:
            return {}
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError("Unexpected x-ui JSON structure")
        return parsed

    def find_client_by_email(self, email: str) -> dict[str, Any] | None:
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
        return None

    def find_client_by_sub_id(self, sub_id: str) -> dict[str, Any] | None:
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
        # FIX 2026-08-22 (incident np4mp1ouyxadr4ht): this method previously
        # updated ONLY inbounds.settings. subjson trusts client_traffics
        # (enable/expiry_time) when deciding whether a subscription is active,
        # so renewed clients were still served an "expired" stub.
        conn = sqlite3.connect(self.path)
        try:
            row = conn.execute("SELECT settings FROM inbounds WHERE id = ?", (inbound_id,)).fetchone()
            if not row or not row[0]:
                return False
            st = json.loads(row[0])
            updated = False
            for cl in st.get("clients") or []:
                if str(cl.get("email") or "") == email:
                    cl["expiryTime"] = new_expiry_ms
                    cl["enable"] = enable
                    if device_limit is not None:
                        cl["limitIp"] = max(int(device_limit), 0)
                    updated = True
                    break
            if not updated:
                return False
            conn.execute("UPDATE inbounds SET settings = ? WHERE id = ?", (json.dumps(st, ensure_ascii=False), inbound_id))
            # Keep client_traffics consistent - subjson reads enable/expiry from here.
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
            conn.commit()
            return True
        finally:
            conn.close()

