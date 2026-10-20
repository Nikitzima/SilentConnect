from __future__ import annotations

import json
import os
import re
import sqlite3
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
VPN_SHOP_DIR = REPO_ROOT / "vpn-shop"
if str(VPN_SHOP_DIR) not in sys.path:
    sys.path.insert(0, str(VPN_SHOP_DIR))


def get_store_initialized_schema() -> dict[str, set[str]]:
    """
    Прогоняет полный Store.init() (включая все _SCHEMA_STATEMENTS и все ALTER TABLE миграции)
    на временной SQLite БД и возвращает словарь {table_name: {col1, col2, ...}}.
    """
    from vpn_shop.store import Store

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    old_flag = os.environ.get("TURSO_REPLICA_ENABLED")
    os.environ["TURSO_REPLICA_ENABLED"] = "false"
    try:
        store = Store(tmp_path)
        store.init()
        conn = sqlite3.connect(str(tmp_path))
        tables = [
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_litestream_%'"
            ).fetchall()
        ]
        schema: dict[str, set[str]] = {}
        for t in tables:
            cols = {r[1] for r in conn.execute(f'PRAGMA table_info("{t}")').fetchall()}
            schema[t] = cols
        conn.close()
        return schema
    finally:
        if old_flag is not None:
            os.environ["TURSO_REPLICA_ENABLED"] = old_flag
        else:
            os.environ.pop("TURSO_REPLICA_ENABLED", None)
        tmp_path.unlink(missing_ok=True)


def get_live_turso_schema(db_url: str, auth_token: str) -> dict[str, set[str]]:
    """Выгружает реальные таблицы и колонки из живой базы Turso через /v2/pipeline."""
    endpoint = db_url.strip().rstrip("/").replace("libsql://", "https://") + "/v2/pipeline"

    def _query(sql: str) -> list[list[Any]]:
        req = urllib.request.Request(
            endpoint,
            data=json.dumps({"requests": [{"type": "execute", "stmt": {"sql": sql}}, {"type": "close"}]}).encode("utf-8"),
            headers={"Authorization": f"Bearer {auth_token}", "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        res = data["results"][0]["response"]["result"]
        return [[c.get("value") for c in row] for row in res.get("rows", [])]

    tables = [
        r[0]
        for r in _query(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_litestream_%' AND name NOT LIKE 'libsql_%'"
        )
    ]
    schema: dict[str, set[str]] = {}
    for t in tables:
        cols = {r[1] for r in _query(f'PRAGMA table_info("{t}")')}
        schema[t] = cols
    return schema


def parse_tgcloud_schema_js(schema_js_path: Path) -> dict[str, set[str]]:
    """
    Парсит tgcloud/schema.js и проверяет:
    1. Отсутствие запрещённых в sdk/db foreign keys (.references).
    2. Имена таблиц и колонок.
    """
    text = schema_js_path.read_text(encoding="utf-8")
    if ".references(" in text or "foreignKey" in text:
        raise AssertionError("tgcloud/schema.js contains foreign key references, which are forbidden in Telegram Serverless sdk/db")

    tables: dict[str, set[str]] = {}
    table_pattern = re.compile(r"table\(\s*['\"]([a-zA-Z0-9_]+)['\"]\s*,\s*\{([^}]+)\}", re.MULTILINE | re.DOTALL)
    col_pattern = re.compile(r"(?:integer|text|boolean|json)\(\s*['\"]([a-zA-Z0-9_]+)['\"]\s*\)")
    for match in table_pattern.finditer(text):
        t_name = match.group(1)
        body = match.group(2)
        cols = {c.group(1) for c in col_pattern.finditer(body)}
        tables[t_name] = cols
    return tables


class SchemaParityTests(unittest.TestCase):
    def test_store_py_and_live_turso_100_percent_column_parity(self) -> None:
        expected_schema = get_store_initialized_schema()
        self.assertGreaterEqual(len(expected_schema), 20, "Store.init() must create all shop tables")

        turso_url = os.environ.get("TURSO_DATABASE_URL", "").strip()
        turso_token = os.environ.get("TURSO_AUTH_TOKEN", "").strip()
        if not turso_url or not turso_token:
            self.skipTest("TURSO_DATABASE_URL / TURSO_AUTH_TOKEN not set; skipping live Turso check")

        live_schema = get_live_turso_schema(turso_url, turso_token)

        missing_tables = set(expected_schema.keys()) - set(live_schema.keys())
        self.assertFalse(missing_tables, f"Tables missing in live Turso DB: {sorted(missing_tables)}")

        for table_name, expected_cols in expected_schema.items():
            live_cols = live_schema.get(table_name, set())
            missing_cols = expected_cols - live_cols
            self.assertFalse(
                missing_cols,
                f"Table '{table_name}' in Turso is missing columns (check ALTER TABLE migrations!): {sorted(missing_cols)}",
            )

    def test_tgcloud_schema_js_rules_and_session_columns(self) -> None:
        schema_js = Path("tgcloud/schema.js")
        if not schema_js.is_file():
            self.skipTest("tgcloud/schema.js not found in current directory")
        js_tables = parse_tgcloud_schema_js(schema_js)
        self.assertTrue(
            "chat_sessions" in js_tables or "cached_sessions" in js_tables,
            "tgcloud/schema.js must define chat_sessions / cached_sessions table",
        )


if __name__ == "__main__":
    unittest.main()
