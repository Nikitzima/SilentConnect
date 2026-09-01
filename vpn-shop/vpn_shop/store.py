from __future__ import annotations

from contextlib import contextmanager
import json
import sqlite3
from pathlib import Path
from typing import Any, Iterator

from .security import hash_secret, masked_code, now_ts, public_id, random_code


SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS chat_sessions (
  chat_id TEXT PRIMARY KEY,
  scope TEXT NOT NULL,
  state TEXT NOT NULL,
  context_json TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS invite_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code_hash TEXT NOT NULL UNIQUE,
  code_preview TEXT NOT NULL,
  purpose TEXT NOT NULL DEFAULT 'storefront',
  max_uses INTEGER NOT NULL DEFAULT 1,
  used_count INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  note TEXT
);

CREATE TABLE IF NOT EXISTS promo_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code_hash TEXT NOT NULL UNIQUE,
  code_preview TEXT NOT NULL,
  promo_type TEXT NOT NULL DEFAULT 'fixed',
  transport TEXT NOT NULL,
  duration_days INTEGER NOT NULL,
  duration_months INTEGER,
  discount_percent INTEGER NOT NULL,
  fixed_price_rub INTEGER,
  device_limit INTEGER NOT NULL DEFAULT 3,
  profile_mode TEXT NOT NULL,
  family_label TEXT,
  max_uses INTEGER NOT NULL DEFAULT 1,
  used_count INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER
);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  public_id TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL,
  status TEXT NOT NULL,
  transport TEXT NOT NULL,
  duration_days INTEGER NOT NULL,
  profile_mode TEXT NOT NULL,
  family_label TEXT,
  base_price_rub INTEGER NOT NULL,
  final_price_rub INTEGER NOT NULL,
  promo_id INTEGER,
  invite_id INTEGER,
  customer_chat_id TEXT,
  customer_email TEXT NOT NULL DEFAULT '',
  manager_chat_id TEXT,
  manager_message_id INTEGER,
  privacy_ack INTEGER NOT NULL DEFAULT 0,
  loss_policy_ack INTEGER NOT NULL DEFAULT 0,
  terms_version TEXT NOT NULL,
  provisioned_profile_id INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  closed_at INTEGER,
  meta_json TEXT NOT NULL DEFAULT '{}',
  FOREIGN KEY (promo_id) REFERENCES promo_codes(id),
  FOREIGN KEY (invite_id) REFERENCES invite_tokens(id),
  FOREIGN KEY (provisioned_profile_id) REFERENCES profiles(id)
);

CREATE TABLE IF NOT EXISTS profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  public_id TEXT NOT NULL UNIQUE,
  xui_inbound_id INTEGER NOT NULL,
  transport TEXT NOT NULL,
  profile_mode TEXT NOT NULL,
  family_label TEXT,
  xui_email TEXT NOT NULL UNIQUE,
  xui_client_id TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_renewed_at INTEGER,
  deleted_at INTEGER,
  notes TEXT
);

CREATE TABLE IF NOT EXISTS profile_owners (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  profile_public_id TEXT NOT NULL UNIQUE,
  user_id TEXT NOT NULL,
  chat_id TEXT NOT NULL,
  source_order_public_id TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY (profile_public_id) REFERENCES profiles(public_id)
);

CREATE INDEX IF NOT EXISTS idx_profile_owners_user_id
  ON profile_owners(user_id, updated_at);

CREATE TABLE IF NOT EXISTS profile_reminders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  profile_public_id TEXT NOT NULL,
  reminder_kind TEXT NOT NULL,
  sent_at INTEGER NOT NULL,
  UNIQUE(profile_public_id, reminder_kind),
  FOREIGN KEY (profile_public_id) REFERENCES profiles(public_id)
);

CREATE INDEX IF NOT EXISTS idx_profile_reminders_profile
  ON profile_reminders(profile_public_id, reminder_kind);

CREATE TABLE IF NOT EXISTS admin_actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  action_type TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_public_id TEXT NOT NULL,
  actor TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  meta_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS telegram_users (
  user_id TEXT PRIMARY KEY,
  chat_id TEXT NOT NULL,
  username TEXT,
  first_name TEXT,
  last_name TEXT,
  is_bot INTEGER NOT NULL DEFAULT 0,
  first_seen_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS trial_redemptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL UNIQUE,
  chat_id TEXT NOT NULL,
  status TEXT NOT NULL,
  transport TEXT NOT NULL DEFAULT 'tcp',
  order_public_id TEXT,
  profile_public_id TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  delivered_at INTEGER,
  meta_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS referrers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL UNIQUE,
  chat_id TEXT NOT NULL,
  code TEXT NOT NULL UNIQUE,
  commission_percent INTEGER NOT NULL DEFAULT 10,
  status TEXT NOT NULL DEFAULT 'active',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS referral_attributions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  referrer_id INTEGER NOT NULL,
  referred_user_id TEXT NOT NULL UNIQUE,
  referred_chat_id TEXT NOT NULL,
  source_code TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  first_order_public_id TEXT,
  FOREIGN KEY (referrer_id) REFERENCES referrers(id)
);

CREATE TABLE IF NOT EXISTS referral_ledger (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  referrer_id INTEGER NOT NULL,
  referred_user_id TEXT NOT NULL,
  order_public_id TEXT NOT NULL UNIQUE,
  base_amount_rub INTEGER NOT NULL,
  amount_rub INTEGER NOT NULL,
  commission_percent INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at INTEGER NOT NULL,
  paid_at INTEGER,
  payout_id INTEGER,
  meta_json TEXT NOT NULL DEFAULT '{}',
  FOREIGN KEY (referrer_id) REFERENCES referrers(id)
);

CREATE TABLE IF NOT EXISTS referral_payouts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  referrer_id INTEGER NOT NULL,
  amount_rub INTEGER NOT NULL,
  actor TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  meta_json TEXT NOT NULL DEFAULT '{}',
  FOREIGN KEY (referrer_id) REFERENCES referrers(id)
);
"""


class Store:
    def __init__(self, database_path: Path):
        self.database_path = Path(database_path)

    def init(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(SCHEMA)
            self._ensure_column(conn, "promo_codes", "promo_type", "TEXT NOT NULL DEFAULT 'fixed'")
            self._ensure_column(conn, "promo_codes", "device_limit", "INTEGER NOT NULL DEFAULT 3")
            self._ensure_column(conn, "promo_codes", "duration_months", "INTEGER")
            self._ensure_column(conn, "promo_codes", "fixed_price_rub", "INTEGER")
            self._ensure_column(conn, "orders", "customer_email", "TEXT NOT NULL DEFAULT ''")

    @staticmethod
    def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
        columns = {
            str(row["name"])
            for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
        }
        if column not in columns:
            try:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
            except sqlite3.OperationalError as exc:
                if "duplicate column name" not in str(exc).lower():
                    raise

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.database_path, timeout=30.0)
        conn.execute("PRAGMA busy_timeout = 30000;")
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        result = dict(row)
        for key in ("context_json", "meta_json"):
            if key in result and isinstance(result[key], str):
                result[key] = json.loads(result[key])
        return result

    def get_session(self, chat_id: int | str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT chat_id, scope, state, context_json, updated_at FROM chat_sessions WHERE chat_id = ?",
                (str(chat_id),),
            ).fetchone()
        return self._row_to_dict(row)

    def set_session(self, chat_id: int | str, scope: str, state: str, context: dict[str, Any]) -> None:
        payload = json.dumps(context, ensure_ascii=False, separators=(",", ":"))
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO chat_sessions(chat_id, scope, state, context_json, updated_at)
                VALUES(?, ?, ?, ?, ?)
                ON CONFLICT(chat_id) DO UPDATE SET
                  scope = excluded.scope,
                  state = excluded.state,
                  context_json = excluded.context_json,
                  updated_at = excluded.updated_at
                """,
                (str(chat_id), scope, state, payload, now_ts()),
            )

    def clear_session(self, chat_id: int | str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM chat_sessions WHERE chat_id = ?", (str(chat_id),))

    def upsert_telegram_user(self, *, user: dict[str, Any], chat_id: int | str) -> None:
        user_id = str(user.get("id") or "")
        if not user_id:
            return
        now = now_ts()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO telegram_users(
                  user_id, chat_id, username, first_name, last_name, is_bot,
                  first_seen_at, last_seen_at
                )
                VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                  chat_id = excluded.chat_id,
                  username = excluded.username,
                  first_name = excluded.first_name,
                  last_name = excluded.last_name,
                  is_bot = excluded.is_bot,
                  last_seen_at = excluded.last_seen_at
                """,
                (
                    user_id,
                    str(chat_id),
                    (user.get("username") or "").strip() or None,
                    (user.get("first_name") or "").strip() or None,
                    (user.get("last_name") or "").strip() or None,
                    int(bool(user.get("is_bot"))),
                    now,
                    now,
                ),
            )

    def list_chat_ids_by_scope(self, scope: str) -> list[str]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT chat_id FROM chat_sessions WHERE scope = ? ORDER BY updated_at DESC",
                (scope,),
            ).fetchall()
            result = [str(row["chat_id"]) for row in rows if row["chat_id"]]
            if not result and scope == "admin":
                admin_rows = conn.execute(
                    "SELECT DISTINCT actor FROM admin_actions WHERE actor LIKE 'tg:%' ORDER BY id DESC LIMIT 10"
                ).fetchall()
                for row in admin_rows:
                    actor = str(row["actor"] or "")
                    if actor.startswith("tg:"):
                        cid = actor.split(":", 1)[1].strip()
                        if cid and cid not in result:
                            result.append(cid)
                if getattr(self, "settings", None) and getattr(self.settings, "admin_user_ids", None):
                    for uid in self.settings.admin_user_ids:
                        suid = str(uid)
                        if suid and suid not in result:
                            result.append(suid)
        return result

    def create_invite(self, max_uses: int = 1, expires_at: int | None = None, note: str = "") -> tuple[str, dict[str, Any]]:
        code = random_code("INV")
        now = now_ts()
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO invite_tokens(code_hash, code_preview, max_uses, expires_at, created_at, note)
                VALUES(?, ?, ?, ?, ?, ?)
                """,
                (hash_secret(code), masked_code(code), max_uses, expires_at, now, note.strip() or None),
            )
            invite_id = cursor.lastrowid
            row = conn.execute("SELECT * FROM invite_tokens WHERE id = ?", (invite_id,)).fetchone()
        return code, dict(row)

    def find_valid_invite(self, code: str) -> dict[str, Any] | None:
        now = now_ts()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM invite_tokens
                WHERE code_hash = ?
                  AND enabled = 1
                  AND used_count < max_uses
                  AND (expires_at IS NULL OR expires_at > ?)
                """,
                (hash_secret(code), now),
            ).fetchone()
        return self._row_to_dict(row)

    def consume_invite(self, code_or_id: str | int) -> dict[str, Any] | None:
        now = now_ts()
        with self._connect() as conn:
            if isinstance(code_or_id, int) or (isinstance(code_or_id, str) and code_or_id.isdigit()):
                cursor = conn.execute(
                    """
                    UPDATE invite_tokens
                    SET used_count = used_count + 1
                    WHERE id = ?
                      AND enabled = 1
                      AND used_count < max_uses
                      AND (expires_at IS NULL OR expires_at > ?)
                    RETURNING *
                    """,
                    (int(code_or_id), now),
                )
            else:
                cursor = conn.execute(
                    """
                    UPDATE invite_tokens
                    SET used_count = used_count + 1
                    WHERE code_hash = ?
                      AND enabled = 1
                      AND used_count < max_uses
                      AND (expires_at IS NULL OR expires_at > ?)
                    RETURNING *
                    """,
                    (hash_secret(str(code_or_id)), now),
                )
            row = cursor.fetchone()
            return self._row_to_dict(row)

    def mark_invite_used(self, invite_id: int) -> dict[str, Any] | None:
        return self.consume_invite(invite_id)

    def restore_invite(self, invite_id: int) -> dict[str, Any] | None:
        with self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE invite_tokens
                SET used_count = MAX(0, used_count - 1)
                WHERE id = ?
                RETURNING *
                """,
                (int(invite_id),),
            )
            row = cursor.fetchone()
            return self._row_to_dict(row)

    def create_promo_code(
        self,
        *,
        promo_type: str = "fixed",
        transport: str,
        duration_days: int,
        discount_percent: int,
        duration_months: int | None = None,
        fixed_price_rub: int | None = None,
        device_limit: int = 3,
        profile_mode: str,
        family_label: str | None = None,
        max_uses: int = 1,
        expires_at: int | None = None,
    ) -> tuple[str, dict[str, Any]]:
        code = random_code("PROMO")
        now = now_ts()
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO promo_codes(
                  code_hash, code_preview, promo_type, transport, duration_days,
                  duration_months, discount_percent, fixed_price_rub,
                  device_limit, profile_mode, family_label,
                  max_uses, expires_at, created_at
                )
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    hash_secret(code),
                    masked_code(code),
                    promo_type,
                    transport,
                    duration_days,
                    duration_months,
                    discount_percent,
                    fixed_price_rub,
                    int(device_limit),
                    profile_mode,
                    family_label,
                    max_uses,
                    expires_at,
                    now,
                ),
            )
            promo_id = cursor.lastrowid
            row = conn.execute("SELECT * FROM promo_codes WHERE id = ?", (promo_id,)).fetchone()
        return code, dict(row)

    def get_promo_code(self, promo_id: int) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM promo_codes WHERE id = ?", (int(promo_id),)).fetchone()
        return self._row_to_dict(row)

    @staticmethod
    def is_promo_valid(promo: dict[str, Any] | None) -> bool:
        if not promo:
            return False
        if not int(promo.get("enabled") or 0):
            return False
        if promo.get("expires_at") and int(promo["expires_at"]) < now_ts():
            return False
        return int(promo.get("used_count") or 0) < int(promo.get("max_uses") or 0)

    def get_valid_promo_by_id(self, promo_id: int) -> dict[str, Any] | None:
        now = now_ts()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM promo_codes
                WHERE id = ?
                  AND enabled = 1
                  AND used_count < max_uses
                  AND (expires_at IS NULL OR expires_at > ?)
                """,
                (int(promo_id), now),
            ).fetchone()
        return self._row_to_dict(row)

    def find_valid_promo(self, code: str) -> dict[str, Any] | None:
        now = now_ts()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM promo_codes
                WHERE code_hash = ?
                  AND enabled = 1
                  AND used_count < max_uses
                  AND (expires_at IS NULL OR expires_at > ?)
                """,
                (hash_secret(code), now),
            ).fetchone()
        return self._row_to_dict(row)

    def get_open_order_for_promo(self, promo_id: int) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM orders
                WHERE promo_id = ?
                  AND closed_at IS NULL
                  AND status IN ('waiting_payment', 'auto_provision')
                ORDER BY created_at ASC, id ASC
                LIMIT 1
                """,
                (int(promo_id),),
            ).fetchone()
        return self._row_to_dict(row)

    def consume_promo_code(self, code_or_id: str | int) -> dict[str, Any] | None:
        now = now_ts()
        with self._connect() as conn:
            if isinstance(code_or_id, int) or (isinstance(code_or_id, str) and code_or_id.isdigit()):
                cursor = conn.execute(
                    """
                    UPDATE promo_codes
                    SET used_count = used_count + 1, last_used_at = ?
                    WHERE id = ?
                      AND enabled = 1
                      AND used_count < max_uses
                      AND (expires_at IS NULL OR expires_at > ?)
                    RETURNING *
                    """,
                    (now, int(code_or_id), now),
                )
            else:
                cursor = conn.execute(
                    """
                    UPDATE promo_codes
                    SET used_count = used_count + 1, last_used_at = ?
                    WHERE code_hash = ?
                      AND enabled = 1
                      AND used_count < max_uses
                      AND (expires_at IS NULL OR expires_at > ?)
                    RETURNING *
                    """,
                    (now, hash_secret(str(code_or_id)), now),
                )
            row = cursor.fetchone()
            return self._row_to_dict(row)

    def mark_promo_used(self, promo_id: int) -> dict[str, Any] | None:
        return self.consume_promo_code(promo_id)

    def restore_promo_code(self, promo_id: int) -> dict[str, Any] | None:
        with self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE promo_codes
                SET used_count = MAX(0, used_count - 1)
                WHERE id = ?
                RETURNING *
                """,
                (int(promo_id),),
            )
            row = cursor.fetchone()
            return self._row_to_dict(row)

    def create_order(
        self,
        *,
        kind: str,
        status: str,
        transport: str,
        duration_days: int,
        profile_mode: str,
        family_label: str | None,
        base_price_rub: int,
        final_price_rub: int,
        promo_id: int | None,
        invite_id: int | None,
        customer_chat_id: int | str | None,
        privacy_ack: bool,
        loss_policy_ack: bool,
        terms_version: str,
        customer_email: str = "",
        meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = now_ts()
        public = public_id("ord")
        merged_meta = dict(meta or {})
        if customer_email:
            merged_meta["customer_email"] = customer_email
        payload = json.dumps(merged_meta, ensure_ascii=False, separators=(",", ":"))
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO orders(
                  public_id, kind, status, transport, duration_days, profile_mode, family_label,
                  base_price_rub, final_price_rub, promo_id, invite_id, customer_chat_id,
                  privacy_ack, loss_policy_ack, terms_version, customer_email, created_at, updated_at, meta_json
                )
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    public,
                    kind,
                    status,
                    transport,
                    duration_days,
                    profile_mode,
                    family_label,
                    base_price_rub,
                    final_price_rub,
                    promo_id,
                    invite_id,
                    str(customer_chat_id) if customer_chat_id is not None else None,
                    int(privacy_ack),
                    int(loss_policy_ack),
                    terms_version,
                    customer_email,
                    now,
                    now,
                    payload,
                ),
            )
            row = conn.execute("SELECT * FROM orders WHERE id = ?", (cursor.lastrowid,)).fetchone()
        return self._row_to_dict(row) or {}

    def update_order_meta(self, public_id_value: str, meta: dict[str, Any]) -> None:
        payload = json.dumps(meta, ensure_ascii=False, separators=(",", ":"))
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE orders
                SET meta_json = ?, updated_at = ?
                WHERE public_id = ?
                """,
                (payload, now_ts(), public_id_value),
            )

    def get_order(self, public_id_value: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM orders WHERE public_id = ?", (public_id_value,)).fetchone()
        return self._row_to_dict(row)

    def get_latest_order_for_chat(
        self,
        chat_id: int | str,
        *,
        statuses: tuple[str, ...] | None = None,
    ) -> dict[str, Any] | None:
        query = """
            SELECT *
            FROM orders
            WHERE customer_chat_id = ?
        """
        params: list[Any] = [str(chat_id)]
        if statuses:
            placeholders = ",".join("?" for _ in statuses)
            query += f" AND status IN ({placeholders})"
            params.extend(statuses)
        query += " ORDER BY created_at DESC, id DESC LIMIT 1"
        with self._connect() as conn:
            row = conn.execute(query, params).fetchone()
        return self._row_to_dict(row)

    def get_active_order_for_chat(
        self,
        chat_id: int | str,
        *,
        statuses: tuple[str, ...] = ("waiting_payment", "auto_provision"),
    ) -> dict[str, Any] | None:
        query = """
            SELECT *
            FROM orders
            WHERE customer_chat_id = ? AND closed_at IS NULL
        """
        params: list[Any] = [str(chat_id)]
        if statuses:
            placeholders = ",".join("?" for _ in statuses)
            query += f" AND status IN ({placeholders})"
            params.extend(statuses)
        query += " ORDER BY created_at DESC, id DESC LIMIT 1"
        with self._connect() as conn:
            row = conn.execute(query, params).fetchone()
        return self._row_to_dict(row)

    def list_open_orders_for_chat(
        self,
        chat_id: int | str,
        *,
        statuses: tuple[str, ...] = ("waiting_payment",),
    ) -> list[dict[str, Any]]:
        query = """
            SELECT *
            FROM orders
            WHERE customer_chat_id = ? AND closed_at IS NULL
        """
        params: list[Any] = [str(chat_id)]
        if statuses:
            placeholders = ",".join("?" for _ in statuses)
            query += f" AND status IN ({placeholders})"
            params.extend(statuses)
        query += " ORDER BY created_at ASC, id ASC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(row) or {} for row in rows]

    def cancel_open_orders_for_chat(
        self,
        chat_id: int | str,
        *,
        statuses: tuple[str, ...] = ("waiting_payment",),
    ) -> list[dict[str, Any]]:
        orders = self.list_open_orders_for_chat(chat_id, statuses=statuses)
        if not orders:
            return []
        now = now_ts()
        public_ids = [str(order["public_id"]) for order in orders]
        placeholders = ",".join("?" for _ in public_ids)
        with self._connect() as conn:
            conn.execute(
                f"""
                UPDATE orders
                SET status = 'cancelled', updated_at = ?, closed_at = ?
                WHERE public_id IN ({placeholders})
                """,
                [now, now, *public_ids],
            )
        return orders

    def expire_waiting_payment_orders_for_chat(
        self,
        chat_id: int | str,
        *,
        older_than_seconds: int,
    ) -> list[dict[str, Any]]:
        orders = self.list_open_orders_for_chat(chat_id, statuses=("waiting_payment",))
        if not orders:
            return []
        cutoff = now_ts() - int(older_than_seconds)
        expired_orders = [order for order in orders if int(order.get("created_at") or 0) <= cutoff]
        if not expired_orders:
            return []
        now = now_ts()
        public_ids = [str(order["public_id"]) for order in expired_orders]
        placeholders = ",".join("?" for _ in public_ids)
        with self._connect() as conn:
            conn.execute(
                f"""
                UPDATE orders
                SET status = 'cancelled', updated_at = ?, closed_at = ?
                WHERE public_id IN ({placeholders})
                """,
                [now, now, *public_ids],
            )
        return expired_orders

    def get_order_by_manager_message(self, manager_chat_id: int | str, manager_message_id: int) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM orders
                WHERE manager_chat_id = ? AND manager_message_id = ?
                ORDER BY updated_at DESC
                LIMIT 1
                """,
                (str(manager_chat_id), int(manager_message_id)),
            ).fetchone()
        return self._row_to_dict(row)

    def get_profile(self, public_id_value: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM profiles WHERE public_id = ?", (public_id_value,)).fetchone()
        return self._row_to_dict(row)

    def get_profile_by_xui_email(self, xui_email: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM profiles WHERE xui_email = ? ORDER BY id DESC LIMIT 1",
                (xui_email,),
            ).fetchone()
        return self._row_to_dict(row)

    def get_profile_owner(self, profile_public_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM profile_owners WHERE profile_public_id = ?",
                (profile_public_id,),
            ).fetchone()
        return self._row_to_dict(row)

    def get_order_for_profile(self, profile_public_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT o.*
                FROM orders o
                JOIN profiles p ON p.id = o.provisioned_profile_id
                WHERE p.public_id = ?
                ORDER BY o.created_at DESC, o.id DESC
                LIMIT 1
                """,
                (profile_public_id,),
            ).fetchone()
        return self._row_to_dict(row)

    def link_profile_owner(
        self,
        *,
        profile_public_id: str,
        user_id: int | str,
        chat_id: int | str,
        source_order_public_id: str | None = None,
    ) -> None:
        now = now_ts()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO profile_owners(
                  profile_public_id, user_id, chat_id, source_order_public_id, created_at, updated_at
                )
                VALUES(?, ?, ?, ?, ?, ?)
                ON CONFLICT(profile_public_id) DO UPDATE SET
                  user_id = excluded.user_id,
                  chat_id = excluded.chat_id,
                  source_order_public_id = COALESCE(excluded.source_order_public_id, profile_owners.source_order_public_id),
                  updated_at = excluded.updated_at
                """,
                (
                    profile_public_id,
                    str(user_id),
                    str(chat_id),
                    source_order_public_id,
                    now,
                    now,
                ),
            )

    def get_latest_renewable_profile_for_user(
        self,
        user_id: int | str,
        *,
        excluded_notes: tuple[str, ...] = (),
    ) -> dict[str, Any] | None:
        query = """
            SELECT p.*
            FROM profile_owners po
            JOIN profiles p ON p.public_id = po.profile_public_id
            WHERE po.user_id = ?
              AND p.status != 'deleted'
        """
        params: list[Any] = [str(user_id)]
        if excluded_notes:
            placeholders = ",".join("?" for _ in excluded_notes)
            query += f" AND (p.notes IS NULL OR p.notes NOT IN ({placeholders}))"
            params.extend(excluded_notes)
        query += """
            ORDER BY
              CASE WHEN p.expires_at >= ? THEN 0 ELSE 1 END ASC,
              p.expires_at DESC,
              p.id DESC
            LIMIT 1
        """
        params.append(now_ts())
        with self._connect() as conn:
            row = conn.execute(query, params).fetchone()
        return self._row_to_dict(row)

    def update_order_status(self, public_id_value: str, status: str, *, closed: bool = False) -> None:
        now = now_ts()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE orders
                SET status = ?, updated_at = ?, closed_at = CASE WHEN ? THEN ? ELSE closed_at END
                WHERE public_id = ?
                """,
                (status, now, int(closed), now, public_id_value),
            )

    def attach_manager_message(self, public_id_value: str, manager_chat_id: int | str, manager_message_id: int) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE orders
                SET manager_chat_id = ?, manager_message_id = ?, updated_at = ?
                WHERE public_id = ?
                """,
                (str(manager_chat_id), manager_message_id, now_ts(), public_id_value),
            )

    def clear_order_customer_contact(self, public_id_value: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE orders
                SET customer_chat_id = NULL, updated_at = ?
                WHERE public_id = ?
                """,
                (now_ts(), public_id_value),
            )

    def create_profile(
        self,
        *,
        xui_inbound_id: int,
        transport: str,
        profile_mode: str,
        family_label: str | None,
        xui_email: str,
        xui_client_id: str,
        expires_at: int,
        notes: str = "",
    ) -> dict[str, Any]:
        now = now_ts()
        public = public_id("prf")
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO profiles(
                  public_id, xui_inbound_id, transport, profile_mode, family_label,
                  xui_email, xui_client_id, status, created_at, expires_at, last_renewed_at, notes
                )
                VALUES(?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?)
                """,
                (
                    public,
                    xui_inbound_id,
                    transport,
                    profile_mode,
                    family_label,
                    xui_email,
                    xui_client_id,
                    now,
                    expires_at,
                    now,
                    notes or None,
                ),
            )
            row = conn.execute("SELECT * FROM profiles WHERE id = ?", (cursor.lastrowid,)).fetchone()
        return self._row_to_dict(row) or {}

    def ensure_profile_for_xui_client(
        self,
        xui_inbound_id: int,
        client: dict[str, Any],
        transport: str = "tcp",
    ) -> dict[str, Any]:
        email = str(client.get("email") or "").strip()
        if not email:
            raise ValueError("XUI client has no email")

        existing = self.get_profile_by_xui_email(email)
        if existing:
            return existing

        expiry_ms = int(client.get("expiryTime") or 0)
        expires_at = expiry_ms // 1000 if expiry_ms > 0 else (now_ts() + 30 * 86400)
        client_id = str(client.get("id") or client.get("password") or email)
        mode = "family" if not email.startswith("anon-") else "anonymous"

        return self.create_profile(
            xui_inbound_id=int(xui_inbound_id),
            transport=transport,
            profile_mode=mode,
            family_label=email if mode == "family" else None,
            xui_email=email,
            xui_client_id=client_id,
            expires_at=expires_at,
            notes="auto_sync_from_xui",
        )

    def link_order_profile(self, order_public_id: str, profile_public_id: str) -> None:
        with self._connect() as conn:
            profile_row = conn.execute(
                "SELECT id FROM profiles WHERE public_id = ?",
                (profile_public_id,),
            ).fetchone()
            if profile_row is None:
                raise KeyError(profile_public_id)
            conn.execute(
                """
                UPDATE orders
                SET provisioned_profile_id = ?, updated_at = ?
                WHERE public_id = ?
                """,
                (profile_row["id"], now_ts(), order_public_id),
            )

    def extend_profile(self, profile_public_id: str, expires_at: int) -> dict[str, Any]:
        now = now_ts()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE profiles
                SET expires_at = ?, last_renewed_at = ?, status = 'active', deleted_at = NULL
                WHERE public_id = ? AND status != 'deleted'
                """,
                (int(expires_at), now, profile_public_id),
            )
            row = conn.execute("SELECT * FROM profiles WHERE public_id = ?", (profile_public_id,)).fetchone()
        return self._row_to_dict(row) or {}

    def get_profile_for_order(self, order_public_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT p.*
                FROM orders o
                JOIN profiles p ON p.id = o.provisioned_profile_id
                WHERE o.public_id = ?
                LIMIT 1
                """,
                (order_public_id,),
            ).fetchone()
        return self._row_to_dict(row)

    def record_admin_action(
        self,
        *,
        action_type: str,
        target_type: str,
        target_public_id: str,
        actor: str,
        meta: dict[str, Any] | None = None,
    ) -> None:
        payload = json.dumps(meta or {}, ensure_ascii=False, separators=(",", ":"))
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO admin_actions(action_type, target_type, target_public_id, actor, created_at, meta_json)
                VALUES(?, ?, ?, ?, ?, ?)
                """,
                (action_type, target_type, target_public_id, actor, now_ts(), payload),
            )

    def get_last_admin_action(
        self,
        *,
        action_type: str,
        target_type: str,
        target_public_id: str,
    ) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM admin_actions
                WHERE action_type = ? AND target_type = ? AND target_public_id = ?
                ORDER BY created_at DESC, id DESC
                LIMIT 1
                """,
                (action_type, target_type, target_public_id),
            ).fetchone()
        return self._row_to_dict(row)

    def list_expired_profiles(
        self,
        *,
        status: str = "active",
        notes: str | None = None,
        expires_before: int | None = None,
    ) -> list[dict[str, Any]]:
        cutoff = now_ts() if expires_before is None else int(expires_before)
        query = """
            SELECT *
            FROM profiles
            WHERE status = ? AND expires_at <= ?
        """
        params: list[Any] = [status, cutoff]
        if notes is not None:
            query += " AND notes = ?"
            params.append(notes)
        query += " ORDER BY expires_at ASC, id ASC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(row) or {} for row in rows]

    def list_profiles_due_for_reminder(
        self,
        *,
        reminder_kind: str,
        now: int,
        horizon_seconds: int,
        excluded_notes: tuple[str, ...] = (),
    ) -> list[dict[str, Any]]:
        query = """
            SELECT
              p.*,
              po.user_id AS owner_user_id,
              po.chat_id AS owner_chat_id,
              po.source_order_public_id AS owner_source_order_public_id
            FROM profiles p
            JOIN profile_owners po ON po.profile_public_id = p.public_id
            LEFT JOIN profile_reminders pr
              ON pr.profile_public_id = p.public_id
             AND pr.reminder_kind = ?
            WHERE p.status = 'active'
              AND p.expires_at > ?
              AND p.expires_at <= ?
              AND pr.id IS NULL
        """
        params: list[Any] = [reminder_kind, int(now), int(now) + int(horizon_seconds)]
        if excluded_notes:
            placeholders = ",".join("?" for _ in excluded_notes)
            query += f" AND (p.notes IS NULL OR p.notes NOT IN ({placeholders}))"
            params.extend(excluded_notes)
        query += " ORDER BY p.expires_at ASC, p.id ASC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(row) or {} for row in rows]

    def mark_profile_reminder_sent(self, profile_public_id: str, reminder_kind: str, *, sent_at: int | None = None) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO profile_reminders(profile_public_id, reminder_kind, sent_at)
                VALUES(?, ?, ?)
                """,
                (profile_public_id, reminder_kind, int(sent_at or now_ts())),
            )

    def mark_profile_deleted(self, public_id_value: str) -> None:
        deleted_at = now_ts()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE profiles
                SET status = 'deleted', deleted_at = ?
                WHERE public_id = ? AND status != 'deleted'
                """,
                (deleted_at, public_id_value),
            )

    def get_trial_redemption(self, user_id: int | str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM trial_redemptions WHERE user_id = ?",
                (str(user_id),),
            ).fetchone()
        return self._row_to_dict(row)

    def claim_trial_redemption(
        self,
        *,
        user_id: int | str,
        chat_id: int | str,
        transport: str = "tcp",
    ) -> tuple[bool, dict[str, Any]]:
        now = now_ts()
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT * FROM trial_redemptions WHERE user_id = ?",
                (str(user_id),),
            ).fetchone()
            if existing is not None:
                redemption = self._row_to_dict(existing) or {}
                if redemption.get("status") in {"claimed", "delivered"}:
                    return False, redemption
                conn.execute(
                    """
                    UPDATE trial_redemptions
                    SET chat_id = ?, status = 'claimed', transport = ?, updated_at = ?, meta_json = '{}'
                    WHERE user_id = ?
                    """,
                    (str(chat_id), transport, now, str(user_id)),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO trial_redemptions(user_id, chat_id, status, transport, created_at, updated_at)
                    VALUES(?, ?, 'claimed', ?, ?, ?)
                    """,
                    (str(user_id), str(chat_id), transport, now, now),
                )
            row = conn.execute(
                "SELECT * FROM trial_redemptions WHERE user_id = ?",
                (str(user_id),),
            ).fetchone()
        return True, self._row_to_dict(row) or {}

    def mark_trial_delivered(self, *, user_id: int | str, profile_public_id: str, order_public_id: str | None = None) -> None:
        now = now_ts()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE trial_redemptions
                SET status = 'delivered', profile_public_id = ?, order_public_id = ?,
                    updated_at = ?, delivered_at = ?
                WHERE user_id = ?
                """,
                (profile_public_id, order_public_id, now, now, str(user_id)),
            )

    def mark_trial_failed(self, *, user_id: int | str, error: str) -> None:
        payload = json.dumps({"error": error[:500]}, ensure_ascii=False, separators=(",", ":"))
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE trial_redemptions
                SET status = 'failed', updated_at = ?, meta_json = ?
                WHERE user_id = ?
                """,
                (now_ts(), payload, str(user_id)),
            )

    def get_referrer_by_user(self, user_id: int | str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM referrers WHERE user_id = ?", (str(user_id),)).fetchone()
        return self._row_to_dict(row)

    def get_referrer_by_id(self, referrer_id: int) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM referrers WHERE id = ?", (int(referrer_id),)).fetchone()
        return self._row_to_dict(row)

    def find_referrer_by_code(self, code: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM referrers WHERE code = ? AND status = 'active'", (code,)).fetchone()
        return self._row_to_dict(row)

    def ensure_referrer(
        self,
        *,
        user_id: int | str,
        chat_id: int | str,
        commission_percent: int = 10,
    ) -> dict[str, Any]:
        now = now_ts()
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM referrers WHERE user_id = ?", (str(user_id),)).fetchone()
            if row is not None:
                conn.execute(
                    """
                    UPDATE referrers
                    SET chat_id = ?, updated_at = ?
                    WHERE user_id = ?
                    """,
                    (str(chat_id), now, str(user_id)),
                )
                row = conn.execute("SELECT * FROM referrers WHERE user_id = ?", (str(user_id),)).fetchone()
                return self._row_to_dict(row) or {}

            for _ in range(20):
                code = public_id("ref", 8)
                try:
                    cursor = conn.execute(
                        """
                        INSERT INTO referrers(user_id, chat_id, code, commission_percent, created_at, updated_at)
                        VALUES(?, ?, ?, ?, ?, ?)
                        """,
                        (str(user_id), str(chat_id), code, int(commission_percent), now, now),
                    )
                    row = conn.execute("SELECT * FROM referrers WHERE id = ?", (cursor.lastrowid,)).fetchone()
                    return self._row_to_dict(row) or {}
                except sqlite3.IntegrityError:
                    continue
        raise RuntimeError("Failed to generate unique referral code")

    def get_referral_attribution_for_user(self, user_id: int | str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT a.*, r.code AS referrer_code, r.user_id AS referrer_user_id,
                       r.chat_id AS referrer_chat_id, r.commission_percent
                FROM referral_attributions a
                JOIN referrers r ON r.id = a.referrer_id
                WHERE a.referred_user_id = ?
                LIMIT 1
                """,
                (str(user_id),),
            ).fetchone()
        return self._row_to_dict(row)

    def attach_referral(
        self,
        *,
        code: str,
        referred_user_id: int | str,
        referred_chat_id: int | str,
    ) -> tuple[str, dict[str, Any] | None]:
        now = now_ts()
        with self._connect() as conn:
            ref_row = conn.execute(
                "SELECT * FROM referrers WHERE code = ? AND status = 'active'",
                (code,),
            ).fetchone()
            if ref_row is None:
                return "not_found", None
            referrer = self._row_to_dict(ref_row) or {}
            if str(referrer["user_id"]) == str(referred_user_id):
                return "self", referrer

            existing = conn.execute(
                """
                SELECT a.*, r.code AS referrer_code, r.user_id AS referrer_user_id,
                       r.chat_id AS referrer_chat_id, r.commission_percent
                FROM referral_attributions a
                JOIN referrers r ON r.id = a.referrer_id
                WHERE a.referred_user_id = ?
                LIMIT 1
                """,
                (str(referred_user_id),),
            ).fetchone()
            if existing is not None:
                return "exists", self._row_to_dict(existing)

            cursor = conn.execute(
                """
                INSERT INTO referral_attributions(
                  referrer_id, referred_user_id, referred_chat_id, source_code, created_at
                )
                VALUES(?, ?, ?, ?, ?)
                """,
                (int(referrer["id"]), str(referred_user_id), str(referred_chat_id), code, now),
            )
            row = conn.execute("SELECT * FROM referral_attributions WHERE id = ?", (cursor.lastrowid,)).fetchone()
        return "created", self._row_to_dict(row)

    def create_referral_ledger_for_order(self, order: dict[str, Any]) -> dict[str, Any] | None:
        customer_chat_id = order.get("customer_chat_id")
        final_price = int(order.get("final_price_rub") or 0)
        if not customer_chat_id or final_price <= 0 or order.get("kind") not in {"purchase", "renewal"}:
            return None
        if (order.get("meta_json") or {}).get("source") == "trial":
            return None

        with self._connect() as conn:
            attribution = conn.execute(
                """
                SELECT a.*, r.commission_percent
                FROM referral_attributions a
                JOIN referrers r ON r.id = a.referrer_id
                WHERE a.referred_user_id = ?
                LIMIT 1
                """,
                (str(customer_chat_id),),
            ).fetchone()
            if attribution is None:
                return None
            percent = int(attribution["commission_percent"])
            amount = max(final_price * percent // 100, 0)
            if amount <= 0:
                return None
            payload = json.dumps(
                {
                    "order_transport": order.get("transport"),
                    "order_duration_days": order.get("duration_days"),
                    "device_limit": (order.get("meta_json") or {}).get("device_limit"),
                },
                ensure_ascii=False,
                separators=(",", ":"),
            )
            try:
                cursor = conn.execute(
                    """
                    INSERT INTO referral_ledger(
                      referrer_id, referred_user_id, order_public_id, base_amount_rub,
                      amount_rub, commission_percent, created_at, meta_json
                    )
                    VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        int(attribution["referrer_id"]),
                        str(customer_chat_id),
                        str(order["public_id"]),
                        final_price,
                        amount,
                        percent,
                        now_ts(),
                        payload,
                    ),
                )
            except sqlite3.IntegrityError:
                row = conn.execute(
                    "SELECT * FROM referral_ledger WHERE order_public_id = ?",
                    (str(order["public_id"]),),
                ).fetchone()
                return self._row_to_dict(row)
            if not attribution["first_order_public_id"]:
                conn.execute(
                    """
                    UPDATE referral_attributions
                    SET first_order_public_id = ?
                    WHERE id = ?
                    """,
                    (str(order["public_id"]), int(attribution["id"])),
                )
            row = conn.execute("SELECT * FROM referral_ledger WHERE id = ?", (cursor.lastrowid,)).fetchone()
        return self._row_to_dict(row)

    def list_referral_balances(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                  r.id, r.user_id, r.chat_id, r.code, r.commission_percent, r.status,
                  u.username, u.first_name, u.last_name,
                  COALESCE(lb.balance_rub, 0) AS balance_rub,
                  COALESCE(lb.pending_count, 0) AS pending_count,
                  COALESCE(ac.referred_count, 0) AS referred_count
                FROM referrers r
                LEFT JOIN telegram_users u ON u.user_id = r.user_id
                LEFT JOIN (
                  SELECT referrer_id, SUM(amount_rub) AS balance_rub, COUNT(*) AS pending_count
                  FROM referral_ledger
                  WHERE status = 'pending'
                  GROUP BY referrer_id
                ) lb ON lb.referrer_id = r.id
                LEFT JOIN (
                  SELECT referrer_id, COUNT(*) AS referred_count
                  FROM referral_attributions
                  GROUP BY referrer_id
                ) ac ON ac.referrer_id = r.id
                ORDER BY balance_rub DESC, r.created_at ASC
                """
            ).fetchall()
        return [self._row_to_dict(row) or {} for row in rows]

    def get_referral_balance(self, referrer_id: int) -> dict[str, Any] | None:
        balances = [item for item in self.list_referral_balances() if int(item["id"]) == int(referrer_id)]
        return balances[0] if balances else None

    def create_referral_payout(self, *, referrer_id: int, actor: str) -> dict[str, Any] | None:
        now = now_ts()
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, amount_rub
                FROM referral_ledger
                WHERE referrer_id = ? AND status = 'pending'
                ORDER BY created_at ASC, id ASC
                """,
                (int(referrer_id),),
            ).fetchall()
            amount = sum(int(row["amount_rub"]) for row in rows)
            if amount <= 0:
                return None
            cursor = conn.execute(
                """
                INSERT INTO referral_payouts(referrer_id, amount_rub, actor, created_at)
                VALUES(?, ?, ?, ?)
                """,
                (int(referrer_id), amount, actor, now),
            )
            payout_id = int(cursor.lastrowid)
            ledger_ids = [int(row["id"]) for row in rows]
            placeholders = ",".join("?" for _ in ledger_ids)
            conn.execute(
                f"""
                UPDATE referral_ledger
                SET status = 'paid', paid_at = ?, payout_id = ?
                WHERE id IN ({placeholders})
                """,
                [now, payout_id, *ledger_ids],
            )
            row = conn.execute("SELECT * FROM referral_payouts WHERE id = ?", (payout_id,)).fetchone()
        return self._row_to_dict(row)

    def get_profiles_due_for_email_reminder(self, reminder_kind: str, min_seconds_left: int, max_seconds_left: int) -> list[dict[str, Any]]:
        now = now_ts()
        min_ts = now + min_seconds_left
        max_ts = now + max_seconds_left
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT p.*, o.customer_email, o.public_id AS order_public_id, o.meta_json AS order_meta
                FROM profiles p
                JOIN orders o ON o.provisioned_profile_id = p.id
                LEFT JOIN profile_reminders pr ON pr.profile_public_id = p.public_id AND pr.reminder_kind = ?
                WHERE p.status = 'active'
                  AND p.expires_at >= ?
                  AND p.expires_at <= ?
                  AND o.customer_email != ''
                  AND pr.id IS NULL
                ORDER BY p.expires_at ASC
                """,
                (reminder_kind, min_ts, max_ts),
            ).fetchall()

        result = []
        for r in rows:
            d = self._row_to_dict(r)
            if not d:
                continue
            meta = json.loads(d.get("order_meta") or "{}") if isinstance(d.get("order_meta"), str) else (d.get("order_meta") or {})
            if meta.get("email_reminders", True):
                result.append(d)
        return result

    def record_profile_reminder(self, profile_public_id: str, reminder_kind: str) -> None:
        now = now_ts()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO profile_reminders(profile_public_id, reminder_kind, sent_at)
                VALUES(?, ?, ?)
                """,
                (profile_public_id, reminder_kind, now),
            )

    def get_active_profiles_by_customer_email(self, email: str) -> list[dict[str, Any]]:
        clean_email = (email or "").strip().lower()
        if not clean_email:
            return []
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT p.*, o.customer_email, o.public_id AS order_public_id, o.meta_json AS order_meta
                FROM profiles p
                JOIN orders o ON o.provisioned_profile_id = p.id
                WHERE LOWER(o.customer_email) = ?
                  AND p.status != 'deleted'
                ORDER BY p.created_at ASC
                """,
                (clean_email,),
            ).fetchall()

        seen_profile_ids = set()
        result = []
        for r in rows:
            d = self._row_to_dict(r)
            if not d:
                continue
            pid = d.get("public_id")
            if pid and pid not in seen_profile_ids:
                seen_profile_ids.add(pid)
                result.append(d)
        return result
