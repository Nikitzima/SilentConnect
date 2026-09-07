from __future__ import annotations

from contextlib import contextmanager
import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable, Iterator

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

CREATE UNIQUE INDEX IF NOT EXISTS uq_open_orders_promo
  ON orders(promo_id) WHERE promo_id IS NOT NULL
  AND status IN ('waiting_payment', 'auto_provision');

CREATE UNIQUE INDEX IF NOT EXISTS uq_open_orders_invite
  ON orders(invite_id) WHERE invite_id IS NOT NULL
  AND status IN ('waiting_payment', 'auto_provision');

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

CREATE TABLE IF NOT EXISTS webhook_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  gateway TEXT NOT NULL,
  event_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  order_public_id TEXT,
  processed_at INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'processed',
  payload_sha256 TEXT,
  attempts INTEGER NOT NULL DEFAULT 1,
  last_error TEXT,
  updated_at INTEGER,
  UNIQUE(gateway, event_id)
);

-- Append-only journal of every order state transition (who / when / why).
CREATE TABLE IF NOT EXISTS order_state_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_public_id TEXT NOT NULL,
  from_status TEXT,
  to_status TEXT NOT NULL,
  actor TEXT NOT NULL,
  reason TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_order_state_log_order ON order_state_log(order_public_id, id);

-- Ledger of *manual* payment confirmations. One row per order (UNIQUE) gives
-- hard idempotency: a second confirm can never provision twice.
CREATE TABLE IF NOT EXISTS payment_confirmations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_public_id TEXT NOT NULL UNIQUE,
  idempotency_key TEXT NOT NULL UNIQUE,
  confirmed_by TEXT NOT NULL,
  confirmed_by_id TEXT,
  amount_rub INTEGER NOT NULL,
  expected_amount_rub INTEGER NOT NULL,
  method TEXT NOT NULL DEFAULT 'manual_sbp',
  reference TEXT,
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  finalized_at INTEGER,
  error TEXT,
  meta_json TEXT NOT NULL DEFAULT '{}'
);

-- Hashed single-use magic links for the self-service cabinet.
CREATE TABLE IF NOT EXISTS magic_links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token_hash TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER,
  request_ip TEXT
);
CREATE INDEX IF NOT EXISTS ix_magic_links_email ON magic_links(email, created_at);

CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_orders_customer_status ON orders(customer_chat_id, status);
CREATE INDEX IF NOT EXISTS ix_orders_status_created ON orders(status, created_at);
CREATE INDEX IF NOT EXISTS ix_profiles_status_expires ON profiles(status, expires_at);
CREATE INDEX IF NOT EXISTS ix_orders_customer_email ON orders(customer_email);
"""

SCHEMA_VERSION = 2

# Order finite-state machine. Any transition not listed here is rejected at the
# storage layer, regardless of what the caller asks for.
ORDER_TRANSITIONS: dict[str, frozenset[str]] = {
    "waiting_payment": frozenset({"provisioning", "delivered", "cancelled", "expired", "auto_provision"}),
    "auto_provision": frozenset({"provisioning", "delivered", "failed", "cancelled"}),
    "provisioning": frozenset({"delivered", "failed", "waiting_payment"}),
    "failed": frozenset({"provisioning", "delivered", "cancelled"}),
    # terminal states
    "delivered": frozenset(),
    "cancelled": frozenset(),
    "expired": frozenset(),
}
TERMINAL_ORDER_STATES = frozenset({"delivered", "cancelled", "expired"})


class OrderStateError(RuntimeError):
    """Raised when an order transition violates the FSM or a precondition."""


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
            self._ensure_column(conn, "orders", "web_token_hash", "TEXT")
            self._ensure_column(conn, "orders", "version", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(conn, "webhook_events", "status", "TEXT NOT NULL DEFAULT 'processed'")
            self._ensure_column(conn, "webhook_events", "payload_sha256", "TEXT")
            self._ensure_column(conn, "webhook_events", "attempts", "INTEGER NOT NULL DEFAULT 1")
            self._ensure_column(conn, "webhook_events", "last_error", "TEXT")
            self._ensure_column(conn, "webhook_events", "updated_at", "INTEGER")
            conn.execute(
                "INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES(?, ?)",
                (SCHEMA_VERSION, now_ts()),
            )

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

    def _open(self) -> sqlite3.Connection:
        # isolation_level=None => Python does not inject implicit BEGINs; we
        # control transaction boundaries explicitly (autocommit otherwise).
        conn = sqlite3.connect(self.database_path, timeout=30.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 30000;")
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA temp_store = MEMORY;")
        return conn

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Legacy helper: a DEFERRED transaction around the block.

        Prefer :meth:`transaction` (BEGIN IMMEDIATE) for any read-modify-write.
        """
        conn = self._open()
        try:
            conn.execute("BEGIN;")
            yield conn
            if conn.in_transaction:  # executescript() may have auto-committed
                conn.execute("COMMIT;")
        except Exception:
            try:
                conn.execute("ROLLBACK;")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Serialising write transaction (BEGIN IMMEDIATE).

        Acquires the RESERVED lock up-front so concurrent writers queue on
        ``busy_timeout`` instead of failing with SQLITE_BUSY mid-transaction,
        and so SELECT-then-UPDATE sequences are free of TOCTOU races.
        """
        conn = self._open()
        try:
            conn.execute("BEGIN IMMEDIATE;")
            yield conn
            if conn.in_transaction:
                conn.execute("COMMIT;")
        except Exception:
            try:
                conn.execute("ROLLBACK;")
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

    def online_backup(self, destination: Path | str, *, pages: int = 256) -> Path:
        """Consistent snapshot using the SQLite online-backup API (safe under WAL)."""
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        tmp = destination.with_suffix(destination.suffix + ".tmp")
        src = self._open()
        try:
            dst = sqlite3.connect(tmp)
            try:
                src.backup(dst, pages=pages)
                dst.execute("PRAGMA wal_checkpoint(TRUNCATE);")
            finally:
                dst.close()
        finally:
            src.close()
        tmp.replace(destination)
        return destination

    # ------------------------------------------------------------------
    # Order finite-state machine
    # ------------------------------------------------------------------
    @staticmethod
    def _log_transition(
        conn: sqlite3.Connection,
        order_public_id: str,
        from_status: str | None,
        to_status: str,
        actor: str,
        reason: str | None,
    ) -> None:
        conn.execute(
            """
            INSERT INTO order_state_log(order_public_id, from_status, to_status, actor, reason, created_at)
            VALUES(?, ?, ?, ?, ?, ?)
            """,
            (order_public_id, from_status, to_status, actor, reason, now_ts()),
        )

    def transition_order(
        self,
        public_id_value: str,
        to_status: str,
        *,
        expected_from: Iterable[str] | None = None,
        actor: str = "system",
        reason: str | None = None,
        conn: sqlite3.Connection | None = None,
    ) -> dict[str, Any]:
        """Atomically move an order along the FSM.

        ``UPDATE ... WHERE status IN (allowed)`` is the compare-and-swap that
        makes concurrent confirm/cancel/expire requests safe: exactly one wins.
        Raises :class:`OrderStateError` on any illegal transition.
        """
        if to_status not in ORDER_TRANSITIONS:
            raise OrderStateError(f"Unknown order status {to_status!r}")
        allowed_from = {s for s, targets in ORDER_TRANSITIONS.items() if to_status in targets}
        if expected_from is not None:
            allowed_from &= set(expected_from)
        if not allowed_from:
            raise OrderStateError(f"No legal transition into {to_status!r}")

        def _run(c: sqlite3.Connection) -> dict[str, Any]:
            current = c.execute(
                "SELECT status FROM orders WHERE public_id = ?", (public_id_value,)
            ).fetchone()
            if current is None:
                raise OrderStateError(f"Order {public_id_value} not found")
            from_status = str(current["status"])
            placeholders = ",".join("?" for _ in allowed_from)
            now = now_ts()
            closed = to_status in TERMINAL_ORDER_STATES
            cur = c.execute(
                f"""
                UPDATE orders
                SET status = ?, updated_at = ?, version = version + 1,
                    closed_at = CASE WHEN ? THEN COALESCE(closed_at, ?) ELSE closed_at END
                WHERE public_id = ? AND status IN ({placeholders})
                """,
                (to_status, now, int(closed), now, public_id_value, *sorted(allowed_from)),
            )
            if cur.rowcount != 1:
                raise OrderStateError(
                    f"Illegal transition for {public_id_value}: {from_status} -> {to_status}"
                )
            self._log_transition(c, public_id_value, from_status, to_status, actor, reason)
            row = c.execute("SELECT * FROM orders WHERE public_id = ?", (public_id_value,)).fetchone()
            return self._row_to_dict(row) or {}

        if conn is not None:
            return _run(conn)
        with self.transaction() as c:
            return _run(c)

    def list_order_state_log(self, public_id_value: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM order_state_log WHERE order_public_id = ? ORDER BY id",
                (public_id_value,),
            ).fetchall()
        return [self._row_to_dict(r) or {} for r in rows]

    def claim_order_for_provisioning(
        self,
        public_id_value: str,
        *,
        actor: str,
        idempotency_key: str,
        amount_rub: int,
        confirmed_by_id: str | None = None,
        method: str = "manual_sbp",
        reference: str | None = None,
    ) -> dict[str, Any]:
        """Phase 1 of manual payment confirmation (single BEGIN IMMEDIATE).

        In one transaction: CAS order waiting_payment->provisioning, consume
        promo / invite (if any) and write a ``payment_confirmations`` row with
        status ``claimed``. If anything fails, everything rolls back.
        """
        with self.transaction() as conn:
            order_row = conn.execute("SELECT * FROM orders WHERE public_id = ?", (public_id_value,)).fetchone()
            order = self._row_to_dict(order_row)
            if not order:
                raise OrderStateError(f"Order {public_id_value} not found")
            existing = conn.execute(
                "SELECT * FROM payment_confirmations WHERE order_public_id = ?", (public_id_value,)
            ).fetchone()
            if existing is not None:
                raise OrderStateError(
                    f"Order {public_id_value} already has a payment confirmation "
                    f"(status={existing['status']}, key={existing['idempotency_key']})"
                )
            expected = int(order.get("final_price_rub") or 0)
            if int(amount_rub) < expected:
                raise OrderStateError(
                    f"Amount mismatch for {public_id_value}: paid {amount_rub} < expected {expected}"
                )
            self.transition_order(
                public_id_value,
                "provisioning",
                expected_from=("waiting_payment", "auto_provision", "failed"),
                actor=actor,
                reason="payment_confirmed",
                conn=conn,
            )
            now = now_ts()
            promo_id = order.get("promo_id")
            if promo_id and order.get("kind") in {"purchase", "renewal"}:
                cur = conn.execute(
                    """
                    UPDATE promo_codes
                    SET used_count = used_count + 1, last_used_at = ?
                    WHERE id = ? AND enabled = 1 AND used_count < max_uses
                      AND (expires_at IS NULL OR expires_at > ?)
                    """,
                    (now, int(promo_id), now),
                )
                if cur.rowcount != 1:
                    raise OrderStateError(f"Promo code for order {public_id_value} is exhausted or disabled")
            invite_id = order.get("invite_id")
            if invite_id and not (order.get("meta_json") or {}).get("invite_consumed"):
                cur = conn.execute(
                    """
                    UPDATE invite_tokens
                    SET used_count = used_count + 1
                    WHERE id = ? AND enabled = 1 AND used_count < max_uses
                      AND (expires_at IS NULL OR expires_at > ?)
                    """,
                    (int(invite_id), now),
                )
                if cur.rowcount != 1:
                    raise OrderStateError(f"Invite for order {public_id_value} is exhausted or disabled")
            conn.execute(
                """
                INSERT INTO payment_confirmations(
                  order_public_id, idempotency_key, confirmed_by, confirmed_by_id, amount_rub,
                  expected_amount_rub, method, reference, status, created_at, meta_json
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, 'claimed', ?, '{}')
                """,
                (
                    public_id_value,
                    idempotency_key,
                    actor,
                    str(confirmed_by_id) if confirmed_by_id is not None else None,
                    int(amount_rub),
                    expected,
                    method,
                    reference,
                    now,
                ),
            )
            row = conn.execute("SELECT * FROM orders WHERE public_id = ?", (public_id_value,)).fetchone()
            return self._row_to_dict(row) or {}

    def finalize_order_delivered(
        self,
        public_id_value: str,
        *,
        profile_public_id: str | None,
        actor: str,
        meta_update: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Phase 3: provisioning succeeded – mark delivered + close confirmation."""
        with self.transaction() as conn:
            if profile_public_id:
                profile_row = conn.execute(
                    "SELECT id FROM profiles WHERE public_id = ?", (profile_public_id,)
                ).fetchone()
                if profile_row is None:
                    raise KeyError(profile_public_id)
                conn.execute(
                    "UPDATE orders SET provisioned_profile_id = ? WHERE public_id = ?",
                    (profile_row["id"], public_id_value),
                )
            if meta_update:
                current = conn.execute(
                    "SELECT meta_json FROM orders WHERE public_id = ?", (public_id_value,)
                ).fetchone()
                meta = {}
                if current and current["meta_json"]:
                    try:
                        meta = json.loads(current["meta_json"])
                    except json.JSONDecodeError:
                        meta = {}
                meta.update(meta_update)
                conn.execute(
                    "UPDATE orders SET meta_json = ? WHERE public_id = ?",
                    (json.dumps(meta, ensure_ascii=False, separators=(",", ":")), public_id_value),
                )
            order = self.transition_order(
                public_id_value,
                "delivered",
                expected_from=("provisioning", "auto_provision"),
                actor=actor,
                reason="provisioned",
                conn=conn,
            )
            conn.execute(
                """
                UPDATE payment_confirmations
                SET status = 'finalized', finalized_at = ?
                WHERE order_public_id = ? AND status = 'claimed'
                """,
                (now_ts(), public_id_value),
            )
            return order

    def fail_order_provisioning(
        self,
        public_id_value: str,
        *,
        actor: str,
        error: str,
        release_reservations: bool = True,
    ) -> dict[str, Any]:
        """Compensation path: provisioning failed after the claim.

        Moves the order to ``failed`` (admin can retry) and, when requested,
        returns the promo/invite usage and removes the claimed confirmation so
        that a later confirm starts from a clean slate. All in one transaction.
        """
        with self.transaction() as conn:
            order_row = conn.execute("SELECT * FROM orders WHERE public_id = ?", (public_id_value,)).fetchone()
            order = self._row_to_dict(order_row) or {}
            result = self.transition_order(
                public_id_value,
                "failed",
                expected_from=("provisioning", "auto_provision"),
                actor=actor,
                reason=error[:500],
                conn=conn,
            )
            if release_reservations:
                if order.get("promo_id"):
                    conn.execute(
                        "UPDATE promo_codes SET used_count = MAX(0, used_count - 1) WHERE id = ?",
                        (int(order["promo_id"]),),
                    )
                if order.get("invite_id") and not (order.get("meta_json") or {}).get("invite_consumed"):
                    conn.execute(
                        "UPDATE invite_tokens SET used_count = MAX(0, used_count - 1) WHERE id = ?",
                        (int(order["invite_id"]),),
                    )
                conn.execute(
                    "DELETE FROM payment_confirmations WHERE order_public_id = ? AND status = 'claimed'",
                    (public_id_value,),
                )
            else:
                conn.execute(
                    "UPDATE payment_confirmations SET status = 'failed', error = ? WHERE order_public_id = ?",
                    (error[:1000], public_id_value),
                )
            return result

    def get_payment_confirmation(self, public_id_value: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM payment_confirmations WHERE order_public_id = ?", (public_id_value,)
            ).fetchone()
        return self._row_to_dict(row)

    def list_stale_provisioning_orders(self, older_than_seconds: int = 600) -> list[dict[str, Any]]:
        """Orders stuck in ``provisioning`` (process crashed mid-flight)."""
        cutoff = now_ts() - int(older_than_seconds)
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM orders WHERE status = 'provisioning' AND updated_at < ? ORDER BY updated_at",
                (cutoff,),
            ).fetchall()
        return [self._row_to_dict(r) or {} for r in rows]

    # ------------------------------------------------------------------
    # Web order tokens (hashed at rest) & magic links
    # ------------------------------------------------------------------
    def set_order_web_token(self, public_id_value: str, token: str) -> None:
        from .security import hash_token

        with self.transaction() as conn:
            conn.execute(
                "UPDATE orders SET web_token_hash = ?, updated_at = ? WHERE public_id = ?",
                (hash_token(token, purpose="order_web"), now_ts(), public_id_value),
            )

    def get_order_by_web_token(self, public_id_value: str, token: str) -> dict[str, Any] | None:
        from .security import constant_time_equals, hash_token

        order = self.get_order(public_id_value)
        if not order:
            return None
        stored = str(order.get("web_token_hash") or "")
        if not stored:
            # Legacy orders created before v2 kept the token in meta_json.
            legacy = str((order.get("meta_json") or {}).get("web_token") or "")
            if legacy and constant_time_equals(legacy, token):
                return order
            return None
        if constant_time_equals(stored, hash_token(token, purpose="order_web")):
            return order
        return None

    def create_magic_link(self, *, email: str, token: str, ttl_seconds: int, request_ip: str | None) -> None:
        from .security import hash_token

        now = now_ts()
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO magic_links(token_hash, email, created_at, expires_at, used_at, request_ip)
                VALUES(?, ?, ?, ?, NULL, ?)
                """,
                (hash_token(token, purpose="magic_link"), email.lower(), now, now + int(ttl_seconds), request_ip),
            )
            # Housekeeping: drop expired links older than a day.
            conn.execute("DELETE FROM magic_links WHERE expires_at < ?", (now - 86400,))

    def consume_magic_link(self, token: str) -> str | None:
        """Single-use redemption; returns the e-mail or None."""
        from .security import hash_token

        now = now_ts()
        with self.transaction() as conn:
            cur = conn.execute(
                """
                UPDATE magic_links SET used_at = ?
                WHERE token_hash = ? AND used_at IS NULL AND expires_at >= ?
                RETURNING email
                """,
                (now, hash_token(token, purpose="magic_link"), now),
            )
            row = cur.fetchone()
        return str(row["email"]) if row else None

    def count_recent_magic_links(self, *, email: str, request_ip: str | None, window_seconds: int) -> int:
        since = now_ts() - int(window_seconds)
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS n FROM magic_links
                WHERE created_at >= ? AND (email = ? OR (request_ip IS NOT NULL AND request_ip = ?))
                """,
                (since, email.lower(), request_ip),
            ).fetchone()
        return int(row["n"] if row else 0)

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
        meta = dict(meta)
        # Never persist the plaintext web bearer token (kept in-memory only).
        meta.pop("web_token", None)
        payload = json.dumps(meta, ensure_ascii=False, separators=(",", ":"))
        with self.transaction() as conn:
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

    def record_webhook_event(
        self,
        gateway: str,
        event_id: str,
        event_type: str,
        order_public_id: str | None = None,
        *,
        payload_sha256: str | None = None,
    ) -> bool:
        """Idempotent *reservation* of an inbound event (returns False on duplicate).

        v1 committed the event as processed *before* any business logic ran, so
        a crash after INSERT lost the event forever (audit A-03). The row is now
        created with status='pending' and must be closed with
        :meth:`finish_webhook_event`. A duplicate whose previous attempt failed
        is allowed to retry (status != processed) – at-least-once semantics with
        exactly-once side effects guaranteed by the order FSM.
        """
        now = now_ts()
        with self.transaction() as conn:
            existing = conn.execute(
                "SELECT status, payload_sha256 FROM webhook_events WHERE gateway = ? AND event_id = ?",
                (gateway, event_id),
            ).fetchone()
            if existing is None:
                conn.execute(
                    """
                    INSERT INTO webhook_events(
                      gateway, event_id, event_type, order_public_id, processed_at,
                      status, payload_sha256, attempts, updated_at
                    ) VALUES(?, ?, ?, ?, ?, 'pending', ?, 1, ?)
                    """,
                    (gateway, event_id, event_type, order_public_id, now, payload_sha256, now),
                )
                return True
            if existing["status"] == "processed":
                return False
            if payload_sha256 and existing["payload_sha256"] and existing["payload_sha256"] != payload_sha256:
                # Same event id, different body: replay/tampering attempt.
                return False
            conn.execute(
                """
                UPDATE webhook_events
                SET status = 'pending', attempts = attempts + 1, updated_at = ?
                WHERE gateway = ? AND event_id = ? AND status != 'processed'
                """,
                (now, gateway, event_id),
            )
            return True

    def finish_webhook_event(self, gateway: str, event_id: str, *, ok: bool, error: str | None = None) -> None:
        with self.transaction() as conn:
            conn.execute(
                """
                UPDATE webhook_events
                SET status = ?, last_error = ?, processed_at = ?, updated_at = ?
                WHERE gateway = ? AND event_id = ?
                """,
                ("processed" if ok else "failed", (error or "")[:1000] or None, now_ts(), now_ts(), gateway, event_id),
            )

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
              po.id DESC,
              p.id DESC
            LIMIT 1
        """
        params.append(now_ts())
        with self._connect() as conn:
            row = conn.execute(query, params).fetchone()
        return self._row_to_dict(row)

    def update_order_status(
        self,
        public_id_value: str,
        status: str,
        *,
        closed: bool = False,
        actor: str = "legacy",
        reason: str | None = None,
    ) -> None:
        """Backwards-compatible wrapper that now enforces the order FSM.

        v1 blindly overwrote ``status`` (audit C-01): a cancelled/expired order
        could be flipped back to delivered, and two concurrent confirms both
        succeeded. All writes now go through :meth:`transition_order`.
        """
        self.transition_order(public_id_value, status, actor=actor, reason=reason)

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
        """Exactly-once trial claim.

        v1 did SELECT-then-INSERT under a deferred transaction, so two parallel
        /start taps from the same user could both pass the check (audit C-04).
        Now a single ``INSERT ... ON CONFLICT DO UPDATE ... WHERE status NOT IN``
        executed under BEGIN IMMEDIATE decides the winner in the database.
        """
        now = now_ts()
        with self.transaction() as conn:
            cur = conn.execute(
                """
                INSERT INTO trial_redemptions(user_id, chat_id, status, transport, created_at, updated_at)
                VALUES(?, ?, 'claimed', ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                  chat_id = excluded.chat_id,
                  status = 'claimed',
                  transport = excluded.transport,
                  updated_at = excluded.updated_at,
                  meta_json = '{}'
                WHERE trial_redemptions.status NOT IN ('claimed', 'delivered')
                """,
                (str(user_id), str(chat_id), transport, now, now),
            )
            claimed = cur.rowcount == 1
            row = conn.execute(
                "SELECT * FROM trial_redemptions WHERE user_id = ?",
                (str(user_id),),
            ).fetchone()
        return claimed, self._row_to_dict(row) or {}

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

    def get_referrer_by_code(self, code: str) -> dict[str, Any] | None:
        clean = (code or "").strip()
        if not clean:
            return None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM referrers WHERE code = ? AND status = 'active'",
                (clean,),
            ).fetchone()
        return self._row_to_dict(row)

    def get_referrer(self, referrer_id: int) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM referrers WHERE id = ?", (int(referrer_id),)).fetchone()
        return self._row_to_dict(row)

    def count_delivered_paid_orders(
        self,
        *,
        customer_chat_id: int | str | None = None,
        customer_email: str | None = None,
    ) -> int:
        clauses = []
        params: list[Any] = []
        if customer_chat_id is not None and str(customer_chat_id).strip():
            clauses.append("customer_chat_id = ?")
            params.append(str(customer_chat_id))
        if customer_email is not None and str(customer_email).strip():
            clauses.append("LOWER(customer_email) = ?")
            params.append(str(customer_email).strip().lower())
        if not clauses:
            return 0
        where_clause = " OR ".join(clauses)
        with self._connect() as conn:
            row = conn.execute(
                f"""
                SELECT COUNT(*) AS c FROM orders
                WHERE ({where_clause})
                  AND final_price_rub > 0
                  AND status = 'delivered'
                """,
                params,
            ).fetchone()
        return int(row["c"]) if row else 0

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

            # Anti-retroactive protection (Requirement 5):
            # Check if user has existing completed or waiting paid orders.
            user_key = str(referred_user_id).strip()
            prior_order = conn.execute(
                """
                SELECT 1 FROM orders
                WHERE (customer_chat_id = ? OR LOWER(customer_email) = ?)
                  AND final_price_rub > 0
                  AND status IN ('delivered', 'waiting_payment')
                LIMIT 1
                """,
                (user_key, user_key.lower()),
            ).fetchone()
            if prior_order is not None:
                return "already_customer", None

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
            attribution_id = cursor.lastrowid
            row = conn.execute(
                """
                SELECT a.*, r.code AS referrer_code, r.user_id AS referrer_user_id,
                       r.chat_id AS referrer_chat_id, r.commission_percent
                FROM referral_attributions a
                JOIN referrers r ON r.id = a.referrer_id
                WHERE a.id = ?
                """,
                (attribution_id,),
            ).fetchone()
        return "created", self._row_to_dict(row)

    def create_referral_ledger_for_order(
        self,
        order: dict[str, Any],
    ) -> tuple[dict[str, Any] | None, int, int]:
        customer_chat_id = order.get("customer_chat_id")
        customer_email = str(order.get("customer_email") or "").strip().lower()
        final_price = int(order.get("final_price_rub") or 0)
        kind = str(order.get("kind") or "")

        meta = order.get("meta_json") or {}
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except Exception:
                meta = {}

        if final_price <= 0 or kind not in {"purchase", "renewal"}:
            return None, 0, 0
        if meta.get("source") == "trial":
            return None, 0, 0

        with self._connect() as conn:
            referrer_id: int | None = None
            commission_percent: int = 10
            attribution_id: int | None = None
            attribution_first_order: str | None = None

            # Step 1: customer_chat_id in referral_attributions
            if customer_chat_id:
                row = conn.execute(
                    """
                    SELECT a.id, a.first_order_public_id, r.id AS referrer_id, r.commission_percent
                    FROM referral_attributions a
                    JOIN referrers r ON r.id = a.referrer_id
                    WHERE a.referred_user_id = ? AND r.status = 'active'
                    LIMIT 1
                    """,
                    (str(customer_chat_id),),
                ).fetchone()
                if row:
                    referrer_id = int(row["referrer_id"])
                    commission_percent = int(row["commission_percent"] or 10)
                    attribution_id = int(row["id"])
                    attribution_first_order = row["first_order_public_id"]

            # Step 2: customer_email in referral_attributions
            if not referrer_id and customer_email:
                row = conn.execute(
                    """
                    SELECT a.id, a.first_order_public_id, r.id AS referrer_id, r.commission_percent
                    FROM referral_attributions a
                    JOIN referrers r ON r.id = a.referrer_id
                    WHERE LOWER(a.referred_user_id) = ? AND r.status = 'active'
                    LIMIT 1
                    """,
                    (customer_email,),
                ).fetchone()
                if row:
                    referrer_id = int(row["referrer_id"])
                    commission_percent = int(row["commission_percent"] or 10)
                    attribution_id = int(row["id"])
                    attribution_first_order = row["first_order_public_id"]

            # Step 3: meta_json["referrer_id"]
            if not referrer_id and meta.get("referrer_id"):
                try:
                    ref_candidate = int(meta["referrer_id"])
                    row = conn.execute(
                        "SELECT id, commission_percent FROM referrers WHERE id = ? AND status = 'active'",
                        (ref_candidate,),
                    ).fetchone()
                    if row:
                        referrer_id = int(row["id"])
                        commission_percent = int(row["commission_percent"] or 10)
                except (ValueError, TypeError):
                    pass

            # Step 4: For renewals, lookup provisioned_profile_id -> find initial purchase order / profile owner
            if not referrer_id and kind == "renewal" and order.get("provisioned_profile_id"):
                prof_id = int(order["provisioned_profile_id"])
                # 4a. Look up earlier order for this profile
                earlier_order = conn.execute(
                    """
                    SELECT customer_chat_id, customer_email, meta_json
                    FROM orders
                    WHERE provisioned_profile_id = ? AND id != ?
                    ORDER BY id ASC LIMIT 1
                    """,
                    (prof_id, int(order.get("id") or 0)),
                ).fetchone()
                if earlier_order:
                    earlier_chat_id = earlier_order["customer_chat_id"]
                    earlier_email = str(earlier_order["customer_email"] or "").strip().lower()
                    earlier_meta = earlier_order["meta_json"] or {}
                    if isinstance(earlier_meta, str):
                        try:
                            earlier_meta = json.loads(earlier_meta)
                        except Exception:
                            earlier_meta = {}

                    if earlier_chat_id:
                        row = conn.execute(
                            """
                            SELECT r.id AS referrer_id, r.commission_percent
                            FROM referral_attributions a
                            JOIN referrers r ON r.id = a.referrer_id
                            WHERE a.referred_user_id = ? AND r.status = 'active'
                            LIMIT 1
                            """,
                            (str(earlier_chat_id),),
                        ).fetchone()
                        if row:
                            referrer_id = int(row["referrer_id"])
                            commission_percent = int(row["commission_percent"] or 10)

                    if not referrer_id and earlier_email:
                        row = conn.execute(
                            """
                            SELECT r.id AS referrer_id, r.commission_percent
                            FROM referral_attributions a
                            JOIN referrers r ON r.id = a.referrer_id
                            WHERE LOWER(a.referred_user_id) = ? AND r.status = 'active'
                            LIMIT 1
                            """,
                            (earlier_email,),
                        ).fetchone()
                        if row:
                            referrer_id = int(row["referrer_id"])
                            commission_percent = int(row["commission_percent"] or 10)

                    if not referrer_id and earlier_meta.get("referrer_id"):
                        try:
                            row = conn.execute(
                                "SELECT id, commission_percent FROM referrers WHERE id = ? AND status = 'active'",
                                (int(earlier_meta["referrer_id"]),),
                            ).fetchone()
                            if row:
                                referrer_id = int(row["id"])
                                commission_percent = int(row["commission_percent"] or 10)
                        except (ValueError, TypeError):
                            pass

                # 4b. If still not found, check profile_owners
                if not referrer_id:
                    owner_row = conn.execute(
                        """
                        SELECT po.user_id, po.chat_id
                        FROM profile_owners po
                        JOIN profiles p ON p.public_id = po.profile_public_id
                        WHERE p.id = ?
                        LIMIT 1
                        """,
                        (prof_id,),
                    ).fetchone()
                    if owner_row:
                        for uid in (owner_row["user_id"], owner_row["chat_id"]):
                            if uid and not referrer_id:
                                row = conn.execute(
                                    """
                                    SELECT r.id AS referrer_id, r.commission_percent
                                    FROM referral_attributions a
                                    JOIN referrers r ON r.id = a.referrer_id
                                    WHERE a.referred_user_id = ? AND r.status = 'active'
                                    LIMIT 1
                                    """,
                                    (str(uid),),
                                ).fetchone()
                                if row:
                                    referrer_id = int(row["referrer_id"])
                                    commission_percent = int(row["commission_percent"] or 10)

            if not referrer_id:
                return None, 0, 0

            amount = max(final_price * commission_percent // 100, 0)
            if amount <= 0:
                return None, 0, 0

            # Calculate old balance: total_earned - total_paid
            bal_row = conn.execute(
                """
                SELECT
                  COALESCE(le.total_earned, 0) - COALESCE(lp.total_paid, 0) AS balance_rub
                FROM (SELECT ? AS ref_id) x
                LEFT JOIN (
                  SELECT referrer_id, SUM(amount_rub) AS total_earned
                  FROM referral_ledger
                  WHERE referrer_id = ?
                ) le ON 1=1
                LEFT JOIN (
                  SELECT referrer_id, SUM(amount_rub) AS total_paid
                  FROM referral_payouts
                  WHERE referrer_id = ?
                ) lp ON 1=1
                """,
                (referrer_id, referrer_id, referrer_id),
            ).fetchone()
            old_balance = max(int(bal_row["balance_rub"]) if bal_row and bal_row["balance_rub"] is not None else 0, 0)

            payload = json.dumps(
                {
                    "order_transport": order.get("transport"),
                    "order_duration_days": order.get("duration_days"),
                    "device_limit": meta.get("device_limit"),
                },
                ensure_ascii=False,
                separators=(",", ":"),
            )

            ref_user_key = str(customer_chat_id or customer_email or f"order_{order.get('public_id')}")
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
                        referrer_id,
                        ref_user_key,
                        str(order["public_id"]),
                        final_price,
                        amount,
                        commission_percent,
                        now_ts(),
                        payload,
                    ),
                )
                ledger_id = cursor.lastrowid
                new_balance = old_balance + amount
            except sqlite3.IntegrityError:
                # Idempotent replay
                row = conn.execute(
                    "SELECT * FROM referral_ledger WHERE order_public_id = ?",
                    (str(order["public_id"]),),
                ).fetchone()
                return self._row_to_dict(row), old_balance, old_balance

            if attribution_id and not attribution_first_order:
                conn.execute(
                    """
                    UPDATE referral_attributions
                    SET first_order_public_id = ?
                    WHERE id = ?
                    """,
                    (str(order["public_id"]), attribution_id),
                )

            row = conn.execute("SELECT * FROM referral_ledger WHERE id = ?", (ledger_id,)).fetchone()
            return self._row_to_dict(row), old_balance, new_balance

    def list_referral_balances(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                  r.id, r.user_id, r.chat_id, r.code, r.commission_percent, r.status,
                  u.username, u.first_name, u.last_name,
                  COALESCE(le.total_earned, 0) AS total_earned_rub,
                  COALESCE(lp.total_paid, 0) AS total_paid_rub,
                  MAX(COALESCE(le.total_earned, 0) - COALESCE(lp.total_paid, 0), 0) AS balance_rub,
                  COALESCE(le.pending_count, 0) AS pending_count,
                  COALESCE(ac.referred_count, 0) AS referred_count
                FROM referrers r
                LEFT JOIN telegram_users u ON u.user_id = r.user_id
                LEFT JOIN (
                  SELECT referrer_id, SUM(amount_rub) AS total_earned, COUNT(*) AS pending_count
                  FROM referral_ledger
                  GROUP BY referrer_id
                ) le ON le.referrer_id = r.id
                LEFT JOIN (
                  SELECT referrer_id, SUM(amount_rub) AS total_paid
                  FROM referral_payouts
                  GROUP BY referrer_id
                ) lp ON lp.referrer_id = r.id
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

    def create_referral_payout(
        self,
        *,
        referrer_id: int,
        actor: str,
        amount_rub: int | None = None,
    ) -> dict[str, Any] | None:
        now = now_ts()
        with self._connect() as conn:
            # Calculate current debt
            bal_row = conn.execute(
                """
                SELECT
                  COALESCE(le.total_earned, 0) - COALESCE(lp.total_paid, 0) AS balance_rub
                FROM (SELECT ? AS ref_id) x
                LEFT JOIN (
                  SELECT referrer_id, SUM(amount_rub) AS total_earned
                  FROM referral_ledger
                  WHERE referrer_id = ?
                ) le ON 1=1
                LEFT JOIN (
                  SELECT referrer_id, SUM(amount_rub) AS total_paid
                  FROM referral_payouts
                  WHERE referrer_id = ?
                ) lp ON 1=1
                """,
                (int(referrer_id), int(referrer_id), int(referrer_id)),
            ).fetchone()
            cur_balance = max(int(bal_row["balance_rub"]) if bal_row and bal_row["balance_rub"] is not None else 0, 0)
            if cur_balance <= 0:
                return None

            payout_amount = cur_balance if amount_rub is None else int(amount_rub)
            if payout_amount <= 0:
                return None
            if payout_amount > cur_balance:
                payout_amount = cur_balance

            cursor = conn.execute(
                """
                INSERT INTO referral_payouts(referrer_id, amount_rub, actor, created_at)
                VALUES(?, ?, ?, ?)
                """,
                (int(referrer_id), payout_amount, actor, now),
            )
            payout_id = int(cursor.lastrowid)

            # Cumulative calculation to mark covered referral_ledger rows as 'paid'
            new_total_paid_row = conn.execute(
                "SELECT SUM(amount_rub) AS total_paid FROM referral_payouts WHERE referrer_id = ?",
                (int(referrer_id),),
            ).fetchone()
            total_paid_so_far = int(new_total_paid_row["total_paid"] or 0) if new_total_paid_row else payout_amount

            all_ledger_rows = conn.execute(
                """
                SELECT id, amount_rub, status
                FROM referral_ledger
                WHERE referrer_id = ?
                ORDER BY created_at ASC, id ASC
                """,
                (int(referrer_id),),
            ).fetchall()

            ids_to_mark_paid = []
            cumulative = 0
            for r in all_ledger_rows:
                cumulative += int(r["amount_rub"])
                if cumulative <= total_paid_so_far and r["status"] == "pending":
                    ids_to_mark_paid.append(int(r["id"]))

            if ids_to_mark_paid:
                placeholders = ",".join("?" for _ in ids_to_mark_paid)
                conn.execute(
                    f"""
                    UPDATE referral_ledger
                    SET status = 'paid', paid_at = ?, payout_id = ?
                    WHERE id IN ({placeholders})
                    """,
                    [now, payout_id, *ids_to_mark_paid],
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
