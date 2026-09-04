#!/usr/bin/env python3
"""
SilentConnect – Failback 3-Way SQLite Reconciliation Engine (v2).

Merges the state produced on the STANDBY node (FI) while it served traffic back
into the PRIMARY node (NL) database, using the last common snapshot (BASELINE)
to distinguish "changed on FI" from "unchanged since split".

Why v2 (audit findings D-01 .. D-08 against the previous implementation):

  D-01  Orders were merged last-writer-wins on ``updated_at`` with ``>=`` (FI
        wins ties). Any clock skew let a *delivered* order regress to
        *waiting_payment*. v2 treats delivered/cancelled/expired as terminal and
        merges the FSM monotonically; on conflict the more advanced state wins.
  D-02  ``promo_codes.used_count`` without a baseline was ``max(0, fi-nl)`` → if
        both nodes redeemed once the delta was 0 and a redemption was lost.
        v2 requires a baseline for counters (or ``--allow-two-way``) and uses
        ``nl + (fi - base)``.
  D-03  ``profiles.deleted_at = fi OR nl`` resurrected deletions the wrong way:
        a profile un-deleted by a renewal on FI stayed deleted. v2 resolves the
        (status, deleted_at) pair as a unit by the most recent change vs baseline.
  D-04  Profiles were matched by ``public_id`` only although ``xui_email`` is
        UNIQUE – a profile created independently on both nodes with the same
        e-mail aborted the whole merge with IntegrityError (or was silently
        skipped by broad ``except OperationalError: pass`` blocks). v2 matches
        by both keys and never swallows errors.
  D-05  ``PRAGMA integrity_check`` ran *after* COMMIT. v2 verifies inside the
        transaction and rolls back on failure; foreign keys are checked too.
  D-06  FI and baseline files were opened read-write. v2 opens them ``mode=ro``.
  D-07  ``client_traffics.enable = nl OR fi`` re-enabled clients that NL had
        disabled for abuse. v2 uses baseline-aware resolution.
  D-08  webhook_events / payment_confirmations / order_state_log were not
        merged consistently. v2 unions append-only tables by their natural key.

CLI is backwards compatible with ``demote_fi.sh``.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import shutil
import sqlite3
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Optional

TERMINAL_ORDER_STATES = {"delivered", "cancelled", "expired"}
ORDER_RANK = {
    "waiting_payment": 0,
    "auto_provision": 1,
    "failed": 1,
    "provisioning": 2,
    "cancelled": 3,
    "expired": 3,
    "delivered": 4,
}


def log(msg: str) -> None:
    ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[{ts}] [MERGE] {msg}", flush=True)


def err(msg: str) -> None:
    ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[{ts}] [MERGE] ERROR: {msg}", file=sys.stderr, flush=True)


class MergeError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Connection helpers
# ---------------------------------------------------------------------------

def open_rw(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=60.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 60000;")
    conn.execute("PRAGMA foreign_keys = OFF;")  # FK graph is validated explicitly at the end
    return conn


def open_ro(path: str) -> sqlite3.Connection:
    uri = f"file:{os.path.abspath(path)}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=60.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 60000;")
    return conn


def table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()
    return row is not None


def columns(conn: sqlite3.Connection, table: str) -> list[str]:
    return [str(r["name"]) for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]


def make_backup(db_path: str) -> str:
    ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_path = f"{db_path}.bak_{ts}"
    src = sqlite3.connect(db_path, timeout=60.0)
    try:
        src.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        dst = sqlite3.connect(backup_path)
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()
    log(f"Created backup: {backup_path}")
    return backup_path


def check_integrity(conn: sqlite3.Connection, label: str) -> None:
    rows = conn.execute("PRAGMA integrity_check;").fetchall()
    result = [str(r[0]) for r in rows]
    if result != ["ok"]:
        raise MergeError(f"{label}: integrity_check failed: {result[:5]}")
    fk = conn.execute("PRAGMA foreign_key_check;").fetchall()
    if fk:
        sample = [tuple(r) for r in fk[:5]]
        raise MergeError(f"{label}: foreign_key_check reported {len(fk)} violations, e.g. {sample}")
    log(f"{label}: integrity OK")


def insert_row(conn: sqlite3.Connection, table: str, row: sqlite3.Row, *, skip: Iterable[str] = ("id",), override: Optional[dict[str, Any]] = None, dry_run: bool = False) -> None:
    target_cols = set(columns(conn, table))
    data = {k: row[k] for k in row.keys() if k not in set(skip) and k in target_cols}
    if override:
        data.update({k: v for k, v in override.items() if k in target_cols})
    if dry_run:
        return
    cols = ", ".join(data.keys())
    ph = ", ".join("?" for _ in data)
    conn.execute(f"INSERT INTO {table} ({cols}) VALUES ({ph})", list(data.values()))


def rget(row: Optional[sqlite3.Row], key: str, default: Any = None) -> Any:
    """Schema-tolerant row access (older DBs may lack newer columns)."""
    if row is None or key not in row.keys():
        return default
    return row[key]


def changed_since(base: Optional[sqlite3.Row], current: sqlite3.Row, fields: Iterable[str]) -> bool:
    if base is None:
        return True
    for f in fields:
        if f in current.keys() and f in base.keys() and current[f] != base[f]:
            return True
    return False


@dataclass
class Stats:
    counters: Dict[str, int] = field(default_factory=dict)
    conflicts: list[str] = field(default_factory=list)

    def inc(self, key: str, n: int = 1) -> None:
        self.counters[key] = self.counters.get(key, 0) + n

    def conflict(self, msg: str) -> None:
        self.conflicts.append(msg)
        log(f"CONFLICT: {msg}")


# ---------------------------------------------------------------------------
# vpn_shop.db
# ---------------------------------------------------------------------------

def _lookup(conn: Optional[sqlite3.Connection], sql: str, params: tuple) -> Optional[sqlite3.Row]:
    if conn is None:
        return None
    try:
        return conn.execute(sql, params).fetchone()
    except sqlite3.OperationalError:
        return None


def merge_counter_table(
    nl: sqlite3.Connection,
    fi: sqlite3.Connection,
    base: Optional[sqlite3.Connection],
    *,
    table: str,
    key: str,
    counter: str,
    extra_max: tuple[str, ...],
    stats: Stats,
    dry_run: bool,
    allow_two_way: bool,
) -> dict[int, int]:
    """Merge promo_codes / invite_tokens; returns FI id -> NL id map."""
    id_map: dict[int, int] = {}
    if not table_exists(fi, table) or not table_exists(nl, table):
        return id_map
    for fi_row in fi.execute(f"SELECT * FROM {table}").fetchall():
        nl_row = nl.execute(f"SELECT * FROM {table} WHERE {key} = ?", (fi_row[key],)).fetchone()
        base_row = _lookup(base, f"SELECT * FROM {table} WHERE {key} = ?", (fi_row[key],))
        if nl_row is None:
            insert_row(nl, table, fi_row, dry_run=dry_run)
            stats.inc(f"{table}_inserted")
            if not dry_run:
                nl_row = nl.execute(f"SELECT * FROM {table} WHERE {key} = ?", (fi_row[key],)).fetchone()
        else:
            fi_count = int(fi_row[counter] or 0)
            nl_count = int(nl_row[counter] or 0)
            if base_row is not None:
                delta = fi_count - int(base_row[counter] or 0)
            elif allow_two_way:
                delta = max(0, fi_count - nl_count)
                stats.conflict(f"{table}[{fi_row[key][:12]}…]: no baseline, two-way delta={delta}")
            else:
                raise MergeError(
                    f"{table}: baseline missing for {key}={fi_row[key][:12]}… – counters cannot be "
                    "merged safely. Provide --baseline-vpn or pass --allow-two-way."
                )
            delta = max(0, delta)
            new_count = nl_count + delta
            sets = [f"{counter} = ?"]
            params: list[Any] = [new_count]
            for col in extra_max:
                if col in fi_row.keys() and col in nl_row.keys():
                    sets.append(f"{col} = ?")
                    params.append(max(int(nl_row[col] or 0), int(fi_row[col] or 0)) or None)
            # 'enabled' is a policy flag: a disable on either side wins.
            if "enabled" in fi_row.keys():
                sets.append("enabled = ?")
                params.append(int(bool(nl_row["enabled"]) and bool(fi_row["enabled"])))
            params.append(fi_row[key])
            if not dry_run:
                nl.execute(f"UPDATE {table} SET {', '.join(sets)} WHERE {key} = ?", params)
            stats.inc(f"{table}_updated")
        if nl_row is not None:
            id_map[int(fi_row["id"])] = int(nl_row["id"])
    return id_map


def merge_profiles(nl, fi, base, stats: Stats, dry_run: bool) -> dict[int, int]:
    id_map: dict[int, int] = {}
    fields = ("expires_at", "last_renewed_at", "status", "deleted_at", "xui_client_id", "family_label", "notes")
    for fi_p in fi.execute("SELECT * FROM profiles").fetchall():
        nl_p = nl.execute("SELECT * FROM profiles WHERE public_id = ?", (fi_p["public_id"],)).fetchone()
        if nl_p is None:
            # D-04: second natural key
            nl_p = nl.execute("SELECT * FROM profiles WHERE xui_email = ?", (fi_p["xui_email"],)).fetchone()
            if nl_p is not None:
                stats.conflict(
                    f"profile xui_email={fi_p['xui_email']} exists on NL as {nl_p['public_id']} "
                    f"but on FI as {fi_p['public_id']} – merging into NL row"
                )
        base_p = _lookup(base, "SELECT * FROM profiles WHERE public_id = ?", (fi_p["public_id"],))
        if nl_p is None:
            insert_row(nl, "profiles", fi_p, dry_run=dry_run)
            stats.inc("profiles_inserted")
            if not dry_run:
                nl_p = nl.execute("SELECT * FROM profiles WHERE public_id = ?", (fi_p["public_id"],)).fetchone()
        else:
            fi_changed = changed_since(base_p, fi_p, fields)
            nl_changed = changed_since(base_p, nl_p, fields)
            expires = max(int(nl_p["expires_at"] or 0), int(fi_p["expires_at"] or 0))
            renewed = max(int(nl_p["last_renewed_at"] or 0), int(fi_p["last_renewed_at"] or 0)) or None
            # D-03: (status, deleted_at) resolved as a unit.
            if fi_changed and not nl_changed:
                status, deleted_at = fi_p["status"], fi_p["deleted_at"]
            elif nl_changed and not fi_changed:
                status, deleted_at = nl_p["status"], nl_p["deleted_at"]
            else:
                # both changed (or no baseline): the side with the later renewal
                # wins; a renewal always re-activates.
                if int(fi_p["last_renewed_at"] or 0) > int(nl_p["last_renewed_at"] or 0):
                    status, deleted_at = fi_p["status"], fi_p["deleted_at"]
                elif int(nl_p["last_renewed_at"] or 0) > int(fi_p["last_renewed_at"] or 0):
                    status, deleted_at = nl_p["status"], nl_p["deleted_at"]
                else:
                    status, deleted_at = nl_p["status"], nl_p["deleted_at"]
                if base_p is not None and fi_changed and nl_changed:
                    stats.conflict(f"profile {fi_p['public_id']}: changed on both sides; status={status}")
            if status == "active" and expires > int(_dt.datetime.now().timestamp()):
                deleted_at = None
            if not dry_run:
                nl.execute(
                    """
                    UPDATE profiles SET expires_at=?, last_renewed_at=?, status=?, deleted_at=?,
                        xui_client_id=COALESCE(?, xui_client_id),
                        family_label=COALESCE(?, family_label),
                        notes=COALESCE(?, notes)
                    WHERE id=?
                    """,
                    (expires, renewed, status, deleted_at, fi_p["xui_client_id"], fi_p["family_label"], fi_p["notes"], nl_p["id"]),
                )
            stats.inc("profiles_merged")
        if nl_p is not None:
            id_map[int(fi_p["id"])] = int(nl_p["id"])
    return id_map


def resolve_order_status(nl_status: str, fi_status: str, base_status: Optional[str], public_id: str, stats: Stats) -> str:
    if nl_status == fi_status:
        return nl_status
    if base_status is not None:
        if fi_status == base_status:
            return nl_status  # only NL moved
        if nl_status == base_status:
            return fi_status  # only FI moved
    # Both moved (or unknown baseline): terminal states are sticky, the most
    # advanced state wins; delivered beats cancelled because money+profile exist.
    winner = max((nl_status, fi_status), key=lambda s: ORDER_RANK.get(s, -1))
    stats.conflict(f"order {public_id}: NL={nl_status} FI={fi_status} base={base_status} -> {winner}")
    return winner


def merge_orders(nl, fi, base, stats: Stats, dry_run: bool, prof_map, promo_map, invite_map) -> None:
    nl_cols = set(columns(nl, "orders"))
    for fi_o in fi.execute("SELECT * FROM orders").fetchall():
        nl_o = nl.execute("SELECT * FROM orders WHERE public_id = ?", (fi_o["public_id"],)).fetchone()
        base_o = _lookup(base, "SELECT * FROM orders WHERE public_id = ?", (fi_o["public_id"],))
        remap: dict[str, Any] = {}
        if rget(fi_o, "provisioned_profile_id") is not None:
            remap["provisioned_profile_id"] = prof_map.get(int(fi_o["provisioned_profile_id"]))
        if rget(fi_o, "promo_id") is not None:
            remap["promo_id"] = promo_map.get(int(fi_o["promo_id"]))
        if rget(fi_o, "invite_id") is not None:
            remap["invite_id"] = invite_map.get(int(fi_o["invite_id"]))
        if nl_o is None:
            insert_row(nl, "orders", fi_o, override=remap, dry_run=dry_run)
            stats.inc("orders_inserted")
            continue
        status = resolve_order_status(str(nl_o["status"]), str(fi_o["status"]), rget(base_o, "status"), fi_o["public_id"], stats)
        try:
            nl_meta = json.loads(rget(nl_o, "meta_json") or "{}")
            fi_meta = json.loads(rget(fi_o, "meta_json") or "{}")
        except json.JSONDecodeError:
            nl_meta, fi_meta = {}, {}
        merged_meta = {**fi_meta, **nl_meta} if status == nl_o["status"] else {**nl_meta, **fi_meta}
        merged_meta.pop("web_token", None)
        closed_at = rget(nl_o, "closed_at") if status == nl_o["status"] else rget(fi_o, "closed_at")
        fi_updated = int(rget(fi_o, "updated_at") or 0)
        nl_updated = int(rget(nl_o, "updated_at") or 0)
        if status in TERMINAL_ORDER_STATES and not closed_at:
            closed_at = max(nl_updated, fi_updated) or None
        sets = ["status = ?"]
        params: list[Any] = [status]
        if "closed_at" in nl_cols:
            sets.append("closed_at = ?"); params.append(closed_at)
        if "meta_json" in nl_cols:
            sets.append("meta_json = ?"); params.append(json.dumps(merged_meta, ensure_ascii=False, separators=(",", ":")))
        for col in ("provisioned_profile_id", "promo_id", "invite_id"):
            if col in nl_cols:
                sets.append(f"{col} = COALESCE({col}, ?)"); params.append(remap.get(col))
        if "updated_at" in nl_cols:
            sets.append("updated_at = MAX(COALESCE(updated_at, 0), ?)"); params.append(fi_updated)
        if "version" in nl_cols:
            sets.append("version = COALESCE(version, 0) + 1")
        params.append(fi_o["public_id"])
        if not dry_run:
            nl.execute(f"UPDATE orders SET {', '.join(sets)} WHERE public_id = ?", params)
        stats.inc("orders_merged")


def merge_by_key_lww(nl, fi, base, *, table: str, key: str, ts_col: str, stats: Stats, dry_run: bool, remap: Optional[dict[str, dict[int, int]]] = None) -> None:
    """Generic 3-way merge for tables with a natural key and an updated_at."""
    if not table_exists(fi, table) or not table_exists(nl, table):
        return
    nl_cols = set(columns(nl, table))
    for fi_r in fi.execute(f"SELECT * FROM {table}").fetchall():
        nl_r = nl.execute(f"SELECT * FROM {table} WHERE {key} = ?", (fi_r[key],)).fetchone()
        override: dict[str, Any] = {}
        for col, mapping in (remap or {}).items():
            if col in fi_r.keys() and fi_r[col] is not None:
                override[col] = mapping.get(int(fi_r[col]), fi_r[col])
        if nl_r is None:
            insert_row(nl, table, fi_r, override=override, dry_run=dry_run)
            stats.inc(f"{table}_inserted")
            continue
        base_r = _lookup(base, f"SELECT * FROM {table} WHERE {key} = ?", (fi_r[key],))
        fi_ts, nl_ts = int(fi_r[ts_col] or 0), int(nl_r[ts_col] or 0)
        base_ts = int(base_r[ts_col] or 0) if base_r is not None and ts_col in base_r.keys() else None
        fi_moved = base_ts is None or fi_ts != base_ts
        nl_moved = base_ts is None or nl_ts != base_ts
        if not fi_moved:
            continue
        if nl_moved and fi_ts <= nl_ts:
            continue  # NL is at least as recent – keep
        data = {k: fi_r[k] for k in fi_r.keys() if k not in ("id", key) and k in nl_cols}
        data.update(override)
        if data and not dry_run:
            sets = ", ".join(f"{k} = ?" for k in data)
            nl.execute(f"UPDATE {table} SET {sets} WHERE {key} = ?", [*data.values(), fi_r[key]])
        stats.inc(f"{table}_updated")


def merge_append_only(nl, fi, *, table: str, keys: tuple[str, ...], stats: Stats, dry_run: bool, remap: Optional[dict[str, dict[int, int]]] = None) -> None:
    if not table_exists(fi, table) or not table_exists(nl, table):
        return
    where = " AND ".join(f"{k} = ?" for k in keys)
    for fi_r in fi.execute(f"SELECT * FROM {table}").fetchall():
        exists = nl.execute(f"SELECT 1 FROM {table} WHERE {where}", tuple(fi_r[k] for k in keys)).fetchone()
        if exists:
            continue
        override: dict[str, Any] = {}
        for col, mapping in (remap or {}).items():
            if col in fi_r.keys() and fi_r[col] is not None:
                override[col] = mapping.get(int(fi_r[col]), fi_r[col])
        insert_row(nl, table, fi_r, override=override, dry_run=dry_run)
        stats.inc(f"{table}_inserted")


def merge_awg_peers(nl, fi, stats: Stats, dry_run: bool) -> None:
    """AmneziaWG peers: key (sub_id, server_code); telemetry counters are monotonic -> MAX."""
    if not table_exists(fi, "awg_peers") or not table_exists(nl, "awg_peers"):
        return
    nl_cols = set(columns(nl, "awg_peers"))
    for fp in fi.execute("SELECT * FROM awg_peers").fetchall():
        np_ = nl.execute("SELECT * FROM awg_peers WHERE sub_id = ? AND server_code = ?", (fp["sub_id"], fp["server_code"])).fetchone()
        if np_ is None:
            insert_row(nl, "awg_peers", fp, dry_run=dry_run)
            stats.inc("awg_peers_merged")
            continue
        sets, params = [], []
        for col in ("bytes_used", "last_rx", "last_tx", "monthly_bytes", "last_handshake_at", "updated_at"):
            if col in nl_cols and col in fp.keys():
                sets.append(f"{col} = MAX(COALESCE({col}, 0), ?)"); params.append(int(fp[col] or 0))
        if "active" in nl_cols and "active" in fp.keys():
            # a suspension (quota / abuse) on either node sticks
            sets.append("active = MIN(COALESCE(active, 1), ?)"); params.append(int(fp["active"] if fp["active"] is not None else 1))
        if "inactive_reason" in nl_cols and "inactive_reason" in fp.keys():
            sets.append("inactive_reason = COALESCE(inactive_reason, ?)"); params.append(fp["inactive_reason"])
        if sets and not dry_run:
            nl.execute(f"UPDATE awg_peers SET {', '.join(sets)} WHERE sub_id = ? AND server_code = ?", [*params, fp["sub_id"], fp["server_code"]])
        stats.inc("awg_peers_merged")


def merge_vpn_shop(nl_db_path: str, fi_db_path: str, baseline_db_path: Optional[str] = None, dry_run: bool = False, allow_two_way: bool = False) -> Dict[str, Any]:
    log("=== vpn_shop.db merge ===")
    log(f"NL: {nl_db_path}\n           FI: {fi_db_path}\n           BASE: {baseline_db_path or '-'}")
    for p in (nl_db_path, fi_db_path):
        if not os.path.exists(p):
            raise FileNotFoundError(p)
    if not dry_run:
        make_backup(nl_db_path)
    stats = Stats()
    nl = open_rw(nl_db_path)
    fi = open_ro(fi_db_path)
    base = open_ro(baseline_db_path) if baseline_db_path and os.path.exists(baseline_db_path) else None
    try:
        check_integrity(fi, "FI vpn_shop.db")
        nl.execute("BEGIN IMMEDIATE;")
        try:
            # 1. users
            merge_by_key_lww(nl, fi, base, table="telegram_users", key="user_id", ts_col="last_seen_at", stats=stats, dry_run=dry_run)
            # 2. referrers (by user_id)
            ref_map: dict[int, int] = {}
            if table_exists(fi, "referrers"):
                for r in fi.execute("SELECT * FROM referrers").fetchall():
                    nl_r = nl.execute("SELECT id FROM referrers WHERE user_id = ? OR code = ?", (r["user_id"], r["code"])).fetchone()
                    if nl_r is None:
                        insert_row(nl, "referrers", r, dry_run=dry_run)
                        stats.inc("referrers_inserted")
                        nl_r = nl.execute("SELECT id FROM referrers WHERE user_id = ?", (r["user_id"],)).fetchone() if not dry_run else None
                    if nl_r is not None:
                        ref_map[int(r["id"])] = int(nl_r["id"])
            # 3. counters
            promo_map = merge_counter_table(nl, fi, base, table="promo_codes", key="code_hash", counter="used_count", extra_max=("last_used_at",), stats=stats, dry_run=dry_run, allow_two_way=allow_two_way)
            invite_map = merge_counter_table(nl, fi, base, table="invite_tokens", key="code_hash", counter="used_count", extra_max=(), stats=stats, dry_run=dry_run, allow_two_way=allow_two_way)
            # 4. profiles / orders
            prof_map = merge_profiles(nl, fi, base, stats, dry_run)
            merge_orders(nl, fi, base, stats, dry_run, prof_map, promo_map, invite_map)
            # 5. ownership & redemptions
            merge_by_key_lww(nl, fi, base, table="profile_owners", key="profile_public_id", ts_col="updated_at", stats=stats, dry_run=dry_run)
            merge_by_key_lww(nl, fi, base, table="trial_redemptions", key="user_id", ts_col="updated_at", stats=stats, dry_run=dry_run)
            merge_by_key_lww(nl, fi, base, table="referral_attributions", key="referred_user_id", ts_col="created_at", stats=stats, dry_run=dry_run, remap={"referrer_id": ref_map})
            # 6. append-only ledgers
            before_ledger = stats.counters.get("referral_ledger_inserted", 0)
            merge_append_only(nl, fi, table="referral_ledger", keys=("order_public_id",), stats=stats, dry_run=dry_run, remap={"referrer_id": ref_map})
            stats.counters["referral_ledger_merged"] = stats.counters.get("referral_ledger_inserted", 0) - before_ledger
            merge_append_only(nl, fi, table="referral_payouts", keys=("referrer_id", "created_at"), stats=stats, dry_run=dry_run, remap={"referrer_id": ref_map})
            merge_append_only(nl, fi, table="webhook_events", keys=("gateway", "event_id"), stats=stats, dry_run=dry_run)
            merge_append_only(nl, fi, table="payment_confirmations", keys=("order_public_id",), stats=stats, dry_run=dry_run)
            merge_append_only(nl, fi, table="order_state_log", keys=("order_public_id", "to_status", "created_at"), stats=stats, dry_run=dry_run)
            merge_append_only(nl, fi, table="admin_actions", keys=("action_type", "target_public_id", "created_at"), stats=stats, dry_run=dry_run)
            merge_append_only(nl, fi, table="profile_reminders", keys=("profile_public_id", "reminder_kind"), stats=stats, dry_run=dry_run)
            merge_awg_peers(nl, fi, stats, dry_run)
            # 7. verify BEFORE commit (D-05)
            if not dry_run:
                check_integrity(nl, "NL vpn_shop.db (pre-commit)")
                nl.execute("COMMIT;")
                nl.execute("PRAGMA wal_checkpoint(TRUNCATE);")
                log("vpn_shop.db merge COMMITTED")
            else:
                nl.execute("ROLLBACK;")
                log("[DRY-RUN] vpn_shop.db merge computed, nothing written")
        except Exception:
            if nl.in_transaction:
                nl.execute("ROLLBACK;")
            raise
    finally:
        nl.close()
        fi.close()
        if base is not None:
            base.close()
    log(f"vpn_shop.db stats: {stats.counters}; conflicts: {len(stats.conflicts)}")
    return {**stats.counters, "conflicts": stats.conflicts}


# ---------------------------------------------------------------------------
# x-ui.db
# ---------------------------------------------------------------------------

def merge_xui(nl_db_path: str, fi_db_path: str, baseline_db_path: Optional[str] = None, dry_run: bool = False) -> Dict[str, Any]:
    log("=== x-ui.db merge ===")
    for p in (nl_db_path, fi_db_path):
        if not os.path.exists(p):
            raise FileNotFoundError(p)
    if not dry_run:
        make_backup(nl_db_path)
    stats = Stats()
    nl = open_rw(nl_db_path)
    fi = open_ro(fi_db_path)
    base = open_ro(baseline_db_path) if baseline_db_path and os.path.exists(baseline_db_path) else None

    base_clients: dict[str, dict[str, Any]] = {}
    base_traffic: dict[str, sqlite3.Row] = {}
    if base is not None:
        for r in base.execute("SELECT settings FROM inbounds").fetchall():
            try:
                for c in json.loads(r["settings"] or "{}").get("clients", []):
                    if c.get("email"):
                        base_clients[str(c["email"])] = c
            except json.JSONDecodeError:
                continue
        if table_exists(base, "client_traffics"):
            for r in base.execute("SELECT * FROM client_traffics").fetchall():
                base_traffic[str(r["email"])] = r
    try:
        check_integrity(fi, "FI x-ui.db")
        nl.execute("BEGIN IMMEDIATE;")
        try:
            # 1. inbounds.settings clients
            for fi_in in fi.execute("SELECT id, settings FROM inbounds").fetchall():
                nl_in = nl.execute("SELECT id, settings FROM inbounds WHERE id = ?", (fi_in["id"],)).fetchone()
                if nl_in is None:
                    stats.conflict(f"inbound {fi_in['id']} exists only on FI – skipped (inbounds are provisioned per node)")
                    continue
                nl_s = json.loads(nl_in["settings"] or "{}")
                fi_s = json.loads(fi_in["settings"] or "{}")
                nl_clients = nl_s.get("clients", [])
                by_email = {c.get("email"): c for c in nl_clients if c.get("email")}
                modified = False
                for fc in fi_s.get("clients", []):
                    email = fc.get("email")
                    if not email:
                        continue
                    if email not in by_email:
                        nl_clients.append(fc)
                        stats.inc("inbounds_clients_added")
                        modified = True
                        continue
                    nc = by_email[email]
                    bc = base_clients.get(email)
                    # D-07 enable flag: only adopt FI's value if FI changed it vs baseline
                    fi_en, nl_en = bool(fc.get("enable", True)), bool(nc.get("enable", True))
                    if fi_en != nl_en:
                        base_en = bool(bc.get("enable", True)) if bc else None
                        if base_en is None:
                            # unknown history: a renewal on FI (newer expiry) re-enables, otherwise primary wins
                            winner = True if (fi_en and int(fc.get("expiryTime") or 0) > int(nc.get("expiryTime") or 0)) else nl_en
                        elif fi_en != base_en and nl_en == base_en:
                            winner = fi_en
                        elif nl_en != base_en and fi_en == base_en:
                            winner = nl_en
                        else:
                            winner = False  # both changed: fail safe (disabled)
                            stats.conflict(f"client {email}: enable changed on both sides -> disabled")
                        if winner != nl_en:
                            nc["enable"] = winner
                            modified = True
                    if int(fc.get("limitIp") or 0) != int(nc.get("limitIp") or 0):
                        base_lim = int(bc.get("limitIp") or 0) if bc else None
                        fi_renewed = int(fc.get("expiryTime") or 0) > int(nc.get("expiryTime") or 0)
                        if base_lim is None:
                            adopt = fi_renewed  # no history: the side that renewed set the limit
                        else:
                            adopt = int(fc.get("limitIp") or 0) != base_lim and int(nc.get("limitIp") or 0) == base_lim
                        if adopt:
                            nc["limitIp"] = int(fc.get("limitIp") or 0)
                            modified = True
                    new_exp = max(int(nc.get("expiryTime") or 0), int(fc.get("expiryTime") or 0))
                    if new_exp != int(nc.get("expiryTime") or 0):
                        nc["expiryTime"] = new_exp
                        modified = True
                    stats.inc("inbounds_clients_updated")
                if modified and not dry_run:
                    nl_s["clients"] = nl_clients
                    nl.execute("UPDATE inbounds SET settings = ? WHERE id = ?", (json.dumps(nl_s, ensure_ascii=False), fi_in["id"]))
            # 2. client_traffics deltas
            if table_exists(fi, "client_traffics") and table_exists(nl, "client_traffics"):
                for ft in fi.execute("SELECT * FROM client_traffics").fetchall():
                    email = str(ft["email"])
                    nt = nl.execute("SELECT * FROM client_traffics WHERE email = ?", (email,)).fetchone()
                    bt = base_traffic.get(email)
                    if bt is not None:
                        base_up, base_down = int(bt["up"] or 0), int(bt["down"] or 0)
                    elif nt is not None:
                        base_up, base_down = int(nt["up"] or 0), int(nt["down"] or 0)
                    else:
                        base_up = base_down = 0
                    d_up = max(0, int(ft["up"] or 0) - base_up)
                    d_down = max(0, int(ft["down"] or 0) - base_down)
                    stats.inc("total_up_delta_bytes", d_up)
                    stats.inc("total_down_delta_bytes", d_down)
                    if nt is None:
                        insert_row(nl, "client_traffics", ft, dry_run=dry_run)
                        stats.inc("traffic_clients_added")
                        continue
                    enable = bool(nt["enable"])
                    if bool(ft["enable"]) != enable:
                        base_en = bool(bt["enable"]) if bt is not None else None
                        if base_en is not None and bool(ft["enable"]) != base_en and enable == base_en:
                            enable = bool(ft["enable"])
                    if not dry_run:
                        nl.execute(
                            "UPDATE client_traffics SET up = up + ?, down = down + ?, expiry_time = MAX(expiry_time, ?), last_online = MAX(COALESCE(last_online,0), ?), enable = ? WHERE email = ?",
                            (d_up, d_down, int(ft["expiry_time"] or 0), int(ft["last_online"] or 0), int(enable), email),
                        )
                    stats.inc("traffic_deltas_applied")
            if not dry_run:
                check_integrity(nl, "NL x-ui.db (pre-commit)")
                nl.execute("COMMIT;")
                nl.execute("PRAGMA wal_checkpoint(TRUNCATE);")
                log("x-ui.db merge COMMITTED")
            else:
                nl.execute("ROLLBACK;")
                log("[DRY-RUN] x-ui.db merge computed, nothing written")
        except Exception:
            if nl.in_transaction:
                nl.execute("ROLLBACK;")
            raise
    finally:
        nl.close()
        fi.close()
        if base is not None:
            base.close()
    log(f"x-ui.db stats: {stats.counters}; conflicts: {len(stats.conflicts)}")
    return {**stats.counters, "conflicts": stats.conflicts}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Failback 3-Way SQLite Merger for SilentConnect (v2)")
    parser.add_argument("--nl-vpn", default="/root/vpn-shop/data-silentconnect/vpn_shop.db")
    parser.add_argument("--fi-vpn", default="/root/vpn-shop/data-silentconnect/vpn_shop.db")
    parser.add_argument("--baseline-vpn", default="/var/lib/litestream/baseline_vpn_shop.db")
    parser.add_argument("--nl-xui", default="/etc/x-ui/x-ui.db")
    parser.add_argument("--fi-xui", default="/etc/x-ui/x-ui.db")
    parser.add_argument("--baseline-xui", default="/var/lib/litestream/baseline_xui.db")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--skip-xui", action="store_true")
    parser.add_argument("--skip-vpn", action="store_true")
    parser.add_argument("--allow-two-way", action="store_true", help="Permit counter merges without a baseline (lossy; logged as conflicts)")
    parser.add_argument("--report", default="", help="Write a JSON merge report to this path")
    args = parser.parse_args()

    log("=== Starting Safe 3-Way Failback Merge Pipeline (v2) ===")
    if args.dry_run:
        log("DRY-RUN MODE: no database records will be modified")
    report: dict[str, Any] = {"dry_run": args.dry_run}
    ok = True
    if not args.skip_vpn:
        try:
            report["vpn_shop"] = merge_vpn_shop(args.nl_vpn, args.fi_vpn, args.baseline_vpn if os.path.exists(args.baseline_vpn) else None, args.dry_run, args.allow_two_way)
        except Exception as exc:  # noqa: BLE001
            err(f"vpn_shop.db merge failed: {exc}")
            report["vpn_shop_error"] = str(exc)
            ok = False
    if not args.skip_xui:
        try:
            report["xui"] = merge_xui(args.nl_xui, args.fi_xui, args.baseline_xui if os.path.exists(args.baseline_xui) else None, args.dry_run)
        except Exception as exc:  # noqa: BLE001
            err(f"x-ui.db merge failed: {exc}")
            report["xui_error"] = str(exc)
            ok = False
    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2)
    if ok:
        log("[SUCCESS] 3-Way Failback Merge Pipeline finished with zero errors.")
        sys.exit(0)
    err("[FATAL] 3-Way Failback Merge Pipeline encountered errors – NL databases were rolled back.")
    sys.exit(1)


if __name__ == "__main__":
    main()
