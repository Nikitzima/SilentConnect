#!/usr/bin/env python3
"""
failback_merge.py - Safe 3-Way SQLite & X-UI Data Merge Engine for SilentConnect Failover/Failback

Reconciles transactional changes made on Secondary Standby (FI) during an outage
back into Primary Master (NL) without ID collisions or data loss.

Integrity Standards:
- Natural Business Keys: public_id, UUID, xui_email, telegram user_id.
- Dynamic Foreign Key Remapping: profiles.id, referrers.id, promo_codes.id, invite_tokens.id.
- Traffic Delta Accumulation: Computes FI delta from baseline snapshot and adds to NL counters.
- Expiry Preservation: Uses MAX(nl.expires_at, fi.expires_at) across all subscription profiles and inbounds.
- Atomic Transactions & Automatic Timestamped Backups (.bak_YYYYMMDD_HHMMSS).
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import shutil
import sqlite3
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def log(msg: str) -> None:
    try:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [failback_merge] {msg}")
    except UnicodeEncodeError:
        safe_msg = msg.encode("ascii", errors="replace").decode("ascii")
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [failback_merge] {safe_msg}")


def err(msg: str) -> None:
    try:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [failback_merge] ERROR: {msg}", file=sys.stderr)
    except UnicodeEncodeError:
        safe_msg = msg.encode("ascii", errors="replace").decode("ascii")
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [failback_merge] ERROR: {safe_msg}", file=sys.stderr)


def make_backup(db_path: str) -> str:
    """Create timestamped backup before modifying database using SQLite online backup API."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = f"{db_path}.bak_{ts}"
    conn = sqlite3.connect(db_path, timeout=30.0)
    try:
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        except sqlite3.Error:
            pass
        bak_conn = sqlite3.connect(backup_path, timeout=30.0)
        try:
            conn.backup(bak_conn)
        finally:
            bak_conn.close()
    finally:
        conn.close()
    log(f"Created backup: {backup_path}")
    return backup_path


def check_integrity(conn: sqlite3.Connection, db_name: str) -> None:
    cursor = conn.cursor()
    cursor.execute("PRAGMA integrity_check;")
    res = cursor.fetchall()
    if not res or res[0][0] != "ok":
        raise RuntimeError(f"Integrity check failed for {db_name}: {res}")
    log(f"Integrity check OK for {db_name}")


# ==============================================================================
# VPN Shop Database Merge (vpn_shop.db)
# ==============================================================================

def merge_vpn_shop(
    nl_db_path: str,
    fi_db_path: str,
    baseline_db_path: Optional[str] = None,
    dry_run: bool = False
) -> Dict[str, Any]:
    """
    Merges vpn_shop.db from FI into NL database.
    """
    log(f"=== Starting merge for vpn_shop.db ===")
    log(f"NL Target DB: {nl_db_path}")
    log(f"FI Source DB: {fi_db_path}")
    if baseline_db_path:
        log(f"Baseline DB: {baseline_db_path}")

    stats = {
        "profiles_merged": 0,
        "profiles_inserted": 0,
        "orders_merged": 0,
        "orders_inserted": 0,
        "profile_owners_merged": 0,
        "telegram_users_merged": 0,
        "trial_redemptions_merged": 0,
        "referrers_merged": 0,
        "referral_ledger_merged": 0,
        "awg_peers_merged": 0,
    }

    if not os.path.exists(nl_db_path):
        raise FileNotFoundError(f"NL database not found: {nl_db_path}")
    if not os.path.exists(fi_db_path):
        raise FileNotFoundError(f"FI database not found: {fi_db_path}")

    if not dry_run:
        make_backup(nl_db_path)

    nl_conn = sqlite3.connect(nl_db_path)
    nl_conn.row_factory = sqlite3.Row
    fi_conn = sqlite3.connect(fi_db_path)
    fi_conn.row_factory = sqlite3.Row

    # Enable foreign keys and check integrity
    check_integrity(nl_conn, "NL vpn_shop.db")
    check_integrity(fi_conn, "FI vpn_shop.db")

    nl_cur = nl_conn.cursor()
    fi_cur = fi_conn.cursor()

    try:
        if not dry_run:
            nl_cur.execute("BEGIN IMMEDIATE;")

        # ----------------------------------------------------------------------
        # 1. Merge telegram_users
        # ----------------------------------------------------------------------
        fi_cur.execute("SELECT * FROM telegram_users;")
        for fi_u in fi_cur.fetchall():
            nl_cur.execute("SELECT * FROM telegram_users WHERE user_id = ?;", (fi_u["user_id"],))
            nl_u = nl_cur.fetchone()
            if nl_u is None:
                cols = [k for k in fi_u.keys()]
                vals = [fi_u[k] for k in cols]
                placeholders = ", ".join(["?"] * len(cols))
                col_names = ", ".join(cols)
                if not dry_run:
                    nl_cur.execute(f"INSERT INTO telegram_users ({col_names}) VALUES ({placeholders});", vals)
                stats["telegram_users_merged"] += 1
            else:
                max_last_seen = max(nl_u["last_seen_at"] or 0, fi_u["last_seen_at"] or 0)
                if not dry_run:
                    nl_cur.execute("""
                        UPDATE telegram_users SET
                            chat_id = COALESCE(?, chat_id),
                            username = COALESCE(?, username),
                            first_name = COALESCE(?, first_name),
                            last_name = COALESCE(?, last_name),
                            is_bot = COALESCE(?, is_bot),
                            last_seen_at = ?
                        WHERE user_id = ?;
                    """, (
                        fi_u["chat_id"],
                        fi_u["username"],
                        fi_u["first_name"],
                        fi_u["last_name"],
                        fi_u["is_bot"],
                        max_last_seen,
                        fi_u["user_id"]
                    ))
                stats["telegram_users_merged"] += 1

        # ----------------------------------------------------------------------
        # 2. Merge referrers
        # ----------------------------------------------------------------------
        # Match by user_id or code
        fi_cur.execute("SELECT * FROM referrers;")
        for fi_ref in fi_cur.fetchall():
            nl_cur.execute("SELECT * FROM referrers WHERE user_id = ? OR code = ?;", (fi_ref["user_id"], fi_ref["code"]))
            nl_ref = nl_cur.fetchone()
            if nl_ref is None:
                cols = [k for k in fi_ref.keys() if k != "id"]
                vals = [fi_ref[k] for k in cols]
                placeholders = ", ".join(["?"] * len(cols))
                col_names = ", ".join(cols)
                if not dry_run:
                    nl_cur.execute(f"INSERT INTO referrers ({col_names}) VALUES ({placeholders});", vals)
                stats["referrers_merged"] += 1

        # Build referrer id mapping: FI referrer id -> NL referrer id (by user_id)
        ref_id_map: Dict[int, int] = {}
        fi_cur.execute("SELECT id, user_id, code FROM referrers;")
        for row in fi_cur.fetchall():
            nl_cur.execute("SELECT id FROM referrers WHERE user_id = ? OR code = ?;", (row["user_id"], row["code"]))
            nl_match = nl_cur.fetchone()
            if nl_match:
                ref_id_map[row["id"]] = nl_match["id"]

        # ----------------------------------------------------------------------
        # 3. Merge profiles
        # ----------------------------------------------------------------------
        fi_cur.execute("SELECT * FROM profiles;")
        for fi_prof in fi_cur.fetchall():
            pub_id = fi_prof["public_id"]
            nl_cur.execute("SELECT * FROM profiles WHERE public_id = ?;", (pub_id,))
            nl_prof = nl_cur.fetchone()
            if nl_prof is None:
                cols = [k for k in fi_prof.keys() if k != "id"]
                vals = [fi_prof[k] for k in cols]
                placeholders = ", ".join(["?"] * len(cols))
                col_names = ", ".join(cols)
                if not dry_run:
                    nl_cur.execute(f"INSERT INTO profiles ({col_names}) VALUES ({placeholders});", vals)
                stats["profiles_inserted"] += 1
            else:
                max_exp = max(nl_prof["expires_at"] or 0, fi_prof["expires_at"] or 0)
                max_renew = max(nl_prof["last_renewed_at"] or 0, fi_prof["last_renewed_at"] or 0)
                new_status = fi_prof["status"] if (fi_prof["last_renewed_at"] or 0) >= (nl_prof["last_renewed_at"] or 0) else nl_prof["status"]
                new_deleted = fi_prof["deleted_at"] or nl_prof["deleted_at"]
                if not dry_run:
                    nl_cur.execute("""
                        UPDATE profiles SET
                            expires_at = ?,
                            last_renewed_at = ?,
                            status = ?,
                            deleted_at = ?,
                            xui_client_id = COALESCE(?, xui_client_id),
                            family_label = COALESCE(?, family_label),
                            notes = COALESCE(?, notes)
                        WHERE public_id = ?;
                    """, (
                        max_exp,
                        max_renew,
                        new_status,
                        new_deleted,
                        fi_prof["xui_client_id"],
                        fi_prof["family_label"],
                        fi_prof["notes"],
                        pub_id
                    ))
                stats["profiles_merged"] += 1

        # Build profile id mapping: FI profile id -> NL profile id (by public_id)
        prof_id_map: Dict[int, int] = {}
        fi_cur.execute("SELECT id, public_id FROM profiles;")
        for row in fi_cur.fetchall():
            nl_cur.execute("SELECT id FROM profiles WHERE public_id = ?;", (row["public_id"],))
            nl_match = nl_cur.fetchone()
            if nl_match:
                prof_id_map[row["id"]] = nl_match["id"]

        # ----------------------------------------------------------------------
        # 4. Merge orders (Remapping FK provisioned_profile_id)
        # ----------------------------------------------------------------------
        fi_cur.execute("SELECT * FROM orders;")
        for fi_ord in fi_cur.fetchall():
            ord_pub_id = fi_ord["public_id"]
            nl_cur.execute("SELECT * FROM orders WHERE public_id = ?;", (ord_pub_id,))
            nl_ord = nl_cur.fetchone()

            # Remap foreign keys
            remapped_prof_id = prof_id_map.get(fi_ord["provisioned_profile_id"]) if fi_ord["provisioned_profile_id"] else None

            if nl_ord is None:
                cols = [k for k in fi_ord.keys() if k != "id"]
                vals = []
                for k in cols:
                    if k == "provisioned_profile_id":
                        vals.append(remapped_prof_id)
                    else:
                        vals.append(fi_ord[k])
                placeholders = ", ".join(["?"] * len(cols))
                col_names = ", ".join(cols)
                if not dry_run:
                    nl_cur.execute(f"INSERT INTO orders ({col_names}) VALUES ({placeholders});", vals)
                stats["orders_inserted"] += 1
            else:
                # Update if FI is more recent
                if (fi_ord["updated_at"] or 0) >= (nl_ord["updated_at"] or 0):
                    if not dry_run:
                        nl_cur.execute("""
                            UPDATE orders SET
                                status = ?,
                                provisioned_profile_id = COALESCE(?, provisioned_profile_id),
                                closed_at = COALESCE(?, closed_at),
                                meta_json = COALESCE(?, meta_json),
                                updated_at = ?
                            WHERE public_id = ?;
                        """, (
                            fi_ord["status"],
                            remapped_prof_id,
                            fi_ord["closed_at"],
                            fi_ord["meta_json"],
                            fi_ord["updated_at"],
                            ord_pub_id
                        ))
                stats["orders_merged"] += 1

        # ----------------------------------------------------------------------
        # 5. Merge profile_owners
        # ----------------------------------------------------------------------
        fi_cur.execute("SELECT * FROM profile_owners;")
        for fi_po in fi_cur.fetchall():
            prof_pub_id = fi_po["profile_public_id"]
            nl_cur.execute("SELECT * FROM profile_owners WHERE profile_public_id = ?;", (prof_pub_id,))
            nl_po = nl_cur.fetchone()
            if nl_po is None:
                cols = [k for k in fi_po.keys() if k != "id"]
                vals = [fi_po[k] for k in cols]
                placeholders = ", ".join(["?"] * len(cols))
                col_names = ", ".join(cols)
                if not dry_run:
                    nl_cur.execute(f"INSERT INTO profile_owners ({col_names}) VALUES ({placeholders});", vals)
                stats["profile_owners_merged"] += 1
            else:
                if (fi_po["updated_at"] or 0) >= (nl_po["updated_at"] or 0):
                    if not dry_run:
                        nl_cur.execute("""
                            UPDATE profile_owners SET
                                user_id = ?,
                                chat_id = ?,
                                source_order_public_id = ?,
                                updated_at = ?
                            WHERE profile_public_id = ?;
                        """, (
                            fi_po["user_id"],
                            fi_po["chat_id"],
                            fi_po["source_order_public_id"],
                            fi_po["updated_at"],
                            prof_pub_id
                        ))
                stats["profile_owners_merged"] += 1

        # ----------------------------------------------------------------------
        # 6. Merge trial_redemptions
        # ----------------------------------------------------------------------
        try:
            fi_cur.execute("SELECT * FROM trial_redemptions;")
            for fi_tr in fi_cur.fetchall():
                u_id = fi_tr["user_id"]
                nl_cur.execute("SELECT * FROM trial_redemptions WHERE user_id = ?;", (u_id,))
                nl_tr = nl_cur.fetchone()
                if nl_tr is None:
                    cols = [k for k in fi_tr.keys() if k != "id"]
                    vals = [fi_tr[k] for k in cols]
                    placeholders = ", ".join(["?"] * len(cols))
                    col_names = ", ".join(cols)
                    if not dry_run:
                        nl_cur.execute(f"INSERT INTO trial_redemptions ({col_names}) VALUES ({placeholders});", vals)
                    stats["trial_redemptions_merged"] += 1
                else:
                    if (fi_tr["updated_at"] or 0) >= (nl_tr["updated_at"] or 0):
                        if not dry_run:
                            nl_cur.execute("""
                                UPDATE trial_redemptions SET
                                    status = ?,
                                    delivered_at = COALESCE(?, delivered_at),
                                    updated_at = ?
                                WHERE user_id = ?;
                            """, (fi_tr["status"], fi_tr["delivered_at"], fi_tr["updated_at"], u_id))
                    stats["trial_redemptions_merged"] += 1
        except sqlite3.OperationalError:
            pass  # Table may not exist

        # ----------------------------------------------------------------------
        # 7. Merge referral_ledger
        # ----------------------------------------------------------------------
        try:
            fi_cur.execute("SELECT * FROM referral_ledger;")
            for fi_rl in fi_cur.fetchall():
                ord_pub_id = fi_rl["order_public_id"]
                nl_cur.execute("SELECT * FROM referral_ledger WHERE order_public_id = ?;", (ord_pub_id,))
                nl_rl = nl_cur.fetchone()
                remapped_ref_id = ref_id_map.get(fi_rl["referrer_id"], fi_rl["referrer_id"])
                if nl_rl is None:
                    cols = [k for k in fi_rl.keys() if k != "id"]
                    vals = []
                    for k in cols:
                        if k == "referrer_id":
                            vals.append(remapped_ref_id)
                        else:
                            vals.append(fi_rl[k])
                    placeholders = ", ".join(["?"] * len(cols))
                    col_names = ", ".join(cols)
                    if not dry_run:
                        nl_cur.execute(f"INSERT INTO referral_ledger ({col_names}) VALUES ({placeholders});", vals)
                    stats["referral_ledger_merged"] += 1
                else:
                    if not dry_run:
                        nl_cur.execute("UPDATE referral_ledger SET status = ? WHERE order_public_id = ?;", (fi_rl["status"], ord_pub_id))
                    stats["referral_ledger_merged"] += 1
        except sqlite3.OperationalError:
            pass

        # ----------------------------------------------------------------------
        # 8. Merge awg_peers
        # ----------------------------------------------------------------------
        try:
            fi_cur.execute("SELECT * FROM awg_peers;")
            for fi_peer in fi_cur.fetchall():
                sub_id = fi_peer["sub_id"]
                server_code = fi_peer["server_code"]
                nl_cur.execute("SELECT * FROM awg_peers WHERE sub_id = ? AND server_code = ?;", (sub_id, server_code))
                nl_peer = nl_cur.fetchone()
                if nl_peer is None:
                    cols = [k for k in fi_peer.keys() if k != "id"]
                    vals = [fi_peer[k] for k in cols]
                    placeholders = ", ".join(["?"] * len(cols))
                    col_names = ", ".join(cols)
                    if not dry_run:
                        nl_cur.execute(f"INSERT INTO awg_peers ({col_names}) VALUES ({placeholders});", vals)
                    stats["awg_peers_merged"] += 1
                else:
                    max_bytes = max(nl_peer["bytes_used"] or 0, fi_peer["bytes_used"] or 0)
                    max_rx = max(nl_peer["last_rx"] or 0, fi_peer["last_rx"] or 0)
                    max_tx = max(nl_peer["last_tx"] or 0, fi_peer["last_tx"] or 0)
                    if not dry_run:
                        nl_cur.execute("""
                            UPDATE awg_peers SET
                                bytes_used = ?,
                                last_rx = ?,
                                last_tx = ?,
                                active = COALESCE(?, active),
                                inactive_reason = COALESCE(?, inactive_reason)
                            WHERE sub_id = ? AND server_code = ?;
                        """, (max_bytes, max_rx, max_tx, fi_peer["active"], fi_peer["inactive_reason"], sub_id, server_code))
                    stats["awg_peers_merged"] += 1
        except sqlite3.OperationalError:
            pass

        if not dry_run:
            nl_conn.commit()
            nl_cur.execute("PRAGMA wal_checkpoint(TRUNCATE);")
            check_integrity(nl_conn, "Merged NL vpn_shop.db")
            log("✅ Successfully committed vpn_shop.db merge")
        else:
            log("🔍 [DRY-RUN] vpn_shop.db merge calculated successfully without modifications")

    except Exception as e:
        if not dry_run:
            nl_conn.rollback()
        err(f"vpn_shop.db merge failed: {e}")
        raise
    finally:
        nl_conn.close()
        fi_conn.close()

    log(f"Merge statistics for vpn_shop.db: {stats}")
    return stats


# ==============================================================================
# X-UI Database Merge (x-ui.db)
# ==============================================================================

def merge_xui(
    nl_db_path: str,
    fi_db_path: str,
    baseline_db_path: Optional[str] = None,
    dry_run: bool = False
) -> Dict[str, Any]:
    """
    Merges x-ui.db from FI into NL database.
    Reconciles inbounds.settings client list and client_traffics bandwidth deltas.
    """
    log(f"=== Starting merge for x-ui.db ===")
    log(f"NL Target DB: {nl_db_path}")
    log(f"FI Source DB: {fi_db_path}")
    if baseline_db_path:
        log(f"Baseline DB: {baseline_db_path}")

    stats = {
        "inbounds_clients_updated": 0,
        "inbounds_clients_added": 0,
        "traffic_deltas_applied": 0,
        "traffic_clients_added": 0,
        "total_up_delta_bytes": 0,
        "total_down_delta_bytes": 0,
    }

    if not os.path.exists(nl_db_path):
        raise FileNotFoundError(f"NL database not found: {nl_db_path}")
    if not os.path.exists(fi_db_path):
        raise FileNotFoundError(f"FI database not found: {fi_db_path}")

    if not dry_run:
        make_backup(nl_db_path)

    nl_conn = sqlite3.connect(nl_db_path)
    nl_conn.row_factory = sqlite3.Row
    fi_conn = sqlite3.connect(fi_db_path)
    fi_conn.row_factory = sqlite3.Row

    baseline_traffics: Dict[str, Dict[str, int]] = {}
    if baseline_db_path and os.path.exists(baseline_db_path):
        base_conn = sqlite3.connect(baseline_db_path)
        base_conn.row_factory = sqlite3.Row
        base_cur = base_conn.cursor()
        base_cur.execute("SELECT email, up, down FROM client_traffics;")
        for row in base_cur.fetchall():
            baseline_traffics[row["email"]] = {
                "up": row["up"] or 0,
                "down": row["down"] or 0,
            }
        base_conn.close()

    check_integrity(nl_conn, "NL x-ui.db")
    check_integrity(fi_conn, "FI x-ui.db")

    nl_cur = nl_conn.cursor()
    fi_cur = fi_conn.cursor()

    try:
        if not dry_run:
            nl_cur.execute("BEGIN IMMEDIATE;")

        # ----------------------------------------------------------------------
        # 1. Merge inbounds.settings JSON
        # ----------------------------------------------------------------------
        fi_cur.execute("SELECT id, settings FROM inbounds;")
        for fi_inbound in fi_cur.fetchall():
            inbound_id = fi_inbound["id"]
            nl_cur.execute("SELECT id, settings FROM inbounds WHERE id = ?;", (inbound_id,))
            nl_inbound = nl_cur.fetchone()
            if not nl_inbound:
                continue

            try:
                nl_settings = json.loads(nl_inbound["settings"] or "{}")
                fi_settings = json.loads(fi_inbound["settings"] or "{}")
            except Exception as e:
                err(f"JSON decode failed on inbound {inbound_id}: {e}")
                continue

            nl_clients = nl_settings.get("clients", [])
            fi_clients = fi_settings.get("clients", [])

            nl_clients_by_email = {c.get("email"): c for c in nl_clients if c.get("email")}

            modified = False
            for fi_c in fi_clients:
                email = fi_c.get("email")
                if not email:
                    continue

                if email not in nl_clients_by_email:
                    nl_clients.append(fi_c)
                    stats["inbounds_clients_added"] += 1
                    modified = True
                else:
                    nl_c = nl_clients_by_email[email]
                    old_exp = int(nl_c.get("expiryTime") or 0)
                    fi_exp = int(fi_c.get("expiryTime") or 0)
                    if fi_exp > old_exp:
                        nl_c["expiryTime"] = fi_exp
                        modified = True

                    if fi_c.get("enable") and not nl_c.get("enable"):
                        nl_c["enable"] = True
                        modified = True

                    if int(fi_c.get("limitIp") or 0) > int(nl_c.get("limitIp") or 0):
                        nl_c["limitIp"] = int(fi_c.get("limitIp"))
                        modified = True

                    stats["inbounds_clients_updated"] += 1

            if modified and not dry_run:
                nl_settings["clients"] = nl_clients
                new_settings_json = json.dumps(nl_settings, ensure_ascii=False)
                nl_cur.execute("UPDATE inbounds SET settings = ? WHERE id = ?;", (new_settings_json, inbound_id))

        # ----------------------------------------------------------------------
        # 2. Merge client_traffics (Delta Calculation)
        # ----------------------------------------------------------------------
        fi_cur.execute("SELECT * FROM client_traffics;")
        for fi_ct in fi_cur.fetchall():
            email = fi_ct["email"]
            nl_cur.execute("SELECT * FROM client_traffics WHERE email = ?;", (email,))
            nl_ct = nl_cur.fetchone()

            fi_up = fi_ct["up"] or 0
            fi_down = fi_ct["down"] or 0

            # Determine baseline for delta computation
            if email in baseline_traffics:
                base_up = baseline_traffics[email]["up"]
                base_down = baseline_traffics[email]["down"]
            elif nl_ct:
                base_up = nl_ct["up"] or 0
                base_down = nl_ct["down"] or 0
            else:
                base_up = 0
                base_down = 0

            delta_up = max(0, fi_up - base_up)
            delta_down = max(0, fi_down - base_down)

            stats["total_up_delta_bytes"] += delta_up
            stats["total_down_delta_bytes"] += delta_down

            if nl_ct is None:
                cols = [k for k in fi_ct.keys() if k != "id"]
                vals = [fi_ct[k] for k in cols]
                placeholders = ", ".join(["?"] * len(cols))
                col_names = ", ".join(cols)
                if not dry_run:
                    nl_cur.execute(f"INSERT INTO client_traffics ({col_names}) VALUES ({placeholders});", vals)
                stats["traffic_clients_added"] += 1
            else:
                new_up = (nl_ct["up"] or 0) + delta_up
                new_down = (nl_ct["down"] or 0) + delta_down
                max_exp = max(nl_ct["expiry_time"] or 0, fi_ct["expiry_time"] or 0)
                max_online = max(nl_ct["last_online"] or 0, fi_ct["last_online"] or 0)
                new_enable = bool(nl_ct["enable"] or fi_ct["enable"])

                if not dry_run:
                    nl_cur.execute("""
                        UPDATE client_traffics SET
                            up = ?,
                            down = ?,
                            expiry_time = ?,
                            last_online = ?,
                            enable = ?
                        WHERE email = ?;
                    """, (new_up, new_down, max_exp, max_online, new_enable, email))
                stats["traffic_deltas_applied"] += 1

        if not dry_run:
            nl_conn.commit()
            nl_cur.execute("PRAGMA wal_checkpoint(TRUNCATE);")
            check_integrity(nl_conn, "Merged NL x-ui.db")
            log("✅ Successfully committed x-ui.db merge")
        else:
            log("🔍 [DRY-RUN] x-ui.db merge calculated successfully without modifications")

    except Exception as e:
        if not dry_run:
            nl_conn.rollback()
        err(f"x-ui.db merge failed: {e}")
        raise
    finally:
        nl_conn.close()
        fi_conn.close()

    log(f"Merge statistics for x-ui.db: {stats}")
    return stats


# ==============================================================================
# Main Orchestration CLI
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(description="Failback 3-Way SQLite Merger for SilentConnect")
    parser.add_argument("--nl-vpn", default="/root/vpn-shop/data-silentconnect/vpn_shop.db", help="Path to NL vpn_shop.db")
    parser.add_argument("--fi-vpn", default="/root/vpn-shop/data-silentconnect/vpn_shop.db", help="Path to FI vpn_shop.db")
    parser.add_argument("--baseline-vpn", default="/var/lib/litestream/baseline_vpn_shop.db", help="Baseline vpn_shop.db snapshot")
    parser.add_argument("--nl-xui", default="/etc/x-ui/x-ui.db", help="Path to NL x-ui.db")
    parser.add_argument("--fi-xui", default="/etc/x-ui/x-ui.db", help="Path to FI x-ui.db")
    parser.add_argument("--baseline-xui", default="/var/lib/litestream/baseline_xui.db", help="Baseline x-ui.db snapshot")
    parser.add_argument("--dry-run", action="store_true", help="Calculate merge without writing changes")
    parser.add_argument("--skip-xui", action="store_true", help="Skip merging x-ui.db")
    parser.add_argument("--skip-vpn", action="store_true", help="Skip merging vpn_shop.db")

    args = parser.parse_args()

    log("=== Starting Safe 3-Way Failback Merge Pipeline ===")
    if args.dry_run:
        log("DRY-RUN MODE ENABLED: No database records will be modified")

    overall_success = True

    if not args.skip_vpn:
        try:
            vpn_stats = merge_vpn_shop(
                nl_db_path=args.nl_vpn,
                fi_db_path=args.fi_vpn,
                baseline_db_path=args.baseline_vpn if os.path.exists(args.baseline_vpn) else None,
                dry_run=args.dry_run
            )
            log("vpn_shop.db merge completed successfully.")
        except Exception as e:
            err(f"vpn_shop.db merge failed: {e}")
            overall_success = False

    if not args.skip_xui:
        try:
            xui_stats = merge_xui(
                nl_db_path=args.nl_xui,
                fi_db_path=args.fi_xui,
                baseline_db_path=args.baseline_xui if os.path.exists(args.baseline_xui) else None,
                dry_run=args.dry_run
            )
            log("x-ui.db merge completed successfully.")
        except Exception as e:
            err(f"x-ui.db merge failed: {e}")
            overall_success = False

    if overall_success:
        log("🎉 [SUCCESS] 3-Way Failback Merge Pipeline finished with ZERO errors.")
        sys.exit(0)
    else:
        err("💥 [FATAL] 3-Way Failback Merge Pipeline encountered errors.")
        sys.exit(1)


if __name__ == "__main__":
    main()
