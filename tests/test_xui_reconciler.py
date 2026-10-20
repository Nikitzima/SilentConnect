from __future__ import annotations

import dataclasses
import json
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
VPN_SHOP_DIR = REPO_ROOT / "vpn-shop"
if str(VPN_SHOP_DIR) not in sys.path:
    sys.path.insert(0, str(VPN_SHOP_DIR))

from vpn_shop.config import load_settings
from vpn_shop.provisioning import PUBLIC_TRIAL_PROFILE_NOTES
from vpn_shop.store import Store
from vpn_shop.xui_reconciler import XuiReconciler


class TestXuiReconciler(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="test_xui_rec_"))
        self.shop_db_path = self.tmp_dir / "vpn_shop.db"
        self.xui_db_path = self.tmp_dir / "x-ui.db"

        self.store = Store(self.shop_db_path)
        self.store.init()

        base_settings = load_settings(self.tmp_dir)
        self.settings = dataclasses.replace(
            base_settings,
            database_path=self.shop_db_path,
            xui_db_path=self.xui_db_path,
            xui_tcp_inbound_id=1,
            xui_xhttp_inbound_id=2,
            default_device_limit=3,
        )
        self._init_mock_xui_db()

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _init_mock_xui_db(self) -> None:
        conn = sqlite3.connect(self.xui_db_path)
        conn.executescript(
            """
            CREATE TABLE inbounds (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER DEFAULT 1,
                up INTEGER DEFAULT 0,
                down INTEGER DEFAULT 0,
                total INTEGER DEFAULT 0,
                remark TEXT,
                enable INTEGER DEFAULT 1,
                expiry_time INTEGER DEFAULT 0,
                listen TEXT DEFAULT '',
                port INTEGER,
                protocol TEXT,
                settings TEXT,
                stream_settings TEXT,
                tag TEXT,
                sniffing TEXT DEFAULT '{}'
            );
            CREATE TABLE clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE,
                sub_id TEXT,
                uuid TEXT,
                password TEXT,
                auth TEXT,
                flow TEXT,
                security TEXT,
                reverse TEXT,
                wg_private_key TEXT,
                wg_public_key TEXT,
                wg_allowed_ips TEXT,
                wg_pre_shared_key TEXT,
                wg_keep_alive INTEGER,
                secret TEXT,
                ad_tag TEXT,
                limit_ip INTEGER,
                total_gb INTEGER,
                expiry_time INTEGER,
                enable INTEGER,
                tg_id INTEGER,
                group_name TEXT,
                comment TEXT,
                reset INTEGER,
                created_at INTEGER,
                updated_at INTEGER
            );
            CREATE TABLE client_traffics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                inbound_id INTEGER,
                enable INTEGER,
                email TEXT UNIQUE,
                up INTEGER DEFAULT 0,
                down INTEGER DEFAULT 0,
                total INTEGER DEFAULT 0,
                expiry_time INTEGER DEFAULT 0,
                reset INTEGER DEFAULT 0,
                last_online INTEGER DEFAULT 0
            );
            CREATE TABLE client_inbounds (
                client_id INTEGER,
                inbound_id INTEGER,
                flow_override TEXT,
                created_at INTEGER,
                PRIMARY KEY (client_id, inbound_id)
            );
            """
        )
        # Inbound 1: TCP Reality Vision (port 23385)
        conn.execute(
            "INSERT INTO inbounds (id, remark, port, protocol, settings, stream_settings, tag) VALUES (1, 'reality-tcp', 23385, 'vless', ?, ?, 'inbound-23385')",
            (json.dumps({"clients": []}), json.dumps({"network": "tcp", "security": "reality"})),
        )
        # Inbound 2: gRPC Reality (port 29443)
        conn.execute(
            "INSERT INTO inbounds (id, remark, port, protocol, settings, stream_settings, tag) VALUES (2, 'reality-grpc', 29443, 'vless', ?, ?, 'inbound-29443')",
            (json.dumps({"clients": []}), json.dumps({"network": "grpc", "security": "reality"})),
        )
        conn.commit()
        conn.close()

    def test_01_zero_profiles_circuit_breaker(self) -> None:
        rec = XuiReconciler(self.settings, self.store)
        rec.xui_api = MagicMock()
        res = rec.reconcile_once(dry_run=False)
        self.assertTrue(res["ok"])
        self.assertEqual(res.get("skipped"), "zero_profiles_circuit_breaker")
        rec.xui_api.add_client.assert_not_called()

    def test_02_add_active_profile_across_multiple_inbounds(self) -> None:
        future_exp = int(time.time()) + 30 * 86400
        prof = self.store.create_profile(
            xui_inbound_id=1,
            transport="tcp",
            profile_mode="anonymous",
            family_label=None,
            xui_email="anon-user1",
            xui_client_id="11111111-2222-3333-4444-555555555555",
            xui_sub_id="sub_token_user1",
            expires_at=future_exp,
            device_limit=6,
        )

        rec = XuiReconciler(self.settings, self.store)
        rec.xui_api = MagicMock()

        res = rec.reconcile_once(dry_run=False)
        self.assertTrue(res["ok"])
        self.assertEqual(res["added"], 1)
        # Called for both inbound 1 (TCP Vision) and inbound 2 (gRPC)
        self.assertEqual(rec.xui_api.add_client.call_count, 2)

        calls = {c.args[0]: c.args[1] for c in rec.xui_api.add_client.call_args_list}
        self.assertEqual(calls[1]["flow"], "xtls-rprx-vision")
        self.assertEqual(calls[1]["subId"], "sub_token_user1")
        self.assertEqual(calls[1]["limitIp"], 6)
        self.assertEqual(calls[2]["flow"], "")
        self.assertEqual(calls[2]["subId"], "sub_token_user1")

        # Second run with no changes -> 0 API calls!
        rec.xui_api.reset_mock()
        res2 = rec.reconcile_once(dry_run=False)
        self.assertEqual(res2["added"], 0)
        self.assertEqual(res2["updated"], 0)
        rec.xui_api.add_client.assert_not_called()

    def test_03_expired_paid_profile_is_disabled_not_deleted(self) -> None:
        future_exp = int(time.time()) + 30 * 86400
        prof = self.store.create_profile(
            xui_inbound_id=1,
            transport="tcp",
            profile_mode="anonymous",
            family_label=None,
            xui_email="anon-exp1",
            xui_client_id="22222222-3333-4444-5555-666666666666",
            xui_sub_id="sub_exp1",
            expires_at=future_exp,
            device_limit=3,
        )
        rec = XuiReconciler(self.settings, self.store)
        rec.xui_api = MagicMock()
        rec.reconcile_once(dry_run=False)

        # Now expire the profile in store
        past_exp = int(time.time()) - 3600
        with self.store.transaction() as conn:
            conn.execute("UPDATE profiles SET expires_at = ?, status = 'expired' WHERE public_id = ?", (past_exp, prof["public_id"]))

        rec.xui_api.reset_mock()
        res = rec.reconcile_once(dry_run=False)
        self.assertEqual(res["disabled"], 1)
        self.assertEqual(res["deleted"], 0)
        rec.xui_api.delete_client.assert_not_called()
        self.assertEqual(rec.xui_api.update_client.call_count, 2)

        # Verify client is still in x-ui.db with enable=False
        found = rec.xui_db.find_client_by_sub_id("sub_exp1")
        self.assertIsNotNone(found)
        self.assertFalse(found["client"]["enable"])

    def test_04_deleted_trial_profile_is_purged(self) -> None:
        future_exp = int(time.time()) + 86400
        prof = self.store.create_profile(
            xui_inbound_id=1,
            transport="tcp",
            profile_mode="anonymous",
            family_label=None,
            xui_email="trial-user99",
            xui_client_id="33333333-4444-5555-6666-777777777777",
            xui_sub_id="sub_trial99",
            expires_at=future_exp,
            notes=PUBLIC_TRIAL_PROFILE_NOTES,
        )
        rec = XuiReconciler(self.settings, self.store)
        rec.xui_api = MagicMock()
        rec.reconcile_once(dry_run=False)

        # Mark trial deleted
        self.store.mark_profile_deleted(prof["public_id"])
        rec.xui_api.reset_mock()
        res = rec.reconcile_once(dry_run=False)
        self.assertEqual(res["deleted"], 1)
        self.assertEqual(rec.xui_api.delete_client.call_count, 2)


if __name__ == "__main__":
    unittest.main()
