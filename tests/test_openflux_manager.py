import base64
import json
import sqlite3
import unittest
from unittest.mock import patch, MagicMock
import zlib

import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "vpn-shop"))

from vpn_shop import openflux_manager


class TestOpenFluxManager(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(
            """
            CREATE TABLE profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                public_id TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'active',
                expires_at INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        self.conn.execute("INSERT INTO profiles (public_id) VALUES ('prf_test_user_1')")
        self.conn.execute("INSERT INTO profiles (public_id) VALUES ('prf_test_user_2')")
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def test_build_openflux_stream_link_cupsonline(self):
        test_url = "https://interview.cups.online/live-coding/?room=12345678-1234-1234-1234-123456789abc"
        link = openflux_manager.build_openflux_stream_link(test_url, "nl")
        self.assertTrue(link.startswith("openflux://v1/"))

        # Decode link
        b64 = link[len("openflux://v1/"):]
        # Add padding if needed
        rem = len(b64) % 4
        if rem > 0:
            b64 += "=" * (4 - rem)
        raw_deflate = base64.urlsafe_b64decode(b64.encode("ascii"))
        decompressed = zlib.decompress(raw_deflate, -zlib.MAX_WBITS)
        payload = json.loads(decompressed.decode("utf-8"))

        self.assertEqual(payload["mode"], "stream")
        self.assertEqual(len(payload["transports"]), 1)
        self.assertEqual(payload["transports"][0]["type"], "cupsonline")
        self.assertEqual(payload["transports"][0]["url"], test_url)
        self.assertIn("Нидерланды", payload["name"])

    @patch("urllib.request.urlopen")
    def test_create_cups_room_scraping(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = (
            b'<html><head><meta name="test"></head><body>'
            b'<div data-room="{&quot;uuid&quot;: &quot;f4ef3561-97e3-4365-8323-1e4c40b35320&quot;, &quot;access_type&quot;: &quot;public&quot;}"></div>'
            b'</body></html>'
        )
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        room_uuid, room_url = openflux_manager.create_cups_room()
        self.assertEqual(room_uuid, "f4ef3561-97e3-4365-8323-1e4c40b35320")
        self.assertEqual(room_url, "https://interview.cups.online/live-coding/?room=f4ef3561-97e3-4365-8323-1e4c40b35320")

    @patch("vpn_shop.openflux_manager.start_openflux_worker", return_value=True)
    @patch("vpn_shop.openflux_manager.stop_openflux_worker", return_value=True)
    @patch("vpn_shop.openflux_manager.rename_openflux_worker", return_value=True)
    @patch("vpn_shop.openflux_manager.create_cups_room")
    def test_slot_activation_and_handover(self, mock_create_room, mock_rename, mock_stop, mock_start):
        mock_create_room.side_effect = [
            ("uuid_nl_1", "https://interview.cups.online/live-coding/?room=uuid_nl_1"),
            ("uuid_pl_2", "https://interview.cups.online/live-coding/?room=uuid_pl_2"),
        ]

        # 1. Uninitialized
        slot = openflux_manager.get_or_create_openflux_slot(self.conn, "prf_test_user_1")
        self.assertEqual(slot["status"], "uninitialized")

        # 2. Activate
        with patch("vpn_shop.openflux_manager._is_node_reachable", return_value=True):
            slot = openflux_manager.activate_openflux_slot(self.conn, "prf_test_user_1")
        self.assertEqual(slot["status"], "active")
        self.assertIn("cups_uuid_nl_1", slot["active_doc_name"])
        self.assertIn("openflux-worker-prf_test_user_1", slot["active_container_name"])
        mock_start.assert_called()

        # 3. Two-phase migration: start switch to other server ('pl' legacy code normalizes to 'de')
        target_srv = "pl" if slot["active_server"] == "nl" else "nl"
        expected_srv = "de" if target_srv == "pl" else target_srv
        slot = openflux_manager.start_server_switch(self.conn, "prf_test_user_1", target_srv)
        self.assertEqual(slot["status"], "migrating")
        self.assertEqual(slot["pending_server"], expected_srv)
        self.assertIn("cups_uuid_pl_2", slot["pending_doc_name"])

        # 4. Confirm switch
        slot = openflux_manager.confirm_server_switch(self.conn, "prf_test_user_1", async_cleanup=False)
        self.assertEqual(slot["status"], "active")
        self.assertEqual(slot["active_server"], expected_srv)
        self.assertIsNone(slot["pending_server"])

    @patch("vpn_shop.openflux_manager.start_openflux_worker", return_value=True)
    @patch("vpn_shop.openflux_manager.create_cups_room")
    @patch("vpn_shop.openflux_manager.is_cups_room_alive", return_value=False)
    def test_ensure_openflux_slot_healthy_heals_dead_room(self, mock_alive, mock_create_room, mock_start):
        mock_create_room.return_value = ("uuid_healed_99", "https://interview.cups.online/live-coding/?room=uuid_healed_99")
        openflux_manager.init_openflux_db(self.conn)
        self.conn.execute(
            """
            INSERT INTO openflux_slots (
                profile_public_id, slot_label, status, active_server,
                active_doc_name, active_doc_url, active_container_name,
                created_at, updated_at
            ) VALUES (
                'prf_test_user_2', 'Белые списки (OpenFlux)', 'active', 'de',
                'cups_dead_404', 'https://interview.cups.online/live-coding/?room=dead_404',
                'openflux-worker-prf_test_user_2', 1000, 1000
            )
            """
        )
        self.conn.commit()

        healed = openflux_manager.ensure_openflux_slot_healthy(self.conn, "prf_test_user_2")
        self.assertEqual(healed["status"], "active")
        self.assertEqual(healed["active_server"], "de")
        self.assertEqual(healed["active_doc_name"], "cups_uuid_healed_99")
        self.assertEqual(healed["active_doc_url"], "https://interview.cups.online/live-coding/?room=uuid_healed_99")
        mock_start.assert_called_once_with(
            "de",
            "openflux-worker-prf_test_user_2",
            "https://interview.cups.online/live-coding/?room=uuid_healed_99",
        )

    def test_concurrent_state_lazy_expiry_cas_single_stop_and_outbox_crash_recovery(self):
        import tempfile
        import threading
        import time

        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "of_cas.db"
            c0 = sqlite3.connect(db_path)
            c0.row_factory = sqlite3.Row
            c0.execute(
                """
                CREATE TABLE profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    public_id TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL DEFAULT 'active',
                    expires_at INTEGER NOT NULL DEFAULT 0
                );
                """
            )
            c0.execute("INSERT INTO profiles (public_id) VALUES ('prf_cas_1')")
            openflux_manager.init_openflux_db(c0)
            expired_at = int(time.time()) - (openflux_manager.MIGRATION_TIMEOUT_SECONDS + 120)
            c0.execute(
                """
                INSERT INTO openflux_slots (
                    profile_public_id, slot_label, status,
                    active_server, active_doc_name, active_doc_url, active_container_name,
                    pending_server, pending_doc_name, pending_doc_url, pending_container_name,
                    pending_started_at, created_at, updated_at
                ) VALUES (
                    'prf_cas_1', 'Белые списки (OpenFlux)', 'migrating',
                    'nl', 'cups_act_1', 'https://interview.cups.online/live-coding/?room=act_1', 'openflux-worker-prf_cas_1',
                    'de', 'cups_pend_1', 'https://interview.cups.online/live-coding/?room=pend_1', 'openflux-worker-prf_cas_1-pending',
                    ?, ?, ?
                )
                """,
                (expired_at, expired_at, expired_at),
            )
            c0.commit()
            c0.close()

            # A. 5 concurrent /state lazy expiry checks -> CAS ensures single stop_openflux_worker invocation
            stop_calls = []
            barrier = threading.Barrier(5)

            def mock_stop_ok(srv, cname):
                stop_calls.append((srv, cname))
                return True

            with patch("vpn_shop.openflux_manager.stop_openflux_worker", side_effect=mock_stop_ok):
                results = []
                errors = []

                def worker():
                    conn = sqlite3.connect(db_path, timeout=10.0)
                    conn.row_factory = sqlite3.Row
                    try:
                        barrier.wait(timeout=5.0)
                        won, slot = openflux_manager.cancel_expired_migration_if_due(conn, "prf_cas_1")
                        results.append((won, slot["status"], slot.get("active_server"), slot.get("pending_server")))
                    except Exception as exc:
                        errors.append(exc)
                    finally:
                        conn.close()

                threads = [threading.Thread(target=worker) for _ in range(5)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join(timeout=10.0)

            self.assertEqual(errors, [])
            self.assertEqual(sum(1 for won, *_ in results if won), 1)
            self.assertTrue(all(st == "active" and act == "nl" and pend is None for _, st, act, pend in results))
            self.assertEqual(stop_calls, [("de", "openflux-worker-prf_cas_1-pending")])

            # B. Crash simulation: stop_openflux_worker fails once -> DB still flips to 'active' and outbox keeps item until watchdog retries
            c1 = sqlite3.connect(db_path)
            c1.row_factory = sqlite3.Row
            c1.execute(
                """
                UPDATE openflux_slots
                SET status = 'migrating',
                    pending_server = 'de',
                    pending_doc_name = 'cups_pend_2',
                    pending_doc_url = 'https://interview.cups.online/live-coding/?room=pend_2',
                    pending_container_name = 'openflux-worker-prf_cas_1-pending',
                    pending_started_at = ?
                WHERE profile_public_id = 'prf_cas_1'
                """,
                (expired_at,),
            )
            c1.commit()

            with patch("vpn_shop.openflux_manager.stop_openflux_worker", side_effect=RuntimeError("ssh timeout")):
                won2, slot2 = openflux_manager.cancel_expired_migration_if_due(c1, "prf_cas_1")
            self.assertTrue(won2)
            self.assertEqual(slot2["status"], "active")
            self.assertIsNone(slot2["pending_server"])
            out_rows = c1.execute("SELECT attempts, last_error FROM openflux_cleanup_queue").fetchall()
            self.assertEqual(len(out_rows), 1)
            self.assertEqual(out_rows[0]["attempts"], 1)

            # Now watchdog drains outbox cleanly once SSH recovers
            retry_calls = []
            with patch("vpn_shop.openflux_manager.stop_openflux_worker", side_effect=lambda s, c: retry_calls.append((s, c)) or True):
                openflux_manager.cleanup_expired_migrations(c1)
            self.assertEqual(retry_calls, [("de", "openflux-worker-prf_cas_1-pending")])
            self.assertEqual(c1.execute("SELECT COUNT(*) FROM openflux_cleanup_queue").fetchone()[0], 0)
            c1.close()

    def test_outbox_skips_superseded_live_container_and_bounds_attempts(self):
        import time

        openflux_manager.init_openflux_db(self.conn)
        now = int(time.time())
        self.conn.execute(
            """
            INSERT INTO openflux_slots (
                profile_public_id, slot_label, status,
                active_server, active_doc_name, active_doc_url, active_container_name,
                pending_server, pending_doc_name, pending_doc_url, pending_container_name,
                pending_started_at, created_at, updated_at
            ) VALUES (
                'prf_test_user_2', 'Белые списки (OpenFlux)', 'migrating',
                'nl', 'cups_act_2', 'https://interview.cups.online/live-coding/?room=act_2', 'openflux-worker-prf_test_user_2',
                'de', 'cups_pend_live', 'https://interview.cups.online/live-coding/?room=pend_live', 'openflux-worker-prf_test_user_2-pending',
                ?, ?, ?
            )
            """,
            (now, now, now),
        )
        # 1. Stale queued cleanup for exact same live pending container -> must be deleted WITHOUT calling stop
        self.conn.execute(
            """
            INSERT INTO openflux_cleanup_queue (
                profile_public_id, server_code, container_name, doc_name, created_at, attempts
            ) VALUES ('prf_test_user_2', 'de', 'openflux-worker-prf_test_user_2-pending', 'cups_old', ?, 1)
            """,
            (now - 60,),
        )
        # 2. Exhausted retry row (attempts = 10) -> must NOT trigger stop on unreachable server
        self.conn.execute(
            """
            INSERT INTO openflux_cleanup_queue (
                profile_public_id, server_code, container_name, doc_name, created_at, attempts
            ) VALUES ('prf_test_user_1', 'de', 'openflux-worker-prf_test_user_1-pending', 'cups_dead', ?, 10)
            """,
            (now - 600,),
        )
        self.conn.commit()

        stop_calls = []
        with patch("vpn_shop.openflux_manager.stop_openflux_worker", side_effect=lambda s, c: stop_calls.append((s, c)) or True):
            openflux_manager.process_pending_openflux_cleanups(self.conn)

        self.assertEqual(stop_calls, [])
        # Superseded row deleted, exhausted row preserved at attempts=10
        remaining = self.conn.execute("SELECT profile_public_id, attempts FROM openflux_cleanup_queue").fetchall()
        self.assertEqual([(r["profile_public_id"], r["attempts"]) for r in remaining], [("prf_test_user_1", 10)])

    def test_confirm_vs_cancel_cas_unique_container_legacy_doc_and_whitespace_watchdog(self):
        import time

        openflux_manager.init_openflux_db(self.conn)
        now = int(time.time())
        expired_at = now - (openflux_manager.MIGRATION_TIMEOUT_SECONDS + 30)

        # 1. Start switch uses generation-unique pending container and preserves legacy doc cleanup in outbox
        self.conn.execute(
            """
            INSERT INTO openflux_slots (
                profile_public_id, slot_label, status,
                active_server, active_doc_name, active_doc_url, active_container_name,
                created_at, updated_at
            ) VALUES (
                'prf_test_user_1', 'Белые списки (OpenFlux)', 'active',
                'nl', 'cups_act_race', 'https://interview.cups.online/live-coding/?room=act_race', 'openflux-worker-prf_test_user_1',
                ?, ?
            )
            """,
            (now - 500, now - 500),
        )
        # Existing pending legacy doc cleanup for 'de' from an earlier failure
        self.conn.execute(
            """
            INSERT INTO openflux_cleanup_queue (
                profile_public_id, server_code, container_name, doc_name, created_at, attempts
            ) VALUES ('prf_test_user_1', 'de', 'openflux-worker-prf_test_user_1-pending', 'legacy_old.docx', ?, 1)
            """,
            (now - 100,),
        )
        self.conn.commit()

        with patch("vpn_shop.openflux_manager.create_cups_room", return_value=("11111111-2222-3333-4444-555555555555", "https://interview.cups.online/live-coding/?room=11111111-2222-3333-4444-555555555555")), \
             patch("vpn_shop.openflux_manager.start_openflux_worker", return_value=True):
            sw = openflux_manager.start_server_switch(self.conn, "prf_test_user_1", "de")
        self.assertEqual(sw["status"], "migrating")
        self.assertIn("-pend-", sw["pending_container_name"])

        # Legacy doc outbox entry was NOT deleted by start_server_switch, and draining outbox deletes legacy doc without stopping new worker!
        stopped = []
        deleted_docs = []
        with patch("vpn_shop.openflux_manager.stop_openflux_worker", side_effect=lambda s, c: stopped.append((s, c)) or True), \
             patch("vpn_shop.openflux_manager.rclone_delete_user_doc", side_effect=lambda d: deleted_docs.append(d) or True):
            openflux_manager.process_pending_openflux_cleanups(self.conn)
        self.assertEqual(deleted_docs, ["legacy_old.docx"])
        self.assertNotIn(("de", sw["pending_container_name"]), stopped)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM openflux_cleanup_queue").fetchone()[0], 0)

        # 2. Confirm after cancel returns cancelled slot cleanly without resurrecting stopped pending worker
        with patch("vpn_shop.openflux_manager.stop_openflux_worker", return_value=True):
            openflux_manager.cancel_server_switch(self.conn, "prf_test_user_1")
        post_cancel = openflux_manager.confirm_server_switch(self.conn, "prf_test_user_1", async_cleanup=False)
        self.assertEqual(post_cancel["active_server"], "nl")
        self.assertIsNone(post_cancel["pending_server"])

        # 3. Cancel after confirm does NOT stop newly promoted server
        with patch("vpn_shop.openflux_manager.create_cups_room", return_value=("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "https://interview.cups.online/live-coding/?room=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")), \
             patch("vpn_shop.openflux_manager.start_openflux_worker", return_value=True):
            openflux_manager.start_server_switch(self.conn, "prf_test_user_1", "de")
        with patch("vpn_shop.openflux_manager.stop_openflux_worker", return_value=True), \
             patch("vpn_shop.openflux_manager.rename_openflux_worker", return_value=True):
            confirmed = openflux_manager.confirm_server_switch(self.conn, "prf_test_user_1", async_cleanup=False)
        self.assertEqual(confirmed["active_server"], "de")

        with patch("vpn_shop.openflux_manager.stop_openflux_worker") as mock_stop_after_confirm:
            won_late, _ = openflux_manager.cancel_expired_migration_if_due(self.conn, "prf_test_user_1")
        self.assertFalse(won_late)
        mock_stop_after_confirm.assert_not_called()

        # 4. Watchdog catches whitespace-only malformed migrating rows (Finding #8)
        self.conn.execute(
            """
            INSERT INTO openflux_slots (
                profile_public_id, slot_label, status,
                active_server, active_doc_name, active_doc_url, active_container_name,
                pending_server, pending_doc_name, pending_doc_url, pending_container_name,
                pending_started_at, created_at, updated_at
            ) VALUES (
                'prf_test_user_2', 'Белые списки (OpenFlux)', 'migrating',
                'nl', 'cups_act_ws', 'https://interview.cups.online/live-coding/?room=act_ws', 'openflux-worker-prf_test_user_2',
                '   ', 'cups_ws', '   ', NULL,
                ?, ?, ?
            )
            """,
            (now + 999, expired_at, expired_at),
        )
        self.conn.commit()
        cleaned = openflux_manager.cleanup_expired_migrations(self.conn)
        self.assertEqual(cleaned, 1)
        repaired = openflux_manager.get_or_create_openflux_slot(self.conn, "prf_test_user_2")
        self.assertEqual(repaired["status"], "active")
        self.assertEqual(repaired["active_server"], "nl")


if __name__ == "__main__":
    unittest.main()
