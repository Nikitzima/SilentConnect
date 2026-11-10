from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

# Add vpn-shop to sys.path
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "vpn-shop"))

from vpn_shop.awg_traffic import (
    AwgTrafficCollector,
    CounterStateTracker,
    TrafficDelta,
    enforce_quota_soft_disable,
    evaluate_profile_quota,
    is_valid_wg_key,
    parse_awg_transfer,
    process_cluster_traffic_sync,
    restore_quota_peers,
)
from vpn_shop.store import Store, default_awg_quota_bytes_for_devices


class TestAwgTrafficAccounting(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_vpn_shop.db"
        self.state_file = Path(self.temp_dir.name) / "awg_counters.json"
        self.store = Store(self.db_path)
        self.store.init()

        # Create test profiles
        # Profile 1: 3 devices (250 GB quota)
        self.profile1 = self.store.create_profile(
            xui_inbound_id=1,
            transport="tcp",
            profile_mode="personal",
            family_label=None,
            xui_email="alice@silentconnect.test",
            xui_client_id="uuid-alice-1",
            expires_at=1800000000,
            awg_quota_bytes=default_awg_quota_bytes_for_devices(3),
        )
        self.p1_id = self.profile1["public_id"]

        # Profile 2: 6 devices (500 GB quota)
        self.profile2 = self.store.create_profile(
            xui_inbound_id=1,
            transport="tcp",
            profile_mode="family",
            family_label="bob-family",
            xui_email="bob@silentconnect.test",
            xui_client_id="uuid-bob-1",
            expires_at=1800000000,
            awg_quota_bytes=default_awg_quota_bytes_for_devices(6),
        )
        self.p2_id = self.profile2["public_id"]

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_01_wireguard_key_validation(self) -> None:
        """Verify standard 32-byte base64 WireGuard key validator."""
        # 32 bytes base64 encoded -> 44 chars
        valid_key = "aB3/dE5+gH7=jK9/mN1+pQ3=rS5/tU7+vW9=xY1/zA=="[:44]
        # Generate genuine 32-byte base64
        import base64
        real_key = base64.b64encode(b"A" * 32).decode("ascii")
        self.assertTrue(is_valid_wg_key(real_key))

        self.assertFalse(is_valid_wg_key(""))
        self.assertFalse(is_valid_wg_key("short_key"))
        self.assertFalse(is_valid_wg_key("a" * 44))  # missing valid base64 / padding
        self.assertFalse(is_valid_wg_key(12345))  # type check

    def test_02_parse_awg_transfer_output(self) -> None:
        """Verify parsing kernel transfer output with tabs, spaces, and edge cases."""
        sample_output = """
        # Header or comment
        uR1test1pubkey1234567890123456789012345678=\t1048576\t2097152
        K8xtest2pubkey1234567890123456789012345678=   4096   8192
        
        invalid_line_without_numbers
        another_key   not_an_int   100
        z99test3pubkey1234567890123456789012345678= 0 0
        """
        counters = parse_awg_transfer(sample_output)
        self.assertEqual(len(counters), 3)
        self.assertEqual(
            counters["uR1test1pubkey1234567890123456789012345678="],
            (1048576, 2097152),
        )
        self.assertEqual(
            counters["K8xtest2pubkey1234567890123456789012345678="],
            (4096, 8192),
        )
        self.assertEqual(
            counters["z99test3pubkey1234567890123456789012345678="],
            (0, 0),
        )

        # Empty output
        self.assertEqual(parse_awg_transfer(""), {})

    def test_03_monotonic_deltas_and_kernel_reboot(self) -> None:
        """Verify delta monotonicity, normal increments, and interface reboot recovery."""
        tracker = CounterStateTracker(state_file=self.state_file)
        pubkey = "peerA_pubkey_1234567890123456789012345678="

        # Tick 1: Baseline (first measurement) -> delta equals current
        deltas1 = tracker.calculate_monotonic_deltas(
            {pubkey: (1000, 2000)},
            node_id="nl-master",
            collected_at=100,
        )
        self.assertEqual(len(deltas1), 1)
        self.assertEqual(deltas1[0].delta_rx_bytes, 1000)
        self.assertEqual(deltas1[0].delta_tx_bytes, 2000)
        self.assertEqual(deltas1[0].total_bytes, 3000)

        # Tick 2: Normal increment (rx: 1000->1500, tx: 2000->3000)
        deltas2 = tracker.calculate_monotonic_deltas(
            {pubkey: (1500, 3000)},
            node_id="nl-master",
            collected_at=160,
        )
        self.assertEqual(len(deltas2), 1)
        self.assertEqual(deltas2[0].delta_rx_bytes, 500)
        self.assertEqual(deltas2[0].delta_tx_bytes, 1000)

        # Tick 3: Idle (counters unchanged) -> zero deltas filtered out
        deltas3 = tracker.calculate_monotonic_deltas(
            {pubkey: (1500, 3000)},
            node_id="nl-master",
            collected_at=220,
        )
        self.assertEqual(len(deltas3), 0)

        # Tick 4: Kernel reboot or interface recreate! Counters reset to (200, 100)
        # MUST NOT produce negative deltas! Must treat as reset and yield (200, 100).
        deltas4 = tracker.calculate_monotonic_deltas(
            {pubkey: (200, 100)},
            node_id="nl-master",
            collected_at=280,
        )
        self.assertEqual(len(deltas4), 1)
        self.assertEqual(deltas4[0].delta_rx_bytes, 200)
        self.assertEqual(deltas4[0].delta_tx_bytes, 100)
        self.assertGreaterEqual(deltas4[0].delta_rx_bytes, 0)
        self.assertGreaterEqual(deltas4[0].delta_tx_bytes, 0)

    def test_04_counter_state_persistence(self) -> None:
        """Verify tracker persists state to disk and loads back accurately."""
        tracker1 = CounterStateTracker(state_file=self.state_file)
        pubkey = "peer_persist_test_123456789012345678901234="
        tracker1.calculate_monotonic_deltas(
            {pubkey: (5000, 6000)},
            node_id="nl-master",
        )

        # Create a fresh tracker instance pointing to same file
        tracker2 = CounterStateTracker(state_file=self.state_file)
        self.assertIn(pubkey, tracker2.previous_counters)
        prev_rx, prev_tx, _ = tracker2.previous_counters[pubkey]
        self.assertEqual(prev_rx, 5000)
        self.assertEqual(prev_tx, 6000)

        # Next delta should calculate off the loaded state
        deltas = tracker2.calculate_monotonic_deltas(
            {pubkey: (5500, 6200)},
            node_id="nl-master",
        )
        self.assertEqual(deltas[0].delta_rx_bytes, 500)
        self.assertEqual(deltas[0].delta_tx_bytes, 200)

    def test_05_awg_collector_mock(self) -> None:
        """Verify AwgTrafficCollector executing mock command runner."""
        mock_output = "peer_mock_1234567890123456789012345678=\t1000\t2000\n"

        def mock_runner(cmd: str) -> str:
            self.assertIn("awg show awg0 transfer", cmd)
            return mock_output

        collector = AwgTrafficCollector(
            interface="awg0",
            node_id="test-node",
            state_file=self.state_file,
            command_runner=mock_runner,
        )
        deltas = collector.collect_node_deltas()
        self.assertEqual(len(deltas), 1)
        self.assertEqual(deltas[0].node_id, "test-node")
        self.assertEqual(deltas[0].delta_rx_bytes, 1000)

    def test_06_quota_evaluation_and_tiers(self) -> None:
        """Verify quota evaluator respects 250 GB and 500 GB tiers."""
        eval1 = evaluate_profile_quota(self.p1_id, self.store)
        self.assertEqual(eval1.awg_quota_bytes, 250 * 1024**3)
        self.assertEqual(eval1.awg_used_bytes, 0)
        self.assertFalse(eval1.is_exceeded)

        eval2 = evaluate_profile_quota(self.p2_id, self.store)
        self.assertEqual(eval2.awg_quota_bytes, 500 * 1024**3)
        self.assertEqual(eval2.awg_used_bytes, 0)
        self.assertFalse(eval2.is_exceeded)

    def test_07_soft_disable_enforcement_keeps_vless_alive(self) -> None:
        """Verify soft-disable removes AmneziaWG peers but NEVER touches VLESS/XHTTP."""
        # Create 2 slots for profile 1
        slot1 = self.store.create_awg_slot(
            profile_public_id=self.p1_id,
            slot_index=1,
            slot_label="Телефон",
            public_key="p1_slot1_key12345678901234567890123456=",
            private_key_enc="enc1",
            client_ip="10.8.1.10",
        )
        slot2 = self.store.create_awg_slot(
            profile_public_id=self.p1_id,
            slot_index=2,
            slot_label="Ноутбук",
            public_key="p1_slot2_key12345678901234567890123456=",
            private_key_enc="enc2",
            client_ip="10.8.1.11",
        )

        # Set quota to 10 MB for testing
        quota_limit = 10 * 1024 * 1024
        self.store.set_awg_profile_quota(self.p1_id, quota_limit)

        # Track kernel calls
        kernel_removed: list[tuple[str, str]] = []

        def mock_kernel_remover(srv: str, pubkey: str) -> bool:
            kernel_removed.append((srv, pubkey))
            return True

        # Pre-check: before exceeding quota
        res_pre = enforce_quota_soft_disable(
            self.p1_id,
            self.store,
            kernel_peer_remover=mock_kernel_remover,
        )
        self.assertEqual(res_pre["status"], "not_exceeded")
        self.assertEqual(len(kernel_removed), 0)

        # Consume quota past limit
        self.store.record_awg_traffic_delta(
            node_id="nl-master",
            profile_public_id=self.p1_id,
            slot_id=slot1["id"],
            delta_rx_bytes=6 * 1024 * 1024,
            delta_tx_bytes=5 * 1024 * 1024,
        )

        # Enforcement execution
        res_post = enforce_quota_soft_disable(
            self.p1_id,
            self.store,
            kernel_peer_remover=mock_kernel_remover,
        )
        self.assertEqual(res_post["status"], "soft_disabled")
        self.assertEqual(res_post["disabled_count"], 2)
        self.assertEqual(len(kernel_removed), 2)

        # Verify slots in DB are disabled
        slots_after = self.store.list_awg_slots(self.p1_id)
        for s in slots_after:
            self.assertEqual(s["enabled"], 0)

        # CRITICAL VERIFICATION: VLESS Profile in store remains ACTIVE and untouched!
        profile_after = self.store.get_profile(self.p1_id)
        self.assertEqual(profile_after["status"], "active")
        self.assertEqual(profile_after["xui_client_id"], "uuid-alice-1")
        self.assertEqual(profile_after["xui_email"], "alice@silentconnect.test")
        self.assertEqual(profile_after["transport"], "tcp")

    def test_08_quota_restore_after_renewal(self) -> None:
        """Verify restore_quota_peers enables slots after renewal / quota reset."""
        slot = self.store.create_awg_slot(
            profile_public_id=self.p1_id,
            slot_index=1,
            slot_label="Девайс",
            public_key="p1_restore_key12345678901234567890123=",
            private_key_enc="enc_rest",
            client_ip="10.8.1.15",
            enabled=False,
        )
        self.assertEqual(slot["enabled"], 0)

        kernel_restored: list[dict[str, Any]] = []

        def mock_kernel_adder(s: dict[str, Any]) -> bool:
            kernel_restored.append(s)
            return True

        restore_res = restore_quota_peers(
            self.p1_id,
            self.store,
            kernel_peer_adder=mock_kernel_adder,
        )
        self.assertEqual(restore_res["status"], "restored")
        self.assertEqual(restore_res["restored_count"], 1)
        self.assertEqual(len(kernel_restored), 1)

        slot_after = self.store.get_awg_slot(slot["id"])
        self.assertEqual(slot_after["enabled"], 1)

    def test_09_distributed_cluster_traffic_sync(self) -> None:
        """Verify multi-node sync (NL + PL), aggregation, and automatic quota trigger."""
        # Create slots for alice
        pk_alice_phone = "alice_phone_key_12345678901234567890123="
        pk_alice_laptop = "alice_laptop_key_1234567890123456789012="
        self.store.create_awg_slot(
            profile_public_id=self.p1_id,
            slot_index=1,
            slot_label="Alice Phone",
            public_key=pk_alice_phone,
            private_key_enc="enc_p",
            client_ip="10.8.1.50",
        )
        self.store.create_awg_slot(
            profile_public_id=self.p1_id,
            slot_index=2,
            slot_label="Alice Laptop",
            public_key=pk_alice_laptop,
            private_key_enc="enc_l",
            client_ip="10.8.1.51",
        )

        # Set quota = 100 MB
        quota_100mb = 100 * 1024 * 1024
        self.store.set_awg_profile_quota(self.p1_id, quota_100mb)

        # Sync from NL Master: 40 MB from phone
        payload_nl = {
            "node_id": "nl-master",
            "deltas": [
                {
                    "public_key": pk_alice_phone,
                    "delta_rx_bytes": 20 * 1024 * 1024,
                    "delta_tx_bytes": 20 * 1024 * 1024,
                }
            ],
            "collected_at": 1000,
        }
        res_nl = process_cluster_traffic_sync(self.store, payload_nl)
        self.assertEqual(res_nl["recorded_count"], 1)
        self.assertEqual(res_nl["disable_peers"], [])  # not exceeded (40 MB < 100 MB)

        # Sync from PL Node: 70 MB from laptop
        # Total will become 40 + 70 = 110 MB > 100 MB -> triggers cutoff!
        payload_pl = {
            "node_id": "pl-node2",
            "deltas": [
                {
                    "public_key": pk_alice_laptop,
                    "delta_rx_bytes": 35 * 1024 * 1024,
                    "delta_tx_bytes": 35 * 1024 * 1024,
                },
                {
                    "public_key": "unknown_peer_key_not_in_system===",
                    "delta_rx_bytes": 1000,
                    "delta_tx_bytes": 1000,
                },
            ],
            "collected_at": 1060,
        }
        res_pl = process_cluster_traffic_sync(self.store, payload_pl)
        self.assertEqual(res_pl["recorded_count"], 1)  # unknown peer safely skipped
        self.assertIn(self.p1_id, res_pl["affected_profiles"])

        # disable_peers must contain both active keys of Alice
        self.assertIn(pk_alice_phone, res_pl["disable_peers"])
        self.assertIn(pk_alice_laptop, res_pl["disable_peers"])

        # Profile quota in store must reflect total multi-node aggregation
        quota_final = self.store.get_awg_profile_quota(self.p1_id)
        self.assertEqual(quota_final["awg_used_bytes"], 110 * 1024 * 1024)
        self.assertTrue(quota_final["is_exceeded"])

    def test_10_edge_cases_and_corrupt_payloads(self) -> None:
        """Verify handling of invalid payloads, unmetered profiles, and corrupted state files."""
        # Invalid payload types
        with self.assertRaises(ValueError):
            process_cluster_traffic_sync(self.store, "not a dict")  # type: ignore

        with self.assertRaises(ValueError):
            process_cluster_traffic_sync(self.store, {"deltas": "not a list"})

        # Empty payload
        res_empty = process_cluster_traffic_sync(self.store, {"deltas": []})
        self.assertEqual(res_empty["recorded_count"], 0)
        self.assertEqual(res_empty["disable_peers"], [])

        # Non-existent profile evaluation
        ghost_eval = evaluate_profile_quota("non_existent_profile_id", self.store)
        self.assertFalse(ghost_eval.is_exceeded)
        self.assertEqual(ghost_eval.awg_quota_bytes, 0)

        # Unmetered profile (awg_quota_bytes = 0)
        unmetered = self.store.create_profile(
            xui_inbound_id=1,
            transport="tcp",
            profile_mode="personal",
            family_label=None,
            xui_email="unmetered@silentconnect.test",
            xui_client_id="uuid-unmetered-1",
            expires_at=1800000000,
            awg_quota_bytes=0,
        )
        self.store.record_awg_traffic_delta(
            node_id="nl-master",
            profile_public_id=unmetered["public_id"],
            delta_rx_bytes=100 * 1024**3,  # 100 GB
            delta_tx_bytes=100 * 1024**3,
        )
        unmetered_eval = evaluate_profile_quota(unmetered["public_id"], self.store)
        self.assertFalse(unmetered_eval.is_exceeded)
        self.assertEqual(unmetered_eval.remaining_bytes, 0)

        # Corrupted state file
        bad_state = Path(self.temp_dir.name) / "corrupted_state.json"
        with open(bad_state, "w", encoding="utf-8") as f:
            f.write("{corrupted json!!")
        tracker = CounterStateTracker(state_file=bad_state)
        # Must load cleanly without raising exception
        self.assertEqual(tracker.previous_counters, {})

    def test_11_auto_30day_cycle_rollover_and_anomaly_guard(self) -> None:
        """Verify 30-day cycle auto-resets awg_used_bytes even on perpetual/100-year profiles
        and filters out >10GB single-tick counter dump anomalies."""
        now_sim = 1793383000  # 2026-10-30
        created_sim = 1777251033  # 2026-04-27 (6 cycles of 30d passed -> cycle 6 started at 1792803033)
        perpetual_exp = 4933443033  # Year 2126

        prof = self.store.create_profile(
            xui_inbound_id=1,
            transport="tcp",
            profile_mode="family",
            family_label="admin",
            xui_email="admin-cycle@silentconnect.test",
            xui_client_id="uuid-admin-cycle",
            expires_at=perpetual_exp,
            awg_quota_bytes=default_awg_quota_bytes_for_devices(6),
            awg_reset_at=perpetual_exp,
        )
        pid = prof["public_id"]

        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE profiles SET created_at = ?, awg_used_bytes = ? WHERE public_id = ?",
                (created_sim, 316412566638, pid),
            )
            # Old traffic from cycle 5 (before 1792803033)
            conn.execute(
                """
                INSERT INTO awg_traffic_ledger(node_id, profile_public_id, delta_rx_bytes, delta_tx_bytes, collected_at)
                VALUES ('nl', ?, 5000000000, 5000000000, ?)
                """,
                (pid, 1792000000),
            )
            # Current cycle traffic (after 1792803033): 1.5 GB legitimate
            conn.execute(
                """
                INSERT INTO awg_traffic_ledger(node_id, profile_public_id, delta_rx_bytes, delta_tx_bytes, collected_at)
                VALUES ('nl', ?, 500000000, 1000000000, ?)
                """,
                (pid, 1793000000),
            )

        updated_q = self.store.ensure_awg_cycle_up_to_date(pid, now_override=now_sim)
        self.assertIsNotNone(updated_q)
        # Should be recalculated to only current cycle legitimate traffic (1.5 GB)
        self.assertEqual(updated_q["awg_used_bytes"], 1500000000)
        # And awg_reset_at should be aligned to the end of cycle 6 (1792803033 + 2592000 = 1795395033)
        self.assertEqual(updated_q["awg_reset_at"], 1795395033)

        # Also verify CounterStateTracker baselines unseen peer with >10GB cumulative kernel counter
        fresh_state = Path(self.temp_dir.name) / "fresh_counters.json"
        tracker = CounterStateTracker(state_file=fresh_state)
        huge_pubkey = "huge_peer_pubkey_12345678901234567890123456="
        deltas = tracker.calculate_monotonic_deltas(
            {huge_pubkey: (20 * 1024**3, 32 * 1024**3)},
            node_id="nl",
        )
        self.assertEqual(deltas, [])
        # Next normal increment (10 MB) is tracked accurately
        deltas_next = tracker.calculate_monotonic_deltas(
            {huge_pubkey: (20 * 1024**3 + 5 * 1024**2, 32 * 1024**3 + 5 * 1024**2)},
            node_id="nl",
        )
        self.assertEqual(len(deltas_next), 1)
        self.assertEqual(deltas_next[0].total_bytes, 10 * 1024**2)

    def test_12_first_tick_small_traffic_preserved_across_restart(self):
        """Unseen peer < min_flush_bytes must keep baseline (0,0) on disk so first traffic is never lost."""
        state_file = Path(self.temp_dir.name) / "first_tick_state.json"
        tracker = CounterStateTracker(state_file=state_file)
        pubkey = "first_tick_pubkey_12345678901234567890="

        d1 = tracker.calculate_monotonic_deltas(
            {pubkey: (400, 600)},
            min_flush_bytes=10 * 1024 * 1024,
            max_flush_interval_sec=1800,
            collected_at=1000,
        )
        self.assertEqual(d1, [])
        self.assertEqual(tracker.previous_counters[pubkey], (0, 0, 1000))

        # Reload tracker from disk (simulating process restart) and advance past 1800s
        reloaded = CounterStateTracker(state_file=state_file)
        d2 = reloaded.calculate_monotonic_deltas(
            {pubkey: (500, 700)},
            min_flush_bytes=10 * 1024 * 1024,
            max_flush_interval_sec=1800,
            collected_at=2860,
        )
        self.assertEqual(len(d2), 1)
        self.assertEqual(d2[0].delta_rx_bytes, 500)
        self.assertEqual(d2[0].delta_tx_bytes, 700)

    def test_13_single_counter_reset_and_zero_delta_reset_preserved_across_restart(self):
        """Single-side counter reset and (0,0) reset while buffering must not double-count or lose data."""
        state_file = Path(self.temp_dir.name) / "reset_state.json"
        tracker = CounterStateTracker(state_file=state_file)
        pk_partial = "partial_reset_pubkey_123456789012345="
        pk_zero = "zero_reset_pubkey_123456789012345678="

        tracker.calculate_monotonic_deltas(
            {pk_partial: (1000, 500), pk_zero: (1000, 0)},
            baseline_only=True,
            collected_at=1000,
        )

        # Tick 2: pk_partial has RX reset (200 < 1000) while TX stays 500; pk_zero drops cleanly to (0, 0)
        held = tracker.calculate_monotonic_deltas(
            {pk_partial: (200, 500), pk_zero: (0, 0)},
            min_flush_bytes=10 * 1024 * 1024,
            max_flush_interval_sec=1800,
            collected_at=1060,
        )
        self.assertEqual(held, [])
        self.assertEqual(tracker.previous_counters[pk_partial], (0, 500, 1000))
        self.assertEqual(tracker.previous_counters[pk_zero], (0, 0, 1000))

        # Tick 3 after daemon reload and 31 minutes: verify exact deltas without TX double-count or RX loss
        reloaded = CounterStateTracker(state_file=state_file)
        flushed = reloaded.calculate_monotonic_deltas(
            {pk_partial: (300, 600), pk_zero: (1200, 0)},
            min_flush_bytes=10 * 1024 * 1024,
            max_flush_interval_sec=1800,
            collected_at=2900,
        )
        by_pk = {d.public_key: d for d in flushed}
        self.assertEqual(by_pk[pk_partial].delta_rx_bytes, 300)
        self.assertEqual(by_pk[pk_partial].delta_tx_bytes, 100)
        self.assertEqual(by_pk[pk_zero].delta_rx_bytes, 1200)
        self.assertEqual(by_pk[pk_zero].delta_tx_bytes, 0)


if __name__ == "__main__":
    unittest.main()
