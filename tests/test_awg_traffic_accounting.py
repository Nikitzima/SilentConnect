from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

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

    def test_11_cluster_sync_subsequent_node_receives_disable_peers(self) -> None:
        """Verify that when a profile's quota is exceeded, subsequent sync requests from other nodes
        still receive all peer keys in disable_peers even if the slots were already marked disabled in DB.
        """
        pk1 = "sync_node_peer_1_key123456789012345678901="
        pk2 = "sync_node_peer_2_key123456789012345678902="
        self.store.create_awg_slot(
            profile_public_id=self.p1_id,
            slot_index=1,
            slot_label="Slot NL",
            public_key=pk1,
            private_key_enc="enc_pk1",
            client_ip="10.8.1.71",
            server_code="nl",
        )
        self.store.create_awg_slot(
            profile_public_id=self.p1_id,
            slot_index=2,
            slot_label="Slot PL",
            public_key=pk2,
            private_key_enc="enc_pk2",
            client_ip="10.8.3.71",
            server_code="pl",
        )

        # Set quota to 1000 bytes
        self.store.set_awg_profile_quota(self.p1_id, 1000)

        # First sync from Node NL reports 1500 bytes -> exceeds quota!
        r1 = process_cluster_traffic_sync(
            self.store,
            {
                "node_id": "nl-master",
                "deltas": [{"public_key": pk1, "delta_rx_bytes": 1500, "delta_tx_bytes": 0}],
                "collected_at": 1000,
            },
        )
        self.assertIn(pk1, r1["disable_peers"])
        self.assertIn(pk2, r1["disable_peers"])

        # Second sync arrives 30 seconds later from Node PL reporting 50 bytes on pk2.
        # Even though slots were already set to enabled=0 in DB by first sync,
        # Node PL MUST still receive both keys in disable_peers to purge them from its kernel!
        r2 = process_cluster_traffic_sync(
            self.store,
            {
                "node_id": "pl-node2",
                "deltas": [{"public_key": pk2, "delta_rx_bytes": 50, "delta_tx_bytes": 0}],
                "collected_at": 1030,
            },
        )
        self.assertIn(pk1, r2["disable_peers"])
        self.assertIn(pk2, r2["disable_peers"])

    def test_12_collector_baseline_initialization(self) -> None:
        """Verify initialize_baseline records pre-existing kernel counters without emitting traffic deltas."""
        mock_output = "peer_cold_start_1234567890123456789012345=\t50000000\t50000000\n"

        collector = AwgTrafficCollector(
            interface="awg0",
            node_id="cold-node",
            state_file=self.state_file,
            command_runner=lambda cmd: mock_output,
        )

        # Cold start initialize baseline
        collector.initialize_baseline()

        # Check that tracker recorded the baseline
        pk = "peer_cold_start_1234567890123456789012345="
        self.assertIn(pk, collector.tracker.previous_counters)
        self.assertEqual(collector.tracker.previous_counters[pk][0], 50000000)
        self.assertEqual(collector.tracker.previous_counters[pk][1], 50000000)

        # Next normal collection with 100 bytes additional traffic should yield only 100 bytes delta
        mock_output_next = "peer_cold_start_1234567890123456789012345=\t50000050\t50000050\n"
        collector.command_runner = lambda cmd: mock_output_next
        deltas = collector.collect_node_deltas()

        self.assertEqual(len(deltas), 1)
        self.assertEqual(deltas[0].delta_rx_bytes, 50)
        self.assertEqual(deltas[0].delta_tx_bytes, 50)
        self.assertEqual(deltas[0].total_bytes, 100)


if __name__ == "__main__":
    unittest.main()
