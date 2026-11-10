import os
import sys
import time
import unittest
from pathlib import Path
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "vpn-shop"))

from vpn_shop.awg_traffic import CounterStateTracker, AwgTrafficCollector
from vpn_shop.store import Store
from vpn_shop.bot import TEST_PROFILE_CLEANUP_INTERVAL


class TestTursoSyncOptimizations(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.db_path = Path(self.td.name) / "test.db"
        self.state_file = Path(self.td.name) / "counters.json"
        self.store = Store(self.db_path)
        self.store.init()

    def tearDown(self):
        self.td.cleanup()

    def test_01_awg_keepalive_buffering_under_10mb(self):
        """Keepalive packets (< 10 MB and < 1800s) must NOT generate deltas or writes."""
        tracker = CounterStateTracker(state_file=self.state_file)
        pubkey = "test_peer_pubkey_1234567890123456789012="
        now = 1000

        # Baseline
        deltas = tracker.calculate_monotonic_deltas(
            {pubkey: (100, 200)},
            min_flush_bytes=10 * 1024 * 1024,
            max_flush_interval_sec=1800,
            collected_at=now,
        )
        self.assertEqual(len(deltas), 0)

        # Small keepalive after 60s (+300 bytes total)
        deltas = tracker.calculate_monotonic_deltas(
            {pubkey: (250, 350)},
            min_flush_bytes=10 * 1024 * 1024,
            max_flush_interval_sec=1800,
            collected_at=now + 60,
        )
        self.assertEqual(len(deltas), 0, "Keepalive packet must be buffered, not flushed")

        # Heavy traffic (+15 MB) -> should flush
        deltas = tracker.calculate_monotonic_deltas(
            {pubkey: (250 + 8 * 1024 * 1024, 350 + 7 * 1024 * 1024)},
            min_flush_bytes=10 * 1024 * 1024,
            max_flush_interval_sec=1800,
            collected_at=now + 120,
        )
        self.assertEqual(len(deltas), 1, "Traffic >= 10 MB must flush")
        self.assertGreaterEqual(deltas[0].total_bytes, 15 * 1024 * 1024)

    def test_02_awg_keepalive_flush_after_30_minutes(self):
        """Even small traffic must flush once 30 minutes (1800s) have passed."""
        tracker = CounterStateTracker(state_file=self.state_file)
        pubkey = "test_peer_pubkey_30min_1234567890123456="
        now = 1000

        # Baseline
        tracker.calculate_monotonic_deltas(
            {pubkey: (100, 200)},
            baseline_only=True,
            min_flush_bytes=10 * 1024 * 1024,
            max_flush_interval_sec=1800,
            collected_at=now,
        )

        # 31 minutes later with just +500 bytes keepalive -> must flush
        deltas = tracker.calculate_monotonic_deltas(
            {pubkey: (350, 450)},
            min_flush_bytes=10 * 1024 * 1024,
            max_flush_interval_sec=1800,
            collected_at=now + 1860,
        )
        self.assertEqual(len(deltas), 1, "Must flush after 30 min interval even if < 10 MB")
        self.assertEqual(deltas[0].delta_rx_bytes, 250)
        self.assertEqual(deltas[0].delta_tx_bytes, 250)

    def test_03_cluster_lease_ro_check_blocks_write_transaction(self):
        """Standby node must not open a write transaction if lease is held and unexpired."""
        # Node A acquires lease
        ok = self.store.try_acquire_cluster_lease("test_lease", "nodeA", ttl_seconds=600)
        self.assertTrue(ok)

        # Node B attempts to acquire -> should return False via RO check
        ok2 = self.store.try_acquire_cluster_lease("test_lease", "nodeB", ttl_seconds=600)
        self.assertFalse(ok2)

    def test_04_bot_cleanup_interval_is_600s(self):
        """TEST_PROFILE_CLEANUP_INTERVAL must be 600 seconds (10 minutes)."""
        self.assertEqual(TEST_PROFILE_CLEANUP_INTERVAL, 600)


if __name__ == "__main__":
    unittest.main()
