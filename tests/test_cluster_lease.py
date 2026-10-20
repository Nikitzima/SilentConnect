from __future__ import annotations

import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
VPN_SHOP_DIR = REPO_ROOT / "vpn-shop"
if str(VPN_SHOP_DIR) not in sys.path:
    sys.path.insert(0, str(VPN_SHOP_DIR))

from vpn_shop.store import Store


class TestClusterLease(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="test_lease_"))
        self.db_path = self.tmp / "test_vpn.db"
        self.store = Store(self.db_path)
        self.store.init()

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_lease_acquisition_and_concurrency(self) -> None:
        # 1. Node NL acquires lease
        acquired = self.store.try_acquire_cluster_lease("periodic_tasks", "nl", ttl_seconds=2)
        self.assertTrue(acquired)

        # 2. Node PL tries to acquire same lease while active -> must be rejected
        acquired_pl = self.store.try_acquire_cluster_lease("periodic_tasks", "pl", ttl_seconds=2)
        self.assertFalse(acquired_pl)

        # 3. Node NL can refresh its own lease
        renewed_nl = self.store.try_acquire_cluster_lease("periodic_tasks", "nl", ttl_seconds=2)
        self.assertTrue(renewed_nl)

        # 4. Wait for lease to expire
        time.sleep(2.1)

        # 5. Node PL now successfully acquires lease
        acquired_pl_after_exp = self.store.try_acquire_cluster_lease("periodic_tasks", "pl", ttl_seconds=2)
        self.assertTrue(acquired_pl_after_exp)


if __name__ == "__main__":
    unittest.main()
