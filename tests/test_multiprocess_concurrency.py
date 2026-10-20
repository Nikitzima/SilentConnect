"""Multi-process concurrent stress test for Store with SQLite WAL and busy_timeout.

Tests real-world inter-process contention using multiprocessing (spawn on Windows, fork on Linux)
with true simultaneous firing via multiprocessing.Event and heavy read-modify-write operations.
"""

from __future__ import annotations

import multiprocessing as mp
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
from typing import Any
import unittest

# Ensure workspace root and vpn-shop are importable
WORKSPACE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WORKSPACE_ROOT / "vpn-shop"))
sys.path.insert(0, str(WORKSPACE_ROOT))

from vpn_shop.store import Store


def _thread_worker(
    db_path: str,
    start_event: Any,
    worker_id: int,
    ops_count: int,
    shared_promo_code: str,
    results_q: Any,
) -> None:
    store = Store(Path(db_path))
    # Wait for the starting gun from main process
    start_event.wait()

    successes = 0
    locked_errors = 0
    other_errors = 0
    rmw_successes = 0

    for i in range(ops_count):
        op = i % 4
        try:
            if op == 0:
                # Concurrent order creation
                store.create_order(
                    kind="direct",
                    status="pending",
                    transport="tcp",
                    duration_days=30,
                    profile_mode="family",
                    family_label=None,
                    base_price_rub=149,
                    final_price_rub=149,
                    promo_id=None,
                    invite_id=None,
                    customer_chat_id=10000 + worker_id,
                    privacy_ack=True,
                    loss_policy_ack=True,
                    terms_version="2026-09",
                    customer_email=f"w{worker_id}_{i}@stress.test",
                )
                successes += 1
            elif op == 1:
                # READ-MODIFY-WRITE CONTENTION: All 12 workers hit the SAME shared promo code simultaneously!
                # Tests BEGIN IMMEDIATE lock acquisition under extreme cross-process contention.
                consumed = store.consume_promo_code(shared_promo_code)
                if consumed:
                    rmw_successes += 1
                successes += 1
            elif op == 2:
                # Concurrent admin audit logging
                store.record_admin_action(
                    action_type="stress_write",
                    target_type="order",
                    target_public_id=f"target_{worker_id}_{i}",
                    actor=f"worker_{worker_id}",
                )
                successes += 1
            else:
                # Concurrent user session upsert
                store.set_session(
                    chat_id=str(30000 + worker_id),
                    scope="public",
                    state=f"menu_{i}",
                    context={"last_op": i, "worker": worker_id},
                )
                successes += 1
        except Exception as exc:
            err_msg = str(exc).lower()
            if "database is locked" in err_msg or "busy" in err_msg:
                locked_errors += 1
            else:
                other_errors += 1

    results_q.put({
        "worker_id": worker_id,
        "successes": successes,
        "rmw_successes": rmw_successes,
        "locked_errors": locked_errors,
        "other_errors": other_errors,
    })


def _process_entrypoint(
    db_path: str,
    start_event: Any,
    proc_idx: int,
    threads_per_proc: int,
    ops_per_thread: int,
    shared_promo_code: str,
    results_q: Any,
) -> None:
    threads = []
    for t_idx in range(threads_per_proc):
        worker_id = proc_idx * threads_per_proc + t_idx
        t = threading.Thread(
            target=_thread_worker,
            args=(db_path, start_event, worker_id, ops_per_thread, shared_promo_code, results_q),
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join()


def run_multiprocess_stress_test(
    num_processes: int = 4,
    threads_per_proc: int = 3,
    ops_per_thread: int = 10,
) -> dict[str, Any]:
    total_workers = num_processes * threads_per_proc
    total_expected_ops = total_workers * ops_per_thread

    # Run on real disk file in a temporary directory (POSIX / Windows filesystem locks active)
    with tempfile.TemporaryDirectory() as tmp_dir:
        test_db = Path(tmp_dir) / "stress_concurrency.db"
        store = Store(test_db)
        store.init()

        # Seed shared promo code for read-modify-write contention test
        shared_code, _ = store.create_promo_code(
            transport="tcp",
            duration_days=30,
            discount_percent=10,
            device_limit=3,
            profile_mode="family",
            max_uses=1000,
        )

        # Cross-platform Event for Windows spawn & Linux fork
        start_event = mp.Event()
        results_q = mp.Queue()

        processes = []
        for p_idx in range(num_processes):
            p = mp.Process(
                target=_process_entrypoint,
                args=(str(test_db), start_event, p_idx, threads_per_proc, ops_per_thread, shared_code, results_q),
            )
            processes.append(p)
            p.start()

        # Small pause to allow all processes and threads to initialize and wait at start_event
        time.sleep(0.5)

        # Fire! All 12 workers begin writing simultaneously
        start_event.set()

        for p in processes:
            p.join(timeout=30)

        total_successes = 0
        total_rmw = 0
        total_locked = 0
        total_other_errs = 0

        while not results_q.empty():
            res = results_q.get()
            total_successes += res["successes"]
            total_rmw += res["rmw_successes"]
            total_locked += res["locked_errors"]
            total_other_errs += res["other_errors"]

        # Check SQLite integrity
        with store._connect() as conn:
            integrity = conn.execute("PRAGMA integrity_check;").fetchone()[0]
            orders_count = conn.execute("SELECT count(*) FROM orders;").fetchone()[0]
            promo_row = conn.execute("SELECT used_count FROM promo_codes WHERE code_hash = ?", (test_db.name,)).fetchone()
            # Check actual used count from DB
            all_promos = conn.execute("SELECT code_preview, used_count FROM promo_codes;").fetchall()
            promo_used = all_promos[0]["used_count"] if all_promos else 0

        result = {
            "processes": num_processes,
            "threads_per_process": threads_per_proc,
            "total_workers": total_workers,
            "expected_ops": total_expected_ops,
            "actual_ops": total_successes,
            "rmw_contention_ops": total_rmw,
            "locked_errors": total_locked,
            "other_errors": total_other_errs,
            "integrity": integrity,
            "orders_created": orders_count,
            "promo_used_count": promo_used,
            "passed": (total_locked == 0 and total_other_errs == 0 and integrity == "ok"),
        }
        return result


class TestMultiprocessConcurrency(unittest.TestCase):
    def test_multiprocess_concurrency_stress(self):
        # 3 processes x 2 threads = 6 concurrent workers with true simultaneous barrier
        res = run_multiprocess_stress_test(num_processes=3, threads_per_proc=2, ops_per_thread=5)
        self.assertEqual(res["locked_errors"], 0)
        self.assertEqual(res["other_errors"], 0)
        self.assertEqual(res["integrity"], "ok")
        self.assertTrue(res["passed"])


if __name__ == "__main__":
    mp.freeze_support()
    unittest.main()

