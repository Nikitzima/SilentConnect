"""Regression tests for the v2 hardening (payments FSM, concurrency, merge, security helpers).

Run:  SC_ALLOW_INSECURE_DEV=1 python -m unittest tests.test_v2_hardening -v
"""
from __future__ import annotations

import concurrent.futures
import importlib
import os
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
os.environ.setdefault("SERVER_PEPPER", "unit-test-pepper-0123456789abcdefghijklmnop")
os.environ.setdefault("HYSTERIA_SALAMANDER_PASSWORD", "test-salamander-pwd-123")
os.environ.setdefault("HYSTERIA_AUTH_PASSWORD", "test-auth-pwd-123")
os.environ.setdefault("SECRET_SEGMENT", "test-secret-sub")
sys.path.insert(0, str(ROOT / "vpn-shop"))
sys.path.insert(0, str(ROOT / "scripts"))

from vpn_shop import security  # noqa: E402
from vpn_shop.payments import ConfirmationRequest, ManualPaymentProcessor, PaymentConfirmationError  # noqa: E402
from vpn_shop.store import OrderStateError, Store  # noqa: E402

failback_merge = importlib.import_module("failback_merge")


def make_store() -> tuple[Store, Path]:
    tmp = Path(tempfile.mkdtemp())
    store = Store(tmp / "vpn_shop.db")
    store.init()
    return store, tmp


def make_order(store: Store, *, price: int = 199, promo_id=None, kind="purchase", meta=None) -> dict:
    return store.create_order(
        kind=kind,
        status="waiting_payment",
        transport="tcp",
        duration_days=30,
        profile_mode="single",
        family_label=None,
        base_price_rub=price,
        final_price_rub=price,
        promo_id=promo_id,
        invite_id=None,
        customer_chat_id=None,
        privacy_ack=True,
        loss_policy_ack=True,
        terms_version="v1",
        meta=meta or {},
    )


class FakeProvisioner:
    def __init__(self, store: Store, *, fail: bool = False, delay: float = 0.0):
        self.store = store
        self.fail = fail
        self.delay = delay
        self.calls = 0
        self.lock = threading.Lock()

    def create_profile_for_order(self, order):
        with self.lock:
            self.calls += 1
        if self.delay:
            time.sleep(self.delay)
        if self.fail:
            raise RuntimeError("x-ui unreachable")
        profile = self.store.create_profile(
            xui_inbound_id=1,
            transport="tcp",
            profile_mode="single",
            family_label=None,
            xui_email=f"u-{order['public_id']}",
            xui_client_id="cid",
            expires_at=security.days_from_now(30),
        )
        return {"profile": profile, "subscription_url": "https://sub/x", "sub_id": "abc", "expires_at": profile["expires_at"]}

    def renew_profile(self, profile_public_id, duration_days, device_limit=None, *, target_expires_at=None):
        with self.lock:
            self.calls += 1
        profile = self.store.get_profile(profile_public_id)
        if target_expires_at:
            new_exp = int(target_expires_at)
        else:
            new_exp = max(security.now_ts(), int(profile["expires_at"])) + duration_days * 86400
        updated = self.store.extend_profile(profile_public_id, new_exp)
        return {"profile": updated, "sub_id": "abc", "expires_at": new_exp, "subscription_url": "https://sub/x"}


def processor(store: Store, prov: FakeProvisioner) -> ManualPaymentProcessor:
    return ManualPaymentProcessor(store, prov, subscription_recover=lambda o: {"subscription_url": "https://sub/x"})


class OrderFsmTests(unittest.TestCase):
    def test_terminal_states_are_sticky(self):
        store, _ = make_store()
        order = make_order(store)
        store.transition_order(order["public_id"], "cancelled", actor="t")
        with self.assertRaises(OrderStateError):
            store.transition_order(order["public_id"], "provisioning", actor="t")
        with self.assertRaises(OrderStateError):
            store.update_order_status(order["public_id"], "delivered")
        log = store.list_order_state_log(order["public_id"])
        self.assertEqual([e["to_status"] for e in log], ["cancelled"])

    def test_concurrent_confirm_and_cancel_exactly_one_wins(self):
        store, _ = make_store()
        order = make_order(store)
        results = []

        def confirm():
            try:
                store.transition_order(order["public_id"], "provisioning", actor="a")
                results.append("confirm")
            except OrderStateError:
                results.append("confirm-lost")

        def cancel():
            try:
                store.transition_order(order["public_id"], "cancelled", actor="b")
                results.append("cancel")
            except OrderStateError:
                results.append("cancel-lost")

        for _ in range(10):
            results.clear()
            o = make_order(store)
            order = o
            t1, t2 = threading.Thread(target=confirm), threading.Thread(target=cancel)
            t1.start(); t2.start(); t1.join(); t2.join()
            self.assertEqual(len([r for r in results if not r.endswith("lost")]), 1)


class ManualPaymentTests(unittest.TestCase):
    def test_double_confirm_provisions_once(self):
        store, _ = make_store()
        prov = FakeProvisioner(store, delay=0.05)
        proc = processor(store, prov)
        order = make_order(store)
        reqs = [ConfirmationRequest(order["public_id"], f"admin{i}", f"key-{i}", 199) for i in range(6)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
            outcomes = list(ex.map(lambda r: self._safe(proc, r), reqs))
        completed = [o for o in outcomes if getattr(o, "completed_now", False)]
        self.assertEqual(len(completed), 1)
        self.assertEqual(prov.calls, 1)
        final = store.get_order(order["public_id"])
        self.assertEqual(final["status"], "delivered")
        self.assertIsNotNone(store.get_payment_confirmation(order["public_id"]))

    @staticmethod
    def _safe(proc, req):
        try:
            return proc.confirm(req)
        except PaymentConfirmationError as exc:
            return exc

    def test_failed_provisioning_compensates_and_allows_retry(self):
        store, _ = make_store()
        code, promo = store.create_promo_code(
            promo_type="fixed", transport="tcp", duration_days=30,
            discount_percent=0, fixed_price_rub=99, device_limit=3, profile_mode="single", family_label=None,
        ) if hasattr(store, "create_promo_code") else (None, None)
        promo_id = promo["id"] if promo else None
        order = make_order(store, price=99, promo_id=promo_id)
        prov = FakeProvisioner(store, fail=True)
        proc = processor(store, prov)
        with self.assertRaises(PaymentConfirmationError):
            proc.confirm(ConfirmationRequest(order["public_id"], "admin", "k1", 99))
        after = store.get_order(order["public_id"])
        self.assertEqual(after["status"], "failed")
        self.assertIsNone(store.get_payment_confirmation(order["public_id"]))
        if promo_id:
            self.assertEqual(store.get_promo_code(promo_id)["used_count"], 0)
        prov.fail = False
        out = proc.confirm(ConfirmationRequest(order["public_id"], "admin", "k2", 99))
        self.assertTrue(out.completed_now)
        if promo_id:
            self.assertEqual(store.get_promo_code(promo_id)["used_count"], 1)

    def test_amount_below_price_is_rejected(self):
        store, _ = make_store()
        order = make_order(store, price=500)
        proc = processor(store, FakeProvisioner(store))
        with self.assertRaises(PaymentConfirmationError):
            proc.confirm(ConfirmationRequest(order["public_id"], "admin", "k", 100))
        self.assertEqual(store.get_order(order["public_id"])["status"], "waiting_payment")

    def test_cancelled_order_cannot_be_confirmed(self):
        store, _ = make_store()
        order = make_order(store)
        store.transition_order(order["public_id"], "cancelled", actor="customer")
        proc = processor(store, FakeProvisioner(store))
        with self.assertRaises(PaymentConfirmationError):
            proc.confirm(ConfirmationRequest(order["public_id"], "admin", "k", 199))

    def test_renewal_is_idempotent_on_retry(self):
        store, _ = make_store()
        base_exp = security.days_from_now(10)
        profile = store.create_profile(
            xui_inbound_id=1, transport="tcp", profile_mode="single", family_label=None,
            xui_email="renew@x", xui_client_id="cid", expires_at=base_exp,
        )
        order = make_order(store, kind="renewal", meta={"renewal_profile_public_id": profile["public_id"]})
        prov = FakeProvisioner(store)
        proc = processor(store, prov)
        out = proc.confirm(ConfirmationRequest(order["public_id"], "admin", "k1", 199))
        exp1 = store.get_profile(profile["public_id"])["expires_at"]
        self.assertEqual(exp1, base_exp + 30 * 86400)
        # Replay with the same key: no second extension.
        out2 = proc.confirm(ConfirmationRequest(order["public_id"], "admin", "k1", 199))
        self.assertFalse(out2.completed_now)
        self.assertEqual(store.get_profile(profile["public_id"])["expires_at"], exp1)

    def test_stale_provisioning_recovery(self):
        store, _ = make_store()
        order = make_order(store)
        store.claim_order_for_provisioning(order["public_id"], actor="a", idempotency_key="k", amount_rub=199)
        with store.transaction() as conn:
            conn.execute("UPDATE orders SET updated_at = updated_at - 10000 WHERE public_id = ?", (order["public_id"],))
        proc = processor(store, FakeProvisioner(store))
        actions = proc.recover_stale(older_than_seconds=600)
        self.assertEqual(actions[0]["action"], "failed_for_retry")
        self.assertEqual(store.get_order(order["public_id"])["status"], "failed")


class TrialAndWebhookTests(unittest.TestCase):
    def test_trial_claim_exactly_once_under_concurrency(self):
        store, _ = make_store()
        wins = []

        def claim():
            ok, _ = store.claim_trial_redemption(user_id=42, chat_id=42)
            if ok:
                wins.append(1)

        threads = [threading.Thread(target=claim) for _ in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(wins), 1)

    def test_webhook_event_lifecycle(self):
        store, _ = make_store()
        self.assertTrue(store.record_webhook_event("gw", "evt-1", "paid", payload_sha256="aa"))
        self.assertFalse(store.record_webhook_event("gw", "evt-1", "paid", payload_sha256="bb"))  # tampered body
        store.finish_webhook_event("gw", "evt-1", ok=False, error="boom")
        self.assertTrue(store.record_webhook_event("gw", "evt-1", "paid", payload_sha256="aa"))  # retry allowed
        store.finish_webhook_event("gw", "evt-1", ok=True)
        self.assertFalse(store.record_webhook_event("gw", "evt-1", "paid", payload_sha256="aa"))  # processed


class SecurityHelperTests(unittest.TestCase):
    def test_signed_token_roundtrip_and_purpose_isolation(self):
        tok = security.sign_token({"email": "a@b"}, purpose="magic_link", ttl_seconds=60)
        self.assertEqual(security.verify_token(tok, purpose="magic_link")["email"], "a@b")
        self.assertIsNone(security.verify_token(tok, purpose="order_web"))
        self.assertIsNone(security.verify_token(tok[:-2] + "zz", purpose="magic_link"))

    def test_client_ip_ignores_headers_from_untrusted_peer(self):
        headers = {"X-Forwarded-For": "1.1.1.1, 127.0.0.1", "CF-Connecting-IP": "9.9.9.9"}
        self.assertEqual(security.client_ip_from_headers(headers, "203.0.113.5"), "203.0.113.5")
        self.assertEqual(security.client_ip_from_headers(headers, "127.0.0.1"), "9.9.9.9")
        self.assertEqual(security.client_ip_from_headers({"X-Forwarded-For": "8.8.8.8, 127.0.0.2"}, "127.0.0.1"), "8.8.8.8")

    def test_host_allowlist(self):
        self.assertTrue(security.is_allowed_host("shop.example.com:443", ["shop.example.com"]))
        self.assertTrue(security.is_allowed_host("a.example.com", ["*.example.com"]))
        self.assertFalse(security.is_allowed_host("evil.com", ["shop.example.com"]))
        self.assertFalse(security.is_allowed_host("shop.example.com@evil.com", ["shop.example.com"]))

    def test_web_token_hashed_at_rest(self):
        store, _ = make_store()
        order = make_order(store)
        token = security.random_web_token()
        store.set_order_web_token(order["public_id"], token)
        row = store.get_order(order["public_id"])
        self.assertNotIn(token, str(row))
        self.assertIsNotNone(store.get_order_by_web_token(order["public_id"], token))
        self.assertIsNone(store.get_order_by_web_token(order["public_id"], token + "_invalid"))

    def test_magic_link_single_use(self):
        store, _ = make_store()
        tok = security.sign_token({"email": "c@d"}, purpose="magic_link", ttl_seconds=60)
        store.create_magic_link(email="c@d", token=tok, ttl_seconds=60, request_ip="127.0.0.1")
        self.assertEqual(store.consume_magic_link(tok), "c@d")
        self.assertIsNone(store.consume_magic_link(tok))


class FailbackMergeTests(unittest.TestCase):
    def _seed(self) -> tuple[Path, Path, Path, Path]:
        tmp = Path(tempfile.mkdtemp())
        base = Store(tmp / "base.db"); base.init()
        o1 = make_order(base)  # will be delivered on NL, stay waiting on FI
        o2 = make_order(base)  # will be cancelled on NL, paid on FI
        _, promo = base.create_promo_code(
            promo_type="fixed", transport="tcp", duration_days=30,
            discount_percent=0, fixed_price_rub=99, device_limit=3, profile_mode="single",
            family_label=None, max_uses=10,
        )
        prof = base.create_profile(
            xui_inbound_id=1, transport="tcp", profile_mode="single", family_label=None,
            xui_email="p@x", xui_client_id="cid", expires_at=security.days_from_now(5),
        )
        import shutil
        for name in ("nl.db", "fi.db"):
            src = sqlite3.connect(tmp / "base.db"); dst = sqlite3.connect(tmp / name)
            src.backup(dst); dst.close(); src.close()
        nl = Store(tmp / "nl.db"); fi = Store(tmp / "fi.db")
        # NL: deliver o1, cancel o2, consume promo once, mark profile deleted
        nl.transition_order(o1["public_id"], "provisioning", actor="nl")
        nl.transition_order(o1["public_id"], "delivered", actor="nl")
        nl.transition_order(o2["public_id"], "cancelled", actor="nl")
        nl.consume_promo_code(int(promo["id"]))
        nl.mark_profile_deleted(prof["public_id"])
        # FI (clock ahead): o1 untouched, o2 delivered (!), promo consumed once, profile renewed
        time.sleep(1.1)
        fi.transition_order(o2["public_id"], "provisioning", actor="fi")
        fi.transition_order(o2["public_id"], "delivered", actor="fi")
        fi.consume_promo_code(int(promo["id"]))
        fi.extend_profile(prof["public_id"], security.days_from_now(40))
        new_fi_order = make_order(fi)
        with fi.transaction() as c:
            c.execute("UPDATE orders SET updated_at = updated_at + 3600")  # simulate clock skew
        self._ids = (o1["public_id"], o2["public_id"], promo["id"], prof["public_id"], new_fi_order["public_id"])
        return tmp / "nl.db", tmp / "fi.db", tmp / "base.db", tmp

    def test_three_way_merge_semantics(self):
        nl_path, fi_path, base_path, _ = self._seed()
        o1, o2, promo_id, prof_id, new_order = self._ids
        stats = failback_merge.merge_vpn_shop(str(nl_path), str(fi_path), str(base_path))
        nl = Store(nl_path)
        # D-01: delivered on NL must not regress even though FI updated_at is newer
        self.assertEqual(nl.get_order(o1)["status"], "delivered")
        # both moved: delivered (rank 4) beats cancelled, logged as a conflict
        self.assertEqual(nl.get_order(o2)["status"], "delivered")
        self.assertTrue(any(o2 in c for c in stats["conflicts"]))
        # D-02: counters are additive relative to the baseline
        self.assertEqual(nl.get_promo_code(promo_id)["used_count"], 2)
        # D-03: renewal on FI re-activates a profile deleted on NL
        prof = nl.get_profile(prof_id)
        self.assertEqual(prof["status"], "active")
        self.assertIsNone(prof["deleted_at"])
        # new FI order carried over
        self.assertIsNotNone(nl.get_order(new_order))

    def test_counters_require_baseline_unless_allowed(self):
        nl_path, fi_path, _, _ = self._seed()
        with self.assertRaises(failback_merge.MergeError):
            failback_merge.merge_vpn_shop(str(nl_path), str(fi_path), None)
        stats = failback_merge.merge_vpn_shop(str(nl_path), str(fi_path), None, allow_two_way=True)
        self.assertTrue(stats["conflicts"])

    def test_dry_run_writes_nothing(self):
        nl_path, fi_path, base_path, _ = self._seed()
        before = sqlite3.connect(nl_path).execute("SELECT COUNT(*) FROM orders").fetchone()[0]
        failback_merge.merge_vpn_shop(str(nl_path), str(fi_path), str(base_path), dry_run=True)
        after = sqlite3.connect(nl_path).execute("SELECT COUNT(*) FROM orders").fetchone()[0]
        self.assertEqual(before, after)


class SubjsonSecurityTests(unittest.TestCase):
    def test_subjson_paid_and_cancel_token_validation(self):
        sys.path.insert(0, str(ROOT / "subjson-service"))
        import app as subjson_app

        store, tmp = make_store()
        token = security.random_web_token()
        order = make_order(store, meta={"web_token": token, "sub_id": "test_sub_123"})
        order_id = order["public_id"]

        with unittest.mock.patch("app.find_store_db_path", return_value=str(tmp / "vpn_shop.db")):
            # Unauthorized call with bad token should fail
            self.assertFalse(subjson_app.handle_inline_order_paid(order_id, web_token="wrong-token-xyz"))
            self.assertEqual(subjson_app.handle_inline_order_cancel(order_id, web_token="wrong-token-xyz"), "")

            # Authorized call with valid token succeeds
            self.assertTrue(subjson_app.handle_inline_order_paid(order_id, web_token=token))
            self.assertEqual(subjson_app.handle_inline_order_cancel(order_id, web_token=token), "test_sub_123")


if __name__ == "__main__":
    unittest.main()
