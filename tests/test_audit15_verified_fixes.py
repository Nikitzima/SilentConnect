"""Regression tests for the verified findings of РѕС‚РІРµС‚15.md (audit round 15).

Only findings confirmed against real code / prod data are covered here.
"""
from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from unittest.mock import MagicMock, patch

ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent
VPN_SHOP_DIR = ROOT_DIR / "vpn-shop"
SUBJSON_DIR = ROOT_DIR / "subjson-service"
for p in (str(VPN_SHOP_DIR), str(SUBJSON_DIR), str(ROOT_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

os.environ.setdefault("HYSTERIA_SALAMANDER_PASSWORD", "test-salamander-pass")  # PLACEHOLDER
os.environ.setdefault("HYSTERIA_AUTH_PASSWORD", "test-auth-pass")  # PLACEHOLDER
os.environ.setdefault("TCP_REALITY_PUBLIC_KEY", "test-pub-key")  # PLACEHOLDER
os.environ.setdefault("TCP_REALITY_SHORT_ID", "1234abcd")  # PLACEHOLDER
os.environ.setdefault("TCP_REALITY_SNI_CLASSIC", "sber.ru")
os.environ.setdefault("TCP_REALITY_SNI_FAST", "st.kinopoisk.ru")
os.environ.setdefault("GRPC_REALITY_PUBLIC_KEY", "test-grpc-pub-key")  # PLACEHOLDER
os.environ.setdefault("GRPC_REALITY_SHORT_ID", "4d7a")  # PLACEHOLDER
os.environ.setdefault("GRPC_REALITY_SNI", "vk.com")
os.environ.setdefault("SECRET_SEGMENT", "my-secret-sub")  # PLACEHOLDER
os.environ.setdefault("INTERNAL_SECRET", "test-internal-secret")  # PLACEHOLDER
os.environ.setdefault("XUI_DB_PATH", ":memory:")
os.environ.setdefault("STATIC_JSON_CONFIG_DIR", "/tmp")

from vpn_shop import security  # noqa: E402
from vpn_shop.config import load_settings  # noqa: E402
from vpn_shop.store import DatabaseQueryError, Store  # noqa: E402
from vpn_shop.web import WebCheckout  # noqa: E402
import app as subjson_app  # noqa: E402


class _Headers(dict):
    """Minimal header bag: case-sensitive .get plus the peer_ip attribute web.py reads."""

    peer_ip = "127.0.0.1"
    scheme = "https"


class TestPublicPepperForgery(unittest.TestCase):
    def test_token_signed_with_public_default_pepper_is_rejected(self) -> None:
        with patch.dict(os.environ, {"SERVER_PEPPER": "unit-test-secret-pepper-xyz"}):
            body = b'{"email":"victim@example.com","exp":9999999999,"n":"00"}'
            import base64
            import hashlib
            import hmac

            mac = hmac.new(
                security.DEFAULT_SERVER_PEPPER.encode(),
                b"magic_link\x00" + body,
                hashlib.sha256,
            ).digest()
            forged = (
                base64.urlsafe_b64encode(body).rstrip(b"=").decode()
                + "."
                + base64.urlsafe_b64encode(mac).rstrip(b"=").decode()
            )
            self.assertIsNone(security.verify_token(forged, purpose="magic_link"))

    def test_genuine_token_still_verifies(self) -> None:
        with patch.dict(os.environ, {"SERVER_PEPPER": "unit-test-secret-pepper-xyz"}):
            token = security.sign_token({"email": "a@example.com"}, purpose="magic_link", ttl_seconds=60)
            payload = security.verify_token(token, purpose="magic_link")
            self.assertEqual(payload["email"], "a@example.com")


class TestHappImportQueryStripping(unittest.TestCase):
    def test_strip_import_source_query_drops_query_and_fragment(self) -> None:
        got = subjson_app._strip_import_source_query("https://sub.example.com/x/y?rand=1&b=2#frag")
        self.assertEqual(got, "https://sub.example.com/x/y")

    def test_strip_import_source_query_passthrough_without_scheme(self) -> None:
        self.assertEqual(subjson_app._strip_import_source_query("not a url"), "not a url")

    def test_happ_import_branch_uses_normalizer(self) -> None:
        src = (SUBJSON_DIR / "app.py").read_text(encoding="utf-8")
        marker = "target = path[2]\n                sub_id = path[3]"
        marker_crlf = marker.replace("\n", "\r\n")
        idx = src.find(marker) if marker in src else src.find(marker_crlf)
        self.assertGreater(idx, 0, "4-segment import branch not found")
        branch = src[idx : idx + 900]
        self.assertNotIn("source_url = raw_source", branch)
        self.assertIn("_strip_import_source_query(raw_source)", branch)


class TestLoopbackIsNotASharedRateLimitKey(unittest.TestCase):
    def test_is_loopback_or_unknown_ip(self) -> None:
        for ip in ("127.0.0.1", "::1", "unknown", "", None, "127.0.0.5"):
            self.assertTrue(security.is_loopback_or_unknown_ip(ip), ip)
        for ip in ("203.0.113.9", "198.51.100.7", "2001:db8::1"):
            self.assertFalse(security.is_loopback_or_unknown_ip(ip), ip)

    def _checkout(self, tmp: pathlib.Path) -> WebCheckout:
        settings = replace(
            load_settings(VPN_SHOP_DIR),
            root_dir=VPN_SHOP_DIR,
            database_path=tmp / "shop.db",
            platega_enabled=False,
            cf_turnstile_secret_key="",
            web_public_base_url="https://example.com",
        )
        store = Store(settings.database_path)
        store.init()
        return WebCheckout(settings, store)

    def test_two_visitors_behind_loopback_do_not_block_each_other(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            wc = self._checkout(pathlib.Path(tmpdir))
            hdrs = _Headers()
            first = wc.request_cabinet_access_link(hdrs, "first.visitor@example.com")
            second = wc.request_cabinet_access_link(hdrs, "second.visitor@example.org")
            self.assertTrue(first["ok"], first)
            self.assertTrue(second["ok"], second)  # was: "РїРѕРґРѕР¶РґРёС‚Рµ 20 СЃРµРєСѓРЅРґ" for a different person

    def test_same_email_is_still_throttled(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            wc = self._checkout(pathlib.Path(tmpdir))
            hdrs = _Headers()
            self.assertTrue(wc.request_cabinet_access_link(hdrs, "same@example.com")["ok"])
            again = wc.request_cabinet_access_link(hdrs, "same@example.com")
            self.assertFalse(again["ok"])

    def test_real_public_ip_is_still_rate_limited_per_ip(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            wc = self._checkout(pathlib.Path(tmpdir))
            hdrs = _Headers()
            hdrs.peer_ip = "203.0.113.50"
            self.assertTrue(wc.request_cabinet_access_link(hdrs, "x1@example.com")["ok"])
            blocked = wc.request_cabinet_access_link(hdrs, "x2@example.com")
            self.assertFalse(blocked["ok"])


class TestReferralBalancePointQuery(unittest.TestCase):
    def test_get_referral_balance_matches_list_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = Store(pathlib.Path(tmpdir) / "r.db")
            store.init()
            now = int(time.time())
            with store._connect() as conn:
                conn.execute(
                    "INSERT INTO telegram_users(user_id, chat_id, username, first_name, last_name, is_bot, first_seen_at, last_seen_at)"
                    " VALUES('u1','c1','neo','N','O',0,?,?)",
                    (now, now),
                )
                for uid, code in (("u1", "R1"), ("u2", "R2")):
                    conn.execute(
                        "INSERT INTO referrers(user_id, chat_id, code, commission_percent, status, created_at, updated_at)"
                        " VALUES(?, 'c', ?, 10, 'active', ?, ?)",
                        (uid, code, now, now),
                    )
                conn.execute(
                    "INSERT INTO referral_ledger(referrer_id, referred_user_id, order_public_id, base_amount_rub, amount_rub,"
                    " commission_percent, status, created_at) VALUES(1,'x','ord_a',1000,100,10,'pending',?)",
                    (now,),
                )
                conn.execute(
                    "INSERT INTO referral_ledger(referrer_id, referred_user_id, order_public_id, base_amount_rub, amount_rub,"
                    " commission_percent, status, created_at, paid_at) VALUES(1,'y','ord_b',500,50,10,'paid',?,?)",
                    (now, now),
                )
                conn.execute(
                    "INSERT INTO referral_payouts(referrer_id, amount_rub, actor, created_at) VALUES(1, 30, 'admin', ?)",
                    (now,),
                )
                conn.execute(
                    "INSERT INTO referral_attributions(referrer_id, referred_user_id, referred_chat_id, source_code, created_at)"
                    " VALUES(1,'z','cz','R1',?)",
                    (now,),
                )
            by_list = {int(i["id"]): i for i in store.list_referral_balances()}
            for rid in (1, 2):
                self.assertEqual(store.get_referral_balance(rid), by_list[rid])
            self.assertIsNone(store.get_referral_balance(999))

    def test_get_referral_balance_does_not_scan_all_referrers(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = Store(pathlib.Path(tmpdir) / "r2.db")
            store.init()
            with patch.object(store, "list_referral_balances", side_effect=AssertionError("full scan")):
                self.assertIsNone(store.get_referral_balance(1))


class TestReconcileReusesInjectedStore(unittest.TestCase):
    def test_injected_store_is_used_and_no_new_store_is_built(self) -> None:
        from vpn_shop import awg_manager

        fake_store = MagicMock()
        fake_store.list_active_awg_slots.side_effect = DatabaseQueryError("boom")
        with patch("vpn_shop.store.Store", side_effect=AssertionError("Store() must not be constructed")):
            with self.assertRaises(DatabaseQueryError):
                awg_manager.reconcile_awg_peers(server_code="nl", dry_run=True, store=fake_store)
        fake_store.init.assert_not_called()


class TestBotUserUpsertThrottle(unittest.TestCase):
    def test_repeat_clicks_do_not_rewrite_telegram_user(self) -> None:
        from vpn_shop.bot import ShopBot

        bot = ShopBot.__new__(ShopBot)
        bot.store = MagicMock()
        user = {"id": 42, "username": "u"}
        for _ in range(5):
            bot._remember_user(1001, user)
        self.assertEqual(bot.store.upsert_telegram_user.call_count, 1)
        bot._remember_user(1001, {"id": 43, "username": "other"})
        self.assertEqual(bot.store.upsert_telegram_user.call_count, 2)


if __name__ == "__main__":
    unittest.main()

