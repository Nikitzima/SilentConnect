from __future__ import annotations

import base64
import json
import os
import signal
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent
VPN_SHOP_DIR = REPO_ROOT / "vpn-shop"
if str(VPN_SHOP_DIR) not in sys.path:
    sys.path.insert(0, str(VPN_SHOP_DIR))

from vpn_shop import awg_manager, bridge, xui_api, xui_reconciler


class TestBridgeHardening(unittest.TestCase):
    def setUp(self) -> None:
        self.secret = "test-secret-bridge-token"
        self.provisioner = MagicMock()
        self.provisioner.settings.web_public_base_url = "https://sub.silentconnect.net"
        self.provisioner.settings.subscription_base_url = "https://silentconnect.net/sub"
        self.awg_mgr = MagicMock()

    def _sign_and_dispatch(self, payload: dict, now: int = 1700000000) -> tuple[int, dict]:
        raw_body = json.dumps(payload).encode("utf-8")
        sig = bridge.sign_bridge_payload(self.secret, now, raw_body)
        headers = {
            "X-Bridge-Timestamp": str(now),
            "X-Bridge-Signature": sig,
        }
        return bridge.verify_and_dispatch_bridge(
            headers=headers,
            raw_body=raw_body,
            secret=self.secret,
            provisioner=self.provisioner,
            awg_manager=self.awg_mgr,
            now_fn=lambda: now,
        )

    def test_allowed_actions_whitelist_exact_13(self) -> None:
        expected = {
            "ping", "status", "server_status", "reconcile_xui", "find_client_by_email",
            "find_client_by_sub_id", "get_client_traffic", "list_client_traffic",
            "provision_profile", "renew_profile", "set_profile_enabled",
            "build_warp_conf", "send_subscription_email"
        }
        self.assertEqual(bridge.ALLOWED_BRIDGE_ACTIONS, expected)
        self.assertEqual(len(bridge.ALLOWED_BRIDGE_ACTIONS), 13)

    def test_disallowed_action_rejected(self) -> None:
        status, data = self._sign_and_dispatch({"action": "unauthorized_action_exec"})
        self.assertEqual(status, 400)
        self.assertFalse(data["ok"])
        self.assertEqual(data["error"], "action_not_allowed:unauthorized_action_exec")

    def test_allowed_ping_action(self) -> None:
        status, data = self._sign_and_dispatch({"action": "ping"})
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"])
        self.assertEqual(data["result"], "pong")

    def test_send_subscription_email_approved_urls(self) -> None:
        payload = {
            "action": "send_subscription_email",
            "params": {
                "customer_email": "user@example.com",
                "order_public_id": "ord_12345",
                "setup_url": "https://sub.silentconnect.net/setup/123",
                "json_url": "https://silentconnect.net/sub/my-sub-id",
                "cabinet_url": "https://nl.silentconnect.net/cabinet",
                "bind_tg_url": "https://t.me/SilentConnectBot?start=bind_123",
            },
        }
        with patch("vpn_shop.mailer.send_subscription_email_async") as mock_mail:
            status, data = self._sign_and_dispatch(payload, now=1700000001)
            self.assertEqual(status, 200)
            self.assertTrue(data["ok"])
            mock_mail.assert_called_once()

    def test_send_subscription_email_rejects_unapproved_domain(self) -> None:
        payload = {
            "action": "send_subscription_email",
            "params": {
                "customer_email": "user@example.com",
                "order_public_id": "ord_12345",
                "setup_url": "https://attacker.evil.com/phish",
            },
        }
        status, data = self._sign_and_dispatch(payload, now=1700000002)
        self.assertEqual(status, 400)
        self.assertFalse(data["ok"])
        self.assertEqual(data["error"], "invalid_or_unapproved_url:setup_url")

    def test_send_subscription_email_rejects_insecure_tg_url(self) -> None:
        payload = {
            "action": "send_subscription_email",
            "params": {
                "customer_email": "user@example.com",
                "order_public_id": "ord_12345",
                "bind_tg_url": "http://t.me/insecure_bot",
            },
        }
        status, data = self._sign_and_dispatch(payload, now=1700000003)
        self.assertEqual(status, 400)
        self.assertFalse(data["ok"])
        self.assertEqual(data["error"], "invalid_or_unapproved_url:bind_tg_url")


class TestAwgManagerHardening(unittest.TestCase):
    def test_validate_wg_key(self) -> None:
        # 32 random bytes in base64
        valid_key = base64.b64encode(os.urandom(32)).decode("ascii")
        self.assertTrue(awg_manager.validate_wg_key(valid_key))

        # Invalid keys
        self.assertFalse(awg_manager.validate_wg_key("not-a-valid-key"))
        self.assertFalse(awg_manager.validate_wg_key("AAAA" * 10))  # too short
        self.assertFalse(awg_manager.validate_wg_key(valid_key + "extra"))
        self.assertFalse(awg_manager.validate_wg_key(""))
        self.assertFalse(awg_manager.validate_wg_key(None))  # type: ignore

    def test_create_peer_uses_dev_stdin_no_psk_file(self) -> None:
        executed_cmds = []

        def mock_dex(cmd, *args, **kwargs):
            executed_cmds.append({"cmd": cmd, "args": args, "kwargs": kwargs})
            if "awg0.conf" in cmd or "cat" in cmd:
                return "[Interface]\nPrivateKey = " + base64.b64encode(os.urandom(32)).decode() + "\n"
            if "awg pubkey" in cmd or "awg genkey" in cmd or "awg genpsk" in cmd:
                return base64.b64encode(os.urandom(32)).decode()
            return ""

        with patch("vpn_shop.awg_manager._dex", side_effect=mock_dex), \
             patch("vpn_shop.awg_manager._next_free_ip", return_value="10.8.1.15"), \
             patch("vpn_shop.awg_manager.get_peer", return_value=None), \
             patch("vpn_shop.awg_manager._db"):
            
            row = awg_manager.create_peer("test_sub_stdin", server_code="nl")
            self.assertIsNotNone(row)

            # Ensure preshared-key /dev/stdin was passed and no /tmp/.awg-psk.tmp file was created
            awg_set_calls = [c for c in executed_cmds if "awg set" in c["cmd"]]
            self.assertTrue(len(awg_set_calls) > 0)
            awg_set = awg_set_calls[0]
            self.assertIn("preshared-key /dev/stdin", awg_set["cmd"])
            self.assertNotIn(".awg-psk.tmp", awg_set["cmd"])
            self.assertEqual(awg_set["kwargs"].get("inp"), row["preshared_key"])

            # Ensure no command creates or removes .awg-psk.tmp
            for c in executed_cmds:
                self.assertNotIn(".awg-psk.tmp", c["cmd"])

    def test_remove_peer_uses_atomic_tmp_and_flock(self) -> None:
        executed_cmds = []

        def mock_dex(cmd, *args, **kwargs):
            executed_cmds.append({"cmd": cmd, "kwargs": kwargs})
            return ""

        dummy_peer = {
            "sub_id": "sub_del",
            "server_code": "nl",
            "public_key": base64.b64encode(os.urandom(32)).decode("ascii"),
            "active": 1,
            "tunnel_ip": "10.8.1.55",
        }

        with patch("vpn_shop.awg_manager._dex", side_effect=mock_dex), \
             patch("vpn_shop.awg_manager.get_peer", return_value=dummy_peer), \
             patch("vpn_shop.awg_manager._server_conf", return_value=f"[Interface]\n[Peer]\nPublicKey = {dummy_peer['public_key']}\n"), \
             patch("vpn_shop.awg_manager._db"):
            
            res = awg_manager.remove_peer("sub_del", reason="expired", server_code="nl")
            self.assertTrue(res)

            # Check atomic write script
            atomic_writes = [c for c in executed_cmds if "flock -x 200" in c["cmd"]]
            self.assertTrue(len(atomic_writes) > 0)
            script = atomic_writes[0]["cmd"]
            self.assertIn(".awg0.conf.tmp.$$", script)
            self.assertIn("mv -f", script)
            self.assertIn("flock -x 200", script)

    def test_remove_slot_peer_uses_atomic_tmp_and_flock(self) -> None:
        executed_cmds = []

        def mock_dex(cmd, *args, **kwargs):
            executed_cmds.append({"cmd": cmd, "kwargs": kwargs})
            return ""

        pub = base64.b64encode(os.urandom(32)).decode("ascii")

        with patch("vpn_shop.awg_manager._dex", side_effect=mock_dex), \
             patch("vpn_shop.awg_manager._server_conf", return_value=f"[Interface]\n[Peer]\nPublicKey = {pub}\n"):
            
            res = awg_manager.remove_slot_peer("nl", public_key=pub)
            self.assertTrue(res)

            atomic_writes = [c for c in executed_cmds if "flock -x 200" in c["cmd"]]
            self.assertTrue(len(atomic_writes) > 0)
            script = atomic_writes[0]["cmd"]
            self.assertIn(".awg0.conf.tmp.$$", script)
            self.assertIn("mv -f", script)
            self.assertIn("flock -x 200", script)


class TestXuiApiLock(unittest.TestCase):
    def test_xui_api_client_has_rlock(self) -> None:
        client = xui_api.XuiApiClient(
            panel_url="http://127.0.0.1:2053",
            username="admin",
            password="password",
            verify_tls=False,
        )
        self.assertIsInstance(client._lock, type(threading.RLock()))

    def test_xui_api_concurrent_provisioning_thread_safety(self) -> None:
        client = xui_api.XuiApiClient(
            panel_url="http://127.0.0.1:2053",
            username="admin",
            password="password",
            verify_tls=False,
        )

        call_log = []

        def mock_open(req, timeout=30):
            call_log.append("open_start")
            time.sleep(0.01)
            call_log.append("open_end")
            resp = MagicMock()
            resp.read.return_value = b'{"success": true, "msg": "ok", "obj": []}'
            resp.__enter__.return_value = resp
            resp.__exit__.return_value = None
            return resp

        client._opener.open = mock_open
        client._logged_in = True

        threads = []
        for _ in range(5):
            t = threading.Thread(target=client.get_inbounds)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # Since each call is guarded by _lock, open_start and open_end must alternate cleanly
        for i in range(0, len(call_log), 2):
            self.assertEqual(call_log[i], "open_start")
            self.assertEqual(call_log[i+1], "open_end")


class TestXuiReconcilerCmdline(unittest.TestCase):
    def test_notify_local_reconciler_checks_cmdline(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as pid_file:
            pid_file.write("999999\n")
            pid_path = Path(pid_file.name)

        with patch("vpn_shop.xui_reconciler.PID_FILE_PATH", pid_path), \
             patch("signal.SIGUSR1", 10, create=True), \
             patch("os.kill") as mock_kill:
            
            # Case 1: /proc/999999/cmdline does not exist
            with patch("vpn_shop.xui_reconciler.Path.exists") as mock_exists:
                def side_exists(*args, **kwargs):
                    if args and str(args[0]) == str(pid_path):
                        return True
                    return False
                mock_exists.side_effect = side_exists

                res = xui_reconciler.notify_local_reconciler()
                self.assertFalse(res)
                mock_kill.assert_not_called()

            # Case 2: /proc/999999/cmdline contains unrelated process (e.g. nginx)
            with patch("vpn_shop.xui_reconciler.Path.exists", return_value=True), \
                 patch("vpn_shop.xui_reconciler.Path.read_bytes", return_value=b"nginx: worker process\x00"):
                res = xui_reconciler.notify_local_reconciler()
                self.assertFalse(res)
                mock_kill.assert_not_called()

            # Case 3: /proc/999999/cmdline contains python vpn_shop reconcile-xui
            with patch("vpn_shop.xui_reconciler.Path.exists", return_value=True), \
                 patch("vpn_shop.xui_reconciler.Path.read_bytes", return_value=b"/usr/bin/python3\x00-m\x00vpn_shop.xui_reconciler\x00"):
                res = xui_reconciler.notify_local_reconciler()
                self.assertTrue(res)
                mock_kill.assert_called_once_with(999999, 10)

        try:
            pid_path.unlink()
        except OSError:
            pass


if __name__ == "__main__":
    unittest.main()
