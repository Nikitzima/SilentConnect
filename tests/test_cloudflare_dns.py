from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError

REPO_ROOT = Path(__file__).resolve().parent.parent
VPN_SHOP_DIR = REPO_ROOT / "vpn-shop"
if str(VPN_SHOP_DIR) not in sys.path:
    sys.path.insert(0, str(VPN_SHOP_DIR))

from vpn_shop.cloudflare_dns import (
    CloudflareDnsClient,
    CloudflareDnsError,
    resolve_node_ip,
)


class CloudflareDnsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.token = "test_token_123"
        self.zone_id = "test_zone_456"
        self.client = CloudflareDnsClient(token=self.token, zone_id=self.zone_id)

    @patch("socket.gethostbyname", return_value="2.56.125.250")
    def test_resolve_node_ip_dynamic_no_hardcoding(self, mock_dns: MagicMock) -> None:
        ip = resolve_node_ip("pl.silentconnect.net")
        self.assertEqual(ip, "2.56.125.250")
        mock_dns.assert_called_once_with("pl.silentconnect.net")

    @patch("socket.gethostbyname", return_value="2.56.125.250")
    @patch("urllib.request.urlopen")
    def test_switch_cluster_dns_success(self, mock_urlopen: MagicMock, mock_dns: MagicMock) -> None:
        # 1. Mock search response
        search_resp = {
            "success": True,
            "result": [
                {"id": "rec_1", "name": "silentconnect.net", "content": "213.165.41.144", "proxied": False}
            ],
        }
        # 2. Mock update response
        update_resp = {
            "success": True,
            "result": {
                "id": "rec_1",
                "name": "silentconnect.net",
                "content": "2.56.125.250",
                "proxied": False,
                "ttl": 60,
            },
        }

        mock_conn1 = MagicMock()
        mock_conn1.__enter__.return_value = mock_conn1
        mock_conn1.read.return_value = json.dumps(search_resp).encode("utf-8")

        mock_conn2 = MagicMock()
        mock_conn2.__enter__.return_value = mock_conn2
        mock_conn2.read.return_value = json.dumps(update_resp).encode("utf-8")

        mock_urlopen.side_effect = [mock_conn1, mock_conn2]

        results = self.client.switch_cluster_dns(
            target_node_domain="pl.silentconnect.net",
            managed_domains=["silentconnect.net"],
        )

        self.assertEqual(results["target_ip"], "2.56.125.250")
        self.assertEqual(len(results["updated"]), 1)
        self.assertFalse(results["updated"][0]["proxied"])
        self.assertEqual(results["updated"][0]["content"], "2.56.125.250")

    @patch("socket.gethostbyname", return_value="2.56.125.250")
    @patch("urllib.request.urlopen")
    def test_switch_cluster_dns_rejects_orange_cloud_proxied(
        self, mock_urlopen: MagicMock, mock_dns: MagicMock
    ) -> None:
        search_resp = {
            "success": True,
            "result": [{"id": "rec_1", "name": "silentconnect.net", "content": "213.165.41.144", "proxied": False}],
        }
        # Cloudflare returned proxied=True (illegal!)
        illegal_update_resp = {
            "success": True,
            "result": {
                "id": "rec_1",
                "name": "silentconnect.net",
                "content": "2.56.125.250",
                "proxied": True,
                "ttl": 60,
            },
        }

        mock_conn1 = MagicMock()
        mock_conn1.__enter__.return_value = mock_conn1
        mock_conn1.read.return_value = json.dumps(search_resp).encode("utf-8")

        mock_conn2 = MagicMock()
        mock_conn2.__enter__.return_value = mock_conn2
        mock_conn2.read.return_value = json.dumps(illegal_update_resp).encode("utf-8")

        mock_urlopen.side_effect = [mock_conn1, mock_conn2]

        with self.assertRaises(CloudflareDnsError) as ctx:
            self.client.switch_cluster_dns(
                target_node_domain="pl.silentconnect.net",
                managed_domains=["silentconnect.net"],
            )
        self.assertIn("Safety Violation: Cloudflare Proxied mode is forbidden", str(ctx.exception))


class BotFailoverMenuTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mock_settings = MagicMock()
        self.mock_settings.subscription_base_url = "https://sub.example.com/sub"
        self.mock_settings.cf_api_token = "test_cf_token"
        self.mock_settings.cf_zone_id = "test_zone_id"
        self.mock_store = MagicMock()
        self.mock_tg = MagicMock()

        from vpn_shop.bot import ShopBot

        self.bot = object.__new__(ShopBot)
        self.bot.settings = self.mock_settings
        self.bot.store = self.mock_store
        self.bot.telegram = self.mock_tg
        self.bot._merge_session_state = MagicMock()

    def test_show_admin_failover_renders_country_buttons(self) -> None:
        with patch.object(self.bot, "_render_or_edit") as mock_render:
            self.bot.show_admin_failover(12345)
            mock_render.assert_called_once()
            args = mock_render.call_args[0]
            self.assertEqual(args[0], 12345)
            self.assertIn("Аварийный переезд", args[1])
            markup = mock_render.call_args[1]["reply_markup"]
            buttons = markup["inline_keyboard"]
            # Check country buttons exist
            button_callbacks = [b["callback_data"] for row in buttons for b in row]
            self.assertIn("admin:failover:confirm:de", button_callbacks)
            self.assertIn("admin:failover:confirm:fi", button_callbacks)
            self.assertIn("admin:failover:confirm:nl", button_callbacks)

    @patch("vpn_shop.cloudflare_dns.resolve_node_ip", return_value="203.0.113.10")
    def test_show_admin_failover_confirm_resolves_and_renders_ip(self, mock_resolve: MagicMock) -> None:
        with patch.object(self.bot, "_render_or_edit") as mock_render:
            self.bot.show_admin_failover_confirm(12345, "de")
            mock_resolve.assert_called_once_with("de.example.com")
            mock_render.assert_called_once()
            text = mock_render.call_args[0][1]
            self.assertIn("203.0.113.10", text)
            self.assertIn("Германия", text)
            markup = mock_render.call_args[1]["reply_markup"]
            button_callbacks = [b["callback_data"] for row in markup["inline_keyboard"] for b in row]
            self.assertIn("admin:failover:apply:de", button_callbacks)

    @patch("vpn_shop.cloudflare_dns.CloudflareDnsClient.switch_cluster_dns")
    def test_execute_admin_failover_calls_cloudflare_and_renders_success(self, mock_switch: MagicMock) -> None:
        mock_switch.return_value = {
            "target_node_domain": "de.example.com",
            "target_ip": "203.0.113.10",
            "updated": [{"domain": "example.com", "content": "203.0.113.10", "proxied": False}],
        }
        with patch.object(self.bot, "_render_or_edit") as mock_render:
            self.bot.execute_admin_failover(12345, "de")
            mock_switch.assert_called_once_with(target_node_domain="de.example.com")
            mock_render.assert_called_once()
            text = mock_render.call_args[0][1]
            self.assertIn("УСПЕШНО ВЫПОЛНЕН", text)
            self.assertIn("203.0.113.10", text)


if __name__ == "__main__":
    unittest.main()
