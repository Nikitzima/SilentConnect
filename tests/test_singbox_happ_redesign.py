"""
tests/test_singbox_happ_redesign.py

Unit test suite verifying:
1. Happ Tag Style in build_singbox_smart_config with country flags and descriptive labels
2. Backward compatibility with legacy tag style
3. Singbox official PNG icon integrity and dimensions
4. Telegram bot is_admin robustness and Smart Grid 2x3 navigation markup
"""

import base64
import io
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for p in [
    os.path.join(PROJECT_ROOT, "subjson-service"),
    os.path.join(PROJECT_ROOT, "vpn-shop"),
]:
    if os.path.exists(p) and p not in sys.path:
        sys.path.insert(0, p)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

os.environ["HYSTERIA_SALAMANDER_PASSWORD"] = "485a96779d1ad79d0fa80ca0"  # PLACEHOLDER
os.environ["HYSTERIA_AUTH_PASSWORD"] = "test_auth_pass_443"  # PLACEHOLDER
os.environ["SECRET_SEGMENT"] = "test-secret"  # PLACEHOLDER
os.environ["LISTEN_PORT"] = "3088"
os.environ["PUBLIC_HOST"] = "sub.example.com"
os.environ["WS443_PUBLIC_HOST"] = "edge.example.com"
os.environ["FI_STANDBY_HOST"] = "fi.example.com"

import app as subjson_app
from vpn_shop.bot import ShopBot
from vpn_shop.config import DEFAULT_MANAGER_TG_ID


class TestSingboxHappRedesign(unittest.TestCase):

    def test_official_singbox_png_icon(self):
        """Verify OFFICIAL_SINGBOX_ICON is a valid base64 PNG data-URI."""
        icon = subjson_app.OFFICIAL_SINGBOX_ICON
        self.assertTrue(icon.startswith("data:image/png;base64,"))

        # Decode base64 and verify PNG signature
        b64_data = icon.split(",", 1)[1]
        raw_bytes = base64.b64decode(b64_data)
        self.assertTrue(raw_bytes.startswith(b"\x89PNG\r\n\x1a\n"))

        # Check dimensions via PIL if available
        try:
            from PIL import Image
            im = Image.open(io.BytesIO(raw_bytes))
            self.assertEqual(im.format, "PNG")
            self.assertEqual(im.size, (144, 144))
        except ImportError:
            pass

    def test_singbox_legacy_tag_style_backward_compatibility(self):
        """Verify default tag_style remains legacy for backward compatibility."""
        mock_summary = {"status_kind": "active"}
        with patch.object(subjson_app, "subscription_summary", return_value=mock_summary), \
             patch.object(subjson_app, "find_subscription", return_value=(None, None, None, None, {"id": "test-uuid", "email": "test@example.com"})):
            cfg = subjson_app.build_singbox_smart_config("test-sub", tag_style="legacy")
            outbounds = cfg.get("outbounds", [])
            tags = [ob.get("tag") for ob in outbounds]
            self.assertIn("auto-urltest", tags)
            self.assertIn("nl-classic-tcp", tags)
            self.assertIn("fi-classic-tcp", tags)
            self.assertNotIn("⚡ Авто-выбор (Лучший пинг)", tags)

    def test_singbox_happ_tag_style(self):
        """Verify Happ tag style translates outbounds to emoji and flag tags."""
        mock_summary = {"status_kind": "active"}
        with patch.object(subjson_app, "subscription_summary", return_value=mock_summary), \
             patch.object(subjson_app, "find_subscription", return_value=(None, None, None, None, {"id": "test-uuid", "email": "test@example.com"})), \
             patch.dict(os.environ, {"PL_STANDBY_HOST": "pl.example.com"}):
            cfg = subjson_app.build_singbox_smart_config("test-sub", tag_style="happ")
            outbounds = cfg.get("outbounds", [])
            tags = [ob.get("tag") for ob in outbounds]

            self.assertIn("⚡ Авто-выбор (Лучший пинг)", tags)
            self.assertIn("🇳🇱 Classic (TCP Reality)", tags)
            self.assertIn("🇫🇮 Classic (TCP Reality)", tags)
            self.assertIn("🇵🇱 Classic (TCP Reality)", tags)
            self.assertNotIn("auto-urltest", tags)
            self.assertNotIn("nl-classic-tcp", tags)

            # Check selector outbounds list
            selector = next(ob for ob in outbounds if ob.get("tag") == "proxy-selector")
            self.assertIn("⚡ Авто-выбор (Лучший пинг)", selector["outbounds"])
            self.assertIn("🇳🇱 Classic (TCP Reality)", selector["outbounds"])
            self.assertEqual(selector.get("default"), "⚡ Авто-выбор (Лучший пинг)")

            # Check urltest outbounds list
            urltest = next(ob for ob in outbounds if ob.get("tag") == "⚡ Авто-выбор (Лучший пинг)")
            self.assertIn("🇳🇱 Classic (TCP Reality)", urltest["outbounds"])
            self.assertIn("🇫🇮 Classic (TCP Reality)", urltest["outbounds"])

    def test_telegram_bot_is_admin_safe(self):
        """Verify is_admin handles None, int, str, dict and DEFAULT_MANAGER_TG_ID."""
        bot = ShopBot.__new__(ShopBot)
        mock_settings = MagicMock()
        mock_settings.admin_user_ids = (111222333,)  # PLACEHOLDER
        mock_settings.admin_usernames = ()
        bot.settings = mock_settings

        self.assertTrue(bot.is_admin(111222333))
        self.assertTrue(bot.is_admin("111222333"))
        self.assertTrue(bot.is_admin({"id": 111222333}))
        self.assertTrue(bot.is_admin(DEFAULT_MANAGER_TG_ID))
        self.assertTrue(bot.is_admin(str(DEFAULT_MANAGER_TG_ID)))
        self.assertTrue(bot.is_admin({"id": DEFAULT_MANAGER_TG_ID}))

        self.assertFalse(bot.is_admin(None))
        self.assertFalse(bot.is_admin({}))
        self.assertFalse(bot.is_admin(999999999))
        self.assertFalse(bot.is_admin("invalid"))

    def test_telegram_bot_home_markup(self):
        """Verify organized public home menu markup structure."""
        bot = ShopBot.__new__(ShopBot)
        markup = bot._public_home_markup()
        keyboard = markup.get("inline_keyboard", [])

        # 4 logical rows: main CTA, subscription actions, loyalty/promo, support/help
        self.assertEqual(len(keyboard), 4)

        button_texts = [btn["text"] for row in keyboard for btn in row]
        self.assertIn("🚀 Подключить VPN / Выбрать тариф", button_texts)
        self.assertIn("🔄 Продлить подписку", button_texts)
        self.assertIn("🎁 Пробный период", button_texts)
        self.assertIn("🎟 Промокод", button_texts)
        self.assertIn("🤝 Рефералы", button_texts)
        self.assertIn("📖 Помощь & FAQ", button_texts)
        self.assertIn("💬 Поддержка", button_texts)


if __name__ == "__main__":
    unittest.main()
