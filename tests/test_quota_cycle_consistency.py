import os
import sys
import time
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
VPN_SHOP_DIR = os.path.join(PROJECT_ROOT, "vpn-shop")
if VPN_SHOP_DIR not in sys.path:
    sys.path.insert(0, VPN_SHOP_DIR)

from vpn_shop.quota import CYCLE_SECONDS, get_quota_cycle_info


class TestQuotaCycleConsistency(unittest.TestCase):
    def test_empty_profile_defaults(self):
        now = 1700000000
        info = get_quota_cycle_info(None, now_ts=now)
        self.assertEqual(info["period_start_utc"], now)
        self.assertEqual(info["next_reset_utc"], now + CYCLE_SECONDS)
        self.assertEqual(info["cycle_days"], 30)
        self.assertFalse(info["is_perpetual"])
        expected_date = time.strftime("%d.%m.%Y", time.gmtime(now + CYCLE_SECONDS))
        self.assertEqual(info["reset_date_str"], expected_date)

    def test_cycle_within_first_30_days(self):
        # Subscription created 10 days ago
        created_at = 1700000000
        now = created_at + 10 * 86400
        profile = {"created_at": created_at, "expires_at": created_at + 30 * 86400}

        info = get_quota_cycle_info(profile, now_ts=now)
        self.assertEqual(info["period_start_utc"], created_at)
        self.assertEqual(info["next_reset_utc"], created_at + 30 * 86400)
        self.assertFalse(info["is_perpetual"])

    def test_cycle_in_second_month(self):
        # Subscription created 45 days ago (in month 2)
        created_at = 1700000000
        now = created_at + 45 * 86400
        profile = {"created_at": created_at, "expires_at": created_at + 90 * 86400}

        info = get_quota_cycle_info(profile, now_ts=now)
        self.assertEqual(info["period_start_utc"], created_at)
        # Next reset is at 60 days
        self.assertEqual(info["next_reset_utc"], created_at + 60 * 86400)

    def test_perpetual_lifetime_subscription_never_resets_in_distant_future(self):
        # Profile expires in year 2126 (100 years in future)
        created_at = 1700000000
        expires_at = created_at + 100 * 365 * 86400
        now = created_at + 15 * 86400

        profile = {"created_at": created_at, "expires_at": expires_at}
        info = get_quota_cycle_info(profile, now_ts=now)

        self.assertTrue(info["is_perpetual"])
        # Reset date must be 30 days from created_at, NOT year 2126!
        self.assertEqual(info["next_reset_utc"], created_at + 30 * 86400)
        reset_year = int(info["reset_date_str"].split(".")[-1])
        self.assertLess(reset_year, 2035)

    def test_subscriptions_earlier_start(self):
        # Subscriptions list provides earlier purchase date
        sub_start = 1690000000
        created_at = 1700000000
        now = 1705000000
        profile = {"created_at": created_at, "expires_at": created_at + 365 * 86400}
        subscriptions = [
            {"purchased_at": sub_start + 50000},
            {"created_at": sub_start},
        ]

        info = get_quota_cycle_info(profile, subscriptions=subscriptions, now_ts=now)
        self.assertEqual(info["period_start_utc"], sub_start)

    def test_future_start_fallback(self):
        # If created_at is in the future (clock skew)
        now = 1700000000
        profile = {"created_at": now + 86400, "expires_at": now + 30 * 86400}
        info = get_quota_cycle_info(profile, now_ts=now)
        self.assertEqual(info["period_start_utc"], now)
        self.assertEqual(info["next_reset_utc"], now + CYCLE_SECONDS)


if __name__ == "__main__":
    unittest.main()
