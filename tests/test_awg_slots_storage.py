from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

# Add vpn-shop to sys.path
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "vpn-shop"))

from vpn_shop.store import (
    AWG_TIER_QUOTAS_BYTES,
    AWG_TIER_QUOTAS_GB,
    Store,
    default_awg_quota_bytes_for_devices,
)


class TestAwgSlotsStorage(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_vpn_shop.db"
        self.store = Store(self.db_path)
        self.store.init()

        # Create a primary test profile
        self.profile = self.store.create_profile(
            xui_inbound_id=1,
            transport="tcp",
            profile_mode="personal",
            family_label=None,
            xui_email="client1@silentconnect.test",
            xui_client_id="uuid-client-1",
            expires_at=1800000000,
            notes="test profile 1",
            awg_quota_bytes=default_awg_quota_bytes_for_devices(3),
            awg_reset_at=1800000000,
        )
        self.profile_id = self.profile["public_id"]

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_01_tier_quota_constants(self) -> None:
        """Verify agreed quotas: 3 dev = 250 GB, 6 dev = 500 GB, 9 dev = 1000 GB."""
        self.assertEqual(AWG_TIER_QUOTAS_GB[3], 250)
        self.assertEqual(AWG_TIER_QUOTAS_GB[6], 500)
        self.assertEqual(AWG_TIER_QUOTAS_GB[9], 1000)

        self.assertEqual(default_awg_quota_bytes_for_devices(1), 250 * 1024**3)
        self.assertEqual(default_awg_quota_bytes_for_devices(3), 250 * 1024**3)
        self.assertEqual(default_awg_quota_bytes_for_devices(4), 500 * 1024**3)
        self.assertEqual(default_awg_quota_bytes_for_devices(6), 500 * 1024**3)
        self.assertEqual(default_awg_quota_bytes_for_devices(9), 1000 * 1024**3)
        self.assertEqual(default_awg_quota_bytes_for_devices(12), 1000 * 1024**3)

    def test_02_schema_and_migration_idempotency(self) -> None:
        """Verify tables and columns exist and running init() repeatedly is safe."""
        self.store.init()
        quota = self.store.get_awg_profile_quota(self.profile_id)
        self.assertIsNotNone(quota)
        self.assertEqual(quota["awg_quota_bytes"], 250 * 1024**3)
        self.assertEqual(quota["awg_used_bytes"], 0)
        self.assertEqual(quota["is_exceeded"], False)

    def test_03_create_and_get_awg_slots(self) -> None:
        """Verify creating slots 1..3 and retrieving them by id, index, and pubkey."""
        slot1 = self.store.create_awg_slot(
            profile_public_id=self.profile_id,
            slot_index=1,
            slot_label="Телефон iPhone",
            public_key="pubkey_slot_1_test_abc123=",
            private_key_enc="enc_privkey_slot_1_xxx",
            preshared_key="psk_slot_1_test",
            client_ip="10.8.1.10",
            server_code="nl",
        )
        self.assertEqual(slot1["profile_public_id"], self.profile_id)
        self.assertEqual(slot1["slot_index"], 1)
        self.assertEqual(slot1["slot_label"], "Телефон iPhone")
        self.assertEqual(slot1["client_ip"], "10.8.1.10")
        self.assertEqual(slot1["enabled"], 1)

        slot2 = self.store.create_awg_slot(
            profile_public_id=self.profile_id,
            slot_index=2,
            slot_label="Рабочий MacBook",
            public_key="pubkey_slot_2_test_def456=",
            private_key_enc="enc_privkey_slot_2_yyy",
            preshared_key=None,
            client_ip="10.8.1.11",
            server_code="nl",
        )
        self.assertEqual(slot2["slot_index"], 2)

        # Retrieve by id
        fetched_id = self.store.get_awg_slot(slot1["id"])
        self.assertIsNotNone(fetched_id)
        self.assertEqual(fetched_id["slot_label"], "Телефон iPhone")

        # Retrieve by index
        fetched_idx = self.store.get_awg_slot_by_index(self.profile_id, 2)
        self.assertIsNotNone(fetched_idx)
        self.assertEqual(fetched_idx["public_key"], "pubkey_slot_2_test_def456=")

        # Retrieve by public key
        fetched_pk = self.store.get_awg_slot_by_public_key("pubkey_slot_1_test_abc123=")
        self.assertIsNotNone(fetched_pk)
        self.assertEqual(fetched_pk["id"], slot1["id"])

        # List slots
        slots = self.store.list_awg_slots(self.profile_id)
        self.assertEqual(len(slots), 2)
        self.assertEqual([s["slot_index"] for s in slots], [1, 2])

    def test_04_slot_boundaries_and_validations(self) -> None:
        """Verify slot_index must be in 1..9, non-existent profile raises KeyError, empty strings raise."""
        # slot_index 0
        with self.assertRaises(ValueError):
            self.store.create_awg_slot(
                profile_public_id=self.profile_id,
                slot_index=0,
                slot_label="Zero slot",
                public_key="pk0=",
                private_key_enc="enc0",
                client_ip="10.8.1.20",
            )

        # slot_index 10
        with self.assertRaises(ValueError):
            self.store.create_awg_slot(
                profile_public_id=self.profile_id,
                slot_index=10,
                slot_label="Ten slot",
                public_key="pk10=",
                private_key_enc="enc10",
                client_ip="10.8.1.21",
            )

        # Non-existent profile
        with self.assertRaises(KeyError):
            self.store.create_awg_slot(
                profile_public_id="non_existent_profile_id",
                slot_index=1,
                slot_label="Ghost",
                public_key="pk_ghost=",
                private_key_enc="enc_ghost",
                client_ip="10.8.1.22",
            )

        # Empty public key
        with self.assertRaises(ValueError):
            self.store.create_awg_slot(
                profile_public_id=self.profile_id,
                slot_index=1,
                slot_label="Valid label",
                public_key="",
                private_key_enc="enc1",
                client_ip="10.8.1.23",
            )

    def test_05_uniqueness_constraints(self) -> None:
        """Verify unique slot_index per profile and globally unique public_key."""
        self.store.create_awg_slot(
            profile_public_id=self.profile_id,
            slot_index=1,
            slot_label="Slot 1",
            public_key="unique_pk_1=",
            private_key_enc="enc_pk_1",
            client_ip="10.8.1.30",
        )

        # Duplicate slot_index for same profile -> sqlite3.IntegrityError
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.create_awg_slot(
                profile_public_id=self.profile_id,
                slot_index=1,
                slot_label="Duplicate Slot 1",
                public_key="unique_pk_2=",
                private_key_enc="enc_pk_2",
                client_ip="10.8.1.31",
            )

        # Create second profile
        p2 = self.store.create_profile(
            xui_inbound_id=1,
            transport="tcp",
            profile_mode="personal",
            family_label=None,
            xui_email="client2@silentconnect.test",
            xui_client_id="uuid-client-2",
            expires_at=1800000000,
        )

        # Second profile CAN have slot_index 1
        p2_slot1 = self.store.create_awg_slot(
            profile_public_id=p2["public_id"],
            slot_index=1,
            slot_label="Slot 1 profile 2",
            public_key="unique_pk_for_p2=",
            private_key_enc="enc_p2",
            client_ip="10.8.1.32",
        )
        self.assertEqual(p2_slot1["slot_index"], 1)

        # Duplicate public key across profiles -> sqlite3.IntegrityError
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.create_awg_slot(
                profile_public_id=p2["public_id"],
                slot_index=2,
                slot_label="Slot 2 profile 2",
                public_key="unique_pk_1=",  # already used by profile 1
                private_key_enc="enc_p2_dup",
                client_ip="10.8.1.33",
            )

    def test_06_rename_and_enable_toggle(self) -> None:
        """Verify renaming and toggling enabled state."""
        slot = self.store.create_awg_slot(
            profile_public_id=self.profile_id,
            slot_index=1,
            slot_label="Original Name",
            public_key="pk_toggle=",
            private_key_enc="enc_toggle",
            client_ip="10.8.1.40",
        )

        # Rename by id
        updated = self.store.rename_awg_slot(slot["id"], "Renamed Name")
        self.assertEqual(updated["slot_label"], "Renamed Name")

        # Rename by index
        updated2 = self.store.rename_awg_slot_by_index(self.profile_id, 1, "Renamed By Index")
        self.assertEqual(updated2["slot_label"], "Renamed By Index")

        # Disable slot
        disabled = self.store.set_awg_slot_enabled(slot["id"], False)
        self.assertEqual(disabled["enabled"], 0)

        # Re-enable by index
        enabled = self.store.set_awg_slot_enabled_by_index(self.profile_id, 1, True)
        self.assertEqual(enabled["enabled"], 1)

    def test_07_delete_slot(self) -> None:
        """Verify slot deletion by id and by index."""
        slot1 = self.store.create_awg_slot(
            profile_public_id=self.profile_id,
            slot_index=1,
            slot_label="Slot 1",
            public_key="pk_del_1=",
            private_key_enc="enc_del_1",
            client_ip="10.8.1.50",
        )
        slot2 = self.store.create_awg_slot(
            profile_public_id=self.profile_id,
            slot_index=2,
            slot_label="Slot 2",
            public_key="pk_del_2=",
            private_key_enc="enc_del_2",
            client_ip="10.8.1.51",
        )

        # Delete by id
        res1 = self.store.delete_awg_slot(slot1["id"])
        self.assertTrue(res1)
        self.assertIsNone(self.store.get_awg_slot(slot1["id"]))

        # Delete by index
        res2 = self.store.delete_awg_slot_by_index(self.profile_id, 2)
        self.assertTrue(res2)
        self.assertIsNone(self.store.get_awg_slot_by_index(self.profile_id, 2))

        # Re-delete returns False
        self.assertFalse(self.store.delete_awg_slot(slot1["id"]))

    def test_08_traffic_ledger_and_profile_used_bytes(self) -> None:
        """Verify traffic delta recording and atomic increment of awg_used_bytes."""
        slot = self.store.create_awg_slot(
            profile_public_id=self.profile_id,
            slot_index=1,
            slot_label="Slot 1",
            public_key="pk_traffic_1=",
            private_key_enc="enc_traffic_1",
            client_ip="10.8.1.60",
        )

        # Record single delta
        self.store.record_awg_traffic_delta(
            node_id="nl-master",
            profile_public_id=self.profile_id,
            slot_id=slot["id"],
            delta_rx_bytes=1000,
            delta_tx_bytes=2000,
        )

        quota = self.store.get_awg_profile_quota(self.profile_id)
        self.assertEqual(quota["awg_used_bytes"], 3000)
        self.assertEqual(quota["remaining_bytes"], 250 * 1024**3 - 3000)

        # Record batch deltas
        deltas = [
            {
                "node_id": "nl-master",
                "profile_public_id": self.profile_id,
                "slot_id": slot["id"],
                "delta_rx_bytes": 5000,
                "delta_tx_bytes": 5000,
            },
            {
                "node_id": "pl-node2",
                "profile_public_id": self.profile_id,
                "slot_id": slot["id"],
                "delta_rx_bytes": 2000,
                "delta_tx_bytes": 3000,
            },
        ]
        count = self.store.record_awg_traffic_deltas(deltas)
        self.assertEqual(count, 2)

        quota_after = self.store.get_awg_profile_quota(self.profile_id)
        # 3000 + 10000 + 5000 = 18000
        self.assertEqual(quota_after["awg_used_bytes"], 18000)

        # Ledger retrieval
        ledger = self.store.get_awg_traffic_ledger(self.profile_id)
        self.assertEqual(len(ledger), 3)

        # Traffic summary
        summary = self.store.get_awg_traffic_summary(self.profile_id)
        self.assertEqual(summary["total_rx_bytes"], 1000 + 5000 + 2000)
        self.assertEqual(summary["total_tx_bytes"], 2000 + 5000 + 3000)
        self.assertEqual(summary["total_bytes"], 18000)

    def test_09_quota_exceeded_and_reset(self) -> None:
        """Verify quota calculation, is_exceeded flag, and monthly reset."""
        # Set quota to small value for testing
        self.store.set_awg_profile_quota(self.profile_id, quota_bytes=10000)
        quota = self.store.get_awg_profile_quota(self.profile_id)
        self.assertEqual(quota["awg_quota_bytes"], 10000)
        self.assertFalse(quota["is_exceeded"])

        # Record 10001 bytes
        self.store.record_awg_traffic_delta(
            node_id="nl-master",
            profile_public_id=self.profile_id,
            delta_rx_bytes=6000,
            delta_tx_bytes=4001,
        )

        quota_exceeded = self.store.get_awg_profile_quota(self.profile_id)
        self.assertEqual(quota_exceeded["awg_used_bytes"], 10001)
        self.assertTrue(quota_exceeded["is_exceeded"])
        self.assertEqual(quota_exceeded["remaining_bytes"], 0)

        # Monthly reset
        new_reset_at = 1850000000
        reset_quota = self.store.reset_awg_monthly_quota(self.profile_id, new_reset_at)
        self.assertEqual(reset_quota["awg_used_bytes"], 0)
        self.assertEqual(reset_quota["awg_reset_at"], new_reset_at)
        self.assertFalse(reset_quota["is_exceeded"])
        self.assertEqual(reset_quota["remaining_bytes"], 10000)

    def test_10_extend_profile_quota_reset(self) -> None:
        """Verify extending profile resets used bytes when reset_awg_quota is True."""
        self.store.record_awg_traffic_delta(
            node_id="nl-master",
            profile_public_id=self.profile_id,
            delta_rx_bytes=5000,
            delta_tx_bytes=5000,
        )
        self.assertEqual(self.store.get_awg_profile_quota(self.profile_id)["awg_used_bytes"], 10000)

        new_expiry = 1900000000
        self.store.extend_profile(self.profile_id, new_expiry, reset_awg_quota=True)

        quota = self.store.get_awg_profile_quota(self.profile_id)
        self.assertEqual(quota["awg_used_bytes"], 0)
        self.assertEqual(quota["awg_reset_at"], new_expiry)

    def test_11_device_limit_enforcement_and_tiers(self) -> None:
        """Verify slot creation strictly respects device limit (3, 6, 9) by plan tier."""
        # Current self.profile has 3 devices limit
        self.store.create_awg_slot(
            profile_public_id=self.profile_id,
            slot_index=1,
            slot_label="Dev 1",
            public_key="pk_tier_1=",
            private_key_enc="enc_tier_1",
            client_ip="10.8.1.101",
        )
        self.store.create_awg_slot(
            profile_public_id=self.profile_id,
            slot_index=2,
            slot_label="Dev 2",
            public_key="pk_tier_2=",
            private_key_enc="enc_tier_2",
            client_ip="10.8.1.102",
        )
        self.store.create_awg_slot(
            profile_public_id=self.profile_id,
            slot_index=3,
            slot_label="Dev 3",
            public_key="pk_tier_3=",
            private_key_enc="enc_tier_3",
            client_ip="10.8.1.103",
        )

        # Attempting slot_index=4 on 3-device plan must raise ValueError
        with self.assertRaises(ValueError) as ctx:
            self.store.create_awg_slot(
                profile_public_id=self.profile_id,
                slot_index=4,
                slot_label="Dev 4",
                public_key="pk_tier_4=",
                private_key_enc="enc_tier_4",
                client_ip="10.8.1.104",
            )
        self.assertIn("exceeds profile device limit", str(ctx.exception))

        # Create a 6-device profile (500 GB tier)
        p6 = self.store.create_profile(
            xui_inbound_id=1,
            transport="tcp",
            profile_mode="family",
            family_label="fam6",
            xui_email="fam6@silentconnect.test",
            xui_client_id="uuid-fam6",
            expires_at=1800000000,
            awg_quota_bytes=default_awg_quota_bytes_for_devices(6),
        )
        # Should allow slot 6
        s6 = self.store.create_awg_slot(
            profile_public_id=p6["public_id"],
            slot_index=6,
            slot_label="Dev 6",
            public_key="pk_tier_6=",
            private_key_enc="enc_tier_6",
            client_ip="10.8.1.106",
        )
        self.assertEqual(s6["slot_index"], 6)

        # Slot 7 on 6-device tier must raise ValueError
        with self.assertRaises(ValueError):
            self.store.create_awg_slot(
                profile_public_id=p6["public_id"],
                slot_index=7,
                slot_label="Dev 7",
                public_key="pk_tier_7=",
                private_key_enc="enc_tier_7",
                client_ip="10.8.1.107",
            )

    def test_12_ip_collision_prevention_on_same_server(self) -> None:
        """Verify duplicate client IPs on the same server are rejected to prevent cryptokey routing hijacking."""
        self.store.create_awg_slot(
            profile_public_id=self.profile_id,
            slot_index=1,
            slot_label="Device NL",
            public_key="pk_nl_1=",
            private_key_enc="enc_nl_1",
            client_ip="10.8.1.150",
            server_code="nl",
        )

        # Create another profile
        p2 = self.store.create_profile(
            xui_inbound_id=1,
            transport="tcp",
            profile_mode="personal",
            family_label=None,
            xui_email="p2@silentconnect.test",
            xui_client_id="uuid-p2",
            expires_at=1800000000,
        )

        # Reusing same IP on same server ('nl') must raise sqlite3.IntegrityError
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.create_awg_slot(
                profile_public_id=p2["public_id"],
                slot_index=1,
                slot_label="Hijack IP",
                public_key="pk_nl_2=",
                private_key_enc="enc_nl_2",
                client_ip="10.8.1.150",
                server_code="nl",
            )

        # Same IP on a different server ('fi' or 'pl') is permitted
        slot_fi = self.store.create_awg_slot(
            profile_public_id=p2["public_id"],
            slot_index=1,
            slot_label="Device FI",
            public_key="pk_fi_1=",
            private_key_enc="enc_fi_1",
            client_ip="10.8.1.150",
            server_code="fi",
        )
        self.assertEqual(slot_fi["server_code"], "fi")

    def test_13_device_label_validation_and_xss_sanitization(self) -> None:
        """Verify device label length limit (1..16 chars) and XSS character sanitization."""
        # Empty label raises ValueError
        with self.assertRaises(ValueError):
            self.store.sanitize_device_label("")

        # Whitespace only raises ValueError
        with self.assertRaises(ValueError):
            self.store.sanitize_device_label("   ")

        # Label longer than 16 chars raises ValueError
        with self.assertRaises(ValueError):
            self.store.sanitize_device_label("ThisNameIsWayTooLong123")

        # XSS script injection is sanitized
        sanitized = self.store.sanitize_device_label("<script>pc</script>")
        self.assertEqual(sanitized, "scriptpc/script"[:16])

        # Renaming to valid name works
        slot = self.store.create_awg_slot(
            profile_public_id=self.profile_id,
            slot_index=1,
            slot_label="Phone 15",
            public_key="pk_lbl_1=",
            private_key_enc="enc_lbl_1",
            client_ip="10.8.1.180",
        )
        renamed = self.store.rename_awg_slot(slot["id"], "My iPhone 📱")
        self.assertEqual(renamed["slot_label"], "My iPhone 📱")

        # Renaming with string > 16 chars raises ValueError
        with self.assertRaises(ValueError):
            self.store.rename_awg_slot(slot["id"], "SuperLongDeviceNameExceedingLimit")


if __name__ == "__main__":
    unittest.main()
