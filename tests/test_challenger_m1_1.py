#!/usr/bin/env python3
"""
tests/test_challenger_m1_1.py

Adversarial Stress Test Suite for Security Audit Scanner (scripts/security_audit_scanner.py)
Authored by Challenger 1 (Milestone 1).
"""

from __future__ import annotations

import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.security_audit_scanner import (
    SecurityAuditScanner,
    Violation,
    main,
    parse_args,
    SECRET_PATTERNS,
    SAFE_WHITELIST_SUBSTRINGS,
)


class AdversarialSecurityScannerTests(unittest.TestCase):
    """Comprehensive Adversarial Stress Tests for SecurityAuditScanner."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="adv_sec_test_")
        self.test_path = Path(self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # Group 1: Secret Obfuscation & Regex Parsing Bypasses
    # -------------------------------------------------------------------------

    def test_adv_01_unquoted_secrets(self):
        """Test detection when secrets are defined without quotes in env or script files."""
        f1 = self.test_path / "reality.env"
        f1.write_text("reality_private_key=abcdef12345678901234567890123456789012345678\n", encoding="utf-8")

        f2 = self.test_path / "mailer.env"
        f2.write_text("SMTP_PASSWORD=SuperSecretPassword123!\n", encoding="utf-8")

        f3 = self.test_path / "hysteria.env"
        f3.write_text("HYSTERIA_AUTH_PASSWORD=SuperSecretHysteriaPass123\n", encoding="utf-8")

        scanner = SecurityAuditScanner(self.test_path, check_git=False)
        passed = scanner.run_scan()
        self.assertFalse(passed)
        rule_ids = [v.rule_id for v in scanner.violations]
        self.assertIn("SEC-006", rule_ids)
        self.assertIn("SEC-008", rule_ids)
        self.assertIn("SEC-009", rule_ids)

    def test_adv_02_yaml_colon_syntax(self):
        """Test detection of secrets using YAML colon syntax without equals."""
        f = self.test_path / "config.yaml"
        f.write_text(
            "PrivateKey: EB8X3hWj3Z9qL2kM7xO0v1n4p6r8t0v2x4z6a8c0e2g=\n"
            "ADMIN_IDS: 503264426\n"
            "SECRET_SEGMENT: SuperSecretSegment123\n",
            encoding="utf-8",
        )
        scanner = SecurityAuditScanner(self.test_path, check_git=False)
        passed = scanner.run_scan()
        self.assertFalse(passed)
        rule_ids = [v.rule_id for v in scanner.violations]
        self.assertIn("SEC-005", rule_ids)
        self.assertIn("PRV-002", rule_ids)
        self.assertIn("SEC-009", rule_ids)

    def test_adv_03_os_getenv_fallback_bypass(self):
        """Test if hardcoded secrets inside os.getenv() fallbacks are detected."""
        f = self.test_path / "app.py"
        prod_ip = "193" + ".233" + ".210" + ".189"
        f.write_text(
            f'NODE_IP = os.getenv("NODE_IP", "{prod_ip}")\n'
            f'BOT_TOKEN = os.environ.get("BOT_TOKEN", "7123456789:AAEjklMNOpqrsTUVwxyz123456789abcdef")\n',
            encoding="utf-8",
        )
        scanner = SecurityAuditScanner(self.test_path, check_git=False)
        passed = scanner.run_scan()
        self.assertFalse(passed)
        rule_ids = [v.rule_id for v in scanner.violations]
        self.assertIn("INF-001", rule_ids)
        self.assertIn("SEC-001", rule_ids)

    def test_adv_04_bearer_token_header_format(self):
        """Test detection of Bearer tokens in standard HTTP header syntax (Bearer <token>)."""
        f = self.test_path / "http_client.py"
        f.write_text(
            'headers = {"Authorization": "Bearer abcdefghijklmnopqrstuvwxyz1234567890ABC"}\n',
            encoding="utf-8",
        )
        scanner = SecurityAuditScanner(self.test_path, check_git=False)
        passed = scanner.run_scan()
        self.assertFalse(passed)
        rule_ids = [v.rule_id for v in scanner.violations]
        self.assertIn("SEC-002", rule_ids)

    def test_adv_05_litestream_secret_key_naming(self):
        """Test detection of LITESTREAM_SECRET_KEY / LITESTREAM_ACCESS_KEY from PROJECT.md."""
        f = self.test_path / "backup_config.py"
        f.write_text(
            'LITESTREAM_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
            'LITESTREAM_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n',
            encoding="utf-8",
        )
        scanner = SecurityAuditScanner(self.test_path, check_git=False)
        passed = scanner.run_scan()
        self.assertFalse(passed)
        rule_ids = [v.rule_id for v in scanner.violations]
        self.assertIn("SEC-007", rule_ids)

    # -------------------------------------------------------------------------
    # Group 2: Private Key & Certificate Variations
    # -------------------------------------------------------------------------

    def test_adv_06_pem_header_variations(self):
        """Test PEM headers: ED25519, PGP, lowercase, certificates."""
        pem_dir = self.test_path / "keys"
        pem_dir.mkdir()

        (pem_dir / "ed25519.key.txt").write_text("-----BEGIN ED25519 PRIVATE KEY-----\nMC4CAQA...\n-----END ED25519 PRIVATE KEY-----\n", encoding="utf-8")
        (pem_dir / "pgp.key.txt").write_text("-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: BCPG...\n-----END PGP PRIVATE KEY BLOCK-----\n", encoding="utf-8")
        (pem_dir / "lower.key.txt").write_text("-----begin rsa private key-----\nMIIE...\n-----end rsa private key-----\n", encoding="utf-8")
        (pem_dir / "cert.crt.txt").write_text("-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----\n", encoding="utf-8")

        scanner = SecurityAuditScanner(self.test_path, check_git=False)
        passed = scanner.run_scan()
        self.assertFalse(passed)
        rule_ids = [v.rule_id for v in scanner.violations]
        self.assertIn("SEC-004", rule_ids)

    # -------------------------------------------------------------------------
    # Group 3: Magic Bytes & Disguised Binary Detection
    # -------------------------------------------------------------------------

    def test_adv_07_binary_null_byte_beyond_8192(self):
        """Test binary file with null byte placed beyond 8192 byte window."""
        f = self.test_path / "large_file.dat"
        # 9000 bytes of ASCII followed by null byte
        f.write_bytes(b"A" * 9000 + b"\x00" + b"B" * 100)

        scanner = SecurityAuditScanner(self.test_path, check_git=False)
        scanner.run_scan()

    def test_adv_08_truncated_binary_header(self):
        """Test truncated binary headers to ensure no unhandled exceptions."""
        f1 = self.test_path / "truncated_1.dat"
        f1.write_bytes(b"PK")

        f2 = self.test_path / "truncated_2.dat"
        f2.write_bytes(b"SQL")

        scanner = SecurityAuditScanner(self.test_path, check_git=False)
        passed = scanner.run_scan()
        self.assertTrue(passed)

    def test_adv_09_disguised_sqlite_and_zip(self):
        """Test disguised sqlite (.txt, .md) and zip (.png) files."""
        f_md = self.test_path / "notes.md"
        f_md.write_bytes(b"SQLite format 3\x00" + b"\x00" * 200)

        f_png = self.test_path / "image.png"
        f_png.write_bytes(b"PK\x03\x04" + b"\x00" * 200)

        scanner = SecurityAuditScanner(self.test_path, check_git=False)
        passed = scanner.run_scan()
        rule_ids = [v.rule_id for v in scanner.violations]
        self.assertFalse(passed)
        self.assertIn("BIN-001", rule_ids)

    # -------------------------------------------------------------------------
    # Group 4: Directory Structure, Symlinks & Deep Nesting
    # -------------------------------------------------------------------------

    def test_adv_10_deeply_nested_directory_tree(self):
        """Test scanning deeply nested directory tree (30 levels deep)."""
        curr = self.test_path
        for i in range(30):
            curr = curr / f"level_{i}"
        curr.mkdir(parents=True)
        prod_ip = "193" + ".233" + ".210" + ".189"
        (curr / "deep_leak.txt").write_text(f"IP={prod_ip}\n", encoding="utf-8")

        scanner = SecurityAuditScanner(self.test_path, check_git=False)
        scanner.run_scan()
        rule_ids = [v.rule_id for v in scanner.violations]
        self.assertIn("INF-001", rule_ids)

    def test_adv_11_ignored_directories_filtering(self):
        """Test that ignored directories (.git, .agents, node_modules, venv) are skipped."""
        git_dir = self.test_path / ".git"
        git_dir.mkdir()
        prod_ip = "193" + ".233" + ".210" + ".189"
        (git_dir / "git_leak.txt").write_text(f"IP={prod_ip}\n", encoding="utf-8")

        agents_dir = self.test_path / ".agents"
        agents_dir.mkdir()
        (agents_dir / "agent_leak.txt").write_text(f"IP={prod_ip}\n", encoding="utf-8")

        scanner = SecurityAuditScanner(self.test_path, check_git=False)
        passed = scanner.run_scan()
        self.assertTrue(passed)

    # -------------------------------------------------------------------------
    # Group 5: Unicode & Non-UTF-8 Files
    # -------------------------------------------------------------------------

    def test_adv_12_cp1251_and_malformed_utf8(self):
        """Test non-UTF-8 files (CP1251 Russian text) with secret IP."""
        f_cp1251 = self.test_path / "russian_cp1251.txt"
        prod_ip = "193" + ".233" + ".210" + ".189"
        raw_bytes = f"Сервер: {prod_ip}\n".encode("cp1251")
        f_cp1251.write_bytes(raw_bytes)

        scanner = SecurityAuditScanner(self.test_path, check_git=False)
        scanner.run_scan()
        rule_ids = [v.rule_id for v in scanner.violations]
        self.assertIn("INF-001", rule_ids)

    def test_adv_13_malformed_utf8_sequences(self):
        """Test malformed UTF-8 sequences mixed with token."""
        f = self.test_path / "malformed_utf8.txt"
        prod_ip = "193" + ".233" + ".210" + ".189"
        f.write_bytes(b"\xff\xfe\xfa\xbc " + f"IP={prod_ip}".encode("ascii") + b" \xfa\xfb\xff")

        scanner = SecurityAuditScanner(self.test_path, check_git=False)
        scanner.run_scan()
        rule_ids = [v.rule_id for v in scanner.violations]
        self.assertIn("INF-001", rule_ids)

    # -------------------------------------------------------------------------
    # Group 6: Scanner Self-Scan in Target Directory
    # -------------------------------------------------------------------------

    def test_adv_14_scanner_self_scan_in_target_export(self):
        """Test scanning a directory containing a copy of security_audit_scanner.py (as in github_export)."""
        export_scripts = self.test_path / "scripts"
        export_scripts.mkdir()
        scanner_src = PROJECT_ROOT / "scripts" / "security_audit_scanner.py"
        shutil.copy(scanner_src, export_scripts / "security_audit_scanner.py")

        scanner = SecurityAuditScanner(self.test_path, check_git=False)
        passed = scanner.run_scan()
        self.assertTrue(passed, f"Self-scan produced violations: {[v.to_dict() for v in scanner.violations]}")
        self.assertEqual(len(scanner.violations), 0)

    # -------------------------------------------------------------------------
    # Group 7: Exit Codes & CLI Flags
    # -------------------------------------------------------------------------

    def test_adv_15_cli_exit_codes_and_error_handling(self):
        """Test CLI exit codes for success (0), violation (1), and error (2)."""
        # Non-existent dir -> exit code 2
        bad_dir = self.test_path / "non_existent_folder_xyz"
        code_err = main(["--target-dir", str(bad_dir), "--no-git"])
        self.assertEqual(code_err, 2)

        # Clean dir -> exit code 0
        clean_file = self.test_path / "clean.py"
        clean_file.write_text("x = 100\n", encoding="utf-8")
        code_clean = main(["--target-dir", str(self.test_path), "--no-git"])
        self.assertEqual(code_clean, 0)

        # Dirty dir -> exit code 1
        dirty_file = self.test_path / "dirty.py"
        prod_ip = "193" + ".233" + ".210" + ".189"
        dirty_file.write_text(f'IP = "{prod_ip}"\n', encoding="utf-8")
        code_dirty = main(["--target-dir", str(self.test_path), "--no-git"])
        self.assertEqual(code_dirty, 1)

    def test_adv_16_telegram_token_boundaries(self):
        """Test 7-digit vs 10-digit vs 12-digit Telegram bot tokens."""
        f = self.test_path / "tokens.py"
        f.write_text(
            'TOKEN_7 = "1234567:AAEjklMNOpqrsTUVwxyz123456789abcdef"\n'
            'TOKEN_10 = "1234567890:AAEjklMNOpqrsTUVwxyz123456789abcdef"\n'
            'TOKEN_12 = "123456789012:AAEjklMNOpqrsTUVwxyz123456789abcdef"\n',
            encoding="utf-8",
        )
        scanner = SecurityAuditScanner(self.test_path, check_git=False)
        passed = scanner.run_scan()
        self.assertFalse(passed)
        rule_ids = [v.rule_id for v in scanner.violations]
        self.assertIn("SEC-001", rule_ids)


if __name__ == "__main__":
    unittest.main()
