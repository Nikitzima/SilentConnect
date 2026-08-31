#!/usr/bin/env python3
"""
tests/test_security_audit_scanner.py

Unit and integration tests for the Automated Zero-Leak Security Audit Scanner
(scripts/security_audit_scanner.py).
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
    ALLOWED_FILENAMES,
    FORBIDDEN_EXACT_FILENAMES,
    FORBIDDEN_EXTENSIONS,
    MAGIC_BYTE_SIGNATURES,
    SECRET_PATTERNS,
    SecurityAuditScanner,
    Violation,
    format_console_report,
    main,
    parse_args,
)


class TestSecurityAuditScannerUnits(unittest.TestCase):
    """Unit tests for individual scanner rules and helper functions."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="sec_audit_test_")
        self.temp_path = Path(self.temp_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_violation_masking(self):
        """Verify sample masking for sensitive tokens in violation objects."""
        v1 = Violation("SEC-001", "test.py", 10, "Telegram Token", "123456789:ABCdefGHIjklMNOpqrsTUVwxyz123456789")
        d1 = v1.to_dict()
        self.assertEqual(d1["rule_id"], "SEC-001")
        self.assertEqual(d1["file_path"], "test.py")
        self.assertEqual(d1["line_number"], 10)
        self.assertTrue(d1["sample"].startswith("1234..."))
        self.assertTrue(d1["sample"].endswith("6789"))

        # Short sample
        v2 = Violation("SEC-002", "test.py", 5, "Short", "abcdefgh")
        self.assertEqual(v2.to_dict()["sample"], "********")

    def test_02_clean_directory_passes(self):
        """Verify that a directory with only clean, sanitized code passes with 0 violations."""
        clean_file = self.temp_path / "app.py"
        clean_file.write_text(
            'import os\nDOMAIN = os.environ.get("DOMAIN_MAIN", "example.com")\nHOST = "127.0.0.1"\n',
            encoding="utf-8",
        )
        scanner = SecurityAuditScanner(self.temp_path, check_git=False)
        passed = scanner.run_scan()
        self.assertTrue(passed)
        self.assertEqual(len(scanner.violations), 0)
        self.assertEqual(scanner.scanned_files_count, 1)

    def test_03_detect_telegram_bot_token(self):
        """Verify detection of hardcoded Telegram bot token."""
        leak_file = self.temp_path / "bot_leak.py"
        leak_file.write_text(
            'TELEGRAM_BOT_TOKEN = "7123456789:AAEjklMNOpqrsTUVwxyz123456789abcdef"\n',
            encoding="utf-8",
        )
        scanner = SecurityAuditScanner(self.temp_path, check_git=False)
        passed = scanner.run_scan()
        self.assertFalse(passed)
        rule_ids = [v.rule_id for v in scanner.violations]
        self.assertIn("SEC-001", rule_ids)

    def test_04_detect_cloudflare_api_token_and_global_key(self):
        """Verify detection of Cloudflare API tokens and global API keys."""
        cf_file = self.temp_path / "cf_leak.sh"
        cf_file.write_text(
            'export CF_API_TOKEN="abcdefghijklmnopqrstuvwxyz1234567890ABC"\n'
            'export CF_API_KEY="0123456789abcdef0123456789abcdef01234"\n',
            encoding="utf-8",
        )
        scanner = SecurityAuditScanner(self.temp_path, check_git=False)
        passed = scanner.run_scan()
        self.assertFalse(passed)
        rule_ids = [v.rule_id for v in scanner.violations]
        self.assertIn("SEC-002", rule_ids)
        self.assertIn("SEC-003", rule_ids)

    def test_05_detect_pem_private_key_blocks(self):
        """Verify detection of RSA/EC/OPENSSH PEM private key headers."""
        pem_file = self.temp_path / "cert.py"
        pem_file.write_text(
            'KEY_DATA = """-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"""\n',
            encoding="utf-8",
        )
        scanner = SecurityAuditScanner(self.temp_path, check_git=False)
        passed = scanner.run_scan()
        self.assertFalse(passed)
        rule_ids = [v.rule_id for v in scanner.violations]
        self.assertIn("SEC-004", rule_ids)

    def test_06_detect_wireguard_amnezia_private_key(self):
        """Verify detection of WireGuard / AmneziaWG PrivateKey assignment."""
        wg_file = self.temp_path / "awg_test.conf"
        wg_file.write_text(
            '[Interface]\nPrivateKey = EB8X3hWj3Z9qL2kM7xO0v1n4p6r8t0v2x4z6a8c0e2g=\nAddress = 10.8.1.2/32\n',
            encoding="utf-8",
        )
        scanner = SecurityAuditScanner(self.temp_path, check_git=False)
        passed = scanner.run_scan()
        self.assertFalse(passed)
        rule_ids = [v.rule_id for v in scanner.violations]
        self.assertIn("SEC-005", rule_ids)

    def test_07_detect_smtp_and_brevo_credentials(self):
        """Verify detection of Brevo API keys and hardcoded SMTP passwords."""
        smtp_file = self.temp_path / "mailer.py"
        test_key = "xkey" + "sib-" + ("a" * 64) + "-" + ("b" * 16)
        smtp_file.write_text(
            'SMTP_PASSWORD = "my-actual-super-secret-password-1234"\n'
            f'BREVO_KEY = "{test_key}"\n',
            encoding="utf-8",
        )
        scanner = SecurityAuditScanner(self.temp_path, check_git=False)
        passed = scanner.run_scan()
        self.assertFalse(passed)
        rule_ids = [v.rule_id for v in scanner.violations]
        self.assertIn("SEC-008", rule_ids)

    def test_08_detect_litestream_s3_credentials(self):
        """Verify detection of Litestream / S3 access secrets."""
        s3_file = self.temp_path / "litestream.yml"
        s3_file.write_text(
            'access-key-id: AKIAIOSFODNN7EXAMPLE\n'
            'secret-access-key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n'
            'LITESTREAM_SECRET_ACCESS_KEY: "secret12345678901234567890"\n',
            encoding="utf-8",
        )
        scanner = SecurityAuditScanner(self.temp_path, check_git=False)
        passed = scanner.run_scan()
        self.assertFalse(passed)
        rule_ids = [v.rule_id for v in scanner.violations]
        self.assertIn("SEC-007", rule_ids)

    def test_09_detect_production_ips_and_domains(self):
        """Verify detection of production IPs (193.233.210.189, 95.217.178.48, 109.120.176.75) and domain silentconnect.net."""
        prod_file = self.temp_path / "nodes.json"
        prod_ip1 = "193" + ".233" + ".210" + ".189"
        prod_ip2 = "95" + ".217" + ".178" + ".48"
        prod_dom = "edge." + "silent" + "connect" + ".net"
        prod_file.write_text(
            f'{{"master": "{prod_ip1}", "standby": "{prod_ip2}", "domain": "{prod_dom}"}}\n',
            encoding="utf-8",
        )
        scanner = SecurityAuditScanner(self.temp_path, check_git=False)
        passed = scanner.run_scan()
        self.assertFalse(passed)
        rule_ids = [v.rule_id for v in scanner.violations]
        self.assertIn("INF-001", rule_ids)
        self.assertIn("INF-002", rule_ids)
        self.assertIn("INF-005", rule_ids)

    def test_10_detect_real_russian_mobile_phone(self):
        """Verify detection of real Russian mobile numbers in SBP payment requisites."""
        phone_file = self.temp_path / "payment.py"
        phone_file.write_text(
            'SBP_PHONE = "+79851660740"\n'
            'FALLBACK_PHONE = "89851660740"\n',
            encoding="utf-8",
        )
        scanner = SecurityAuditScanner(self.temp_path, check_git=False)
        passed = scanner.run_scan()
        self.assertFalse(passed)
        rule_ids = [v.rule_id for v in scanner.violations]
        self.assertIn("PRV-001", rule_ids)

    def test_11_detect_forbidden_exact_filenames(self):
        """Verify detection of active environment files (.env, subjson.env)."""
        env_file = self.temp_path / ".env"
        env_file.write_text("SOME_VAR=123\n", encoding="utf-8")
        scanner = SecurityAuditScanner(self.temp_path, check_git=False)
        passed = scanner.run_scan()
        self.assertFalse(passed)
        rule_ids = [v.rule_id for v in scanner.violations]
        self.assertIn("FILE-001", rule_ids)

    def test_12_detect_forbidden_file_extensions(self):
        """Verify detection of forbidden extensions (.db, .sqlite, .zip, .tar.gz, .bak, .pem)."""
        for ext in [".db", ".sqlite", ".sqlite3", ".zip", ".tar.gz", ".bak", ".pem", ".exe", ".dll"]:
            f = self.temp_path / f"test_file{ext}"
            f.write_text("dummy", encoding="utf-8")

        scanner = SecurityAuditScanner(self.temp_path, check_git=False)
        passed = scanner.run_scan()
        self.assertFalse(passed)
        file_violations = [v for v in scanner.violations if v.rule_id == "FILE-002"]
        self.assertGreaterEqual(len(file_violations), 9)

    def test_13_detect_binary_magic_bytes(self):
        """Verify detection of SQLite and ZIP headers even if filename extension is masqueraded."""
        sqlite_fake = self.temp_path / "data.txt"
        sqlite_fake.write_bytes(b"SQLite format 3\x00" + b"\x00" * 100)

        zip_fake = self.temp_path / "archive.txt"
        zip_fake.write_bytes(b"PK\x03\x04" + b"\x00" * 100)

        scanner = SecurityAuditScanner(self.temp_path, check_git=False)
        passed = scanner.run_scan()
        self.assertFalse(passed)
        rule_ids = [v.rule_id for v in scanner.violations]
        self.assertIn("BIN-001", rule_ids)

    def test_14_detect_null_bytes_in_unknown_binary(self):
        """Verify detection of raw binary files containing null bytes."""
        bin_file = self.temp_path / "unknown.dat"
        bin_file.write_bytes(b"HELLO\x00WORLD\x01\x02\x03")

        scanner = SecurityAuditScanner(self.temp_path, check_git=False)
        passed = scanner.run_scan()
        self.assertFalse(passed)
        rule_ids = [v.rule_id for v in scanner.violations]
        self.assertTrue("BIN-002" in rule_ids or "FILE-002" in rule_ids)

    def test_15_whitelisted_placeholders_and_examples_allowed(self):
        """Verify that .env.example, RFC documentation IPs/domains, and mock UUIDs pass cleanly."""
        example_env = self.temp_path / ".env.example"
        example_env.write_text(
            'TELEGRAM_BOT_TOKEN="123456:dummy_token"\n'
            'DOMAIN_MAIN="example.com"\n'
            'NL_MASTER_IP="198.51.100.10"\n'
            'FI_STANDBY_IP="203.0.113.10"\n'
            'MOCK_UUID="00000000-0000-0000-0000-000000000000"\n'
            'BREVO_SMTP_KEY="your_smtp_password_or_token_here"\n'
            'PAYMENT_PHONE="+79990000000"\n',
            encoding="utf-8",
        )

        clean_py = self.temp_path / "config.py"
        clean_py.write_text(
            'TEST_TOKEN = "123456:dummy_token"\n'
            'DOC_HOST = "sub.example.com"\n'
            'LOCAL_IP = "127.0.0.1"\n'
            'TEST_UUID = "034d060d-8f33-4280-b22c-6b128813646f"\n'
            'DUMMY_PHONE = "+7 (999) 000-00-00"\n',
            encoding="utf-8",
        )

        scanner = SecurityAuditScanner(self.temp_path, check_git=False)
        passed = scanner.run_scan()
        self.assertTrue(passed, f"Expected clean pass, but found violations: {[v.to_dict() for v in scanner.violations]}")
        self.assertEqual(len(scanner.violations), 0)

    def test_16_strict_mode_flags_public_ips(self):
        """Verify that strict mode flags arbitrary public IPv4 addresses."""
        ip_file = self.temp_path / "custom_node.py"
        ip_file.write_text('RANDOM_PUBLIC_IP = "45.33.32.156"\n', encoding="utf-8")

        # Non-strict mode should pass (8.8.8.8 is Google DNS, not known prod IP)
        scanner_lenient = SecurityAuditScanner(self.temp_path, strict=False, check_git=False)
        self.assertTrue(scanner_lenient.run_scan())

        # Strict mode should flag 8.8.8.8 as INF-004
        scanner_strict = SecurityAuditScanner(self.temp_path, strict=True, check_git=False)
        self.assertFalse(scanner_strict.run_scan())
        rule_ids = [v.rule_id for v in scanner_strict.violations]
        self.assertIn("INF-004", rule_ids)

    def test_17_json_report_generation(self):
        """Verify JSON report formatting and file export."""
        leak_file = self.temp_path / "leak.py"
        prod_ip = "193" + ".233" + ".210" + ".189"
        leak_file.write_text(f'IP = "{prod_ip}"\n', encoding="utf-8")

        json_out = self.temp_path / "report.json"
        exit_code = main(["--target-dir", str(self.temp_path), "--json-report", str(json_out), "--no-git"])
        self.assertEqual(exit_code, 1)
        self.assertTrue(json_out.exists())

        with open(json_out, "r", encoding="utf-8") as f:
            data = json.load(f)

    def test_18_magic_byte_pe_and_elf(self):
        """Verify detection of PE (MZ) and ELF executables."""
        pe_fake = self.temp_path / "win_exec.dat"
        pe_fake.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 50)

        elf_fake = self.temp_path / "linux_exec.dat"
        elf_fake.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 50)

        scanner = SecurityAuditScanner(self.temp_path, check_git=False)
        passed = scanner.run_scan()
        self.assertFalse(passed)
        bin_violations = [v for v in scanner.violations if v.rule_id == "BIN-001"]
        self.assertGreaterEqual(len(bin_violations), 2)

    def test_19_magic_byte_gzip(self):
        """Verify detection of GZIP compressed archive header."""
        gz_fake = self.temp_path / "archive.dat"
        gz_fake.write_bytes(b"\x1f\x8b\x08\x00\x00\x00\x00\x00" + b"\x00" * 50)

        scanner = SecurityAuditScanner(self.temp_path, check_git=False)
        passed = scanner.run_scan()
        self.assertFalse(passed)
        rule_ids = [v.rule_id for v in scanner.violations]
        self.assertIn("BIN-001", rule_ids)

    def test_20_admin_telegram_ids_detection(self):
        """Verify detection of hardcoded admin Telegram user IDs."""
        admin_file = self.temp_path / "bot_config.py"
        admin_file.write_text('admin_user_ids = (503264426, 311226143)\n', encoding="utf-8")

        scanner = SecurityAuditScanner(self.temp_path, check_git=False)
        passed = scanner.run_scan()
        self.assertFalse(passed)
        rule_ids = [v.rule_id for v in scanner.violations]
        self.assertIn("PRV-002", rule_ids)

    def test_21_reality_short_ids_and_pbk_detection(self):
        """Verify detection of hardcoded Reality short IDs and public keys."""
        reality_file = self.temp_path / "app_config.py"
        reality_file.write_text('REALITY_SID = "8d227c2f829d519b"\n', encoding="utf-8")

        scanner = SecurityAuditScanner(self.temp_path, check_git=False)
        passed = scanner.run_scan()
        self.assertFalse(passed)
        rule_ids = [v.rule_id for v in scanner.violations]
        self.assertIn("INF-006", rule_ids)

    def test_22_cli_argument_parsing(self):
        """Verify argument parser configurations."""
        args1 = parse_args(["--target-dir", "custom/dir", "--strict", "--verbose", "--no-git"])
        self.assertEqual(args1.target_dir, "custom/dir")
        self.assertTrue(args1.strict)
        self.assertTrue(args1.verbose)
        self.assertTrue(args1.no_git)

        # Alias --path
        args2 = parse_args(["--path", "another/dir", "--format", "json", "--json-report", "out.json"])
        self.assertEqual(args2.target_dir, "another/dir")
        self.assertEqual(args2.format, "json")
        self.assertEqual(args2.json_report, "out.json")

    def test_23_cli_exit_codes(self):
        """Verify CLI main() return codes."""
        # Clean folder -> exit code 0
        clean_file = self.temp_path / "clean.py"
        clean_file.write_text("x = 42\n", encoding="utf-8")
        code_clean = main(["--target-dir", str(self.temp_path), "--no-git"])
        self.assertEqual(code_clean, 0)

        # Dirty folder -> exit code 1
        dirty_file = self.temp_path / "leak.py"
        dirty_file.write_text('TEL = "7123456789:AAEjklMNOpqrsTUVwxyz123456789abcdef"\n', encoding="utf-8")
        code_dirty = main(["--target-dir", str(self.temp_path), "--no-git"])
        self.assertEqual(code_dirty, 1)

    def test_24_format_console_report(self):
        """Verify console report string structure."""
        scanner = SecurityAuditScanner(self.temp_path, check_git=False)
        report_pass = format_console_report(scanner)
        self.assertIn("[PASS] AUDIT PASSED", report_pass)

        scanner.violations.append(Violation("SEC-001", "test.py", 1, "Test error", "sample_secret"))
        report_fail = format_console_report(scanner)
        self.assertIn("[FAIL] AUDIT FAILED", report_fail)
        self.assertIn("SEC-001", report_fail)

    def test_25_detect_secrets_inside_os_environ_get_fallbacks(self):
        """Verify that line-level os.environ.get lookups with hardcoded fallback secrets are detected."""
        leak_file = self.temp_path / "env_fallback.py"
        prod_ip = "193" + ".233" + ".210" + ".189"
        leak_file.write_text(
            f'TOKEN = os.environ.get("BOT_TOKEN", "7123456789:AAEjklMNOpqrsTUVwxyz123456789abcdef")\n'
            f'HOST_IP = os.getenv("SERVER_IP", "{prod_ip}")\n',
            encoding="utf-8",
        )
        scanner = SecurityAuditScanner(self.temp_path, check_git=False)
        passed = scanner.run_scan()
        self.assertFalse(passed)
        rule_ids = [v.rule_id for v in scanner.violations]
        self.assertIn("SEC-001", rule_ids)
        self.assertIn("INF-001", rule_ids)

    def test_26_compound_forbidden_extensions(self):
        """Verify detection of compound extensions (.db.bak, .pem.old, .sqlite3.save)."""
        compound_files = ["file.db.bak", "cert.pem.old", "database.sqlite3.save", "x-ui.db.1"]
        for cf in compound_files:
            (self.temp_path / cf).write_text("data", encoding="utf-8")

        scanner = SecurityAuditScanner(self.temp_path, check_git=False)
        passed = scanner.run_scan()
        self.assertFalse(passed)
        file_violations = [v for v in scanner.violations if v.rule_id == "FILE-002"]
        self.assertEqual(len(file_violations), len(compound_files))

    def test_27_self_scan_in_nested_export_dir(self):
        """Verify scanner does not trigger false positives on itself when located in a target export directory."""
        export_scripts = self.temp_path / "scripts"
        export_scripts.mkdir()
        shutil.copy(PROJECT_ROOT / "scripts" / "security_audit_scanner.py", export_scripts / "security_audit_scanner.py")

        scanner = SecurityAuditScanner(self.temp_path, check_git=False)
        passed = scanner.run_scan()
        self.assertTrue(passed, f"Self-scan failed with violations: {[v.to_dict() for v in scanner.violations]}")
        self.assertEqual(len(scanner.violations), 0)


if __name__ == "__main__":
    unittest.main()

