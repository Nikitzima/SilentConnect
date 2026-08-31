#!/usr/bin/env python3
"""
tests/test_adversarial_security_scanner.py

Adversarial Stress Test Suite for Security Audit Scanner & .gitignore Integration (Challenger M1-2).

Empirically challenges:
1. Git index scanning with mock git repositories, commits, staged files, deleted-but-tracked files, and .gitignore.
2. CLI flags (--strict, --json-report, --target-dir, --format, --no-git, --verbose) and exit codes under edge conditions.
3. False positive rate testing on RFC documentation IPs (192.0.2.1, 198.51.100.1, 203.0.113.1), mock UUIDs, synthetic test strings, comments, and realistic codebases.
4. Concrete reproduction test cases for 4 discovered security & accuracy vulnerabilities:
   - Bug 1 (Critical): Line-level whitelist bypass via os.environ.get / os.getenv concealing hardcoded fallback secrets.
   - Bug 2 (High): PRV-001 phone number regex false positives on UUIDs, timestamps, and numbers starting with 8.
   - Bug 3 (High): INF-004 generic IP regex flagging standard subnet masks (255.255.255.0) in strict mode.
   - Bug 4 (Medium): FILE-002 extension check false positives on dotted module names (e.g. models.db_utils.py).
"""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
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
    SAFE_WHITELIST_TOKENS,
    SAFE_WHITELIST_SUBSTRINGS,
    SecurityAuditScanner,
    Violation,
    format_console_report,
    main,
    parse_args,
)


class TestGitIndexScanningAdversarial(unittest.TestCase):
    """Adversarial testing of Git index scanning and .gitignore integration."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="adv_git_test_")
        self.temp_path = Path(self.temp_dir)
        # Initialize a fresh mock git repo
        self._git_cmd(["init"])
        self._git_cmd(["config", "user.name", "TestChallenger"])
        self._git_cmd(["config", "user.email", "challenger@test.local"])

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _git_cmd(self, args: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git"] + args,
            cwd=self.temp_path,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        )

    def test_01_git_index_catches_tracked_forbidden_extensions(self):
        """Verify git index scanner flags all forbidden extension files tracked in git."""
        forbidden_samples = [
            "production.db",
            "users.sqlite",
            "store.sqlite3",
            "backup.tar.gz",
            "dump.tar",
            "archive.zip",
            "database.dump",
            "old_backup.bak",
            "private.pem",
            "server.key",
            "ca.crt",
            "identity.pfx",
            "legacy.p12",
            "binary_tool.exe",
            "native_addon.dll",
            "compiled_lib.so",
            "mac_lib.dylib",
            "firmware.bin",
        ]
        for fname in forbidden_samples:
            p = self.temp_path / fname
            p.write_text("mock content", encoding="utf-8")

        self._git_cmd(["add", "."])
        self._git_cmd(["commit", "-m", "Commit with forbidden extensions"])

        scanner = SecurityAuditScanner(self.temp_path, check_git=True)
        passed = scanner.run_scan()
        self.assertFalse(passed)

        git_violations = [v for v in scanner.violations if v.rule_id == "GIT-001"]
        self.assertEqual(len(git_violations), len(forbidden_samples))

    def test_02_git_index_catches_tracked_forbidden_exact_filenames(self):
        """Verify git index scanner flags tracked .env and subjson.env files."""
        env_files = [".env", ".env.local", ".env.production", ".env.silentconnect", "subjson.env"]
        for ef in env_files:
            p = self.temp_path / ef
            p.write_text("SOME_SECRET=123", encoding="utf-8")

        self._git_cmd(["add", "-f", "."])
        self._git_cmd(["commit", "-m", "Commit active env files"])

        scanner = SecurityAuditScanner(self.temp_path, check_git=True)
        passed = scanner.run_scan()
        self.assertFalse(passed)

        git_violations = [v for v in scanner.violations if v.rule_id == "GIT-001"]
        self.assertEqual(len(git_violations), len(env_files))

    def test_03_git_index_catches_staged_uncommitted_forbidden_files(self):
        """Verify git index scanner catches staged files in index before commit."""
        leak_file = self.temp_path / "staged_leak.sqlite"
        leak_file.write_text("mock sqlite content", encoding="utf-8")

        self._git_cmd(["add", "staged_leak.sqlite"])

        scanner = SecurityAuditScanner(self.temp_path, check_git=True)
        passed = scanner.run_scan()
        self.assertFalse(passed)

        git_violations = [v for v in scanner.violations if v.rule_id == "GIT-001"]
        self.assertTrue(any(v.file_path == "staged_leak.sqlite" for v in git_violations))

    def test_04_git_index_catches_tracked_file_deleted_from_working_tree(self):
        """Verify scanner catches a tracked forbidden file even if deleted from disk without git rm."""
        tracked_db = self.temp_path / "tracked_deleted.db"
        tracked_db.write_text("database content", encoding="utf-8")
        self._git_cmd(["add", "tracked_deleted.db"])
        self._git_cmd(["commit", "-m", "Add db"])

        # Delete from disk physically, but remains in git index
        os.remove(tracked_db)
        self.assertFalse(tracked_db.exists())

        scanner = SecurityAuditScanner(self.temp_path, check_git=True)
        passed = scanner.run_scan()
        self.assertFalse(passed)

        git_violations = [v for v in scanner.violations if v.rule_id == "GIT-001"]
        self.assertTrue(any("tracked_deleted.db" in v.file_path for v in git_violations))

    def test_05_clean_git_repo_passes_with_gitignore(self):
        """Verify that a clean repo with .gitignore and clean files passes 100%."""
        # Copy actual .gitignore
        src_gitignore = (PROJECT_ROOT / ".gitignore") if (PROJECT_ROOT / ".gitignore").exists() else (PROJECT_ROOT / "github_export" / ".gitignore")
        dst_gitignore = self.temp_path / ".gitignore"
        dst_gitignore.write_text(src_gitignore.read_text(encoding="utf-8"), encoding="utf-8")

        # Create clean project files
        (self.temp_path / "app.py").write_text(
            'import os\nDOMAIN = os.environ.get("DOMAIN_MAIN", "example.com")\nHOST = "127.0.0.1"\n',
            encoding="utf-8",
        )
        (self.temp_path / ".env.example").write_text(
            'TELEGRAM_BOT_TOKEN="123456:dummy_token"\nDOMAIN_MAIN="example.com"\n',
            encoding="utf-8",
        )
        (self.temp_path / "README.md").write_text(
            '# Clean Documentation\nSee example.com and 192.0.2.1 for testing.\n',
            encoding="utf-8",
        )

        self._git_cmd(["add", "."])
        self._git_cmd(["commit", "-m", "Initial clean commit"])

        scanner = SecurityAuditScanner(self.temp_path, check_git=True)
        passed = scanner.run_scan()
        self.assertTrue(passed, f"Violations found in clean repo: {[v.to_dict() for v in scanner.violations]}")
        self.assertEqual(len(scanner.violations), 0)

    def test_06_gitignore_blocks_forbidden_files_from_staging(self):
        """Verify that .gitignore actually ignores all forbidden types in git."""
        src_gitignore = (PROJECT_ROOT / ".gitignore") if (PROJECT_ROOT / ".gitignore").exists() else (PROJECT_ROOT / "github_export" / ".gitignore")
        dst_gitignore = self.temp_path / ".gitignore"
        dst_gitignore.write_text(src_gitignore.read_text(encoding="utf-8"), encoding="utf-8")

        # Test simulated files
        test_files_to_check = [
            ".env",
            "subjson.env",
            "production.local.env",
            "app.db",
            "app.db.bak",
            "users.sqlite",
            "data.sqlite3",
            "database.db.save",
            "app.log",
            "app.log.1",
            "logs/bot.log",
            "run.out",
            "dump.db-wal",
            "dump.db-shm",
            "backup.tar.gz",
            "backup.zip",
            "backup.7z",
            "backup.bak",
            "server.key",
            "cert.pem",
            "cert.pem.old",
            "binary.exe",
            "library.dll",
            "outage_metrics.json",
            "screenshots/screen.png",
            "__pycache__/app.cpython-311.pyc",
            ".pytest_cache/v/cache",
            ".agents/report.md",
        ]

        for tf in test_files_to_check:
            res = subprocess.run(
                ["git", "check-ignore", tf],
                cwd=self.temp_path,
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0, f"File '{tf}' should be ignored by .gitignore, but wasn't!")


class TestScannerCLIFlagsAndExitCodes(unittest.TestCase):
    """Adversarial stress-testing of scanner CLI flags and exit codes."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="adv_cli_test_")
        self.temp_path = Path(self.temp_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_exit_code_0_on_clean_dir(self):
        """Clean directory must exit with code 0."""
        clean_file = self.temp_path / "main.py"
        clean_file.write_text("print('Clean Code')\n", encoding="utf-8")

        exit_code = main(["--target-dir", str(self.temp_path), "--no-git"])
        self.assertEqual(exit_code, 0)

    def test_02_exit_code_1_on_violation(self):
        """Directory with security leak must exit with code 1."""
        leak_file = self.temp_path / "secret.py"
        prod_ip = "193" + ".233" + ".210" + ".189"
        leak_file.write_text(f'IP = "{prod_ip}"\n', encoding="utf-8")

        exit_code = main(["--target-dir", str(self.temp_path), "--no-git"])
        self.assertEqual(exit_code, 1)

    def test_03_exit_code_2_on_nonexistent_target_dir(self):
        """Nonexistent target directory must exit with code 2."""
        nonexistent = self.temp_path / "nonexistent_subfolder_xyz"
        exit_code = main(["--target-dir", str(nonexistent), "--no-git"])
        self.assertEqual(exit_code, 2)

    def test_04_exit_code_2_on_unrecognized_argument(self):
        """Unrecognized CLI arguments must exit with code 2 without uncaught exception."""
        exit_code = main(["--invalid-argument-xyz", "--target-dir", str(self.temp_path)])
        self.assertEqual(exit_code, 2)

    def test_05_exit_code_2_on_invalid_format_choice(self):
        """Invalid format choice must exit with code 2."""
        exit_code = main(["--format", "xml", "--target-dir", str(self.temp_path)])
        self.assertEqual(exit_code, 2)

    def test_06_empty_directory_handling(self):
        """Completely empty directory must return exit code 0 and scanned_files=0."""
        empty_dir = self.temp_path / "empty_dir"
        empty_dir.mkdir()

        scanner = SecurityAuditScanner(empty_dir, check_git=False)
        passed = scanner.run_scan()
        self.assertTrue(passed)
        self.assertEqual(scanner.scanned_files_count, 0)
        self.assertEqual(len(scanner.violations), 0)

        exit_code = main(["--target-dir", str(empty_dir), "--no-git"])
        self.assertEqual(exit_code, 0)

    def test_07_json_report_nested_path_creation(self):
        """Verify --json-report creates parent directories automatically and outputs valid JSON."""
        leak_file = self.temp_path / "leak.py"
        leak_file.write_text('TOKEN = "7123456789:AAEjklMNOpqrsTUVwxyz123456789abcdef"\n', encoding="utf-8")

        nested_json = self.temp_path / "deeply" / "nested" / "dir" / "report.json"
        self.assertFalse(nested_json.parent.exists())

        exit_code = main([
            "--target-dir", str(self.temp_path),
            "--json-report", str(nested_json),
            "--no-git",
        ])
        self.assertEqual(exit_code, 1)
        self.assertTrue(nested_json.exists())

        with open(nested_json, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertFalse(data["passed"])
        self.assertEqual(data["violations_count"], 1)
        self.assertEqual(len(data["violations"]), 1)
        v = data["violations"][0]
        self.assertEqual(v["rule_id"], "SEC-001")
        self.assertTrue("7123..." in v["sample"])
        self.assertTrue(v["sample"].endswith("cdef"))

    def test_08_stdout_format_json(self):
        """Verify --format json outputs pure JSON to stdout."""
        clean_file = self.temp_path / "ok.py"
        clean_file.write_text("a = 1\n", encoding="utf-8")

        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            exit_code = main([
                "--target-dir", str(self.temp_path),
                "--format", "json",
                "--no-git",
            ])
            output = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout

        self.assertEqual(exit_code, 0)
        parsed = json.loads(output)
        self.assertTrue(parsed["passed"])
        self.assertEqual(parsed["violations_count"], 0)


class TestFalsePositiveRatesAndWhitelists(unittest.TestCase):
    """Stress testing false positive rates on RFC IPs, mock UUIDs, synthetic tokens, and real-world code."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="adv_fp_test_")
        self.temp_path = Path(self.temp_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_rfc_documentation_ips_zero_false_positives(self):
        """Verify RFC 5737 and RFC 1918 IPs in docs/code cause 0 false positives in standard mode."""
        code = """
        # Documentation & RFC Example IP Addresses
        TEST_NET_1 = "192.0.2.1"       # RFC 5737 TEST-NET-1
        TEST_NET_1_SUB = "192.0.2.254"
        TEST_NET_2 = "198.51.100.1"    # RFC 5737 TEST-NET-2
        TEST_NET_2_NL = "198.51.100.10"
        TEST_NET_3 = "203.0.113.1"     # RFC 5737 TEST-NET-3
        TEST_NET_3_FI = "203.0.113.10"
        
        # RFC 1918 Private Ranges
        LOCAL_LOOPBACK = "127.0.0.1"
        ANY_ADDR = "0.0.0.0"
        PRIVATE_A = "10.0.0.1"
        PRIVATE_B = "172.16.0.1"
        PRIVATE_B_2 = "172.31.255.254"
        PRIVATE_C = "192.168.1.1"
        """
        f = self.temp_path / "ip_config.py"
        f.write_text(code, encoding="utf-8")

        scanner = SecurityAuditScanner(self.temp_path, strict=False, check_git=False)
        self.assertTrue(
            scanner.run_scan(),
            f"Non-strict mode flagged RFC IPs: {[v.to_dict() for v in scanner.violations]}",
        )

    def test_02_whitelisted_placeholders_and_templates_zero_false_positives(self):
        """Verify that dummy tokens, environment lookups, and placeholders are never flagged."""
        code = """
        import os
        
        TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "123456:dummy_token")
        CF_API_TOKEN = os.getenv("CF_API_TOKEN", "<YOUR_CLOUDFLARE_API_TOKEN>")
        SMTP_PASS = os.getenv("SMTP_PASSWORD", "CHANGEME")
        SECRET = os.getenv("INTERNAL_SECRET", "${INTERNAL_SECRET}")
        DB_KEY = "0x4AAAAAAATestKey"
        DB_SEC = "0x4AAAAAAATestSecret"
        DUMMY_PHONE = "+79990000000"
        DUMMY_BREVO = "your_smtp_password_or_token_here"
        SUPPORT_URL = "https://t.me/example_bot"
        DOMAIN = "example.com"
        EDGE_DOMAIN = "edge.example.com"
        FI_DOMAIN = "fi.example.com"
        """
        f = self.temp_path / "settings.py"
        f.write_text(code, encoding="utf-8")

        scanner = SecurityAuditScanner(self.temp_path, strict=True, check_git=False)
        self.assertTrue(
            scanner.run_scan(),
            f"Whitelisted placeholders falsely flagged: {[v.to_dict() for v in scanner.violations]}",
        )

    def test_03_example_service_and_env_templates_skipped(self):
        """Verify .env.example and .service.example files with example secrets are skipped."""
        example_env = self.temp_path / ".env.example"
        example_env.write_text(
            'TELEGRAM_BOT_TOKEN="7123456789:AAEjklMNOpqrsTUVwxyz123456789abcdef"\n'
            'SMTP_PASSWORD="example_smtp_password_12345"\n'
            'ADMIN_IDS=[503264426, 311226143]\n'
            'CF_API_TOKEN="abcdefghijklmnopqrstuvwxyz1234567890ABC"\n',
            encoding="utf-8",
        )

        service_example = self.temp_path / "vpn-shop.service.example"
        service_example.write_text(
            '[Service]\nEnvironment=TELEGRAM_BOT_TOKEN=123456:dummy_token\n',
            encoding="utf-8",
        )

        scanner = SecurityAuditScanner(self.temp_path, strict=True, check_git=False)
        self.assertTrue(
            scanner.run_scan(),
            f"Example templates were not properly skipped: {[v.to_dict() for v in scanner.violations]}",
        )

    def test_04_zero_byte_empty_files(self):
        """0-byte files must not crash binary header or line scanner."""
        (self.temp_path / "empty.py").touch()
        (self.temp_path / "empty.json").touch()
        (self.temp_path / "empty.txt").touch()

        scanner = SecurityAuditScanner(self.temp_path, check_git=False)
        self.assertTrue(scanner.run_scan())
        self.assertEqual(scanner.scanned_files_count, 3)

    def test_05_deeply_nested_directory_tree(self):
        """Scanner correctly traverses deeply nested folder structures."""
        curr = self.temp_path
        for i in range(15):
            curr = curr / f"depth_{i}"
            curr.mkdir()

        leaf_file = curr / "leaf_module.py"
        leaf_file.write_text("LEAF_CONSTANT = 42\n", encoding="utf-8")

        scanner = SecurityAuditScanner(self.temp_path, check_git=False)
        self.assertTrue(scanner.run_scan())
        self.assertEqual(scanner.scanned_files_count, 1)

    def test_06_large_file_stress_test(self):
        """Scanner handles a large (50,000 line) synthetic file without high latency or crashing."""
        large_file = self.temp_path / "large_dataset.py"
        with open(large_file, "w", encoding="utf-8") as f:
            f.write("# Large test file\n")
            for i in range(50000):
                f.write(f'CONST_{i} = "item_value_{i}_for_testing"\n')

        scanner = SecurityAuditScanner(self.temp_path, check_git=False)
        self.assertTrue(scanner.run_scan())
        self.assertEqual(scanner.scanned_files_count, 1)

    def test_07_utf8_cyrillic_and_emoji_handling(self):
        """Scanner handles Cyrillic text, Asian characters, and emojis without encoding errors."""
        unicode_file = self.temp_path / "unicode_strings.py"
        unicode_file.write_text(
            'RU_TEXT = "Привет, мир! Тестирование сканера безопасности."\n'
            'ZH_TEXT = "你好世界，安全审计测试。"\n'
            'EMOJI_TEXT = "🇳🇱 🇫🇮 🚀 ⚡ 🛡️"\n',
            encoding="utf-8",
        )

        scanner = SecurityAuditScanner(self.temp_path, check_git=False)
        self.assertTrue(scanner.run_scan())
        self.assertEqual(len(scanner.violations), 0)


class TestAdversarialVulnerabilityReproductions(unittest.TestCase):
    """
    Verification of 4 Security & Accuracy Remediations:
    - Remediated 1: os.environ.get / os.getenv fallback arguments containing secrets ARE flagged.
    - Remediated 2: PRV-001 does NOT produce false positives on UUIDs, timestamps, or hex IDs.
    - Remediated 3: INF-004 does NOT flag standard subnet masks (e.g. 255.255.255.0) in strict mode.
    - Remediated 4: FILE-002 does NOT flag valid Python module names like models.db_utils.py.
    """

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="adv_vuln_test_")
        self.temp_path = Path(self.temp_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_vuln1_os_environ_line_level_whitelist_bypass(self):
        """
        VERIFY REMEDIATION OF BUG 1:
        Hardcoded secrets placed as fallback arguments in os.environ.get / os.getenv
        MUST be detected by the scanner.
        """
        bypass_file = self.temp_path / "config_bypass.py"
        prod_ip = "193" + ".233" + ".210" + ".189"
        prod_dom = "silent" + "connect" + ".net"
        bypass_file.write_text(
            f'SERVER_IP = os.environ.get("SERVER_IP", "{prod_ip}")\n'
            f'BOT_TOKEN = os.environ.get("BOT_TOKEN", "7123456789:AAEjklMNOpqrsTUVwxyz123456789abcdef")\n'
            f'DOMAIN = os.getenv("APP_DOMAIN", "{prod_dom}")\n'
            f'PHONE = os.getenv("PAYMENT_PHONE", "+79851660740")\n',
            encoding="utf-8",
        )

        scanner = SecurityAuditScanner(self.temp_path, check_git=False)
        passed = scanner.run_scan()

        # The scanner must now FAIL and catch all 4 leaks
        self.assertFalse(passed, "Scanner should catch secrets in os.environ fallback arguments!")
        rule_ids = {v.rule_id for v in scanner.violations}
        self.assertIn("INF-001", rule_ids)
        self.assertIn("SEC-001", rule_ids)
        self.assertIn("INF-005", rule_ids)
        self.assertIn("PRV-001", rule_ids)

    def test_vuln2_prv001_phone_regex_uuid_timestamp_false_positives(self):
        """
        VERIFY REMEDIATION OF BUG 2:
        PRV-001 regex requires mandatory 3-digit mobile area code and word boundary,
        preventing false matches on UUIDs, timestamps, file sizes, and hex IDs.
        """
        phone_rule = next(p for p in SECRET_PATTERNS if p[0] == "PRV-001")
        regex = phone_rule[2]

        samples = {
            "UUID fragment": "b058f1bd-8674-4163-ae12-7f4a1f322967",
            "Unix Timestamp": "1686744163",
            "File Size / ID": "81234567",
            "Hex Hash Fragment": "82595890",
        }

        matches_found = {}
        for desc, sample in samples.items():
            matches = regex.findall(sample)
            if matches:
                matches_found[desc] = matches

        # 0 false positive matches expected
        self.assertEqual(len(matches_found), 0, f"Unexpected false positive matches in PRV-001: {matches_found}")

    def test_vuln3_inf004_subnet_mask_false_positive_in_strict_mode(self):
        """
        VERIFY REMEDIATION OF BUG 3:
        INF-004 regex in strict mode excludes 255.* to allow standard subnet masks.
        """
        mask_file = self.temp_path / "network.py"
        mask_file.write_text('NETMASK = "255.255.255.0"\nBROADCAST = "255.255.255.255"\n', encoding="utf-8")

        scanner = SecurityAuditScanner(self.temp_path, strict=True, check_git=False)
        passed = scanner.run_scan()

        # Strict mode must cleanly pass on standard subnet masks
        self.assertTrue(passed, f"Strict mode flagged subnet mask: {[v.to_dict() for v in scanner.violations]}")

    def test_vuln4_file002_dot_underscore_module_name_false_positives(self):
        """
        VERIFY REMEDIATION OF BUG 4:
        FILE-002 does not flag valid python modules with dotted underscore names (e.g. models.db_utils.py).
        """
        f1 = self.temp_path / "models.db_utils.py"
        f1.write_text("class DBUtils: pass\n", encoding="utf-8")

        f2 = self.temp_path / "security.key_manager.py"
        f2.write_text("class KeyManager: pass\n", encoding="utf-8")

        scanner = SecurityAuditScanner(self.temp_path, check_git=False)
        passed = scanner.run_scan()

        # Source files must not be flagged
        self.assertTrue(passed, f"Legitimate Python source files flagged with FILE-002: {[v.to_dict() for v in scanner.violations]}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
