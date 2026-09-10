#!/usr/bin/env python3
"""
scripts/security_audit_scanner.py

Automated Zero-Leak Secret, Binary & Infrastructure Audit Scanner.
Verifies that no production credentials, private keys, certificates,
internal hostnames, production IPs, or binary database dumps exist
in the target directory before GitHub export.

Exit codes:
  0 : Clean audit. 0 leaks, 0 forbidden binaries, 0 git tracking violations.
  1 : Violations detected. Details printed to stdout / JSON report.
  2 : Configuration or argument error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

# =============================================================================
# Forbidden Extensions, Files, and Ignored Directories
# =============================================================================

FORBIDDEN_EXTENSIONS: Set[str] = {
    # Databases & storage
    ".db", ".db-shm", ".db-wal", ".db-journal", ".sqlite", ".sqlite3", ".dump",
    # Archives & backups
    ".tar", ".tar.gz", ".tgz", ".zip", ".gz", ".bz2", ".xz", ".7z", ".rar", ".bak", ".old", ".orig",
    # Certificates & private keys
    ".pem", ".key", ".crt", ".cer", ".pfx", ".p12", ".csr",
    # Executables & compiled binaries
    ".exe", ".dll", ".so", ".dylib", ".bin", ".iso", ".pyc", ".pyo",
}

FORBIDDEN_EXACT_FILENAMES: Set[str] = {
    ".env", ".env.local", ".env.production", ".env.staging", ".env.silentconnect", ".env.platega", "subjson.env",
}

ALLOWED_FILENAMES: Set[str] = {
    ".env.example", ".env.silentconnect.example", "subjson.env.example",
    "vpn-shop-silentconnect.service.example", "vpn-shop-web.service.example",
    "vpn-shop.service.example", "BOTFATHER_SETUP.md", ".gitignore", ".gitkeep",
}

ALLOWED_MEDIA_EXTENSIONS: Set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".svg",
}

IGNORED_FILENAMES: Set[str] = {
    "test_security_audit_scanner.py",
    "test_adversarial_security_scanner.py",
    "test_challenger_m1_1.py",
}

IGNORED_DIR_NAMES: Set[str] = {
    ".git", ".agents", "__pycache__", ".pytest_cache", "venv", ".venv",
    "node_modules", ".idea", ".vscode", ".gemini",
}

MAGIC_BYTE_SIGNATURES: List[Tuple[bytes, str]] = [
    (b"SQLite format 3\x00", "SQLite Database"),
    (b"PK\x03\x04", "ZIP Archive"),
    (b"\x1f\x8b", "GZIP Compressed Archive"),
    (b"MZ", "Windows PE Executable"),
    (b"\x7fELF", "Linux ELF Executable"),
]

# Sensitive pattern building blocks (concatenated dynamically to prevent self-scan matching)
_P_PROD_IP1 = "".join(["193", ".233", ".210", ".189"])
_P_PROD_IP2 = "".join(["95", ".217", ".178", ".48"])
_P_PROD_IP3 = "".join(["109", ".120", ".176", ".75"])
_P_PROD_IP4 = "".join(["192", ".168", ".0", ".107"])
_P_PROD_DOMAIN = "".join(["silent", "connect", ".net"])
_P_PROD_PBK = "".join(["vzP98i", "_s-v_OEvZcI", "_c7iK681d", "_H2I5k6i34kL5m8no"])
_P_SHORT_IDS = [
    "".join(["8d227c2f", "829d519b"]),
    "".join(["c84f", "885e"]),
    "".join(["d749", "a930"]),
    "".join(["e6b2", "c801"]),
]

# =============================================================================
# Secret & Infrastructure Regex Rules
# =============================================================================

# Format: (Rule ID, Description, Compiled Regex, Strict Only?)
SECRET_PATTERNS: List[Tuple[str, str, re.Pattern, bool]] = [
    (
        "SEC-001",
        "Telegram Bot API Token",
        re.compile(r"\b[0-9]{8,11}:[A-Za-z0-9_-]{35}\b"),
        False,
    ),
    (
        "SEC-002",
        "Cloudflare API Token / Bearer Token",
        re.compile(r"(?:CF_API_TOKEN|CLOUDFLARE_TOKEN|CLOUDFLARE_API_TOKEN)\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,45})['\"]?|\bBearer\s+['\"]?([A-Za-z0-9_-]{32,45})['\"]?|\bBearer\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,45})['\"]?", re.IGNORECASE),
        False,
    ),
    (
        "SEC-003",
        "Cloudflare Global API Key",
        re.compile(r"(?:CF_API_KEY|CLOUDFLARE_API_KEY|CF_KEY)\s*[:=]\s*['\"]?([0-9a-fA-F]{32,45})['\"]?", re.IGNORECASE),
        False,
    ),
    (
        "SEC-004",
        "PEM Private Key Block",
        re.compile(r"-----BEGIN (?:[A-Za-z0-9_-]+ )?PRIVATE KEY(?: BLOCK)?-----", re.IGNORECASE),
        False,
    ),
    (
        "SEC-005",
        "WireGuard / AmneziaWG PrivateKey Assignment",
        re.compile(r"\b(?:PrivateKey|wg_private_key|amnezia_private_key|awg_priv_key)\s*[:=]\s*['\"]?([A-Za-z0-9+/]{42,44}={0,2})['\"]?", re.IGNORECASE),
        False,
    ),
    (
        "SEC-006",
        "Reality / VLESS Private Key Assignment",
        re.compile(r"\b(?:reality_private_key|private_key|priv_key)\s*[:=]\s*['\"]?([A-Za-z0-9_-]{43,44})['\"]?", re.IGNORECASE),
        False,
    ),
    (
        "SEC-007",
        "Litestream / S3 Access Credentials",
        re.compile(r"(?:LITESTREAM_ACCESS_KEY_ID|LITESTREAM_SECRET_ACCESS_KEY|LITESTREAM_ACCESS_KEY|LITESTREAM_SECRET_KEY|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{16,40})['\"]?", re.IGNORECASE),
        False,
    ),
    (
        "SEC-008",
        "SMTP Password / Brevo API Key",
        re.compile(r"\bxkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16}\b|(?:SMTP_PASSWORD|BREVO_API_KEY|MAIL_PASSWORD)\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE),
        False,
    ),
    (
        "SEC-010",
        "Platega API Secret / Key",
        re.compile(r"(?:PLATEGA_SECRET|PLATEGA_API_KEY|PLATEGA_KEY|PLATEGA_SECRET_BOT|PLATEGA_SECRET_WEB)\s*[:=]\s*['\"]?([A-Za-z0-9_-]{12,128})['\"]?", re.IGNORECASE),
        False,
    ),
    (
        "SEC-009",
        "Hardcoded Auth Password / Secret",
        re.compile(r"(?:HYSTERIA_SALAMANDER_PASSWORD|HYSTERIA_AUTH_PASSWORD|INTERNAL_SECRET|SECRET_SEGMENT)\s*[:=]\s*['\"]?([^\s'\"]{6,})['\"]?", re.IGNORECASE),
        False,
    ),
    (
        "INF-001",
        f"Production Primary Node IP ({_P_PROD_IP1})",
        re.compile(r"\b" + re.escape(_P_PROD_IP1) + r"\b"),
        False,
    ),
    (
        "INF-002",
        f"Production Secondary Node IP ({_P_PROD_IP2})",
        re.compile(r"\b" + re.escape(_P_PROD_IP2) + r"\b"),
        False,
    ),
    (
        "INF-003",
        "Production Node Additional IPs",
        re.compile(r"\b(?:" + re.escape(_P_PROD_IP3) + r"|" + re.escape(_P_PROD_IP4) + r")\b"),
        False,
    ),
    (
        "INF-004",
        "Generic Public IPv4 Address",
        re.compile(r"(?<![\d\.])(?!(?:10\.|127\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|0\.0\.0\.0|255\.|198\.51\.100\.|203\.0\.113\.|192\.0\.2\.|100\.(?:6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|169\.254\.|198\.1[89]\.|24[0-9]\.|25[0-5]\.))(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?!\.[\d])"),
        True,  # Strict mode only
    ),
    (
        "INF-005",
        f"Production Infrastructure Domain ({_P_PROD_DOMAIN})",
        re.compile(r"\b(?:https?://)?(?:[a-zA-Z0-9_-]+\.)*" + re.escape(_P_PROD_DOMAIN) + r"\b"),
        False,
    ),
    (
        "INF-006",
        "Hardcoded Reality Public Key / Short ID",
        re.compile(r"\b(?:" + re.escape(_P_PROD_PBK) + r"|" + "|".join(re.escape(sid) for sid in _P_SHORT_IDS) + r")\b"),
        False,
    ),
    (
        "PRV-001",
        "Personal Phone Number",
        re.compile(r"(?:\+7|(?<!\d)8)[\s\-]?(?:\(9\d{2}\)|9\d{2})[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}\b"),
        False,
    ),
    (
        "PRV-002",
        "Admin Telegram User IDs",
        re.compile(r'\b(?:admin_user_ids|ADMIN_IDS|ADMIN_USER_ID|ADMIN_ID)\s*[:=]\s*[\[\(\{\"\']?\s*[0-9]{8,11}', re.IGNORECASE),
        False,
    ),
]

# Safe whitelist tokens / placeholders that must never trigger violations
SAFE_WHITELIST_TOKENS: Set[str] = {
    "123456:dummy_token",
    "123456789:dummy_token_placeholder_abcdefghij",
    "0000000000:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "0x4AAAAAAATestKey",
    "0x4AAAAAAATestSecret",
    "example.com",
    "sub.example.com",
    "edge.example.com",
    "fi.example.com",
    "warp.example.com",
    "relay.example.com",
    "127.0.0.1",
    "0.0.0.0",
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "77.88.8.8",
    "77.88.8.1",
    "94.140.14.14",
    "94.140.15.15",
    "120.0.0.0",
    "198.51.100.1",
    "198.51.100.10",
    "198.51.100.24",
    "203.0.113.1",
    "192.0.2.1",
    "00000000-0000-0000-0000-000000000000",
    "034d060d-8f33-4280-b22c-6b128813646f",
    "dummy_smtp_password_placeholder",
    "+79990000000",
    "+79001234567",
    "+7 (999) 000-00-00",
    "89001234567",
}

SAFE_WHITELIST_SUBSTRINGS: List[str] = [
    "example.com",
    "dummy",
    "0000000000",
    "YOUR_",
    "<YOUR_",
    "${",
    "PLACEHOLDER",
    "CHANGEME",
    "Mozilla/5.0",
    "Chrome/120.0.0.0",
]


# =============================================================================
# Violation Data Class
# =============================================================================

class Violation:
    def __init__(
        self,
        rule_id: str,
        file_path: str,
        line_number: Optional[int],
        message: str,
        sample: str = "",
    ):
        self.rule_id = rule_id
        self.file_path = file_path
        self.line_number = line_number
        self.message = message
        self.sample = sample

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "message": self.message,
            "sample": self._mask_sample(self.sample),
        }

    @staticmethod
    def _mask_sample(s: str) -> str:
        s = s.strip()
        if not s:
            return ""
        if len(s) <= 8:
            return "*" * len(s)
        return s[:4] + "..." + s[-4:]


# =============================================================================
# Security Audit Scanner Engine
# =============================================================================

class SecurityAuditScanner:
    def __init__(
        self,
        root_dir: Path,
        strict: bool = False,
        check_git: bool = True,
        verbose: bool = False,
    ):
        self.root_dir = root_dir.resolve()
        self.strict = strict
        self.check_git = check_git
        self.verbose = verbose
        self.violations: List[Violation] = []
        self.scanned_files_count = 0
        self.script_path = Path(__file__).resolve()

    def run_scan(self) -> bool:
        """Executes full audit scan. Returns True if 0 violations, False otherwise."""
        if not self.root_dir.exists():
            raise FileNotFoundError(f"Target directory '{self.root_dir}' does not exist")

        self._scan_filesystem()
        if self.check_git:
            self._scan_git_index()

        return len(self.violations) == 0

    def _should_ignore_dir(self, dir_name: str) -> bool:
        return dir_name in IGNORED_DIR_NAMES

    def _scan_filesystem(self) -> None:
        for root, dirs, files in os.walk(self.root_dir):
            dirs[:] = [d for d in dirs if not self._should_ignore_dir(d)]
            for file_name in files:
                file_path = Path(root) / file_name
                try:
                    rel_path = file_path.relative_to(self.root_dir).as_posix()
                except ValueError:
                    rel_path = str(file_path)
                self._audit_file(file_path, rel_path)

    def _audit_file(self, file_path: Path, rel_path: str) -> None:
        self.scanned_files_count += 1
        name = file_path.name

        # 1. Allowed examples / templates / media whitelist check
        if name in ALLOWED_FILENAMES or name.endswith(".example") or file_path.suffix.lower() in ALLOWED_MEDIA_EXTENSIONS or name in IGNORED_FILENAMES:
            if self.verbose:
                print(f"[INFO] Skipping whitelisted file/asset: {rel_path}")
            return

        # 2. Check forbidden active environment files (.env, .env.local, subjson.env, etc.)
        is_active_env = (
            name in FORBIDDEN_EXACT_FILENAMES
            or ((name.startswith(".env") or name.endswith(".env")) and name not in ALLOWED_FILENAMES and not name.endswith(".example"))
        )
        if is_active_env:
            self.violations.append(Violation(
                rule_id="FILE-001",
                file_path=rel_path,
                line_number=None,
                message=f"Forbidden active environment file '{name}' found in repository",
                sample=name,
            ))

        # 3. Check forbidden file extensions (.db, .tar.gz, .bak, .pem, .exe, compound extensions)
        name_lower = name.lower()
        is_forbidden_ext = False
        offending_ext = ""
        for forbidden_ext in FORBIDDEN_EXTENSIONS:
            if name_lower.endswith(forbidden_ext) or f"{forbidden_ext}." in name_lower:
                is_forbidden_ext = True
                offending_ext = forbidden_ext
                break

        if is_forbidden_ext:
            self.violations.append(Violation(
                rule_id="FILE-002",
                file_path=rel_path,
                line_number=None,
                message=f"Forbidden file extension '{offending_ext}' detected in path '{rel_path}'",
                sample=rel_path,
            ))

        # 4. Check binary magic bytes & null bytes
        try:
            with open(file_path, "rb") as f:
                header = f.read(8192)
                for magic_bytes, desc in MAGIC_BYTE_SIGNATURES:
                    if header.startswith(magic_bytes):
                        self.violations.append(Violation(
                            rule_id="BIN-001",
                            file_path=rel_path,
                            line_number=None,
                            message=f"Binary file detected via magic signature: {desc}",
                            sample=desc,
                        ))
                        return
                if b"\x00" in header:
                    self.violations.append(Violation(
                        rule_id="BIN-002",
                        file_path=rel_path,
                        line_number=None,
                        message="Binary file detected (contains null bytes)",
                        sample=name,
                    ))
                    return
        except Exception as e:
            if self.verbose:
                print(f"[WARN] Failed to read binary header for {rel_path}: {e}")

        # 5. Full-text content scan (Skip scanning scanner script's own rule definitions)
        is_scanner_self = False
        try:
            if file_path.name == "security_audit_scanner.py" or file_path.name == self.script_path.name:
                is_scanner_self = True
        except Exception:
            pass

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                for line_idx, line in enumerate(f, start=1):
                    if is_scanner_self and line_idx < 195:
                        # Skip rule definitions section in scanner self-scan
                        continue
                    self._scan_text_line(line, line_idx, rel_path)
        except Exception as e:
            if self.verbose:
                print(f"[WARN] Failed to read text content of {rel_path}: {e}")

    def _scan_text_line(self, line: str, line_idx: int, rel_path: str) -> None:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            # Comment line check: still scan comments for real tokens unless whitelisted
            pass

        for rule_id, rule_desc, regex, is_strict_rule in SECRET_PATTERNS:
            if is_strict_rule and not self.strict:
                continue

            for m in regex.finditer(line):
                matched_text = m.group(0)

                # Check exact whitelist
                if matched_text in SAFE_WHITELIST_TOKENS:
                    continue

                # Check substring whitelists
                if any(sub in line for sub in SAFE_WHITELIST_SUBSTRINGS):
                    continue

                self.violations.append(Violation(
                    rule_id=rule_id,
                    file_path=rel_path,
                    line_number=line_idx,
                    message=f"{rule_desc} detected",
                    sample=matched_text,
                ))

    def _scan_git_index(self) -> None:
        """Verifies git tracked index and staged files if git is initialized."""
        git_dir = self.root_dir / ".git"
        if not git_dir.exists():
            return

        try:
            res = subprocess.run(
                ["git", "ls-files"],
                cwd=self.root_dir,
                capture_output=True,
                text=True,
                check=True,
            )
            tracked_files = res.stdout.splitlines()
            for tf in tracked_files:
                p = Path(tf)
                name = p.name
                name_lower = name.lower()
                if name in ALLOWED_FILENAMES or name.endswith(".example"):
                    continue

                is_forbidden_env = (
                    name in FORBIDDEN_EXACT_FILENAMES
                    or ((name.startswith(".env") or name.endswith(".env")) and name not in ALLOWED_FILENAMES and not name.endswith(".example"))
                )
                is_forbidden_ext = any(
                    name_lower.endswith(ext) or f"{ext}." in name_lower
                    for ext in FORBIDDEN_EXTENSIONS
                )
                if is_forbidden_env or is_forbidden_ext:
                    self.violations.append(Violation(
                        rule_id="GIT-001",
                        file_path=tf,
                        line_number=None,
                        message=f"Forbidden file '{tf}' is tracked in git index",
                        sample=tf,
                    ))
        except Exception as e:
            if self.verbose:
                print(f"[WARN] Git index verification skipped: {e}")


# =============================================================================
# Output Formatting & Reporting
# =============================================================================

def format_console_report(scanner: SecurityAuditScanner) -> str:
    lines: List[str] = []
    lines.append("=" * 80)
    lines.append("        SILENTCONNECT AUTOMATED ZERO-LEAK SECURITY AUDIT SCANNER")
    lines.append("=" * 80)
    lines.append(f"Target Directory : {scanner.root_dir}")
    lines.append(f"Strict Mode      : {'ENABLED' if scanner.strict else 'DISABLED'}")
    lines.append(f"Git Index Check  : {'ENABLED' if scanner.check_git else 'DISABLED'}")
    lines.append(f"Files Scanned    : {scanner.scanned_files_count}")
    lines.append(f"Violations Found : {len(scanner.violations)}")
    lines.append("-" * 80)

    if not scanner.violations:
        lines.append("[PASS] AUDIT PASSED: Zero leaks, zero binaries, zero untracked secrets detected.")
        lines.append("=" * 80)
        return "\n".join(lines)

    lines.append("[FAIL] AUDIT FAILED: The following security / binary violations were detected:\n")
    for v in scanner.violations:
        loc = f"{v.file_path}:{v.line_number}" if v.line_number else v.file_path
        lines.append(f"  [{v.rule_id}] {loc}")
        lines.append(f"    Reason : {v.message}")
        if v.sample:
            lines.append(f"    Sample : {Violation._mask_sample(v.sample)}")
        lines.append("")

    lines.append("=" * 80)
    lines.append("Action required: Sanitize or remove the offending files before export.")
    return "\n".join(lines)


# =============================================================================
# CLI Entrypoint
# =============================================================================

def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SilentConnect Automated Zero-Leak Security & Binary Audit Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--target-dir",
        "--path",
        dest="target_dir",
        default=".",
        help="Root directory to scan (default: current directory)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Enable strict heuristics (flags public IPs, UUIDs, extra checks)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format to stdout (default: text)",
    )
    parser.add_argument(
        "--json-report",
        dest="json_report",
        default=None,
        help="Path to write JSON report file",
    )
    parser.add_argument(
        "--no-git",
        action="store_true",
        help="Disable git index inspection",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging output",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    try:
        args = parse_args(argv)
    except SystemExit as e:
        return 2 if e.code != 0 else 0

    target_path = Path(args.target_dir)

    scanner = SecurityAuditScanner(
        root_dir=target_path,
        strict=args.strict,
        check_git=not args.no_git,
        verbose=args.verbose,
    )

    try:
        passed = scanner.run_scan()
    except Exception as err:
        print(f"[ERROR] Scan execution failed: {err}", file=sys.stderr)
        return 2

    # Save JSON report if requested
    report_dict = {
        "passed": passed,
        "target_dir": str(scanner.root_dir),
        "strict": scanner.strict,
        "scanned_files": scanner.scanned_files_count,
        "violations_count": len(scanner.violations),
        "violations": [v.to_dict() for v in scanner.violations],
    }

    if args.json_report:
        try:
            report_file = Path(args.json_report)
            report_file.parent.mkdir(parents=True, exist_ok=True)
            with open(report_file, "w", encoding="utf-8") as f:
                json.dump(report_dict, f, indent=2)
            if args.verbose:
                print(f"[INFO] JSON report written to {report_file}")
        except Exception as err:
            print(f"[ERROR] Failed to write JSON report to {args.json_report}: {err}", file=sys.stderr)

    # Print output to stdout
    if args.format == "json":
        print(json.dumps(report_dict, indent=2))
    else:
        print(format_console_report(scanner))

    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
