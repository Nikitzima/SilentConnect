#!/usr/bin/env python3
"""
scripts/git_pre_commit.py

Git Pre-Commit Hook Engine for SilentConnect.
Automatically executed before every git commit to ensure:
  1. Zero production secrets or bot tokens in staged changes.
  2. No forbidden files, credentials, or binary database dumps staged.
  3. No unresolved git merge conflict markers.
  4. 100% clean Python syntax compilation (py_compile) on all staged .py files.
  5. Full repository audit via security_audit_scanner.py in strict mode.

Exit code 0: Commit allowed.
Exit code 1: Commit blocked with detailed diagnostic report.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import py_compile
from pathlib import Path
from typing import List, Tuple

# Ensure UTF-8 output on Windows consoles without crashing
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_CYAN = "\033[96m"
COLOR_BOLD = "\033[1m"
COLOR_RESET = "\033[0m"

FORBIDDEN_EXTENSIONS = {
    ".db", ".db-shm", ".db-wal", ".db-journal", ".sqlite", ".sqlite3",
    ".pem", ".key", ".crt", ".pfx", ".p12", ".csr",
    ".tar", ".tar.gz", ".zip", ".gz", ".7z", ".bak", ".old", ".orig",
    ".pyc", ".pyo"
}

FORBIDDEN_FILENAMES = {
    ".env", ".env.local", ".env.production", ".env.staging",
    ".env.silentconnect", "subjson.env", "x-ui.db", "vpn_shop.db"
}

ALLOWED_FILENAMES = {
    ".env.example", ".env.silentconnect.example", "subjson.env.example",
    "vpn-shop-silentconnect.service.example", "vpn-shop-web.service.example",
    "vpn-shop.service.example", "BOTFATHER_SETUP.md", ".gitignore", ".gitkeep"
}

SECRET_PATTERNS: List[Tuple[str, str, re.Pattern]] = [
    (
        "TG_BOT_TOKEN",
        "Telegram Bot API Token",
        re.compile(r"\b[0-9]{8,11}:[A-Za-z0-9_-]{35}\b")
    ),
    (
        "PRIVATE_KEY_PEM",
        "PEM Private Key Block",
        re.compile(r"-----BEGIN (?:[A-Za-z0-9_-]+ )?PRIVATE KEY", re.IGNORECASE)
    ),
    (
        "CF_API_TOKEN",
        "Cloudflare API Token / Bearer Token",
        re.compile(r"(?:CF_API_TOKEN|CLOUDFLARE_TOKEN|CLOUDFLARE_API_TOKEN)\s*[:=]\s*['\"]?([A-Za-z0-9_-]{32,45})['\"]?", re.IGNORECASE)
    ),
    (
        "CF_GLOBAL_KEY",
        "Cloudflare Global API Key",
        re.compile(r"(?:CF_API_KEY|CLOUDFLARE_API_KEY|CF_KEY)\s*[:=]\s*['\"]?([0-9a-fA-F]{32,45})['\"]?", re.IGNORECASE)
    ),
    (
        "WIREGUARD_PRIVKEY",
        "WireGuard / Amnezia Private Key",
        re.compile(r"\b(?:PrivateKey|wg_private_key|amnezia_private_key|awg_priv_key)\s*[:=]\s*['\"]?([A-Za-z0-9+/]{42,44}={0,2})['\"]?", re.IGNORECASE)
    ),
    (
        "REALITY_PRIVKEY",
        "Reality / VLESS Private Key",
        re.compile(r"\b(?:reality_private_key|private_key|priv_key)\s*[:=]\s*['\"]?([A-Za-z0-9_-]{43,44})['\"]?", re.IGNORECASE)
    ),
    (
        "SMTP_BREVO_KEY",
        "SMTP Password / Brevo API Key",
        re.compile(r"\bxkeysib-[a-f0-9]{64}-[a-zA-Z0-9]{16}\b|(?:SMTP_PASSWORD|BREVO_API_KEY|MAIL_PASSWORD)\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?", re.IGNORECASE)
    ),
]

CONFLICT_MARKERS = [
    re.compile(r"^<{7}\s+"),
    re.compile(r"^={7}$"),
    re.compile(r"^>{7}\s+"),
]

def run_git_command(args: List[str]) -> str:
    res = subprocess.run(["git"] + args, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if res.returncode != 0:
        return ""
    return res.stdout.strip()

def get_staged_files() -> List[str]:
    out = run_git_command(["diff", "--cached", "--name-only", "--diff-filter=ACM"])
    if not out:
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]

def main() -> int:
    print(f"\n{COLOR_CYAN}{COLOR_BOLD}=== [SilentConnect Pre-Commit Security & Quality Guard] ==={COLOR_RESET}")
    staged_files = get_staged_files()
    if not staged_files:
        print(f"{COLOR_GREEN}[PASS]{COLOR_RESET} No files staged for commit.")
        return 0

    repo_root = Path(run_git_command(["rev-parse", "--show-toplevel"]) or os.getcwd())
    violations: List[str] = []

    # 1. Check staged filenames against forbidden list
    print(f"{COLOR_CYAN}[1/4]{COLOR_RESET} Verifying staged file names and extensions...")
    for f in staged_files:
        p = Path(f)
        fname = p.name.lower()
        ext = p.suffix.lower()

        if fname in FORBIDDEN_FILENAMES or (fname.startswith(".env") and fname not in ALLOWED_FILENAMES and not fname.endswith(".example")):
            violations.append(f"Forbidden file staged: {f}")

        if ext in FORBIDDEN_EXTENSIONS:
            violations.append(f"Forbidden file extension staged: {f} ({ext})")

    # 2. Inspect staged diff content for secrets and conflict markers
    print(f"{COLOR_CYAN}[2/4]{COLOR_RESET} Scanning staged diff lines for secrets & conflict markers...")
    diff_output = run_git_command(["diff", "--cached", "-U0"])
    current_file = ""
    for line in diff_output.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:]
            continue

        if line.startswith("+") and not line.startswith("+++"):
            added_line = line[1:]

            # Conflict markers
            for cm in CONFLICT_MARKERS:
                if cm.search(added_line):
                    violations.append(f"Merge conflict marker found in {current_file}: {added_line.strip()[:60]}")

            # Secrets scan
            for code, desc, pattern in SECRET_PATTERNS:
                matches = pattern.findall(added_line)
                if matches:
                    is_placeholder = any(ph in added_line for ph in ["YOUR_", "PLACEHOLDER", "example", "<token>", "CHANGEME", "0000000000"])
                    if not is_placeholder:
                        violations.append(f"[{code}] {desc} detected in {current_file}: {added_line.strip()[:50]}...")

    # 3. Compile Python syntax on staged .py files
    print(f"{COLOR_CYAN}[3/4]{COLOR_RESET} Verifying Python syntax (py_compile) on staged files...")
    py_files = [f for f in staged_files if f.endswith(".py")]
    for pf in py_files:
        full_path = repo_root / pf
        if full_path.exists():
            try:
                py_compile.compile(str(full_path), doraise=True)
            except py_compile.PyCompileError as e:
                violations.append(f"Syntax error in Python file {pf}: {e}")

    # 4. Run full security_audit_scanner.py in strict mode
    print(f"{COLOR_CYAN}[4/4]{COLOR_RESET} Running automated security audit scanner in strict mode...")
    scanner_script = repo_root / "scripts" / "security_audit_scanner.py"
    if scanner_script.exists():
        res = subprocess.run([sys.executable, str(scanner_script), "--strict"], capture_output=True, text=True, encoding="utf-8", errors="replace")
        if res.returncode != 0:
            violations.append(f"security_audit_scanner.py reported violations:\n{res.stdout}\n{res.stderr}")

    if violations:
        print(f"\n{COLOR_RED}{COLOR_BOLD}[BLOCKED] COMMIT REJECTED! Security or syntax violations detected:{COLOR_RESET}")
        for v in violations:
            print(f"  {COLOR_RED}* {v}{COLOR_RESET}")
        print(f"\n{COLOR_YELLOW}Fix the above issues before committing.{COLOR_RESET}\n")
        return 1

    print(f"\n{COLOR_GREEN}{COLOR_BOLD}[PASSED] PRE-COMMIT VERIFIED:{COLOR_RESET} 0 leaks, 0 syntax errors, 0 forbidden files staged.")
    print(f"===============================================================\n")
    return 0

if __name__ == "__main__":
    sys.exit(main())
