#!/usr/bin/env python3
"""
scripts/git_pre_push.py

Git Pre-Push Hook Engine for SilentConnect.
Automatically executed before every git push to remote:
  1. Full security audit scanner (--strict).
  2. Full test suite execution (unittest discover).

Exit code 0: Push allowed.
Exit code 1: Push rejected.
"""

import os
import subprocess
import sys
from pathlib import Path

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

def main() -> int:
    print(f"\n{COLOR_CYAN}{COLOR_BOLD}=== [SilentConnect Pre-Push Quality & Safety Gate] ==={COLOR_RESET}")
    repo_root = Path(__file__).resolve().parent.parent

    # 1. Security scan
    print(f"{COLOR_CYAN}[1/2]{COLOR_RESET} Running strict security audit scanner...")
    scanner_script = repo_root / "scripts" / "security_audit_scanner.py"
    res = subprocess.run([sys.executable, str(scanner_script), "--strict"], capture_output=True, text=True, encoding="utf-8", errors="replace")
    if res.returncode != 0:
        print(f"{COLOR_RED}{COLOR_BOLD}[BLOCKED] PUSH REJECTED: Security audit violations found!{COLOR_RESET}")
        print(res.stdout)
        print(res.stderr)
        return 1

    # 2. Automated test suite
    print(f"{COLOR_CYAN}[2/2]{COLOR_RESET} Running complete regression test suite...")
    test_res = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace"
    )
    if test_res.returncode != 0:
        print(f"{COLOR_RED}{COLOR_BOLD}[BLOCKED] PUSH REJECTED: Unit tests failed!{COLOR_RESET}")
        print(test_res.stdout)
        print(test_res.stderr)
        return 1

    print(f"\n{COLOR_GREEN}{COLOR_BOLD}[PASSED] PRE-PUSH VERIFIED:{COLOR_RESET} 100% tests green, 0 security leaks.")
    print(f"===============================================================\n")
    return 0

if __name__ == "__main__":
    sys.exit(main())
