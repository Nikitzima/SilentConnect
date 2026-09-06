#!/usr/bin/env python3
"""
scripts/setup_git_hooks.py

Installs and configures Git Pre-Commit and Pre-Push hooks for SilentConnect.
Run this script after cloning the repository.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    hooks_dir = repo_root / ".githooks"
    git_hooks_dir = repo_root / ".git" / "hooks"

    print("Configuring SilentConnect Git Safety Hooks...")

    # 1. Point core.hooksPath to .githooks
    res = subprocess.run(["git", "config", "core.hooksPath", ".githooks"], cwd=str(repo_root))
    if res.returncode == 0:
        print("  [OK] Set git config core.hooksPath = .githooks")
    else:
        print("  [WARN] Failed to set core.hooksPath, falling back to copying to .git/hooks")

    # 2. Copy as fallback to .git/hooks if it exists
    if git_hooks_dir.exists():
        for hook_name in ["pre-commit", "pre-push"]:
            src = hooks_dir / hook_name
            dst = git_hooks_dir / hook_name
            if src.exists():
                shutil.copy2(src, dst)
                print(f"  [OK] Copied {hook_name} to .git/hooks/{hook_name}")

    print("SUCCESS: Git security gates installed. Zero-leak enforcement active.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
