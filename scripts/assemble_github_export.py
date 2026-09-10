#!/usr/bin/env python3
"""
scripts/assemble_github_export.py

Assembles a clean, sanitized export repository in the target directory (github_export).
Copies only required source code, configurations, tests, and documentation,
strictly excluding any databases, backups, legacy binaries, active env files, or agent logs.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

SOURCE_ROOT = Path.cwd()
EXPORT_DIR = SOURCE_ROOT / "github_export"

# Root level files to include
ROOT_FILES = [
    ".env.example",
    "README.md",
    "LICENSE",
    ".gitignore",
]

# Directories to copy and their include/exclude rules
SUBDIRECTORIES = [
    "vpn-shop",
    "subjson-service",
    "scripts",
    "tests",
]

# Patterns and names that must NEVER be copied to github_export
FORBIDDEN_DIR_NAMES = {
    "__pycache__",
    ".pytest_cache",
    ".git",
    ".agents",
    ".gemini",
    "venv",
    ".venv",
    "data",
    "data-silentconnect",
    "node_modules",
    ".idea",
    ".vscode",
}

FORBIDDEN_EXTENSIONS = {
    ".db", ".db-shm", ".db-wal", ".db-journal", ".sqlite", ".sqlite3", ".dump",
    ".bak", ".old", ".orig", ".tar", ".gz", ".zip", ".7z", ".rar",
    ".pem", ".key", ".crt", ".cer", ".pfx", ".p12", ".csr",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".iso", ".pyc", ".pyo",
}

FORBIDDEN_EXACT_FILENAMES = {
    ".env", ".env.local", ".env.production", ".env.staging", ".env.silentconnect", ".env.platega", "subjson.env",
    "outage_metrics.json", "cluster_doctor.py",
}

ALLOWED_EXEMPT_NAMES = {
    ".env.example", ".env.silentconnect.example", "subjson.env.example",
    "vpn-shop-silentconnect.service.example", "vpn-shop-web.service.example",
    "vpn-shop.service.example", "BOTFATHER_SETUP.md", ".gitignore", ".gitkeep",
    "README.md", "LICENSE", "SILENTCONNECT_IMAGE_PROMPTS.txt",
}


def is_file_allowed(path: Path) -> bool:
    name = path.name
    name_lower = name.lower()

    if name in ALLOWED_EXEMPT_NAMES or name.endswith(".example"):
        return True

    if name in FORBIDDEN_EXACT_FILENAMES:
        return False

    if (name.startswith(".env") or name.endswith(".env")) and name not in ALLOWED_EXEMPT_NAMES and not name.endswith(".example"):
        return False

    for ext in FORBIDDEN_EXTENSIONS:
        if name_lower.endswith(ext) or f"{ext}." in name_lower:
            return False

    return True


def copy_tree_sanitized(src_dir: Path, dst_dir: Path) -> int:
    copied_count = 0
    dst_dir.mkdir(parents=True, exist_ok=True)

    for root, dirs, files in os.walk(src_dir):
        # Filter out forbidden directories
        dirs[:] = [d for d in dirs if d not in FORBIDDEN_DIR_NAMES and not d.startswith(".bak")]

        rel_root = Path(root).relative_to(src_dir)
        target_sub_dir = dst_dir / rel_root
        target_sub_dir.mkdir(parents=True, exist_ok=True)

        for file_name in files:
            file_path = Path(root) / file_name
            if not is_file_allowed(file_path):
                print(f"[SKIP-FORBIDDEN] {file_path.relative_to(SOURCE_ROOT)}")
                continue

            target_file_path = target_sub_dir / file_name
            shutil.copy2(file_path, target_file_path)
            copied_count += 1

    return copied_count


def assemble():
    print("=" * 80)
    print("        SILENTCONNECT CLEAN GITHUB EXPORT REPOSITORY ASSEMBLER")
    print("=" * 80)
    print(f"Source Directory : {SOURCE_ROOT}")
    print(f"Export Directory : {EXPORT_DIR}")
    print("-" * 80)

    # Ensure EXPORT_DIR exists
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Copy root files
    root_copied = 0
    for root_file in ROOT_FILES:
        src_path = SOURCE_ROOT / root_file
        if src_path.exists():
            shutil.copy2(src_path, EXPORT_DIR / root_file)
            root_copied += 1
            print(f"[COPY-ROOT] {root_file}")
        elif root_file == ".gitignore" and (EXPORT_DIR / ".gitignore").exists():
            root_copied += 1
            print("[EXISTING-ROOT] .gitignore")

    # 2. Copy subdirectories
    total_copied = root_copied
    for sub in SUBDIRECTORIES:
        src_sub = SOURCE_ROOT / sub
        dst_sub = EXPORT_DIR / sub
        if not src_sub.exists():
            print(f"[WARN] Subdirectory {sub} does not exist in source root")
            continue
        count = copy_tree_sanitized(src_sub, dst_sub)
        print(f"[COPY-SUBDIR] {sub}/ : {count} files copied")
        total_copied += count

    print("-" * 80)
    print(f"Assembly Complete! Total files copied: {total_copied}")
    print("=" * 80)


if __name__ == "__main__":
    assemble()
