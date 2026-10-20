#!/usr/bin/env python3
"""
scripts/build_audit_zip.py

Creates clean, token-optimized ZIP archives for LLM code review / audit.
Strictly excludes binary media, compiled bytecode, duplicate dumps, and git metadata.
"""

import os
import sys
import zipfile
from pathlib import Path

SOURCE_DIR = Path(r"C:\Users\Yuric\Desktop\сервер\github_export")
DESKTOP_DIR = Path(r"C:\Users\Yuric\Desktop")

EXCLUDE_EXTENSIONS = {
    ".pyc", ".pyo", ".png", ".webp", ".jpg", ".jpeg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".db", ".db-wal", ".db-shm",
    ".sqlite", ".sqlite3", ".bak", ".old", ".zip", ".tar", ".gz"
}

EXCLUDE_DIRS = {
    ".git", "__pycache__", ".pytest_cache", "nl_audit", "ui_templates",
    "node_modules", "data", "data-silentconnect", ".agents", ".gemini"
}

def estimate_tokens(text: str) -> int:
    return max(1, int(len(text) / 3.8))

def build_zip(include_tests: bool = True, output_name: str = "SilentConnect_Audit_Clean.zip") -> tuple[Path, int, int, int]:
    out_path = DESKTOP_DIR / output_name
    files_added = 0
    total_uncompressed = 0
    total_tokens = 0

    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(SOURCE_DIR):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith(".bak")]
            rel_root = Path(root).relative_to(SOURCE_DIR)
            
            if any(part in EXCLUDE_DIRS for part in rel_root.parts):
                continue
            if not include_tests and "tests" in rel_root.parts:
                continue

            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext in EXCLUDE_EXTENSIONS or fname.endswith(".bak-20260822") or fname.endswith(".old"):
                    continue
                
                # Exclude stress test scripts from scripts/ if without tests
                if not include_tests and fname.startswith(("test_", "stress_")):
                    continue

                full_path = Path(root) / fname
                arcname = str(rel_root / fname).replace("\\", "/")
                
                sz = full_path.stat().st_size
                total_uncompressed += sz
                try:
                    with open(full_path, "r", encoding="utf-8", errors="replace") as fh:
                        tok = estimate_tokens(fh.read())
                except Exception:
                    tok = int(sz / 3.8)
                total_tokens += tok

                zf.write(full_path, arcname)
                files_added += 1

    return out_path, files_added, total_uncompressed, total_tokens

if __name__ == "__main__":
    print("Building clean audit archives on Desktop...")
    p1, f1, u1, t1 = build_zip(include_tests=True, output_name="SilentConnect_Audit_Full.zip")
    print(f"[Full (with tests)] -> {p1}")
    print(f"  Files: {f1} | Uncompressed: {u1/1024:.1f} KB | Compressed: {p1.stat().st_size/1024:.1f} KB | Est. Tokens: ~{t1:,}")

    p2, f2, u2, t2 = build_zip(include_tests=False, output_name="SilentConnect_Audit_Lean.zip")
    print(f"[Lean (code only)]  -> {p2}")
    print(f"  Files: {f2} | Uncompressed: {u2/1024:.1f} KB | Compressed: {p2.stat().st_size/1024:.1f} KB | Est. Tokens: ~{t2:,}")
