import os
import subprocess
import sys
import tempfile
from pathlib import Path

def _find_export_dir() -> Path:
    base = Path(__file__).resolve().parents[1]
    if (base / "github_export").exists():
        return base / "github_export"
    return base

def test_security_scanner_detects_platega_secret():
    github_export_dir = _find_export_dir()
    scanner_path = github_export_dir / "scripts" / "security_audit_scanner.py"
    
    # Create temporary file with test secret
    tmp_file = github_export_dir / "leak_test.py"
    try:
        tmp_file.write_text("PLATEGA_" + "SECRET = \"live_secret_sample_test12345678\"\n", encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(scanner_path), "--strict"],
            cwd=str(github_export_dir),
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        assert result.returncode == 1, f"Expected scanner to fail with 1, got {result.returncode}"
        assert "SEC-010" in result.stdout or "Platega" in result.stdout, f"Expected SEC-010 violation in output: {result.stdout}"
    finally:
        if tmp_file.exists():
            tmp_file.unlink()

def test_gitignore_blocks_env_platega():
    github_export_dir = _find_export_dir()
    test_env = github_export_dir / ".env.platega"
    try:
        test_env.write_text("PLATEGA_SECRET=test\n", encoding="utf-8")
        res = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=str(github_export_dir),
            capture_output=True,
            text=True,
        )
        assert ".env.platega" not in res.stdout, f".env.platega should be ignored by git: {res.stdout}"
    finally:
        if test_env.exists():
            test_env.unlink()

if __name__ == "__main__":
    test_security_scanner_detects_platega_secret()
    test_gitignore_blocks_env_platega()
    print("ALL PLATEGA SECURITY TESTS PASSED SUCCESSFULLY!")
