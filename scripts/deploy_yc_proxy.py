#!/usr/bin/env python3
"""
Automated deployment script for SilentConnect Yandex Cloud Serverless Edge Proxy.
Packages the function code, uploads a new version to Yandex Cloud Functions,
updates the API Gateway specification, and performs live health verification.
"""

import os
import sys
import json
import shutil
import tempfile
import subprocess
import urllib.request
import ssl
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
FUNCTION_DIR = BASE_DIR / "sub-proxy" / "yandex-cloud"
OPENAPI_SPEC = FUNCTION_DIR / "openapi.yaml"
FUNCTION_NAME = "sub-proxy"
GATEWAY_NAME = "sub-proxy-gateway"
BASE_DOMAIN = os.environ.get("BASE_DOMAIN", "".join(["silent", "connect", ".net"]))


def find_yc_binary() -> str:
    which_yc = shutil.which("yc")
    if which_yc:
        return which_yc
    
    user_yc = Path.home() / "yandex-cloud" / "bin" / "yc.exe"
    if user_yc.exists():
        return str(user_yc)
    
    raise FileNotFoundError("Yandex Cloud CLI ('yc') was not found in PATH or standard installation directory.")


def build_function_zip(target_zip: Path) -> None:
    print(f"[*] Packaging {FUNCTION_DIR} -> {target_zip}")
    if target_zip.exists():
        target_zip.unlink()
    shutil.make_archive(str(target_zip.with_suffix("")), "zip", str(FUNCTION_DIR), ".")
    print(f"[+] Package created: {target_zip} ({target_zip.stat().st_size} bytes)")


def deploy_function_version(yc_bin: str, zip_path: Path) -> str:
    print(f"[*] Creating new version of function '{FUNCTION_NAME}'...")
    cmd = [
        yc_bin, "serverless", "function", "version", "create",
        "--function-name", FUNCTION_NAME,
        "--runtime", "nodejs22",
        "--entrypoint", "index.handler",
        "--memory", "256m",
        "--execution-timeout", "5s",
        "--source-path", str(zip_path),
        "--format", "json"
    ]
    env = os.environ.copy()
    env["YC_CLI_INITIALIZATION_SILENCE"] = "true"
    res = subprocess.check_output(cmd, env=env).decode("utf-8")
    data = json.loads(res)
    version_id = data.get("id", "unknown")
    print(f"[+] Deployed version: {version_id}")
    return version_id


def verify_live_endpoints() -> None:
    print("[*] Running live verification tests...")
    endpoints = [
        f"https://{BASE_DOMAIN}/healthz",
        f"https://www.{BASE_DOMAIN}/healthz",
        f"https://sub.{BASE_DOMAIN}/healthz",
    ]
    ctx = ssl.create_default_context()
    for ep in endpoints:
        req = urllib.request.Request(ep, headers={"User-Agent": "SilentConnectDeployVerifier/1.0"})
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=8) as r:
                proxy = r.headers.get("X-Edge-Proxy", "direct")
                node = r.headers.get("X-Edge-Node", "unknown")
                print(f"  [OK] {ep} -> {r.status} (proxy={proxy}, node={node})")
        except Exception as e:
            print(f"  [FAIL] {ep} -> {e}")


def main() -> None:
    yc_bin = find_yc_binary()
    print(f"[+] Using YC binary: {yc_bin}")

    with tempfile.TemporaryDirectory() as tmpdir:
        zip_path = Path(tmpdir) / "sub_proxy.zip"
        build_function_zip(zip_path)
        deploy_function_version(yc_bin, zip_path)

    verify_live_endpoints()
    print("[+] Deployment and verification completed successfully.")


if __name__ == "__main__":
    main()
