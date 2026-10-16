#!/usr/bin/env python3
"""
scripts/cluster_node_tool.py

Cluster Node Management & Security Tool for SilentConnect.
Features:
- pin-key <node_code>: Secure SSH ed25519 host key pinning with MITM verification
- reconcile: Cluster AmneziaWG peer reconciliation with Master Mutex protection
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

# Ensure vpn-shop is in import path
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
if str(REPO_ROOT / "vpn-shop") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "vpn-shop"))

def load_cluster_env() -> None:
    """Load cluster environment variables from standard locations if present."""
    candidates = [
        Path("/root/vpn-shop/.env.silentconnect"),
        Path("/etc/silentconnect/.env.silentconnect"),
        REPO_ROOT / ".env.silentconnect",
        REPO_ROOT / "vpn-shop" / ".env.silentconnect",
    ]
    for p in candidates:
        if p.is_file():
            try:
                for line in p.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip("'\"")
                    if k not in os.environ:
                        os.environ[k] = v
            except Exception:
                pass
            break

load_cluster_env()

from vpn_shop.awg_manager import SERVERS, CLUSTER_KNOWN_HOSTS_PATH


if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def compute_ed25519_fingerprint(b64_pubkey: str) -> str:
    """Compute standard OpenSSH SHA256 base64 fingerprint without trailing '='."""
    raw_key = base64.b64decode(b64_pubkey)
    digest = hashlib.sha256(raw_key).digest()
    fp_b64 = base64.b64encode(digest).decode("ascii").rstrip("=")
    return f"SHA256:{fp_b64}"


def run_pin_key(node_code: str, force_confirm: bool = False, custom_known_hosts: str | None = None) -> int:
    code = node_code.lower().strip()
    if code not in SERVERS:
        print(f"[ERROR] Неизвестный код ноды '{code}'. Допустимые: {list(SERVERS.keys())}")
        return 1

    srv = SERVERS[code]
    host = str(srv.get("ssh_host") or srv.get("host") or "").strip()
    port = str(srv.get("ssh_port", 22))

    if not host or host in {"127.0.0.1", "localhost"}:
        print(f"[ERROR] Нода '{code}' настроена как локальная ({host}). Pin-key выполняется только для удаленных SSH-нод.")
        return 1

    srv_name = str(srv.get("name", code)).encode("ascii", errors="ignore").decode("ascii").strip() or code.upper()
    print(f"[*] Сканирование ed25519 ключа хоста {host}:{port} ({srv_name})...")
    try:
        keyscan_cmd = ["ssh-keyscan", "-t", "ed25519", "-p", port, host]
        proc = subprocess.run(keyscan_cmd, capture_output=True, text=True, timeout=15)
        raw_output = proc.stdout.strip()
    except Exception as exc:
        print(f"[ERROR] Не удалось выполнить ssh-keyscan: {exc}")
        return 1

    # Find the public key line
    key_line = None
    for line in raw_output.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "ssh-ed25519" in line:
            key_line = line
            break

    if not key_line:
        print(f"[ERROR] Не удалось получить ssh-ed25519 ключ от хоста {host}. Проверьте доступность SSH порта {port}.")
        if proc.stderr:
            print(f"[DEBUG] stderr: {proc.stderr.strip()[:300]}")
        return 1

    parts = key_line.split()
    if len(parts) < 3:
        print(f"[ERROR] Неожиданный формат вывода ssh-keyscan: {key_line}")
        return 1

    host_token = parts[0]
    key_type = parts[1]
    b64_key = parts[2]

    fingerprint = compute_ed25519_fingerprint(b64_key)

    print("\n" + "=" * 70)
    print(f" Хост          : {host}")
    print(f" Тип ключа     : {key_type}")
    print(f" SHA256 Fingerprint: {fingerprint}")
    print("=" * 70)
    print("\nВНИМАНИЕ! Для защиты от MITM-атак обязательно выполните в консоли провайдера (Aeza/Hetzner):")
    print("  ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub")
    print(f"и сравните полученный fingerprint с выведенным выше: {fingerprint}\n")

    expected_phrase = f"CONFIRM PIN {code}"
    if not force_confirm:
        try:
            user_input = input(f"Для подтверждения введите точную фразу '{expected_phrase}': ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[ABORT] Операция отменена пользователем.")
            return 1

        if user_input != expected_phrase:
            print(f"[ABORT] Фраза подтверждения не совпала. Введено: '{user_input}'. Изменения не сохранены.")
            return 1
    else:
        print(f"[*] Автоподтверждение (--yes) активно для {code}.")

    known_hosts_file = Path(custom_known_hosts or CLUSTER_KNOWN_HOSTS_PATH)
    known_hosts_file.parent.mkdir(parents=True, exist_ok=True)

    # Read existing entries, filter out old entries for this host
    existing_lines = []
    if known_hosts_file.is_file():
        try:
            for l in known_hosts_file.read_text(encoding="utf-8").splitlines():
                l_s = l.strip()
                if not l_s or l_s.startswith("#"):
                    continue
                # If first token contains this host, skip it (replacing)
                tok = l_s.split()[0]
                if host not in tok and f"[{host}]:{port}" not in tok:
                    existing_lines.append(l_s)
        except Exception as exc:
            print(f"[WARNING] Не удалось прочитать существующий {known_hosts_file}: {exc}")

    # Add new entry
    new_entry = f"{host} {key_type} {b64_key}"
    existing_lines.append(new_entry)

    # Atomic write
    tmp_path = known_hosts_file.with_suffix(f".tmp.{os.getpid()}")
    try:
        tmp_path.write_text("\n".join(existing_lines) + "\n", encoding="utf-8")
        if hasattr(os, "chmod"):
            try:
                os.chmod(tmp_path, 0o644)
            except Exception:
                pass
        tmp_path.replace(known_hosts_file)
        print(f"[SUCCESS] Ключ хоста {host} успешно зафиксирован в {known_hosts_file}")
    except Exception as exc:
        print(f"[ERROR] Ошибка записи в {known_hosts_file}: {exc}")
        if tmp_path.exists():
            tmp_path.unlink()
        return 1

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="SilentConnect Cluster Node Management & Security Tool"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: pin-key
    pin_parser = subparsers.add_parser("pin-key", help="Pin SSH ed25519 host key for a cluster node")
    pin_parser.add_argument("node_code", help="Node code (nl, pl, fi)")
    pin_parser.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompt")
    pin_parser.add_argument("--known-hosts-file", default=None, help="Custom cluster_known_hosts file path")

    # Subcommand: reconcile (for Step 4)
    rec_parser = subparsers.add_parser("reconcile", help="Reconcile AWG peers with database")
    rec_parser.add_argument("--node", default="all", help="Target node code (nl, pl, fi, all)")
    rec_parser.add_argument("--apply", action="store_true", help="Apply changes (default is dry-run)")
    rec_parser.add_argument("--allow-empty", action="store_true", help="Allow applying empty state")
    rec_parser.add_argument("--force-mass-delete", action="store_true", help="Force deletion of >30% peers")

    args = parser.parse_args()

    if args.command == "pin-key":
        return run_pin_key(args.node_code, force_confirm=args.yes, custom_known_hosts=args.known_hosts_file)
    elif args.command == "reconcile":
        dry_run = not args.apply
        mode_str = "DRY-RUN" if dry_run else "LIVE APPLY"
        print(f"[*] Reconcile invoked for node '{args.node}' ({mode_str})")
        from vpn_shop import awg_manager
        try:
            target_node = (args.node or "nl").lower().strip()
            if target_node == "all":
                results = {}
                for code in ("nl", "pl", "fi"):
                    print(f"[*] Acquiring master_node_lock('{code}')...")
                    with awg_manager.master_node_lock(code):
                        results[code] = awg_manager.reconcile_awg_peers(
                            server_code=code,
                            dry_run=dry_run,
                            allow_empty=args.allow_empty,
                            force_mass_delete=args.force_mass_delete,
                        )
                res = results
            else:
                print(f"[*] Acquiring master_node_lock('{target_node}')...")
                with awg_manager.master_node_lock(target_node):
                    res = awg_manager.reconcile_awg_peers(
                        server_code=target_node,
                        dry_run=dry_run,
                        allow_empty=args.allow_empty,
                        force_mass_delete=args.force_mass_delete,
                    )
            import json
            print(f"[RECONCILE RESULT]:\n{json.dumps(res, indent=2, ensure_ascii=False)}")
            return 0
        except Exception as exc:
            print(f"[ERROR] Reconciliation failed or aborted: {exc}")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
