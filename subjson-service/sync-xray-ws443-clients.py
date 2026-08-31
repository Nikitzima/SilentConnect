#!/usr/bin/env python3
from __future__ import annotations

import json
import sqlite3
import subprocess
import time
from pathlib import Path

XUI_DB = Path("/etc/x-ui/x-ui.db")
XRAY_CONFIG = Path("/usr/local/etc/xray-ws443/config.json")
XRAY_BIN_CANDIDATES = (
    Path("/usr/local/x-ui/bin/xray-linux-amd64"),
    Path("/usr/local/bin/xray"),
    Path("/usr/bin/xray"),
)
EXTRA_CLIENT = {
    "id": os.environ.get("EXTRA_CLIENT_ID", "00000000-0000-0000-0000-000000000000"),
    "email": "NL WS 443",
}


def read_active_vless_clients() -> list[dict[str, str]]:
    now_ms = int(time.time() * 1000)
    conn = sqlite3.connect(f"file:{XUI_DB.as_posix()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    clients: dict[str, dict[str, str]] = {EXTRA_CLIENT["id"]: dict(EXTRA_CLIENT)}
    try:
        rows = conn.execute("SELECT protocol, settings FROM inbounds WHERE protocol = 'vless'").fetchall()
        for row in rows:
            settings = json.loads(row["settings"] or "{}")
            for client in settings.get("clients") or []:
                client_id = str(client.get("id") or "").strip()
                if not client_id:
                    continue
                if client.get("enable") is False:
                    continue
                expiry_ms = int(client.get("expiryTime") or 0)
                if expiry_ms > 0 and expiry_ms <= now_ms:
                    continue
                clients[client_id] = {
                    "id": client_id,
                    "email": str(client.get("email") or client_id),
                }
    finally:
        conn.close()
    return sorted(clients.values(), key=lambda item: (item["email"], item["id"]))


def current_clients(config: dict) -> list[dict[str, str]]:
    clients = config["inbounds"][0]["settings"].get("clients") or []
    normalized = [
        {
            "id": str(client.get("id") or ""),
            "email": str(client.get("email") or client.get("id") or ""),
        }
        for client in clients
        if client.get("id")
    ]
    return sorted(normalized, key=lambda item: (item["email"], item["id"]))


def xray_bin() -> Path:
    for candidate in XRAY_BIN_CANDIDATES:
        if candidate.exists():
            return candidate
    raise RuntimeError("xray binary not found")


def main() -> None:
    clients = read_active_vless_clients()
    germany_ip = os.environ.get("FRANKFURT_IP", "203.0.113.1")

    def normalize_clients(cls):
        return sorted(
            [{k: v for k, v in c.items() if k in ("id", "email", "flow", "auth")} for c in cls],
            key=lambda x: (x.get("email", ""), x.get("id", ""), x.get("auth", ""))
        )

    # --- Netherlands local sync ---
    config = json.loads(XRAY_CONFIG.read_text(encoding="utf-8-sig"))
    local_changed = False
    if current_clients(config) != clients:
        config["inbounds"][0]["settings"]["clients"] = clients
        tmp = XRAY_CONFIG.with_name(f"{XRAY_CONFIG.stem}.tmp.json")
        tmp.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        subprocess.run([str(xray_bin()), "run", "-test", "-config", str(tmp)], check=True)
        tmp.replace(XRAY_CONFIG)
        subprocess.run(["systemctl", "restart", "xray-ws443.service"], check=True)
        print(f"ws443 clients synced locally: {len(clients)}")
        local_changed = True
    else:
        print(f"ws443 clients unchanged locally: {len(clients)}")

    # --- Netherlands local xray-maxru sync ---
    xray_maxru_config_path = Path("/usr/local/etc/xray-maxru/config.json")
    if xray_maxru_config_path.exists():
        maxru_config = json.loads(xray_maxru_config_path.read_text(encoding="utf-8"))
        
        # Build list of active VLESS clients
        expected_maxru_tcp = [{"id": c["id"], "email": c["email"], "flow": "xtls-rprx-vision"} for c in clients]
        expected_maxru_xhttp = [{"id": c["id"], "email": c["email"]} for c in clients]
        expected_maxru_grpc = [{"id": c["id"], "email": c["email"]} for c in clients]
        expected_maxru_xhttp_tcp = [{"id": c["id"], "email": c["email"]} for c in clients]
        
        # Build list of Hysteria clients: unique client UUIDs only
        expected_maxru_hysteria = [{"auth": c["id"], "email": c["email"]} for c in clients]

        # Find inbounds by tag
        inbounds_by_tag = {ib.get("tag"): ib for ib in maxru_config.get("inbounds", [])}
        tcp_inbound = inbounds_by_tag.get("vless-tcp-maxru")
        xhttp_inbound = inbounds_by_tag.get("vless-xhttp-maxru")
        grpc_inbound = inbounds_by_tag.get("vless-grpc-maxru")
        xhttp_tcp_inbound = inbounds_by_tag.get("vless-xhttp-tcp-maxru")
        hysteria_inbound = inbounds_by_tag.get("hysteria-1443")

        current_maxru_tcp = tcp_inbound["settings"].get("clients") or [] if tcp_inbound else []
        current_maxru_xhttp = xhttp_inbound["settings"].get("clients") or [] if xhttp_inbound else []
        current_maxru_grpc = grpc_inbound["settings"].get("clients") or [] if grpc_inbound else []
        current_maxru_xhttp_tcp = xhttp_tcp_inbound["settings"].get("clients") or [] if xhttp_tcp_inbound else []
        current_maxru_hysteria = hysteria_inbound["settings"].get("clients") or [] if hysteria_inbound else []

        maxru_changed = False
        if tcp_inbound and normalize_clients(current_maxru_tcp) != normalize_clients(expected_maxru_tcp):
            tcp_inbound["settings"]["clients"] = expected_maxru_tcp
            maxru_changed = True
        if xhttp_inbound and normalize_clients(current_maxru_xhttp) != normalize_clients(expected_maxru_xhttp):
            xhttp_inbound["settings"]["clients"] = expected_maxru_xhttp
            maxru_changed = True
        if grpc_inbound and normalize_clients(current_maxru_grpc) != normalize_clients(expected_maxru_grpc):
            grpc_inbound["settings"]["clients"] = expected_maxru_grpc
            maxru_changed = True
        if xhttp_tcp_inbound and normalize_clients(current_maxru_xhttp_tcp) != normalize_clients(expected_maxru_xhttp_tcp):
            xhttp_tcp_inbound["settings"]["clients"] = expected_maxru_xhttp_tcp
            maxru_changed = True
        if hysteria_inbound and normalize_clients(current_maxru_hysteria) != normalize_clients(expected_maxru_hysteria):
            hysteria_inbound["settings"]["clients"] = expected_maxru_hysteria
            maxru_changed = True

        if maxru_changed:
            print("Syncing local xray-maxru config...")
            tmp_maxru = xray_maxru_config_path.with_name("config.maxru.tmp.json")
            tmp_maxru.write_text(json.dumps(maxru_config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            subprocess.run([str(xray_bin()), "run", "-test", "-config", str(tmp_maxru)], check=True)
            tmp_maxru.replace(xray_maxru_config_path)
            subprocess.run(["systemctl", "restart", "xray-maxru.service"], check=True)
            print("Local xray-maxru config synced!")
        else:
            print("Local xray-maxru config already in sync.")

    # --- Germany sync ---
    try:
        # 1. Sync Germany xray-ws443
        res = subprocess.run([
            "ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
            f"root@{germany_ip}",
            "cat /usr/local/etc/xray-ws443/config.json"
        ], capture_output=True, text=True, check=True)
        g_ws_config = json.loads(res.stdout)
        
        expected_ws_config = json.loads(XRAY_CONFIG.read_text(encoding="utf-8-sig"))
        expected_ws_config["inbounds"][0]["settings"]["clients"] = clients
        try:
            expected_ws_config["inbounds"][0]["streamSettings"]["wsSettings"]["headers"] = {}
        except (KeyError, IndexError):
            pass

        def ws_configs_equal(c1, c2):
            if current_clients(c1) != current_clients(c2):
                return False
            try:
                h1 = c1["inbounds"][0]["streamSettings"]["wsSettings"]["headers"]
                h2 = c2["inbounds"][0]["streamSettings"]["wsSettings"]["headers"]
                if h1 != h2:
                    return False
            except (KeyError, IndexError):
                return False
            return True

        if not ws_configs_equal(g_ws_config, expected_ws_config) or local_changed:
            print("Syncing Germany xray-ws443...")
            tmp_local_ws = Path("/tmp/germany_ws_config.json")
            tmp_local_ws.write_text(json.dumps(expected_ws_config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            
            tmp_remote_ws = "/usr/local/etc/xray-ws443/config.tmp.json"
            subprocess.run([
                "scp", "-o", "StrictHostKeyChecking=no",
                str(tmp_local_ws),
                f"root@{germany_ip}:{tmp_remote_ws}"
            ], check=True)
            
            subprocess.run([
                "ssh", "-o", "StrictHostKeyChecking=no",
                f"root@{germany_ip}",
                f"/usr/local/bin/xray run -test -config {tmp_remote_ws}"
            ], check=True)
            
            subprocess.run([
                "ssh", "-o", "StrictHostKeyChecking=no",
                f"root@{germany_ip}",
                f"mv {tmp_remote_ws} /usr/local/etc/xray-ws443/config.json && systemctl restart xray-ws443.service"
            ], check=True)
            print("Germany xray-ws443 synced!")
        else:
            print("Germany xray-ws443 clients already in sync.")


        # 2. Sync Germany xray main (Reality TCP, XHTTP & gRPC)
        res = subprocess.run([
            "ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
            f"root@{germany_ip}",
            "cat /usr/local/etc/xray/config.json"
        ], capture_output=True, text=True, check=True)
        g_main_config = json.loads(res.stdout)
        
        expected_tcp = [{"id": c["id"], "email": c["email"], "flow": "xtls-rprx-vision"} for c in clients]
        expected_xhttp = [{"id": c["id"], "email": c["email"]} for c in clients]
        expected_grpc = [{"id": c["id"], "email": c["email"]} for c in clients]
        
        current_tcp = g_main_config["inbounds"][0]["settings"].get("clients") or []
        current_xhttp = g_main_config["inbounds"][1]["settings"].get("clients") or []
        current_grpc = g_main_config["inbounds"][2]["settings"].get("clients") or []
        

        if normalize_clients(current_tcp) != normalize_clients(expected_tcp) or normalize_clients(current_xhttp) != normalize_clients(expected_xhttp) or normalize_clients(current_grpc) != normalize_clients(expected_grpc):
            print("Syncing Germany xray main config...")
            g_main_config["inbounds"][0]["settings"]["clients"] = expected_tcp
            g_main_config["inbounds"][1]["settings"]["clients"] = expected_xhttp
            g_main_config["inbounds"][2]["settings"]["clients"] = expected_grpc
            
            tmp_local = Path("/tmp/germany_xray_config.json")
            tmp_local.write_text(json.dumps(g_main_config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            
            tmp_remote = "/usr/local/etc/xray/config.tmp.json"
            subprocess.run([
                "scp", "-o", "StrictHostKeyChecking=no",
                str(tmp_local),
                f"root@{germany_ip}:{tmp_remote}"
            ], check=True)
            
            subprocess.run([
                "ssh", "-o", "StrictHostKeyChecking=no",
                f"root@{germany_ip}",
                f"/usr/local/bin/xray run -test -config {tmp_remote}"
            ], check=True)
            
            subprocess.run([
                "ssh", "-o", "StrictHostKeyChecking=no",
                f"root@{germany_ip}",
                f"mv {tmp_remote} /usr/local/etc/xray/config.json && systemctl restart xray.service"
            ], check=True)
            print("Germany xray main config synced!")
        else:
            print("Germany xray main config already in sync.")
            
    except Exception as e:
        print(f"Error syncing Germany server: {e}")


if __name__ == "__main__":
    main()
