#!/usr/bin/env python3
"""
deploy_openflux_nodes.py
Configures and launches OpenFlux Core v0.2.0 shards on NL, PL, and FI servers.
"""

import sys
from pathlib import Path
from remote_exec import run_cmd, get_client

UNIT_FILE = """[Unit]
Description=OpenFlux Core v0.2.0 Exit Node Shard %i
After=network.target

[Service]
Type=simple
EnvironmentFile=/etc/openflux-node/%i.env
ExecStart=/opt/openflux-node/bin/openflux --role=exit --mode=l3 --transport=${OPENFLUX_TRANSPORT} --url=${OPENFLUX_URL} --encryption-key-file=${OPENFLUX_KEY_FILE} ${OPENFLUX_EXTRA_ARGS}
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
"""

SERVERS = {
    "nl": {
        "shards": [
            ("nl_01", "https://disk.yandex.ru/i/_-g0vNUuu69ffw")
        ]
    },
    "pl": {
        "shards": [
            ("pl_01", "https://disk.yandex.ru/i/hb1xodFfECGL8w")
        ]
    },
    "fi": {
        "shards": [
            ("fi_01", "https://yadi.sk/d/I0ULWUKv_9YzpA")
        ]
    }
}

KEY_CONTENT = "sc_oflux_2026_e8d47b19a3c25f01e74a"


def deploy_to_node(node_name: str, config: dict):
    print(f"\n==========================================")
    print(f"[*] Deploying OpenFlux v0.2.0 to {node_name.upper()}...")
    print(f"==========================================")

    # 1. Clean legacy files
    clean_cmd = (
        "systemctl stop openflux-exit.service 2>/dev/null || true; "
        "systemctl disable openflux-exit.service 2>/dev/null || true; "
        "rm -rf /opt/OpenFlux/downloads /opt/OpenFlux/universal-bypass-tool* /root/openflux-downloads /etc/systemd/system/openflux-exit.service; "
        "mkdir -p /opt/openflux-node/bin /etc/openflux-node"
    )
    code, out, err = run_cmd(node_name, clean_cmd)
    if code != 0:
        print(f"[!] Warning on clean ({node_name}): {err}")

    # 2. Write key file
    key_cmd = f"echo -n '{KEY_CONTENT}' > /etc/openflux-node/secret.key && chmod 600 /etc/openflux-node/secret.key"
    run_cmd(node_name, key_cmd)

    # 3. Write unit file safely via base64
    import base64
    b64_unit = base64.b64encode(UNIT_FILE.encode("utf-8")).decode("ascii")
    unit_cmd = (
        f"echo '{b64_unit}' | base64 -d > /etc/systemd/system/openflux-node@.service && "
        "systemctl daemon-reload"
    )
    code, out, err = run_cmd(node_name, unit_cmd)
    if code != 0:
        print(f"[!] Error writing unit file on {node_name}: {err}")
        return False

    # 4. Write pool JSON and shard env files
    shards_list = []
    for shard_id, shard_url in config["shards"]:
        env_content = f"""OPENFLUX_TRANSPORT="vyandex"
OPENFLUX_URL="{shard_url}"
OPENFLUX_KEY_FILE="/etc/openflux-node/secret.key"
OPENFLUX_EXTRA_ARGS="--debug=1"
"""
        b64_env = base64.b64encode(env_content.encode("utf-8")).decode("ascii")
        shard_setup = (
            f"echo '{b64_env}' | base64 -d > /etc/openflux-node/{shard_id}.env && "
            f"systemctl enable --now openflux-node@{shard_id}.service"
        )
        run_cmd(node_name, shard_setup)
        shards_list.append({"id": shard_id, "url": shard_url, "active": True})

    import json
    pool_json = json.dumps({
        "country": node_name,
        "updated_at": "2026-09-29T22:00:00Z",
        "total_shards": len(shards_list),
        "shards": shards_list,
    }, indent=2)
    b64_pool = base64.b64encode(pool_json.encode("utf-8")).decode("ascii")
    run_cmd(node_name, f"echo '{b64_pool}' | base64 -d > /etc/openflux-node/pool_{node_name}.json")

    # 5. Check status
    for shard_id, _ in config["shards"]:
        code, out, _ = run_cmd(node_name, f"sleep 1; systemctl is-active openflux-node@{shard_id}.service")
        status = out.strip()
        print(f"    -> Shard {shard_id}: {status}")

    return True


def main():
    for node, cfg in SERVERS.items():
        deploy_to_node(node, cfg)
    print("\n[OK] All nodes processed.")


if __name__ == "__main__":
    main()
