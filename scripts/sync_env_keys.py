import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
import scripts.remote_exec as r

AWG_PUBKEYS = {
    "AWG_NL_SERVER_PUBKEY": "70IPdY8HdG8GnzI6R5XfOFUSVlzuF19J615ohu/wxEI=",
    "AWG_PL_SERVER_PUBKEY": "bi1igMRahaWDgvo7ClePLOwnXYjhdo+7PMaswXVtlAs=",
    "AWG_FI_SERVER_PUBKEY": "Ddu8+r+rovOke5uONFDjt+R9iUPy6E5CCzaXNw+PJWQ=",
}

FI_XUI_CONFIG = {
    "XUI_DB_PATH": "/etc/x-ui/x-ui.db",
    "XUI_PANEL_URL": "http://127.0.0.1:2053/e3gzIe9TsXpSddXQXk/",
    "XUI_USERNAME": "Nikitzima",
    "XUI_PASSWORD": "Nik!t@1881",
    "XUI_VERIFY_TLS": "false",
    "XUI_XHTTP_INBOUND_ID": "1",
    "XUI_TCP_INBOUND_ID": "2",
}

def sync_env_for_node(target: str):
    print(f"\n==================================================")
    print(f"UPDATING ENV FOR NODE: {target.upper()}")
    print(f"==================================================")
    client = r.get_client(target)
    
    # 1. Read current .env.silentconnect
    stdin, stdout, stderr = client.exec_command("cat /root/vpn-shop/.env.silentconnect")
    current_content = stdout.read().decode('utf-8', errors='replace')
    
    # Backup
    stdin, stdout, stderr = client.exec_command("cp /root/vpn-shop/.env.silentconnect /root/vpn-shop/.env.silentconnect.bak_audit8")
    
    lines = current_content.splitlines()
    env_map = {}
    ordered_keys = []
    for line in lines:
        line_s = line.strip()
        if not line_s or line_s.startswith("#") or "=" not in line_s:
            continue
        k, v = line_s.split("=", 1)
        k = k.strip()
        v = v.strip().strip('"\'')
        env_map[k] = v
        ordered_keys.append(k)

    # Add AWG pubkeys
    for k, v in AWG_PUBKEYS.items():
        env_map[k] = v

    # Node-specific XUI settings
    if target == "fi":
        for k, v in FI_XUI_CONFIG.items():
            env_map[k] = v
    elif target == "pl":
        env_map["XUI_PANEL_URL"] = "http://127.0.0.1:2053/e3gzIe9TsXpSddXQXk/"
        env_map["XUI_VERIFY_TLS"] = "false"

    # Reconstruct env content
    new_lines = []
    seen = set()
    for line in lines:
        line_s = line.strip()
        if line_s and not line_s.startswith("#") and "=" in line_s:
            k = line_s.split("=", 1)[0].strip()
            if k in env_map:
                new_lines.append(f'{k}="{env_map[k]}"')
                seen.add(k)
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)

    # Append new keys that were not originally in file
    new_lines.append("\n# --- Audit 8: Cluster Mesh & Local Reconciler Keys ---")
    for k, v in AWG_PUBKEYS.items():
        if k not in seen:
            new_lines.append(f'{k}="{v}"')
            seen.add(k)
    if target == "fi":
        for k, v in FI_XUI_CONFIG.items():
            if k not in seen:
                new_lines.append(f'{k}="{v}"')
                seen.add(k)

    updated_text = "\n".join(new_lines).strip() + "\n"

    # Upload updated file
    sftp = client.open_sftp()
    with sftp.file("/root/vpn-shop/.env.silentconnect", "w") as f:
        f.write(updated_text)
    sftp.close()
    print(f"Successfully updated /root/vpn-shop/.env.silentconnect on {target.upper()}")

    # Also sync subjson.env if needed
    stdin, stdout, stderr = client.exec_command("cat /root/subjson-service/subjson.env")
    sub_content = stdout.read().decode('utf-8', errors='replace')
    sub_lines = sub_content.splitlines()
    sub_seen = {l.split("=", 1)[0].strip() for l in sub_lines if l.strip() and not l.strip().startswith("#") and "=" in l}
    sub_additions = []
    for k, v in AWG_PUBKEYS.items():
        if k not in sub_seen:
            sub_additions.append(f'{k}="{v}"')
    if sub_additions:
        new_sub = sub_content.strip() + "\n\n# --- Audit 8 Keys ---\n" + "\n".join(sub_additions) + "\n"
        sftp = client.open_sftp()
        with sftp.file("/root/subjson-service/subjson.env", "w") as f:
            f.write(new_sub)
        sftp.close()
        print(f"Successfully updated /root/subjson-service/subjson.env on {target.upper()}")

    client.close()

def main():
    for t in ["fi", "pl", "nl"]:
        sync_env_for_node(t)

if __name__ == "__main__":
    main()
