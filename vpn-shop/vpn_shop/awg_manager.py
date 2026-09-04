"""AWG (AmneziaWG) peer manager для выдачи warp-конфигов клиентам.

Поддерживает мультисерверную архитектуру:
- NL (Нидерланды): локальный docker-контейнер amnezia-awg2 (порт 44121, подсеть 10.8.1.0/24).
- FI (Финляндия): удаленный docker-контейнер amnezia-awg2 на FI_HOST (порт 49752, подсеть 10.8.2.0/24) через SSH.

Live-изменения через `awg set` + персистентность в /opt/amnezia/awg/awg0.conf
(официальный механизм Amnezia: конфиг-файл - источник истины при старте контейнера).

Привязка: sub_id подписки Happ <-> пир. Срок/квоту контролирует awg_reconcile.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

SERVERS: dict[str, dict[str, Any]] = {
    "nl": {
        "code": "nl",
        "name": "Нидерланды 🇳🇱",
        "flag": "🇳🇱",
        "mode": "local",
        "exec_mode": "local",
        "host": "127.0.0.1",
        "container": os.environ.get("AWG_NL_CONTAINER", os.environ.get("AWG_CONTAINER_NAME", "amnezia-awg2")),
        "conf_path": "/opt/amnezia/awg/awg0.conf",
        "subnet": os.environ.get("AWG_NL_SUBNET", "10.8.1"),
        "endpoint_host": os.environ.get("AWG_NL_ENDPOINT_HOST", "warp.example.com"),
        "endpoint_port": os.environ.get("AWG_NL_ENDPOINT_PORT", "44121"),
        "allowed_ips_file": os.environ.get("AWG_ALLOWED_IPS_FILE", "/root/vpn-shop/awg/allowed-ips.txt"),
        "client_dns": os.environ.get("AWG_CLIENT_DNS", "1.1.1.1, 1.0.0.1"),
        "client_mtu": os.environ.get("AWG_CLIENT_MTU", "1280"),
        "reserved_ips": {"10.8.1.1", "10.8.1.2", "10.8.1.3", "10.8.1.4", "10.8.1.6"},
    },
    "fi": {
        "code": "fi",
        "name": "Финляндия 🇫🇮",
        "flag": "🇫🇮",
        "mode": "ssh",
        "exec_mode": "ssh",
        "host": os.environ.get("AWG_FI_HOST", os.environ.get("AWG_REMOTE_SSH_FI", os.environ.get("FI_STANDBY_IP", "198.51.100.1"))),
        "ssh_host": os.environ.get("AWG_FI_HOST", os.environ.get("AWG_REMOTE_SSH_FI", os.environ.get("FI_STANDBY_IP", "198.51.100.1"))),
        "ssh_user": os.environ.get("AWG_FI_SSH_USER", "root"),
        "ssh_port": int(os.environ.get("AWG_FI_SSH_PORT", "22")),
        "container": os.environ.get("AWG_FI_CONTAINER", "amnezia-awg2"),
        "conf_path": "/opt/amnezia/awg/awg0.conf",
        "subnet": os.environ.get("AWG_FI_SUBNET", "10.8.2"),
        "endpoint_host": os.environ.get("AWG_FI_ENDPOINT_HOST", os.environ.get("AWG_FI_ENDPOINT", "fi.example.com")),
        "endpoint_port": os.environ.get("AWG_FI_ENDPOINT_PORT", "49752"),
        "allowed_ips_file": os.environ.get("AWG_FI_ALLOWED_IPS_FILE", os.environ.get("AWG_ALLOWED_IPS_FILE", "/root/vpn-shop/awg/allowed-ips.txt")),
        "client_dns": os.environ.get("AWG_CLIENT_DNS", "1.1.1.1, 1.0.0.1"),
        "client_mtu": os.environ.get("AWG_CLIENT_MTU", "1280"),
        "reserved_ips": {"10.8.2.1", "10.8.2.2", "10.8.2.3", "10.8.2.4", "10.8.2.6"},
    },
    "pl": {
        "code": "pl",
        "name": "Польша 🇵🇱",
        "flag": "🇵🇱",
        "mode": "ssh",
        "exec_mode": "ssh",
        "host": os.environ.get("AWG_PL_HOST", "2.56.125.177"),
        "ssh_host": os.environ.get("AWG_PL_HOST", "2.56.125.177"),
        "ssh_user": os.environ.get("AWG_PL_SSH_USER", "root"),
        "ssh_port": int(os.environ.get("AWG_PL_SSH_PORT", "22")),
        "container": os.environ.get("AWG_PL_CONTAINER", "amnezia-awg2"),
        "conf_path": "/opt/amnezia/awg/awg0.conf",
        "subnet": os.environ.get("AWG_PL_SUBNET", "10.8.3"),
        "endpoint_host": os.environ.get("AWG_PL_ENDPOINT_HOST", "pl.silentconnect.net"),
        "endpoint_port": os.environ.get("AWG_PL_ENDPOINT_PORT", "44121"),
        "allowed_ips_file": os.environ.get("AWG_PL_ALLOWED_IPS_FILE", os.environ.get("AWG_ALLOWED_IPS_FILE", "/root/vpn-shop/awg/allowed-ips.txt")),
        "client_dns": os.environ.get("AWG_CLIENT_DNS", "1.1.1.1, 1.0.0.1"),
        "client_mtu": os.environ.get("AWG_CLIENT_MTU", "1280"),
        "reserved_ips": {"10.8.3.1", "10.8.3.2", "10.8.3.3", "10.8.3.4", "10.8.3.6"},
    },
}

DB_PATH = os.environ.get("SHOP_DB_PATH", "/root/vpn-shop/data/vpn_shop.db")


def _get_server(server_code: str = "nl") -> dict[str, Any]:
    code = (server_code or "nl").lower().strip()
    if code not in SERVERS:
        code = "nl"
    srv = dict(SERVERS[code])
    local_server = os.environ.get("AWG_LOCAL_SERVER", "nl").lower().strip()
    if local_server == "fi":
        if code == "fi":
            srv["mode"] = "local"
            srv["exec_mode"] = "local"
            srv["host"] = "127.0.0.1"
        elif code == "nl":
            srv["mode"] = "ssh"
            srv["exec_mode"] = "ssh"
            srv["host"] = os.environ.get("AWG_NL_HOST", os.environ.get("NL_MASTER_IP", "192.0.2.1"))
            srv["ssh_host"] = os.environ.get("AWG_NL_HOST", os.environ.get("NL_MASTER_IP", "192.0.2.1"))
            srv["ssh_user"] = os.environ.get("AWG_NL_SSH_USER", "root")
            srv["ssh_port"] = int(os.environ.get("AWG_NL_SSH_PORT", "22"))
    elif local_server == "pl":
        if code == "pl":
            srv["mode"] = "local"
            srv["exec_mode"] = "local"
            srv["host"] = "127.0.0.1"
    return srv


def _dex(*args: Any, **kwargs: Any) -> str:
    """Execute command inside target container either locally (NL) or over SSH (FI).
    
    Supports flexible signatures:
    - _dex(cmd, inp=None, server_code="nl")
    - _dex(server_code, cmd, inp=None)
    - _dex(cmd=..., inp=..., server_code=...)
    """
    server_code = "nl"
    cmd = ""
    inp = kwargs.get("inp")

    if "server_code" in kwargs:
        server_code = kwargs["server_code"]
    if "cmd" in kwargs:
        cmd = kwargs["cmd"]

    if len(args) == 1:
        if not cmd:
            cmd = args[0]
    elif len(args) == 2:
        if str(args[0]).lower() in SERVERS:
            server_code = str(args[0])
            cmd = str(args[1])
        else:
            cmd = str(args[0])
            inp = str(args[1])
    elif len(args) >= 3:
        if str(args[0]).lower() in SERVERS:
            server_code = str(args[0])
            cmd = str(args[1])
            inp = str(args[2])
        else:
            cmd = str(args[0])
            inp = str(args[1])
            server_code = str(args[2])

    srv = _get_server(server_code)
    mode = srv.get("mode") or srv.get("exec_mode", "local")

    if mode == "local":
        call_args = ["docker", "exec", "-i", srv["container"], "sh", "-c", cmd]
    elif mode == "ssh":
        ssh_user = srv.get("ssh_user", "root")
        ssh_host = srv.get("host") or srv.get("ssh_host", os.environ.get("FI_STANDBY_IP", "198.51.100.1"))
        ssh_port = str(srv.get("ssh_port", 22))
        remote_cmd = f"docker exec -i {srv['container']} sh -c {shlex.quote(cmd)}"
        call_args = [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ControlMaster=auto",
            "-o", "ControlPath=/tmp/ssh-awg-%r@%h:%p",
            "-o", "ControlPersist=300",
            "-p", ssh_port,
            f"{ssh_user}@{ssh_host}",
            remote_cmd,
        ]
    else:
        raise ValueError(f"Unsupported execution mode: {mode}")

    r = subprocess.run(call_args, input=inp, capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise RuntimeError(f"[{server_code.upper()}] exec failed: {r.stderr.strip()[:300]}")
    return r.stdout.strip()


def _server_conf(server_code: str = "nl") -> str:
    srv = _get_server(server_code)
    return _dex(f"cat {srv['conf_path']}", server_code=server_code)


def _interface_params(conf: str) -> dict[str, str]:
    """Значения [Interface] серверного конфига, нужные клиенту (обфускация и т.п.)."""
    params: dict[str, str] = {}
    in_iface = False
    for line in conf.splitlines():
        s = line.strip()
        if s == "[Peer]":
            break
        if s == "[Interface]":
            in_iface = True
            continue
        if in_iface and "=" in s:
            k, v = s.split("=", 1)
            params[k.strip()] = v.strip()
    return params


def _server_public_key(conf: str, server_code: str = "nl") -> str:
    m = re.search(r"^PrivateKey\s*=\s*(\S+)", conf, re.M)
    if not m:
        raise RuntimeError(f"server PrivateKey not found for {server_code}")
    try:
        return _dex(f"echo '{m.group(1)}' | awg pubkey", server_code="nl")
    except Exception:
        return _dex(f"echo '{m.group(1)}' | awg pubkey", server_code=server_code)


def _used_ips(server_code: str = "nl") -> set[str]:
    srv = _get_server(server_code)
    ips: set[str] = set()
    conf = _server_conf(server_code)
    subnet = srv["subnet"]
    for m in re.finditer(r"AllowedIPs\s*=\s*([^\r\n#]+)", conf):
        for cidr in m.group(1).split(","):
            cidr = cidr.strip()
            if cidr.startswith(subnet + "."):
                ips.add(cidr.split("/")[0])
    try:
        with _db() as conn:
            for row in conn.execute("SELECT tunnel_ip FROM awg_peers WHERE server_code = ?", (server_code,)).fetchall():
                ips.add(row[0])
    except Exception:
        pass
    return ips


def _next_free_ip(server_code: str = "nl") -> str:
    srv = _get_server(server_code)
    used = _used_ips(server_code) | set(srv.get("reserved_ips", set()))
    subnet = srv["subnet"]
    for i in range(2, 255):
        ip = f"{subnet}.{i}"
        if ip not in used:
            return ip
    raise RuntimeError(f"AWG subnet {subnet}.0/24 exhausted on {server_code}")


def _genkey(server_code: str = "nl") -> str:
    try:
        return _dex("awg genkey", server_code="nl")
    except Exception:
        return _dex("awg genkey", server_code=server_code)


def _pubkey(privkey: str, server_code: str = "nl") -> str:
    try:
        return _dex("awg pubkey", inp=privkey + "\n", server_code="nl")
    except Exception:
        return _dex("awg pubkey", inp=privkey + "\n", server_code=server_code)


def _genpsk(server_code: str = "nl") -> str:
    try:
        return _dex("awg genpsk", server_code="nl")
    except Exception:
        return _dex("awg genpsk", server_code=server_code)


@contextmanager
def _db() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def ensure_table() -> None:
    with _db() as conn:
        table_info = conn.execute("PRAGMA table_info(awg_peers)").fetchall()
        if not table_info:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS awg_peers (
                    sub_id          TEXT NOT NULL,
                    server_code     TEXT NOT NULL DEFAULT 'nl',
                    private_key     TEXT NOT NULL,
                    public_key      TEXT NOT NULL,
                    preshared_key   TEXT NOT NULL,
                    tunnel_ip       TEXT NOT NULL,
                    created_at      TEXT NOT NULL,
                    period_start    TEXT NOT NULL,
                    bytes_used      INTEGER NOT NULL DEFAULT 0,
                    last_rx         INTEGER NOT NULL DEFAULT 0,
                    last_tx         INTEGER NOT NULL DEFAULT 0,
                    active          INTEGER NOT NULL DEFAULT 1,
                    inactive_reason TEXT,
                    PRIMARY KEY (sub_id, server_code)
                )
                """
            )
        else:
            cols = {row[1] for row in table_info}
            if "server_code" not in cols:
                conn.execute("PRAGMA foreign_keys=OFF")
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS awg_peers_v2 (
                        sub_id          TEXT NOT NULL,
                        server_code     TEXT NOT NULL DEFAULT 'nl',
                        private_key     TEXT NOT NULL,
                        public_key      TEXT NOT NULL,
                        preshared_key   TEXT NOT NULL,
                        tunnel_ip       TEXT NOT NULL,
                        created_at      TEXT NOT NULL,
                        period_start    TEXT NOT NULL,
                        bytes_used      INTEGER NOT NULL DEFAULT 0,
                        last_rx         INTEGER NOT NULL DEFAULT 0,
                        last_tx         INTEGER NOT NULL DEFAULT 0,
                        active          INTEGER NOT NULL DEFAULT 1,
                        inactive_reason TEXT,
                        PRIMARY KEY (sub_id, server_code)
                    )
                    """
                )
                conn.execute(
                    """
                    INSERT OR IGNORE INTO awg_peers_v2 (
                        sub_id, server_code, private_key, public_key, preshared_key,
                        tunnel_ip, created_at, period_start, bytes_used, last_rx, last_tx,
                        active, inactive_reason
                    )
                    SELECT
                        sub_id, 'nl', private_key, public_key, preshared_key,
                        tunnel_ip, created_at, period_start, bytes_used, last_rx, last_tx,
                        active, inactive_reason
                    FROM awg_peers
                    """
                )
                conn.execute("DROP TABLE awg_peers")
                conn.execute("ALTER TABLE awg_peers_v2 RENAME TO awg_peers")
                conn.execute("PRAGMA foreign_keys=ON")

        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_awg_peers_server_ip ON awg_peers (server_code, tunnel_ip)"
        )


def get_peer(sub_id: str, server_code: str | None = "nl") -> dict[str, Any] | None:
    ensure_table()
    with _db() as conn:
        if server_code is None:
            row = conn.execute(
                "SELECT * FROM awg_peers WHERE sub_id = ? ORDER BY active DESC LIMIT 1",
                (sub_id,),
            ).fetchone()
        else:
            code = (server_code or "nl").lower().strip()
            row = conn.execute(
                "SELECT * FROM awg_peers WHERE sub_id = ? AND server_code = ?",
                (sub_id, code),
            ).fetchone()
            if not row and code == "nl":
                row = conn.execute("SELECT * FROM awg_peers WHERE sub_id = ?", (sub_id,)).fetchone()
    return dict(row) if row else None


def create_peer(sub_id: str, server_code: str = "nl") -> dict[str, Any]:
    """Создать пир на указанном сервере и привязать к sub_id. Возвращает запись пира."""
    ensure_table()
    server_code = (server_code or "nl").lower().strip()
    srv = _get_server(server_code)

    existing = get_peer(sub_id, server_code=server_code)
    if existing and existing.get("active"):
        return existing

    conf = _server_conf(server_code)
    server_pub = _server_public_key(conf, server_code=server_code)
    ip = _next_free_ip(server_code)
    priv = _genkey(server_code)
    pub = _pubkey(priv, server_code=server_code)
    psk = _genpsk(server_code)

    # live add in container
    psk_file = "/tmp/.awg-psk.tmp"
    _dex(f"echo '{psk}' > {psk_file}", server_code=server_code)
    _dex(f"awg set awg0 peer {pub} allowed-ips {ip}/32 preshared-key {psk_file}", server_code=server_code)
    _dex(f"rm -f {psk_file}", server_code=server_code)

    # персистентность: дописать только блок [Peer] в awg0.conf внутри контейнера (если ещё не присутствует)
    if pub not in conf:
        block = (
            f"\n[Peer]\nPublicKey = {pub}\nPresharedKey = {psk}\n"
            f"AllowedIPs = {ip}/32\n"
        )
        _dex(f"cat >> {srv['conf_path']}", inp=block, server_code=server_code)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    row = {
        "sub_id": sub_id,
        "server_code": server_code,
        "private_key": priv,
        "public_key": pub,
        "preshared_key": psk,
        "tunnel_ip": ip,
        "created_at": now,
        "period_start": now[:10],
        "bytes_used": 0,
        "last_rx": 0,
        "last_tx": 0,
        "active": 1,
        "inactive_reason": "",
    }
    with _db() as conn:
        conn.execute(
            """INSERT INTO awg_peers (
                sub_id, server_code, private_key, public_key, preshared_key,
                tunnel_ip, created_at, period_start, bytes_used, last_rx, last_tx,
                active, inactive_reason
               )
               VALUES (
                :sub_id, :server_code, :private_key, :public_key, :preshared_key,
                :tunnel_ip, :created_at, :period_start, :bytes_used, :last_rx,
                :last_tx, :active, :inactive_reason
               )
               ON CONFLICT(sub_id, server_code) DO UPDATE SET
                 private_key=:private_key, public_key=:public_key,
                 preshared_key=:preshared_key, tunnel_ip=:tunnel_ip,
                 created_at=:created_at, period_start=:period_start,
                 active=1, inactive_reason=''""",
            row,
        )
    return row


def remove_peer(sub_id: str, reason: str = "", server_code: str = "nl") -> bool:
    """Удалить пир из live и из конфига сервера. Запись остаётся в БД (active=0)."""
    server_code = (server_code or "nl").lower().strip()
    srv = _get_server(server_code)
    peer = get_peer(sub_id, server_code=server_code)
    if not peer or not peer.get("active"):
        return False
    conf = _server_conf(server_code)
    try:
        _dex(f"awg set awg0 peer {peer['public_key']} remove", server_code=server_code)
    except Exception:
        pass
    blocks = conf.split("\n[Peer]\n")
    kept = [blocks[0]]
    for b in blocks[1:]:
        if peer["public_key"] not in b:
            kept.append(b)
    new_conf = "\n[Peer]\n".join(kept)
    if not new_conf.endswith("\n"):
        new_conf += "\n"
    _dex(f"cat > {srv['conf_path']}", inp=new_conf, server_code=server_code)
    with _db() as conn:
        conn.execute(
            "UPDATE awg_peers SET active=0, inactive_reason=? WHERE sub_id=? AND server_code=?",
            (reason, sub_id, server_code),
        )
    return True


def readd_peer(sub_id: str, server_code: str = "nl") -> bool:
    """Вернуть ранее удалённого пира (продление/новый период)."""
    server_code = (server_code or "nl").lower().strip()
    srv = _get_server(server_code)
    peer = get_peer(sub_id, server_code=server_code)
    if not peer:
        return False
    conf = _server_conf(server_code)
    psk_file = "/tmp/.awg-psk.tmp"
    _dex(f"echo '{peer['preshared_key']}' > {psk_file}", server_code=server_code)
    _dex(f"awg set awg0 peer {peer['public_key']} allowed-ips {peer['tunnel_ip']}/32 preshared-key {psk_file}", server_code=server_code)
    _dex(f"rm -f {psk_file}", server_code=server_code)
    
    if peer["public_key"] not in conf:
        block = (
            f"\n[Peer]\nPublicKey = {peer['public_key']}\n"
            f"PresharedKey = {peer['preshared_key']}\nAllowedIPs = {peer['tunnel_ip']}/32\n"
        )
        _dex(f"cat >> {srv['conf_path']}", inp=block, server_code=server_code)

    with _db() as conn:
        conn.execute(
            "UPDATE awg_peers SET active=1, inactive_reason='' WHERE sub_id=? AND server_code=?",
            (sub_id, server_code),
        )
    return True


def build_conf(sub_id: str, server_code: str = "nl") -> str:
    """Собрать клиентский .conf по официальному шаблону Amnezia (template.conf) для выбранного сервера."""
    server_code = (server_code or "nl").lower().strip()
    srv = _get_server(server_code)
    peer = get_peer(sub_id, server_code=server_code)
    if not peer or not peer.get("active"):
        raise RuntimeError(f"AWG peer for {sub_id} on {server_code.upper()} is not active")

    conf = _server_conf(server_code)
    iface = _interface_params(conf)
    server_pub = _server_public_key(conf, server_code=server_code)

    allowed = "0.0.0.0/0, ::/0"
    try:
        allowed_ips_file = srv.get("allowed_ips_file") or "/root/vpn-shop/awg/allowed-ips.txt"
        lst = Path(allowed_ips_file).read_text(encoding="utf-8").strip()
        if lst:
            allowed = lst + ", ::/0"
    except OSError:
        pass

    lines = [
        "[Interface]",
        f"Address = {peer['tunnel_ip']}/32",
        f"DNS = {srv['client_dns']}",
        f"PrivateKey = {peer['private_key']}",
    ]
    # обфускационные параметры - 1:1 с сервером (порядок как в template.conf AmneziaWG 3.1)
    for k in (
        "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4",
        "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5",
        "HeaderProtectionKey", "ContentPaddingAddition",
        "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime",
        "KeepaliveTimeout", "MaxHandshakeAttempts",
        "RandomTrailers", "DisableCookies"
    ):
        if k in iface:
            lines.append(f"{k} = {iface[k]}")
    lines += [
        f"MTU = {srv['client_mtu']}",
        "",
        "[Peer]",
        f"PublicKey = {server_pub}",
        f"PresharedKey = {peer['preshared_key']}",
        f"AllowedIPs = {allowed}",
        f"Endpoint = {srv['endpoint_host']}:{srv['endpoint_port']}",
        "PersistentKeepalive = 25",
    ]
    return "\n".join(lines) + "\n"


def peer_transfer(server_code: str = "nl") -> dict[str, tuple[int, int]]:
    """Счётчики трафика пиров из `awg show awg0 dump` на выбранном сервере: {pubkey: (rx, tx)}."""
    server_code = (server_code or "nl").lower().strip()
    out = _dex("awg show awg0 dump", server_code=server_code)
    result: dict[str, tuple[int, int]] = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 7 and parts[0].count("/") == 0 and len(parts[0]) >= 40:
            try:
                result[parts[0]] = (int(parts[5]), int(parts[6]))
            except ValueError:
                continue
    return result


def set_usage(sub_id: str, total_used: int, server_code: str = "nl") -> None:
    server_code = (server_code or "nl").lower().strip()
    with _db() as conn:
        conn.execute(
            "UPDATE awg_peers SET bytes_used=? WHERE sub_id=? AND server_code=?",
            (total_used, sub_id, server_code),
        )


def set_period(sub_id: str, period_start: str, server_code: str = "nl") -> None:
    server_code = (server_code or "nl").lower().strip()
    with _db() as conn:
        conn.execute(
            "UPDATE awg_peers SET period_start=?, bytes_used=0 WHERE sub_id=? AND server_code=?",
            (period_start, sub_id, server_code),
        )


def set_counters(sub_id: str, rx: int, tx: int, server_code: str = "nl") -> None:
    server_code = (server_code or "nl").lower().strip()
    with _db() as conn:
        conn.execute(
            "UPDATE awg_peers SET last_rx=?, last_tx=? WHERE sub_id=? AND server_code=?",
            (rx, tx, sub_id, server_code),
        )


def deactivate(sub_id: str, reason: str, server_code: str = "nl") -> None:
    remove_peer(sub_id, reason, server_code=server_code)


def activate(sub_id: str, server_code: str = "nl") -> None:
    readd_peer(sub_id, server_code=server_code)


def all_peers(active_only: bool = True, server_code: str | None = None) -> list[dict[str, Any]]:
    ensure_table()
    q = "SELECT * FROM awg_peers"
    clauses = []
    params: list[Any] = []
    if active_only:
        clauses.append("active = 1")
    if server_code:
        clauses.append("server_code = ?")
        params.append(server_code.lower().strip())
    if clauses:
        q += " WHERE " + " AND ".join(clauses)
    with _db() as conn:
        return [dict(r) for r in conn.execute(q, params).fetchall()]
