"""AWG (AmneziaWG) peer manager для выдачи warp-конфигов клиентам.

Поддерживает мультисерверную архитектуру:
- NL (Нидерланды): локальный docker-контейнер amnezia-awg2 (порт 44121, подсеть 10.8.1.0/24).
- FI (Финляндия): удаленный docker-контейнер amnezia-awg2 на FI_HOST (порт 49752, подсеть 10.8.2.0/24) через SSH.

Live-изменения через `awg set` + персистентность в /opt/amnezia/awg/awg0.conf
(официальный механизм Amnezia: конфиг-файл - источник истины при старте контейнера).

Привязка: sub_id подписки Happ <-> пир. Срок/квоту контролирует awg_reconcile.
"""

from __future__ import annotations

import logging
import os
import re
import shlex
import subprocess
import sqlite3
import socket
import tempfile
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

try:
    import fcntl
except ImportError:
    fcntl = None  # type: ignore

LOGGER = logging.getLogger("vpn_shop.awg_manager")

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
        "endpoint_host": os.environ.get("AWG_NL_ENDPOINT_HOST", "warp.silentconnect.net"),  # PLACEHOLDER
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
        "host": os.environ.get("AWG_FI_HOST", os.environ.get("AWG_REMOTE_SSH_FI", os.environ.get("FI_STANDBY_IP", ""))),  # PLACEHOLDER
        "ssh_host": os.environ.get("AWG_FI_HOST", os.environ.get("AWG_REMOTE_SSH_FI", os.environ.get("FI_STANDBY_IP", ""))),  # PLACEHOLDER
        "ssh_user": os.environ.get("AWG_FI_SSH_USER", "root"),
        "ssh_port": int(os.environ.get("AWG_FI_SSH_PORT", "22")),
        "container": os.environ.get("AWG_FI_CONTAINER", "amnezia-awg2"),
        "conf_path": "/opt/amnezia/awg/awg0.conf",
        "subnet": os.environ.get("AWG_FI_SUBNET", "10.8.2"),
        "endpoint_host": os.environ.get("AWG_FI_ENDPOINT_HOST", os.environ.get("AWG_FI_ENDPOINT", "fi.silentconnect.net")),  # PLACEHOLDER
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
        "host": os.environ.get("AWG_PL_HOST", os.environ.get("AWG_REMOTE_SSH_PL", os.environ.get("PL_STANDBY_IP", ""))),  # PLACEHOLDER
        "ssh_host": os.environ.get("AWG_PL_HOST", os.environ.get("AWG_REMOTE_SSH_PL", os.environ.get("PL_STANDBY_IP", ""))),  # PLACEHOLDER
        "ssh_user": os.environ.get("AWG_PL_SSH_USER", "root"),
        "ssh_port": int(os.environ.get("AWG_PL_SSH_PORT", "22")),
        "container": os.environ.get("AWG_PL_CONTAINER", "amnezia-awg2"),
        "conf_path": "/opt/amnezia/awg/awg0.conf",
        "subnet": os.environ.get("AWG_PL_SUBNET", "10.8.3"),
        "endpoint_host": os.environ.get("AWG_PL_ENDPOINT_HOST", "pl.silentconnect.net"),  # PLACEHOLDER
        "endpoint_port": os.environ.get("AWG_PL_ENDPOINT_PORT", "44121"),
        "allowed_ips_file": os.environ.get("AWG_PL_ALLOWED_IPS_FILE", os.environ.get("AWG_ALLOWED_IPS_FILE", "/root/vpn-shop/awg/allowed-ips.txt")),
        "client_dns": os.environ.get("AWG_PL_CLIENT_DNS", os.environ.get("AWG_CLIENT_DNS", "1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001")),
        "client_mtu": os.environ.get("AWG_CLIENT_MTU", "1280"),
        "reserved_ips": {"10.8.3.1", "10.8.3.2", "10.8.3.3", "10.8.3.4", "10.8.3.6"},
    },
}

def _resolve_default_db_path() -> str:
    env_p = os.environ.get("SHOP_DB_PATH")
    if env_p:
        return env_p
    for candidate in (
        Path("/root/vpn-shop/data-silentconnect/vpn_shop.db"),
        Path("/root/vpn-shop/data/vpn_shop.db"),
        Path.cwd() / "data-silentconnect" / "vpn_shop.db",
        Path.cwd() / "data" / "vpn_shop.db",
    ):
        try:
            if candidate.is_file():
                return str(candidate)
        except (PermissionError, OSError):
            pass
    return "data/vpn_shop.db"


DB_PATH = _resolve_default_db_path()
WG_KEY_REGEX = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$")
CLUSTER_KNOWN_HOSTS_PATH = os.environ.get("CLUSTER_KNOWN_HOSTS_PATH", "/root/.ssh/cluster_known_hosts")


def validate_wg_key(key: str) -> bool:
    return bool(WG_KEY_REGEX.match(key.strip()))


def validate_ip(ip: str, server_code: str | None = None) -> bool:
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip.strip())
        if not isinstance(addr, ipaddress.IPv4Address):
            return False
        octets = str(addr).split(".")
        if int(octets[3]) in (0, 1, 255):
            return False
        if server_code:
            code = (server_code or "nl").lower().strip()
            if code in SERVERS:
                prefix = SERVERS[code]["subnet"]
                if not str(addr).startswith(f"{prefix}."):
                    return False
        return True
    except Exception:
        return False


class ClusterSecurityError(RuntimeError):
    """Raised when SSH host key verification fails or cluster security constraint is violated."""


class NodeIdentityConflictError(RuntimeError):
    """Raised when node identity sources contradict each other."""


class NodeIdentityMissingError(RuntimeError):
    """Raised when no node identity source could determine current node code."""


class ReconciliationAbortedError(RuntimeError):
    """Raised when reconciliation is safely aborted by circuit breakers or validation."""


_NODE_LOCK_DEPTH: dict[tuple[str, int], int] = {}
_NODE_LOCK_HANDLES: dict[str, Any] = {}
_NODE_LOCK_MUTEX = threading.Lock()
_NODE_THREAD_LOCKS: dict[str, threading.RLock] = {}


def _get_node_thread_lock(code: str) -> threading.RLock:
    with _NODE_LOCK_MUTEX:
        if code not in _NODE_THREAD_LOCKS:
            _NODE_THREAD_LOCKS[code] = threading.RLock()
        return _NODE_THREAD_LOCKS[code]


@contextmanager
def master_node_lock(server_code: str = "nl") -> Iterator[None]:
    """OS-level mutual exclusion lock for an individual cluster node.

    Protects against race conditions across multiple processes (CLI, WebCheckout, background sync)
    and multiple threads modifying WireGuard peers on the same target node.
    Re-entrant per thread to allow nested slot manipulation within a single transaction.
    """
    code = (server_code or "nl").lower().strip()
    thread_lock = _get_node_thread_lock(code)

    with thread_lock:
        tid = threading.get_ident()
        key = (code, tid)

        with _NODE_LOCK_MUTEX:
            depth = _NODE_LOCK_DEPTH.get(key, 0)
            if depth > 0:
                _NODE_LOCK_DEPTH[key] = depth + 1
                is_outer = False
            else:
                _NODE_LOCK_DEPTH[key] = 1
                is_outer = True

        if is_outer:
            if os.name == "nt":
                lock_dir = Path(tempfile.gettempdir())
            else:
                lock_dir = Path("/tmp")
            lock_file_path = lock_dir / f"silentconnect_master_node_{code}.lock"

            lock_file = open(lock_file_path, "a+")
            if fcntl:
                try:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                except Exception as exc:
                    LOGGER.warning("Could not acquire flock on %s: %s", lock_file_path, exc)
            _NODE_LOCK_HANDLES[code] = lock_file

        try:
            yield
        finally:
            with _NODE_LOCK_MUTEX:
                depth = _NODE_LOCK_DEPTH.get(key, 1) - 1
                if depth <= 0:
                    _NODE_LOCK_DEPTH.pop(key, None)
                    release_os = True
                else:
                    _NODE_LOCK_DEPTH[key] = depth
                    release_os = False

            if release_os:
                lock_file = _NODE_LOCK_HANDLES.pop(code, None)
                if lock_file:
                    try:
                        if fcntl:
                            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
                    except Exception:
                        pass
                    finally:
                        try:
                            lock_file.close()
                        except Exception:
                            pass


def get_current_node_code(marker_file: str | Path | None = None) -> str:
    """Determine current cluster node code ('nl', 'pl', 'fi') using a three-way consistency check:
    1. Marker file: /etc/silentconnect/node_code (or local .node_code)
    2. Environment variable: AWG_LOCAL_SERVER
    3. Hostname: socket.gethostname() matched against known nodes

    Rules:
    - If at least 2 sources are present and disagree -> raise NodeIdentityConflictError.
    - If no source is present -> raise NodeIdentityMissingError.
    - If consistent -> return the agreed server code in lowercase.
    """
    marker_code: str | None = None
    env_code: str | None = None
    host_code: str | None = None

    # Source 1: Marker file
    paths_to_check = []
    if marker_file:
        paths_to_check.append(Path(marker_file))
    paths_to_check.extend([
        Path("/etc/silentconnect/node_code"),
        Path.cwd() / ".node_code",
        Path(__file__).resolve().parent.parent / ".node_code",
    ])
    for p in paths_to_check:
        try:
            if p.is_file():
                txt = p.read_text(encoding="utf-8").strip().lower()
                if txt in SERVERS:
                    marker_code = txt
                    break
        except Exception:
            pass

    # Source 2: Environment variable
    env_val = os.environ.get("AWG_LOCAL_SERVER")
    if env_val:
        env_val = env_val.strip().lower()
        if env_val in SERVERS:
            env_code = env_val

    # Source 3: Hostname
    raw_host = socket.gethostname().lower()
    if "hel1" in raw_host or "finland" in raw_host or raw_host.startswith("fi-") or "-fi" in raw_host or "helsinki" in raw_host:
        host_code = "fi"
    elif "certain-coral" in raw_host or "poland" in raw_host or raw_host.startswith("pl-") or "-pl" in raw_host or "warsaw" in raw_host:
        host_code = "pl"
    elif "nikitzimawarp" in raw_host or "warp" in raw_host or "netherlands" in raw_host or raw_host.startswith("nl-") or "-nl" in raw_host or "amsterdam" in raw_host:
        host_code = "nl"
    else:
        for code, srv in SERVERS.items():
            h = str(srv.get("host") or "").lower()
            eh = str(srv.get("endpoint_host") or "").lower()
            if raw_host in {h, eh} or (h and h.startswith(raw_host)):
                host_code = code
                break

    sources = {"marker": marker_code, "env": env_code, "hostname": host_code}
    active_sources = {k: v for k, v in sources.items() if v is not None}

    if len(active_sources) >= 2:
        distinct_vals = set(active_sources.values())
        if len(distinct_vals) > 1:
            raise NodeIdentityConflictError(
                f"Критический конфликт роли ноды! Источники дают разные результаты: "
                f"marker='{marker_code}', env='{env_code}', hostname='{host_code}'. "
                "Автозапуск заблокирован во избежание порчи конфигураций."
            )

    if active_sources:
        return next(iter(active_sources.values()))

    raise NodeIdentityMissingError(
        "Роль ноды не определена! Ни один источник (маркер-файл /etc/silentconnect/node_code, "
        "AWG_LOCAL_SERVER, hostname) не вернул корректный код ноды."
    )


def _get_server(server_code: str = "nl") -> dict[str, Any]:
    code = (server_code or "nl").lower().strip()
    if code not in SERVERS:
        code = "nl"
    srv = dict(SERVERS[code])
    try:
        local_server = get_current_node_code()
    except Exception:
        local_server = os.environ.get("AWG_LOCAL_SERVER", "nl").lower().strip()

    if code == local_server:
        srv["mode"] = "local"
        srv["exec_mode"] = "local"
        srv["host"] = "127.0.0.1"
    else:
        srv["mode"] = "ssh"
        srv["exec_mode"] = "ssh"
        if code == "nl":
            srv["host"] = os.environ.get("AWG_NL_HOST", os.environ.get("NL_MASTER_IP", ""))  # PLACEHOLDER
            srv["ssh_host"] = srv["host"]
            srv["ssh_user"] = os.environ.get("AWG_NL_SSH_USER", "root")
            srv["ssh_port"] = int(os.environ.get("AWG_NL_SSH_PORT", "22"))
        elif code == "pl":
            srv["host"] = os.environ.get("AWG_PL_HOST", os.environ.get("AWG_REMOTE_SSH_PL", os.environ.get("PL_STANDBY_IP", "")))  # PLACEHOLDER
            srv["ssh_host"] = srv["host"]
            srv["ssh_user"] = os.environ.get("AWG_PL_SSH_USER", "root")
            srv["ssh_port"] = int(os.environ.get("AWG_PL_SSH_PORT", "22"))
        elif code == "fi":
            srv["host"] = os.environ.get("AWG_FI_HOST", os.environ.get("AWG_REMOTE_SSH_FI", os.environ.get("FI_STANDBY_IP", "")))  # PLACEHOLDER
            srv["ssh_host"] = srv["host"]
            srv["ssh_user"] = os.environ.get("AWG_FI_SSH_USER", "root")
            srv["ssh_port"] = int(os.environ.get("AWG_FI_SSH_PORT", "22"))
    # Dynamically pick up updated endpoint host from environment if set
    env_endpoint = os.environ.get(f"AWG_{code.upper()}_ENDPOINT_HOST")
    if env_endpoint:
        srv["endpoint_host"] = env_endpoint
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
        call_args = ["docker", "exec", "-i", srv["container"], "bash", "-c", cmd]
    elif mode == "ssh":
        ssh_user = srv.get("ssh_user", "root")
        ssh_host = srv.get("host") or srv.get("ssh_host", os.environ.get("FI_STANDBY_IP", "198.51.100.1"))
        ssh_port = str(srv.get("ssh_port", 22))
        remote_cmd = f"docker exec -i {srv['container']} bash -c {shlex.quote(cmd)}"
        call_args = [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={CLUSTER_KNOWN_HOSTS_PATH}",
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
        err_msg = r.stderr.strip()[:300]
        if "Host key verification failed" in r.stderr or "REMOTE HOST IDENTIFICATION HAS CHANGED" in r.stderr:
            raise ClusterSecurityError(f"[{server_code.upper()}] SSH host key verification failed: {err_msg}")
        raise RuntimeError(f"[{server_code.upper()}] exec failed: {err_msg}")
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
    privkey = m.group(1).strip()
    return _pubkey(privkey, server_code=server_code)


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


_STORE_INSTANCE: Any = None
_STORE_LOCK = threading.Lock()


def _get_store() -> Any:
    global _STORE_INSTANCE
    if _STORE_INSTANCE is None:
        with _STORE_LOCK:
            if _STORE_INSTANCE is None:
                try:
                    from .store import Store
                    _STORE_INSTANCE = Store(database_path=Path(DB_PATH), replica_name="awg")
                    _STORE_INSTANCE.init()
                except Exception:
                    pass
    return _STORE_INSTANCE


def _genkey(server_code: str = "nl") -> str:
    try:
        from cryptography.hazmat.primitives.asymmetric import x25519
        import base64
        priv = x25519.X25519PrivateKey.generate()
        return base64.b64encode(priv.private_bytes_raw()).decode("ascii")
    except Exception:
        import base64
        raw_priv = bytearray(os.urandom(32))
        raw_priv[0] &= 248
        raw_priv[31] &= 127
        raw_priv[31] |= 64
        return base64.b64encode(bytes(raw_priv)).decode("ascii")


def _pubkey(privkey: str, server_code: str = "nl") -> str:
    try:
        from cryptography.hazmat.primitives.asymmetric import x25519
        import base64
        priv_bytes = base64.b64decode(privkey.strip())
        priv = x25519.X25519PrivateKey.from_private_bytes(priv_bytes)
        return base64.b64encode(priv.public_key().public_bytes_raw()).decode("ascii")
    except Exception:
        try:
            return _dex("awg pubkey", inp=privkey.strip() + "\n", server_code=server_code)
        except Exception:
            return _dex("awg pubkey", inp=privkey.strip() + "\n", server_code="nl")


def _genpsk(server_code: str = "nl") -> str:
    import base64
    return base64.b64encode(os.urandom(32)).decode("ascii")


@contextmanager
def _db() -> Iterator[sqlite3.Connection | Any]:
    st = _get_store()
    if st is not None:
        with st.connection() as conn:
            yield conn
            try:
                conn.commit()
            except Exception:
                pass
        return

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
    peer_ips = f"{ip}/32"
    if server_code == "pl":
        peer_ips = f"{ip}/32,fd00:8:3::{ip.split('.')[-1]}/128"
    _dex(f"echo '{psk}' > {psk_file}", server_code=server_code)
    _dex(f"awg set awg0 peer {pub} allowed-ips {peer_ips} preshared-key {psk_file}", server_code=server_code)
    _dex(f"rm -f {psk_file}", server_code=server_code)

    # персистентность: дописать только блок [Peer] в awg0.conf внутри контейнера (если ещё не присутствует)
    if pub not in conf:
        peer_ips_conf = f"{ip}/32"
        if server_code == "pl":
            peer_ips_conf = f"{ip}/32, fd00:8:3::{ip.split('.')[-1]}/128"
        block = (
            f"\n[Peer]\nPublicKey = {pub}\nPresharedKey = {psk}\n"
            f"AllowedIPs = {peer_ips_conf}\n"
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
    peer_ips = f"{peer['tunnel_ip']}/32"
    if server_code == "pl":
        peer_ips = f"{peer['tunnel_ip']}/32,fd00:8:3::{peer['tunnel_ip'].split('.')[-1]}/128"
    _dex(f"echo '{peer['preshared_key']}' > {psk_file}", server_code=server_code)
    _dex(f"awg set awg0 peer {peer['public_key']} allowed-ips {peer_ips} preshared-key {psk_file}", server_code=server_code)
    _dex(f"rm -f {psk_file}", server_code=server_code)
    
    if peer["public_key"] not in conf:
        peer_ips_conf = f"{peer['tunnel_ip']}/32"
        if server_code == "pl":
            peer_ips_conf = f"{peer['tunnel_ip']}/32, fd00:8:3::{peer['tunnel_ip'].split('.')[-1]}/128"
        block = (
            f"\n[Peer]\nPublicKey = {peer['public_key']}\n"
            f"PresharedKey = {peer['preshared_key']}\nAllowedIPs = {peer_ips_conf}\n"
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

    allowed = "0.0.0.0/0"
    try:
        allowed_ips_file = srv.get("allowed_ips_file") or "/root/vpn-shop/awg/allowed-ips.txt"
        lst = Path(allowed_ips_file).read_text(encoding="utf-8").strip()
        if lst:
            allowed = lst
    except OSError:
        pass

    if server_code == "pl":
        client_last_octet = peer['tunnel_ip'].split('.')[-1]
        addr_str = f"{peer['tunnel_ip']}/32, fd00:8:3::{client_last_octet}/128"
        if "::/0" not in allowed:
            allowed = f"{allowed}, ::/0"
    else:
        addr_str = f"{peer['tunnel_ip']}/32"

    lines = [
        "[Interface]",
        f"Address = {addr_str}",
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


def add_slot_peer(
    server_code: str = "nl",
    public_key: str = "",
    preshared_key: str = "",
    client_ip: str = "",
) -> bool:
    """Add a slot peer to live WireGuard interface and persist to awg0.conf."""
    server_code = (server_code or "nl").lower().strip()
    with master_node_lock(server_code):
        srv = _get_server(server_code)
        pub = public_key.strip()
        psk = preshared_key.strip()
        ip = client_ip.strip()
        if not pub or not ip or not validate_wg_key(pub) or not validate_ip(ip):
            LOGGER.warning("Invalid AWG peer parameters: pub=%s ip=%s", pub, ip)
            return False
        if psk and not validate_wg_key(psk):
            LOGGER.warning("Invalid AWG PSK: %s", psk)
            return False

        # 1. Live add in container
        psk_file = "/tmp/.awg-psk.tmp"
        try:
            peer_ips = f"{ip}/32"
            if server_code == "pl":
                peer_ips = f"{ip}/32,fd00:8:3::{ip.split('.')[-1]}/128"
            if psk:
                _dex(f"echo {shlex.quote(psk)} > {psk_file}", server_code=server_code)
                _dex(f"awg set awg0 peer {shlex.quote(pub)} allowed-ips {shlex.quote(peer_ips)} preshared-key {psk_file}", server_code=server_code)
                _dex(f"rm -f {psk_file}", server_code=server_code)
            else:
                _dex(f"awg set awg0 peer {shlex.quote(pub)} allowed-ips {shlex.quote(peer_ips)}", server_code=server_code)
        except Exception as exc:
            LOGGER.warning("Could not live-add AWG peer %s on %s: %s", pub, server_code, exc)
            return False

        # 2. Persist to awg0.conf if not already present
        try:
            conf = _server_conf(server_code)
            if pub not in conf:
                peer_ips_conf = f"{ip}/32"
                if server_code == "pl":
                    peer_ips_conf = f"{ip}/32, fd00:8:3::{ip.split('.')[-1]}/128"
                if psk:
                    block = f"\n[Peer]\nPublicKey = {pub}\nPresharedKey = {psk}\nAllowedIPs = {peer_ips_conf}\n"
                else:
                    block = f"\n[Peer]\nPublicKey = {pub}\nAllowedIPs = {peer_ips_conf}\n"
                _dex(f"cat >> {srv['conf_path']}", inp=block, server_code=server_code)
        except Exception as exc:
            LOGGER.warning("Could not persist AWG peer %s to %s on %s: %s", pub, srv.get("conf_path"), server_code, exc)
        return True


def remove_slot_peer(server_code: str = "nl", public_key: str = "") -> bool:
    """Remove a slot peer from live WireGuard interface and strip from awg0.conf.
    DO NOT delete from database to preserve traffic history and allow instant reactivation.
    """
    server_code = (server_code or "nl").lower().strip()
    with master_node_lock(server_code):
        srv = _get_server(server_code)
        pub = public_key.strip()
        if not pub or not validate_wg_key(pub):
            LOGGER.warning("Invalid AWG public key for removal: %s", pub)
            return False
        # 1. Live remove in container kernel
        try:
            _dex(f"awg set awg0 peer {shlex.quote(pub)} remove", server_code=server_code)
        except Exception as exc:
            LOGGER.warning("Could not live-remove AWG peer %s on %s: %s", pub, server_code, exc)

        # 2. Persist removal to awg0.conf
        try:
            conf = _server_conf(server_code)
            if pub in conf:
                blocks = conf.split("\n[Peer]\n")
                kept = [blocks[0]]
                for b in blocks[1:]:
                    if pub not in b:
                        kept.append(b)
                new_conf = "\n[Peer]\n".join(kept)
                if not new_conf.endswith("\n"):
                    new_conf += "\n"
                _dex(f"cat > {srv['conf_path']}", inp=new_conf, server_code=server_code)
        except Exception as exc:
            LOGGER.warning("Could not strip AWG peer %s from %s on %s: %s", pub, srv.get("conf_path"), server_code, exc)
        return True


def _resolve_db_path(db_path: str | Path | None = None) -> str:
    if db_path:
        return str(db_path)
    env_path = os.environ.get("SHOP_DB_PATH")
    if env_path and Path(env_path).is_file():
        return env_path
    candidates = [
        env_path,
        "/root/vpn-shop/data-silentconnect/vpn_shop.db",
        "/root/vpn-shop/data/vpn_shop.db",
        str(Path.cwd() / "vpn_shop.db"),
    ]
    for c in candidates:
        if c:
            try:
                if Path(c).is_file():
                    return str(c)
            except (PermissionError, OSError):
                pass
    return env_path or "/root/vpn-shop/data-silentconnect/vpn_shop.db"


def _parse_awg_conf(conf: str) -> tuple[str, list[dict[str, str]]]:
    """Parse awg0.conf into raw [Interface] section text and a list of peer dictionaries."""
    parts = conf.split("[Peer]")
    iface_text = parts[0].strip()
    peers: list[dict[str, str]] = []
    for block in parts[1:]:
        peer_dict: dict[str, str] = {}
        for line in block.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if "=" in s:
                k, v = s.split("=", 1)
                peer_dict[k.strip()] = v.strip()
        if "PublicKey" in peer_dict:
            peer_dict["public_key"] = peer_dict["PublicKey"]
            peer_dict["preshared_key"] = peer_dict.get("PresharedKey", "")
            peer_dict["allowed_ips"] = peer_dict.get("AllowedIPs", "")
            peers.append(peer_dict)
    return iface_text, peers


def _render_awg_conf(iface_text: str, peers: list[dict[str, str]]) -> str:
    """Render complete awg0.conf with [Interface] section and [Peer] blocks."""
    lines = [iface_text.strip(), ""]
    for p in peers:
        lines.append("[Peer]")
        lines.append(f"PublicKey = {p['public_key']}")
        if p.get("preshared_key"):
            lines.append(f"PresharedKey = {p['preshared_key']}")
        allowed = p.get("allowed_ips") or (f"{p.get('client_ip')}/32" if p.get("client_ip") else "")
        if allowed:
            lines.append(f"AllowedIPs = {allowed}")
        for k, v in p.items():
            if k not in {
                "public_key", "preshared_key", "allowed_ips", "client_ip",
                "PublicKey", "PresharedKey", "AllowedIPs"
            }:
                lines.append(f"{k} = {v}")
        lines.append("")
    return "\n".join(lines).strip() + "\n"


def _apply_staged_awg_conf(server_code: str, new_conf: str) -> None:
    """Safely apply new_conf to target node using staging directory, awg-quick strip validation,
    timestamped backup rotation (max 20), atomic mv, and live kernel syncconf.
    Raises RuntimeError if validation fails (leaving live configuration untouched).
    """
    srv = _get_server(server_code)
    conf_path = srv.get("conf_path", "/opt/amnezia/awg/awg0.conf")
    base_dir = str(Path(conf_path).parent)

    apply_script = (
        "set -e\n"
        f"exec 200>\"{base_dir}/awg0.lock\"\n"
        "flock -x 200\n"
        f"STAGE_DIR=\"{base_dir}/.stage.$$\"\n"
        "mkdir -m 700 -p \"$STAGE_DIR\"\n"
        f"cat > \"${{STAGE_DIR}}/awg0.conf\"\n"
        f"chmod 600 \"${{STAGE_DIR}}/awg0.conf\"\n"
        "\n"
        "# 1. Validation in container using awg-quick strip\n"
        "if ! awg-quick strip \"${STAGE_DIR}/awg0.conf\" > /dev/null 2>&1; then\n"
        "    rm -rf \"$STAGE_DIR\"\n"
        "    echo \"STAGING_VALIDATION_FAILED\" >&2\n"
        "    exit 42\n"
        "fi\n"
        "\n"
        "# 2. Secure backup of existing conf with 0600 permissions\n"
        f"if [ -f \"{conf_path}\" ]; then\n"
        f"    BAK_FILE=\"{conf_path}.bak.$(date +%s)\"\n"
        f"    cp \"{conf_path}\" \"$BAK_FILE\"\n"
        f"    chmod 600 \"$BAK_FILE\"\n"
        f"    ls -1t \"{conf_path}\".bak.* 2>/dev/null | tail -n +21 | xargs -r rm -f\n"
        "fi\n"
        "\n"
        "# 3. Atomic replacement\n"
        f"mv \"${{STAGE_DIR}}/awg0.conf\" \"{conf_path}\"\n"
        "rmdir \"$STAGE_DIR\" 2>/dev/null || rm -rf \"$STAGE_DIR\"\n"
        "\n"
        "# 4. Live kernel synchronization\n"
        f"awg syncconf awg0 <(awg-quick strip \"{conf_path}\")\n"
    )

    _dex(apply_script, inp=new_conf, server_code=server_code)


def reconcile_awg_peers(
    server_code: str = "nl",
    dry_run: bool = True,
    allow_empty: bool = False,
    force_mass_delete: bool = False,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Reconcile AmneziaWG peers on server_code with active database slots.

    Guarantees:
    - Thread & process serialization via master_node_lock.
    - DatabaseQueryError is strictly propagated; does not treat db errors as empty slots.
    - Zero active slots without allow_empty=True aborts immediately.
    - Mass deletion circuit breaker: aborts if >30% or >10 peers would be deleted unless force_mass_delete=True.
    - Preserves reserved/infrastructure server peers.
    - Staged validation via awg-quick strip; corrupt configs are rejected before touching awg0.conf.
    - Live kernel syncconf without dropping existing sessions.
    """
    if (server_code or "nl").lower().strip() == "all":
        results = {}
        for code in ("nl", "pl", "fi"):
            results[code] = reconcile_awg_peers(
                server_code=code,
                dry_run=dry_run,
                allow_empty=allow_empty,
                force_mass_delete=force_mass_delete,
                db_path=db_path,
            )
        return results

    code = (server_code or "nl").lower().strip()
    if code not in SERVERS:
        raise ValueError(f"Unknown server code: '{server_code}'. Available: {list(SERVERS.keys())}")

    with master_node_lock(code):
        resolved_db = _resolve_db_path(db_path)
        from .store import Store, DatabaseQueryError
        store = Store(resolved_db)

        # 1. Query active slots from DB (fail-closed on db error)
        try:
            active_slots = store.list_active_awg_slots(server_code=code)
        except DatabaseQueryError:
            LOGGER.critical("[%s] DatabaseQueryError during reconciliation", code.upper())
            raise
        except Exception as exc:
            LOGGER.critical("[%s] Failed to query active slots: %s", code.upper(), exc)
            raise DatabaseQueryError(f"Database query failed: {exc}") from exc

        # 2. Check for empty database
        if len(active_slots) == 0 and not allow_empty:
            msg = f"Zero active slots returned for {code.upper()} and allow_empty is False"
            LOGGER.warning("[%s] %s", code.upper(), msg)
            raise ReconciliationAbortedError(msg)

        # 3. Read current conf from node
        current_conf = _server_conf(code)
        iface_text, peers_list = _parse_awg_conf(current_conf)

        srv = _get_server(code)
        reserved_ips = set(srv.get("reserved_ips") or set())

        # Classify current peers into reserved vs manageable
        reserved_peers: list[dict[str, str]] = []
        manageable_peers: list[dict[str, str]] = []
        for p in peers_list:
            ip_addr = p.get("allowed_ips", "").split("/")[0].strip()
            if ip_addr in reserved_ips:
                reserved_peers.append(p)
            else:
                manageable_peers.append(p)

        desired_by_pubkey = {s["public_key"]: s for s in active_slots if s.get("public_key")}
        current_by_pubkey = {p["public_key"]: p for p in manageable_peers if p.get("public_key")}

        to_add = [s for pk, s in desired_by_pubkey.items() if pk not in current_by_pubkey]
        to_remove = [p for pk, p in current_by_pubkey.items() if pk not in desired_by_pubkey]
        to_update = []
        unchanged = []

        for pk, cur_p in current_by_pubkey.items():
            if pk in desired_by_pubkey:
                des_slot = desired_by_pubkey[pk]
                cur_allowed = cur_p.get("allowed_ips", "").strip()
                des_ip = str(des_slot.get("client_ip") or "").strip()
                des_allowed = f"{des_ip}/32, fd00:8:3::{des_ip.split('.')[-1]}/128" if code == "pl" else f"{des_ip}/32"
                cur_psk = cur_p.get("preshared_key", "").strip()
                des_psk = str(des_slot.get("preshared_key") or "").strip()

                if cur_allowed != des_allowed or cur_psk != des_psk:
                    to_update.append(des_slot)
                else:
                    unchanged.append(cur_p)

        # 4. Mass Deletion Circuit Breaker
        num_manageable = len(current_by_pubkey)
        num_to_remove = len(to_remove)
        if num_manageable > 0 and num_to_remove > 0:
            ratio = num_to_remove / num_manageable
            if ((ratio > 0.30 and num_to_remove > 3) or num_to_remove > 10) and not force_mass_delete:
                msg = (
                    f"Mass deletion circuit breaker triggered for {code.upper()}: "
                    f"attempting to remove {num_to_remove}/{num_manageable} peers ({ratio:.1%}). "
                    "Operation aborted to prevent accidental outage. Pass force_mass_delete=True to override."
                )
                LOGGER.error("[%s] %s", code.upper(), msg)
                raise ReconciliationAbortedError(msg)

        summary = {
            "server_code": code,
            "dry_run": dry_run,
            "applied": False,
            "current_total_peers": len(peers_list),
            "reserved_peers_count": len(reserved_peers),
            "active_slots_db": len(active_slots),
            "to_add": [{"public_key": s["public_key"], "client_ip": s.get("client_ip")} for s in to_add],
            "to_remove": [{"public_key": p["public_key"], "allowed_ips": p.get("allowed_ips")} for p in to_remove],
            "to_update": [{"public_key": s["public_key"], "client_ip": s.get("client_ip")} for s in to_update],
            "unchanged_count": len(unchanged),
        }

        # 5. Apply if dry_run is False and changes are needed
        if not dry_run and (to_add or to_remove or to_update):
            final_peers = list(reserved_peers)
            sorted_slots = sorted(desired_by_pubkey.values(), key=lambda x: str(x.get("client_ip", "")))
            for s in sorted_slots:
                ip_val = s["client_ip"]
                if code == "pl":
                    peer_ips = f"{ip_val}/32, fd00:8:3::{ip_val.split('.')[-1]}/128"
                else:
                    peer_ips = f"{ip_val}/32"
                final_peers.append({
                    "public_key": s["public_key"],
                    "preshared_key": str(s.get("preshared_key") or ""),
                    "allowed_ips": peer_ips,
                })

            rendered_conf = _render_awg_conf(iface_text, final_peers)
            _apply_staged_awg_conf(code, rendered_conf)
            summary["applied"] = True

        return summary

