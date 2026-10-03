"""
OpenFlux 0.3.0 Mail.ru Stream Dedicated Slots & Worker Lifecycle Manager
Supports lazy provisioning, smart balancing across NL/PL/FI, and two-phase server handover.
"""
from __future__ import annotations

import base64
import html
import json
import logging
import os
import re
import sqlite3
import subprocess
import time
import zlib
from typing import Any, Optional

LOGGER = logging.getLogger("openflux_manager")

def load_env_file_if_needed() -> None:
    for f in ("/root/subjson-service/subjson.env", "/root/vpn-shop/.env.silentconnect"):
        if os.path.exists(f):
            try:
                with open(f, "r", encoding="utf-8") as fp:
                    for line in fp:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            k, v = k.strip(), v.strip().strip("'").strip('"')
                            if k not in os.environ:
                                os.environ[k] = v
            except Exception:
                pass

load_env_file_if_needed()

NL_IP = os.environ.get("NL_HOST", os.environ.get("NL_MASTER_IP", "192.0.2.1"))
PL_IP = os.environ.get("PL_HOST", os.environ.get("PL_STANDBY_IP", "192.0.2.2"))
FI_IP = os.environ.get("FI_HOST", os.environ.get("FI_STANDBY_IP", "198.51.100.1"))

DEFAULT_MAILRU_USER = os.environ.get("MAILRU_USER", "")
DEFAULT_MAILRU_PASS = os.environ.get("MAILRU_PASS", "")
DEFAULT_MAILRU_FOLDER = os.environ.get("MAILRU_FOLDER", "openflux_docs")
DEFAULT_TEMPLATE_PATH = os.environ.get("OPENFLUX_TEMPLATE_PATH", "/opt/openflux/template.docx")

SERVERS: dict[str, dict[str, Any]] = {
    "nl": {
        "code": "nl",
        "name": "Нидерланды",
        "flag": "🇳🇱",
        "ip": NL_IP,
    },
    "pl": {
        "code": "pl",
        "name": "Польша",
        "flag": "🇵🇱",
        "ip": PL_IP,
    },
    "fi": {
        "code": "fi",
        "name": "Финляндия",
        "flag": "🇫🇮",
        "ip": FI_IP,
    },
}

MIGRATION_TIMEOUT_SECONDS = 300  # 5 minutes


def get_mailru_env() -> dict[str, str]:
    env = dict(os.environ)
    env["RCLONE_CONFIG_MAILRU_TYPE"] = "mailru"
    env["RCLONE_CONFIG_MAILRU_USER"] = os.environ.get("MAILRU_USER", DEFAULT_MAILRU_USER)
    env["RCLONE_CONFIG_MAILRU_PASS"] = os.environ.get("MAILRU_PASS", DEFAULT_MAILRU_PASS)
    return env


def init_openflux_db(conn: sqlite3.Connection) -> None:
    """Create openflux_slots table if not exists."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS openflux_slots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile_public_id TEXT NOT NULL UNIQUE,
            slot_label TEXT NOT NULL DEFAULT 'Белые списки (OpenFlux)',
            status TEXT NOT NULL DEFAULT 'uninitialized',
            active_server TEXT DEFAULT NULL,
            active_doc_name TEXT DEFAULT NULL,
            active_doc_url TEXT DEFAULT NULL,
            active_container_name TEXT DEFAULT NULL,
            pending_server TEXT DEFAULT NULL,
            pending_doc_name TEXT DEFAULT NULL,
            pending_doc_url TEXT DEFAULT NULL,
            pending_container_name TEXT DEFAULT NULL,
            pending_started_at INTEGER DEFAULT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY (profile_public_id) REFERENCES profiles(public_id)
        );
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS ix_openflux_slots_profile ON openflux_slots(profile_public_id);"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS ix_openflux_slots_status ON openflux_slots(status);"
    )
    conn.commit()


def build_openflux_stream_link(public_url: str, country_code: str) -> str:
    """Encode an OpenFlux v1 stream link for a given public Mail.ru doc URL."""
    c_info = SERVERS.get(country_code.lower().strip(), SERVERS["nl"])
    payload = {
        "name": f"SilentConnect {c_info['flag']} {c_info['name']}",
        "mode": "stream",
        "transports": [
            {
                "type": "mailru",
                "url": public_url.strip(),
            }
        ],
    }
    json_bytes = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    compressor = zlib.compressobj(level=9, wbits=-zlib.MAX_WBITS)
    deflated = compressor.compress(json_bytes) + compressor.flush()
    b64 = base64.urlsafe_b64encode(deflated).decode("ascii").rstrip("=")
    return f"openflux://v1/{b64}"


def get_server_ip(server_code: str) -> str:
    code = (server_code or "").lower().strip()
    if code == "nl":
        return os.environ.get("NL_HOST", os.environ.get("NL_MASTER_IP", "192.0.2.1"))
    if code == "pl":
        return os.environ.get("PL_HOST", os.environ.get("PL_STANDBY_IP", "192.0.2.2"))
    if code == "fi":
        return os.environ.get("FI_HOST", os.environ.get("FI_STANDBY_IP", "198.51.100.1"))
    return "192.0.2.1"


def run_node_command(server_code: str, cmd: str, timeout: int = 15) -> tuple[int, str, str]:
    """Execute a shell command either locally (if on NL) or via SSH on remote nodes."""
    srv = SERVERS.get(server_code.lower().strip())
    if not srv:
        return 1, "", f"Unknown server {server_code}"

    # Determine if local execution is possible
    # Detect local host by matching server code or local ips
    target_ip = get_server_ip(srv["code"])
    is_local = False
    local_ips = {ip.strip() for ip in os.environ.get("LOCAL_NODE_IPS", "").split(",") if ip.strip()}
    local_ips.add("127.0.0.1")
    local_ips.add("::1")
    local_ips.add(get_server_ip("nl"))

    current_srv = os.environ.get("CURRENT_SERVER_CODE", "nl").lower().strip()
    if srv["code"] == current_srv or target_ip in local_ips:
        is_local = True

    if is_local:
        try:
            res = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return res.returncode, res.stdout.strip(), res.stderr.strip()
        except Exception as exc:
            return 1, "", str(exc)

    # For remote node: SSH execution
    # If target is PL, we route via FI or direct
    ssh_cmd = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={min(5, timeout)}",
        f"root@{target_ip}",
        cmd,
    ]
    try:
        res = subprocess.run(
            ssh_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return res.returncode, res.stdout.strip(), res.stderr.strip()
    except Exception as exc:
        # Fallback for PL: jump through FI if direct SSH fails
        if srv["code"] == "pl":
            try:
                fi_host = get_server_ip("fi")
                jump_cmd = [
                    "ssh",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "BatchMode=yes",
                    "-o", "ConnectTimeout=5",
                    f"root@{fi_host}",
                    f"ssh -o StrictHostKeyChecking=no -o BatchMode=yes root@{target_ip} {subprocess.list2cmdline([cmd])}",
                ]
                jump_res = subprocess.run(
                    jump_cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
                return jump_res.returncode, jump_res.stdout.strip(), jump_res.stderr.strip()
            except Exception as jexc:
                return 1, "", f"Direct and Jump SSH failed: {exc} | {jexc}"
        return 1, "", str(exc)


# Rclone Mail.ru Cloud Operations
def rclone_create_user_doc(doc_name: str, template_path: str = DEFAULT_TEMPLATE_PATH) -> bool:
    """Copy template .docx to mailru:openflux_docs/<doc_name>."""
    folder = os.environ.get("MAILRU_FOLDER", DEFAULT_MAILRU_FOLDER)
    remote_path = f"mailru:{folder}/{doc_name}"
    env = get_mailru_env()
    cmd = ["rclone", "copyto", template_path, remote_path]
    try:
        res = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=20)
        if res.returncode != 0:
            LOGGER.error("rclone copyto failed: %s %s", res.stdout, res.stderr)
            return False
        return True
    except Exception as exc:
        LOGGER.exception("rclone copyto exception: %s", exc)
        return False


def rclone_get_public_link(doc_name: str) -> Optional[str]:
    """Obtain public link https://cloud.mail.ru/public/... via rclone link."""
    folder = os.environ.get("MAILRU_FOLDER", DEFAULT_MAILRU_FOLDER)
    remote_path = f"mailru:{folder}/{doc_name}"
    env = get_mailru_env()
    cmd = ["rclone", "link", remote_path]
    try:
        res = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=15)
        if res.returncode == 0 and res.stdout.strip().startswith("http"):
            return res.stdout.strip()
        LOGGER.error("rclone link failed: %s %s", res.stdout, res.stderr)
        return None
    except Exception as exc:
        LOGGER.exception("rclone link exception: %s", exc)
        return None


def rclone_delete_user_doc(doc_name: str) -> bool:
    """Delete document from Mail.ru Cloud."""
    if not doc_name:
        return True
    folder = os.environ.get("MAILRU_FOLDER", DEFAULT_MAILRU_FOLDER)
    remote_path = f"mailru:{folder}/{doc_name}"
    env = get_mailru_env()
    cmd = ["rclone", "delete", remote_path]
    try:
        res = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=15)
        return res.returncode == 0
    except Exception as exc:
        LOGGER.warning("rclone delete failed: %s", exc)
        return False


# Docker Worker Operations
def start_openflux_worker(server_code: str, container_name: str, public_doc_url: str) -> bool:
    """Launch a lightweight Docker container running mailruexit.php on target node."""
    clean_name = re.sub(r"[^\w\-]", "", container_name)
    docker_cmd = (
        f"docker rm -f {clean_name} 2>/dev/null || true; "
        f"docker run -d --name {clean_name} --restart unless-stopped "
        f"--memory=64m --cpus=0.5 "
        f"-v /opt/openflux:/opt/openflux:ro "
        f"php:8.2-cli-alpine "
        f"sh -c 'while true; do php -d memory_limit=48M /opt/openflux/runner.php \"$1\"; sleep 1; done' _ '{public_doc_url}'"
    )
    code, stdout, stderr = run_node_command(server_code, docker_cmd, timeout=20)
    if code == 0:
        LOGGER.info("Started openflux worker %s on %s", clean_name, server_code)
        return True
    LOGGER.error("Failed to start openflux worker %s on %s: %s %s", clean_name, server_code, stdout, stderr)
    return False


def stop_openflux_worker(server_code: str, container_name: str) -> bool:
    """Stop and remove Docker container on target node."""
    if not container_name:
        return True
    clean_name = re.sub(r"[^\w\-]", "", container_name)
    docker_cmd = f"docker rm -f {clean_name} 2>/dev/null || true"
    code, _, _ = run_node_command(server_code, docker_cmd, timeout=15)
    return code == 0


def rename_openflux_worker(server_code: str, old_container: str, new_container: str) -> bool:
    """Rename a Docker container on target node."""
    if not old_container or not new_container or old_container == new_container:
        return True
    old_clean = re.sub(r"[^\w\-]", "", old_container)
    new_clean = re.sub(r"[^\w\-]", "", new_container)
    cmd = f"docker rm -f {new_clean} 2>/dev/null || true; docker rename {old_clean} {new_clean} 2>/dev/null || true"
    code, _, _ = run_node_command(server_code, cmd, timeout=15)
    return code == 0


# Slot State & Operations
def get_or_create_openflux_slot(conn: sqlite3.Connection, profile_id: str) -> dict[str, Any]:
    """Retrieve slot state or initialize in 'uninitialized' state."""
    init_openflux_db(conn)
    row = conn.execute(
        "SELECT * FROM openflux_slots WHERE profile_public_id = ?",
        (profile_id,),
    ).fetchone()

    now = int(time.time())
    if not row:
        conn.execute(
            """
            INSERT INTO openflux_slots (
                profile_public_id, slot_label, status,
                created_at, updated_at
            ) VALUES (?, 'Белые списки (OpenFlux)', 'uninitialized', ?, ?)
            """,
            (profile_id, now, now),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM openflux_slots WHERE profile_public_id = ?",
            (profile_id,),
        ).fetchone()

    return dict(row)


def choose_least_loaded_server(conn: sqlite3.Connection) -> str:
    """Smart Balancer: Select least loaded server among NL, PL, FI."""
    counts = {"nl": 0, "pl": 0, "fi": 0}
    rows = conn.execute(
        """
        SELECT active_server, count(*) as cnt
        FROM openflux_slots
        WHERE status = 'active' AND active_server IS NOT NULL
        GROUP BY active_server
        """
    ).fetchall()
    for r in rows:
        srv = (r[0] or "").lower()
        if srv in counts:
            counts[srv] = int(r[1])

    # Select lowest count with priority nl -> pl -> fi on tie
    min_count = min(counts.values())
    for srv in ("nl", "pl", "fi"):
        if counts[srv] == min_count:
            return srv
    return "nl"


def activate_openflux_slot(conn: sqlite3.Connection, profile_id: str) -> dict[str, Any]:
    """
    Activate an uninitialized slot:
    1. Smart Balancer picks optimal node.
    2. Provisions unique doc <COUNTRY>_<USER_ID>.docx in Mail.ru Cloud.
    3. Starts docker container on chosen node.
    4. Updates slot to 'active'.
    """
    slot = get_or_create_openflux_slot(conn, profile_id)
    if slot["status"] == "active" and slot.get("active_doc_url"):
        return slot

    target_srv = choose_least_loaded_server(conn)
    clean_uid = re.sub(r"[^\w\-]", "", profile_id)
    doc_name = f"{target_srv.upper()}_{clean_uid}.docx"
    container_name = f"openflux-worker-{clean_uid}"

    # Step 1: Create doc in Mail.ru Cloud
    if not rclone_create_user_doc(doc_name):
        raise RuntimeError(f"Не удалось создать документ {doc_name} в Облаке Mail.ru")

    # Step 2: Obtain public link
    public_url = rclone_get_public_link(doc_name)
    if not public_url:
        rclone_delete_user_doc(doc_name)
        raise RuntimeError(f"Не удалось получить публичную ссылку для {doc_name}")

    # Step 3: Start Docker container on node
    if not start_openflux_worker(target_srv, container_name, public_url):
        rclone_delete_user_doc(doc_name)
        raise RuntimeError(f"Не удалось запустить рабочий контейнер OpenFlux на сервере {target_srv.upper()}")

    # Step 4: Persist in database
    now = int(time.time())
    conn.execute(
        """
        UPDATE openflux_slots
        SET status = 'active',
            active_server = ?,
            active_doc_name = ?,
            active_doc_url = ?,
            active_container_name = ?,
            updated_at = ?
        WHERE profile_public_id = ?
        """,
        (target_srv, doc_name, public_url, container_name, now, profile_id),
    )
    conn.commit()

    return get_or_create_openflux_slot(conn, profile_id)


def start_server_switch(conn: sqlite3.Connection, profile_id: str, target_server: str) -> dict[str, Any]:
    """
    Phase 1 of Two-Phase Handover:
    - Prepares parallel worker on target node.
    - Leaves old server working!
    - Starts 5-minute countdown.
    """
    slot = get_or_create_openflux_slot(conn, profile_id)
    if slot["status"] != "active":
        raise ValueError("Слот должен быть активен для запуска смены сервера")

    target_srv = (target_server or "").lower().strip()
    if target_srv not in SERVERS:
        raise ValueError(f"Недопустимый целевой сервер: {target_server}")

    if target_srv == slot.get("active_server"):
        raise ValueError(f"Сервер {target_srv.upper()} уже активен")

    clean_uid = re.sub(r"[^\w\-]", "", profile_id)
    pending_doc_name = f"{target_srv.upper()}_{clean_uid}_pending.docx"
    pending_container = f"openflux-worker-{clean_uid}-pending"

    # Step 1: Create doc in Mail.ru Cloud
    if not rclone_create_user_doc(pending_doc_name):
        raise RuntimeError(f"Не удалось создать документ {pending_doc_name} в Облаке Mail.ru")

    # Step 2: Obtain public link
    pending_public_url = rclone_get_public_link(pending_doc_name)
    if not pending_public_url:
        rclone_delete_user_doc(pending_doc_name)
        raise RuntimeError(f"Не удалось получить публичную ссылку для {pending_doc_name}")

    # Step 3: Start parallel Docker worker on target server
    if not start_openflux_worker(target_srv, pending_container, pending_public_url):
        rclone_delete_user_doc(pending_doc_name)
        raise RuntimeError(f"Не удалось запустить новый воркер на сервере {target_srv.upper()}")

    # Step 4: Record pending migration state
    now = int(time.time())
    conn.execute(
        """
        UPDATE openflux_slots
        SET status = 'migrating',
            pending_server = ?,
            pending_doc_name = ?,
            pending_doc_url = ?,
            pending_container_name = ?,
            pending_started_at = ?,
            updated_at = ?
        WHERE profile_public_id = ?
        """,
        (target_srv, pending_doc_name, pending_public_url, pending_container, now, now, profile_id),
    )
    conn.commit()

    return get_or_create_openflux_slot(conn, profile_id)


def confirm_server_switch(conn: sqlite3.Connection, profile_id: str) -> dict[str, Any]:
    """
    Phase 2 of Two-Phase Handover:
    - User confirmed they imported the new config.
    - Decommissions old server (stops old worker, deletes old .docx).
    - Promotes pending to active.
    """
    slot = get_or_create_openflux_slot(conn, profile_id)
    if slot["status"] != "migrating" or not slot.get("pending_server"):
        raise ValueError("Нет активной процедуры смены сервера для подтверждения")

    old_srv = slot.get("active_server")
    old_container = slot.get("active_container_name")
    old_doc = slot.get("active_doc_name")

    new_srv = slot["pending_server"]
    new_doc = slot["pending_doc_name"]
    new_url = slot["pending_doc_url"]
    new_container = slot["pending_container_name"]

    # 1. Stop and remove old worker
    clean_uid = re.sub(r"[^\w\-]", "", profile_id)
    if old_srv:
        if old_container:
            stop_openflux_worker(old_srv, old_container)
        if old_container != f"openflux-worker-{clean_uid}":
            stop_openflux_worker(old_srv, f"openflux-worker-{clean_uid}")

    # 2. Delete old doc from Cloud
    if old_doc:
        rclone_delete_user_doc(old_doc)

    # 3. Rename pending container to canonical name on new server
    canonical_container = f"openflux-worker-{clean_uid}"
    if new_srv and new_container and new_container != canonical_container:
        rename_openflux_worker(new_srv, new_container, canonical_container)
        new_container = canonical_container

    # 4. Finalize slot state
    now = int(time.time())
    conn.execute(
        """
        UPDATE openflux_slots
        SET status = 'active',
            active_server = ?,
            active_doc_name = ?,
            active_doc_url = ?,
            active_container_name = ?,
            pending_server = NULL,
            pending_doc_name = NULL,
            pending_doc_url = NULL,
            pending_container_name = NULL,
            pending_started_at = NULL,
            updated_at = ?
        WHERE profile_public_id = ?
        """,
        (new_srv, new_doc, new_url, new_container, now, profile_id),
    )
    conn.commit()

    LOGGER.info("Confirmed server switch for %s: migrated to %s", profile_id, new_srv)
    return get_or_create_openflux_slot(conn, profile_id)


def cancel_server_switch(conn: sqlite3.Connection, profile_id: str) -> dict[str, Any]:
    """
    Cancel switch or handle 5-minute timeout:
    - Stops pending worker and deletes pending .docx.
    - Leaves old server completely intact!
    """
    slot = get_or_create_openflux_slot(conn, profile_id)
    if slot["status"] != "migrating":
        return slot

    pending_srv = slot.get("pending_server")
    pending_container = slot.get("pending_container_name")
    pending_doc = slot.get("pending_doc_name")

    clean_uid = re.sub(r"[^\w\-]", "", profile_id)
    if pending_srv:
        if pending_container:
            stop_openflux_worker(pending_srv, pending_container)
        if pending_container != f"openflux-worker-{clean_uid}-pending":
            stop_openflux_worker(pending_srv, f"openflux-worker-{clean_uid}-pending")

    if pending_doc:
        rclone_delete_user_doc(pending_doc)

    now = int(time.time())
    conn.execute(
        """
        UPDATE openflux_slots
        SET status = 'active',
            pending_server = NULL,
            pending_doc_name = NULL,
            pending_doc_url = NULL,
            pending_container_name = NULL,
            pending_started_at = NULL,
            updated_at = ?
        WHERE profile_public_id = ?
        """,
        (now, profile_id),
    )
    conn.commit()

    LOGGER.info("Cancelled server switch for %s; old server %s preserved", profile_id, slot.get("active_server"))
    return get_or_create_openflux_slot(conn, profile_id)


def cleanup_expired_migrations(conn: sqlite3.Connection, timeout_seconds: int = MIGRATION_TIMEOUT_SECONDS) -> int:
    """Watchdog janitor: Automatically cancel abandoned migrations older than timeout."""
    init_openflux_db(conn)
    now = int(time.time())
    deadline = now - timeout_seconds

    rows = conn.execute(
        """
        SELECT profile_public_id
        FROM openflux_slots
        WHERE status = 'migrating' AND pending_started_at IS NOT NULL AND pending_started_at < ?
        """,
        (deadline,),
    ).fetchall()

    cleaned = 0
    for r in rows:
        pid = str(r[0])
        try:
            cancel_server_switch(conn, pid)
            cleaned += 1
        except Exception as exc:
            LOGGER.warning("Watchdog failed to cancel expired migration for %s: %s", pid, exc)

    if cleaned > 0:
        LOGGER.info("Watchdog cleaned up %d expired OpenFlux migrations", cleaned)
    return cleaned
