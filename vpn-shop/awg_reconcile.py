"""AWG reconcile: синхронизация пиров с жизненным циклом подписок на всех серверах (NL и FI).

Каждые 10 минут:
  - истёк срок подписки (x-ui) -> пир удаляется
  - трафик пира >= 500 ГБ за период (30 дней от даты привязки) -> пир удаляется
    до конца периода, потом возвращается
  - подписка продлена (срок снова в будущем) -> пир возвращается
Ручные пиры (админ, дядя) в БД отсутствуют - не трогаются.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Support running both inside vpn-shop dir and from /root/vpn-shop
sys.path.insert(0, "/root/vpn-shop")
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent / "vpn_shop"))

try:
    from vpn_shop import awg_manager
    from vpn_shop.awg_manager import _dex
    from vpn_shop.xui_db import XuiDatabase
except ImportError:
    try:
        import awg_manager
        from awg_manager import _dex
        from xui_db import XuiDatabase
    except ImportError:
        from vpn_shop import awg_manager
        from vpn_shop.awg_manager import _dex
        from vpn_shop.xui_db import XuiDatabase

QUOTA_GB = int(os.environ.get("AWG_MONTHLY_QUOTA_GB", 500))
QUOTA_BYTES = QUOTA_GB * 1024 ** 3
PERIOD_DAYS = 30
XUI_DB = Path(os.environ.get("XUI_DB_PATH", "/etc/x-ui/x-ui.db"))


def log(msg: str) -> None:
    print(f"[awg-reconcile] {datetime.now(timezone.utc).strftime('%H:%M:%S')} {msg}", flush=True)


def ensure_torrent_block(server_code: str = "nl") -> None:
    """DPI-блок BitTorrent/DHT в FORWARD контейнера на указанном сервере (идемпотентно)."""
    rules = [
        ("BitTorrent protocol", "tcp"),
        ("d1:ad2:id20:", "udp"),   # DHT announce
        ("BT-SEARCH", "udp"),      # LSD
    ]
    try:
        existing = _dex("iptables -S FORWARD", server_code=server_code)
        for sig, proto in rules:
            if sig not in existing:
                _dex(
                    f"iptables -I FORWARD 1 -p {proto} -m string --string '{sig}' --algo bm -j REJECT --reject-with icmp-port-unreachable",
                    server_code=server_code,
                )
    except Exception as exc:
        log(f"[{server_code.upper()}] warn: could not set torrent block: {exc}")


def main() -> None:
    awg_manager.ensure_table()
    for srv in ("nl", "fi"):
        ensure_torrent_block(srv)

    xui = XuiDatabase(XUI_DB)
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    now_s = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    transfers: dict[str, dict[str, tuple[int, int]]] = {}
    for srv in ("nl", "fi"):
        try:
            transfers[srv] = awg_manager.peer_transfer(srv)
        except Exception as exc:
            log(f"[{srv.upper()}] error getting peer transfer: {exc}")
            transfers[srv] = {}

    actions = 0

    for peer in awg_manager.all_peers(active_only=False):
        sub_id = peer["sub_id"]
        server_code = peer.get("server_code") or "nl"
        pub = peer["public_key"]

        client = xui.find_client_by_sub_id(sub_id)
        if not client:
            log(f"[{server_code.upper()}] {sub_id}: клиент исчез из панели - пропуск")
            continue

        email = str((client.get("client") or {}).get("email") or "")
        traffic = xui.get_client_traffic(email) if email else None
        expiry_ms = int((traffic or {}).get("expiry_time") or 0)
        expired = 0 < expiry_ms < now_ms

        srv_transfer = transfers.get(server_code, {})
        rx, tx = srv_transfer.get(pub, (peer["last_rx"], peer["last_tx"]))
        d_rx = max(rx - peer["last_rx"], 0)
        d_tx = max(tx - peer["last_tx"], 0)
        used = peer["bytes_used"] + d_rx + d_tx
        awg_manager.set_counters(sub_id, rx, tx, server_code=server_code)

        period_start = peer["period_start"]
        try:
            period_age_days = (
                datetime.now(timezone.utc)
                - datetime.strptime(period_start, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            ).days
        except ValueError:
            period_age_days = 0

        quota_exhausted = used >= QUOTA_BYTES
        period_over = period_age_days >= PERIOD_DAYS

        try:
            if expired:
                if peer["active"]:
                    awg_manager.remove_peer(sub_id, "subscription expired", server_code=server_code)
                    awg_manager.set_usage(sub_id, used, server_code=server_code)
                    log(f"[{server_code.upper()}] {sub_id}: пир удалён (подписка истекла)")
                    actions += 1
                continue

            if quota_exhausted and not period_over:
                if peer["active"]:
                    awg_manager.remove_peer(sub_id, "quota exhausted", server_code=server_code)
                    awg_manager.set_usage(sub_id, used, server_code=server_code)
                    log(f"[{server_code.upper()}] {sub_id}: пир удалён (квота {used / 1024 ** 3:.1f} ГБ исчерпана)")
                    actions += 1
                continue

            if not peer["active"]:
                awg_manager.readd_peer(sub_id, server_code=server_code)
                log(f"[{server_code.upper()}] {sub_id}: пир возвращён (подписка активна)")
                actions += 1

            if period_over:
                awg_manager.set_period(sub_id, now_s, server_code=server_code)
                log(f"[{server_code.upper()}] {sub_id}: новый период, счётчик трафика сброшен")
                actions += 1

            awg_manager.set_usage(sub_id, used, server_code=server_code)
        except Exception as exc:
            log(f"[{server_code.upper()}] error reconciling peer {sub_id}: {exc}")

    log(f"готово, действий: {actions}")


if __name__ == "__main__":
    main()
