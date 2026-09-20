"""AmneziaWG Distributed Traffic Accounting Engine & Device Slots Controller.

Обеспечивает:
1. Парсинг вывода ядра WireGuard / AmneziaWG (`awg show <interface> transfer`).
2. Монотонный расчет дельт трафика (с защитой от перезапуска интерфейса и сброса счетчиков).
3. Распределенную синхронизацию трафика между нодами кластера (NL, PL, FI).
4. Оценку квот (250 GB / 3 девайса, 500 GB / 6 девайсов, 1000 GB / 9 девайсов).
5. Мягкое отключение пиров AmneziaWG при превышении лимита пакета без влияния
   на безлимитный протокол VLESS/XHTTP.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Sequence

from .security import now_ts
from .store import Store, default_awg_quota_bytes_for_devices

LOGGER = logging.getLogger("vpn_shop.awg_traffic")

DEFAULT_STATE_FILE = Path("/dev/shm/awg_last_counters.json")
FALLBACK_STATE_FILE = Path(os.environ.get("TEMP", os.environ.get("TMP", "/tmp"))) / "awg_last_counters.json"


@dataclass(frozen=True)
class TrafficDelta:
    public_key: str
    delta_rx_bytes: int
    delta_tx_bytes: int
    node_id: str
    collected_at: int

    @property
    def total_bytes(self) -> int:
        return self.delta_rx_bytes + self.delta_tx_bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            "public_key": self.public_key,
            "delta_rx_bytes": self.delta_rx_bytes,
            "delta_tx_bytes": self.delta_tx_bytes,
            "total_bytes": self.total_bytes,
            "node_id": self.node_id,
            "collected_at": self.collected_at,
        }


@dataclass
class QuotaEvaluation:
    profile_public_id: str
    awg_quota_bytes: int
    awg_used_bytes: int
    remaining_bytes: int
    usage_percent: float
    is_exceeded: bool
    active_slots: list[dict[str, Any]] = field(default_factory=list)
    disabled_slots: list[dict[str, Any]] = field(default_factory=list)
    keys_to_disable: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def is_valid_wg_key(key: str) -> bool:
    """Проверка корректности публичного/приватного ключа WireGuard (Base64 32 байта)."""
    if not isinstance(key, str):
        return False
    stripped = key.strip()
    if len(stripped) != 44 or not stripped.endswith("="):
        return False
    try:
        decoded = base64.b64decode(stripped, validate=True)
        return len(decoded) == 32
    except Exception:
        return False


def parse_awg_transfer(raw_output: str) -> dict[str, tuple[int, int]]:
    """Парсинг вывода `awg show <interface> transfer` или `wg show <interface> transfer`.

    Формат ядра WireGuard:
    <public_key>\t<rx_bytes>\t<tx_bytes>
    Возвращает: {public_key: (rx_bytes, tx_bytes)}
    """
    counters: dict[str, tuple[int, int]] = {}
    if not raw_output:
        return counters

    for line in raw_output.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"[\t\s]+", line)
        if len(parts) < 3:
            continue
        pubkey, rx_str, tx_str = parts[0].strip(), parts[1].strip(), parts[2].strip()
        try:
            rx = int(rx_str)
            tx = int(tx_str)
            if rx >= 0 and tx >= 0:
                counters[pubkey] = (rx, tx)
        except ValueError:
            continue

    return counters


class CounterStateTracker:
    """Хранит и обновляет предыдущее состояние счетчиков интерфейса.

    Гарантирует монотонный неотрицательный расчет дельты при:
    - Обычном инкременте трафика
    - Перезапуске ядра / сетевого интерфейса (когда счетчики сбрасываются в 0)
    - Переполнении счетчиков ядра
    """

    def __init__(self, state_file: Path | str | None = None) -> None:
        self.state_file: Path | None = None
        if state_file:
            self.state_file = Path(state_file)
        else:
            # Выбор пути: /dev/shm (ОЗУ) если доступно, иначе временная папка ОС
            if DEFAULT_STATE_FILE.parent.exists() and os.access(str(DEFAULT_STATE_FILE.parent), os.W_OK):
                self.state_file = DEFAULT_STATE_FILE
            else:
                self.state_file = FALLBACK_STATE_FILE

        self.previous_counters: dict[str, tuple[int, int, int]] = {}
        self.load_state()

    def load_state(self) -> None:
        """Загрузка сохраненного состояния счетчиков из файла."""
        if not self.state_file or not self.state_file.exists():
            return
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, (list, tuple)) and len(v) >= 2:
                        rx = int(v[0])
                        tx = int(v[1])
                        ts = int(v[2]) if len(v) >= 3 else now_ts()
                        self.previous_counters[k] = (rx, tx, ts)
        except Exception as exc:
            LOGGER.warning("Could not load AWG counter state from %s: %s", self.state_file, exc)

    def save_state(self) -> None:
        """Сохранение текущего состояния счетчиков в файл."""
        if not self.state_file:
            return
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            tmp_file = self.state_file.with_suffix(".tmp")
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(self.previous_counters, f, separators=(",", ":"))
            tmp_file.replace(self.state_file)
        except Exception as exc:
            LOGGER.warning("Could not persist AWG counter state to %s: %s", self.state_file, exc)

    def calculate_monotonic_deltas(
        self,
        current_counters: dict[str, tuple[int, int]],
        *,
        node_id: str = "local",
        collected_at: int | None = None,
        baseline_only: bool = False,
    ) -> list[TrafficDelta]:
        """Расчет неотрицательных дельт между текущим замером и предыдущим состоянием."""
        ts = collected_at or now_ts()
        deltas: list[TrafficDelta] = []

        for pubkey, (curr_rx, curr_tx) in current_counters.items():
            if baseline_only:
                self.previous_counters[pubkey] = (curr_rx, curr_tx, ts)
                continue

            if pubkey not in self.previous_counters:
                # Первый замер для данного пира — дельта равна текущему значению
                delta_rx = curr_rx
                delta_tx = curr_tx
            else:
                prev_rx, prev_tx, _ = self.previous_counters[pubkey]

                # Защита от сброса ядра/интерфейса: если curr < prev, счетчик сбросился
                if curr_rx >= prev_rx:
                    delta_rx = curr_rx - prev_rx
                else:
                    delta_rx = curr_rx

                if curr_tx >= prev_tx:
                    delta_tx = curr_tx - prev_tx
                else:
                    delta_tx = curr_tx

            delta_rx = max(0, delta_rx)
            delta_tx = max(0, delta_tx)

            # Обновляем сохраненное состояние
            self.previous_counters[pubkey] = (curr_rx, curr_tx, ts)

            # Фиксируем дельту, если был хоть какой-то обмен данными
            if delta_rx > 0 or delta_tx > 0:
                deltas.append(
                    TrafficDelta(
                        public_key=pubkey,
                        delta_rx_bytes=delta_rx,
                        delta_tx_bytes=delta_tx,
                        node_id=node_id,
                        collected_at=ts,
                    )
                )

        self.save_state()
        return deltas


class AwgTrafficCollector:
    """Сборщик трафика сетевых туннелей AmneziaWG на ноде."""

    def __init__(
        self,
        *,
        interface: str = "awg0",
        node_id: str = "nl-master",
        state_file: Path | str | None = None,
        command_runner: Callable[[str], str] | None = None,
    ) -> None:
        self.interface = interface
        self.node_id = node_id
        self.tracker = CounterStateTracker(state_file)
        self.command_runner = command_runner or self._default_command_runner

    def _default_command_runner(self, cmd: str) -> str:
        """Выполнение команды `awg show` в системе."""
        proc = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if proc.returncode != 0:
            LOGGER.warning("Command '%s' exited with code %s: %s", cmd, proc.returncode, proc.stderr.strip())
            return ""
        return proc.stdout

    def collect_node_deltas(self) -> list[TrafficDelta]:
        """Опрос ядра и вычисление дельт трафика на текущей ноде."""
        cmd = f"awg show {self.interface} transfer"
        output = self.command_runner(cmd)
        counters = parse_awg_transfer(output)
        return self.tracker.calculate_monotonic_deltas(counters, node_id=self.node_id)

    def initialize_baseline(self) -> None:
        """Инициализация базового состояния счетчиков без начисления дельт трафика."""
        cmd = f"awg show {self.interface} transfer"
        output = self.command_runner(cmd)
        counters = parse_awg_transfer(output)
        self.tracker.calculate_monotonic_deltas(counters, node_id=self.node_id, baseline_only=True)


def evaluate_profile_quota(profile_public_id: str, store: Store) -> QuotaEvaluation:
    """Оценка остатка трафика AmneziaWG для указанного профиля."""
    quota = store.get_awg_profile_quota(profile_public_id)
    if not quota:
        return QuotaEvaluation(
            profile_public_id=profile_public_id,
            awg_quota_bytes=0,
            awg_used_bytes=0,
            remaining_bytes=0,
            usage_percent=0.0,
            is_exceeded=False,
        )

    slots = store.list_awg_slots(profile_public_id)
    active_slots = [s for s in slots if s.get("enabled")]
    disabled_slots = [s for s in slots if not s.get("enabled")]

    quota_bytes = int(quota.get("awg_quota_bytes") or 0)
    used_bytes = int(quota.get("awg_used_bytes") or 0)
    is_exceeded = bool(quota_bytes > 0 and used_bytes >= quota_bytes)
    remaining = max(0, quota_bytes - used_bytes) if quota_bytes > 0 else 0
    usage_pct = round((used_bytes / quota_bytes) * 100.0, 2) if quota_bytes > 0 else 0.0

    # When quota is exceeded, ALL public keys belonging to this profile must be disabled
    # across the entire cluster to prevent traffic leaks.
    all_pubkeys = [str(s["public_key"]) for s in slots if s.get("public_key")]
    keys_to_disable = all_pubkeys if is_exceeded else []

    return QuotaEvaluation(
        profile_public_id=profile_public_id,
        awg_quota_bytes=quota_bytes,
        awg_used_bytes=used_bytes,
        remaining_bytes=remaining,
        usage_percent=usage_pct,
        is_exceeded=is_exceeded,
        active_slots=active_slots,
        disabled_slots=disabled_slots,
        keys_to_disable=keys_to_disable,
    )


def enforce_quota_soft_disable(
    profile_public_id: str,
    store: Store,
    *,
    kernel_peer_remover: Callable[[str, str], bool] | None = None,
) -> dict[str, Any]:
    """Мягкое отключение слотов AmneziaWG при исчерпании квоты трафика.

    ВАЖНО: Доступ по VLESS/XHTTP в X-UI не затрагивается и продолжает работать!
    """
    evaluation = evaluate_profile_quota(profile_public_id, store)
    if not evaluation.is_exceeded:
        return {
            "profile_public_id": profile_public_id,
            "status": "not_exceeded",
            "disabled_count": 0,
            "keys_disabled": [],
        }

    # Disable any slots still marked enabled in the database
    newly_disabled_keys: list[str] = []
    for slot in evaluation.active_slots:
        slot_id = slot["id"]
        pubkey = slot["public_key"]
        server_code = slot.get("server_code", "nl")

        # Отключаем слот в базе данных
        store.set_awg_slot_enabled(slot_id, False)
        newly_disabled_keys.append(pubkey)

        # Удаляем пир из оперативной памяти ядра (если передан обработчик)
        if kernel_peer_remover:
            try:
                kernel_peer_remover(server_code, pubkey)
            except Exception as exc:
                LOGGER.error("Failed to remove peer %s on server %s from kernel: %s", pubkey, server_code, exc)

    all_keys = evaluation.keys_to_disable

    LOGGER.info(
        "Soft-disabled %d AmneziaWG slots for profile %s (used %d / quota %d bytes). VLESS remains active.",
        len(all_keys),
        profile_public_id,
        evaluation.awg_used_bytes,
        evaluation.awg_quota_bytes,
    )

    return {
        "profile_public_id": profile_public_id,
        "status": "soft_disabled",
        "disabled_count": len(all_keys),
        "newly_disabled_count": len(newly_disabled_keys),
        "keys_disabled": all_keys,
        "used_bytes": evaluation.awg_used_bytes,
        "quota_bytes": evaluation.awg_quota_bytes,
    }


def restore_quota_peers(
    profile_public_id: str,
    store: Store,
    *,
    kernel_peer_adder: Callable[[dict[str, Any]], bool] | None = None,
) -> dict[str, Any]:
    """Восстановление слотов AmneziaWG после продления или сброса квоты."""
    slots = store.list_awg_slots(profile_public_id)
    restored_keys: list[str] = []

    for slot in slots:
        slot_id = slot["id"]
        store.set_awg_slot_enabled(slot_id, True)
        restored_keys.append(slot["public_key"])

        if kernel_peer_adder:
            try:
                kernel_peer_adder(slot)
            except Exception as exc:
                LOGGER.error("Failed to re-add peer %s to kernel: %s", slot["public_key"], exc)

    return {
        "profile_public_id": profile_public_id,
        "status": "restored",
        "restored_count": len(restored_keys),
        "keys_restored": restored_keys,
    }


def process_cluster_traffic_sync(
    store: Store,
    payload: dict[str, Any],
    *,
    kernel_peer_remover: Callable[[str, str], bool] | None = None,
) -> dict[str, Any]:
    """Обработчик синхронизации трафика от удаленных нод (POST /api/internal/awg/traffic-sync).

    Принимает пачку дельт, сопоставляет открытые ключи со слотами клиентов,
    обновляет журнал и общий расход профиля, проверяет лимит квоты и возвращает
    список ключей, которые необходимо отключить на нодах.
    """
    if not isinstance(payload, dict):
        raise ValueError("Invalid sync payload: must be a JSON object")

    node_id = str(payload.get("node_id") or "unknown")
    raw_deltas = payload.get("deltas")
    if not isinstance(raw_deltas, list):
        raise ValueError("Invalid sync payload: 'deltas' must be a list")

    collected_at = int(payload.get("collected_at") or now_ts())

    ledger_records: list[dict[str, Any]] = []
    affected_profiles: set[str] = set()

    for item in raw_deltas:
        if not isinstance(item, dict):
            continue
        pubkey = str(item.get("public_key") or "").strip()
        if not pubkey:
            continue
        rx = max(0, int(item.get("delta_rx_bytes", item.get("delta_rx", 0))))
        tx = max(0, int(item.get("delta_tx_bytes", item.get("delta_tx", 0))))
        if rx == 0 and tx == 0:
            continue

        slot = store.get_awg_slot_by_public_key(pubkey)
        if not slot:
            # Пир не принадлежит ни одному активному слоту системы
            continue

        profile_id = str(slot["profile_public_id"])
        affected_profiles.add(profile_id)
        ledger_records.append(
            {
                "node_id": node_id,
                "profile_public_id": profile_id,
                "slot_id": slot["id"],
                "delta_rx_bytes": rx,
                "delta_tx_bytes": tx,
                "collected_at": collected_at,
            }
        )

    recorded_count = store.record_awg_traffic_deltas(ledger_records)

    # Проверка квот по всем затронутым профилям
    disable_peers: list[str] = []
    seen_keys: set[str] = set()
    for pid in affected_profiles:
        eval_res = evaluate_profile_quota(pid, store)
        if eval_res.is_exceeded:
            enforce_res = enforce_quota_soft_disable(pid, store, kernel_peer_remover=kernel_peer_remover)
            for k in enforce_res.get("keys_disabled", []):
                if k not in seen_keys:
                    seen_keys.add(k)
                    disable_peers.append(k)

    return {
        "status": "ok",
        "node_id": node_id,
        "recorded_count": recorded_count,
        "affected_profiles": list(affected_profiles),
        "disable_peers": disable_peers,
    }
