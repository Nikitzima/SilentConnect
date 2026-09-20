"""AmneziaWG Quota Cycle & Period Calculation Engine (UTC).

Обеспечивает монотонный 30-дневный цикл сброса квоты в UTC от даты начала подписки,
исключая аномалии (например, сброс через 100 лет при бессрочных тарифах).
"""
from __future__ import annotations

import time
from typing import Any

CYCLE_SECONDS = 30 * 86400  # 30 дней в секундах


def get_quota_cycle_info(
    profile: dict[str, Any] | None,
    subscriptions: list[dict[str, Any]] | None = None,
    now_ts: int | None = None,
) -> dict[str, Any]:
    """
    Рассчитывает параметры текущего 30-дневного цикла квоты в UTC.

    :param profile: словарь с данными профиля (содержит created_at, expires_at)
    :param subscriptions: опциональный список заказов/подписок для уточнения даты старта
    :param now_ts: текущее время (unix timestamp), по умолчанию time.time()
    :return: словарь с period_start_utc, next_reset_utc, reset_date_str, cycle_days, is_perpetual
    """
    now = int(now_ts if now_ts is not None else time.time())

    if not profile:
        next_ts = now + CYCLE_SECONDS
        return {
            "period_start_utc": now,
            "next_reset_utc": next_ts,
            "cycle_days": 30,
            "reset_date_str": time.strftime("%d.%m.%Y", time.gmtime(next_ts)),
            "is_perpetual": False,
        }

    created_at = int(profile.get("created_at") or now)
    expires_at = int(profile.get("expires_at") or 0)

    # Определение даты старта непрерывного периода
    start_ts = created_at
    if subscriptions:
        valid_starts = []
        for s in subscriptions:
            c_at = s.get("created_at") or s.get("purchased_at")
            if c_at and int(c_at) > 0:
                valid_starts.append(int(c_at))
        if valid_starts:
            start_ts = min(valid_starts)

    # Защита от некорректных дат из будущего или отрицательных
    if start_ts <= 0 or start_ts > now:
        start_ts = now

    elapsed = max(0, now - start_ts)
    cycles_passed = elapsed // CYCLE_SECONDS
    next_reset_utc = start_ts + (cycles_passed + 1) * CYCLE_SECONDS

    reset_date_str = time.strftime("%d.%m.%Y", time.gmtime(next_reset_utc))
    is_perpetual = bool(expires_at > now and (expires_at - now) > 365 * 10 * 86400)

    return {
        "period_start_utc": start_ts,
        "next_reset_utc": next_reset_utc,
        "cycle_days": 30,
        "reset_date_str": reset_date_str,
        "is_perpetual": is_perpetual,
    }
