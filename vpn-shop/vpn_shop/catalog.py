from __future__ import annotations

from dataclasses import dataclass

import os

from .config import Settings


@dataclass(frozen=True)
class Offer:
    code: str
    label: str
    transport: str
    duration_days: int
    price_rub: int
    device_limit: int
    profile_mode: str = "anonymous"
    beta: bool = False


def quote_price(
    device_limit: int = 3,
    duration_days: int = 30,
    settings: Settings | None = None,
) -> int:
    """Authoritative pricing calculator for SilentConnect subscriptions and renewals.

    Applies tier base pricing, multi-month discounts (-10% for 3mo, -20% for 6mo, -30% for 12mo),
    and psychological 9-ending rounding (e.g. 540 -> 539).
    """
    if settings is not None:
        device_prices = {
            3: settings.monthly_price_3_devices_rub,
            6: settings.monthly_price_6_devices_rub,
            9: settings.monthly_price_9_devices_rub,
        }
    else:
        device_prices = {
            3: int(os.environ.get("MONTHLY_PRICE_3_DEVICES_RUB", os.environ.get("MONTHLY_PRICE_TCP_RUB", 149))),
            6: int(os.environ.get("MONTHLY_PRICE_6_DEVICES_RUB", 199)),
            9: int(os.environ.get("MONTHLY_PRICE_9_DEVICES_RUB", 235)),
        }

    monthly_price = device_prices.get(device_limit, device_prices.get(3, 149))
    months = max(duration_days // 30, 1)

    discount = 0
    if duration_days >= 360:
        discount = 30
    elif duration_days >= 180:
        discount = 20
    elif duration_days >= 90:
        discount = 10

    raw_price = (monthly_price * months * (100 - discount)) // 100
    if raw_price <= 0:
        return 0
    return max(((raw_price + 5) // 10) * 10 - 1, 9)


def calculate_renewal_price(
    device_limit: int = 3,
    duration_days: int = 30,
    settings: Settings | None = None,
) -> int:
    """Alias for quote_price for renewal pricing calculations."""
    return quote_price(device_limit=device_limit, duration_days=duration_days, settings=settings)


def build_offers(settings: Settings) -> dict[str, Offer]:
    device_limits = (3, 6, 9)
    durations = {
        30: "1 месяц",
        90: "3 месяца",
        180: "6 месяцев",
        360: "12 месяцев",
    }
    offers: dict[str, Offer] = {}
    for device_limit in device_limits:
        for duration_days, duration_label in durations.items():
            standard_price = quote_price(device_limit, duration_days, settings=settings)
            universal_price = standard_price

            offers[f"tcp_{device_limit}_{duration_days}"] = Offer(
                code=f"tcp_{device_limit}_{duration_days}",
                label=f"Доступ на {duration_label}, до {device_limit} устройств",
                transport="tcp",
                duration_days=duration_days,
                price_rub=standard_price,
                device_limit=device_limit,
            )
            offers[f"xhttp_{device_limit}_{duration_days}"] = Offer(
                code=f"xhttp_{device_limit}_{duration_days}",
                label=f"XHTTP доступ на {duration_label}, до {device_limit} устройств",
                transport="xhttp",
                duration_days=duration_days,
                price_rub=standard_price,
                device_limit=device_limit,
            )
            offers[f"hybrid_{device_limit}_{duration_days}"] = Offer(
                code=f"hybrid_{device_limit}_{duration_days}",
                label=f"Доступ на {duration_label}, до {device_limit} устройств",
                transport="hybrid",
                duration_days=duration_days,
                price_rub=universal_price,
                device_limit=device_limit,
            )

    offers["tcp_30"] = offers["tcp_3_30"]
    offers["xhttp_30"] = offers["xhttp_3_30"]
    return offers
