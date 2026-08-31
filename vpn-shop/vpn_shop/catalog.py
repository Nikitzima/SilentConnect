from __future__ import annotations

from dataclasses import dataclass

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


def build_offers(settings: Settings) -> dict[str, Offer]:
    device_prices = {
        3: settings.monthly_price_3_devices_rub,
        6: settings.monthly_price_6_devices_rub,
        9: settings.monthly_price_9_devices_rub,
    }
    durations = {
        30: "1 месяц",
        90: "3 месяца",
        180: "6 месяцев",
        360: "12 месяцев",
    }
    offers: dict[str, Offer] = {}
    for device_limit, monthly_price in device_prices.items():
        for duration_days, duration_label in durations.items():
            months = max(duration_days // 30, 1)
            
            # Apply duration discounts: 3mo (-10%), 6mo (-20%), 12mo (-30%)
            discount = 0
            if duration_days == 90:
                discount = 10
            elif duration_days == 180:
                discount = 20
            elif duration_days == 360:
                discount = 30
                
            raw_price = (monthly_price * months * (100 - discount)) // 100
            
            # Round psychologically to end with 9 (e.g. 537 -> 539)
            if raw_price <= 0:
                standard_price = 0
            else:
                standard_price = max(((raw_price + 5) // 10) * 10 - 1, 9)
                
            # Collapse hybrid mode price to match standard price for simplicity
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
