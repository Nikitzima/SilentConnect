from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _load_dotenv(dotenv_path: Path, *, override: bool = False) -> None:
    if not dotenv_path.exists():
        return
    for raw_line in dotenv_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        if override:
            os.environ[key] = value
        else:
            os.environ.setdefault(key, value)


def _env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if value is None:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _int(name: str, default: int) -> int:
    return int(os.environ.get(name, str(default)))


def _bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _path_from_env(name: str, default: str | Path, root_dir: Path) -> Path:
    raw = os.environ.get(name)
    path = Path(raw) if raw is not None else Path(default)
    if not path.is_absolute():
        path = root_dir / path
    return path.resolve()


def _csv_usernames(name: str) -> tuple[str, ...]:
    raw = os.environ.get(name, "")
    values = []
    for item in raw.split(","):
        cleaned = item.strip().lstrip("@").lower()
        if cleaned:
            values.append(cleaned)
    return tuple(values)


def _csv_ints(name: str) -> tuple[int, ...]:
    raw = os.environ.get(name, "")
    values = []
    for item in raw.split(","):
        cleaned = item.strip()
        if cleaned:
            values.append(int(cleaned))
    return tuple(values)


DEFAULT_MANAGER_TG_ID = 958026436  # PLACEHOLDER

REFERRAL_INVITEE_DISCOUNT_PERCENT: int = 10
REFERRAL_COOKIE_NAME: str = "sc_ref"
REFERRAL_COOKIE_MAX_AGE: int = 2592000  # 30 days


@dataclass(frozen=True)
class Settings:
    root_dir: Path
    data_dir: Path
    database_path: Path
    telegram_bot_token: str
    telegram_bot_username: str
    brand_name: str
    support_tg_url: str
    welcome_media: str
    quickstart_media: str
    admin_usernames: tuple[str, ...]
    admin_user_ids: tuple[int, ...]
    subscription_base_url: str
    payment_instructions_text: str
    payment_transfer_url: str
    payment_bank_note: str
    xui_panel_url: str
    xui_username: str
    xui_password: str
    xui_verify_tls: bool
    xui_db_path: Path
    xui_xhttp_inbound_id: int
    xui_tcp_inbound_id: int
    web_listen_host: str
    web_listen_port: int
    web_public_base_url: str
    monthly_price_xhttp_rub: int
    monthly_price_tcp_rub: int
    monthly_price_3_devices_rub: int
    monthly_price_6_devices_rub: int
    monthly_price_9_devices_rub: int
    default_device_limit: int
    invite_required: bool
    terms_version: str
    purge_after_days: int
    support_email: str
    smtp_host: str
    smtp_port: int
    smtp_user: str
    smtp_password: str
    smtp_from_email: str
    cf_turnstile_site_key: str
    cf_turnstile_secret_key: str
    cf_turnstile_enabled: bool = True
    platega_merchant_id_bot: str = "c3393290-d96e-4a5e-aca3-12015a843b0e"
    platega_merchant_id_web: str = "e4d5af52-9c18-444b-b8bf-db1a26f0c61d"
    platega_secret: str = ""
    platega_secret_bot: str = ""
    platega_secret_web: str = ""
    platega_enabled: bool = False


def load_settings(root_dir: Path | None = None, env_file: str | Path | None = None) -> Settings:
    resolved_root = (root_dir or Path(__file__).resolve().parents[1]).resolve()
    _load_dotenv(resolved_root / ".env")
    _load_dotenv(resolved_root / ".env.platega")
    if not os.environ.get("PLATEGA_SECRET") and not os.environ.get("PLATEGA_SECRET_BOT") and not os.environ.get("PLATEGA_SECRET_WEB"):
        for alt in (
            resolved_root.parent / ".env.platega",
            resolved_root.parent / "vpn-shop" / ".env.platega",
            resolved_root.parent.parent / "vpn-shop" / ".env.platega",
        ):
            if alt.exists():
                _load_dotenv(alt)
                break
    selected_env_file = env_file or os.environ.get("VPN_SHOP_ENV_FILE")
    if selected_env_file:
        selected_path = Path(selected_env_file)
        if not selected_path.is_absolute():
            selected_path = resolved_root / selected_path
        _load_dotenv(selected_path, override=True)
    data_dir = _path_from_env("SHOP_DATA_DIR", resolved_root / "data", resolved_root)
    database_path = _path_from_env("SHOP_DB_PATH", data_dir / "vpn_shop.db", resolved_root)

    return Settings(
        root_dir=resolved_root,
        data_dir=data_dir,
        database_path=database_path,
        telegram_bot_token=os.environ.get("TELEGRAM_BOT_TOKEN", "").strip(),
        telegram_bot_username=os.environ.get("TELEGRAM_BOT_USERNAME", "").strip().lstrip("@"),
        brand_name=os.environ.get("BRAND_NAME", "SilentConnect").strip() or "SilentConnect",
        support_tg_url=os.environ.get("SUPPORT_TG_URL", "https://t.me/your_support").strip(),
        welcome_media=os.environ.get("WELCOME_MEDIA", "").strip(),
        quickstart_media=os.environ.get("QUICKSTART_MEDIA", "").strip(),
        admin_usernames=_csv_usernames("ADMIN_TG_USERNAMES"),
        admin_user_ids=_csv_ints("ADMIN_TG_IDS") or (DEFAULT_MANAGER_TG_ID,),
        subscription_base_url=_env("SUBSCRIPTION_BASE_URL", "http://127.0.0.1:3088/sub/json").rstrip("/"),
        payment_instructions_text=os.environ.get(
            "PAYMENT_INSTRUCTIONS_TEXT",
            "Оплата пока подтверждается вручную. После перевода дождитесь подтверждения менеджером.",
        ).strip(),
        payment_transfer_url=os.environ.get(
            "PAYMENT_TRANSFER_URL",
            "https://t.tb.ru/c2c-qr-choose-bank?requisiteNumber=+79990000000&bankCode=100000000004",
        ).strip(),
        payment_bank_note=os.environ.get(
            "PAYMENT_BANK_NOTE",
            "Приоритетно переводить через СБП по указанным реквизитам.",
        ).strip(),
        xui_panel_url=_env("XUI_PANEL_URL", "https://127.0.0.1:2053/").rstrip("/") + "/",
        xui_username=os.environ.get("XUI_USERNAME", "").strip(),
        xui_password=os.environ.get("XUI_PASSWORD", "").strip(),
        xui_verify_tls=_bool("XUI_VERIFY_TLS", True),
        xui_db_path=_path_from_env("XUI_DB_PATH", "/etc/x-ui/x-ui.db", resolved_root),
        xui_xhttp_inbound_id=_int("XUI_XHTTP_INBOUND_ID", 1),
        xui_tcp_inbound_id=_int("XUI_TCP_INBOUND_ID", 2),
        web_listen_host=os.environ.get("WEB_LISTEN_HOST", "127.0.0.1").strip() or "127.0.0.1",
        web_listen_port=_int("WEB_LISTEN_PORT", 3090),
        web_public_base_url=os.environ.get("WEB_PUBLIC_BASE_URL", "https://example.com").strip().rstrip("/"),
        monthly_price_xhttp_rub=_int("MONTHLY_PRICE_XHTTP_RUB", 149),
        monthly_price_tcp_rub=_int("MONTHLY_PRICE_TCP_RUB", 149),
        monthly_price_3_devices_rub=_int("MONTHLY_PRICE_3_DEVICES_RUB", _int("MONTHLY_PRICE_TCP_RUB", 149)),
        monthly_price_6_devices_rub=_int("MONTHLY_PRICE_6_DEVICES_RUB", 199),
        monthly_price_9_devices_rub=_int("MONTHLY_PRICE_9_DEVICES_RUB", 235),
        default_device_limit=_int("DEFAULT_DEVICE_LIMIT", 3),
        invite_required=_bool("INVITE_REQUIRED", True),
        terms_version=_env("TERMS_VERSION", "2026-04-20"),
        purge_after_days=_int("PURGE_AFTER_DAYS", 90),
        support_email=os.environ.get("SUPPORT_EMAIL", "support@example.com").strip(),
        smtp_host=os.environ.get("SMTP_HOST", "").strip(),
        smtp_port=_int("SMTP_PORT", 465),
        smtp_user=os.environ.get("SMTP_USER", "").strip(),
        smtp_password=os.environ.get("SMTP_PASSWORD", "").strip(),  # PLACEHOLDER
        smtp_from_email=os.environ.get("SMTP_FROM_EMAIL", "SilentConnect <support@example.com>").strip(),
        cf_turnstile_site_key=os.environ.get("CF_TURNSTILE_SITE_KEY", "").strip(),
        cf_turnstile_secret_key=os.environ.get("CF_TURNSTILE_SECRET_KEY", "").strip(),
        cf_turnstile_enabled=_bool("CF_TURNSTILE_ENABLED", True) and bool(os.environ.get("CF_TURNSTILE_SECRET_KEY", "").strip()),
        platega_merchant_id_bot=os.environ.get("PLATEGA_MERCHANT_ID_BOT", "c3393290-d96e-4a5e-aca3-12015a843b0e").strip(),
        platega_merchant_id_web=os.environ.get("PLATEGA_MERCHANT_ID_WEB", "e4d5af52-9c18-444b-b8bf-db1a26f0c61d").strip(),
        platega_secret=os.environ.get("PLATEGA_SECRET", "").strip(),
        platega_secret_bot=os.environ.get("PLATEGA_SECRET_BOT", "").strip() or os.environ.get("PLATEGA_SECRET", "").strip(),
        platega_secret_web=os.environ.get("PLATEGA_SECRET_WEB", "").strip() or os.environ.get("PLATEGA_SECRET", "").strip(),
        platega_enabled=_bool("PLATEGA_ENABLED", False) and bool(
            os.environ.get("PLATEGA_SECRET", "").strip()
            or os.environ.get("PLATEGA_SECRET_BOT", "").strip()
            or os.environ.get("PLATEGA_SECRET_WEB", "").strip()
        ),
    )

