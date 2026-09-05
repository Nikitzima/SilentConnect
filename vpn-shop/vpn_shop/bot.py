from __future__ import annotations

import concurrent.futures
import logging
import os
import shutil
import socket
import re
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlencode, urlsplit, urlunsplit

from . import awg_manager

from .catalog import Offer, build_offers
from .config import DEFAULT_MANAGER_TG_ID, Settings
from .mailer import send_subscription_email_async
from .provisioning import ADMIN_PROFILE_NOTES, PUBLIC_TRIAL_PROFILE_NOTES, TEST_PROFILE_NOTES, Provisioner
from .security import days_from_now, normalize_username, now_ts
from .store import Store
from .telegram_api import TelegramApiError, TelegramBotClient
from .web import subscription_setup_url
from .xui_api import XuiApiError


LOGGER = logging.getLogger("vpn-shop")
TEST_PROFILE_CLEANUP_INTERVAL = 60
ACTION_GUARD_KEY = "_action_guard"
ACTION_GUARD_TTL_SECONDS = 120
WAITING_PAYMENT_EXPIRY_SECONDS = 6 * 3600
ORDER_NOTIFICATION_BUMP_SECONDS = 30 * 60
PAYMENT_REPORT_REPEAT_SECONDS = 10 * 60
TRIAL_TRANSPORT = "tcp"
REFERRAL_COMMISSION_PERCENT = 10
REFERRAL_PAYOUT_MIN_RUB = 500
REFERRAL_MONTHLY_REPORT_DAY = 28
PUBLIC_ACCESS_START_CODE = "open"


def kb(rows: list[list[Any]]) -> dict[str, Any]:
    def _button(spec: Any) -> dict[str, Any]:
        if isinstance(spec, dict):
            button: dict[str, Any] = {"text": spec["text"]}
            style = spec.get("style")
            if style:
                button["style"] = style
            if spec.get("copy_text") is not None:
                button["copy_text"] = {"text": str(spec["copy_text"])}
                return button
            data = str(spec.get("data") or spec.get("url") or spec.get("callback_data") or "")
        else:
            text, data = spec[0], spec[1]
            style = spec[2] if len(spec) >= 3 else None
            button = {"text": text}
            if style:
                button["style"] = style
        if data.startswith(("https://", "http://", "tg://")):
            button["url"] = data
        else:
            button["callback_data"] = data
        return button

    return {
        "inline_keyboard": [
            [_button(spec) for spec in row]
            for row in rows
        ]
    }


class ShopBot:
    def __init__(self, settings: Settings, store: Store) -> None:
        self.settings = settings
        self.store = store
        self.store.init()
        self.telegram = TelegramBotClient(settings.telegram_bot_token)
        self.provisioner = Provisioner(settings, store)
        self.offers = build_offers(settings)
        self._last_test_profile_cleanup_at = 0
        self._periodic_task_lock = threading.Lock()
        self._background_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=4, thread_name_prefix="bot_bg_worker"
        )

    def invite_link(self, invite_code: str) -> str:
        username = (self.settings.telegram_bot_username or "").strip()
        if not username:
            raise RuntimeError("TELEGRAM_BOT_USERNAME is not configured")
        return f"https://t.me/{username}?start={invite_code}"

    def referral_link(self, referral_code: str) -> str:
        username = (self.settings.telegram_bot_username or "").strip()
        if not username:
            raise RuntimeError("TELEGRAM_BOT_USERNAME is not configured")
        return f"https://t.me/{username}?start={referral_code}"

    def public_access_link(self) -> str:
        username = (self.settings.telegram_bot_username or "").strip()
        if not username:
            raise RuntimeError("TELEGRAM_BOT_USERNAME is not configured")
        return f"https://t.me/{username}?start={PUBLIC_ACCESS_START_CODE}"

    def legal_terms_url(self) -> str:
        parsed = urlsplit(self.settings.subscription_base_url)
        if parsed.scheme and parsed.netloc:
            return urlunsplit((parsed.scheme, parsed.netloc, "/legal/terms", "", ""))
        return f"{self.settings.web_public_base_url}/legal/terms"

    def payment_transfer_url(self, order: dict[str, Any] | None = None) -> str:
        return (self.settings.payment_transfer_url or "").strip()

    def payment_bank_note(self) -> str:
        return (
            (self.settings.payment_bank_note or "").strip()
            or "Приоритетно переводить в МТС Банк. Если удобнее, можно Ozon Банк или Т-Банк."
        )

    def _remember_user(self, chat_id: int | str | None, user: dict[str, Any]) -> None:
        if chat_id is None:
            return
        self.store.upsert_telegram_user(user=user, chat_id=chat_id)

    @staticmethod
    def _subscription_id_from_url(subscription_url: str) -> str:
        path = urlsplit(subscription_url).path.rstrip("/")
        return unquote(path.split("/")[-1]) if path else ""

    @staticmethod
    def _subscription_import_url(subscription_url: str, target: str) -> str:
        parsed = urlsplit(subscription_url)
        parts = [segment for segment in parsed.path.split("/") if segment]
        if len(parts) >= 3:
            sub_id = parts[-1]
            base_parts = parts[:-2]
            import_path = "/" + "/".join([*base_parts, "import", target, quote(sub_id, safe="")])
        else:
            sub_id = parts[-1] if parts else ""
            import_path = f"/import/{target}/{quote(sub_id, safe='')}"
        query = urlencode({"url": subscription_url})
        return urlunsplit((parsed.scheme, parsed.netloc, import_path, query, ""))

    @staticmethod
    def _subscription_setup_url(subscription_url: str) -> str:
        parsed = urlsplit(subscription_url)
        parts = [segment for segment in parsed.path.split("/") if segment]
        if len(parts) >= 3:
            sub_id = parts[-1]
            base_parts = parts[:-2]
            import_path = "/" + "/".join([*base_parts, "import", quote(sub_id, safe="~")])
        else:
            sub_id = parts[-1] if parts else ""
            import_path = f"/import/{quote(sub_id, safe='~')}"
        query = urlencode({"url": subscription_url})
        return urlunsplit((parsed.scheme, parsed.netloc, import_path, query, ""))

    def _subscription_url_from_id(self, subscription_id: str) -> str:
        return f"{self.settings.subscription_base_url}/{quote(subscription_id, safe='')}"

    def _subscription_url_for_route(self, route: str, subscription_id: str) -> str:
        parsed = urlsplit(self.settings.subscription_base_url)
        base_parts = [segment for segment in parsed.path.split("/") if segment]
        if base_parts:
            base_parts = base_parts[:-1]
        path = "/" + "/".join([*base_parts, route, quote(subscription_id, safe="~")])
        return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))

    def _hybrid_subscription_url(self, tcp_sub_id: str, xhttp_sub_id: str) -> str:
        return self._subscription_url_for_route("json-hybrid", f"{tcp_sub_id}~{xhttp_sub_id}")

    def create_default_invite(self) -> tuple[str, int, int]:
        uses = 1
        days = 30
        expires_at = days_from_now(days)
        code, _ = self.store.create_invite(max_uses=uses, expires_at=expires_at)
        return code, uses, days

    @staticmethod
    def transport_label(transport: str) -> str:
        if transport == "xhttp":
            return "XHTTP"
        if transport == "tcp":
            return "Стандартный"
        if transport == "hybrid":
            return "Универсальный"
        return transport

    @staticmethod
    def _format_ts(value: int | str | None) -> str:
        try:
            timestamp = int(value or 0)
        except (TypeError, ValueError):
            timestamp = 0
        if timestamp <= 0:
            return "не указано"
        return time.strftime("%d.%m.%Y %H:%M", time.localtime(timestamp))

    @staticmethod
    def device_limit_label(device_limit: int | str | None) -> str:
        limit = int(device_limit or 0)
        if limit <= 0:
            return "без лимита"
        return f"до {limit} устройств одновременно"

    @staticmethod
    def _format_gb(value: int | str | None) -> str:
        try:
            raw = int(value or 0)
        except (TypeError, ValueError):
            raw = 0
        return f"{raw / 1024 ** 3:.2f} GB"

    @staticmethod
    def _format_xui_ts(value: int | str | None) -> str:
        try:
            timestamp = int(value or 0)
        except (TypeError, ValueError):
            timestamp = 0
        if timestamp > 10**12:
            timestamp //= 1000
        return ShopBot._format_ts(timestamp)

    @staticmethod
    def _run_local_command(args: list[str], timeout: int = 4) -> tuple[int, str]:
        try:
            completed = subprocess.run(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout,
                check=False,
            )
            return completed.returncode, (completed.stdout or "").strip()
        except FileNotFoundError:
            return 127, f"{args[0]} not found"
        except subprocess.TimeoutExpired:
            return 124, "timeout"
        except Exception as exc:
            return 1, str(exc)

    @staticmethod
    def _service_state(name: str) -> str:
        code, output = ShopBot._run_local_command(["systemctl", "is-active", name], timeout=3)
        if code == 0 and output:
            return output.splitlines()[0]
        if output:
            return output.splitlines()[0]
        return "unknown"

    @staticmethod
    def _mem_usage_mb() -> tuple[int, int]:
        total = 0
        available = 0
        try:
            for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
                if line.startswith("MemTotal:"):
                    total = int(line.split()[1]) // 1024
                elif line.startswith("MemAvailable:"):
                    available = int(line.split()[1]) // 1024
        except Exception:
            return 0, 0
        used = max(total - available, 0)
        return used, total

    @staticmethod
    def _established_tcp_count() -> int:
        total = 0
        for path in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
            try:
                lines = path.read_text(encoding="utf-8").splitlines()[1:]
            except Exception:
                continue
            total += sum(1 for line in lines if len(line.split()) > 3 and line.split()[3] == "01")
        return total

    @staticmethod
    def _dns_probe(hostname: str = "api.telegram.org") -> str:
        try:
            records = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
        except Exception as exc:
            return f"ошибка: {exc}"
        addresses = []
        for record in records:
            address = str(record[4][0])
            if address not in addresses:
                addresses.append(address)
        if not addresses:
            return "ошибка: пустой ответ"
        return "ok: " + ", ".join(addresses[:3])

    def order_device_limit(self, order: dict[str, Any]) -> int:
        meta = order.get("meta_json") or {}
        if "device_limit" in meta and meta["device_limit"] is not None:
            return int(meta["device_limit"])
        return int(self.settings.default_device_limit)

    def promo_device_limit(self, promo: dict[str, Any]) -> int:
        if "device_limit" in promo and promo["device_limit"] is not None:
            return int(promo["device_limit"])
        return int(self.settings.default_device_limit)

    @staticmethod
    def promo_type(promo: dict[str, Any]) -> str:
        return str(promo.get("promo_type") or "fixed")

    @staticmethod
    def promo_duration_label(promo: dict[str, Any] | dict[str, object]) -> str:
        months = promo.get("duration_months")
        if months:
            return f"{int(months)} мес. ({int(promo.get('duration_days') or 0)} дн.)"
        days = int(promo.get("duration_days") or 0)
        if days == 36500:
            return "пожизненно"
        return f"{days} дн."

    @staticmethod
    def fixed_promo_final_price(promo: dict[str, Any], base_price: int) -> int:
        fixed_price = promo.get("fixed_price_rub")
        if fixed_price is not None:
            return max(int(fixed_price), 0)
        return max(int(base_price) * (100 - int(promo["discount_percent"])) // 100, 0)

    @staticmethod
    def fixed_promo_price_label(promo: dict[str, Any] | dict[str, object], base_price: int | None = None) -> str:
        fixed_price = promo.get("fixed_price_rub")
        if fixed_price is not None:
            return f"{int(fixed_price)} RUB"
        discount = int(promo.get("discount_percent") or 0)
        if discount:
            return f"скидка {discount}%"
        if base_price is None:
            return "обычная цена"
        return f"обычная цена ({int(base_price)} RUB)"

    def _active_discount_promo_from_context(self, context: dict[str, Any]) -> dict[str, Any] | None:
        promo_id = context.get("discount_promo_id")
        if not promo_id:
            return None
        promo = self.store.get_valid_promo_by_id(int(promo_id))
        if promo and self.promo_type(promo) == "discount":
            return promo
        return None

    def _support_contact(self) -> str:
        raw = (self.settings.support_tg_url or "").strip()
        if not raw:
            return "@SilentConnectHelp"
        if raw.startswith("@"):
            return raw
        if raw.startswith("https://t.me/"):
            handle = raw.removeprefix("https://t.me/").strip("/")
            if handle:
                return f"@{handle}"
        return raw

    def _public_has_purchase_access(self, chat_id: int | str, context: dict[str, Any] | None = None) -> bool:
        if not self.settings.invite_required:
            return True
        payload = dict(context or {})
        if payload.get("invite_id"):
            return True
        if payload.get("referrer_id"):
            return True
        if payload.get("public_access"):
            return True
        if payload.get("discount_promo_id") and self._active_discount_promo_from_context(payload):
            return True
        session = self.store.get_session(chat_id)
        if session and session.get("scope") == "public":
            session_context = self._context_from_session(session)
            if session_context.get("invite_id"):
                return True
            if session_context.get("referrer_id"):
                return True
            if session_context.get("public_access"):
                return True
            if session_context.get("discount_promo_id") and self._active_discount_promo_from_context(session_context):
                return True
        if self.store.get_referral_attribution_for_user(chat_id):
            return True
        return self.store.get_latest_order_for_chat(chat_id) is not None

    def _send_optional_photo(
        self,
        chat_id: int | str,
        *,
        media: str,
        text: str,
        reply_markup: dict[str, Any] | None = None,
        protect_content: bool = False,
    ) -> None:
        media = self._resolve_media_reference(media)
        if media:
            try:
                self.telegram.send_photo(
                    chat_id,
                    media,
                    caption=text,
                    reply_markup=reply_markup,
                    protect_content=protect_content,
                )
                return
            except TelegramApiError:
                LOGGER.exception("Failed to send media %r, falling back to text mode", media)
        self.telegram.send_message(
            chat_id,
            text,
            reply_markup=reply_markup,
            protect_content=protect_content,
        )

    def _resolve_media_reference(self, media: str) -> str:
        media = (media or "").strip()
        if not media or media.startswith(("http://", "https://")):
            return media
        candidate = Path(media).expanduser()
        if candidate.is_file():
            return str(candidate)
        root_candidate = (self.settings.root_dir / media).resolve()
        if root_candidate.is_file():
            return str(root_candidate)
        return media

    def _render_or_edit(
        self,
        chat_id: int | str,
        text: str,
        *,
        reply_markup: dict[str, Any] | None = None,
        message_id: int | None = None,
        protect_content: bool = False,
        disable_web_page_preview: bool = True,
    ) -> dict[str, Any]:
        if message_id is not None:
            try:
                return self.telegram.edit_message_text(
                    chat_id=chat_id,
                    message_id=int(message_id),
                    text=text,
                    reply_markup=reply_markup,
                )
            except Exception as exc:
                LOGGER.info(
                    "edit_message_text failed for chat %s message %s (%s), falling back to send_message",
                    chat_id,
                    message_id,
                    exc,
                )
        return self.telegram.send_message(
            chat_id,
            text,
            reply_markup=reply_markup,
            protect_content=protect_content,
            disable_web_page_preview=disable_web_page_preview,
        )

    def _public_home_text(self, *, prefix: str | None = None) -> str:
        lines: list[str] = []
        if prefix:
            lines.extend([prefix, ""])
        lines.extend(
            [
                f"🛡️ {self.settings.brand_name}",
                "",
                "Главное меню",
                "",
                "Выберите действие с помощью кнопок ниже:",
                "",
                "• Оформить быстрый доступ к VPN",
                "• Продлить подписку или активировать пробный период",
                "• Ввести промокод или пригласить друзей",
                "• Инструкции по настройке и поддержка",
                "",
                f"📄 Пользовательское соглашение: {self.legal_terms_url()}",
            ]
        )
        return "\n".join(lines)

    def _public_home_markup(self) -> dict[str, Any]:
        return kb(
            [
                [("🚀 Подключить VPN / Выбрать тариф", "public:access", "success")],
                [("🔄 Продлить подписку", "public:renew", "success"), ("🎁 Пробный период", "public:trial", "success")],
                [("🎟 Промокод", "public:promo"), ("🤝 Рефералы", "public:referral", "success")],
                [("📖 Помощь & FAQ", "public:help", "primary"), ("💬 Поддержка", "public:support", "primary")],
            ]
        )

    def _public_access_markup(self) -> dict[str, Any]:
        price_3 = self.offers["tcp_3_30"].price_rub
        price_6 = self.offers["tcp_6_30"].price_rub
        price_9 = self.offers["tcp_9_30"].price_rub
        return kb(
            [
                [(f"Личный • 3 устройства • 30 дней • {price_3} RUB", "public:buy:tcp_3_30", "success")],
                [(f"Домашний • 6 устройств • 30 дней • {price_6} RUB", "public:buy:tcp_6_30", "success")],
                [(f"Расширенный • 9 устройств • 30 дней • {price_9} RUB", "public:buy:tcp_9_30", "success")],
                [("🎁 Бесплатная неделя", "public:trial", "primary")],
                [("Назад в меню", "public:menu")],
            ]
        )

    def _rules_menu_markup(self) -> dict[str, Any]:
        return kb(
            [
                [("Пользовательское соглашение", self.legal_terms_url(), "primary")],
                [("Правила", "public:rules:general")],
                [("Приватность", "public:rules:privacy")],
                [("Как работает выдача ссылки", "public:rules:delivery")],
                [("Если не получается импорт", "public:rules:import")],
                [("Назад в меню", "public:menu")],
            ]
        )

    def _support_markup(self) -> dict[str, Any]:
        rows: list[list[tuple[str, str]]] = []
        if self.settings.support_tg_url:
            rows.append([("Написать в поддержку", self.settings.support_tg_url)])
        rows.append([("Назад в меню", "public:menu")])
        return kb(rows)

    def _rules_back_markup(self) -> dict[str, Any]:
        return kb(
            [
                [("К разделам", "public:rules")],
                [("Поддержка", "public:support"), ("Назад в меню", "public:menu")],
            ]
        )

    @staticmethod
    def _context_from_session(session: dict[str, Any] | None) -> dict[str, Any]:
        return dict((session or {}).get("context_json") or {})

    def _set_session_state(self, chat_id: int | str, scope: str, state: str, context: dict[str, Any]) -> dict[str, Any]:
        payload = dict(context)
        self.store.set_session(chat_id, scope, state, payload)
        return payload

    def _merge_session_state(
        self,
        chat_id: int | str,
        scope: str,
        state: str,
        updates: dict[str, Any] | None = None,
        *,
        drop_keys: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        context = self._context_from_session(self.store.get_session(chat_id))
        for key in drop_keys:
            context.pop(key, None)
        if updates:
            context.update(updates)
        self.store.set_session(chat_id, scope, state, context)
        return context

    @staticmethod
    def _get_action_guard(context: dict[str, Any]) -> dict[str, Any] | None:
        guard = context.get(ACTION_GUARD_KEY)
        return guard if isinstance(guard, dict) else None

    @staticmethod
    def _matching_action_guard(context: dict[str, Any], action_key: str) -> dict[str, Any] | None:
        guard = ShopBot._get_action_guard(context)
        if guard and guard.get("action_key") == action_key:
            return guard
        return None

    @staticmethod
    def _action_guard_stale(guard: dict[str, Any]) -> bool:
        started_at = int(guard.get("started_at") or 0)
        return started_at > 0 and now_ts() - started_at >= ACTION_GUARD_TTL_SECONDS

    def _claim_action(
        self,
        chat_id: int | str,
        *,
        scope: str,
        state: str,
        action_key: str,
        context: dict[str, Any],
    ) -> tuple[bool, dict[str, Any]]:
        guard = self._matching_action_guard(context, action_key)
        if guard and guard.get("status") == "in_flight" and not self._action_guard_stale(guard):
            return False, guard
        context[ACTION_GUARD_KEY] = {
            "action_key": action_key,
            "status": "in_flight",
            "started_at": now_ts(),
        }
        self.store.set_session(chat_id, scope, state, context)
        return True, context[ACTION_GUARD_KEY]

    def _complete_action(
        self,
        chat_id: int | str,
        *,
        scope: str,
        state: str,
        context: dict[str, Any],
        action_key: str,
        result_kind: str,
        **fields: Any,
    ) -> dict[str, Any]:
        started_at = now_ts()
        existing = self._matching_action_guard(context, action_key)
        if existing and int(existing.get("started_at") or 0) > 0:
            started_at = int(existing["started_at"])
        guard = {
            "action_key": action_key,
            "status": "completed",
            "started_at": started_at,
            "completed_at": now_ts(),
            "result_kind": result_kind,
        }
        guard.update(fields)
        context[ACTION_GUARD_KEY] = guard
        self.store.set_session(chat_id, scope, state, context)
        return guard

    def _clear_action_if_matches(
        self,
        chat_id: int | str,
        action_key: str,
        *,
        statuses: tuple[str, ...] | None = ("in_flight",),
    ) -> None:
        session = self.store.get_session(chat_id)
        if not session:
            return
        context = self._context_from_session(session)
        guard = self._matching_action_guard(context, action_key)
        if not guard:
            return
        if statuses is not None and str(guard.get("status") or "") not in statuses:
            return
        context.pop(ACTION_GUARD_KEY, None)
        self.store.set_session(chat_id, session["scope"], session["state"], context)

    def _notify_action_in_flight(self, chat_id: int | str) -> None:
        self.telegram.send_message(chat_id, "Уже обрабатывается. Новый дубль не создаю.")

    def _public_waiting_payment_markup(self, order_public_id: str) -> dict[str, Any]:
        rows: list[list[Any]] = []
        payment_url = self.payment_transfer_url()
        if payment_url:
            rows.append([("Оплатить переводом", payment_url, "success")])
        rows.extend(
            [
                [("Оплачено", f"public:payment_sent:{order_public_id}", "success")],
                [("Отменить заказ", f"public:cancel_waiting:{order_public_id}", "danger")],
                [("У меня есть промокод", f"public:promo_switch:{order_public_id}")],
            ]
        )
        return kb(rows)

    @staticmethod
    def _public_promo_switch_markup(order_public_id: str) -> dict[str, Any]:
        return kb(
            [
                [("Отменить и ввести промокод", f"public:promo_switch_confirm:{order_public_id}", "danger")],
                [("Оставить текущий заказ", f"public:promo_switch_keep:{order_public_id}")],
            ]
        )

    @staticmethod
    def _admin_order_markup(order_public_id: str) -> dict[str, Any]:
        return kb(
            [
                [("Подтвердить оплату", f"admin:confirm:{order_public_id}", "success")],
                [("Отменить заказ", f"admin:cancel:{order_public_id}", "danger")],
            ]
        )

    def _waiting_payment_message(self, order: dict[str, Any], *, prefix: str | None = None) -> str:
        lines: list[str] = []
        if prefix:
            lines.append(prefix)
        lines.append(f"Заказ `{order['public_id']}` уже создан.")
        meta = order.get("meta_json") or {}
        if order.get("kind") == "renewal":
            lines.append("Тип: увеличение лимита текущей подписки." if meta.get("upgrade_only") else "Тип: продление текущей подписки.")
        if not order.get("promo_id") or meta.get("promo_type") == "discount":
            lines.append(f"Транспорт: {self.transport_label(str(order['transport']))}")
            if meta.get("upgrade_only"):
                lines.append("Срок: без продления, до текущей даты окончания.")
            else:
                lines.append(f"Срок: {int(order['duration_days'])} дн.")
        if order.get("promo_id") and meta.get("promo_type") == "discount":
            lines.append(f"Скидка по промокоду: {int(order['base_price_rub'])} -> {int(order['final_price_rub'])} RUB.")
        device_limit = self.order_device_limit(order)
        lines.append(f"Лимит: {self.device_limit_label(device_limit)}.")
        lines.append(f"Сумма к оплате: {int(order['final_price_rub'])} RUB.")
        lines.extend(
            [
                "",
                "Нажмите «Оплатить переводом» и отправьте сумму по ссылке.",
                f"Комментарий к переводу можно оставить нейтральным: `{order['public_id']}`.",
                self.payment_bank_note(),
                "",
                "После перевода нажмите «Оплачено». Я проверю поступление и бот сам пришлёт ссылку.",
            ]
        )
        return "\n".join(lines)

    def _send_public_terms(self, chat_id: int | str, context: dict[str, Any] | None = None) -> None:
        self._set_session_state(chat_id, "public", "await_terms", dict(context or {}))
        self.telegram.send_message(
            chat_id,
            (
                f"Добро пожаловать в {self.settings.brand_name}.\n\n"
                "Продолжая, Вы подтверждаете, что Вам есть 18 лет, Вы принимаете пользовательское соглашение"
                " и самостоятельно отвечаете за законность своих действий в интернете.\n\n"
                "Коротко:\n"
                "• сервис предназначен для приватного и безопасного доступа к интернету;\n"
                "• незаконное использование запрещено;\n"
                "• мы не ведём журналы посещённых сайтов и содержимого трафика;\n"
                "• ссылка доступа является персональным ключом, её нужно хранить аккуратно.\n"
            ),
            reply_markup=kb(
                [
                    [("Подтверждаю и продолжить", "public:accept_terms", "success")],
                    [("Ознакомиться", self.legal_terms_url(), "primary")],
                ]
            ),
        )

    def _send_public_promo_prompt(self, chat_id: int | str, *, prefix: str | None = None, message_id: int | None = None) -> None:
        session = self.store.get_session(chat_id)
        context = self._context_from_session(session)
        context.pop("pending_promo", None)
        context.pop("pending_promo_id", None)
        self.store.set_session(chat_id, "public", "await_promo_code", context)
        message = "Отправьте промокод одним сообщением без лишних символов."
        if prefix:
            message = f"{prefix}\n\n{message}"
        self._render_or_edit(
            chat_id,
            message,
            reply_markup=kb([[("« Назад в меню", "public:menu")]]),
            message_id=message_id,
        )

    def _send_public_family_privacy_prompt(self, chat_id: int | str, promo: dict[str, Any]) -> None:
        self.telegram.send_message(
            chat_id,
            (
                f"Промокод привязан к профилю `{promo['family_label']}`.\n"
                "Такой профиль не полностью анонимен. Согласны продолжить?"
            ),
            reply_markup=kb(
                [
                    [("Согласен", "public:family_accept")],
                    [("Хочу остаться анонимным", "public:family_decline")],
                ]
            ),
        )

    def _send_access_locked(self, chat_id: int | str, *, prefix: str | None = None) -> None:
        lines: list[str] = []
        if prefix:
            lines.extend([prefix, ""])
        lines.extend(
            [
                "Оформление доступа в этом чате пока не открыто.",
                "",
                "Покупка включается по персональной ссылке-приглашению.",
                "Если такая ссылка у Вас уже есть, откройте именно её и вернитесь в бот.",
                "Промокод можно ввести и без приглашения.",
                "",
                f"Поддержка: {self._support_contact()}",
            ]
        )
        self.telegram.send_message(
            chat_id,
            "\n".join(lines),
            reply_markup=kb(
                [
                    [("У меня есть промокод", "public:promo")],
                    [("Написать в поддержку", self.settings.support_tg_url or "https://t.me/SilentConnectHelp")],
                    [("Назад в меню", "public:menu")],
                ]
            ),
        )

    @staticmethod
    def _duration_label(duration_days: int) -> str:
        if duration_days == 30:
            return "1 месяц"
        if duration_days == 90:
            return "3 месяца"
        if duration_days == 180:
            return "6 месяцев"
        if duration_days == 360:
            return "12 месяцев"
        return f"{duration_days} дн."

    @staticmethod
    def _device_plan_title(device_limit: int) -> str:
        if device_limit <= 3:
            return "Личный"
        if device_limit <= 6:
            return "Домашний"
        return "Расширенный"

    def _purchase_offer_code(self, context: dict[str, Any]) -> str:
        device_limit = int(context.get("buy_device_limit") or 3)
        duration_days = int(context.get("buy_duration_days") or 30)
        mode = str(context.get("buy_mode") or "tcp")
        return f"{mode}_{device_limit}_{duration_days}"

    def show_public_access_menu(self, chat_id: int | str, *, message_id: int | None = None) -> None:
        self._expire_stale_waiting_orders(chat_id, notify_user=True)
        context = self._merge_session_state(
            chat_id,
            "public",
            "buy_devices",
            drop_keys=("pending_promo", "pending_promo_id", "buy_device_limit", "buy_duration_days", "buy_mode"),
        )
        if not self._public_has_purchase_access(chat_id, context):
            self._send_access_locked(chat_id)
            return
        active_order = self._fresh_active_order_for_chat(chat_id, notify_user=True)
        if active_order:
            self._send_existing_public_order(chat_id, active_order, prefix="Возвращаю текущий заказ.")
            return
        discount_promo = self._active_discount_promo_from_context(context)
        lines = [
            "🚀 Оформление доступа",
            "",
            "Сначала выберите, сколько устройств будет подключаться одновременно.",
            "Технические настройки уже подготовлены, разбираться в них не нужно.",
        ]
        if discount_promo:
            lines.extend(["", f"Активен промокод: скидка {int(discount_promo['discount_percent'])}%."])
        self._render_or_edit(
            chat_id,
            "\n".join(lines),
            reply_markup=kb(
                [
                    [("Личный · до 3 устройств", "public:buy_devices:3", "success")],
                    [("Домашний · до 6 устройств", "public:buy_devices:6")],
                    [("Расширенный · до 9 устройств", "public:buy_devices:9")],
                    [("« Назад в меню", "public:menu")],
                ]
            ),
            message_id=message_id,
        )

    def show_public_buy_duration(self, chat_id: int | str, device_limit: int, *, message_id: int | None = None) -> None:
        session = self.store.get_session(chat_id) or {"scope": "public", "state": "buy_devices", "context_json": {}}
        context = self._context_from_session(session)
        context["buy_device_limit"] = int(device_limit)
        self.store.set_session(chat_id, "public", "buy_duration", context)
        self._render_or_edit(
            chat_id,
            "\n".join(
                [
                    f"{self._device_plan_title(device_limit)}: до {device_limit} устройств.",
                    "",
                    "Теперь выберите срок доступа.",
                ]
            ),
            reply_markup=kb(
                [
                    [("1 месяц", "public:buy_duration:30"), ("3 месяца", "public:buy_duration:90")],
                    [("6 месяцев", "public:buy_duration:180"), ("12 месяцев", "public:buy_duration:360")],
                    [("« Назад", "public:access")],
                ]
            ),
            message_id=message_id,
        )

    def show_public_buy_confirm(self, chat_id: int | str, mode: str = "tcp", *, message_id: int | None = None) -> None:
        session = self.store.get_session(chat_id) or {"scope": "public", "state": "buy_duration", "context_json": {}}
        context = self._context_from_session(session)
        if not context.get("buy_device_limit") or not context.get("buy_duration_days"):
            self.show_public_access_menu(chat_id, message_id=message_id)
            return
        context["buy_mode"] = "tcp"
        self.store.set_session(chat_id, "public", "buy_confirm", context)
        offer = self.offers.get(self._purchase_offer_code(context))
        if not offer:
            self.telegram.send_message(chat_id, "Не удалось собрать тариф. Попробуйте выбрать заново.")
            self.show_public_access_menu(chat_id, message_id=message_id)
            return
        discount_promo = self._active_discount_promo_from_context(context)
        discount = int(discount_promo["discount_percent"]) if discount_promo else 0
        final_price = max(offer.price_rub * (100 - discount) // 100, 0)
        price_line = f"{final_price} RUB"
        if discount_promo:
            price_line = f"{offer.price_rub} -> {final_price} RUB по промокоду"
        self._render_or_edit(
            chat_id,
            "\n".join(
                [
                    "Проверьте заказ",
                    "",
                    f"Тариф: {self._device_plan_title(offer.device_limit)}",
                    f"Лимит: {self.device_limit_label(offer.device_limit)}",
                    f"Срок: {self._duration_label(offer.duration_days)}",
                    f"К оплате: {price_line}",
                ]
            ),
            reply_markup=kb(
                [
                    [("Перейти к оплате", "public:buy_confirm", "success")],
                    [("Выбрать другой срок", "public:buy_back:duration")],
                    [("« Назад в меню", "public:menu")],
                ]
            ),
            message_id=message_id,
        )


    def _latest_renewable_profile_for_user(self, user: dict[str, Any], chat_id: int | str) -> dict[str, Any] | None:
        user_id = user.get("id") or chat_id
        profile = self.store.get_latest_renewable_profile_for_user(
            user_id,
            excluded_notes=(TEST_PROFILE_NOTES, ADMIN_PROFILE_NOTES, PUBLIC_TRIAL_PROFILE_NOTES),
        )
        if not profile:
            return None
        if not self.provisioner.xui_db.find_client_by_email(str(profile["xui_email"])):
            self.store.mark_profile_deleted(str(profile["public_id"]))
            return None
        return profile

    def _profile_device_limit(self, profile: dict[str, Any]) -> int:
        found = self.provisioner.xui_db.find_client_by_email(str(profile["xui_email"]))
        if not found:
            return int(self.settings.default_device_limit)
        try:
            limit = int((found.get("client") or {}).get("limitIp") or 0)
        except (TypeError, ValueError):
            limit = 0
        return limit if limit > 0 else int(self.settings.default_device_limit)

    @staticmethod
    def _remaining_days_until(expires_at: int | str | None) -> int:
        try:
            seconds = int(expires_at or 0) - now_ts()
        except (TypeError, ValueError):
            seconds = 0
        return max((seconds + 86399) // 86400, 0)

    def _subscription_url_from_text(self, text: str) -> str:
        raw = (text or "").strip()
        for token in raw.replace("\n", " ").split():
            candidate = token.strip(" \t\r\n<>[]()\"'")
            if not candidate.startswith(("http://", "https://")):
                continue
            parsed = urlsplit(candidate)
            query_url = (parse_qs(parsed.query).get("url") or [""])[0].strip()
            return query_url or candidate
        if raw.startswith(("http://", "https://")):
            parsed = urlsplit(raw)
            query_url = (parse_qs(parsed.query).get("url") or [""])[0].strip()
            return query_url or raw
        return ""

    def _profile_from_subscription_url(self, subscription_url: str) -> tuple[dict[str, Any] | None, str | None, str]:
        subscription_id = self._subscription_id_from_url(subscription_url)
        if not subscription_id:
            return None, None, "Не нашёл ID подписки в ссылке."
        first_sub_id = subscription_id.split("~", 1)[0].strip()
        found = self.provisioner.xui_db.find_client_by_sub_id(first_sub_id)
        if not found:
            return None, None, "Этой подписки нет на сервере. Проверьте ссылку или напишите в поддержку."
        email = str((found.get("client") or {}).get("email") or "")
        profile = self.store.get_profile_by_xui_email(email)
        if not profile:
            try:
                profile = self.store.ensure_profile_for_xui_client(
                    xui_inbound_id=found.get("inbound_id") or 2,
                    client=found.get("client") or {},
                    transport=str(found.get("protocol") or "tcp"),
                )
            except Exception:
                return None, None, "Подписка есть на сервере, но бот не нашёл её в магазине. Напишите в поддержку, я привяжу вручную."
        notes = str(profile.get("notes") or "").lower()
        if profile.get("notes") in {TEST_PROFILE_NOTES, ADMIN_PROFILE_NOTES, PUBLIC_TRIAL_PROFILE_NOTES} or "trial" in notes or "test" in notes or "auto_delete" in notes:
            return None, None, "Пробную подписку (7 дней) или тестовый профиль нельзя продлить через обычную оплату."
        order = self.store.get_order_for_profile(str(profile["public_id"]))
        return profile, str(order["public_id"]) if order else None, ""

    def _renewal_target(self, profile_public_id: str) -> dict[str, Any] | None:
        profile = self.store.get_profile(profile_public_id)
        if not profile or profile.get("status") == "deleted":
            return None
        notes = str(profile.get("notes") or "").lower()
        if profile.get("notes") in {TEST_PROFILE_NOTES, ADMIN_PROFILE_NOTES, PUBLIC_TRIAL_PROFILE_NOTES} or "trial" in notes or "test" in notes or "auto_delete" in notes:
            return None
        if not self.provisioner.xui_db.find_client_by_email(str(profile["xui_email"])):
            self.store.mark_profile_deleted(profile_public_id)
            return None

        owner = self.store.get_profile_owner(profile_public_id) or {}
        source_order_public_id = str(owner.get("source_order_public_id") or "")
        if not source_order_public_id:
            order = self.store.get_order_for_profile(profile_public_id)
            source_order_public_id = str((order or {}).get("public_id") or "")
        source_order = self.store.get_order(source_order_public_id) if source_order_public_id else None
        source_meta = dict((source_order or {}).get("meta_json") or {})

        target: dict[str, Any] = {
            "transport": str(profile["transport"]),
            "profile": profile,
            "renewal_profile_public_id": profile_public_id,
            "renewal_xhttp_profile_public_id": "",
            "source_order_public_id": source_order_public_id,
            "expires_at": int(profile.get("expires_at") or 0),
            "device_limit": self._profile_device_limit(profile),
            "hybrid": False,
        }

        if source_meta.get("hybrid"):
            tcp_profile_public_id = str(source_meta.get("tcp_profile_public_id") or source_meta.get("renewal_profile_public_id") or "")
            xhttp_profile_public_id = str(source_meta.get("xhttp_profile_public_id") or source_meta.get("renewal_xhttp_profile_public_id") or "")
            tcp_profile = self.store.get_profile(tcp_profile_public_id) if tcp_profile_public_id else None
            xhttp_profile = self.store.get_profile(xhttp_profile_public_id) if xhttp_profile_public_id else None
            if (
                not tcp_profile
                or not xhttp_profile
                or tcp_profile.get("status") == "deleted"
                or xhttp_profile.get("status") == "deleted"
                or not self.provisioner.xui_db.find_client_by_email(str(tcp_profile["xui_email"]))
                or not self.provisioner.xui_db.find_client_by_email(str(xhttp_profile["xui_email"]))
            ):
                return None
            target.update(
                {
                    "transport": "hybrid",
                    "profile": tcp_profile,
                    "renewal_profile_public_id": tcp_profile_public_id,
                    "renewal_xhttp_profile_public_id": xhttp_profile_public_id,
                    "expires_at": min(int(tcp_profile.get("expires_at") or 0), int(xhttp_profile.get("expires_at") or 0)),
                    "device_limit": self._profile_device_limit(tcp_profile),
                    "hybrid": True,
                }
            )
        return target

    def _send_renewal_target_missing(self, chat_id: int | str, *, message_id: int | None = None) -> None:
        self._render_or_edit(
            chat_id,
            "Подписка не найдена или уже недоступна на сервере. Можно вставить другую ссылку или написать в поддержку.",
            reply_markup=kb(
                [
                    [("Вставить другую ссылку", "public:renew_other", "primary")],
                    [("Поддержка", "public:support")],
                    [("Назад в меню", "public:menu")],
                ]
            ),
            message_id=message_id,
        )

    def _send_renewal_overview(
        self,
        chat_id: int | str,
        profile: dict[str, Any],
        *,
        prefix: str | None = None,
        message_id: int | None = None,
    ) -> None:
        target = self._renewal_target(str(profile["public_id"]))
        if not target:
            self._send_renewal_target_missing(chat_id, message_id=message_id)
            return
        profile = target["profile"]
        context = self._context_from_session(self.store.get_session(chat_id))
        context["renewal_profile_public_id"] = str(profile["public_id"])
        self.store.set_session(chat_id, "public", "renewal_menu", context)

        current_limit = int(target["device_limit"])
        active = int(target["expires_at"]) > now_ts()
        lines = []
        if prefix:
            lines.extend([prefix, ""])
        lines.extend(
            [
                "Найдена подписка для продления.",
                "",
                f"Профиль: {profile.get('xui_email')}",
                f"Режим: {self.transport_label(str(target['transport']))}",
                f"Лимит: {self.device_limit_label(current_limit)}",
                f"Текущий срок до: {self._format_ts(target.get('expires_at'))}",
                "",
                "Можно продлить на новый срок, изменить лимит устройств или вставить другую ссылку.",
            ]
        )
        discount_promo = self._active_discount_promo_from_context(context)
        if discount_promo:
            lines.append(f"Активен промокод: скидка {int(discount_promo['discount_percent'])}%.")
        rows: list[list[Any]] = [
            [("Продлить / изменить тариф", f"public:renew_devices:{profile['public_id']}", "success")],
        ]
        if active and current_limit < 9:
            rows.append([("Увеличить лимит сейчас", f"public:upgrade_devices:{profile['public_id']}", "primary")])
        rows.extend(
            [
                [("Ввести промокод на скидку", "public:renew_promo")],
                [("Вставить другую ссылку", "public:renew_other")],
                [("Назад в меню", "public:menu")],
            ]
        )
        self._render_or_edit(chat_id, "\n".join(lines), reply_markup=kb(rows), message_id=message_id)

    def show_public_renew_devices(self, chat_id: int | str, profile_public_id: str, *, message_id: int | None = None) -> None:
        target = self._renewal_target(profile_public_id)
        if not target:
            self._send_renewal_target_missing(chat_id, message_id=message_id)
            return
        current_limit = int(target["device_limit"])
        rows = []
        for limit in (3, 6, 9):
            suffix = " · текущий" if limit == current_limit else ""
            rows.append([(f"{self._device_plan_title(limit)} · до {limit} устройств{suffix}", f"public:renew_duration:{target['profile']['public_id']}:{limit}")])
        rows.append([("Назад", "public:renew")])
        self._render_or_edit(
            chat_id,
            "Выберите лимит устройств для следующего оплаченного периода.",
            reply_markup=kb(rows),
            message_id=message_id,
        )

    def show_public_renew_duration(self, chat_id: int | str, profile_public_id: str, device_limit: int, *, message_id: int | None = None) -> None:
        target = self._renewal_target(profile_public_id)
        if not target:
            self._send_renewal_target_missing(chat_id, message_id=message_id)
            return
        transport = str(target["transport"])
        discount_promo = self._active_discount_promo_from_context(self._context_from_session(self.store.get_session(chat_id)))
        discount = int(discount_promo["discount_percent"]) if discount_promo else 0
        rows = []
        for duration_days in (30, 90, 180, 360):
            price = self.base_price_for_duration(transport, duration_days, device_limit=device_limit)
            final_price = max(price * (100 - discount) // 100, 0)
            rows.append([(f"{self._duration_label(duration_days)} · {final_price} RUB", f"public:renew_preview:{target['profile']['public_id']}:{device_limit}:{duration_days}")])
        rows.append([("Назад", f"public:renew_devices:{target['profile']['public_id']}")])
        self._render_or_edit(
            chat_id,
            f"Лимит: {self.device_limit_label(device_limit)}. Теперь выберите срок продления.",
            reply_markup=kb(rows),
            message_id=message_id,
        )

    def show_public_renew_confirm(
        self,
        chat_id: int | str,
        profile_public_id: str,
        *,
        duration_days: int,
        device_limit: int,
        message_id: int | None = None,
    ) -> None:
        target = self._renewal_target(profile_public_id)
        if not target:
            self._send_renewal_target_missing(chat_id, message_id=message_id)
            return
        discount_promo = self._active_discount_promo_from_context(self._context_from_session(self.store.get_session(chat_id)))
        price = self.base_price_for_duration(str(target["transport"]), duration_days, device_limit=device_limit)
        final_price = max(price * (100 - int(discount_promo["discount_percent"])) // 100, 0) if discount_promo else price
        price_line = f"{final_price} RUB" if not discount_promo else f"{price} -> {final_price} RUB по промокоду"
        self._render_or_edit(
            chat_id,
            "\n".join(
                [
                    "Проверьте продление",
                    "",
                    f"Профиль: {target['profile'].get('xui_email')}",
                    f"Режим: {self.transport_label(str(target['transport']))}",
                    f"Текущий срок до: {self._format_ts(target.get('expires_at'))}",
                    f"Новый оплаченный период: {self._duration_label(duration_days)}",
                    f"Лимит после оплаты: {self.device_limit_label(device_limit)}",
                    f"К оплате: {price_line}",
                ]
            ),
            reply_markup=kb(
                [
                    [("Перейти к оплате", f"public:renew_confirm:{target['profile']['public_id']}:{duration_days}:{device_limit}", "success")],
                    [("Изменить срок", f"public:renew_duration:{target['profile']['public_id']}:{device_limit}")],
                    [("Назад", f"public:renew_devices:{target['profile']['public_id']}")],
                ]
            ),
            message_id=message_id,
        )

    def show_public_upgrade_devices(self, chat_id: int | str, profile_public_id: str, *, message_id: int | None = None) -> None:
        target = self._renewal_target(profile_public_id)
        if not target:
            self._send_renewal_target_missing(chat_id, message_id=message_id)
            return
        current_limit = int(target["device_limit"])
        remaining_days = self._remaining_days_until(target.get("expires_at"))
        if remaining_days <= 0:
            self._render_or_edit(chat_id, "Текущий срок уже закончился. Выберите обычное продление.", message_id=message_id)
            self.show_public_renew_devices(chat_id, str(target["profile"]["public_id"]))
            return
        rows = []
        for limit in (3, 6, 9):
            if limit <= current_limit:
                continue
            price = self._upgrade_price(str(target["transport"]), remaining_days, current_limit, limit)
            rows.append([(f"До {limit} устройств · доплата {price} RUB", f"public:upgrade_preview:{target['profile']['public_id']}:{limit}")])
        if not rows:
            rows.append([("Продлить на новый срок", f"public:renew_devices:{target['profile']['public_id']}", "success")])
        rows.append([("Назад", "public:renew")])
        self._render_or_edit(
            chat_id,
            f"До конца текущего срока осталось примерно {remaining_days} дн. Выберите новый лимит.",
            reply_markup=kb(rows),
            message_id=message_id,
        )

    def _upgrade_price(self, transport: str, remaining_days: int, current_limit: int, target_limit: int) -> int:
        current_price = self.base_price_for_duration(transport, remaining_days, device_limit=current_limit)
        target_price = self.base_price_for_duration(transport, remaining_days, device_limit=target_limit)
        return max(target_price - current_price, 0)

    def show_public_upgrade_confirm(self, chat_id: int | str, profile_public_id: str, device_limit: int, *, message_id: int | None = None) -> None:
        target = self._renewal_target(profile_public_id)
        if not target:
            self._send_renewal_target_missing(chat_id, message_id=message_id)
            return
        current_limit = int(target["device_limit"])
        remaining_days = self._remaining_days_until(target.get("expires_at"))
        if remaining_days <= 0 or device_limit <= current_limit:
            self.show_public_upgrade_devices(chat_id, str(target["profile"]["public_id"]), message_id=message_id)
            return
        base_price = self._upgrade_price(str(target["transport"]), remaining_days, current_limit, device_limit)
        discount_promo = self._active_discount_promo_from_context(self._context_from_session(self.store.get_session(chat_id)))
        final_price = max(base_price * (100 - int(discount_promo["discount_percent"])) // 100, 0) if discount_promo else base_price
        price_line = f"{final_price} RUB" if not discount_promo else f"{base_price} -> {final_price} RUB по промокоду"
        self._render_or_edit(
            chat_id,
            "\n".join(
                [
                    "Проверьте изменение лимита",
                    "",
                    f"Профиль: {target['profile'].get('xui_email')}",
                    f"Текущий лимит: {self.device_limit_label(current_limit)}",
                    f"Новый лимит: {self.device_limit_label(device_limit)}",
                    f"Срок не меняется: до {self._format_ts(target.get('expires_at'))}",
                    f"Доплата за оставшиеся {remaining_days} дн.: {price_line}",
                ]
            ),
            reply_markup=kb(
                [
                    [("Перейти к оплате", f"public:upgrade_confirm:{target['profile']['public_id']}:{device_limit}", "success")],
                    [("Назад", f"public:upgrade_devices:{target['profile']['public_id']}")],
                ]
            ),
            message_id=message_id,
        )

    def show_public_renewal(self, chat_id: int | str, user: dict[str, Any], *, message_id: int | None = None) -> None:
        self._expire_stale_waiting_orders(chat_id, notify_user=True)
        active_order = self._fresh_active_order_for_chat(chat_id, notify_user=True)
        if active_order:
            self._send_existing_public_order(chat_id, active_order, prefix="Возвращаю текущий заказ.")
            return

        profile = self._latest_renewable_profile_for_user(user, chat_id)
        if not profile:
            context = self._context_from_session(self.store.get_session(chat_id))
            order_public_id = str(context.get("order_public_id") or "")
            if order_public_id:
                candidate = self.store.get_profile_for_order(order_public_id)
                if candidate and candidate.get("status") != "deleted" and candidate.get("notes") not in {
                    TEST_PROFILE_NOTES,
                    ADMIN_PROFILE_NOTES,
                    PUBLIC_TRIAL_PROFILE_NOTES,
                }:
                    if self.provisioner.xui_db.find_client_by_email(str(candidate["xui_email"])):
                        self.store.link_profile_owner(
                            profile_public_id=str(candidate["public_id"]),
                            user_id=user.get("id") or chat_id,
                            chat_id=chat_id,
                            source_order_public_id=order_public_id,
                        )
                        profile = candidate
                    else:
                        self.store.mark_profile_deleted(str(candidate["public_id"]))
        if not profile:
            self._render_or_edit(
                chat_id,
                (
                    "Я не нашёл живую подписку, которую можно продлить в этом чате.\n\n"
                    "Если профиль уже был удалён, нужно оформить новый доступ. Если подписка есть, но бот её не видит, напишите в поддержку."
                ),
                reply_markup=kb(
                    [
                        [("Вставить другую ссылку", "public:renew_other", "primary")],
                        [("Купить доступ", "public:access", "success")],
                        [("Поддержка", "public:support", "primary")],
                        [("Назад в меню", "public:menu")],
                    ]
                ),
                message_id=message_id,
            )
            return

        self._send_renewal_overview(chat_id, profile, message_id=message_id)

    def prompt_public_renewal_link(self, chat_id: int | str, *, message_id: int | None = None) -> None:
        context = self._context_from_session(self.store.get_session(chat_id))
        context["promo_return"] = "renewal"
        self.store.set_session(chat_id, "public", "await_renewal_subscription_url", context)
        self._render_or_edit(
            chat_id,
            f"Отправьте подписочную ссылку одним сообщением. Подойдёт ссылка вида {self.settings.subscription_base_url}/...",
            reply_markup=kb([[("« Назад", "public:renew")], [("💬 Поддержка", "public:support")]]),
            message_id=message_id,
        )

    def handle_renewal_subscription_url_input(self, chat_id: int, text: str, session: dict[str, Any], user: dict[str, Any]) -> None:
        subscription_url = self._subscription_url_from_text(text)
        if not subscription_url:
            self.telegram.send_message(chat_id, "Не увидел ссылку. Отправьте именно URL подписки или страницы подключения.")
            return
        profile, source_order_public_id, error = self._profile_from_subscription_url(subscription_url)
        if not profile:
            self.telegram.send_message(
                chat_id,
                error or "Не получилось найти подписку по этой ссылке.",
                reply_markup=kb([[("Попробовать другую ссылку", "public:renew_other")], [("Поддержка", "public:support", "primary")]]),
            )
            return
        found = self.provisioner.xui_db.find_client_by_email(str(profile["xui_email"]))
        if not found:
            self.store.mark_profile_deleted(str(profile["public_id"]))
            self.telegram.send_message(chat_id, "Профиль по этой ссылке уже отсутствует на сервере. Напишите в поддержку.")
            return
        self.store.link_profile_owner(
            profile_public_id=str(profile["public_id"]),
            user_id=user.get("id") or chat_id,
            chat_id=chat_id,
            source_order_public_id=source_order_public_id,
        )
        context = self._context_from_session(session)
        context["renewal_profile_public_id"] = str(profile["public_id"])
        if source_order_public_id:
            context["order_public_id"] = source_order_public_id
        self.store.set_session(chat_id, "public", "renewal_menu", context)
        self._send_renewal_overview(chat_id, profile, prefix="Ссылка принята и привязана к этому Telegram.")

    def show_public_help(self, chat_id: int | str, *, message_id: int | None = None) -> None:
        self._merge_session_state(chat_id, "public", "menu", drop_keys=("pending_promo", "pending_promo_id"))
        text = "\n".join(
            [
                "📖 Как подключить VPN",
                "",
                "1. Выберите подходящий тариф или введите промокод.",
                "2. Получите персональную ссылку в этом чате.",
                "3. Нажмите «Подключить».",
                "4. На странице выберите устройство и приложение.",
                "5. Добавьте подписку и включите подключение.",
                "6. Если не получилось, откройте FAQ или поддержку.",
                "",
                f"📄 Пользовательское соглашение: {self.legal_terms_url()}",
            ]
        )
        markup = kb(
            [
                [("🚀 Выбрать тариф", "public:access", "success")],
                [("❓ FAQ", "public:faq", "primary"), ("💬 Поддержка", "public:support", "primary")],
                [("📜 Правила сервиса", "public:rules")],
                [("« Назад в меню", "public:menu")],
            ]
        )
        if self.settings.quickstart_media and message_id is None:
            self._send_optional_photo(
                chat_id,
                media=self.settings.quickstart_media,
                text=text,
                reply_markup=markup,
            )
            return
        self._render_or_edit(
            chat_id,
            text,
            reply_markup=markup,
            message_id=message_id,
        )

    def show_public_faq(self, chat_id: int | str, *, message_id: int | None = None) -> None:
        self._merge_session_state(chat_id, "public", "menu", drop_keys=("pending_promo", "pending_promo_id"))
        self._render_or_edit(
            chat_id,
            "\n".join(
                [
                    "❓ Часто задаваемые вопросы (FAQ)",
                    "",
                    "• Действительно ли трафик безлимитный?",
                    "Да, мы не ограничиваем гигабайты и скорость при использовании сервиса. Действует стандартная политика добросовестного использования (Fair Use Policy) — доступ предназначен для комфортного личного и семейного использования (браузинг, просмотр 4K-видео, игры, стриминг, скачивание файлов). Не допускается использование для коммерческого парсинга, спам-рассылок, непрерывного скачивания терабайтов через торрент-фермы и иных сценариев, создающих паразитарную перегрузку сетевой инфраструктуры.",
                    "",
                    "• Как получить доступ?",
                    "Покупка открывается прямо из главного меню. Промокод также можно активировать по кнопке «🎟 Промокод».",
                    "",
                    "• На каких устройствах работает VPN?",
                    "На любых устройствах: iPhone, iPad, Android, компьютерах Windows, macOS и Linux.",
                    "",
                    "• Как продлить доступ?",
                    "Продление происходит по вашей постоянной ссылке в один клик без необходимости перенастройки устройств.",
                    "",
                    "• Что делать, если ссылка не импортируется?",
                    "Откройте раздел «Как подключить» или напишите в службу поддержки — поможем разобраться.",
                    "",
                    f"📄 Пользовательское соглашение: {self.legal_terms_url()}",
                ]
            ),
            reply_markup=kb(
                [
                    [("📖 Как подключить", "public:help"), ("📜 Правила", "public:rules")],
                    [("💬 Поддержка", "public:support", "primary")],
                    [("« Назад в меню", "public:menu")],
                ]
            ),
            message_id=message_id,
        )

    def show_public_rules_menu(self, chat_id: int | str, *, message_id: int | None = None) -> None:
        self._merge_session_state(chat_id, "public", "menu", drop_keys=("pending_promo", "pending_promo_id"))
        self._render_or_edit(
            chat_id,
            "Правила, приватность и помощь с выдачей ссылки вынесены в отдельные разделы. Выберите нужный пункт:",
            reply_markup=self._rules_menu_markup(),
            message_id=message_id,
        )

    def show_public_rules_section(self, chat_id: int | str, section: str, *, message_id: int | None = None) -> None:
        texts = {
            "general": "\n".join(
                [
                    "Правила",
                    "",
                    "• Ссылку важно хранить аккуратно.",
                    "• Восстановление после потери ссылки не гарантируется.",
                    "• Продление возможно по уже выданной ссылке, пока профиль активен.",
                    "• Неоплаченные заказы не висят вечно и автоматически закрываются со временем.",
                ]
            ),
            "privacy": "\n".join(
                [
                    "Приватность",
                    "",
                    "• Обычные профили оформляются как анонимные.",
                    "• Семейные промокоды могут быть частично подписаны, и это отдельно показывается до подтверждения.",
                    "• В публичной витрине нет лишней технической перегрузки: важные детали открываются только по запросу.",
                    "• Для дальнейшего взаимодействия сама ссылка остаётся главным ключом доступа, поэтому её важно не терять.",
                ]
            ),
            "delivery": "\n".join(
                [
                    "Как работает выдача ссылки",
                    "",
                    "1. Пользователь выбирает доступ или вводит промокод.",
                    "2. После подтверждения оплаты или автопровижининга бот выдаёт персональную ссылку.",
                    "3. Именно эта ссылка используется для импорта и последующего продления, пока профиль остаётся активным.",
                ]
            ),
            "import": "\n".join(
                [
                    "Если не получается импорт",
                    "",
                    "1. Убедитесь, что открываете именно ту ссылку, которую прислал бот.",
                    "2. Попробуйте импорт из URL или из буфера обмена — это зависит от клиента.",
                    "3. Если приложение ругается на формат или безопасность схемы, напишите в поддержку и укажите устройство и приложение.",
                    "4. Не создавайте новые заказы подряд, пока не проверили текущую ссылку.",
                ]
            ),
        }
        self._merge_session_state(chat_id, "public", "menu", drop_keys=("pending_promo", "pending_promo_id"))
        self._render_or_edit(
            chat_id,
            texts.get(section, texts["general"]),
            reply_markup=self._rules_back_markup(),
            message_id=message_id,
        )

    def show_public_support(self, chat_id: int | str, *, message_id: int | None = None) -> None:
        self._merge_session_state(chat_id, "public", "menu", drop_keys=("pending_promo", "pending_promo_id"))
        self._render_or_edit(
            chat_id,
            "\n".join(
                [
                    "Поддержка",
                    "",
                    "Если нужен доступ, помощь с импортом или повторная проверка текущего заказа, напишите в поддержку.",
                    f"Контакт: {self._support_contact()}",
                    "",
                    "Если вопрос связан с уже созданным заказом, приложите номер заказа или скриншот экрана.",
                ]
            ),
            reply_markup=self._support_markup(),
            message_id=message_id,
        )

    @staticmethod
    def _display_user(row: dict[str, Any]) -> str:
        username = str(row.get("username") or "").strip()
        if username:
            return f"@{username}"
        first_name = str(row.get("first_name") or "").strip()
        last_name = str(row.get("last_name") or "").strip()
        name = " ".join(part for part in (first_name, last_name) if part)
        return name or f"id {row.get('user_id') or row.get('chat_id')}"

    def show_public_referral(self, chat_id: int | str, user: dict[str, Any], *, message_id: int | None = None) -> None:
        self._merge_session_state(chat_id, "public", "menu", drop_keys=("pending_promo", "pending_promo_id"))
        user_id = str(user.get("id") or chat_id)
        referrer = self.store.get_referrer_by_user(user_id)
        if referrer:
            balance = self.store.get_referral_balance(int(referrer["id"])) or {}
            self._render_or_edit(
                chat_id,
                "\n".join(
                    [
                        "Реферальная программа",
                        "",
                        "Ваша ссылка:",
                        self.referral_link(str(referrer["code"])),
                        "",
                        f"Комиссия: {int(referrer['commission_percent'])}%",
                        f"Текущий баланс: {int(balance.get('balance_rub') or 0)} RUB",
                        f"Минимальная выплата: {REFERRAL_PAYOUT_MIN_RUB} RUB",
                        "",
                        "Начисления идут только с подтверждённых платных покупок приглашённых пользователей.",
                    ]
                ),
                reply_markup=kb(
                    [
                        [{"text": "Скопировать ссылку", "copy_text": self.referral_link(str(referrer["code"])), "style": "primary"}],
                        [("Назад в меню", "public:menu")],
                    ]
                ),
                message_id=message_id,
            )
            return

        self._render_or_edit(
            chat_id,
            "\n".join(
                [
                    "Реферальная программа",
                    "",
                    f"Вы получаете {REFERRAL_COMMISSION_PERCENT}% с каждой подтверждённой платной покупки приглашённого пользователя.",
                    f"Выплаты вручную от {REFERRAL_PAYOUT_MIN_RUB} RUB, остаток переносится дальше.",
                    "",
                    "После подключения бот выдаст вашу личную ссылку.",
                ]
            ),
            reply_markup=kb(
                [
                    [("Хочу участвовать", "public:referral_join", "success")],
                    [("Назад в меню", "public:menu")],
                ]
            ),
            message_id=message_id,
        )

    def join_public_referral(self, chat_id: int | str, user: dict[str, Any], *, message_id: int | None = None) -> None:
        user_id = str(user.get("id") or chat_id)
        referrer = self.store.ensure_referrer(
            user_id=user_id,
            chat_id=chat_id,
            commission_percent=REFERRAL_COMMISSION_PERCENT,
        )
        link = self.referral_link(str(referrer["code"]))
        self._render_or_edit(
            chat_id,
            "\n".join(
                [
                    "Вы участвуете в реферальной программе.",
                    "",
                    "Ваша ссылка:",
                    link,
                    "",
                    f"Комиссия: {int(referrer['commission_percent'])}%",
                    f"Выплата: от {REFERRAL_PAYOUT_MIN_RUB} RUB вручную.",
                ]
            ),
            reply_markup=kb(
                [
                    [{"text": "Скопировать ссылку", "copy_text": link, "style": "primary"}],
                    [("Назад в меню", "public:menu")],
                ]
            ),
            message_id=message_id,
        )

    def create_public_trial(self, chat_id: int | str, user: dict[str, Any], *, message_id: int | None = None) -> None:
        user_id = str(user.get("id") or chat_id)
        redemption = self.store.get_trial_redemption(user_id)
        if redemption and redemption.get("status") == "delivered":
            self._render_or_edit(
                chat_id,
                "Бесплатная неделя уже была использована на этом Telegram-аккаунте.",
                reply_markup=kb(
                    [
                        [("Купить доступ", "public:access", "success")],
                        [("Назад в меню", "public:menu")],
                    ]
                ),
                message_id=message_id,
            )
            return

        claimed, redemption = self.store.claim_trial_redemption(
            user_id=user_id,
            chat_id=chat_id,
            transport=TRIAL_TRANSPORT,
        )
        if not claimed:
            self.telegram.send_message(
                chat_id,
                "Бесплатная неделя уже создаётся. Дождитесь сообщения со ссылкой.",
            )
            return

        try:
            result = self.provisioner.create_public_trial_profile(user, TRIAL_TRANSPORT)
            self.store.mark_trial_delivered(
                user_id=user_id,
                profile_public_id=result["profile"]["public_id"],
            )
            self.store.record_admin_action(
                action_type="create_public_trial",
                target_type="profile",
                target_public_id=result["profile"]["public_id"],
                actor=f"tg:{user_id}",
                meta={"transport": TRIAL_TRANSPORT, "xui_email": result["xui_email"]},
            )
            self._send_public_subscription(
                chat_id,
                result["subscription_url"],
                prefix="Бесплатная неделя активирована. Ваша ссылка:",
            )
        except Exception as exc:
            LOGGER.exception("Failed to create public trial for user %s", user_id)
            self.store.mark_trial_failed(user_id=user_id, error=str(exc))
            self.telegram.send_message(
                chat_id,
                "Не получилось создать пробный доступ. Попробуйте ещё раз через пару минут или напишите в поддержку.",
                reply_markup=kb(
                    [
                        [("Поддержка", "public:support", "primary")],
                        [("Назад в меню", "public:menu")],
                    ]
                ),
            )

    def _format_referral_admin_report(self, balances: list[dict[str, Any]]) -> str:
        total = sum(int(item.get("balance_rub") or 0) for item in balances)
        payable = sum(
            int(item.get("balance_rub") or 0)
            for item in balances
            if int(item.get("balance_rub") or 0) >= REFERRAL_PAYOUT_MIN_RUB
        )
        lines = [
            "Реферальная программа",
            "",
            f"Общий долг: {total} RUB",
            f"К выплате сейчас: {payable} RUB",
            f"Минимальная выплата: {REFERRAL_PAYOUT_MIN_RUB} RUB",
            "",
        ]
        if not balances:
            lines.append("Участников пока нет.")
            return "\n".join(lines)

        for item in balances[:25]:
            balance = int(item.get("balance_rub") or 0)
            lines.append(
                f"{self._display_user(item)} — {balance} RUB, "
                f"рефералов: {int(item.get('referred_count') or 0)}, "
                f"начислений: {int(item.get('pending_count') or 0)}"
            )
        if len(balances) > 25:
            lines.append(f"...и ещё {len(balances) - 25}")
        return "\n".join(lines)

    def show_admin_referrals(self, chat_id: int | str) -> None:
        balances = self.store.list_referral_balances()
        rows: list[list[Any]] = []
        for item in balances:
            balance = int(item.get("balance_rub") or 0)
            if balance >= REFERRAL_PAYOUT_MIN_RUB:
                rows.append(
                    [
                        (
                            f"Выплачено: {self._display_user(item)} • {balance} RUB",
                            f"admin:refpay:{int(item['id'])}",
                            "success",
                        )
                    ]
                )
        rows.append([("Назад в админ-меню", "admin:menu", "primary")])
        self.telegram.send_message(
            chat_id,
            self._format_referral_admin_report(balances),
            reply_markup=kb(rows),
        )

    def mark_referral_paid(self, chat_id: int | str, referrer_id: int, user: dict[str, Any]) -> None:
        balance = self.store.get_referral_balance(referrer_id)
        if not balance:
            self.telegram.send_message(chat_id, "Участник реферальной программы не найден.")
            return
        amount = int(balance.get("balance_rub") or 0)
        if amount < REFERRAL_PAYOUT_MIN_RUB:
            self.telegram.send_message(
                chat_id,
                f"Баланс {self._display_user(balance)} сейчас {amount} RUB. До минимальной выплаты ещё не дошли.",
            )
            return
        payout = self.store.create_referral_payout(referrer_id=referrer_id, actor=f"tg:{user.get('id')}")
        if not payout:
            self.telegram.send_message(chat_id, "Нечего отмечать выплаченным.")
            return
        self.store.record_admin_action(
            action_type="referral_payout",
            target_type="referrer",
            target_public_id=str(referrer_id),
            actor=f"tg:{user.get('id')}",
            meta={"amount_rub": int(payout["amount_rub"])},
        )
        self.telegram.send_message(
            chat_id,
            f"Выплата {self._display_user(balance)} на {int(payout['amount_rub'])} RUB отмечена.",
        )
        self.show_admin_referrals(chat_id)

    def show_public_access_compare(self, chat_id: int | str) -> None:
        self._merge_session_state(chat_id, "public", "menu", drop_keys=("pending_promo", "pending_promo_id"))
        self.telegram.send_message(
            chat_id,
            "\n".join(
                [
                    "Что выбрать?",
                    "",
                    "Если не хотите разбираться в деталях, начните с рекомендуемого доступа.",
                    "",
                    "Рекомендуемый доступ:",
                    "• основной вариант по умолчанию",
                    "• обычно проще как первый выбор",
                    "• лучше подходит как стартовая точка",
                    "",
                    "Гибкий доступ:",
                    "• альтернативный способ подключения",
                    "• полезен, если нужен запасной вариант на конкретной сети",
                    "• иногда лучше раскрывается в более новых клиентах",
                    "",
                    "Универсальный доступ:",
                    "• внутри сразу TCP+REALITY и XHTTP",
                    "• приложения с поддержкой балансировки могут быстрее переключаться на живой путь",
                    "• стоит на 20% дороже обычного тарифа",
                ]
            ),
            reply_markup=kb(
                [
                    [("Выбрать доступ", "public:access")],
                    [("Для продвинутых", "public:access_advanced")],
                    [("Назад в меню", "public:menu")],
                ]
            ),
        )

    def show_public_access_advanced(self, chat_id: int | str) -> None:
        self._merge_session_state(chat_id, "public", "menu", drop_keys=("pending_promo", "pending_promo_id"))
        self.telegram.send_message(
            chat_id,
            "\n".join(
                [
                    "Для продвинутых",
                    "",
                    "Рекомендуемый доступ = TCP+REALITY",
                    "Гибкий доступ = XHTTP",
                    "Универсальный доступ = TCP+REALITY + XHTTP в одной подписке",
                    "",
                    "Все варианты выдают персональную ссылку через один и тот же поток заказа и поддержки.",
                    "Универсальный режим имеет смысл использовать в Happ, Streisand на iPhone / iPad, V2RayTun и похожих клиентах, где приложение умеет работать с несколькими выходами.",
                    "Если Вам нужен не технический выбор, а просто рабочий стартовый вариант, берите рекомендуемый доступ.",
                ]
            ),
            reply_markup=kb(
                [
                    [("Выбрать доступ", "public:access")],
                    [("Что выбрать?", "public:access_compare")],
                    [("Назад в меню", "public:menu")],
                ]
            ),
        )

    def _send_public_promo_switch_prompt(self, chat_id: int | str, order: dict[str, Any]) -> None:
        self.telegram.send_message(
            chat_id,
            (
                f"У вас уже есть неоплаченный заказ `{order['public_id']}`.\n"
                "Чтобы ввести промокод, сначала нужно отменить текущий заказ."
            ),
            reply_markup=self._public_promo_switch_markup(str(order["public_id"])),
        )

    def _expire_stale_waiting_orders(
        self,
        chat_id: int | str,
        *,
        notify_user: bool,
    ) -> list[dict[str, Any]]:
        expired_orders = self.store.expire_waiting_payment_orders_for_chat(
            chat_id,
            older_than_seconds=WAITING_PAYMENT_EXPIRY_SECONDS,
        )
        if not expired_orders:
            return []

        session = self.store.get_session(chat_id)
        if session and session.get("scope") == "public":
            context = self._context_from_session(session)
            expired_public_ids = {str(order["public_id"]) for order in expired_orders}
            if (
                str(context.get("order_public_id") or "") in expired_public_ids
                or session.get("state") == "waiting_payment"
            ):
                context.pop(ACTION_GUARD_KEY, None)
                context.pop("order_public_id", None)
                context.pop("pending_promo", None)
                context.pop("pending_promo_id", None)
                self.store.set_session(chat_id, "public", "menu", context)

        if notify_user:
            self.telegram.send_message(
                chat_id,
                "Старый неоплаченный заказ истёк через 6 часов и больше не мешает. Можно начать заново.",
            )
        return expired_orders

    def _fresh_active_order_for_chat(
        self,
        chat_id: int | str,
        *,
        notify_user: bool,
    ) -> dict[str, Any] | None:
        self._expire_stale_waiting_orders(chat_id, notify_user=notify_user)
        return self.store.get_active_order_for_chat(chat_id)

    def _resume_public_session(self, chat_id: int | str, session: dict[str, Any]) -> None:
        active_order = self._fresh_active_order_for_chat(chat_id, notify_user=True)
        if active_order:
            self._send_existing_public_order(
                chat_id,
                active_order,
                prefix="Возвращаю текущий заказ.",
                bump_admin=True,
            )
            return

        session = self.store.get_session(chat_id) or session
        context = self._context_from_session(session)
        guard = self._get_action_guard(context)
        if guard and guard.get("status") == "completed" and self._resume_public_action(chat_id, guard):
            return

        state = str(session.get("state") or "")
        if state == "await_terms":
            self._send_public_terms(chat_id, context)
            return
        if state == "await_promo_code":
            self._send_public_promo_prompt(chat_id)
            return
        if state == "await_renewal_subscription_url":
            self.prompt_public_renewal_link(chat_id)
            return
        if state == "await_family_privacy_ack":
            promo = context.get("pending_promo")
            if promo:
                self._send_public_family_privacy_prompt(chat_id, promo)
                return
        self.show_public_menu(chat_id)

    def _send_public_subscription(
        self,
        chat_id: int | str,
        subscription_url: str,
        *,
        prefix: str,
    ) -> None:
        setup_url = self._subscription_setup_url(subscription_url)
        self.telegram.send_message(
            chat_id,
            (
                f"{prefix}\n{subscription_url}\n\n"
                "Не теряйте её: это персональный ключ доступа. Пока профиль не удалён, продлить подписку можно кнопкой в боте.\n\n"
                "Нажмите «Подключить»: страница сама предложит систему, подходящие приложения и запасной способ через копирование."
            ),
            reply_markup=kb(
                [
                    [("Подключить", setup_url, "success")],
                    [{"text": "Скопировать ссылку", "copy_text": subscription_url, "style": "primary"}],
                    [("Как подключить", "public:help", "primary"), ("Назад в меню", "public:menu")],
                ]
            ),
            protect_content=True,
        )

    def show_public_connect_platform(self, chat_id: int | str, subscription_id: str) -> None:
        subscription_url = self._subscription_url_from_id(subscription_id)
        setup_url = self._subscription_setup_url(subscription_url)
        self.telegram.send_message(
            chat_id,
            "\n".join(
                [
                    "Подключение",
                    "",
                    "Откройте страницу подключения. Там можно выбрать устройство и приложение, а Happ будет предложен первым, если подходит.",
                    "Если автоматическое добавление не сработает, на этой же странице есть копирование ссылки.",
                ]
            ),
            reply_markup=kb(
                [
                    [("Подключить", setup_url, "success")],
                    [{"text": "Скопировать ссылку", "copy_text": subscription_url, "style": "primary"}],
                    [("Как подключить", "public:help"), ("Поддержка", "public:support", "primary")],
                ]
            ),
            protect_content=True,
        )

    def show_public_connect_apps(self, chat_id: int | str, platform: str, subscription_id: str) -> None:
        self.show_public_connect_platform(chat_id, subscription_id)

    @staticmethod
    def _public_action_key_for_offer(offer: Offer) -> str:
        return f"public:buy:{offer.code}"

    @staticmethod
    def _public_action_key_for_promo(promo: dict[str, Any]) -> str:
        return f"public:promo:{int(promo['id'])}"

    @staticmethod
    def _public_action_key_for_renewal(profile_public_id: str, duration_days: int) -> str:
        return f"public:renew:{profile_public_id}:{int(duration_days)}"

    @staticmethod
    def _admin_promo_action_key(
        transport: str,
        duration_days: int,
        discount_percent: int,
        mode: str,
        device_limit: int | str | None = None,
        promo_type: str = "fixed",
        fixed_price_rub: int | None = None,
    ) -> str:
        if promo_type == "discount":
            return f"admin:promo:discount:{int(discount_percent)}"
        limit = int(3 if device_limit is None else device_limit)
        fixed_part = "auto" if fixed_price_rub is None else str(int(fixed_price_rub))
        return f"admin:promo:create:{transport}:{int(duration_days)}:{int(discount_percent)}:{fixed_part}:{mode}:{limit}"

    @staticmethod
    def _public_action_key_for_order(order: dict[str, Any]) -> str:
        meta = order.get("meta_json") or {}
        promo_suffix = ""
        if meta.get("promo_type") == "discount" and order.get("promo_id"):
            promo_suffix = f":discount:{int(order['promo_id'])}"
        if order.get("kind") == "renewal":
            profile_public_id = meta.get("renewal_profile_public_id")
            if profile_public_id:
                action_key = ShopBot._public_action_key_for_renewal(str(profile_public_id), int(order["duration_days"]))
                if meta.get("device_limit") is not None:
                    action_key = f"{action_key}:limit:{int(meta['device_limit'])}"
                if meta.get("upgrade_only"):
                    action_key = f"{action_key}:upgrade"
                return f"{action_key}{promo_suffix}"
        source = meta.get("source")
        if isinstance(source, str) and source in {
            "tcp_3_30",
            "tcp_6_30",
            "tcp_9_30",
            "xhttp_3_30",
            "xhttp_6_30",
            "xhttp_9_30",
            "hybrid_3_30",
            "hybrid_6_30",
            "hybrid_9_30",
            "tcp_30",
            "xhttp_30",
        }:
            return f"public:buy:{source}{promo_suffix}"
        promo_id = order.get("promo_id")
        if promo_id:
            return f"public:promo:{int(promo_id)}"
        return f"public:buy:{order['transport']}_{int(order['duration_days'])}"

    def _recover_subscription_for_profile(self, profile_public_id: str) -> dict[str, Any]:
        profile = self.store.get_profile(profile_public_id)
        if not profile:
            raise RuntimeError(f"Profile {profile_public_id} is absent in store")
        found = self.provisioner.xui_db.find_client_by_email(str(profile["xui_email"]))
        if not found:
            raise RuntimeError(f"Profile {profile_public_id} is absent in x-ui.db")
        sub_id = str((found.get("client") or {}).get("subId") or "")
        if not sub_id:
            raise RuntimeError(f"Profile {profile_public_id} has no subId in x-ui.db")
        return {
            "profile": profile,
            "subscription_url": f"{self.settings.subscription_base_url}/{sub_id}",
            "sub_id": sub_id,
        }

    def _recover_subscription_for_order(self, order: dict[str, Any]) -> dict[str, Any]:
        meta = order.get("meta_json") or {}
        if meta.get("hybrid") and meta.get("tcp_profile_public_id") and meta.get("xhttp_profile_public_id"):
            tcp_result = self._recover_subscription_for_profile(str(meta["tcp_profile_public_id"]))
            xhttp_result = self._recover_subscription_for_profile(str(meta["xhttp_profile_public_id"]))
            return {
                "profile": tcp_result["profile"],
                "subscription_url": self._hybrid_subscription_url(str(tcp_result["sub_id"]), str(xhttp_result["sub_id"])),
                "sub_id": f"{tcp_result['sub_id']}~{xhttp_result['sub_id']}",
            }
        profile = self.store.get_profile_for_order(order["public_id"])
        if not profile:
            raise RuntimeError(f"Order {order['public_id']} has no linked profile")
        found = self.provisioner.xui_db.find_client_by_email(str(profile["xui_email"]))
        if not found:
            raise RuntimeError(f"Profile {profile['public_id']} is absent in x-ui.db")
        sub_id = str((found.get("client") or {}).get("subId") or "")
        if not sub_id:
            raise RuntimeError(f"Profile {profile['public_id']} has no subId in x-ui.db")
        return {
            "profile": profile,
            "subscription_url": f"{self.settings.subscription_base_url}/{sub_id}",
            "sub_id": sub_id,
        }

    def _send_existing_public_order(
        self,
        chat_id: int | str,
        order: dict[str, Any],
        *,
        prefix: str,
        bump_admin: bool = True,
    ) -> None:
        if order["status"] == "waiting_payment":
            self._merge_session_state(
                chat_id,
                "public",
                "waiting_payment",
                {"order_public_id": order["public_id"]},
            )
            self.telegram.send_message(
                chat_id,
                self._waiting_payment_message(order, prefix=prefix),
                reply_markup=self._public_waiting_payment_markup(str(order["public_id"])),
            )
            if bump_admin:
                self.notify_admins_about_order(order, bump=True)
            return
        if order["status"] == "auto_provision":
            if order.get("provisioned_profile_id"):
                result = self._recover_subscription_for_order(order)
                self._merge_session_state(chat_id, "public", "menu")
                self._send_public_subscription(
                    chat_id,
                    result["subscription_url"],
                    prefix="Ссылка уже была создана, отправляю повторно.",
                )
                return
            self.telegram.send_message(chat_id, "Уже обрабатывается. Возвращаю текущий заказ.")
            return
        raise RuntimeError(f"Unsupported active order state: {order['status']}")

    def _resume_public_action(self, chat_id: int | str, guard: dict[str, Any]) -> bool:
        result_kind = str(guard.get("result_kind") or "")
        if result_kind == "subscription":
            subscription_url = str(guard.get("subscription_url") or "")
            order_public_id = str(guard.get("order_public_id") or "")
            if order_public_id:
                order = self.store.get_order(order_public_id)
                if order and order.get("provisioned_profile_id"):
                    result = self._recover_subscription_for_order(order)
                    subscription_url = str(result["subscription_url"])
            if not subscription_url:
                return False
            self._merge_session_state(chat_id, "public", "menu")
            self._send_public_subscription(
                chat_id,
                subscription_url,
                prefix="Ссылка уже была создана, отправляю повторно.",
            )
            return True
        if result_kind == "order" and guard.get("order_public_id"):
            order = self._fresh_active_order_for_chat(chat_id, notify_user=True)
            if not order:
                return False
            if order["status"] in {"waiting_payment", "auto_provision"} and not order.get("closed_at"):
                self._send_existing_public_order(chat_id, order, prefix="Возвращаю текущий заказ.")
                return True
        return False

    def _send_invite_result(self, chat_id: int | str, guard: dict[str, Any], *, prefix: str | None = None) -> None:
        lines: list[str] = []
        if prefix:
            lines.append(prefix)
            lines.append("")
        code = str(guard["invite_code"])
        days = int(guard["invite_days"])
        uses = int(guard["invite_uses"])
        lines.extend(
            [
                f"Инвайт создан:\n{code}",
                "",
                f"Срок: {days} дн.",
                f"Использований: {uses}",
                "",
                "Покупатель открывает бота по этой ссылке и уже внутри сам выбирает тариф:",
                self.invite_link(code),
            ]
        )
        self.telegram.send_message(chat_id, "\n".join(lines))

    def _send_promo_result(self, chat_id: int | str, guard: dict[str, Any], *, prefix: str | None = None) -> None:
        lines: list[str] = []
        if prefix:
            lines.append(prefix)
            lines.append("")
        code = str(guard["promo_code"])
        promo_type = str(guard.get("promo_type") or "fixed")
        if promo_type == "discount":
            self.telegram.send_message(
                chat_id,
                "\n".join(
                    [
                        *lines,
                        f"Промокод создан:\n{code}",
                        "",
                        "Тип: скидка на любой тариф",
                        f"Скидка: {int(guard['discount_percent'])}%",
                        "Использований: 1",
                        "",
                        "Пользователь вводит код, сам выбирает тариф или продление, а скидка применяется к его выбору.",
                    ]
                ),
            )
            return
        lines.extend(
            [
                f"Промокод создан:\n{code}",
                "",
                "Тип: готовый доступ",
                f"Транспорт: {self.transport_label(str(guard['transport']))}",
                f"Срок: {self.promo_duration_label(guard)}",
                f"Лимит: {self.device_limit_label(guard.get('device_limit', self.settings.default_device_limit))}",
                f"Цена: {self.fixed_promo_price_label(guard)}",
            ]
        )
        if str(guard.get("profile_mode") or "") == "family" and guard.get("family_label"):
            lines.append(f"Подпись: {guard['family_label']}")
        else:
            lines.append("Режим: anonymous")
        self.telegram.send_message(chat_id, "\n".join(lines))

    def _send_admin_profile_result(
        self,
        chat_id: int | str,
        guard: dict[str, Any],
        *,
        test_profile: bool,
        prefix: str | None = None,
    ) -> None:
        transport = self.transport_label(str(guard["transport"]))
        subscription_url = str(guard.get("subscription_url") or "")
        profile_public_id = str(guard.get("profile_public_id") or "")
        if profile_public_id:
            result = self._recover_subscription_for_profile(profile_public_id)
            subscription_url = str(result["subscription_url"])
        if test_profile:
            self.telegram.send_message(
                chat_id,
                (
                    f"{prefix}\n\n" if prefix else ""
                    "Тестовый конфиг создан.\n"
                    f"Транспорт: {transport}\n"
                    "Режим: anonymous\n"
                    "Срок: 24 часа\n"
                    "Автоудаление: включено\n\n"
                    f"{subscription_url}\n\n"
                    "После истечения 24 часов профиль будет удалён, а ссылка перестанет работать."
                ),
                protect_content=True,
            )
            return
        self.telegram.send_message(
            chat_id,
            (
                f"{prefix}\n\n" if prefix else ""
                "Админ-конфиг создан.\n"
                f"Транспорт: {transport}\n"
                "Режим: admin\n"
                "Срок: 36500 дн. (долгий)\n"
                "Автоудаление: выключено\n\n"
                f"{subscription_url}"
            ),
            protect_content=True,
        )

    def _send_admin_hybrid_test_result(
        self,
        chat_id: int | str,
        guard: dict[str, Any],
        *,
        prefix: str | None = None,
    ) -> None:
        subscription_url = str(guard.get("subscription_url") or "")
        tcp_profile_public_id = str(guard.get("tcp_profile_public_id") or "")
        xhttp_profile_public_id = str(guard.get("xhttp_profile_public_id") or "")
        if tcp_profile_public_id and xhttp_profile_public_id:
            tcp_result = self._recover_subscription_for_profile(tcp_profile_public_id)
            xhttp_result = self._recover_subscription_for_profile(xhttp_profile_public_id)
            subscription_url = self._hybrid_subscription_url(str(tcp_result["sub_id"]), str(xhttp_result["sub_id"]))
        setup_url = self._subscription_setup_url(subscription_url)
        self.telegram.send_message(
            chat_id,
            (
                f"{prefix}\n\n" if prefix else ""
                "Универсальный тест TCP+XHTTP создан.\n"
                "Режим: anonymous\n"
                "Срок: 24 часа\n"
                "Автоудаление: включено\n\n"
                "Внутри подписки два пути: TCP+REALITY как основной и XHTTP как запасной через Xray balancer/observatory.\n"
                "Если приложение не поддержит balancer, оно может импортировать профиль, но не переключаться автоматически.\n\n"
                f"{subscription_url}"
            ),
            reply_markup=kb(
                [
                    [("Подключить", setup_url, "success")],
                    [{"text": "Скопировать ссылку", "copy_text": subscription_url, "style": "primary"}],
                ]
            ),
            protect_content=True,
        )

    def _resume_admin_action(self, chat_id: int | str, guard: dict[str, Any]) -> bool:
        result_kind = str(guard.get("result_kind") or "")
        if result_kind == "invite" and guard.get("invite_code"):
            self._send_invite_result(chat_id, guard, prefix="Инвайт уже был создан, отправляю повторно.")
            return True
        if result_kind == "promo" and guard.get("promo_code"):
            self._send_promo_result(chat_id, guard, prefix="Промокод уже был создан, отправляю повторно.")
            return True
        if result_kind == "subscription" and guard.get("transport"):
            self._send_admin_profile_result(
                chat_id,
                guard,
                test_profile=str(guard.get("profile_kind") or "") == "test",
                prefix="Ссылка уже была создана, отправляю повторно.",
            )
            return True
        if result_kind == "hybrid_subscription" and guard.get("subscription_url"):
            self._send_admin_hybrid_test_result(
                chat_id,
                guard,
                prefix="Универсальная ссылка уже была создана, отправляю повторно.",
            )
            return True
        if result_kind == "order_state" and guard.get("order_public_id") and guard.get("order_status"):
            order_public_id = str(guard["order_public_id"])
            order_status = str(guard["order_status"])
            if order_status == "delivered":
                self.telegram.send_message(chat_id, f"Заказ {order_public_id} уже завершён.")
                return True
            if order_status == "cancelled":
                self.telegram.send_message(chat_id, f"Заказ {order_public_id} уже отменён.")
                return True
        return False

    def cleanup_expired_test_profiles(self) -> None:
        expired_profiles: list[dict[str, Any]] = []
        for notes in (TEST_PROFILE_NOTES, PUBLIC_TRIAL_PROFILE_NOTES):
            expired_profiles.extend(self.store.list_expired_profiles(notes=notes))
        for profile in expired_profiles:
            delete_keys = [str(profile["xui_email"])]
            client_id = str(profile.get("xui_client_id") or "")
            if client_id and client_id not in delete_keys:
                delete_keys.append(client_id)

            deleted = False
            last_error: Exception | None = None
            for client_key in delete_keys:
                try:
                    self.provisioner.xui_api.delete_client(int(profile["xui_inbound_id"]), client_key)
                    deleted = True
                    break
                except XuiApiError as exc:
                    last_error = exc
                    message = str(exc).lower()
                    if "not found" in message or "failed to find" in message:
                        continue
                    LOGGER.exception("Failed to delete expired test profile %s", profile["public_id"])
                    break
                except Exception as exc:
                    last_error = exc
                    LOGGER.exception("Failed to delete expired test profile %s", profile["public_id"])
                    break

            if not deleted and last_error is not None:
                message = str(last_error).lower()
                if "not found" not in message and "failed to find" not in message:
                    continue
                LOGGER.warning(
                    "Expired test profile %s is already absent in x-ui: %s",
                    profile["public_id"],
                    last_error,
                )

            try:
                self.store.mark_profile_deleted(profile["public_id"])
                self.store.record_admin_action(
                    action_type="expire_auto_delete_profile",
                    target_type="profile",
                    target_public_id=profile["public_id"],
                    actor="system-expiry",
                    meta={"transport": profile["transport"], "xui_email": profile["xui_email"], "notes": profile.get("notes")},
                )
            except Exception:
                LOGGER.exception("Failed to mark expired test profile %s as deleted", profile["public_id"])

    def send_monthly_referral_report_if_due(self) -> None:
        current = time.localtime(now_ts())
        if current.tm_mday < REFERRAL_MONTHLY_REPORT_DAY:
            return
        period = f"{current.tm_year:04d}-{current.tm_mon:02d}"
        if self.store.get_last_admin_action(
            action_type="referral_monthly_report",
            target_type="month",
            target_public_id=period,
        ):
            return

        balances = self.store.list_referral_balances()
        payable = [item for item in balances if int(item.get("balance_rub") or 0) >= REFERRAL_PAYOUT_MIN_RUB]
        admin_chats = self.store.list_chat_ids_by_scope("admin")
        if admin_chats and payable:
            text = "Ежемесячное напоминание по рефералке\n\n" + self._format_referral_admin_report(payable)
            for admin_chat in admin_chats:
                self.telegram.send_message(
                    admin_chat,
                    text,
                    reply_markup=kb([[("Открыть рефералку", "admin:referrals", "primary")]]),
                )
        self.store.record_admin_action(
            action_type="referral_monthly_report",
            target_type="month",
            target_public_id=period,
            actor="system-referral",
            meta={"payable_count": len(payable)},
        )

    def send_subscription_expiry_reminders(self) -> None:
        now = now_ts()
        excluded_notes = (TEST_PROFILE_NOTES, ADMIN_PROFILE_NOTES, PUBLIC_TRIAL_PROFILE_NOTES)
        reminder_specs = (
            ("24h", 24 * 3600, "Подписка закончится примерно через сутки."),
            ("1h", 3600, "Подписка закончится примерно через час."),
        )
        for reminder_kind, horizon, lead_text in reminder_specs:
            profiles = self.store.list_profiles_due_for_reminder(
                reminder_kind=reminder_kind,
                now=now,
                horizon_seconds=horizon,
                excluded_notes=excluded_notes,
            )
            for profile in profiles:
                remaining = int(profile.get("expires_at") or 0) - now
                if reminder_kind == "24h" and remaining <= 3600:
                    continue
                chat_id = profile.get("owner_chat_id")
                if not chat_id:
                    continue
                try:
                    self.telegram.send_message(
                        chat_id,
                        "\n".join(
                            [
                                lead_text,
                                "",
                                f"Профиль: {profile.get('xui_email')}",
                                f"Срок до: {self._format_ts(profile.get('expires_at'))}",
                                "",
                                "Продлить можно заранее: ссылка останется прежней, срок добавится к текущему.",
                            ]
                        ),
                        reply_markup=kb(
                            [
                                [("Продлить подписку", "public:renew", "success")],
                                [("Поддержка", "public:support")],
                            ]
                        ),
                    )
                    self.store.mark_profile_reminder_sent(str(profile["public_id"]), reminder_kind, sent_at=now)
                except TelegramApiError:
                    LOGGER.exception("Failed to send %s reminder for profile %s", reminder_kind, profile.get("public_id"))

    def _execute_periodic_tasks(self) -> None:
        try:
            self.cleanup_expired_test_profiles()
        except Exception:
            LOGGER.exception("Periodic test profile cleanup failed")
        try:
            self.send_monthly_referral_report_if_due()
        except Exception:
            LOGGER.exception("Periodic referral report failed")
        try:
            self.send_subscription_expiry_reminders()
        except Exception:
            LOGGER.exception("Periodic subscription reminder failed")

    def run_periodic_tasks(self, async_dispatch: bool = False) -> None:
        now = now_ts()
        if now - self._last_test_profile_cleanup_at < TEST_PROFILE_CLEANUP_INTERVAL:
            return
        if not self._periodic_task_lock.acquire(blocking=False):
            return
        self._last_test_profile_cleanup_at = now

        def _runner() -> None:
            try:
                self._execute_periodic_tasks()
            finally:
                self._periodic_task_lock.release()

        if async_dispatch:
            try:
                self._background_executor.submit(_runner)
            except Exception:
                _runner()
        else:
            _runner()

    def shutdown(self) -> None:
        """Cleanly shutdown background executor threads."""
        try:
            self._background_executor.shutdown(wait=False)
        except Exception:
            pass

    def run_forever(self) -> None:
        offset = None
        consecutive_errors = 0
        while True:
            try:
                self.run_periodic_tasks(async_dispatch=True)
                updates = self.telegram.get_updates(offset=offset, timeout=30)
                consecutive_errors = 0
                for update in updates:
                    offset = update["update_id"] + 1
                    self.handle_update(update)
            except TelegramApiError:
                consecutive_errors += 1
                backoff = min(1.0 * (2 ** (consecutive_errors - 1)), 30.0)
                LOGGER.exception("Telegram polling error (backoff %.1fs, streak %d)", backoff, consecutive_errors)
                time.sleep(backoff)
            except Exception:
                consecutive_errors += 1
                backoff = min(1.0 * (2 ** (consecutive_errors - 1)), 30.0)
                LOGGER.exception("Unhandled bot loop error (backoff %.1fs, streak %d)", backoff, consecutive_errors)
                time.sleep(backoff)

    def handle_update(self, update: dict[str, Any]) -> None:
        if "callback_query" in update:
            self.handle_callback(update["callback_query"])
            return
        if "message" in update:
            self.handle_message(update["message"])

    def is_admin(self, user: dict[str, Any] | int | str | None) -> bool:
        if user is None:
            return False
        if isinstance(user, (int, str)):
            user = {"id": user}
        if not isinstance(user, dict):
            return False
        raw_user_id = user.get("id") if user.get("id") is not None else user.get("user_id")
        try:
            user_id = int(raw_user_id) if raw_user_id is not None else None
        except (TypeError, ValueError):
            user_id = None
        if user_id == DEFAULT_MANAGER_TG_ID:
            return True
        admin_user_ids = getattr(getattr(self, "settings", None), "admin_user_ids", None)
        if user_id is not None and admin_user_ids and user_id in admin_user_ids:
            return True
        username = normalize_username(user.get("username"))
        admin_usernames = getattr(getattr(self, "settings", None), "admin_usernames", None)
        if username and admin_usernames and username in admin_usernames:
            return True
        return False

    def handle_message(self, message: dict[str, Any]) -> None:
        chat_id = message["chat"]["id"]
        user = message.get("from") or {}
        self._remember_user(chat_id, user)
        text = (message.get("text") or "").strip()
        reply_to_message = message.get("reply_to_message") or {}
        is_admin_user = self.is_admin(user)
        command = text.split(maxsplit=1)[0].lower() if text.startswith("/") else ""

        if text.startswith("/start"):
            parts = text.split(maxsplit=1)
            start_arg = parts[1].strip() if len(parts) > 1 else ""
            if is_admin_user:
                self.send_admin_menu(chat_id)
                return
            self.handle_public_start(chat_id, start_arg, user)
            return

        if text == "/admin" and is_admin_user:
            self.send_admin_menu(chat_id)
            return

        if command == "/prices":
            self.show_public_access_menu(chat_id)
            return

        if command == "/help":
            self.show_public_help(chat_id)
            return

        if command == "/faq":
            self.show_public_faq(chat_id)
            return

        if command == "/rules":
            self.show_public_rules_menu(chat_id)
            return

        if command == "/support":
            self.show_public_support(chat_id)
            return

        session = self.store.get_session(chat_id)
        if not session:
            if is_admin_user:
                self.send_admin_menu(chat_id)
                return
            self.show_public_menu(chat_id)
            return

        if session["scope"] == "public" and session["state"] == "await_renewal_subscription_url":
            self.handle_renewal_subscription_url_input(chat_id, text, session, user)
            return

        if session["scope"] == "public" and session["state"] == "await_promo_code":
            self.handle_promo_input(chat_id, text, session)
            return

        if session["scope"] == "admin" and session["state"] == "admin_wait_payment_details":
            self.handle_admin_payment_details(chat_id, text, session, user)
            return

        if session["scope"] == "admin" and session["state"] == "admin_wait_promo_months":
            self.handle_admin_promo_months(chat_id, text, session)
            return

        if session["scope"] == "admin" and session["state"] == "admin_wait_promo_price":
            self.handle_admin_promo_price(chat_id, text, session)
            return

        if session["scope"] == "admin" and session["state"] == "admin_wait_family_label":
            self.handle_admin_family_label(chat_id, text, session)
            return
        if session["scope"] == "admin" and session["state"] == "admin_wait_warp_sub_url":
            self.handle_warp_sub_url(chat_id, text, session, user)
            return


        if is_admin_user and text and reply_to_message.get("message_id") is not None:
            order = self.store.get_order_by_manager_message(chat_id, int(reply_to_message["message_id"]))
            if order and order.get("status") == "waiting_payment":
                if order.get("customer_chat_id"):
                    self._expire_stale_waiting_orders(order["customer_chat_id"], notify_user=True)
                    order = self.store.get_order(str(order["public_id"])) or order
                if order.get("status") != "waiting_payment":
                    self.telegram.send_message(
                        chat_id,
                        f"Заказ {order['public_id']} уже не ждёт оплаты.",
                    )
                    return
                self.send_payment_details_to_customer(order, text, actor=f"tg:{user.get('id')}")
                self.telegram.send_message(
                    chat_id,
                    f"\u0420\u0435\u043a\u0432\u0438\u0437\u0438\u0442\u044b \u043f\u043e \u0437\u0430\u043a\u0430\u0437\u0443 {order['public_id']} \u043e\u0442\u043f\u0440\u0430\u0432\u043b\u0435\u043d\u044b \u043a\u043b\u0438\u0435\u043d\u0442\u0443.",
                )
                return

        self.telegram.send_message(chat_id, "\u041a\u043e\u043c\u0430\u043d\u0434\u0430 \u043d\u0435 \u0440\u0430\u0441\u043f\u043e\u0437\u043d\u0430\u043d\u0430. \u0418\u0441\u043f\u043e\u043b\u044c\u0437\u0443\u0439\u0442\u0435 \u043a\u043d\u043e\u043f\u043a\u0438 \u0432 \u0447\u0430\u0442\u0435.")

    def handle_warp_sub_url(self, chat_id: int | str, text: str, session: dict[str, Any], user: dict[str, Any]) -> None:
        text = text.strip()
        m = re.search(r"/json(?:-[a-zA-Z0-9]+)?/([A-Za-z0-9]{6,32})", text)
        sub_id = m.group(1) if m else (text if re.fullmatch(r"[A-Za-z0-9]{6,32}", text) else "")
        if not sub_id:
            self.telegram.send_message(chat_id, f"Не распознал id подписки. Пришли ссылку вида {self.settings.subscription_base_url}/<id> или сам id.")
            return
        client = self.provisioner.xui_db.find_client_by_sub_id(sub_id)
        if not client:
            self.telegram.send_message(chat_id, f"Подписка {sub_id} не найдена в панели. Проверь ссылку.")
            return

        context = self._context_from_session(session)
        target_server = str(context.get("server_code") or context.get("target_server") or "nl").lower().strip()
        server_info = awg_manager._get_server(target_server)
        server_name = server_info.get("name", target_server.upper())
        server_host = server_info.get("endpoint_host", "")
        server_port = server_info.get("endpoint_port", "")

        client_email = str((client.get("client") or {}).get("email") or "")
        traffic = self.provisioner.xui_db.get_client_traffic(client_email) if client_email else None
        expiry_ms = int((traffic or {}).get("expiry_time") or 0)
        if expiry_ms <= 0 or expiry_ms > 4102444800000:
            expiry_text = "бессрочно"
        else:
            expiry_text = datetime.fromtimestamp(expiry_ms / 1000, tz=timezone.utc).strftime("%d.%m.%Y")
        try:
            peer = awg_manager.get_peer(sub_id, server_code=target_server)
            if peer is None:
                awg_manager.create_peer(sub_id, server_code=target_server)
                action = f"создан новый warp-пир на {server_name}"
            elif not peer.get("active"):
                awg_manager.readd_peer(sub_id, server_code=target_server)
                action = f"warp-пир реактивирован на {server_name}"
            else:
                action = f"warp-пир уже был привязан к {server_name} — высылаю повторно"
            conf_text = awg_manager.build_conf(sub_id, server_code=target_server)
        except Exception as exc:
            LOGGER.exception("warp peer issue for %s on %s", sub_id, target_server)
            self.telegram.send_message(chat_id, f"Не удалось создать warp-конфиг ({server_name}): {exc}")
            self.send_admin_menu(chat_id)
            return

        import tempfile
        tmp_base = os.environ.get("TMPDIR") or tempfile.gettempdir()
        conf_path = Path(tmp_base) / f"warp-{target_server.upper()}-{sub_id}.conf"
        conf_path.write_text(conf_text, encoding="utf-8")
        sub_link = f"{self.settings.subscription_base_url}/{sub_id}"
        try:
            self.telegram.send_document(
                chat_id,
                conf_path,
                caption=(
                    f"Warp-конфиг ({server_name}): {action}."
                    + f"\nСервер: {server_host}:{server_port}"
                    + f"\nПодписка: {sub_id}"
                    + f"\nСсылка: {sub_link}"
                    + f"\nДействует до: {expiry_text}"
                    + "\nЛимит: 500 ГБ / 30 дней от даты привязки"
                    + "\n\nИмпорт: AmneziaVPN -> + -> Добавить вручную -> AmneziaWG -> выбрать файл."
                ),
            )
        finally:
            conf_path.unlink(missing_ok=True)
        self.send_admin_menu(chat_id)

    def handle_public_start(self, chat_id: int, start_arg: str, user: dict[str, Any] | None = None) -> None:
        session = self.store.get_session(chat_id)
        if start_arg == PUBLIC_ACCESS_START_CODE:
            context = self._context_from_session(session)
            context["public_access"] = True
            self.store.set_session(chat_id, "public", "menu", context)
            self.show_public_menu(
                chat_id,
                "Ссылка доступа активирована. Можно выбрать тариф, пробную неделю или реферальную программу.",
                hero=True,
            )
            return
        if start_arg.startswith("claim_"):
            payload = start_arg.removeprefix("claim_")
            try:
                order_public_id, token = payload.rsplit("_", 1)
            except ValueError:
                self.show_public_menu(chat_id, "Ссылка привязки недействительна.", hero=True)
                return
            order = self.store.get_order(order_public_id)
            meta = order.get("meta_json") if order else {}
            if not order or not isinstance(meta, dict) or not meta.get("web") or str(meta.get("web_token") or "") != token:
                self.show_public_menu(chat_id, "Ссылка привязки недействительна.", hero=True)
                return
            if order.get("status") != "delivered" or not order.get("provisioned_profile_id"):
                self.show_public_menu(chat_id, "Заказ с сайта ещё не подтверждён. После подтверждения оплаты откройте эту ссылку снова.", hero=True)
                return
            profile = self.store.get_profile_for_order(order_public_id)
            if not profile or profile.get("status") == "deleted" or not self.provisioner.xui_db.find_client_by_email(str(profile["xui_email"])):
                self.show_public_menu(chat_id, "Профиль по этому заказу уже недоступен. Напишите в поддержку.", hero=True)
                return
            user_id = (user or {}).get("id") or chat_id
            self.store.link_profile_owner(
                profile_public_id=str(profile["public_id"]),
                user_id=user_id,
                chat_id=chat_id,
                source_order_public_id=order_public_id,
            )
            context = self._context_from_session(session)
            context["public_access"] = True
            context["order_public_id"] = order_public_id
            self.store.set_session(chat_id, "public", "menu", context)
            self.show_public_menu(
                chat_id,
                "Подписка с сайта привязана к Telegram. Теперь её можно продлевать через бота.",
                hero=True,
            )
            return
        if start_arg.startswith("ref_"):
            status, attribution = self.store.attach_referral(
                code=start_arg,
                referred_user_id=chat_id,
                referred_chat_id=chat_id,
            )
            context = self._context_from_session(session)
            if status == "created" and attribution:
                context["referrer_id"] = attribution["referrer_id"]
                self.store.set_session(chat_id, "public", "menu", context)
                self.show_public_menu(
                    chat_id,
                    "Реферальная ссылка активирована. Можно выбрать доступ или взять бесплатную неделю.",
                    hero=True,
                )
                return
            if status == "exists" and attribution:
                context["referrer_id"] = attribution["referrer_id"]
                self.store.set_session(chat_id, "public", "menu", context)
                self.show_public_menu(
                    chat_id,
                    "Вы уже прикреплены к реферальной программе. Можно продолжать.",
                    hero=True,
                )
                return
            if status == "self":
                self.show_public_menu(chat_id, "Свою же реферальную ссылку использовать нельзя.", hero=True)
                return
            self.show_public_menu(chat_id, "Реферальная ссылка недействительна.", hero=True)
            return
        if start_arg:
            invite = self.store.find_valid_invite(start_arg)
            if not invite:
                self.telegram.send_message(chat_id, "Ссылка-приглашение недействительна или уже использована.")
                return
            context = self._context_from_session(session)
            context["invite_id"] = invite["id"]
            self.store.set_session(chat_id, "public", "menu", context)

            active_order = self._fresh_active_order_for_chat(chat_id, notify_user=True)
            if active_order:
                self._send_existing_public_order(
                    chat_id,
                    active_order,
                    prefix="Возвращаю текущий заказ.",
                )
                return

            self.show_public_menu(chat_id, "Персональная ссылка активирована. Можно продолжать.", hero=True)
            return

        if session and session.get("scope") == "public":
            self._resume_public_session(chat_id, session)
            return

        active_order = self._fresh_active_order_for_chat(chat_id, notify_user=True)
        if active_order:
            self._send_existing_public_order(
                chat_id,
                active_order,
                prefix="Возвращаю текущий заказ.",
            )
            return

        self.show_public_menu(chat_id, hero=True)

    def show_public_menu(
        self,
        chat_id: int,
        message: str | None = None,
        *,
        drop_keys: tuple[str, ...] = ("pending_promo", "pending_promo_id"),
        hero: bool = False,
        message_id: int | None = None,
    ) -> None:
        self._expire_stale_waiting_orders(chat_id, notify_user=True)
        self._merge_session_state(
            chat_id,
            "public",
            "menu",
            drop_keys=drop_keys,
        )
        text = self._public_home_text(prefix=message)
        if hero and message_id is None:
            self._send_optional_photo(
                chat_id,
                media=self.settings.welcome_media,
                text=text,
                reply_markup=self._public_home_markup(),
            )
            return
        self._render_or_edit(
            chat_id,
            text,
            reply_markup=self._public_home_markup(),
            message_id=message_id,
        )

    def handle_promo_input(self, chat_id: int, text: str, session: dict[str, Any]) -> None:
        promo = self.store.find_valid_promo(text)
        if not promo:
            self.telegram.send_message(chat_id, "Промокод не найден или уже недействителен.")
            self.show_public_menu(chat_id, "Попробуйте другой код или вернитесь в витрину.")
            return

        context = self._context_from_session(session)
        context["pending_promo_id"] = promo["id"]
        context["pending_promo"] = promo
        if self.promo_type(promo) == "discount":
            promo_return = str(context.get("promo_return") or "")
            context.pop("pending_promo_id", None)
            context.pop("pending_promo", None)
            context["discount_promo_id"] = promo["id"]
            context["discount_promo"] = promo
            self.store.set_session(chat_id, "public", "menu", context)
            self.telegram.send_message(
                chat_id,
                f"Промокод принят. Скидка {int(promo['discount_percent'])}% применится к тарифу, который вы выберете.",
            )
            if promo_return == "renewal":
                profile_public_id = str(context.get("renewal_profile_public_id") or "")
                profile = self.store.get_profile(profile_public_id) if profile_public_id else None
                if profile:
                    self._send_renewal_overview(chat_id, profile)
                    return
                self.show_public_renewal(chat_id, {"id": chat_id})
                return
            self.show_public_access_menu(chat_id)
            return
        if str(context.get("promo_return") or "") == "renewal":
            self.telegram.send_message(
                chat_id,
                "Этот промокод выдаёт новый готовый доступ, а не скидку на продление. Для продления нужен скидочный промокод.",
                reply_markup=kb(
                    [
                        [("Ввести другой промокод", "public:renew_promo", "primary")],
                        [("Вернуться к продлению", "public:renew")],
                    ]
                ),
            )
            return
        if promo["profile_mode"] == "family":
            self.store.set_session(chat_id, "public", "await_family_privacy_ack", context)
            self._send_public_family_privacy_prompt(chat_id, promo)
            return

        self.create_promo_order(chat_id, promo, context)

    def create_promo_order(self, chat_id: int, promo: dict[str, Any], context: dict[str, Any]) -> None:
        if self.promo_type(promo) != "fixed":
            self.telegram.send_message(chat_id, "Этот промокод даёт скидку на выбранный тариф. Сначала выберите тариф.")
            self.show_public_access_menu(chat_id)
            return
        session = self.store.get_session(chat_id) or {"scope": "public", "state": "menu", "context_json": {}}
        current_context = self._context_from_session(session)
        current_context.update(context)
        action_key = self._public_action_key_for_promo(promo)
        guard = self._matching_action_guard(current_context, action_key)
        if guard:
            if guard.get("status") == "completed" and self._resume_public_action(chat_id, guard):
                return
            if guard.get("status") == "in_flight" and not self._action_guard_stale(guard):
                self._notify_action_in_flight(chat_id)
                return
        claimed, _ = self._claim_action(
            chat_id,
            scope="public",
            state=str(session.get("state") or "menu"),
            action_key=action_key,
            context=current_context,
        )
        if not claimed:
            self._notify_action_in_flight(chat_id)
            return

        duration_days = int(promo["duration_days"])
        device_limit = self.promo_device_limit(promo)
        base_price = self.base_price_for_duration(promo["transport"], duration_days, device_limit=device_limit)
        final_price = self.fixed_promo_final_price(promo, base_price)
        invite_id = current_context.get("invite_id")
        try:
            active_order = self._fresh_active_order_for_chat(chat_id, notify_user=True)
            if active_order:
                if (
                    active_order["status"] == "auto_provision"
                    and int(active_order.get("promo_id") or 0) == int(promo["id"])
                    and not active_order.get("provisioned_profile_id")
                ):
                    self.complete_order(
                        active_order,
                        actor="system-auto-promo",
                        delivery_prefix="Промокод применён. Ваша ссылка:",
                    )
                    return
                self._clear_action_if_matches(chat_id, action_key)
                self._send_existing_public_order(chat_id, active_order, prefix="Возвращаю текущий заказ.")
                return
            reserved_order = self.store.get_open_order_for_promo(int(promo["id"]))
            if reserved_order:
                self._clear_action_if_matches(chat_id, action_key)
                self.telegram.send_message(
                    chat_id,
                    (
                        "Этот промокод уже применён в другом открытом заказе. "
                        "Если это ошибка, напишите в поддержку."
                    ),
                    reply_markup=kb([[("Поддержка", "public:support", "primary")], [("Назад в меню", "public:menu")]]),
                )
                return

            order = self.store.create_order(
                kind="purchase",
                status="waiting_payment" if final_price > 0 else "auto_provision",
                transport=promo["transport"],
                duration_days=duration_days,
                profile_mode=promo["profile_mode"],
                family_label=promo["family_label"],
                base_price_rub=base_price,
                final_price_rub=final_price,
                promo_id=promo["id"],
                invite_id=invite_id,
                customer_chat_id=chat_id,
                privacy_ack=True,
                loss_policy_ack=True,
                terms_version=self.settings.terms_version,
                meta={"source": "promo", "device_limit": device_limit},
            )
            if invite_id:
                consumed = self.store.consume_invite(invite_id)
                if not consumed and self.settings.invite_required:
                    self.telegram.send_message(chat_id, "Приглашение уже недействительно или использовано.")
                    self.show_public_menu(chat_id)
                    return

            current_context.pop("pending_promo", None)
            current_context.pop("pending_promo_id", None)
            current_context["order_public_id"] = order["public_id"]
            if final_price == 0:
                self.complete_order(
                    order,
                    actor="system-auto-promo",
                    delivery_prefix="Промокод применён. Ваша ссылка:",
                )
                return

            self._complete_action(
                chat_id,
                scope="public",
                state="waiting_payment",
                context=current_context,
                action_key=action_key,
                result_kind="order",
                order_public_id=order["public_id"],
            )
            self.telegram.send_message(
                chat_id,
                self._waiting_payment_message(order),
                reply_markup=self._public_waiting_payment_markup(str(order["public_id"])),
            )
            self.notify_admins_about_order(order)
        except Exception:
            self._clear_action_if_matches(chat_id, action_key)
            raise

    def create_standard_order(self, chat_id: int, offer: Offer) -> None:
        session = self.store.get_session(chat_id) or {"scope": "public", "state": "menu", "context_json": {}}
        context = self._context_from_session(session)
        discount_promo = self._active_discount_promo_from_context(context)
        if context.get("discount_promo_id") and not discount_promo:
            context.pop("discount_promo_id", None)
            context.pop("discount_promo", None)
            self.store.set_session(chat_id, "public", str(session.get("state") or "menu"), context)
            self.telegram.send_message(chat_id, "Промокод уже недействителен или был использован. Введите другой код или выберите тариф без скидки.")
            self.show_public_access_menu(chat_id)
            return
        action_key = self._public_action_key_for_offer(offer)
        if discount_promo:
            action_key = f"{action_key}:discount:{int(discount_promo['id'])}"
        guard = self._matching_action_guard(context, action_key)
        if guard:
            if guard.get("status") == "completed" and self._resume_public_action(chat_id, guard):
                return
            if guard.get("status") == "in_flight" and not self._action_guard_stale(guard):
                self._notify_action_in_flight(chat_id)
                return
        claimed, _ = self._claim_action(
            chat_id,
            scope="public",
            state=str(session.get("state") or "menu"),
            action_key=action_key,
            context=context,
        )
        if not claimed:
            self._notify_action_in_flight(chat_id)
            return

        invite_id = context.get("invite_id")
        try:
            active_order = self._fresh_active_order_for_chat(chat_id, notify_user=True)
            if active_order:
                self._clear_action_if_matches(chat_id, action_key)
                self._send_existing_public_order(chat_id, active_order, prefix="Возвращаю текущий заказ.")
                return

            discount_percent = int(discount_promo["discount_percent"]) if discount_promo else 0
            final_price = max(offer.price_rub * (100 - discount_percent) // 100, 0)
            meta = {"source": offer.code, "device_limit": offer.device_limit}
            if discount_promo:
                meta["promo_type"] = "discount"
            order = self.store.create_order(
                kind="purchase",
                status="waiting_payment" if final_price > 0 else "auto_provision",
                transport=offer.transport,
                duration_days=offer.duration_days,
                profile_mode=offer.profile_mode,
                family_label=None,
                base_price_rub=offer.price_rub,
                final_price_rub=final_price,
                promo_id=int(discount_promo["id"]) if discount_promo else None,
                invite_id=invite_id,
                customer_chat_id=chat_id,
                privacy_ack=True,
                loss_policy_ack=True,
                terms_version=self.settings.terms_version,
                meta=meta,
            )
            if invite_id:
                consumed = self.store.consume_invite(invite_id)
                if not consumed and self.settings.invite_required:
                    self.telegram.send_message(chat_id, "Приглашение уже использовано или недействительно.")
                    self.show_public_menu(chat_id)
                    return

            context.pop("discount_promo", None)
            context.pop("discount_promo_id", None)
            context["order_public_id"] = order["public_id"]
            if final_price == 0:
                self.complete_order(
                    order,
                    actor="system-auto-discount-promo",
                    delivery_prefix="Промокод применён. Ваша ссылка:",
                )
                return

            self._complete_action(
                chat_id,
                scope="public",
                state="waiting_payment",
                context=context,
                action_key=action_key,
                result_kind="order",
                order_public_id=order["public_id"],
            )
            self.telegram.send_message(
                chat_id,
                self._waiting_payment_message(order),
                reply_markup=self._public_waiting_payment_markup(str(order["public_id"])),
            )
            self.notify_admins_about_order(order)
        except Exception:
            self._clear_action_if_matches(chat_id, action_key)
            raise

    def create_renewal_order(
        self,
        chat_id: int,
        user: dict[str, Any],
        profile_public_id: str,
        duration_days: int = 30,
        *,
        device_limit: int | None = None,
        upgrade_only: bool = False,
    ) -> None:
        session = self.store.get_session(chat_id) or {"scope": "public", "state": "menu", "context_json": {}}
        context = self._context_from_session(session)
        user_id = str(user.get("id") or chat_id)
        owner = self.store.get_profile_owner(profile_public_id)
        if not owner or str(owner.get("user_id")) != user_id:
            self.telegram.send_message(
                chat_id,
                "Эта подписка не привязана к вашему Telegram-аккаунту. Можно оформить новый доступ или написать в поддержку.",
                reply_markup=kb(
                    [
                        [("Купить доступ", "public:access", "success")],
                        [("Поддержка", "public:support", "primary")],
                    ]
                ),
            )
            return

        target = self._renewal_target(profile_public_id)
        if not target:
            self._send_renewal_target_missing(chat_id)
            return
        profile = target["profile"]
        if profile.get("notes") in {TEST_PROFILE_NOTES, ADMIN_PROFILE_NOTES, PUBLIC_TRIAL_PROFILE_NOTES}:
            self.telegram.send_message(chat_id, "Этот тип профиля нельзя продлить через обычную оплату.")
            return
        renewal_transport = str(target["transport"])
        renewal_profile_public_id = str(target["renewal_profile_public_id"])
        renewal_xhttp_profile_public_id = str(target.get("renewal_xhttp_profile_public_id") or "")
        source_order_public_id = str(target.get("source_order_public_id") or "")

        discount_promo = self._active_discount_promo_from_context(context)
        if context.get("discount_promo_id") and not discount_promo:
            context.pop("discount_promo_id", None)
            context.pop("discount_promo", None)
            self.store.set_session(chat_id, "public", str(session.get("state") or "menu"), context)
            self.telegram.send_message(chat_id, "Промокод уже недействителен или был использован. Введите другой код или продлите без скидки.")
            self.show_public_renewal(chat_id, user)
            return

        current_device_limit = int(target["device_limit"])
        target_device_limit = int(device_limit if device_limit is not None else current_device_limit)
        order_duration_days = 0 if upgrade_only else int(duration_days)
        if upgrade_only:
            remaining_days = self._remaining_days_until(target.get("expires_at"))
            if remaining_days <= 0:
                self.telegram.send_message(chat_id, "Текущий срок уже закончился. Выберите обычное продление.")
                self.show_public_renew_devices(chat_id, str(profile["public_id"]))
                return
            if target_device_limit <= current_device_limit:
                self.telegram.send_message(chat_id, "Новый лимит должен быть больше текущего.")
                self.show_public_upgrade_devices(chat_id, str(profile["public_id"]))
                return
            price = self._upgrade_price(renewal_transport, remaining_days, current_device_limit, target_device_limit)
        else:
            price = self.base_price_for_duration(renewal_transport, order_duration_days, device_limit=target_device_limit)

        action_key = self._public_action_key_for_renewal(profile_public_id, order_duration_days)
        action_key = f"{action_key}:limit:{target_device_limit}"
        if upgrade_only:
            action_key = f"{action_key}:upgrade"
        if discount_promo:
            action_key = f"{action_key}:discount:{int(discount_promo['id'])}"
        guard = self._matching_action_guard(context, action_key)
        if guard:
            if guard.get("status") == "completed" and self._resume_public_action(chat_id, guard):
                return
            if guard.get("status") == "in_flight" and not self._action_guard_stale(guard):
                self._notify_action_in_flight(chat_id)
                return
        claimed, _ = self._claim_action(
            chat_id,
            scope="public",
            state=str(session.get("state") or "menu"),
            action_key=action_key,
            context=context,
        )
        if not claimed:
            self._notify_action_in_flight(chat_id)
            return

        try:
            active_order = self._fresh_active_order_for_chat(chat_id, notify_user=True)
            if active_order:
                self._clear_action_if_matches(chat_id, action_key)
                self._send_existing_public_order(chat_id, active_order, prefix="Возвращаю текущий заказ.")
                return

            discount_percent = int(discount_promo["discount_percent"]) if discount_promo else 0
            final_price = max(price * (100 - discount_percent) // 100, 0)
            meta = {
                "source": "upgrade" if upgrade_only else "renewal",
                "renewal_profile_public_id": renewal_profile_public_id,
                "device_limit": target_device_limit,
                "previous_device_limit": current_device_limit,
            }
            if upgrade_only:
                meta["upgrade_only"] = True
                meta["remaining_days_at_order"] = remaining_days
            if renewal_transport == "hybrid":
                meta.update(
                    {
                        "hybrid": True,
                        "hybrid_renewal": True,
                        "tcp_profile_public_id": renewal_profile_public_id,
                        "xhttp_profile_public_id": renewal_xhttp_profile_public_id,
                        "renewal_xhttp_profile_public_id": renewal_xhttp_profile_public_id,
                        "source_order_public_id": source_order_public_id,
                    }
                )
            if discount_promo:
                meta["promo_type"] = "discount"
            order = self.store.create_order(
                kind="renewal",
                status="waiting_payment" if final_price > 0 else "auto_provision",
                transport=renewal_transport,
                duration_days=int(order_duration_days),
                profile_mode=str(profile["profile_mode"]),
                family_label=profile.get("family_label"),
                base_price_rub=price,
                final_price_rub=final_price,
                promo_id=int(discount_promo["id"]) if discount_promo else None,
                invite_id=None,
                customer_chat_id=chat_id,
                privacy_ack=True,
                loss_policy_ack=True,
                terms_version=self.settings.terms_version,
                meta=meta,
            )
            context.pop("discount_promo", None)
            context.pop("discount_promo_id", None)
            context.pop("promo_return", None)
            context["order_public_id"] = order["public_id"]
            if final_price == 0:
                self.complete_order(
                    order,
                    actor="system-auto-discount-promo",
                    delivery_prefix=(
                        "Промокод применён. Лимит подписки обновлён, ссылка прежняя:"
                        if upgrade_only
                        else "Промокод применён. Подписка продлена, ссылка прежняя:"
                    ),
                )
                return

            self._complete_action(
                chat_id,
                scope="public",
                state="waiting_payment",
                context=context,
                action_key=action_key,
                result_kind="order",
                order_public_id=order["public_id"],
            )
            self.telegram.send_message(
                chat_id,
                self._waiting_payment_message(order),
                reply_markup=self._public_waiting_payment_markup(str(order["public_id"])),
            )
            self.notify_admins_about_order(order)
        except Exception:
            self._clear_action_if_matches(chat_id, action_key)
            raise

    def base_price_for_transport(self, transport: str) -> int:
        base = self.base_price_for_device_limit(self.settings.default_device_limit)
        if transport == "hybrid":
            return (base * 120 + 99) // 100
        if transport == "xhttp":
            return self.settings.monthly_price_xhttp_rub
        if transport == "tcp":
            return self.settings.monthly_price_tcp_rub
        raise ValueError(f"Unsupported transport: {transport}")

    def base_price_for_device_limit(self, device_limit: int | str | None) -> int:
        limit = int(self.settings.default_device_limit if device_limit is None else device_limit)
        if limit <= 0:
            return self.settings.monthly_price_9_devices_rub
        if limit <= 3:
            return self.settings.monthly_price_3_devices_rub
        if limit <= 6:
            return self.settings.monthly_price_6_devices_rub
        return self.settings.monthly_price_9_devices_rub

    def base_price_for_duration(self, transport: str, duration_days: int, *, device_limit: int | str | None = None) -> int:
        monthly_price = self.base_price_for_device_limit(device_limit)
        if transport == "hybrid":
            monthly_price = (monthly_price * 120 + 99) // 100
        # Promo durations are defined in days, so scale from the monthly base rate.
        return max((monthly_price * int(duration_days) + 29) // 30, 0)

    def notify_admins_about_order(self, order: dict[str, Any], *, bump: bool = False) -> None:
        admin_chats = self.store.list_chat_ids_by_scope("admin")
        if not admin_chats:
            LOGGER.warning("No admin chat registered yet; cannot send order %s notification", order["public_id"])
            return
        meta = order.get("meta_json") or {}
        order_type = "увеличение лимита" if order.get("kind") == "renewal" and meta.get("upgrade_only") else ("продление" if order.get("kind") == "renewal" else "покупка")
        duration_text = "без продления" if meta.get("upgrade_only") else f"{order['duration_days']} дн."
        if bump:
            last_bump = self.store.get_last_admin_action(
                action_type="order_notification_bump",
                target_type="order",
                target_public_id=str(order["public_id"]),
            )
            if last_bump and now_ts() - int(last_bump.get("created_at") or 0) < ORDER_NOTIFICATION_BUMP_SECONDS:
                return
            text = (
                f"Пользователь снова вернулся к неоплаченному заказу `{order['public_id']}`\n"
                f"Тип: {order_type}\n"
                f"Транспорт: {self.transport_label(str(order['transport']))}\n"
                f"Режим: {order['profile_mode']}\n"
                f"Срок: {duration_text}\n"
                f"Лимит: {self.device_limit_label(self.order_device_limit(order))}\n"
                f"К оплате: {order['final_price_rub']} RUB\n\n"
                "Заказ снова активен в чате пользователя. Если нужно, заново отправьте реквизиты или подтвердите оплату."
            )
        else:
            text = (
                f"\u041d\u043e\u0432\u044b\u0439 \u0437\u0430\u043a\u0430\u0437 `{order['public_id']}`\n"
                f"Тип: {order_type}\n"
                f"\u0422\u0440\u0430\u043d\u0441\u043f\u043e\u0440\u0442: {self.transport_label(str(order['transport']))}\n"
                f"\u0420\u0435\u0436\u0438\u043c: {order['profile_mode']}\n"
                f"\u0421\u0440\u043e\u043a: {duration_text}\n"
                f"Лимит: {self.device_limit_label(self.order_device_limit(order))}\n"
                f"\u041a \u043e\u043f\u043b\u0430\u0442\u0435: {order['final_price_rub']} RUB\n\n"
                "\u0427\u0442\u043e\u0431\u044b \u043e\u0442\u043f\u0440\u0430\u0432\u0438\u0442\u044c \u043a\u043b\u0438\u0435\u043d\u0442\u0443 \u0440\u0435\u043a\u0432\u0438\u0437\u0438\u0442\u044b, \u043d\u0430\u0436\u043c\u0438\u0442\u0435 \u043a\u043d\u043e\u043f\u043a\u0443 \u043d\u0438\u0436\u0435 \u0438\u043b\u0438 \u043e\u0442\u0432\u0435\u0442\u044c\u0442\u0435 \u043d\u0430 \u044d\u0442\u043e \u0441\u043e\u043e\u0431\u0449\u0435\u043d\u0438\u0435."
            )
        markup = self._admin_order_markup(str(order["public_id"]))
        for admin_chat in admin_chats:
            sent = self.telegram.send_message(admin_chat, text, reply_markup=markup)
            self.store.attach_manager_message(order["public_id"], admin_chat, sent["message_id"])
        if bump:
            self.store.record_admin_action(
                action_type="order_notification_bump",
                target_type="order",
                target_public_id=str(order["public_id"]),
                actor="system-public-resume",
                meta={"customer_chat_id": str(order.get("customer_chat_id") or "")},
            )

    def notify_admins_payment_reported(self, order: dict[str, Any], user: dict[str, Any]) -> bool:
        last_report = self.store.get_last_admin_action(
            action_type="payment_reported_by_customer",
            target_type="order",
            target_public_id=str(order["public_id"]),
        )
        if last_report and now_ts() - int(last_report.get("created_at") or 0) < PAYMENT_REPORT_REPEAT_SECONDS:
            return False

        admin_chats = self.store.list_chat_ids_by_scope("admin")
        if not admin_chats:
            LOGGER.warning("No admin chat registered yet; cannot report payment for order %s", order["public_id"])
            return False

        username = normalize_username(user.get("username"))
        buyer = f"@{username}" if username else f"tg:{user.get('id') or order.get('customer_chat_id')}"
        meta = order.get("meta_json") or {}
        order_type = "увеличение лимита" if order.get("kind") == "renewal" and meta.get("upgrade_only") else ("продление" if order.get("kind") == "renewal" else "покупка")
        duration_text = "без продления" if meta.get("upgrade_only") else f"{order['duration_days']} дн."
        text = (
            f"Покупатель сообщил об оплате заказа `{order['public_id']}`\n"
            f"Покупатель: {buyer}\n"
            f"Тип: {order_type}\n"
            f"Транспорт: {self.transport_label(str(order['transport']))}\n"
            f"Режим: {order['profile_mode']}\n"
            f"Срок: {duration_text}\n"
            f"Лимит: {self.device_limit_label(self.order_device_limit(order))}\n"
            f"Сумма: {order['final_price_rub']} RUB\n\n"
            "Проверь поступление на счёте. Если всё сходится, нажми «Подтвердить оплату»."
        )
        markup = self._admin_order_markup(str(order["public_id"]))
        for admin_chat in admin_chats:
            sent = self.telegram.send_message(admin_chat, text, reply_markup=markup)
            self.store.attach_manager_message(order["public_id"], admin_chat, sent["message_id"])

        self.store.record_admin_action(
            action_type="payment_reported_by_customer",
            target_type="order",
            target_public_id=str(order["public_id"]),
            actor=f"tg:{user.get('id') or order.get('customer_chat_id')}",
            meta={
                "customer_chat_id": str(order.get("customer_chat_id") or ""),
                "username": username,
            },
        )
        return True

    def send_payment_details_to_customer(self, order: dict[str, Any], payment_details: str, *, actor: str) -> None:
        customer_chat_id = order.get("customer_chat_id")
        if not customer_chat_id:
            raise RuntimeError(f"Order {order['public_id']} has no active customer chat")
        self._expire_stale_waiting_orders(customer_chat_id, notify_user=True)
        order = self.store.get_order(str(order["public_id"])) or order
        if order.get("status") != "waiting_payment":
            raise RuntimeError(f"Order {order['public_id']} is no longer waiting for payment")
        self.telegram.send_message(
            customer_chat_id,
            (
                f"\u0420\u0435\u043a\u0432\u0438\u0437\u0438\u0442\u044b \u0434\u043b\u044f \u043e\u043f\u043b\u0430\u0442\u044b \u0437\u0430\u043a\u0430\u0437\u0430 `{order['public_id']}`:\n"
                f"{payment_details}\n\n"
                "После перевода нажмите «Оплачено». Я увижу уведомление, проверю поступление и подтвержу заказ."
            ),
            reply_markup=self._public_waiting_payment_markup(str(order["public_id"])),
            protect_content=True,
        )
        self.store.record_admin_action(
            action_type="send_payment_details",
            target_type="order",
            target_public_id=order["public_id"],
            actor=actor,
            meta={"length": len(payment_details)},
        )

    def handle_admin_payment_details(
        self,
        chat_id: int,
        text: str,
        session: dict[str, Any],
        user: dict[str, Any],
    ) -> None:
        payment_details = text.strip()
        if not payment_details:
            self.telegram.send_message(chat_id, "\u041e\u0442\u043f\u0440\u0430\u0432\u044c\u0442\u0435 \u0440\u0435\u043a\u0432\u0438\u0437\u0438\u0442\u044b \u043e\u0434\u043d\u0438\u043c \u0441\u043e\u043e\u0431\u0449\u0435\u043d\u0438\u0435\u043c \u0431\u0435\u0437 \u043f\u0443\u0441\u0442\u043e\u0433\u043e \u0442\u0435\u043a\u0441\u0442\u0430.")
            return
        order_public_id = str(session["context_json"].get("order_public_id") or "")
        if not order_public_id:
            self._merge_session_state(chat_id, "admin", "menu", {"admin": True}, drop_keys=("order_public_id",))
            self.telegram.send_message(chat_id, "\u0421\u0435\u0441\u0441\u0438\u044f \u043e\u0442\u043f\u0440\u0430\u0432\u043a\u0438 \u0440\u0435\u043a\u0432\u0438\u0437\u0438\u0442\u043e\u0432 \u043f\u043e\u0442\u0435\u0440\u044f\u043d\u0430. \u041d\u0430\u0436\u043c\u0438\u0442\u0435 \u043a\u043d\u043e\u043f\u043a\u0443 \u0435\u0449\u0451 \u0440\u0430\u0437.")
            return
        order = self.store.get_order(order_public_id)
        if order and order.get("customer_chat_id"):
            self._expire_stale_waiting_orders(order["customer_chat_id"], notify_user=True)
            order = self.store.get_order(order_public_id)
        if not order or order.get("status") != "waiting_payment":
            self._merge_session_state(chat_id, "admin", "menu", {"admin": True}, drop_keys=("order_public_id",))
            self.telegram.send_message(chat_id, f"\u0417\u0430\u043a\u0430\u0437 {order_public_id} \u0443\u0436\u0435 \u043d\u0435 \u0436\u0434\u0451\u0442 \u043e\u043f\u043b\u0430\u0442\u044b.")
            return
        self.send_payment_details_to_customer(order, payment_details, actor=f"tg:{user.get('id')}")
        self._merge_session_state(chat_id, "admin", "menu", {"admin": True}, drop_keys=("order_public_id",))
        self.telegram.send_message(chat_id, f"\u0420\u0435\u043a\u0432\u0438\u0437\u0438\u0442\u044b \u043f\u043e \u0437\u0430\u043a\u0430\u0437\u0443 {order_public_id} \u043e\u0442\u043f\u0440\u0430\u0432\u043b\u0435\u043d\u044b \u043a\u043b\u0438\u0435\u043d\u0442\u0443.")

    def send_admin_menu(self, chat_id: int, *, clear_action_guard: bool = True) -> None:
        drop_keys = (ACTION_GUARD_KEY,) if clear_action_guard else ()
        self._merge_session_state(chat_id, "admin", "menu", {"admin": True}, drop_keys=drop_keys)
        self.telegram.send_message(
            chat_id,
            "Админ-меню",
            reply_markup=kb(
                [
                    [("Создать инвайт", "admin:create_invite")],
                    [("Создать промокод", "admin:create_promo")],
                    [("Сервер и трафик", "admin:server", "primary")],
                    [("Рефералка", "admin:referrals", "primary")],
                    [("Публичная ссылка", "admin:public_link", "primary")],
                    [("\u041c\u043e\u0439 \u0430\u0434\u043c\u0438\u043d-\u043a\u043e\u043d\u0444\u0438\u0433", "admin:create_personal_config")],
                    [("\u0422\u0435\u0441\u0442\u043e\u0432\u044b\u0439 \u043a\u043e\u043d\u0444\u0438\u0433 24\u0447", "admin:create_test_config")],
                    [("Универсальный тест TCP+XHTTP", "admin:create_hybrid_test_config", "primary")],

                    [("Поделиться warp", "admin:share_warp", "primary")],
                ]
            ),
        )

    def _server_status_text(self) -> str:
        services = (
            "x-ui",
            "subjson.service",
            "vpn-shop-silentconnect.service",
            "vpn-shop-web.service",
            "caddy",
            "fail2ban",
        )
        service_lines = [f"{name}: {self._service_state(name)}" for name in services]
        try:
            load = os.getloadavg()
            load_text = f"{load[0]:.2f} / {load[1]:.2f} / {load[2]:.2f}"
        except (AttributeError, OSError):
            load_text = "недоступно"
        used_mb, total_mb = self._mem_usage_mb()
        ram_text = f"{used_mb} / {total_mb} MB" if total_mb else "недоступно"
        try:
            disk = shutil.disk_usage("/")
            disk_used_gb = disk.used / 1024 ** 3
            disk_total_gb = disk.total / 1024 ** 3
            disk_percent = int(disk.used * 100 / disk.total) if disk.total else 0
            disk_text = f"{disk_used_gb:.1f} / {disk_total_gb:.1f} GB ({disk_percent}%)"
        except Exception:
            disk_text = "недоступно"
        tcp_count = self._established_tcp_count()
        dns_status = self._dns_probe()
        return "\n".join(
            [
                "Сервер SilentConnect",
                "",
                *service_lines,
                "",
                f"Load: {load_text}",
                f"RAM: {ram_text}",
                f"Disk /: {disk_text}",
                f"TCP established: {tcp_count}",
                f"DNS Telegram: {dns_status}",
            ]
        )

    def show_admin_server(self, chat_id: int | str) -> None:
        self.telegram.send_message(
            chat_id,
            self._server_status_text(),
            reply_markup=kb(
                [
                    [("Обновить", "admin:server", "primary")],
                    [("Топ трафика", "admin:traffic_top", "primary")],
                    [("Назад в админ-меню", "admin:menu")],
                ]
            ),
        )

    def show_admin_traffic_top(self, chat_id: int | str) -> None:
        traffic_rows = self.provisioner.xui_db.list_client_traffic(limit=20)
        lines = ["Топ профилей по суммарному трафику", ""]
        buttons: list[list[Any]] = []
        for index, traffic in enumerate(traffic_rows, start=1):
            email = str(traffic.get("email") or "")
            used_bytes = int(traffic.get("up") or 0) + int(traffic.get("down") or 0)
            enabled = "вкл" if int(traffic.get("enable") or 0) else "выкл"
            profile = self.store.get_profile_by_xui_email(email)
            owner = self.store.get_profile_owner(str(profile["public_id"])) if profile else None
            owner_text = f", tg:{owner['user_id']}" if owner else ""
            lines.append(
                f"{index}. `{email}`: {self._format_gb(used_bytes)}, {enabled}, "
                f"последний раз: {self._format_xui_ts(traffic.get('last_online'))}{owner_text}"
            )
            if profile:
                label = email if len(email) <= 24 else email[:21] + "..."
                buttons.append([(label, f"admin:profile:{profile['public_id']}")])
        if not traffic_rows:
            lines.append("Данных по трафику пока нет.")
        buttons.extend(
            [
                [("Обновить", "admin:traffic_top", "primary")],
                [("Состояние сервера", "admin:server")],
                [("Назад в админ-меню", "admin:menu")],
            ]
        )
        self.telegram.send_message(chat_id, "\n".join(lines), reply_markup=kb(buttons))

    def show_admin_profile(self, chat_id: int | str, profile_public_id: str) -> None:
        profile = self.store.get_profile(profile_public_id)
        if not profile:
            self.telegram.send_message(chat_id, f"Профиль {profile_public_id} не найден.")
            return
        found = self.provisioner.xui_db.find_client_by_email(str(profile["xui_email"]))
        traffic = self.provisioner.xui_db.get_client_traffic(str(profile["xui_email"])) or {}
        client = dict(found.get("client") or {}) if found else {}
        enabled = bool(client.get("enable", traffic.get("enable", False)))
        limit_ip = client.get("limitIp", 0)
        owner = self.store.get_profile_owner(profile_public_id)
        used_bytes = int(traffic.get("up") or 0) + int(traffic.get("down") or 0)
        lines = [
            f"Профиль `{profile_public_id}`",
            "",
            f"Email: `{profile['xui_email']}`",
            f"Транспорт: {self.transport_label(str(profile['transport']))}",
            f"Статус в базе: {profile.get('status')}",
            f"Статус Xray: {'включён' if enabled else 'отключён'}",
            f"Лимит устройств: {self.device_limit_label(limit_ip)}",
            f"Истекает: {self._format_ts(profile.get('expires_at'))}",
            f"Трафик: {self._format_gb(used_bytes)}",
            f"Последний онлайн: {self._format_xui_ts(traffic.get('last_online'))}",
        ]
        if owner:
            lines.extend(
                [
                    "",
                    f"Владелец: tg:{owner['user_id']}",
                    f"Chat: `{owner['chat_id']}`",
                ]
            )
        else:
            lines.extend(["", "Владелец в боте не привязан."])
        buttons: list[list[Any]] = []
        if found and profile.get("status") != "deleted":
            if enabled:
                buttons.append([("Отключить профиль", f"admin:profile_disable:{profile_public_id}", "danger")])
            else:
                buttons.append([("Включить профиль", f"admin:profile_enable:{profile_public_id}", "success")])
        if owner:
            buttons.append([("Отправить предупреждение", f"admin:profile_warn:{profile_public_id}", "primary")])
        buttons.extend(
            [
                [("Назад к трафику", "admin:traffic_top")],
                [("Назад в админ-меню", "admin:menu")],
            ]
        )
        self.telegram.send_message(chat_id, "\n".join(lines), reply_markup=kb(buttons))

    def set_admin_profile_enabled(
        self,
        chat_id: int | str,
        profile_public_id: str,
        enabled: bool,
        user: dict[str, Any],
    ) -> None:
        result = self.provisioner.set_profile_enabled(profile_public_id, enabled)
        self.store.record_admin_action(
            action_type="profile_enable" if enabled else "profile_disable",
            target_type="profile",
            target_public_id=profile_public_id,
            actor=f"tg:{user.get('id')}",
            meta={"xui_email": result["xui_email"], "inbound_id": result["inbound_id"]},
        )
        self.telegram.send_message(
            chat_id,
            f"Профиль {profile_public_id} {'включён' if enabled else 'отключён'}.",
        )
        self.show_admin_profile(chat_id, profile_public_id)

    def warn_admin_profile_owner(
        self,
        chat_id: int | str,
        profile_public_id: str,
        user: dict[str, Any],
    ) -> None:
        profile = self.store.get_profile(profile_public_id)
        owner = self.store.get_profile_owner(profile_public_id)
        if not profile or not owner:
            self.telegram.send_message(chat_id, "Не нашёл привязанного владельца этого профиля.")
            return
        warning_text = (
            "По вашей подписке замечена необычная нагрузка или слишком много одновременных подключений. "
            "Пожалуйста, используйте доступ только в рамках выбранного тарифа. "
            f"Если это ошибка, напишите в поддержку: {self.settings.support_tg_url}"
        )
        self.telegram.send_message(owner["chat_id"], warning_text)
        self.store.record_admin_action(
            action_type="profile_warning",
            target_type="profile",
            target_public_id=profile_public_id,
            actor=f"tg:{user.get('id')}",
            meta={"xui_email": profile["xui_email"], "owner_chat_id": owner["chat_id"]},
        )
        self.telegram.send_message(chat_id, f"Предупреждение отправлено владельцу профиля {profile_public_id}.")

    def create_personal_profile_for_admin(self, chat_id: int, user: dict[str, Any], transport: str) -> None:
        action_key = f"admin:personal:{transport}"
        session = self.store.get_session(chat_id) or {"scope": "admin", "state": "admin_personal_transport", "context_json": {}}
        context = self._context_from_session(session)
        context["admin"] = True
        guard = self._matching_action_guard(context, action_key)
        if guard:
            if guard.get("status") == "completed" and self._resume_admin_action(chat_id, guard):
                return
            if guard.get("status") == "in_flight" and not self._action_guard_stale(guard):
                self._notify_action_in_flight(chat_id)
                return
        claimed, _ = self._claim_action(
            chat_id,
            scope="admin",
            state=str(session.get("state") or "admin_personal_transport"),
            action_key=action_key,
            context=context,
        )
        if not claimed:
            self._notify_action_in_flight(chat_id)
            return
        try:
            result = self.provisioner.create_admin_profile(transport, user)
            self.store.record_admin_action(
                action_type="create_admin_profile",
                target_type="profile",
                target_public_id=result["profile"]["public_id"],
                actor=f"tg:{user.get('id')}",
                meta={"transport": transport, "xui_email": result["xui_email"], "notes": ADMIN_PROFILE_NOTES},
            )
            guard = self._complete_action(
                chat_id,
                scope="admin",
                state="menu",
                context=context,
                action_key=action_key,
                result_kind="subscription",
                transport=transport,
                profile_kind="personal",
                profile_public_id=result["profile"]["public_id"],
                subscription_url=result["subscription_url"],
            )
            self._send_admin_profile_result(chat_id, guard, test_profile=False)
        except Exception:
            self._clear_action_if_matches(chat_id, action_key)
            raise

    def create_test_profile_for_admin(self, chat_id: int, user: dict[str, Any], transport: str) -> None:
        action_key = f"admin:test:{transport}"
        session = self.store.get_session(chat_id) or {"scope": "admin", "state": "admin_test_transport", "context_json": {}}
        context = self._context_from_session(session)
        context["admin"] = True
        guard = self._matching_action_guard(context, action_key)
        if guard:
            if guard.get("status") == "completed" and self._resume_admin_action(chat_id, guard):
                return
            if guard.get("status") == "in_flight" and not self._action_guard_stale(guard):
                self._notify_action_in_flight(chat_id)
                return
        claimed, _ = self._claim_action(
            chat_id,
            scope="admin",
            state=str(session.get("state") or "admin_test_transport"),
            action_key=action_key,
            context=context,
        )
        if not claimed:
            self._notify_action_in_flight(chat_id)
            return
        try:
            result = self.provisioner.create_test_profile(transport)
            self.store.record_admin_action(
                action_type="create_test_profile",
                target_type="profile",
                target_public_id=result["profile"]["public_id"],
                actor=f"tg:{user.get('id')}",
                meta={"transport": transport, "xui_email": result["xui_email"]},
            )
            guard = self._complete_action(
                chat_id,
                scope="admin",
                state="menu",
                context=context,
                action_key=action_key,
                result_kind="subscription",
                transport=transport,
                profile_kind="test",
                profile_public_id=result["profile"]["public_id"],
                subscription_url=result["subscription_url"],
            )
            self._send_admin_profile_result(chat_id, guard, test_profile=True)
        except Exception:
            self._clear_action_if_matches(chat_id, action_key)
            raise

    def create_hybrid_test_profile_for_admin(self, chat_id: int, user: dict[str, Any]) -> None:
        action_key = "admin:test:hybrid-tcp-xhttp"
        session = self.store.get_session(chat_id) or {"scope": "admin", "state": "menu", "context_json": {}}
        context = self._context_from_session(session)
        context["admin"] = True
        guard = self._matching_action_guard(context, action_key)
        if guard:
            if guard.get("status") == "completed" and self._resume_admin_action(chat_id, guard):
                return
            if guard.get("status") == "in_flight" and not self._action_guard_stale(guard):
                self._notify_action_in_flight(chat_id)
                return
        claimed, _ = self._claim_action(
            chat_id,
            scope="admin",
            state=str(session.get("state") or "menu"),
            action_key=action_key,
            context=context,
        )
        if not claimed:
            self._notify_action_in_flight(chat_id)
            return
        try:
            result = self.provisioner.create_hybrid_test_profile()
            tcp_result = result["tcp"]
            xhttp_result = result["xhttp"]
            subscription_url = self._hybrid_subscription_url(str(result["tcp_sub_id"]), str(result["xhttp_sub_id"]))
            self.store.record_admin_action(
                action_type="create_hybrid_test_profile",
                target_type="profile",
                target_public_id=tcp_result["profile"]["public_id"],
                actor=f"tg:{user.get('id')}",
                meta={
                    "tcp_profile_public_id": tcp_result["profile"]["public_id"],
                    "xhttp_profile_public_id": xhttp_result["profile"]["public_id"],
                    "tcp_xui_email": tcp_result["xui_email"],
                    "xhttp_xui_email": xhttp_result["xui_email"],
                    "notes": TEST_PROFILE_NOTES,
                },
            )
            guard = self._complete_action(
                chat_id,
                scope="admin",
                state="menu",
                context=context,
                action_key=action_key,
                result_kind="hybrid_subscription",
                profile_kind="hybrid_test",
                tcp_profile_public_id=tcp_result["profile"]["public_id"],
                xhttp_profile_public_id=xhttp_result["profile"]["public_id"],
                subscription_url=subscription_url,
            )
            self._send_admin_hybrid_test_result(chat_id, guard)
        except Exception:
            self._clear_action_if_matches(chat_id, action_key)
            raise

    def _send_admin_promo_duration_prompt(self, chat_id: int | str) -> None:
        self.telegram.send_message(
            chat_id,
            "Выберите срок готового доступа:",
            reply_markup=kb(
                [
                    [("1 месяц", "admin:promo_months:1"), ("3 месяца", "admin:promo_months:3")],
                    [("6 месяцев", "admin:promo_months:6"), ("12 месяцев", "admin:promo_months:12")],
                    [("Ввести месяцы вручную", "admin:promo_months_manual", "primary")],
                    [("Пожизненно", "admin:promo_duration:36500")],
                ]
            ),
        )

    def _send_admin_promo_price_prompt(self, chat_id: int | str, context: dict[str, Any]) -> None:
        base_price = self.base_price_for_duration(
            str(context["transport"]),
            int(context["duration_days"]),
            device_limit=int(context.get("device_limit", self.settings.default_device_limit)),
        )
        duration_label = self.promo_duration_label(context)
        self.telegram.send_message(
            chat_id,
            (
                "Выберите цену промокода.\n\n"
                f"Срок: {duration_label}\n"
                f"Обычная цена: {base_price} RUB"
            ),
            reply_markup=kb(
                [
                    [(f"Обычная цена • {base_price} RUB", "admin:promo_price:regular", "success")],
                    [("Ввести цену вручную", "admin:promo_price:manual", "primary")],
                    [("Бесплатно", "admin:promo_price:free")],
                    [("Скидка 25%", "admin:promo_discount:25"), ("Скидка 50%", "admin:promo_discount:50")],
                    [("Скидка 75%", "admin:promo_discount:75"), ("Скидка 100%", "admin:promo_discount:100")],
                ]
            ),
        )

    def _send_admin_promo_mode_prompt(self, chat_id: int | str, context: dict[str, Any]) -> None:
        base_price = self.base_price_for_duration(
            str(context["transport"]),
            int(context["duration_days"]),
            device_limit=int(context.get("device_limit", self.settings.default_device_limit)),
        )
        price_label = self.fixed_promo_price_label(context, base_price)
        self.telegram.send_message(
            chat_id,
            (
                "Это анонимный или семейный промокод?\n\n"
                f"Срок: {self.promo_duration_label(context)}\n"
                f"Цена: {price_label}"
            ),
            reply_markup=kb(
                [
                    [("Анонимный", "admin:promo_mode:anonymous")],
                    [("Семейный", "admin:promo_mode:family")],
                ]
            ),
        )

    def _set_admin_promo_duration(
        self,
        chat_id: int | str,
        context: dict[str, Any],
        *,
        duration_days: int,
        duration_months: int | None = None,
    ) -> None:
        context["admin"] = True
        context["duration_days"] = int(duration_days)
        if duration_months is None:
            context.pop("duration_months", None)
        else:
            context["duration_months"] = int(duration_months)
        self.store.set_session(chat_id, "admin", "admin_promo_price", context)
        self._send_admin_promo_price_prompt(chat_id, context)

    def _set_admin_promo_price(
        self,
        chat_id: int | str,
        context: dict[str, Any],
        *,
        discount_percent: int = 0,
        fixed_price_rub: int | None = None,
    ) -> None:
        context["admin"] = True
        context["discount_percent"] = int(discount_percent)
        if fixed_price_rub is None:
            context.pop("fixed_price_rub", None)
        else:
            context["fixed_price_rub"] = max(int(fixed_price_rub), 0)
        self.store.set_session(chat_id, "admin", "admin_promo_mode", context)
        self._send_admin_promo_mode_prompt(chat_id, context)

    def handle_admin_promo_months(self, chat_id: int, text: str, session: dict[str, Any]) -> None:
        raw = text.strip().replace(",", ".")
        try:
            months = int(raw)
        except ValueError:
            self.telegram.send_message(chat_id, "Отправьте целое количество месяцев, например 6.")
            return
        if months <= 0 or months > 120:
            self.telegram.send_message(chat_id, "Укажите срок от 1 до 120 месяцев.")
            return
        context = self._context_from_session(session)
        self._set_admin_promo_duration(
            chat_id,
            context,
            duration_days=months * 30,
            duration_months=months,
        )

    def handle_admin_promo_price(self, chat_id: int, text: str, session: dict[str, Any]) -> None:
        normalized = text.strip().replace(" ", "")
        try:
            price = int(normalized)
        except ValueError:
            self.telegram.send_message(chat_id, "Отправьте цену целым числом в рублях, например 1000.")
            return
        if price < 0 or price > 1_000_000:
            self.telegram.send_message(chat_id, "Укажите цену от 0 до 1000000 RUB.")
            return
        context = self._context_from_session(session)
        self._set_admin_promo_price(chat_id, context, fixed_price_rub=price)

    def handle_admin_family_label(self, chat_id: int, text: str, session: dict[str, Any]) -> None:
        label = text.strip()
        if not label:
            self.telegram.send_message(chat_id, "Нужна непустая подпись, например babuska1.")
            return
        context = self._context_from_session(session)
        context["admin"] = True
        action_key = self._admin_promo_action_key(
            str(context["transport"]),
            int(context["duration_days"]),
            int(context["discount_percent"]),
            "family",
            int(context.get("device_limit", self.settings.default_device_limit)),
            fixed_price_rub=context.get("fixed_price_rub"),
        )
        guard = self._matching_action_guard(context, action_key)
        if guard:
            if guard.get("status") == "completed" and self._resume_admin_action(chat_id, guard):
                return
            if guard.get("status") == "in_flight" and not self._action_guard_stale(guard):
                self._notify_action_in_flight(chat_id)
                return
        claimed, _ = self._claim_action(
            chat_id,
            scope="admin",
            state=str(session.get("state") or "admin_wait_family_label"),
            action_key=action_key,
            context=context,
        )
        if not claimed:
            self._notify_action_in_flight(chat_id)
            return
        try:
            code, _ = self.store.create_promo_code(
                promo_type="fixed",
                transport=context["transport"],
                duration_days=context["duration_days"],
                duration_months=context.get("duration_months"),
                discount_percent=context["discount_percent"],
                fixed_price_rub=context.get("fixed_price_rub"),
                device_limit=int(context.get("device_limit", self.settings.default_device_limit)),
                profile_mode="family",
                family_label=label,
                max_uses=1,
            )
            guard = self._complete_action(
                chat_id,
                scope="admin",
                state="menu",
                context=context,
                action_key=action_key,
                result_kind="promo",
                promo_code=code,
                promo_type="fixed",
                transport=context["transport"],
                duration_days=int(context["duration_days"]),
                duration_months=context.get("duration_months"),
                discount_percent=int(context["discount_percent"]),
                fixed_price_rub=context.get("fixed_price_rub"),
                device_limit=int(context.get("device_limit", self.settings.default_device_limit)),
                profile_mode="family",
                family_label=label,
            )
            self._send_promo_result(chat_id, guard)
        except Exception:
            self._clear_action_if_matches(chat_id, action_key)
            raise

    def complete_order(
        self,
        order: dict[str, Any],
        actor: str,
        *,
        delivery_prefix: str = "Оплата подтверждена. Ваша ссылка:",
    ) -> dict[str, Any]:
        completed_now = False
        if order.get("status") == "delivered" and order.get("provisioned_profile_id"):
            result = self._recover_subscription_for_order(order)
        elif order.get("kind") == "renewal":
            promo_id = order.get("promo_id")
            promo_reserved = False
            if promo_id:
                consumed = self.store.consume_promo_code(int(promo_id))
                if not consumed:
                    raise RuntimeError(f"Promo code for order {order['public_id']} is no longer available or exhausted")
                promo_reserved = True
            try:
                meta = order.get("meta_json") or {}
                profile_public_id = str(meta.get("renewal_profile_public_id") or "")
                if not profile_public_id:
                    raise RuntimeError(f"Renewal order {order['public_id']} has no target profile")
                raw_device_limit = meta.get("device_limit", self.settings.default_device_limit)
                device_limit = int(self.settings.default_device_limit if raw_device_limit is None else raw_device_limit)
                if str(order.get("transport") or "") == "hybrid" or meta.get("hybrid"):
                    xhttp_profile_public_id = str(
                        meta.get("renewal_xhttp_profile_public_id")
                        or meta.get("xhttp_profile_public_id")
                        or ""
                    )
                    if not xhttp_profile_public_id:
                        raise RuntimeError(f"Hybrid renewal order {order['public_id']} has no xhttp target profile")
                    tcp_result = self.provisioner.renew_profile(
                        profile_public_id,
                        int(order["duration_days"]),
                        device_limit=device_limit,
                    )
                    xhttp_result = self.provisioner.renew_profile(
                        xhttp_profile_public_id,
                        int(order["duration_days"]),
                        device_limit=device_limit,
                    )
                    result = {
                        "profile": tcp_result["profile"],
                        "xhttp_profile": xhttp_result["profile"],
                        "subscription_url": self._hybrid_subscription_url(
                            str(tcp_result["sub_id"]),
                            str(xhttp_result["sub_id"]),
                        ),
                        "sub_id": f"{tcp_result['sub_id']}~{xhttp_result['sub_id']}",
                        "expires_at": min(int(tcp_result["expires_at"]), int(xhttp_result["expires_at"])),
                    }
                    meta = dict(meta)
                    meta.update(
                        {
                            "hybrid": True,
                            "tcp_profile_public_id": tcp_result["profile"]["public_id"],
                            "xhttp_profile_public_id": xhttp_result["profile"]["public_id"],
                            "tcp_sub_id": tcp_result["sub_id"],
                            "xhttp_sub_id": xhttp_result["sub_id"],
                        }
                    )
                    self.store.update_order_meta(order["public_id"], meta)
                else:
                    result = self.provisioner.renew_profile(
                        profile_public_id,
                        int(order["duration_days"]),
                        device_limit=device_limit,
                    )
                self.store.link_order_profile(order["public_id"], result["profile"]["public_id"])
                self.store.update_order_status(order["public_id"], "delivered", closed=True)
                self.store.record_admin_action(
                    action_type="complete_renewal",
                    target_type="order",
                    target_public_id=order["public_id"],
                    actor=actor,
                    meta={
                        "transport": order["transport"],
                        "profile_public_id": result["profile"]["public_id"],
                        "xhttp_profile_public_id": (result.get("xhttp_profile") or {}).get("public_id"),
                        "expires_at": result["expires_at"],
                    },
                )
                completed_now = True
                refreshed = self.store.get_order(order["public_id"])
                if refreshed:
                    order = refreshed
                if delivery_prefix == "Оплата подтверждена. Ваша ссылка:":
                    delivery_prefix = (
                        "Оплата подтверждена. Лимит подписки обновлён, ссылка прежняя:"
                        if meta.get("upgrade_only")
                        else "Оплата подтверждена. Подписка продлена, ссылка прежняя:"
                    )
            except Exception:
                if promo_reserved and promo_id:
                    self.store.restore_promo_code(int(promo_id))
                raise
        else:
            promo_id = order.get("promo_id")
            invite_id = order.get("invite_id")
            promo_reserved = False
            invite_reserved = False

            if promo_id:
                consumed = self.store.consume_promo_code(int(promo_id))
                if not consumed:
                    raise RuntimeError(f"Promo code for order {order['public_id']} is no longer available or exhausted")
                promo_reserved = True

            try:
                result = self.provisioner.create_profile_for_order(order)
                self.store.update_order_status(order["public_id"], "delivered", closed=True)
                self.store.record_admin_action(
                    action_type="complete_order",
                    target_type="order",
                    target_public_id=order["public_id"],
                    actor=actor,
                    meta={"transport": order["transport"], "profile_public_id": result["profile"]["public_id"]},
                )
                completed_now = True
                refreshed = self.store.get_order(order["public_id"])
                if refreshed:
                    order = refreshed
                if not result.get("subscription_url"):
                    result = self._recover_subscription_for_order(order)
            except Exception:
                if promo_reserved and promo_id:
                    self.store.restore_promo_code(int(promo_id))
                if invite_reserved and invite_id:
                    self.store.restore_invite(int(invite_id))
                raise

        if completed_now:
            try:
                ledger = self.store.create_referral_ledger_for_order(order)
                if ledger:
                    self.store.record_admin_action(
                        action_type="referral_accrual",
                        target_type="order",
                        target_public_id=order["public_id"],
                        actor="system-referral",
                        meta={
                            "referrer_id": ledger["referrer_id"],
                            "amount_rub": ledger["amount_rub"],
                            "commission_percent": ledger["commission_percent"],
                        },
                    )
            except Exception:
                LOGGER.exception("Failed to create referral accrual for order %s", order["public_id"])

            customer_email = str(order.get("customer_email") or (order.get("meta_json") or {}).get("customer_email") or "").strip()
            if customer_email:
                try:
                    web_token = str((order.get("meta_json") or {}).get("web_token") or "")
                    cabinet_url = f"{self.settings.web_public_base_url}/order/{quote(str(order['public_id']), safe='')}/{quote(web_token, safe='')}" if web_token else self.settings.web_public_base_url
                    sub_url = str(result.get("subscription_url") or "")
                    setup_url = subscription_setup_url(sub_url) if sub_url else cabinet_url
                    send_subscription_email_async(
                        self.settings,
                        customer_email=customer_email,
                        order_public_id=str(order["public_id"]),
                        plan_name=f"SilentConnect ({order.get('duration_days', 30)} дн.)",
                        duration_days=int(order.get("duration_days") or 30),
                        setup_url=setup_url,
                        json_url=sub_url,
                        cabinet_url=cabinet_url,
                        expires_ts=(result.get("profile") or {}).get("expires_at"),
                    )
                except Exception:
                    LOGGER.exception("Failed to dispatch subscription email for order %s", order["public_id"])

        customer_chat_id = order.get("customer_chat_id")
        if customer_chat_id is not None:
            self.store.link_profile_owner(
                profile_public_id=result["profile"]["public_id"],
                user_id=customer_chat_id,
                chat_id=customer_chat_id,
                source_order_public_id=order["public_id"],
            )
            context = self._context_from_session(self.store.get_session(customer_chat_id))
            context.pop("pending_promo", None)
            context.pop("pending_promo_id", None)
            context.pop("discount_promo", None)
            context.pop("discount_promo_id", None)
            context["order_public_id"] = order["public_id"]
            self._complete_action(
                customer_chat_id,
                scope="public",
                state="menu",
                context=context,
                action_key=self._public_action_key_for_order(order),
                result_kind="subscription",
                order_public_id=order["public_id"],
                profile_public_id=result["profile"]["public_id"],
                subscription_url=result["subscription_url"],
            )
            self._send_public_subscription(
                customer_chat_id,
                result["subscription_url"],
                prefix=delivery_prefix,
            )
            if order["profile_mode"] == "anonymous":
                self.store.clear_order_customer_contact(order["public_id"])
        return result

    def handle_callback(self, callback: dict[str, Any]) -> None:
        callback_id = callback["id"]
        user = callback.get("from") or {}
        data = callback.get("data") or ""
        chat = callback.get("message", {}).get("chat", {})
        chat_id = chat.get("id")
        message_id = callback.get("message", {}).get("message_id")
        self._remember_user(chat_id, user)
        try:
            if data == "admin:menu" and chat_id is not None and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id)
                self.send_admin_menu(chat_id)
                return

            if data == "public:accept_terms":
                self.telegram.answer_callback_query(callback_id)
                if chat_id is not None:
                    try:
                        self.store.record_admin_action(
                            action_type="accept_public_terms",
                            target_type="telegram_user",
                            target_public_id=str(user.get("id") or chat_id),
                            actor=f"tg:{user.get('id') or chat_id}",
                            meta={"version": "2026-04-26", "chat_id": chat_id},
                        )
                    except Exception:
                        LOGGER.exception("Failed to record terms acceptance")
                    self.show_public_menu(chat_id, message_id=message_id)
                return

            if data == "public:menu" and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                self.show_public_menu(chat_id, message_id=message_id)
                return

            if data == "public:access" and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                self.show_public_access_menu(chat_id, message_id=message_id)
                return

            if data.startswith("public:buy_devices:") and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                self.show_public_buy_duration(chat_id, int(data.split(":")[-1]), message_id=message_id)
                return

            if data.startswith("public:buy_duration:") and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                duration_days = int(data.split(":")[-1])
                session = self.store.get_session(chat_id) or {"scope": "public", "state": "buy_devices", "context_json": {}}
                context = self._context_from_session(session)
                context["buy_duration_days"] = duration_days
                context["buy_mode"] = "tcp"
                self.store.set_session(chat_id, "public", "buy_duration", context)
                self.show_public_buy_confirm(chat_id, "tcp", message_id=message_id)
                return

            if data.startswith("public:buy_mode:") and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                self.show_public_buy_confirm(chat_id, "tcp", message_id=message_id)
                return

            if data == "public:buy_confirm" and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                session = self.store.get_session(chat_id) or {"scope": "public", "state": "buy_confirm", "context_json": {}}
                context = self._context_from_session(session)
                offer = self.offers.get(self._purchase_offer_code(context))
                if not offer:
                    self.telegram.send_message(chat_id, "Не удалось собрать тариф. Попробуйте выбрать заново.")
                    self.show_public_access_menu(chat_id)
                    return
                self.create_standard_order(chat_id, offer)
                return

            if data.startswith("public:buy_back:") and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                target = data.split(":")[-1]
                session = self.store.get_session(chat_id) or {"scope": "public", "state": "menu", "context_json": {}}
                context = self._context_from_session(session)
                if target == "devices":
                    self.show_public_access_menu(chat_id, message_id=message_id)
                    return
                if target in {"duration", "mode"} and context.get("buy_device_limit"):
                    self.show_public_buy_duration(chat_id, int(context["buy_device_limit"]), message_id=message_id)
                    return
                self.show_public_access_menu(chat_id, message_id=message_id)
                return


            if data == "public:renew" and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                self.show_public_renewal(chat_id, user, message_id=message_id)
                return

            if data == "public:renew_other" and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                self.prompt_public_renewal_link(chat_id, message_id=message_id)
                return

            if data == "public:renew_promo" and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                context = self._context_from_session(self.store.get_session(chat_id))
                context["promo_return"] = "renewal"
                self.store.set_session(chat_id, "public", "await_promo_code", context)
                self._send_public_promo_prompt(chat_id, prefix="Введите скидочный промокод для продления.", message_id=message_id)
                return

            if data.startswith("public:renew_devices:") and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                self.show_public_renew_devices(chat_id, data.split(":", 2)[-1], message_id=message_id)
                return

            if data.startswith("public:renew_duration:") and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                parts = data.split(":", 3)
                if len(parts) != 4:
                    self._send_renewal_target_missing(chat_id, message_id=message_id)
                    return
                self.show_public_renew_duration(chat_id, parts[2], int(parts[3]), message_id=message_id)
                return

            if data.startswith("public:renew_preview:") and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                parts = data.split(":", 4)
                if len(parts) != 5:
                    self._send_renewal_target_missing(chat_id, message_id=message_id)
                    return
                self.show_public_renew_confirm(
                    chat_id,
                    parts[2],
                    device_limit=int(parts[3]),
                    duration_days=int(parts[4]),
                    message_id=message_id,
                )
                return

            if data.startswith("public:upgrade_devices:") and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                self.show_public_upgrade_devices(chat_id, data.split(":", 2)[-1], message_id=message_id)
                return

            if data.startswith("public:upgrade_preview:") and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                parts = data.split(":", 3)
                if len(parts) != 4:
                    self._send_renewal_target_missing(chat_id, message_id=message_id)
                    return
                self.show_public_upgrade_confirm(chat_id, parts[2], int(parts[3]), message_id=message_id)
                return

            if data.startswith("public:upgrade_confirm:") and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                parts = data.split(":", 3)
                if len(parts) != 4:
                    self._send_renewal_target_missing(chat_id)
                    return
                self.create_renewal_order(chat_id, user, parts[2], duration_days=0, device_limit=int(parts[3]), upgrade_only=True)
                return

            if data.startswith("public:renew_confirm:") and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                parts = data.split(":", 4)
                profile_public_id = parts[2] if len(parts) >= 3 else data.split(":", 2)[-1]
                duration_days = int(parts[3]) if len(parts) >= 4 else 30
                device_limit = int(parts[4]) if len(parts) >= 5 else None
                self.create_renewal_order(chat_id, user, profile_public_id, duration_days=duration_days, device_limit=device_limit)
                return

            if data == "public:trial" and chat_id is not None:
                self.telegram.answer_callback_query(callback_id, "Создаю пробный доступ")
                self.create_public_trial(chat_id, user, message_id=message_id)
                return

            if data == "public:referral" and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                self.show_public_referral(chat_id, user, message_id=message_id)
                return

            if data == "public:referral_join" and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                self.join_public_referral(chat_id, user, message_id=message_id)
                return

            if data == "public:help" and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                self.show_public_help(chat_id, message_id=message_id)
                return

            if data.startswith("public:connect:") and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                subscription_id = data.split(":", 2)[-1]
                self.show_public_connect_platform(chat_id, subscription_id)
                return

            if data.startswith("public:connect_platform:") and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                parts = data.split(":", 3)
                if len(parts) < 4:
                    self.telegram.send_message(chat_id, "Не получилось открыть настройку. Скопируйте ссылку или напишите в поддержку.")
                    return
                self.show_public_connect_apps(chat_id, parts[2], parts[3])
                return

            if data == "public:faq" and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                self.show_public_faq(chat_id, message_id=message_id)
                return

            if data == "public:rules" and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                self.show_public_rules_menu(chat_id, message_id=message_id)
                return

            if data.startswith("public:rules:") and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                self.show_public_rules_section(chat_id, data.split(":")[-1], message_id=message_id)
                return

            if data == "public:support" and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                self.show_public_support(chat_id, message_id=message_id)
                return

            if data == "public:access_compare" and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                self.show_public_access_compare(chat_id)
                return

            if data == "public:access_advanced" and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                self.show_public_access_advanced(chat_id)
                return

            if data == "public:promo" and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                waiting_order = self._fresh_active_order_for_chat(chat_id, notify_user=True)
                if waiting_order and waiting_order["status"] == "waiting_payment":
                    self._send_public_promo_switch_prompt(chat_id, waiting_order)
                    return
                if waiting_order:
                    self._send_existing_public_order(chat_id, waiting_order, prefix="Возвращаю текущий заказ.")
                    return
                self._send_public_promo_prompt(chat_id, message_id=message_id)
                return

            if data.startswith("public:promo_switch:") and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                waiting_order = self._fresh_active_order_for_chat(chat_id, notify_user=True)
                if waiting_order and waiting_order["status"] == "waiting_payment":
                    self._send_public_promo_switch_prompt(chat_id, waiting_order)
                    return
                if waiting_order:
                    self._send_existing_public_order(chat_id, waiting_order, prefix="Возвращаю текущий заказ.")
                    return
                self._send_public_promo_prompt(
                    chat_id,
                    prefix="Открытого неоплаченного заказа уже нет. Можно сразу ввести промокод.",
                )
                return

            if data.startswith("public:promo_switch_confirm:") and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                self._expire_stale_waiting_orders(chat_id, notify_user=True)
                cancelled_orders = self.store.cancel_open_orders_for_chat(chat_id, statuses=("waiting_payment",))
                self._merge_session_state(
                    chat_id,
                    "public",
                    "await_promo_code",
                    drop_keys=(ACTION_GUARD_KEY, "order_public_id", "pending_promo", "pending_promo_id"),
                )
                self._send_public_promo_prompt(
                    chat_id,
                    prefix=(
                        "Все открытые неоплаченные заказы этого чата закрыты."
                        if cancelled_orders
                        else "Открытых неоплаченных заказов уже не было."
                    ),
                )
                return

            if data.startswith("public:promo_switch_keep:") and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                waiting_order = self._fresh_active_order_for_chat(chat_id, notify_user=True)
                if waiting_order and waiting_order["status"] == "waiting_payment":
                    self._send_existing_public_order(chat_id, waiting_order, prefix="Оставляю текущий заказ.")
                    return
                if waiting_order:
                    self._send_existing_public_order(chat_id, waiting_order, prefix="Возвращаю текущий заказ.")
                    return
                self.show_public_menu(
                    chat_id,
                    "Открытых неоплаченных заказов уже нет. Можно выбрать новый вариант.",
                    drop_keys=(ACTION_GUARD_KEY, "order_public_id", "pending_promo", "pending_promo_id"),
                    message_id=message_id,
                )
                return

            if data.startswith("public:payment_sent:") and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                order_public_id = data.split(":")[-1]
                self._expire_stale_waiting_orders(chat_id, notify_user=True)
                order = self.store.get_order(order_public_id)
                if not order or str(order.get("customer_chat_id") or "") != str(chat_id):
                    self.telegram.send_message(chat_id, "Не нашёл активный заказ для этого уведомления.")
                    return
                if order.get("status") != "waiting_payment":
                    self.telegram.send_message(chat_id, "Этот заказ уже не ждёт оплаты.")
                    return
                notified = self.notify_admins_payment_reported(order, user)
                self.telegram.send_message(
                    chat_id,
                    (
                        "Спасибо, уведомление об оплате отправлено. Я проверю поступление и подтвержу заказ."
                        if notified
                        else "Уведомление об оплате уже отправлено. Я проверю поступление и подтвержу заказ."
                    ),
                    reply_markup=self._public_waiting_payment_markup(str(order["public_id"])),
                )
                return

            if data.startswith("public:cancel_waiting:") and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                self._expire_stale_waiting_orders(chat_id, notify_user=True)
                cancelled_orders = self.store.cancel_open_orders_for_chat(chat_id, statuses=("waiting_payment",))
                self.show_public_menu(
                    chat_id,
                    (
                        "Неоплаченный заказ отменён. Можно выбрать новый вариант."
                        if cancelled_orders
                        else "Открытых неоплаченных заказов уже нет. Можно выбрать новый вариант."
                    ),
                    drop_keys=(ACTION_GUARD_KEY, "order_public_id", "pending_promo", "pending_promo_id"),
                    message_id=message_id,
                )
                return

            if data.startswith("public:buy:") and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                offer_code = data.split(":")[-1]
                offer = self.offers.get(offer_code)
                if not offer:
                    self.telegram.send_message(chat_id, "Вариант доступа не найден.")
                    return
                if not self._public_has_purchase_access(chat_id):
                    self._send_access_locked(chat_id, prefix="Этот вариант пока нельзя оформить из открытой витрины.")
                    return
                self.create_standard_order(chat_id, offer)
                return

            if data == "public:family_accept" and chat_id is not None:
                self.telegram.answer_callback_query(callback_id)
                session = self.store.get_session(chat_id)
                if not session:
                    return
                promo = session["context_json"].get("pending_promo")
                if not promo:
                    return
                self.create_promo_order(chat_id, promo, session["context_json"])
                return

            if data == "public:family_decline" and chat_id is not None:
                self.telegram.answer_callback_query(callback_id, "Промокод не потрачен")
                session = self.store.get_session(chat_id)
                if session:
                    promo = session["context_json"].get("pending_promo")
                    if promo:
                        for admin_chat in self.store.list_chat_ids_by_scope("admin"):
                            self.telegram.send_message(
                                admin_chat,
                                (
                                    f"Пользователь отказался от семейного промокода `{promo['family_label']}`"
                                    " из-за приватности. Код не сожжён."
                                ),
                            )
                self.show_public_menu(chat_id, "Промокод не потрачен. Можно вернуться в витрину и выбрать другой сценарий.")
                return

            if data == "admin:server" and chat_id is not None and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id)
                self.show_admin_server(chat_id)
                return

            if data == "admin:traffic_top" and chat_id is not None and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id)
                self.show_admin_traffic_top(chat_id)
                return

            if data.startswith("admin:profile:") and chat_id is not None and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id)
                profile_public_id = data.split(":", 2)[-1]
                self.show_admin_profile(chat_id, profile_public_id)
                return

            if data.startswith("admin:profile_disable:") and chat_id is not None and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id, "Отключаю профиль")
                profile_public_id = data.split(":", 2)[-1]
                self.set_admin_profile_enabled(chat_id, profile_public_id, False, user)
                return

            if data.startswith("admin:profile_enable:") and chat_id is not None and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id, "Включаю профиль")
                profile_public_id = data.split(":", 2)[-1]
                self.set_admin_profile_enabled(chat_id, profile_public_id, True, user)
                return

            if data.startswith("admin:profile_warn:") and chat_id is not None and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id, "Отправляю предупреждение")
                profile_public_id = data.split(":", 2)[-1]
                self.warn_admin_profile_owner(chat_id, profile_public_id, user)
                return

            if data == "admin:referrals" and chat_id is not None and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id)
                self.show_admin_referrals(chat_id)
                return

            if data == "admin:public_link" and chat_id is not None and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id)
                link = self.public_access_link()
                self.telegram.send_message(
                    chat_id,
                    "\n".join(
                        [
                            "Публичная ссылка доступа:",
                            link,
                            "",
                            "Её можно публиковать или отправлять многократно. Она открывает витрину, но не привязывает реферала.",
                        ]
                    ),
                    reply_markup=kb(
                        [
                            [{"text": "Скопировать ссылку", "copy_text": link, "style": "primary"}],
                            [("Назад в админ-меню", "admin:menu", "primary")],
                        ]
                    ),
                )
                return

            if data.startswith("admin:refpay:") and chat_id is not None and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id, "Отмечаю выплату")
                referrer_id = int(data.split(":")[-1])
                self.mark_referral_paid(chat_id, referrer_id, user)
                return

            if data == "admin:share_warp" and chat_id is not None and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id)
                self._merge_session_state(chat_id, "admin", "admin_share_warp_server", {"admin": True}, drop_keys=(ACTION_GUARD_KEY,))
                nl_srv = awg_manager._get_server("nl")
                fi_srv = awg_manager._get_server("fi")
                pl_srv = awg_manager._get_server("pl")
                nl_label = f"🇳🇱 Нидерланды (NL) ({nl_srv.get('endpoint_host')}:{nl_srv.get('endpoint_port')})"
                fi_label = f"🇫🇮 Финляндия (FI) ({fi_srv.get('endpoint_host')}:{fi_srv.get('endpoint_port')})"
                pl_label = f"🇵🇱 Польша (PL) ({pl_srv.get('endpoint_host')}:{pl_srv.get('endpoint_port')})"
                self.telegram.send_message(
                    chat_id,
                    "Выберите сервер для выдачи Warp / AmneziaWG конфига:",
                    reply_markup=kb(
                        [
                            [(nl_label, "admin:share_warp_srv:nl")],
                            [(fi_label, "admin:share_warp_srv:fi")],
                            [(pl_label, "admin:share_warp_srv:pl")],
                            [("« Назад в админ-меню", "admin:menu", "primary")],
                        ]
                    ),
                )
                return

            if (data.startswith("admin:share_warp_srv:") or data.startswith("admin:warp_srv:")) and chat_id is not None and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id)
                target_server = data.split(":")[-1].lower().strip()
                server_info = awg_manager._get_server(target_server)
                server_name = server_info.get("name", target_server.upper())
                server_host = server_info.get("endpoint_host", "")
                server_port = server_info.get("endpoint_port", "")
                self._merge_session_state(
                    chat_id, "admin", "admin_wait_warp_sub_url",
                    {"admin": True, "target_server": target_server, "server_code": target_server},
                    drop_keys=(ACTION_GUARD_KEY,),
                )
                self.telegram.send_message(
                    chat_id,
                    f"Выбран сервер: {server_name} ({server_host}:{server_port})"
                    + f"\n\nПришлите ссылку подписки клиента (вида {self.settings.subscription_base_url}/<id>) или сам id."
                    + f"\n\nЕсли warp-конфиг уже привязан к {server_name} — вышлю повторно. Если нет — создам новый и привяжу к подписке (лимит 500 ГБ / 30 дней).",
                )
                return

            if data == "admin:create_invite" and chat_id is not None and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id)
                action_key = "admin:invite:default"
                session = self.store.get_session(chat_id) or {"scope": "admin", "state": "menu", "context_json": {}}
                context = self._context_from_session(session)
                context["admin"] = True
                guard = self._matching_action_guard(context, action_key)
                if guard:
                    if guard.get("status") == "completed" and self._resume_admin_action(chat_id, guard):
                        return
                    if guard.get("status") == "in_flight" and not self._action_guard_stale(guard):
                        self._notify_action_in_flight(chat_id)
                        return
                claimed, _ = self._claim_action(
                    chat_id,
                    scope="admin",
                    state=str(session.get("state") or "menu"),
                    action_key=action_key,
                    context=context,
                )
                if not claimed:
                    self._notify_action_in_flight(chat_id)
                    return
                try:
                    code, uses, days = self.create_default_invite()
                    guard = self._complete_action(
                        chat_id,
                        scope="admin",
                        state="menu",
                        context=context,
                        action_key=action_key,
                        result_kind="invite",
                        invite_code=code,
                        invite_uses=uses,
                        invite_days=days,
                    )
                    self._send_invite_result(chat_id, guard)
                except Exception:
                    self._clear_action_if_matches(chat_id, action_key)
                    raise
                return

            if data.startswith("admin:invite:") and chat_id is not None and self.is_admin(user):
                self.telegram.answer_callback_query(
                    callback_id,
                    "Кнопка устарела. Нажмите «Создать инвайт» заново.",
                    show_alert=True,
                )
                return
                self.telegram.answer_callback_query(callback_id)
                _, _, uses_raw, days_raw = data.split(":")
                uses = int(uses_raw)
                days = int(days_raw)
                expires_at = days_from_now(days)
                code, _ = self.store.create_invite(max_uses=uses, expires_at=expires_at)
                self.telegram.send_message(
                    chat_id,
                    (
                        f"Инвайт создан:\n{code}\n\n"
                        f"Срок: {days} дн.\n"
                        f"Использований: {uses}\n\n"
                        "Старая кнопка тоже отработала, но ссылка уже нормальная:\n"
                        f"{self.invite_link(code)}"
                    ),
                )
                return

            if data.startswith("admin:payment_details:") and chat_id is not None and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id)
                order_public_id = data.split(":")[-1]
                order = self.store.get_order(order_public_id)
                if order and order.get("customer_chat_id"):
                    self._expire_stale_waiting_orders(order["customer_chat_id"], notify_user=True)
                    order = self.store.get_order(order_public_id)
                if not order:
                    self.telegram.send_message(chat_id, f"Заказ {order_public_id} не найден.")
                    return
                if order.get("status") != "waiting_payment":
                    self.telegram.send_message(chat_id, f"Заказ {order_public_id} уже не ждёт оплаты.")
                    return
                self._merge_session_state(
                    chat_id,
                    "admin",
                    "admin_wait_payment_details",
                    {"admin": True, "order_public_id": order_public_id},
                )
                self.telegram.send_message(
                    chat_id,
                    (
                        f"Отправьте реквизиты одним сообщением для заказа {order_public_id}.\n"
                        "Следующее ваше сообщение бот передаст клиенту."
                    ),
                )
                return

            if data == "admin:create_personal_config" and chat_id is not None and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id)
                self._merge_session_state(chat_id, "admin", "admin_personal_transport", {"admin": True})
                self.telegram.send_message(
                    chat_id,
                    "\u0412\u044b\u0431\u0435\u0440\u0438\u0442\u0435 \u0442\u0440\u0430\u043d\u0441\u043f\u043e\u0440\u0442 \u0434\u043b\u044f \u0432\u0430\u0448\u0435\u0433\u043e \u0430\u0434\u043c\u0438\u043d-\u043a\u043e\u043d\u0444\u0438\u0433\u0430:",
                    reply_markup=kb(
                        [
                            [("XHTTP", "admin:personal_transport:xhttp")],
                            [("TCP+REALITY", "admin:personal_transport:tcp")],
                        ]
                    ),
                )
                return

            if data.startswith("admin:personal_transport:") and chat_id is not None and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id)
                transport = data.split(":")[-1]
                self.create_personal_profile_for_admin(chat_id, user, transport)
                return

            if data == "admin:create_test_config" and chat_id is not None and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id)
                self._merge_session_state(chat_id, "admin", "admin_test_transport", {"admin": True})
                self.telegram.send_message(
                    chat_id,
                    "\u0412\u044b\u0431\u0435\u0440\u0438\u0442\u0435 \u0442\u0440\u0430\u043d\u0441\u043f\u043e\u0440\u0442 \u0434\u043b\u044f 24-\u0447\u0430\u0441\u043e\u0432\u043e\u0433\u043e \u0442\u0435\u0441\u0442\u0430:",
                    reply_markup=kb(
                        [
                            [("XHTTP", "admin:test_transport:xhttp")],
                            [("TCP+REALITY", "admin:test_transport:tcp")],
                        ]
                    ),
                )
                return

            if data.startswith("admin:test_transport:") and chat_id is not None and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id)
                transport = data.split(":")[-1]
                self.create_test_profile_for_admin(chat_id, user, transport)
                return

            if data == "admin:create_hybrid_test_config" and chat_id is not None and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id, "Создаю универсальный тест")
                self.create_hybrid_test_profile_for_admin(chat_id, user)
                return

            if data == "admin:create_promo" and chat_id is not None and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id)
                self._merge_session_state(chat_id, "admin", "admin_promo_type", {"admin": True})
                self.telegram.send_message(
                    chat_id,
                    "Какой промокод создать?",
                    reply_markup=kb(
                        [
                            [("Готовый доступ", "admin:promo_type:fixed", "success")],
                            [("Скидка на любой тариф", "admin:promo_type:discount", "primary")],
                        ]
                    ),
                )
                return

            if data == "admin:promo_type:fixed" and chat_id is not None and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id)
                self._merge_session_state(chat_id, "admin", "admin_promo_transport", {"admin": True, "promo_type": "fixed"})
                self.telegram.send_message(
                    chat_id,
                    "Выберите транспорт для промокода:",
                    reply_markup=kb(
                        [
                            [("Универсальный", "admin:promo_transport:hybrid", "primary")],
                            [("XHTTP", "admin:promo_transport:xhttp")],
                            [("TCP+REALITY", "admin:promo_transport:tcp")],
                        ]
                    ),
                )
                return

            if data == "admin:promo_type:discount" and chat_id is not None and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id)
                self._merge_session_state(chat_id, "admin", "admin_promo_discount", {"admin": True, "promo_type": "discount"})
                self.telegram.send_message(
                    chat_id,
                    "Выберите размер скидки:",
                    reply_markup=kb(
                        [
                            [("10%", "admin:promo_discount:10"), ("25%", "admin:promo_discount:25")],
                            [("50%", "admin:promo_discount:50"), ("75%", "admin:promo_discount:75")],
                            [("100%", "admin:promo_discount:100")],
                        ]
                    ),
                )
                return

            if data.startswith("admin:promo_transport:") and chat_id is not None and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id)
                transport = data.split(":")[-1]
                self._merge_session_state(
                    chat_id,
                    "admin",
                    "admin_promo_device_limit",
                    {"admin": True, "promo_type": "fixed", "transport": transport},
                )
                self.telegram.send_message(
                    chat_id,
                    "Выберите лимит устройств:",
                    reply_markup=kb(
                        [
                            [("3 устройства", "admin:promo_device_limit:3")],
                            [("6 устройств", "admin:promo_device_limit:6")],
                            [("9 устройств", "admin:promo_device_limit:9")],
                            [("Без лимита", "admin:promo_device_limit:0", "primary")],
                        ]
                    ),
                )
                return

            if data.startswith("admin:promo_device_limit:") and chat_id is not None and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id)
                device_limit = int(data.split(":")[-1])
                session = self.store.get_session(chat_id) or {"context_json": {}}
                context = self._context_from_session(session)
                context["admin"] = True
                context["device_limit"] = device_limit
                self.store.set_session(chat_id, "admin", "admin_promo_duration", context)
                self._send_admin_promo_duration_prompt(chat_id)
                return

            if data == "admin:promo_months_manual" and chat_id is not None and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id)
                session = self.store.get_session(chat_id) or {"context_json": {}}
                context = self._context_from_session(session)
                context["admin"] = True
                self.store.set_session(chat_id, "admin", "admin_wait_promo_months", context)
                self.telegram.send_message(chat_id, "Отправьте точное количество месяцев целым числом, например 6.")
                return

            if data.startswith("admin:promo_months:") and chat_id is not None and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id)
                months = int(data.split(":")[-1])
                session = self.store.get_session(chat_id) or {"context_json": {}}
                context = self._context_from_session(session)
                self._set_admin_promo_duration(
                    chat_id,
                    context,
                    duration_days=months * 30,
                    duration_months=months,
                )
                return

            if data.startswith("admin:promo_duration:") and chat_id is not None and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id)
                duration_days = int(data.split(":")[-1])
                session = self.store.get_session(chat_id) or {"context_json": {}}
                context = self._context_from_session(session)
                self._set_admin_promo_duration(chat_id, context, duration_days=duration_days)
                return

            if data == "admin:promo_price:manual" and chat_id is not None and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id)
                session = self.store.get_session(chat_id) or {"context_json": {}}
                context = self._context_from_session(session)
                context["admin"] = True
                self.store.set_session(chat_id, "admin", "admin_wait_promo_price", context)
                self.telegram.send_message(chat_id, "Отправьте итоговую цену в рублях целым числом, например 1000.")
                return

            if data == "admin:promo_price:regular" and chat_id is not None and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id)
                session = self.store.get_session(chat_id) or {"context_json": {}}
                context = self._context_from_session(session)
                self._set_admin_promo_price(chat_id, context, discount_percent=0)
                return

            if data == "admin:promo_price:free" and chat_id is not None and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id)
                session = self.store.get_session(chat_id) or {"context_json": {}}
                context = self._context_from_session(session)
                self._set_admin_promo_price(chat_id, context, fixed_price_rub=0)
                return

            if data.startswith("admin:promo_discount:") and chat_id is not None and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id)
                discount_percent = int(data.split(":")[-1])
                session = self.store.get_session(chat_id) or {"context_json": {}}
                context = self._context_from_session(session)
                context["admin"] = True
                context["discount_percent"] = discount_percent
                if context.get("promo_type") == "discount":
                    action_key = self._admin_promo_action_key(
                        "any",
                        0,
                        discount_percent,
                        "anonymous",
                        promo_type="discount",
                    )
                    guard = self._matching_action_guard(context, action_key)
                    if guard:
                        if guard.get("status") == "completed" and self._resume_admin_action(chat_id, guard):
                            return
                        if guard.get("status") == "in_flight" and not self._action_guard_stale(guard):
                            self._notify_action_in_flight(chat_id)
                            return
                    claimed, _ = self._claim_action(
                        chat_id,
                        scope="admin",
                        state=str(session.get("state") or "admin_promo_discount"),
                        action_key=action_key,
                        context=context,
                    )
                    if not claimed:
                        self._notify_action_in_flight(chat_id)
                        return
                    try:
                        code, _ = self.store.create_promo_code(
                            promo_type="discount",
                            transport="any",
                            duration_days=0,
                            discount_percent=discount_percent,
                            device_limit=self.settings.default_device_limit,
                            profile_mode="anonymous",
                            max_uses=1,
                        )
                        guard = self._complete_action(
                            chat_id,
                            scope="admin",
                            state="menu",
                            context=context,
                            action_key=action_key,
                            result_kind="promo",
                            promo_code=code,
                            promo_type="discount",
                            discount_percent=discount_percent,
                            profile_mode="anonymous",
                        )
                        self._send_promo_result(chat_id, guard)
                    except Exception:
                        self._clear_action_if_matches(chat_id, action_key)
                        raise
                    return

                self._set_admin_promo_price(chat_id, context, discount_percent=discount_percent)
                return

            if data == "admin:promo_mode:anonymous" and chat_id is not None and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id)
                session = self.store.get_session(chat_id) or {"scope": "admin", "state": "admin_promo_mode", "context_json": {}}
                context = self._context_from_session(session)
                context["admin"] = True
                action_key = self._admin_promo_action_key(
                    str(context["transport"]),
                    int(context["duration_days"]),
                    int(context["discount_percent"]),
                    "anonymous",
                    int(context.get("device_limit", self.settings.default_device_limit)),
                    fixed_price_rub=context.get("fixed_price_rub"),
                )
                guard = self._matching_action_guard(context, action_key)
                if guard:
                    if guard.get("status") == "completed" and self._resume_admin_action(chat_id, guard):
                        return
                    if guard.get("status") == "in_flight" and not self._action_guard_stale(guard):
                        self._notify_action_in_flight(chat_id)
                        return
                claimed, _ = self._claim_action(
                    chat_id,
                    scope="admin",
                    state=str(session.get("state") or "admin_promo_mode"),
                    action_key=action_key,
                    context=context,
                )
                if not claimed:
                    self._notify_action_in_flight(chat_id)
                    return
                try:
                    code, _ = self.store.create_promo_code(
                        promo_type="fixed",
                        transport=context["transport"],
                        duration_days=context["duration_days"],
                        duration_months=context.get("duration_months"),
                        discount_percent=context["discount_percent"],
                        fixed_price_rub=context.get("fixed_price_rub"),
                        device_limit=int(context.get("device_limit", self.settings.default_device_limit)),
                        profile_mode="anonymous",
                        max_uses=1,
                    )
                    guard = self._complete_action(
                        chat_id,
                        scope="admin",
                        state="menu",
                        context=context,
                        action_key=action_key,
                        result_kind="promo",
                        promo_code=code,
                        promo_type="fixed",
                        transport=context["transport"],
                        duration_days=int(context["duration_days"]),
                        duration_months=context.get("duration_months"),
                        discount_percent=int(context["discount_percent"]),
                        fixed_price_rub=context.get("fixed_price_rub"),
                        device_limit=int(context.get("device_limit", self.settings.default_device_limit)),
                        profile_mode="anonymous",
                    )
                    self._send_promo_result(chat_id, guard)
                except Exception:
                    self._clear_action_if_matches(chat_id, action_key)
                    raise
                return

            if data == "admin:promo_mode:family" and chat_id is not None and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id)
                session = self.store.get_session(chat_id) or {"context_json": {}}
                context = self._context_from_session(session)
                context["admin"] = True
                self.store.set_session(chat_id, "admin", "admin_wait_family_label", context)
                self.telegram.send_message(chat_id, "Отправьте подпись профиля, например babuska1")
                return

            if data.startswith("admin:confirm:") and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id, "Оплата подтверждается")
                order_public_id = data.split(":")[-1]
                order = self.store.get_order(order_public_id)
                if order and order.get("customer_chat_id"):
                    self._expire_stale_waiting_orders(order["customer_chat_id"], notify_user=True)
                    order = self.store.get_order(order_public_id)
                if not order:
                    if chat_id is not None:
                        self.telegram.send_message(chat_id, f"Заказ {order_public_id} не найден.")
                    return
                if chat_id is not None:
                    action_key = f"admin:confirm:{order_public_id}"
                    session = self.store.get_session(chat_id) or {"scope": "admin", "state": "menu", "context_json": {}}
                    context = self._context_from_session(session)
                    context["admin"] = True
                    guard = self._matching_action_guard(context, action_key)
                    if guard:
                        if guard.get("status") == "completed" and self._resume_admin_action(chat_id, guard):
                            return
                        if guard.get("status") == "in_flight" and not self._action_guard_stale(guard):
                            self._notify_action_in_flight(chat_id)
                            return
                    claimed, _ = self._claim_action(
                        chat_id,
                        scope="admin",
                        state=str(session.get("state") or "menu"),
                        action_key=action_key,
                        context=context,
                    )
                    if not claimed:
                        self._notify_action_in_flight(chat_id)
                        return
                if order.get("status") == "cancelled":
                    if chat_id is not None:
                        self._complete_action(
                            chat_id,
                            scope="admin",
                            state="menu",
                            context=context,
                            action_key=action_key,
                            result_kind="order_state",
                            order_public_id=order_public_id,
                            order_status="cancelled",
                        )
                        self.telegram.send_message(chat_id, f"Заказ {order_public_id} уже отменён.")
                    return
                if order.get("status") == "delivered":
                    if order.get("customer_chat_id"):
                        result = self._recover_subscription_for_order(order)
                        self._send_public_subscription(
                            order["customer_chat_id"],
                            result["subscription_url"],
                            prefix="Ссылка уже была создана, отправляю повторно.",
                        )
                        if order["profile_mode"] == "anonymous":
                            self.store.clear_order_customer_contact(order_public_id)
                    if chat_id is not None:
                        self._complete_action(
                            chat_id,
                            scope="admin",
                            state="menu",
                            context=context,
                            action_key=action_key,
                            result_kind="order_state",
                            order_public_id=order_public_id,
                            order_status="delivered",
                        )
                        self.telegram.send_message(chat_id, f"Заказ {order_public_id} уже завершён.")
                    return
                self.complete_order(order, actor=f"tg:{user.get('id')}")
                if chat_id is not None:
                    self._complete_action(
                        chat_id,
                        scope="admin",
                        state="menu",
                        context=context,
                        action_key=action_key,
                        result_kind="order_state",
                        order_public_id=order_public_id,
                        order_status="delivered",
                    )
                    self.telegram.send_message(chat_id, f"Заказ {order_public_id} завершён.")
                return

            if data.startswith("admin:cancel:") and self.is_admin(user):
                self.telegram.answer_callback_query(callback_id, "Заказ отменён")
                order_public_id = data.split(":")[-1]
                order = self.store.get_order(order_public_id)
                if order and order.get("customer_chat_id"):
                    self._expire_stale_waiting_orders(order["customer_chat_id"], notify_user=True)
                    order = self.store.get_order(order_public_id)
                if not order:
                    if chat_id is not None:
                        self.telegram.send_message(chat_id, f"Заказ {order_public_id} не найден.")
                    return
                if chat_id is not None:
                    action_key = f"admin:cancel:{order_public_id}"
                    session = self.store.get_session(chat_id) or {"scope": "admin", "state": "menu", "context_json": {}}
                    context = self._context_from_session(session)
                    context["admin"] = True
                    guard = self._matching_action_guard(context, action_key)
                    if guard:
                        if guard.get("status") == "completed" and self._resume_admin_action(chat_id, guard):
                            return
                        if guard.get("status") == "in_flight" and not self._action_guard_stale(guard):
                            self._notify_action_in_flight(chat_id)
                            return
                    claimed, _ = self._claim_action(
                        chat_id,
                        scope="admin",
                        state=str(session.get("state") or "menu"),
                        action_key=action_key,
                        context=context,
                    )
                    if not claimed:
                        self._notify_action_in_flight(chat_id)
                        return
                if order.get("status") == "delivered":
                    if chat_id is not None:
                        self._complete_action(
                            chat_id,
                            scope="admin",
                            state="menu",
                            context=context,
                            action_key=action_key,
                            result_kind="order_state",
                            order_public_id=order_public_id,
                            order_status="delivered",
                        )
                        self.telegram.send_message(chat_id, f"Заказ {order_public_id} уже завершён.")
                    return
                if order.get("status") == "cancelled":
                    if chat_id is not None:
                        self._complete_action(
                            chat_id,
                            scope="admin",
                            state="menu",
                            context=context,
                            action_key=action_key,
                            result_kind="order_state",
                            order_public_id=order_public_id,
                            order_status="cancelled",
                        )
                        self.telegram.send_message(chat_id, f"Заказ {order_public_id} уже отменён.")
                    return
                self.store.update_order_status(order_public_id, "cancelled", closed=True)
                self.store.record_admin_action(
                    action_type="cancel_order",
                    target_type="order",
                    target_public_id=order_public_id,
                    actor=f"tg:{user.get('id')}",
                )
                if order.get("customer_chat_id"):
                    self._merge_session_state(
                        order["customer_chat_id"],
                        "public",
                        "menu",
                        drop_keys=(ACTION_GUARD_KEY, "order_public_id", "pending_promo", "pending_promo_id"),
                    )
                    self.telegram.send_message(order["customer_chat_id"], "Заказ отменён. Если нужно, создайте новый.")
                if chat_id is not None:
                    self._complete_action(
                        chat_id,
                        scope="admin",
                        state="menu",
                        context=context,
                        action_key=action_key,
                        result_kind="order_state",
                        order_public_id=order_public_id,
                        order_status="cancelled",
                    )
                    self.telegram.send_message(chat_id, f"Заказ {order_public_id} отменён.")
                return

            self.telegram.answer_callback_query(callback_id, "Неизвестное действие", show_alert=True)
        except Exception:
            LOGGER.exception("Callback handling failed")
            self.telegram.answer_callback_query(callback_id, "Ошибка выполнения", show_alert=True)
            if chat_id is not None:
                self.telegram.send_message(
                    chat_id,
                    "Действие временно не завершилось. Повторный клик не создаст дубликат. Попробуйте ещё раз через 10-20 сек.",
                )
