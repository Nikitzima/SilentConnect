from __future__ import annotations

from collections import OrderedDict
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import html
import json
import logging
from pathlib import Path
import re
import secrets
import threading
import time
from typing import Any
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, quote, urlencode, urlsplit, urlunsplit
import urllib.request

from .catalog import Offer, build_offers
from .config import REFERRAL_COOKIE_MAX_AGE, REFERRAL_COOKIE_NAME, REFERRAL_INVITEE_DISCOUNT_PERCENT, Settings, load_settings
from .mailer import send_subscription_email_async, send_cabinet_access_email_async
from .platega import PlategaClient
import hashlib
from .provisioning import Provisioner
from .security import client_ip_from_headers, hash_token, is_allowed_host, random_web_token, sign_token, verify_token,  now_ts
from .store import Store
from .telegram_api import TelegramBotClient, TelegramApiError


LOGGER = logging.getLogger("vpn-shop-web")
PAYMENT_REPORT_REPEAT_SECONDS = 10 * 60
TEMP_NETWORK_NOTICE = ""
WEB_RATE_LIMIT_MAX_ENTRIES = 10000
MAX_JSON_BODY_BYTES = 16 * 1024
SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("Referrer-Policy", "no-referrer"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    (
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; "
        "frame-src https://challenges.cloudflare.com; connect-src 'self'; "
        "form-action 'self' https://t.me; base-uri 'self'; frame-ancestors 'none'",
    ),
)


def money(value: int | str | None) -> str:
    return f"{int(value or 0)} RUB"


def transport_label(transport: str) -> str:
    if transport == "xhttp":
        return "XHTTP"
    if transport == "tcp":
        return "Стандартный"
    if transport == "hybrid":
        return "Универсальный"
    return transport


def device_limit_label(device_limit: int | str | None) -> str:
    limit = int(device_limit or 0)
    if limit <= 0:
        return "3 устройства"
    if limit == 1:
        return "1 устройство"
    if 2 <= limit <= 4:
        return f"{limit} устройства"
    return f"{limit} устройств"


def verify_cf_turnstile(secret_key: str, response_token: str, client_ip: str = "") -> bool:
    if not secret_key:
        LOGGER.warning("CF_TURNSTILE_SECRET_KEY is not configured - Turnstile verification disabled")
        return True
    if not str(response_token or "").strip():
        LOGGER.warning("Turnstile token is empty while secret key is configured - rejecting request (fail-closed)")
        return False
    try:
        post_data = urlencode({
            "secret": secret_key,
            "response": response_token.strip(),
            "remoteip": client_ip,
        }).encode("utf-8")
        req = urllib.request.Request(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=post_data,
            headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "SilentConnectWeb/1.0"},
        )
        with urllib.request.urlopen(req, timeout=5) as res:
            resp_body = res.read().decode("utf-8")
            parsed = json.loads(resp_body)
            return bool(parsed.get("success"))
    except Exception as exc:
        LOGGER.exception("Failed to verify Cloudflare Turnstile token: %s", exc)
        return False


def public_origin(headers: Any, fallback: str, allowed_hosts: tuple[str, ...] = ()) -> str:
    """Build the public origin *without* trusting an arbitrary Host header.

    v1 reflected X-Forwarded-Host/Host verbatim into links that are e-mailed to
    customers and pushed to admins (Host header injection / link poisoning,
    audit S-03). We now only accept hosts from ALLOWED_HOSTS (or the host of
    WEB_PUBLIC_BASE_URL) and otherwise fall back to the configured base URL.
    """
    fallback = fallback.rstrip("/")
    allow = set(h.lower() for h in allowed_hosts if h)
    try:
        fallback_host = urlsplit(fallback).hostname or ""
    except ValueError:
        fallback_host = ""
    if fallback_host:
        allow.add(fallback_host.lower())
    host = str(headers.get("X-Forwarded-Host") or headers.get("Host") or "").split(",")[0].strip()
    if host and is_allowed_host(host, allow):
        proto = str(headers.get("X-Forwarded-Proto") or "https").split(",")[0].strip().lower()
        if proto not in {"http", "https"}:
            proto = "https"
        return f"{proto}://{host.lower()}"
    return fallback


def subscription_import_url(subscription_url: str, target: str) -> str:
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


def subscription_setup_url(subscription_url: str) -> str:
    parsed = urlsplit(subscription_url)
    parts = [segment for segment in parsed.path.split("/") if segment]
    if len(parts) >= 3:
        sub_id = parts[-1]
        base_parts = parts[:-2]
        import_path = "/" + "/".join([*base_parts, "import", quote(sub_id, safe="~")])
    else:
        sub_id = parts[-1] if parts else ""
        import_path = f"/import/{quote(sub_id, safe='~')}"
    return urlunsplit((parsed.scheme, parsed.netloc, import_path, "", ""))


def subscription_url_for_route(base_url: str, route: str, subscription_id: str) -> str:
    parsed = urlsplit(base_url)
    base_parts = [segment for segment in parsed.path.split("/") if segment]
    if base_parts:
        base_parts = base_parts[:-1]
    path = "/" + "/".join([*base_parts, route, quote(subscription_id, safe="~")])
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def inline_admin_markup(order_public_id: str) -> dict[str, Any]:
    return {
        "inline_keyboard": [
            [{"text": "Подтвердить оплату", "callback_data": f"admin:confirm:{order_public_id}", "style": "success"}],
            [{"text": "Отменить заказ", "callback_data": f"admin:cancel:{order_public_id}", "style": "danger"}],
        ]
    }


class WebCheckout:
    def __init__(self, settings: Settings, store: Store) -> None:
        self.settings = settings
        self.store = store
        self.store.init()
        self.offers = build_offers(settings)
        self.provisioner = Provisioner(settings, store)
        self.telegram = TelegramBotClient(settings.telegram_bot_token) if settings.telegram_bot_token else None
        self.platega = PlategaClient(
            merchant_id_bot=settings.platega_merchant_id_bot,
            merchant_id_web=settings.platega_merchant_id_web,
            secret=settings.platega_secret,
            secret_bot=settings.platega_secret_bot,
            secret_web=settings.platega_secret_web,
        )
        self._bot: Any = None

    @property
    def bot(self) -> Any:
        if self._bot is None:
            from .bot import ShopBot
            self._bot = ShopBot(self.settings, self.store)
        return self._bot

    def get_or_create_platega_payment_url(
        self,
        order: dict[str, Any],
        *,
        return_url: str = "",
        failed_url: str = "",
    ) -> str:
        if not self.settings.platega_enabled or not self.platega.is_configured:
            return ""
        meta = dict(order.get("meta_json") or {})
        existing_url = str(meta.get("platega_url") or "").strip()
        if existing_url:
            return existing_url
        try:
            amount = int(order.get("final_price_rub") or 0)
            if amount <= 0:
                return ""
            duration = int(order.get("duration_days") or 30)
            desc = f"SilentConnect #{order['public_id']} ({duration} дн.)"
            tx = self.platega.create_transaction(
                amount=amount,
                currency="RUB",
                description=desc,
                payload=str(order["public_id"]),
                return_url=return_url,
                failed_url=failed_url,
                metadata={
                    "order_id": str(order["public_id"]),
                    "customer_email": str(order.get("customer_email") or ""),
                },
                is_bot=False,
            )
            url = str(tx.get("url") or "").strip()
            tx_id = str(tx.get("transactionId") or "").strip()
            if url:
                meta["platega_url"] = url
                if tx_id:
                    meta["platega_transaction_id"] = tx_id
                self.store.update_order_meta(str(order["public_id"]), meta)
                return url
        except Exception:
            LOGGER.exception("Failed to create Platega payment URL for web order %s", order["public_id"])
        return ""

    def handle_platega_callback(self, data: dict[str, Any], raw_body: bytes = b"") -> dict[str, Any]:
        status = str(data.get("status") or "").strip().upper()
        tx_id = str(data.get("id") or data.get("transactionId") or "").strip()
        raw_amount = data.get("amount") if data.get("amount") is not None else (data.get("paymentDetails") or {}).get("amount")
        try:
            amount = float(raw_amount) if raw_amount is not None else 0.0
        except (ValueError, TypeError):
            amount = 0.0

        order_id_hint = str(data.get("payload") or "").strip()
        meta_payload = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
        order_public_id = order_id_hint or str(meta_payload.get("order_id") or "").strip()

        order: dict[str, Any] | None = None
        if order_public_id:
            order = self.store.get_order(order_public_id)
        if not order and tx_id:
            order = self.store.get_order_by_platega_tx_id(tx_id)

        if not order:
            LOGGER.warning("Platega callback order not found: hint=%r tx_id=%r", order_id_hint, tx_id)
            return {"status": "error", "message": "order_not_found"}

        order_public_id = str(order["public_id"])
        event_id = f"{tx_id}:{status}" if tx_id else f"{order_public_id}:{status}"

        payload_sha256 = hashlib.sha256(raw_body).hexdigest() if raw_body else None
        reserved = self.store.record_webhook_event(
            gateway="platega",
            event_id=event_id,
            event_type=status,
            order_public_id=order_public_id,
            payload_sha256=payload_sha256,
        )
        if not reserved:
            LOGGER.info("Platega webhook event %s already processed or duplicate", event_id)
            return {"status": "ok", "message": "duplicate_ignored"}

        try:
            if order.get("status") == "delivered":
                LOGGER.info("Order %s already delivered, acknowledging callback", order_public_id)
                self.store.finish_webhook_event("platega", event_id, ok=True)
                return {"status": "ok", "message": "already_delivered"}

            if status == "CONFIRMED":
                expected_rub = int(order.get("final_price_rub") or 0)
                if amount > 0 and expected_rub > 0 and amount < (expected_rub - 0.5):
                    err_msg = f"Amount mismatch: received {amount}, expected {expected_rub}"
                    LOGGER.error("Platega callback for order %s: %s", order_public_id, err_msg)
                    self.store.finish_webhook_event("platega", event_id, ok=False, error=err_msg)
                    return {"status": "error", "message": "amount_too_low"}

                meta = dict(order.get("meta_json") or {})
                if tx_id:
                    meta["platega_transaction_id"] = tx_id
                meta["platega_confirmed_at"] = now_ts()
                meta["platega_confirmed_amount"] = amount
                self.store.update_order_meta(order_public_id, meta)

                self.bot.complete_order(order, actor="platega_webhook")
                self.store.finish_webhook_event("platega", event_id, ok=True)
                LOGGER.info("Order %s confirmed and delivered via Platega callback", order_public_id)
                return {"status": "ok", "message": "confirmed", "order_id": order_public_id}

            elif status in ("CANCELED", "CANCELLED", "FAILED"):
                meta = dict(order.get("meta_json") or {})
                meta["platega_status"] = status
                self.store.update_order_meta(order_public_id, meta)
                self.store.finish_webhook_event("platega", event_id, ok=True)
                LOGGER.info("Order %s marked as %s in Platega", order_public_id, status)
                return {"status": "ok", "message": status.lower(), "order_id": order_public_id}

            else:
                self.store.finish_webhook_event("platega", event_id, ok=True)
                return {"status": "ok", "message": f"status_{status.lower()}", "order_id": order_public_id}
        except Exception as exc:
            LOGGER.exception("Error processing Platega webhook for order %s: %s", order_public_id, exc)
            self.store.finish_webhook_event("platega", event_id, ok=False, error=str(exc))
            raise

    @property
    def support_url(self) -> str:
        return self.settings.support_tg_url or "https://t.me/SilentConnectHelp"

    @property
    def bot_url(self) -> str:
        username = self.settings.telegram_bot_username or "SilentConnectVPNBot"
        return f"https://t.me/{username}?start=open"

    def payment_transfer_url(self, order: dict[str, Any] | None = None) -> str:
        return (self.settings.payment_transfer_url or "").strip()

    def payment_bank_note(self) -> str:
        return (
            (self.settings.payment_bank_note or "").strip()
            or "Приоритетно переводить в МТС Банк. Если удобнее, можно Ozon Банк или Т-Банк."
        )

    def order_url(self, headers: Any, order: dict[str, Any]) -> str:
        token = str((order.get("meta_json") or {}).get("web_token") or "")
        return f"{public_origin(headers, self.settings.web_public_base_url, getattr(self.settings, 'allowed_hosts', ()))}/order/{quote(str(order['public_id']))}/{quote(token)}"

    def claim_url(self, order: dict[str, Any]) -> str:
        username = self.settings.telegram_bot_username or "SilentConnectVPNBot"
        token = str((order.get("meta_json") or {}).get("web_token") or "")
        return f"https://t.me/{username}?start=claim_{order['public_id']}_{token}"

    def recover_profile_sub_id(self, profile_public_id: str) -> str | None:
        profile = self.store.get_profile(profile_public_id)
        if not profile:
            return None
        found = self.provisioner.xui_db.find_client_by_email(str(profile["xui_email"]))
        if not found:
            return None
        sub_id = str((found.get("client") or {}).get("subId") or "")
        return sub_id or None

    def recover_subscription(self, order: dict[str, Any]) -> str | None:
        meta = order.get("meta_json") or {}
        if meta.get("hybrid") and meta.get("tcp_profile_public_id") and meta.get("xhttp_profile_public_id"):
            tcp_sub_id = self.recover_profile_sub_id(str(meta["tcp_profile_public_id"]))
            xhttp_sub_id = self.recover_profile_sub_id(str(meta["xhttp_profile_public_id"]))
            if not tcp_sub_id or not xhttp_sub_id:
                return None
            return subscription_url_for_route(
                self.settings.subscription_base_url,
                "json-hybrid",
                f"{tcp_sub_id}~{xhttp_sub_id}",
            )
        profile = self.store.get_profile_for_order(str(order["public_id"]))
        if not profile:
            return None
        found = self.provisioner.xui_db.find_client_by_email(str(profile["xui_email"]))
        if not found:
            return None
        sub_id = str((found.get("client") or {}).get("subId") or "")
        if not sub_id:
            return None
        return f"{self.settings.subscription_base_url}/{quote(sub_id, safe='')}"

    def offer_by_code(self, code: str) -> Offer:
        offer = self.offers.get(code)
        if not offer:
            raise ValueError("unknown offer")
        return offer

    @staticmethod
    def promo_type(promo: dict[str, Any]) -> str:
        return str(promo.get("promo_type") or "fixed")

    def promo_device_limit(self, promo: dict[str, Any]) -> int:
        if promo.get("device_limit") is not None:
            return int(promo["device_limit"])
        return int(self.settings.default_device_limit)

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
        from .catalog import quote_price
        limit = int(self.settings.default_device_limit if device_limit is None else device_limit)
        return quote_price(limit, duration_days, settings=self.settings)

    @staticmethod
    def fixed_promo_final_price(promo: dict[str, Any], base_price: int) -> int:
        fixed_price = promo.get("fixed_price_rub")
        if fixed_price is not None:
            return max(int(fixed_price), 0)
        return max(int(base_price) * (100 - int(promo["discount_percent"])) // 100, 0)

    def load_valid_promo(self, code: str) -> dict[str, Any]:
        promo = self.store.find_valid_promo(code.strip())
        if not promo:
            raise ValueError("Промокод не найден или уже недействителен.")
        return promo

    def ensure_promo_not_reserved(self, promo: dict[str, Any]) -> None:
        reserved = self.store.get_open_order_for_promo(int(promo["id"]))
        if reserved:
            raise ValueError("Промокод уже применён в другом открытом заказе. Если это ошибка, напишите в поддержку.")

    def maybe_auto_deliver_free_web_order(self, order: dict[str, Any]) -> dict[str, Any]:
        if int(order.get("final_price_rub") or 0) > 0:
            return order

        promo_id = order.get("promo_id")
        invite_id = order.get("invite_id")
        promo_reserved = False
        invite_reserved = False

        if promo_id:
            consumed = self.store.consume_promo_code(int(promo_id))
            if not consumed:
                raise ValueError("Промокод больше недоступен или исчерпан.")
            promo_reserved = True

        if invite_id:
            consumed = self.store.consume_invite(int(invite_id))
            if not consumed:
                if promo_reserved:
                    self.store.restore_promo_code(int(promo_id))
                raise ValueError("Инвайт-код больше недоступен или исчерпан.")
            invite_reserved = True

        try:
            result = self.provisioner.create_profile_for_order(order)
            self.store.update_order_status(str(order["public_id"]), "delivered", closed=True)
            self.store.record_admin_action(
                action_type="web_auto_free_order",
                target_type="order",
                target_public_id=str(order["public_id"]),
                actor="web",
                meta={"transport": order["transport"], "profile_public_id": result["profile"]["public_id"]},
            )
        except Exception:
            if promo_reserved and promo_id:
                self.store.restore_promo_code(int(promo_id))
            if invite_reserved and invite_id:
                self.store.restore_invite(int(invite_id))
            raise
        delivered = self.store.get_order(str(order["public_id"])) or order
        customer_email = str(delivered.get("customer_email") or (delivered.get("meta_json") or {}).get("customer_email") or "").strip()
        if customer_email:
            try:
                sub_url = self.recover_subscription(delivered) or ""
                setup_url = subscription_setup_url(sub_url) if sub_url else self.settings.web_public_base_url
                web_token = str((delivered.get("meta_json") or {}).get("web_token") or "")
                cabinet_url = f"{self.settings.web_public_base_url}/order/{quote(str(delivered['public_id']), safe='')}/{quote(web_token, safe='')}" if web_token else self.settings.web_public_base_url
                send_subscription_email_async(
                    self.settings,
                    customer_email=customer_email,
                    order_public_id=str(delivered["public_id"]),
                    plan_name=f"SilentConnect ({delivered.get('duration_days', 30)} дн.)",
                    duration_days=int(delivered.get("duration_days") or 30),
                    setup_url=setup_url,
                    json_url=sub_url,
                    cabinet_url=cabinet_url,
                )
            except Exception:
                LOGGER.exception("Failed to send auto free order email for %s", delivered["public_id"])
        return delivered

    def create_order(
        self,
        offer_code: str,
        promo_code: str = "",
        customer_email: str = "",
        ref_code: str = "",
    ) -> dict[str, Any]:
        offer = self.offer_by_code(offer_code)
        promo = self.load_valid_promo(promo_code) if promo_code.strip() else None
        if promo and self.promo_type(promo) != "discount":
            return self.create_promo_order(promo_code, customer_email=customer_email)
        if promo:
            self.ensure_promo_not_reserved(promo)
        promo_discount = int(promo["discount_percent"]) if promo else 0

        ref_discount = 0
        referrer = None
        clean_ref = ref_code.strip()
        clean_email = customer_email.strip()
        if clean_ref:
            referrer = self.store.get_referrer_by_code(clean_ref)
            if referrer:
                prior_paid = self.store.count_delivered_paid_orders(customer_email=clean_email) if clean_email else 0
                if prior_paid == 0:
                    ref_discount = REFERRAL_INVITEE_DISCOUNT_PERCENT

        discount_percent = max(promo_discount, ref_discount)
        final_price = max(offer.price_rub * (100 - discount_percent) // 100, 0)
        token = random_web_token()
        meta = {
            "source": offer.code,
            "device_limit": offer.device_limit,
            "web": True,
            "web_token": "",  # persisted as web_token_hash (audit S-02)
            "customer_email": clean_email,
        }
        if promo:
            meta["promo_type"] = "discount"
        if referrer and ref_discount > 0:
            meta["referrer_id"] = int(referrer["id"])
            meta["referrer_code"] = str(referrer["code"])
            meta["referral_discount"] = ref_discount
            if clean_email:
                self.store.attach_referral(
                    code=str(referrer["code"]),
                    referred_user_id=clean_email,
                    referred_chat_id=clean_email,
                )

        order = self.store.create_order(
            kind="purchase",
            status="waiting_payment" if final_price > 0 else "auto_provision",
            transport=offer.transport,
            duration_days=offer.duration_days,
            profile_mode=offer.profile_mode,
            family_label=None,
            base_price_rub=offer.price_rub,
            final_price_rub=final_price,
            promo_id=int(promo["id"]) if promo else None,
            invite_id=None,
            customer_chat_id=None,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version=self.settings.terms_version,
            customer_email=clean_email,
            meta=meta,
        )
        order = self._attach_web_token(order, token)
        delivered = self.maybe_auto_deliver_free_web_order(order)
        if delivered.get("status") == "waiting_payment":
            self._notify_admins_new_web_order(delivered)
        return delivered

    def create_promo_order(self, promo_code: str, customer_email: str = "") -> dict[str, Any]:
        promo = self.load_valid_promo(promo_code)
        if self.promo_type(promo) == "discount":
            raise ValueError("Промокод принят как скидка. Выберите тариф ниже, и цена пересчитается.")
        self.ensure_promo_not_reserved(promo)
        token = random_web_token()
        duration_days = int(promo["duration_days"])
        device_limit = self.promo_device_limit(promo)
        base_price = self.base_price_for_duration(str(promo["transport"]), duration_days, device_limit=device_limit)
        final_price = self.fixed_promo_final_price(promo, base_price)
        meta = {
            "source": "web_promo",
            "promo_type": "fixed",
            "device_limit": device_limit,
            "web": True,
            "web_token": "",  # persisted as web_token_hash (audit S-02)
            "customer_email": customer_email.strip(),
        }
        if promo.get("duration_months"):
            meta["duration_months"] = int(promo["duration_months"])
        if promo.get("fixed_price_rub") is not None:
            meta["fixed_price_rub"] = int(promo["fixed_price_rub"])
        order = self.store.create_order(
            kind="purchase",
            status="waiting_payment" if final_price > 0 else "auto_provision",
            transport=str(promo["transport"]),
            duration_days=duration_days,
            profile_mode=str(promo["profile_mode"]),
            family_label=promo.get("family_label"),
            base_price_rub=base_price,
            final_price_rub=final_price,
            promo_id=int(promo["id"]),
            invite_id=None,
            customer_chat_id=None,
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version=self.settings.terms_version,
            customer_email=customer_email.strip(),
            meta=meta,
        )
        order = self._attach_web_token(order, token)
        delivered = self.maybe_auto_deliver_free_web_order(order)
        if delivered.get("status") == "waiting_payment":
            self._notify_admins_new_web_order(delivered)
        return delivered

    def create_web_renewal_order(
        self,
        *,
        sub_id: str,
        duration_days: int,
        promo_code: str = "",
        customer_email: str = "",
        email_reminders: bool = True,
    ) -> dict[str, Any]:
        found = self.provisioner.xui_db.find_client_by_sub_id(sub_id)
        if not found:
            raise ValueError("Подписка не найдена на сервере.")
        email = str((found.get("client") or {}).get("email") or "")
        profile = self.store.get_profile_by_xui_email(email)
        if not profile or profile.get("status") == "deleted":
            raise ValueError("Профиль подписки не найден или удалён.")

        order_for_profile = self.store.get_order_for_profile(str(profile["public_id"]))
        source_meta = (order_for_profile or {}).get("meta_json") or {}
        device_limit = int(source_meta.get("device_limit") or self.settings.default_device_limit)
        transport = str(profile.get("transport") or "tcp")

        promo = self.load_valid_promo(promo_code) if promo_code.strip() else None
        discount_percent = int(promo["discount_percent"]) if promo else 0

        base_price = self.base_price_for_duration(transport, duration_days, device_limit=device_limit)
        final_price = max(base_price * (100 - discount_percent) // 100, 0)
        token = random_web_token()

        final_email = customer_email.strip() or str((order_for_profile or {}).get("customer_email") or "")

        meta = {
            "source": f"web_renewal_{sub_id}",
            "device_limit": device_limit,
            "web": True,
            "web_token": "",  # persisted as web_token_hash (audit S-02)
            "customer_email": final_email,
            "renewal_profile_public_id": str(profile["public_id"]),
            "sub_id": sub_id,
            "email_reminders": email_reminders,
        }
        if source_meta.get("referrer_id"):
            meta["referrer_id"] = source_meta["referrer_id"]
        if source_meta.get("referrer_code"):
            meta["referrer_code"] = source_meta["referrer_code"]

        order = self.store.create_order(
            kind="renewal",
            status="waiting_payment" if final_price > 0 else "auto_provision",
            transport=transport,
            duration_days=duration_days,
            profile_mode=str(profile.get("profile_mode") or "anonymous"),
            family_label=profile.get("family_label"),
            base_price_rub=base_price,
            final_price_rub=final_price,
            promo_id=int(promo["id"]) if promo else None,
            invite_id=None,
            customer_chat_id=(order_for_profile or {}).get("customer_chat_id"),
            privacy_ack=True,
            loss_policy_ack=True,
            terms_version=self.settings.terms_version,
            customer_email=final_email,
            meta=meta,
        )
        order = self._attach_web_token(order, token)
        delivered = self.maybe_auto_deliver_free_web_order(order)
        if delivered.get("status") == "waiting_payment":
            self._notify_admins_new_web_order(delivered)
        return delivered

    def check_and_send_expiration_reminders(self) -> None:
        try:
            due_1d = self.store.get_profiles_due_for_email_reminder("1_day", 23 * 3600, 25 * 3600)
            for item in due_1d:
                email = str(item.get("customer_email") or "").strip()
                if not email:
                    continue
                found = self.provisioner.xui_db.find_client_by_email(str(item["xui_email"]))
                sub_id = str(item["xui_email"])
                if found and (found.get("client") or {}).get("subId"):
                    sub_id = str(found["client"]["subId"])
                setup_url = f"{self.settings.subscription_base_url}/my-secret-sub/import/{sub_id}"
                if send_expiration_reminder_email_sync(self.settings, customer_email=email, reminder_kind="1_day", setup_url=setup_url):
                    self.store.record_profile_reminder(str(item["public_id"]), "1_day")

            due_1h = self.store.get_profiles_due_for_email_reminder("1_hour", 1800, 5400)
            for item in due_1h:
                email = str(item.get("customer_email") or "").strip()
                if not email:
                    continue
                found = self.provisioner.xui_db.find_client_by_email(str(item["xui_email"]))
                sub_id = str(item["xui_email"])
                if found and (found.get("client") or {}).get("subId"):
                    sub_id = str(found["client"]["subId"])
                setup_url = f"{self.settings.subscription_base_url}/my-secret-sub/import/{sub_id}"
                if send_expiration_reminder_email_sync(self.settings, customer_email=email, reminder_kind="1_hour", setup_url=setup_url):
                    self.store.record_profile_reminder(str(item["public_id"]), "1_hour")
        except Exception:
            LOGGER.exception("Error running check_and_send_expiration_reminders")

    def load_web_order(self, order_public_id: str, token: str) -> dict[str, Any] | None:
        """Resolve an order page by (public_id, bearer token).

        Token is compared in constant time against its HMAC hash stored in
        ``orders.web_token_hash`` (audit S-02: previously plaintext in meta_json
        and compared with ``!=``). The presented token is attached to the
        in-memory order only, so templates can build self-links.
        """
        if not token or len(token) > 128:
            return None
        order = self.store.get_order_by_web_token(order_public_id, token)
        if not order:
            return None
        meta = order.get("meta_json") or {}
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except Exception:
                meta = {}
        if not meta.get("web"):
            return None
        meta = dict(meta)
        meta["web_token"] = token
        order["meta_json"] = meta
        return order

    def _attach_web_token(self, order: dict[str, Any], token: str) -> dict[str, Any]:
        self.store.set_order_web_token(str(order["public_id"]), token)
        meta = dict(order.get("meta_json") or {})
        meta["web_token"] = token
        order["meta_json"] = meta
        return order

    def _notify_admins_new_web_order(self, order: dict[str, Any]) -> None:
        if not self.telegram:
            return
        try:
            meta = dict(order.get("meta_json") or {})
            customer_email = str(order.get("customer_email") or meta.get("customer_email") or "не указан").strip()
            kind_label = "Продление подписки" if order.get("kind") == "renewal" else "Новый заказ"
            text = "\n".join(
                [
                    f"🛒 {kind_label} на сайте (ожидает оплаты)",
                    "",
                    f"Заказ: `{order['public_id']}`",
                    f"Email: `{customer_email}`",
                    f"Транспорт: {transport_label(str(order['transport']))}",
                    f"Срок: {int(order['duration_days'])} дн.",
                    f"Лимит: {device_limit_label(meta.get('device_limit'))}",
                    f"Сумма: {money(order['final_price_rub'])}",
                    "",
                    "Покупатель перешел к оплате. Реквизиты выдаются оператором в поддержке.",
                    "При поступлении перевода нажмите кнопку ниже — доступ автоматически активируется и ссылка отправится клиенту на почту.",
                ]
            )
            admin_chats = self.store.list_chat_ids_by_scope("admin")
            for chat_id in admin_chats:
                try:
                    sent = self.telegram.send_message(
                        chat_id, text, reply_markup=inline_admin_markup(str(order["public_id"]))
                    )
                    self.store.attach_manager_message(str(order["public_id"]), chat_id, int(sent["message_id"]))
                except TelegramApiError:
                    LOGGER.exception("Failed to notify admin chat %s about new web order %s", chat_id, order["public_id"])
        except Exception:
            LOGGER.exception("Error in _notify_admins_new_web_order for order %s", order.get("public_id"))

    def mark_paid(self, headers: Any, order: dict[str, Any]) -> str:
        meta = dict(order.get("meta_json") or {})
        if order.get("status") != "waiting_payment":
            return "Этот заказ уже не ожидает оплату."

        last = self.store.get_last_admin_action(
            action_type="web_payment_reported_by_customer",
            target_type="order",
            target_public_id=str(order["public_id"]),
        )
        repeated = last and now_ts() - int(last.get("created_at") or 0) < PAYMENT_REPORT_REPEAT_SECONDS
        if repeated:
            return "Уведомление уже отправлено. Проверьте эту страницу чуть позже."

        meta["web_paid_reported_at"] = now_ts()
        self.store.update_order_meta(str(order["public_id"]), meta)
        self.store.record_admin_action(
            action_type="web_payment_reported_by_customer",
            target_type="order",
            target_public_id=str(order["public_id"]),
            actor="web",
            meta={"order_url": self.order_url(headers, {**order, "meta_json": meta})},
        )

        if not self.telegram:
            return "Уведомление отправлено. После проверки оплаты на этой странице появится доступ."

        customer_email = str(order.get("customer_email") or meta.get("customer_email") or "не указан").strip()
        text = "\n".join(
            [
                "🔔 Покупатель с сайта нажал «Оплачено»!",
                "",
                f"Заказ: `{order['public_id']}`",
                f"Email: `{customer_email}`",
                f"Транспорт: {transport_label(str(order['transport']))}",
                f"Срок: {int(order['duration_days'])} дн.",
                f"Лимит: {device_limit_label(meta.get('device_limit'))}",
                f"Сумма: {money(order['final_price_rub'])}",
                "",
                "Проверьте поступление и подтвердите оплату.",
            ]
        )
        admin_chats = self.store.list_chat_ids_by_scope("admin")
        for chat_id in admin_chats:
            try:
                sent = self.telegram.send_message(chat_id, text, reply_markup=inline_admin_markup(str(order["public_id"])))
                self.store.attach_manager_message(str(order["public_id"]), chat_id, int(sent["message_id"]))
            except TelegramApiError:
                LOGGER.exception("Failed to notify admin chat %s about web order %s", chat_id, order["public_id"])
        return "Уведомление отправлено. После проверки оплаты на этой странице появится доступ."

    def cancel_order(self, order: dict[str, Any]) -> str:
        if order.get("status") != "waiting_payment":
            return "Этот заказ уже не ожидает оплату."

        self.store.update_order_status(str(order["public_id"]), "cancelled", closed=True)
        self.store.record_admin_action(
            action_type="web_order_cancelled_by_customer",
            target_type="order",
            target_public_id=str(order["public_id"]),
            actor="web",
        )
        return "Заказ отменён."

    def order_status_json(self, order: dict[str, Any]) -> bytes:
        status = str(order.get("status") or "")
        meta = dict(order.get("meta_json") or {})

        # Active reconciliation with Platega if order is waiting payment
        if status == "waiting_payment" and self.settings.platega_enabled and self.platega.is_configured:
            tx_id = str(meta.get("platega_transaction_id") or "").strip()
            last_polled = int(meta.get("platega_last_polled_at") or 0)
            now = now_ts()
            if tx_id and (now - last_polled) >= 8:
                meta["platega_last_polled_at"] = now
                self.store.update_order_meta(str(order["public_id"]), meta)
                try:
                    tx_status = self.platega.get_transaction_status(tx_id, is_bot=False)
                    tx_state = str(tx_status.get("status") or "").strip().upper()
                    if tx_state == "CONFIRMED":
                        raw_amount = tx_status.get("amount") if tx_status.get("amount") is not None else (tx_status.get("paymentDetails") or {}).get("amount")
                        try:
                            amount = float(raw_amount) if raw_amount is not None else 0.0
                        except (ValueError, TypeError):
                            amount = 0.0
                        expected_rub = int(order.get("final_price_rub") or 0)
                        if amount <= 0 or expected_rub <= 0 or amount >= (expected_rub - 0.5):
                            LOGGER.info("Active reconciliation confirmed order %s via Platega API", order["public_id"])
                            meta["platega_confirmed_at"] = now
                            meta["platega_confirmed_amount"] = amount
                            self.store.update_order_meta(str(order["public_id"]), meta)
                            self.bot.complete_order(order, actor="web_polling_reconciliation")
                            refreshed = self.store.get_order(str(order["public_id"]))
                            if refreshed:
                                order = refreshed
                                status = str(order.get("status") or "")
                                meta = dict(order.get("meta_json") or {})
                except Exception as exc:
                    LOGGER.debug("Platega active query during polling for order %s: %s", order.get("public_id"), exc)

        payload = {
            "ok": True,
            "status": status,
            "paid_reported": bool(meta.get("web_paid_reported_at")),
            "updated_at": int(order.get("updated_at") or 0),
        }
        if status == "delivered":
            subscription_url = self.recover_subscription(order)
            if subscription_url:
                payload["setup_url"] = subscription_setup_url(subscription_url)
        return json.dumps(payload, ensure_ascii=False).encode("utf-8")

    def order_poll_script(self, order: dict[str, Any], *, interval_seconds: int = 5) -> str:
        meta = order.get("meta_json") or {}
        status_url = f"/order/{quote(str(order['public_id']), safe='')}/{quote(str(meta.get('web_token') or ''), safe='')}/status"
        return f"""
        <script>
        (() => {{
          const initialStatus = {json.dumps(str(order.get("status") or ""))};
          const statusUrl = {json.dumps(status_url)};
          const statusBox = document.getElementById("order-live-status");
          let failures = 0;

          async function pollOrderStatus() {{
            try {{
              const response = await fetch(statusUrl, {{ cache: "no-store", credentials: "same-origin" }});
              if (!response.ok) return;
              const data = await response.json();
              failures = 0;

              if (data.status && data.status !== initialStatus) {{
                if (statusBox) {{
                  statusBox.textContent = data.status === "delivered"
                    ? "Оплата подтверждена. Открываем доступ..."
                    : "Статус заказа изменился. Обновляем страницу...";
                }}
                if (data.status === "delivered" && data.setup_url) {{
                  window.location.href = data.setup_url;
                  return;
                }}
                window.location.reload();
                return;
              }}

              if (statusBox && data.paid_reported) {{
                statusBox.textContent = "Оплата отмечена. Ждём подтверждение админом, эта страница обновится сама.";
              }}
            }} catch (error) {{
              failures += 1;
              if (statusBox && failures >= 3) {{
                statusBox.textContent = "Проверяем статус. Если страница долго не обновляется, обновите её вручную.";
              }}
            }}
          }}

          window.setTimeout(pollOrderStatus, 1500);
          window.setInterval(pollOrderStatus, {int(interval_seconds) * 1000});
        }})();
        </script>
        """

    _rate_limit_lock = threading.Lock()
    _cabinet_rate_limits: OrderedDict[str, float] = OrderedDict()
    _promo_check_limits: OrderedDict[str, list[float]] = OrderedDict()

    def request_cabinet_access_link(self, headers: Any, email: str, turnstile_token: str = "") -> dict[str, Any]:
        clean_email = (email or "").strip().lower()
        if not clean_email or "@" not in clean_email:
            return {"ok": False, "message": "Пожалуйста, введите корректный адрес электронной почты."}

        client_ip = client_ip_from_headers(headers, getattr(headers, "peer_ip", None))

        # Turnstile CAPTCHA check
        if self.settings.cf_turnstile_secret_key:
            if not verify_cf_turnstile(self.settings.cf_turnstile_secret_key, turnstile_token, client_ip):
                return {"ok": False, "message": "Пожалуйста, подтвердите, что вы человек (поставьте галочку Cloudflare)."}

        # Anti-spam burst protection (minimum 20 seconds between attempts)
        recent_burst = self.store.count_recent_magic_links(email=clean_email, request_ip=client_ip, window_seconds=20)
        if recent_burst >= 1:
            return {
                "ok": False,
                "message": "Письмо со ссылкой уже отправляется. Пожалуйста, подождите 20 секунд перед повторным запросом.",
            }

        # Rate limit: maximum 3 links per 30 minutes (1800s)
        recent_30m = self.store.count_recent_magic_links(email=clean_email, request_ip=client_ip, window_seconds=1800)
        if recent_30m >= 3:
            return {
                "ok": False,
                "message": "Превышен лимит запросов: не более 3 ссылок за 30 минут. Пожалуйста, проверьте почту или воспользуйтесь последней полученной ссылкой.",
            }

        ttl = int(getattr(self.settings, "magic_link_ttl_seconds", 1800) or 1800)
        magic_token = sign_token({"email": clean_email}, purpose="magic_link", ttl_seconds=ttl)
        self.store.create_magic_link(email=clean_email, token=magic_token, ttl_seconds=ttl, request_ip=client_ip)

        generic_ok = {
            "ok": True,
            "message": (
                "Если на этот адрес оформлены активные подписки, мы отправили письмо со ссылкой для входа "
                f"(действует {max(ttl // 60, 1)} мин). Предыдущие ссылки аннулированы."
            ),
        }
        profiles = self.store.get_active_profiles_by_customer_email(clean_email)
        if not profiles:
            return generic_ok

        cabinet_origin = public_origin(headers, self.settings.web_public_base_url, getattr(self.settings, "allowed_hosts", ()))
        cabinet_url = f"{cabinet_origin}/cabinet/{quote(magic_token, safe='')}"

        profiles_data = []
        for p in profiles:
            pid = str(p.get("public_id") or "")
            xui_email = str(p.get("xui_email") or "")
            found = self.provisioner.xui_db.find_client_by_email(xui_email)
            sub_id = str((found.get("client") or {}).get("subId") or "") if found else ""
            transport = str(p.get("transport") or "tcp")
            if sub_id:
                kind = "json-hybrid" if "hybrid" in transport or p.get("profile_mode") == "hybrid" else ("json" if transport == "tcp" else "xhttp-json")
                sub_url = subscription_url_for_route(self.settings.subscription_base_url, kind, sub_id)
                setup_url = subscription_setup_url(sub_url)
            else:
                setup_url = self.settings.subscription_base_url or f"{self.settings.web_public_base_url}/"

            order_meta = p.get("order_meta") or {}
            if isinstance(order_meta, str):
                try:
                    order_meta = json.loads(order_meta)
                except Exception:
                    order_meta = {}
            device_limit = int(order_meta.get("device_limit") or self.settings.default_device_limit)

            profiles_data.append({
                "public_id": pid,
                "created_at": p.get("created_at"),
                "expires_at": p.get("expires_at"),
                "last_renewed_at": p.get("last_renewed_at"),
                "transport": transport,
                "device_limit": device_limit,
                "sub_id": sub_id,
                "setup_url": setup_url,
            })

        send_cabinet_access_email_async(
            self.settings,
            customer_email=clean_email,
            profiles_data=profiles_data,
            cabinet_url=cabinet_url,
        )

        return generic_ok

    def cabinet_profiles_for_email(self, email: str) -> list[dict[str, Any]]:
        profiles = self.store.get_active_profiles_by_customer_email(email)
        items: list[dict[str, Any]] = []
        for p in profiles:
            xui_email = str(p.get("xui_email") or "")
            found = self.provisioner.xui_db.find_client_by_email(xui_email)
            sub_id = str((found.get("client") or {}).get("subId") or "") if found else ""
            transport = str(p.get("transport") or "tcp")
            if sub_id:
                kind = "json-hybrid" if "hybrid" in transport or p.get("profile_mode") == "hybrid" else ("json" if transport == "tcp" else "xhttp-json")
                sub_url = subscription_url_for_route(self.settings.subscription_base_url, kind, sub_id)
                setup_url = subscription_setup_url(sub_url)
            else:
                setup_url = self.settings.subscription_base_url or f"{self.settings.web_public_base_url}/"

            order_meta = p.get("order_meta") or {}
            if isinstance(order_meta, str):
                try:
                    order_meta = json.loads(order_meta)
                except Exception:
                    order_meta = {}
            device_limit = int(order_meta.get("device_limit") or self.settings.default_device_limit)

            items.append({
                "public_id": str(p.get("public_id") or ""),
                "created_at": p.get("created_at"),
                "expires_at": p.get("expires_at"),
                "last_renewed_at": p.get("last_renewed_at"),
                "transport": transport,
                "device_limit": device_limit,
                "sub_id": sub_id,
                "setup_url": setup_url,
            })
        return items

    def render_cabinet(self, email: str, profiles: list[dict[str, Any]]) -> bytes:
        now = now_ts()
        count = len(profiles)

        cards_html = []
        for idx, p in enumerate(profiles, 1):
            pid = str(p.get("public_id") or "---")
            expires_at = int(p.get("expires_at") or 0)
            is_active = expires_at > now
            days_left = max(0, (expires_at - now) // 86400) if is_active else 0

            if not is_active:
                status_badge = '<span class="cabinet-badge expired">🔴 Срок истёк</span>'
                days_str = '<span style="color: #ef4444; font-weight: 700;">Истекла</span>'
            elif days_left <= 3:
                status_badge = f'<span class="cabinet-badge warning">🟡 Истекает ({days_left} дн.)</span>'
                days_str = f'<span style="color: #fbbf24; font-weight: 700;">Осталось {days_left} дн.</span>'
            elif days_left > 365 * 10:
                status_badge = '<span class="cabinet-badge active">🟢 Активна</span>'
                days_str = '<span style="color: #34d399; font-weight: 700;">Бессрочно</span>'
            else:
                status_badge = '<span class="cabinet-badge active">🟢 Активна</span>'
                days_str = f'<span style="color: #34d399; font-weight: 700;">Осталось {days_left} дн.</span>'

            expiry_date_str = time.strftime("%d.%m.%Y", time.localtime(expires_at)) if expires_at else "---"
            device_limit = int(p.get("device_limit") or self.settings.default_device_limit)
            transport_raw = str(p.get("transport") or "tcp")
            transport_label = "Гибридный (TCP + XHTTP)" if "hybrid" in transport_raw else ("VLESS Reality (TCP)" if transport_raw == "tcp" else "VLESS XHTTP")
            setup_url = html.escape(str(p.get("setup_url") or "#"), quote=True)

            cards_html.append(f"""
            <div class="cabinet-card">
              <div class="cabinet-card-header">
                <div class="cabinet-card-title">
                  <span style="font-size: 20px;">🔑</span>
                  <span>Подписка #{idx}</span>
                </div>
                {status_badge}
              </div>

              <table class="cabinet-table">
                <tr>
                  <td>Лимит устройств:</td>
                  <td>до {device_limit} устройств</td>
                </tr>
                <tr>
                  <td>Протокол / сеть:</td>
                  <td>{html.escape(transport_label)}</td>
                </tr>
                <tr>
                  <td>Действует до:</td>
                  <td>{expiry_date_str} ({days_str})</td>
                </tr>
                <tr>
                  <td>ID профиля:</td>
                  <td style="font-family: monospace; font-size: 12px; color: var(--muted);">{html.escape(pid)}</td>
                </tr>
              </table>

              <div class="cabinet-card-actions">
                <a class="btn cabinet-btn-primary" href="{setup_url}" target="_blank" rel="noopener">
                  🚀 Мастер настройки и подключения →
                </a>
              </div>
            </div>
            """)

        cards_str = "".join(cards_html) if cards_html else """
        <div class="cabinet-empty" style="text-align: center; padding: 48px 24px; background: var(--card); border-radius: 16px; border: 1px solid var(--glass-border);">
          <div style="font-size: 36px; margin-bottom: 12px;">🔍</div>
          <h3 style="margin-top: 0; color: #fff;">Активных подписок не найдено</h3>
          <p class="muted">На этот email адрес пока не оформлено действующих подписок.</p>
          <a class="btn" href="/" style="margin-top: 16px; max-width: 260px; display: inline-flex;">Оформить подписку</a>
        </div>
        """

        support_url = (self.settings.support_tg_url or "").strip() or "https://t.me/SilentConnectSupport"

        body = f"""
        <section class="section cabinet-section">
          <div class="cabinet-topbar">
            <h2 class="cabinet-heading">Личный кабинет</h2>
            <div class="cabinet-meta-row">
              <span class="cabinet-sub-badge">🔑 Подписок: <strong>{count}</strong></span>
              <span class="cabinet-email-badge">✉️ {html.escape(email)}</span>
              <span class="cabinet-timer-badge">⏱ Сессия активна (30 мин)</span>
            </div>
          </div>

          <div class="cabinet-cards-grid">
            {cards_str}
          </div>

          <div class="cabinet-bottom-box">
            <div class="cabinet-bottom-info">
              <div style="font-weight: 700; color: #fff; margin-bottom: 4px;">Нужна ещё одна подписка или есть вопросы?</div>
              <div style="font-size: 13.5px; color: var(--muted);">
                Вы можете оформить новый профиль на главном сайте или обратиться к нашему менеджеру.
              </div>
            </div>
            <div class="cabinet-bottom-actions">
              <a class="btn secondary" href="/" style="width: auto; min-height: 42px; padding: 8px 18px; font-size: 14px;">
                ➕ Новая подписка
              </a>
              <a class="btn secondary" href="{html.escape(support_url, quote=True)}" target="_blank" rel="noopener" style="width: auto; min-height: 42px; padding: 8px 18px; font-size: 14px;">
                💬 Поддержка в Telegram
              </a>
            </div>
          </div>
        </section>
        """
        return self.render_page("Личный кабинет", body)

    def check_promo_code(self, headers: Any, code: str) -> dict[str, Any]:
        clean_code = (code or "").strip().upper()
        if not clean_code:
            return {"ok": False, "message": "Пожалуйста, введите промокод."}

        client_ip = client_ip_from_headers(headers, getattr(headers, "peer_ip", None))
        now = time.time()
        rate_key = f"promo:{client_ip}"
        
        # Softened rate limit: 12 attempts per 3 minutes (180s) instead of 5 attempts per 1 hour (3600s)
        window_sec = 180
        max_attempts = 12
        with self._rate_limit_lock:
            history = [t for t in self._promo_check_limits.get(rate_key, []) if now - t < window_sec]
            if len(history) >= max_attempts:
                wait_sec = int(window_sec - (now - min(history)))
                if wait_sec <= 0:
                    wait_sec = 30
                return {
                    "ok": False,
                    "message": f"Слишком много попыток проверки промокодов. Пожалуйста, подождите {wait_sec} сек.",
                }
            history.append(now)
            self._promo_check_limits[rate_key] = history
            self._promo_check_limits.move_to_end(rate_key)
            while len(self._promo_check_limits) > WEB_RATE_LIMIT_MAX_ENTRIES:
                self._promo_check_limits.popitem(last=False)

        try:
            promo = self.load_valid_promo(clean_code)
            # Successful promo check clears failed rate-limit attempts for this IP
            with self._rate_limit_lock:
                self._promo_check_limits.pop(rate_key, None)
            promo_type = self.promo_type(promo)
            if promo_type == "discount":
                pct = int(promo.get("discount_percent") or 0)
                return {
                    "ok": True,
                    "type": "discount",
                    "code": clean_code,
                    "discount_percent": pct,
                    "fixed_price_rub": promo.get("fixed_price_rub"),
                    "message": f"Промокод <b>{html.escape(clean_code)}</b> применён! Скидка {pct}% на все тарифы.",
                }
            else:
                dur = int(promo.get("duration_days") or 30)
                dev = self.promo_device_limit(promo)
                return {
                    "ok": True,
                    "type": "gift",
                    "code": clean_code,
                    "duration_days": dur,
                    "device_limit": dev,
                    "message": f"🎁 Подарочный промокод <b>{html.escape(clean_code)}</b> на {dur} дн. активирован! Укажите Email ниже для получения доступа.",
                }
        except ValueError as exc:
            return {"ok": False, "message": str(exc) or "Промокод не найден или у него истёк срок действия."}

    def render_page(self, title: str, body: str, *, refresh_seconds: int | None = None) -> bytes:
        refresh = f'<meta http-equiv="refresh" content="{int(refresh_seconds)}">' if refresh_seconds else ""
        notice_html = f'<div class="notice site-alert" role="status">{html.escape(TEMP_NETWORK_NOTICE)}</div>' if TEMP_NETWORK_NOTICE else ""
        html_doc = f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <meta name="apple-mobile-web-app-title" content="SilentConnect">
  <meta name="theme-color" content="#0e1317">
  <meta property="og:title" content="SilentConnect — Приватный и безопасный интернет">
  <meta property="og:description" content="Сервис защищенного и приватного сетевого доступа для персонального использования. Без ограничений и без логирования активности.">
  <meta property="og:type" content="website">
  <meta property="og:url" content="https://silentconnect.net"><!-- PLACEHOLDER -->
  <meta property="og:site_name" content="SilentConnect">
  <meta property="og:image" content="https://silentconnect.net/assets/telegram/avatar.png"><!-- PLACEHOLDER -->
  {refresh}
  <title>{html.escape(title)} · SilentConnect</title>
  <link rel="icon" type="image/png" href="/assets/telegram/avatar.png">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700;800&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
  <style>
    :root {{
      color-scheme: dark;
      --bg-dark: #050a08;
      --bg-light: #0a1410;
      --glass-bg: rgba(20, 35, 28, 0.4);
      --glass-bg-hover: rgba(30, 50, 40, 0.6);
      --glass-border: rgba(255, 255, 255, 0.08);
      --text: #f4f7f5;
      --muted: #8ea89a;
      --line: rgba(255, 255, 255, 0.05);
      --green: #2fbf71;
      --green-glow: rgba(47, 191, 113, 0.3);
      --blue: #3b82f6;
      --red: #ef4444;
    }}
    html {{ scroll-behavior: smooth; }}
    * {{ box-sizing: border-box; -webkit-tap-highlight-color: transparent; }}
    #tariffs {{ scroll-margin-top: 92px; }}
    body {{
      margin: 0;
      padding: 0;
      font-family: 'Inter', system-ui, -apple-system, sans-serif;
      background-color: var(--bg-dark);
      background-image: 
        radial-gradient(circle at 15% 50%, rgba(47, 191, 113, 0.08), transparent 25%),
        radial-gradient(circle at 85% 30%, rgba(59, 130, 246, 0.08), transparent 25%);
      background-attachment: fixed;
      color: var(--text);
      line-height: 1.6;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }}
    h1, h2, h3, .brand, .price, strong, .btn, button {{
      font-family: 'Outfit', sans-serif;
    }}
    .wrap {{ width: 100%; max-width: 1120px; margin-left: auto; margin-right: auto; padding-left: 20px; padding-right: 20px; box-sizing: border-box; }}
    main.wrap {{ flex: 1 0 auto; width: 100%; max-width: 1120px; margin: 0 auto; padding: 0 20px 60px; box-sizing: border-box; }}
    header {{ 
      background: rgba(5, 10, 8, 0.7); 
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border-bottom: 1px solid var(--glass-border); 
      position: -webkit-sticky;
      position: sticky;
      top: 0;
      z-index: 1000; 
    }}
    nav {{ height: 72px; display: flex; align-items: center; justify-content: space-between; gap: 16px; }}
    .brand {{ 
      display: inline-flex; align-items: center; gap: 12px;
      font-weight: 800; font-size: 22px; letter-spacing: -0.5px;
      text-decoration: none; color: #fff;
    }}
    .brand span {{
      background: linear-gradient(to right, #fff, #2fbf71);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }}
    .brand-logo {{
      width: 36px; height: 36px; border-radius: 10px; object-fit: cover;
      box-shadow: 0 0 12px var(--green-glow); border: 1px solid var(--glass-border);
    }}
    .navlinks {{ display: flex; align-items: center; gap: 20px; flex-wrap: wrap; }}
    .navlinks a {{ text-decoration: none; color: var(--muted); font-weight: 500; font-size: 15px; }}
    .navlinks a:hover {{ color: #fff; text-shadow: 0 0 10px rgba(255,255,255,0.3); }}
    .mobile-nav-txt {{ display: none; }}
    .desktop-nav-txt {{ display: inline; }}
    .hero {{ display: grid; grid-template-columns: 1fr 1fr; gap: 40px; padding: 60px 0 40px; align-items: center; }}
    .hero h1 {{ font-size: clamp(36px, 5vw, 64px); line-height: 1.1; margin: 0 0 20px; letter-spacing: -1px; }}
    .lead {{ color: var(--muted); font-size: 19px; max-width: 680px; margin: 0 0 24px; font-weight: 400; }}
    .hero-img {{ 
      width: 100%; border-radius: 16px; 
      border: 1px solid var(--glass-border); 
      box-shadow: 0 20px 40px rgba(0,0,0,0.4), 0 0 40px var(--green-glow);
      opacity: .96;
      transition: transform 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275);
    }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }}
    .advantage-grid {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin: 0 0 18px; }}
    .advantage {{
      min-height: 132px; padding: 18px; border-radius: 8px;
      background: rgba(255,255,255,0.055); border: 1px solid var(--glass-border);
    }}
    .advantage b {{ display: block; color: #fff; margin-bottom: 6px; font-family: 'Outfit', sans-serif; font-size: 17px; }}
    .advantage span {{ display: block; color: var(--muted); font-size: 14px; line-height: 1.45; }}
    h1, h2, h3, h4, p, li, .card, .page-card, .page-title {{
      overflow-wrap: break-word;
      word-wrap: break-word;
      box-sizing: border-box;
    }}
    .card {{ 
      background: var(--glass-bg);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--glass-border); 
      border-radius: 16px; 
      padding: 24px;
      transition: all 0.3s ease;
      box-shadow: 0 4px 20px rgba(0,0,0,0.2);
    }}
    .page-card {{
      max-width: 860px;
      margin: 30px auto;
      line-height: 1.7;
      padding: 28px 32px;
      box-sizing: border-box;
    }}
    .page-title {{
      font-size: clamp(22px, 5.2vw, 32px);
      line-height: 1.25;
      margin-top: 0;
      margin-bottom: 12px;
      background: linear-gradient(to right, #fff, #2fbf71);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      overflow-wrap: break-word;
      word-wrap: break-word;
      word-break: normal;
      hyphens: auto;
      -webkit-hyphens: auto;
    }}
    .card strong {{ display: block; font-size: 20px; margin-bottom: 8px; letter-spacing: -0.2px; }}
    .muted {{ color: var(--muted); }}
    .fine {{ color: var(--muted); font-size: 13px; margin: 12px 0 0; opacity: 0.8; }}
    .price {{ font-size: 36px; font-weight: 800; margin: 16px 0; color: #fff; }}
    .badge {{ 
      color: #ffffff !important; background: #f59e0b; 
      border-radius: 6px; padding: 3px 8px; 
      font-weight: 800; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px;
      box-shadow: 0 2px 8px rgba(245, 158, 11, 0.4);
    }}
    .choice .badge {{
      color: #ffffff !important;
      font-weight: 800 !important;
    }}
    .btn, button {{
      display: inline-flex; justify-content: center; align-items: center; min-height: 48px;
      padding: 12px 20px; border-radius: 10px; border: none;
      color: #000; background: var(--green); font-weight: 700; text-decoration: none; cursor: pointer;
      font-size: 16px; width: 100%; letter-spacing: 0.2px;
      transition: all 0.2s ease;
      box-shadow: 0 4px 12px var(--green-glow);
    }}
    .btn:hover, button:hover {{
      transform: translateY(-2px);
      box-shadow: 0 6px 16px rgba(47, 191, 113, 0.4);
      filter: brightness(1.1);
    }}
    .btn:active, button:active {{ transform: translateY(0); box-shadow: none; }}
    .btn.secondary {{ background: rgba(255,255,255,0.1); color: #fff; box-shadow: none; border: 1px solid var(--glass-border); backdrop-filter: blur(4px); }}
    .btn.secondary:hover {{ background: rgba(255,255,255,0.15); border-color: rgba(255,255,255,0.2); }}
    .actions {{ display: grid; gap: 12px; margin-top: 20px; }}
    .builder {{ display: grid; grid-template-columns: minmax(0, 1.2fr) minmax(280px, .8fr); gap: 20px; align-items: stretch; }}
    .choice-section {{ margin-top: 20px; }}
    .choice-section:first-child {{ margin-top: 0; }}
    .choice-title {{ font-weight: 700; margin-bottom: 10px; color: #fff; }}
    .choice-grid {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; }}
    .choice-grid-durations {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; }}
    .choice {{
      position: relative;
      width: 100%; min-height: 76px; padding: 12px; text-align: left; justify-content: flex-start;
      align-items: flex-start; flex-direction: column; gap: 3px;
      color: #e9f3ee; background: rgba(255,255,255,0.06); box-shadow: none;
      border: 1px solid var(--glass-border); border-radius: 12px;
      transition: background 0.25s cubic-bezier(0.16, 1, 0.3, 1),
                  border-color 0.25s cubic-bezier(0.16, 1, 0.3, 1),
                  transform 0.2s cubic-bezier(0.16, 1, 0.3, 1),
                  box-shadow 0.25s cubic-bezier(0.16, 1, 0.3, 1);
      cursor: pointer;
    }}
    .choice:hover {{
      transform: translateY(-2px);
      filter: none;
      background: rgba(255,255,255,0.09);
      border-color: rgba(255,255,255,0.2);
      box-shadow: 0 4px 16px rgba(0,0,0,0.25);
    }}
    .choice.active {{
      border-color: var(--green);
      background: rgba(47, 191, 113, 0.16);
      box-shadow: 0 0 0 1px rgba(47, 191, 113, 0.3) inset, 0 4px 20px rgba(47, 191, 113, 0.15);
      transform: translateY(-2px);
    }}
    .choice span {{ color: var(--muted); font-family: 'Inter', sans-serif; font-size: 13px; font-weight: 500; }}
    .summary-box {{ position: sticky; top: 96px; display: flex; flex-direction: column; }}
    .summary-row {{ display: flex; justify-content: space-between; gap: 14px; border-bottom: 1px solid var(--line); padding: 10px 0; }}
    .summary-row span:first-child {{ color: var(--muted); }}
    .summary-price {{ font-size: 42px; line-height: 1; font-weight: 800; margin: 18px 0; }}
    .summary-note {{ color: var(--muted); font-size: 14px; margin: 0 0 16px; }}
    .notice {{ 
      border-left: 4px solid var(--amber); 
      background: rgba(245, 158, 11, 0.1); 
      padding: 16px; border-radius: 0 8px 8px 0; 
      color: #fff; font-size: 15px; 
      backdrop-filter: blur(8px);
    }}
    .order {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; align-items: stretch; }}
    .order > .card {{ display: flex; flex-direction: column; justify-content: space-between; box-sizing: border-box; }}
    .payment-options {{ display: flex; flex-direction: column; gap: 16px; box-sizing: border-box; }}
    .payment-options > .card {{ display: flex; flex-direction: column; justify-content: space-between; box-sizing: border-box; }}
    .order-summary-card {{
      display: flex; flex-direction: column; justify-content: space-between; box-sizing: border-box;
      padding: 24px; background: var(--card); border: 1px solid var(--glass-border); border-radius: 16px;
      backdrop-filter: blur(12px);
    }}
    .order-primary-card {{
      padding: 24px; background: rgba(16, 185, 129, 0.08);
      border: 1.5px solid rgba(16, 185, 129, 0.5); border-radius: 16px;
      box-shadow: 0 8px 32px rgba(16, 185, 129, 0.18), 0 0 0 1px rgba(16, 185, 129, 0.2) inset;
      display: flex; flex-direction: column; justify-content: space-between;
      backdrop-filter: blur(12px);
    }}
    .btn-platega-primary {{
      display: flex; align-items: center; justify-content: center; gap: 10px; min-height: 52px;
      padding: 14px 22px; font-size: 16.5px; font-weight: 800; color: #041d11 !important;
      background: linear-gradient(135deg, #10b981 0%, #34d399 50%, #10b981 100%);
      background-size: 200% auto; border: none; border-radius: 12px; text-decoration: none;
      cursor: pointer; box-shadow: 0 4px 20px rgba(16, 185, 129, 0.45);
      transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1); letter-spacing: 0.2px; width: 100%; box-sizing: border-box;
    }}
    .btn-platega-primary:hover {{
      transform: translateY(-2px); box-shadow: 0 6px 28px rgba(16, 185, 129, 0.65);
      filter: brightness(1.08);
    }}
    .order-secondary-card {{
      padding: 18px 20px; background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--glass-border); border-radius: 14px;
      backdrop-filter: blur(8px);
    }}
    .cabinet-section {{ max-width: 980px; margin: 0 auto; }}
    .cabinet-topbar {{
      margin-bottom: 28px;
      padding-bottom: 20px; border-bottom: 1px solid rgba(255, 255, 255, 0.08);
    }}
    .cabinet-heading {{
      font-size: clamp(24px, 4vw, 34px); margin: 0 0 10px 0; font-weight: 800;
      background: linear-gradient(to right, #fff, #34d399);
      -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    }}
    .cabinet-meta-row {{ display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }}
    .cabinet-sub-badge {{
      display: inline-flex; align-items: center; gap: 6px; padding: 5px 12px;
      background: rgba(47, 191, 113, 0.12); border: 1px solid rgba(47, 191, 113, 0.35);
      border-radius: 20px; font-size: 13px; color: #2fbf71; font-weight: 600;
    }}
    .cabinet-sub-badge strong {{ color: #fff; font-size: 13px; font-weight: 700; }}
    .cabinet-email-badge {{
      display: inline-flex; align-items: center; gap: 6px; padding: 5px 12px;
      background: rgba(255, 255, 255, 0.06); border: 1px solid var(--glass-border);
      border-radius: 20px; font-size: 13px; color: #cbd5e1;
    }}
    .cabinet-timer-badge {{
      display: inline-flex; align-items: center; gap: 6px; padding: 5px 12px;
      background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3);
      border-radius: 20px; font-size: 13px; color: #34d399; font-weight: 500;
    }}
    .cabinet-cards-grid {{
      display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 20px; margin-bottom: 32px;
    }}
    .cabinet-card {{
      background: var(--card); border: 1px solid var(--glass-border);
      border-radius: 16px; padding: 22px; display: flex; flex-direction: column;
      justify-content: space-between; gap: 16px; backdrop-filter: blur(12px);
      box-shadow: 0 4px 20px rgba(0,0,0,0.25);
      min-width: 0; overflow: hidden; box-sizing: border-box;
      transition: transform 0.25s ease, border-color 0.25s ease, box-shadow 0.25s ease;
    }}
    .cabinet-card:hover {{
      transform: translateY(-3px); border-color: rgba(52, 211, 153, 0.4);
      box-shadow: 0 12px 32px rgba(0,0,0,0.4), 0 0 24px rgba(16, 185, 129, 0.12);
    }}
    .cabinet-card-header {{
      display: flex; justify-content: space-between; align-items: center; gap: 10px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.06); padding-bottom: 12px;
      flex-wrap: wrap; min-width: 0;
    }}
    .cabinet-card-title {{
      font-size: 17px; font-weight: 700; color: #fff; margin: 0;
      display: flex; align-items: center; gap: 8px;
    }}
    .cabinet-badge {{
      display: inline-flex; align-items: center; gap: 4px; padding: 4px 10px;
      border-radius: 12px; font-size: 12px; font-weight: 700; white-space: nowrap;
    }}
    .cabinet-badge.active {{
      background: rgba(16, 185, 129, 0.15); color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.35);
    }}
    .cabinet-badge.warning {{
      background: rgba(245, 158, 11, 0.15); color: #fbbf24;
      border: 1px solid rgba(245, 158, 11, 0.35);
    }}
    .cabinet-badge.expired {{
      background: rgba(239, 68, 68, 0.15); color: #f87171;
      border: 1px solid rgba(239, 68, 68, 0.35);
    }}
    .cabinet-table {{ width: 100%; border-collapse: collapse; font-size: 13.5px; }}
    .cabinet-table td {{ padding: 6px 0; vertical-align: top; }}
    .cabinet-table td:first-child {{ color: var(--muted); padding-right: 8px; }}
    .cabinet-table td:last-child {{ text-align: right; color: #e2e8f0; font-weight: 600; word-break: normal; }}
    .cabinet-card-actions {{ margin-top: 4px; }}
    .cabinet-btn-primary {{
      display: flex; align-items: center; justify-content: center; gap: 8px;
      min-height: 46px; font-size: 14.5px; font-weight: 700; width: 100%;
      border-radius: 10px; text-decoration: none; box-sizing: border-box; text-align: center;
    }}
    .cabinet-bottom-box {{
      display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap;
      gap: 16px; background: rgba(255, 255, 255, 0.025); border: 1px solid var(--glass-border);
      border-radius: 14px; padding: 18px 24px; box-sizing: border-box;
    }}
    .cabinet-bottom-actions {{ display: flex; gap: 12px; flex-wrap: wrap; }}
    @media (max-width: 640px) {{
      .cabinet-topbar {{ margin-bottom: 20px; padding-bottom: 16px; }}
      .cabinet-heading {{ font-size: 24px; }}
      .cabinet-meta-row {{ gap: 8px; }}
      .cabinet-sub-badge, .cabinet-email-badge, .cabinet-timer-badge {{ font-size: 12px; padding: 4px 10px; }}
      .cabinet-cards-grid {{ grid-template-columns: 1fr; gap: 16px; margin-bottom: 24px; }}
      .cabinet-card {{ padding: 18px 16px; gap: 14px; }}
      .cabinet-table {{ font-size: 12.5px; }}
      .cabinet-btn-primary {{ min-height: 42px; font-size: 13.5px; }}
      .cabinet-bottom-box {{ padding: 14px 16px; flex-direction: column; align-items: stretch; gap: 14px; }}
      .cabinet-bottom-actions {{ flex-direction: column; width: 100%; }}
      .cabinet-bottom-actions .btn {{ width: 100% !important; justify-content: center; }}
    }}
    @media (max-width: 390px) {{
      .cabinet-card {{ padding: 14px 12px; }}
      .cabinet-table td {{ font-size: 12px; }}
    }}
    .order-link-input {{
      width: 100%; min-height: 40px; background: rgba(0, 0, 0, 0.35);
      border: 1px solid var(--glass-border); border-radius: 8px; padding: 8px 12px;
      color: #94a3b8; font-family: monospace; font-size: 12.5px; box-sizing: border-box;
    }}
    .order-link-input:focus {{ outline: none; border-color: var(--green); }}
    .field {{ width: 100%; min-height: 48px; color: #fff; background: rgba(0,0,0,0.3); border: 1px solid var(--glass-border); border-radius: 10px; padding: 12px 14px; font-size: 16px; margin-bottom: 12px; }}
    .field:focus {{ outline: none; border-color: var(--green); }}
    textarea {{ 
      width: 100%; min-height: 100px; resize: vertical; 
      color: #fff; background: rgba(0,0,0,0.3); 
      border: 1px solid var(--glass-border); border-radius: 10px; padding: 14px; 
      font-family: inherit; font-size: 14px;
    }}
    textarea:focus {{ outline: none; border-color: var(--green); }}
    footer {{ 
      margin-top: auto;
      border-top: 1px solid var(--glass-border); 
      padding: 28px 0; color: var(--muted); font-size: 13.5px; 
      background: rgba(5, 10, 8, 0.5);
    }}
    .footer-wrap {{
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      gap: 12px;
      text-align: center;
    }}
    .footer-links {{
      display: flex;
      align-items: center;
      justify-content: center;
      flex-wrap: wrap;
      gap: 12px 18px;
    }}
    .footer-links a {{
      color: var(--muted);
      text-decoration: none;
      font-size: 13.5px;
      margin: 0;
      padding: 4px 8px;
      border-radius: 6px;
      transition: color 0.2s ease;
    }}
    .footer-links a:hover {{
      color: #ffffff;
      text-decoration: underline;
    }}
    .footer-copy {{
      color: var(--muted);
      font-size: 12.5px;
      opacity: 0.75;
    }}
    
    /* Modern 60fps FAQ Accordion */
    details.card {{
      transition: background 0.32s cubic-bezier(0.16, 1, 0.3, 1),
                  border-color 0.32s cubic-bezier(0.16, 1, 0.3, 1),
                  box-shadow 0.32s cubic-bezier(0.16, 1, 0.3, 1),
                  transform 0.25s cubic-bezier(0.16, 1, 0.3, 1);
      overflow: hidden;
      position: relative;
    }}
    details.card:hover {{
      border-color: rgba(255, 255, 255, 0.2);
      transform: translateY(-1px);
    }}
    details.card.is-open,
    details.card[open]:not(.is-closing) {{
      border-color: rgba(47, 191, 113, 0.4) !important;
      background: rgba(47, 191, 113, 0.05) !important;
      box-shadow: 0 8px 30px rgba(0, 0, 0, 0.4), 0 0 25px rgba(47, 191, 113, 0.12);
      transform: translateY(-2px);
    }}
    details.card summary {{
      user-select: none;
      cursor: pointer;
      outline: none;
      list-style: none;
    }}
    details.card summary::-webkit-details-marker,
    details.card summary::marker {{
      display: none;
      content: "";
    }}
    details.card summary span.faq-arrow {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 28px;
      height: 28px;
      border-radius: 50%;
      background: rgba(255, 255, 255, 0.06);
      border: 1px solid var(--glass-border);
      color: var(--green);
      font-size: 11px;
      line-height: 1;
      transform: rotate(0deg);
      transition: transform 0.32s cubic-bezier(0.16, 1, 0.3, 1),
                  background 0.32s ease,
                  border-color 0.32s ease,
                  box-shadow 0.32s ease;
      flex-shrink: 0;
    }}
    details.card.is-open summary span.faq-arrow,
    details.card[open]:not(.is-closing) summary span.faq-arrow {{
      transform: rotate(180deg);
      background: rgba(47, 191, 113, 0.18);
      border-color: rgba(47, 191, 113, 0.5);
      box-shadow: 0 0 14px rgba(47, 191, 113, 0.35);
    }}
    .faq-content {{
      display: grid;
      grid-template-rows: 0fr;
      transition: grid-template-rows 0.32s cubic-bezier(0.16, 1, 0.3, 1);
    }}
    .faq-content-inner {{
      overflow: hidden;
    }}
    .faq-content-inner p {{
      margin: 12px 0 2px 0;
      opacity: 0;
      transform: translateY(-6px);
      transition: opacity 0.28s cubic-bezier(0.16, 1, 0.3, 1),
                  transform 0.28s cubic-bezier(0.16, 1, 0.3, 1);
    }}
    details.card.is-open .faq-content,
    details.card[open]:not(.is-closing) .faq-content {{
      grid-template-rows: 1fr;
    }}
    details.card.is-open .faq-content-inner p,
    details.card[open]:not(.is-closing) .faq-content-inner p {{
      opacity: 1;
      transform: translateY(0);
    }}

    /* Modal Overlay & Card Animations */
    .modal-overlay {{
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.78);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      z-index: 9999;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 16px;
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.3s cubic-bezier(0.16, 1, 0.3, 1);
    }}
    .modal-overlay.active {{
      opacity: 1;
      pointer-events: auto;
    }}
    .modal-card {{
      background: #0d1410;
      border: 1px solid rgba(47, 191, 113, 0.35);
      border-radius: 24px;
      width: 100%;
      max-width: 440px;
      padding: 36px 28px;
      position: relative;
      box-shadow: 0 25px 60px rgba(0, 0, 0, 0.9), 0 0 35px rgba(47, 191, 113, 0.15);
      text-align: center;
      transform: scale(0.92) translateY(16px);
      transition: transform 0.35s cubic-bezier(0.34, 1.56, 0.64, 1);
    }}
    .modal-overlay.active .modal-card {{
      transform: scale(1) translateY(0);
    }}
    @media (max-width: 820px) {{
      .wrap {{
        width: 100% !important;
        max-width: 100% !important;
        padding-left: 14px !important;
        padding-right: 14px !important;
        margin-left: auto !important;
        margin-right: auto !important;
        box-sizing: border-box !important;
      }}
      main.wrap {{
        width: 100% !important;
        max-width: 100% !important;
        padding: 0 14px 40px !important;
        box-sizing: border-box !important;
        overflow-x: clip;
      }}
      .card {{
        padding: 16px;
        border-radius: 14px;
        box-sizing: border-box;
      }}
      .page-card {{
        padding: 20px 16px !important;
        margin: 16px auto !important;
        border-radius: 14px !important;
      }}
      .page-title {{
        font-size: clamp(20px, 5.5vw, 24px) !important;
        margin-bottom: 10px !important;
      }}
      .hero, .order {{
        grid-template-columns: 1fr;
        gap: 16px;
        padding: 16px 0;
      }}
      .hero h1 {{ font-size: 26px; margin-bottom: 10px; }}
      .lead {{ font-size: 14.5px; margin-bottom: 14px; }}
      .advantage-grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }}
      .advantage {{ min-height: 90px; padding: 12px; }}
      .advantage b {{ font-size: 14.5px; margin-bottom: 3px; }}
      .advantage span {{ font-size: 11.5px; }}
      .grid {{ grid-template-columns: 1fr; gap: 14px; }}
      .builder {{
        grid-template-columns: 1fr;
        gap: 14px;
        width: 100%;
        box-sizing: border-box;
      }}
      .builder > .card,
      .builder > .summary-box {{
        width: 100%;
        box-sizing: border-box;
      }}
      .choice-grid {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 6px; }}
      .choice-grid-durations {{ grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 6px; }}
      .choice {{
        min-height: 52px;
        padding: 8px 4px;
        gap: 2px;
        font-size: 11.5px;
        font-weight: 700;
        word-break: normal;
        overflow: visible;
        position: relative;
        box-sizing: border-box;
        min-width: 0;
      }}
      .choice span {{ font-size: 9.5px; font-weight: 400; }}
      .summary-box {{
        position: static;
        padding: 16px;
      }}
      .cf-turnstile {{
        max-width: 100%;
        overflow: hidden;
        display: flex;
        justify-content: center;
      }}
      .mobile-nav-txt {{ display: inline; }}
      .desktop-nav-txt {{ display: none; }}
      header {{
        background: rgba(5, 10, 8, 0.7);
        backdrop-filter: blur(16px);
        -webkit-backdrop-filter: blur(16px);
        border-bottom: 1px solid var(--glass-border);
        position: -webkit-sticky;
        position: sticky;
        top: 0;
        z-index: 1000;
        height: auto;
        padding: 6px 0;
      }}
      nav {{
        height: auto;
        min-height: 48px;
        padding: 0;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
        flex-wrap: nowrap;
      }}
      .brand {{ font-size: 15px; display: inline-flex; align-items: center; gap: 6px; flex-shrink: 0; }}
      .brand-logo {{ width: 24px; height: 24px; border-radius: 6px; flex-shrink: 0; }}
      .navlinks {{ display: grid; grid-template-columns: repeat(6, 1fr); gap: 3px 4px; justify-content: end; align-items: center; max-width: 220px; }}
      .navlinks a {{ background: rgba(255,255,255,0.07); border: 1px solid var(--glass-border); padding: 3px 4px; border-radius: 5px; font-size: 10.5px; font-weight: 600; text-align: center; color: var(--muted); text-decoration: none; white-space: nowrap; line-height: 1.25; }}
      .navlinks a.span-2 {{ grid-column: span 2; }}
      .navlinks a.span-3 {{ grid-column: span 3; }}
      .navlinks a.span-6 {{ grid-column: span 6; color: #2fbf71 !important; font-size: 11px; padding: 3.5px 6px; }}
    }}
    @media (max-width: 360px) {{
      .wrap {{ padding-left: 10px !important; padding-right: 10px !important; }}
      main.wrap {{ padding-left: 10px !important; padding-right: 10px !important; }}
      .card {{ padding: 12px; }}
      .page-card {{ padding: 16px 10px !important; }}
      .page-title {{ font-size: 19px !important; }}
      .choice {{ font-size: 10.5px; padding: 6px 2px; }}
      .choice span {{ font-size: 8.5px; }}
      .cf-turnstile > * {{ transform: scale(0.92); transform-origin: center center; }}
    }}
  </style>
  <script type="application/ld+json">
  {{
    "@context": "https://schema.org",
    "@graph": [
      {{
        "@type": "Organization",
        "@id": "https://silentconnect.net/#organization", "placeholder": "PLACEHOLDER",
        "name": "SilentConnect",
        "url": "https://silentconnect.net", "comment": "PLACEHOLDER",
        "description": "Сервис приватного сетевого доступа для персонального использования без логирования активности",
        "contactPoint": {{
          "@type": "ContactPoint",
          "url": "https://t.me/silentconnect_bot",
          "description": "Служба поддержки через Telegram-бот"
        }}
      }},
      {{
        "@type": "SoftwareApplication",
        "@id": "https://silentconnect.net/#software", "placeholder": "PLACEHOLDER",
        "name": "SilentConnect",
        "applicationCategory": "SecurityApplication",
        "operatingSystem": "iOS, Android, Windows, macOS, Linux",
        "offers": {{
          "@type": "Offer",
          "price": "149",
          "priceCurrency": "RUB",
          "description": "Тарифы от 149 RUB/месяц для защищенного доступа к интернету"
        }},
        "url": "https://silentconnect.net", "comment": "PLACEHOLDER"
      }}
    ]
  }}
  </script>
</head>
<body>
  <header><nav class="wrap"><a href="/" class="brand"><img src="/assets/telegram/avatar.png" alt="SilentConnect" class="brand-logo"><span>SilentConnect</span></a><div class="navlinks"><a href="/#tariffs" class="span-2">Тарифы</a><a href="/about" class="span-2"><span class="desktop-nav-txt">О сервисе</span><span class="mobile-nav-txt">О нас</span></a><a href="/contact" class="span-2">Контакты</a><a href="{html.escape(self.bot_url)}" class="span-3">Telegram-бот</a><a href="{html.escape(self.support_url)}" class="span-3">Поддержка</a><a href="#cabinet" class="span-6" onclick="openCabinetModal(); return false;" style="color: #2fbf71; font-weight: 600;">🔑 Личный кабинет</a></div></nav></header>
  <main class="wrap">{notice_html}{body}</main>
  <footer>
    <div class="wrap footer-wrap">
      <div class="footer-links">
        <a href="/about">О сервисе</a>
        <a href="/contact">Контакты &amp; Поддержка</a>
        <a href="/legal/privacy">Политика конфиденциальности</a>
        <a href="/legal/terms">Пользовательское соглашение</a>
            <a href="/legal/refund">Политика возвратов</a>
      </div>
      <div class="footer-copy">© 2026 SilentConnect. Все права защищены. [code: mekbuda]</div>
    </div>
  </footer>

  <div id="cabinetModal" class="modal-overlay" style="display: none;">
    <div class="modal-card">
      <button type="button" onclick="closeCabinetModal()" style="position: absolute; top: 16px; right: 16px; width: 34px !important; height: 34px !important; min-height: 34px !important; max-height: 34px !important; padding: 0 !important; background: rgba(255,255,255,0.06) !important; border: 1px solid rgba(255,255,255,0.12) !important; border-radius: 50% !important; color: #8ea89a !important; cursor: pointer; display: flex !important; align-items: center !important; justify-content: center !important; outline: none; box-shadow: none !important; aspect-ratio: 1 / 1 !important; transition: all 0.2s;" onmouseover="this.style.borderColor='rgba(47,191,113,0.5)'; this.style.color='#fff';" onmouseout="this.style.borderColor='rgba(255,255,255,0.12)'; this.style.color='#8ea89a';"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg></button>
      <div style="font-size: 40px; margin-bottom: 12px;">🔑</div>
      <h2 style="margin: 0 0 8px; font-size: 24px; color: #fff; background: linear-gradient(to right, #fff, #2fbf71); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">Личный кабинет</h2>
      <p style="color: #8ea89a; font-size: 14px; margin: 0 0 22px; line-height: 1.5;">Укажите Email, указанный при покупке. Мы пришлем прямые ссылки доступа на вашу почту.</p>
      <form id="cabinetForm" onsubmit="submitCabinetForm(event)">
        <input type="email" id="cabinetEmailInput" class="field" placeholder="yourname@gmail.com" required style="text-align: center; font-size: 16px; margin-bottom: 12px; height: 50px; background: rgba(0,0,0,0.4); border-color: rgba(255,255,255,0.12);">
        <div class="cf-turnstile" data-sitekey="{html.escape(self.settings.cf_turnstile_site_key)}" data-theme="dark" data-refresh-expired="auto" style="margin: 12px 0; display: flex; justify-content: center;"></div>
        <button type="submit" id="cabinetSubmitBtn" class="btn" style="width: 100%; min-height: 48px; font-size: 15px;">Получить доступ на Email</button>
      </form>
      <div id="cabinetStatus" style="margin-top: 16px; font-size: 14px; display: none; line-height: 1.5;"></div>
    </div>
  </div>

  <script>
    async function copyText(id) {{
      const el = document.getElementById(id);
      if (!el) return;
      await navigator.clipboard.writeText(el.value || el.textContent);
    }}
    function openCabinetModal() {{
      const modal = document.getElementById("cabinetModal");
      const statusDiv = document.getElementById("cabinetStatus");
      if (modal) {{
        modal.style.display = "flex";
        requestAnimationFrame(() => {{
          requestAnimationFrame(() => {{
            modal.classList.add("active");
          }});
        }});
      }}
      if (statusDiv) statusDiv.style.display = "none";
      const inp = document.getElementById("cabinetEmailInput");
      if (inp) setTimeout(() => inp.focus(), 150);
    }}
    function closeCabinetModal() {{
      const modal = document.getElementById("cabinetModal");
      if (modal) {{
        modal.classList.remove("active");
        setTimeout(() => {{
          modal.style.display = "none";
        }}, 300);
      }}
    }}
    document.addEventListener("keydown", function(e) {{
      if (e.key === "Escape") closeCabinetModal();
    }});
    document.addEventListener("click", function(e) {{
      const modal = document.getElementById("cabinetModal");
      if (modal && e.target === modal) closeCabinetModal();
    }});
    async function submitCabinetForm(e) {{
      e.preventDefault();
      const emailInp = document.getElementById("cabinetEmailInput");
      const btn = document.getElementById("cabinetSubmitBtn");
      const statusDiv = document.getElementById("cabinetStatus");
      const email = (emailInp ? emailInp.value : "").trim();
      if (!email) return;
      const turnstileToken = (document.querySelector('[name="cf-turnstile-response"]') || {{}}).value || (window.turnstile ? window.turnstile.getResponse() : "");
      if (!turnstileToken) {{
        statusDiv.style.display = "block";
        statusDiv.style.color = "#ef4444";
        statusDiv.textContent = "Пожалуйста, подтвердите, что вы человек (поставьте галочку Cloudflare).";
        return;
      }}
      btn.disabled = true;
      btn.textContent = "Ищем подписки...";
      statusDiv.style.display = "block";
      statusDiv.style.color = "#8ea89a";
      statusDiv.textContent = "Отправка запроса...";
      try {{
        const res = await fetch("/api/cabinet/request-link", {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
          body: JSON.stringify({{ email: email, turnstile_token: turnstileToken }})
        }});
        const data = await res.json();
        if (data.ok) {{
          statusDiv.style.color = "#2fbf71";
          statusDiv.innerHTML = "<b>Отлично! 📩</b><br>" + data.message;
          if (emailInp) emailInp.value = "";
          if (window.turnstile) window.turnstile.reset();
          let cd = 30;
          btn.disabled = true;
          const cdInterval = setInterval(() => {{
            btn.textContent = `Повторный запрос через ${{cd}} сек...`;
            cd--;
            if (cd < 0) {{
              clearInterval(cdInterval);
              btn.disabled = false;
              btn.textContent = "Получить доступ на Email";
            }}
          }}, 1000);
          return;
        }} else {{
          statusDiv.style.color = "#ef4444";
          statusDiv.textContent = data.message || "Подписок на этот Email не найдено.";
          if (window.turnstile) window.turnstile.reset();
        }}
      }} catch (err) {{
        statusDiv.style.color = "#ef4444";
        statusDiv.textContent = "Ошибка соединения. Попробуйте снова.";
      }} finally {{
        if (!btn.disabled) {{
          btn.disabled = false;
          btn.textContent = "Получить доступ на Email";
        }}
      }}
    }}

    // Global smooth accordion handler for details.faq-card
    document.addEventListener("DOMContentLoaded", function() {{
      document.querySelectorAll("details.faq-card").forEach(function(el) {{
        const summary = el.querySelector("summary");
        const content = el.querySelector(".faq-content");
        if (!summary || !content) return;
        let isAnimating = false;
        let closeTimer = null;
        summary.addEventListener("click", function(e) {{
          e.preventDefault();
          if (isAnimating) return;
          const isOpen = el.hasAttribute("open") && !el.classList.contains("is-closing");
          if (isOpen) {{
            isAnimating = true;
            clearTimeout(closeTimer);
            el.classList.remove("is-open");
            el.classList.add("is-closing");
            content.style.gridTemplateRows = "0fr";
            const p = content.querySelector("p");
            if (p) {{ p.style.opacity = "0"; p.style.transform = "translateY(-6px)"; }}
            closeTimer = setTimeout(function() {{
              el.removeAttribute("open");
              el.classList.remove("is-closing");
              isAnimating = false;
            }}, 320);
          }} else {{
            isAnimating = true;
            clearTimeout(closeTimer);
            el.classList.remove("is-closing");
            el.setAttribute("open", "");
            content.style.gridTemplateRows = "0fr";
            const p = content.querySelector("p");
            if (p) {{ p.style.opacity = "0"; p.style.transform = "translateY(-6px)"; }}
            requestAnimationFrame(function() {{
              requestAnimationFrame(function() {{
                el.classList.add("is-open");
                content.style.gridTemplateRows = "1fr";
                if (p) {{ p.style.opacity = "1"; p.style.transform = "translateY(0)"; }}
                setTimeout(function() {{
                  isAnimating = false;
                }}, 320);
              }});
            }});
          }}
        }});
      }});
    }});
  </script>
</body>
</html>"""
        return html_doc.encode("utf-8")

    def render_legal_privacy(self) -> bytes:
        body = f"""
        <div class="card page-card">
          <div style="margin-bottom: 20px;">
            <a class="btn secondary" href="/" style="display: inline-flex; width: auto; min-height: 38px; padding: 6px 14px; font-size: 14px;">← На главную к тарифам</a>
          </div>
          <h1 class="page-title">Политика конфиденциальности SilentConnect</h1>
          <p class="muted" style="margin-bottom: 24px;">Редакция от 5 сентября 2026 г. · Принципы обработки данных и защита приватности (152-ФЗ / GDPR)</p>

          <p class="muted">Сервис <strong>SilentConnect</strong> ставит своим абсолютным приоритетом цифровую приватность пользователей. Наша политика предельно прозрачна: мы не собираем и не храним информацию о вашей активности в сети, поэтому мы не можем никому ее передать.</p>

          <h3 style="color: #2fbf71; font-size: 19px; margin-top: 24px;">1. Политика полного отсутствия журналов активности (Zero-Logs Policy)</h3>
          <p class="muted">Мы гарантируем строгое соблюдение принципа ненакопления данных сетевого взаимодействия. Серверные узлы Исполнителя технически настроены так, что мы не записываем, не храним и не передаем третьим лицам:</p>
          <ul class="muted" style="padding-left: 20px; line-height: 1.8;">
            <li>Историю посещенных веб-сайтов, интернет-адреса и обращения к сервисам;</li>
            <li>Исходные IP-адреса абонентских устройств;</li>
            <li>Запросы системы доменных имен (DNS-запросы);</li>
            <li>Содержимое передаваемого трафика, файлов и личной переписки;</li>
            <li>Временные метки (timestamps) открытия и завершения соединений с конкретными ресурсами.</li>
          </ul>

          <h3 style="color: #fff; font-size: 19px; margin-top: 24px;">2. Состав и цели обработки минимально необходимых сведений</h3>
          <p class="muted">В соответствии со ст. 5 Федерального закона № 152-ФЗ «О персональных данных» обработка ограничивается достижением конкретных, заранее определенных и законных целей предоставления доступа. Сервис обрабатывает исключительно необходимый технический минимум:</p>
          <ul class="muted" style="padding-left: 20px; line-height: 1.8;">
            <li><strong style="color:#fff;">Адрес электронной почты (Email):</strong> Используется исключительно для доставки индивидуального ключа доступа, направления фискальных расчетных документов и авторизации в личном кабинете.</li>
            <li><strong style="color:#fff;">Telegram ID и Username:</strong> Сохраняются только при добровольном обращении Пользователя к официальному Telegram-боту сервиса для привязки уведомлений.</li>
            <li><strong style="color:#fff;">Реквизиты заказов:</strong> Номер заказа, дата, сумма транзакции и выбранный тарифный план (необходимы для бухгалтерского и финансового учета).</li>
            <li><strong style="color:#fff;">Служебные файлы Cookies:</strong> Временный токен авторизации в личном кабинете (<code>sc_web_token</code>) и маркер реферальной программы (<code>sc_ref</code>, 30 дней) для применения положенной скидки.</li>
            <li><strong style="color:#fff;">Агрегированные счетчики трафика:</strong> Общий суммарный объем переданных байт без привязки к ресурсам или действиям, используемый исключительно для контроля соблюдения лимита устройств и стабильности сетевых каналов.</li>
          </ul>

          <h3 style="color: #fff; font-size: 19px; margin-top: 24px;">3. Безопасность финансовых транзакций</h3>
          <p class="muted">Исполнитель <strong style="color:#fff;">НЕ собирает, НЕ обрабатывает и НЕ хранит</strong> данные банковских карт Пользователей (номера карт, срок действия, CVV/CVC-коды). Все платежи проводятся непосредственно через защищенные платежные шлюзы сертифицированных банков-эквайеров и платежных провайдеров в соответствии со стандартами безопасности PCI DSS и регламентом Системы быстрых платежей (СБП / НСПК).</p>

          <h3 style="color: #fff; font-size: 19px; margin-top: 24px;">4. Взаимодействие с государственными органами и третьими лицами</h3>
          <p class="muted">Мы соблюдаем применимое законодательство. Однако, в силу технической архитектуры Платформы и строгого соблюдения Zero-Logs Policy, мы физически не ведем и не накапливаем журналы сетевой активности и сопоставления трафика с конкретными пользователями. Сервис не имеет технической возможности раскрыть то, чем он не владеет.</p>

          <h3 style="color: #fff; font-size: 19px; margin-top: 24px;">5. Права субъекта персональных данных</h3>
          <p class="muted">Пользователь вправе в любой момент отозвать свое согласие на обработку контактных данных и запросить полное удаление своей учетной записи и истории заказов, направив письменное заявление по официальному адресу <a href="mailto:{html.escape(self.settings.support_email)}" style="color: var(--green); text-decoration: underline;">{html.escape(self.settings.support_email)}</a>. Данные удаляются в течение 72 часов с момента подтверждения запроса.</p>

          <h3 style="color: #fff; font-size: 19px; margin-top: 24px;">6. Контакты службы поддержки</h3>
          <p class="muted">
            Электронная почта: <a href="mailto:{html.escape(self.settings.support_email)}" style="color: var(--green); text-decoration: underline;">{html.escape(self.settings.support_email)}</a><br>
            Telegram-бот поддержки: <a href="{html.escape(self.support_url)}" style="color: var(--green); text-decoration: underline;" target="_blank">{html.escape(self.support_url)}</a>
          </p>
        </div>
        """
        return self.render_page("Политика конфиденциальности", body)

    def render_legal_terms(self) -> bytes:
        body = f"""
        <div class="card page-card">
          <div style="margin-bottom: 20px;">
            <a class="btn secondary" href="/" style="display: inline-flex; width: auto; min-height: 38px; padding: 6px 14px; font-size: 14px;">← На главную к тарифам</a>
          </div>
          <h1 class="page-title">Пользовательское соглашение (Публичная оферта)</h1>
          <p class="muted" style="margin-bottom: 24px;">Редакция от 5 сентября 2026 г. · Условия оказания услуг по ст. 435, 437, 438 ГК РФ</p>

          <p class="muted">Настоящее Пользовательское соглашение (далее — «Соглашение» или «Оферта») регулирует отношения между Администрацией сервиса <strong>SilentConnect</strong> (далее — «Исполнитель») и любым физическим или юридическим лицом, использующим сервисы Сайта, Telegram-бота или инфраструктуру Платформы (далее — «Пользователь»).</p>

          <h3 style="color: #fff; font-size: 19px; margin-top: 24px;">1. Термины и определения</h3>
          <ul class="muted" style="padding-left: 20px; line-height: 1.8;">
            <li><strong style="color:#fff;">Сервис (Платформа)</strong> — программно-аппаратный комплекс SilentConnect, предназначенный для защищенного сетевого взаимодействия, криптографической маршрутизации и безопасной передачи данных через интернет.</li>
            <li><strong style="color:#fff;">Индивидуальный ключ доступа</strong> — уникальная зашифрованная ссылка (URL подписки) либо конфигурационный файл, генерируемый для аутентификации абонентских устройств Пользователя на узлах Сервиса.</li>
            <li><strong style="color:#fff;">Заказ</strong> — действие Пользователя по выбору Тарифа, заполнению контактных данных и оплате услуг через сайт или интерфейс бота.</li>
            <li><strong style="color:#fff;">Тариф</strong> — установленный Исполнителем объем прав доступа, определяющий срок подписки и лимит одновременно подключенных устройств (3, 6 или 9 устройств).</li>
          </ul>

          <h3 style="color: #fff; font-size: 19px; margin-top: 24px;">2. Акцепт оферты и заключение договора</h3>
          <p class="muted">2.1. Настоящий документ является публичной офертой в соответствии со статьями 435 и 437 Гражданского кодекса Российской Федерации (ГК РФ).</p>
          <p class="muted">2.2. Полным и безоговорочным акцептом настоящей Оферты (ст. 438 ГК РФ) признается совершение Пользователем любого из следующих конклюдентных действий: нажатие кнопки оформления/оплаты заказа, совершение платежа, авторизация в боте либо фактическое использование сгенерированного индивидуального ключа доступа.</p>
          <p class="muted">2.3. Акцептуя Оферту, Пользователь подтверждает, что достиг совершеннолетия, обладает полной право- и дееспособностью, ознакомился и безоговорочно согласен со всеми положениями настоящего Соглашения, а также с <a href="/legal/privacy" style="color: var(--green); text-decoration: underline;">Политикой конфиденциальности</a> и <a href="/legal/refund" style="color: var(--green); text-decoration: underline;">Политикой возвратов</a>.</p>

          <h3 style="color: #2fbf71; font-size: 19px; margin-top: 24px;">3. Предмет соглашения и момент исполнения обязательств</h3>
          <p class="muted">3.1. Исполнитель предоставляет Пользователю неисключительное право использования программного обеспечения и услуги защищенного сетевого взаимодействия для безопасной передачи данных в соответствии с выбранным Тарифом.</p>
          <p class="muted">3.2. <strong style="color:#fff;">Момент оказания услуг:</strong> Обязательства Исполнителя по предоставлению доступа считаются исполненными надлежащим образом и в полном объеме в момент автоматической генерации и отображения индивидуального ключа доступа (URL подписки) в веб-интерфейсе либо отправки на указанный Пользователем адрес электронной почты или в Telegram. Фактическая настройка клиентского ПО на стороне абонентского оборудования осуществляется Пользователем самостоятельно.</p>

          <h3 style="color: #fff; font-size: 19px; margin-top: 24px;">4. Стоимость услуг и порядок расчетов</h3>
          <p class="muted">4.1. Стоимость Тарифов публикуется на Сайте и в интерфейсах Сервиса в российских рублях (RUB). Исполнитель вправе в одностороннем порядке изменять стоимость будущих периодов; изменение стоимости уже оплаченного Пользователем периода не допускается.</p>
          <p class="muted">4.2. Оплата производится через сертифицированные платежные шлюзы (включая Систему быстрых платежей СБП / НСПК и банковские карты). Обязательства по оплате считаются исполненными с момента подтверждения зачисления средств банком-эквайером.</p>
          <p class="muted">4.3. Автоматические скрытые списания (рекуррентные подписки без предварительного согласия) сервисом не применяются. Продление осуществляется по добровольной инициативе Пользователя.</p>

          <h3 style="color: #fff; font-size: 19px; margin-top: 24px;">5. Правила добросовестного использования (Fair Use Policy)</h3>
          <p class="muted">5.1. Пользователь обязуется использовать Сервис исключительно в законных целях для личных и семейных нужд в пределах лимита устройств по Тарифу (до 3, 6 или 9 устройств одновременно).</p>
          <p class="muted">5.2. Категорически запрещается использовать Сервис для:</p>
          <ul class="muted" style="padding-left: 20px; line-height: 1.8;">
            <li>Осуществления массовых спам-рассылок, фишинга, мошеннических действий и социальной инженерии;</li>
            <li>Проведения сетевых атак любого рода (DDoS, брутфорс, несанкционированное сканирование портов и уязвимостей);</li>
            <li>Распространения вредоносного программного обеспечения, эксплойтов и троянских программ;</li>
            <li>Нарушения законодательства РФ и прав интеллектуальной собственности третьих лиц;</li>
            <li>Организации публичных прокси-серверов, майнинга, торрент-ферм и перепродажи доступа третьим лицам.</li>
          </ul>
          <p class="muted">5.3. При выявлении грубых нарушений п. 5.2 Исполнитель оставляет за собой право немедленно приостановить или заблокировать доступ без компенсации и возврата средств.</p>

          <h3 style="color: #fff; font-size: 19px; margin-top: 24px;">6. Ограничение ответственности и отказ от гарантий</h3>
          <p class="muted">6.1. Сервис предоставляется на условиях «КАК ЕСТЬ» («AS IS»). Исполнитель принимает все разумные меры для обеспечения непрерывной и стабильной работы узлов связи, однако не гарантирует абсолютную безошибочность или бесперебойность.</p>
          <p class="muted">6.2. Исполнитель не несет ответственности за временные перебои, вызванные действиями локальных интернет-провайдеров Пользователя, магистральных операторов связи, авариями кабельной инфраструктуры, плановыми техническими работами и сетевыми сбоями сторонних операторов связи либо иными форс-мажорными обстоятельствами вне контроля Исполнителя.</p>
          <p class="muted">6.3. Совокупная ответственность Исполнителя по любым претензиям строго ограничена суммой, фактически уплаченной Пользователем за текущий расчетный период.</p>

          <h3 style="color: #fff; font-size: 19px; margin-top: 24px;">7. Изменение условий и контакты</h3>
          <p class="muted">7.1. Исполнитель вправе в одностороннем порядке вносить изменения в настоящую Оферту. Новая редакция вступает в силу с момента ее публикации на данной странице.</p>
          <p class="muted">
            Электронная почта поддержки: <a href="mailto:{html.escape(self.settings.support_email)}" style="color: var(--green); text-decoration: underline;">{html.escape(self.settings.support_email)}</a><br>
            Telegram-бот поддержки: <a href="{html.escape(self.support_url)}" style="color: var(--green); text-decoration: underline;" target="_blank">{html.escape(self.support_url)}</a>
          </p>
        </div>
        """
        return self.render_page("Пользовательское соглашение", body)

    def render_legal_refund(self) -> bytes:
        body = f"""
        <div class="card page-card">
          <div style="margin-bottom: 20px;">
            <a class="btn secondary" href="/" style="display: inline-flex; width: auto; min-height: 38px; padding: 6px 14px; font-size: 14px;">← На главную к тарифам</a>
          </div>
          <h1 class="page-title">Политика возврата денежных средств и отмены подписки</h1>
          <p class="muted" style="margin-bottom: 24px;">Редакция от 5 сентября 2026 г. · Регламент рассмотрения и взаиморасчетов (СБП / НСПК / Fair Use)</p>

          <p class="muted">Мы стремимся обеспечить максимальный комфорт при использовании сервиса SilentConnect. Если сервис по техническим причинам вам не подошел, вы вправе запросить возврат денежных средств в рамках правил добросовестного использования (Fair Use Policy).</p>

          <h3 style="color: #2fbf71; font-size: 19px; margin-top: 24px;">1. Гарантия возврата (Money-back Guarantee)</h3>
          <p class="muted">1.1. Исполнитель предоставляет гарантию возврата 100% уплаченных средств в течение <strong style="color:#fff;">14 (четырнадцати) календарных дней</strong> с момента оплаты, если Пользователь не удовлетворен качеством работы сервиса.</p>
          <p class="muted">1.2. Гарантия возврата распространяется <strong style="color:#fff;">исключительно на первый заказ (первую покупку)</strong>, совершенную с уникального аккаунта пользователя.</p>
          <p class="muted">1.3. Повторные покупки, продления действующей подписки, а также дополнительные заказы тем же пользователем (определяемым по email, Telegram ID либо платежным реквизитам) <strong style="color:#fff;">возврату не подлежат</strong>. Факт повторной оплаты услуги юридически подтверждает полную удовлетворенность Пользователя качеством сервиса за предыдущие периоды.</p>

          <h3 style="color: #fff; font-size: 19px; margin-top: 24px;">2. Условия отказа в возврате (Ограничения Fair Use)</h3>
          <p class="muted">Для защиты инфраструктуры от злоупотреблений и паразитарной нагрузки возврат средств не производится в следующих случаях:</p>
          <ul class="muted" style="padding-left: 20px; line-height: 1.8;">
            <li><strong style="color:#fff;">Лимит трафика (Data Cap):</strong> Если с момента генерации доступа через аккаунт прошло более <strong style="color:#fff;">5 ГБ (Гигабайт)</strong> суммарного трафика. Превышение порога в 5 ГБ юридически признается Сторонами фактом полного потребления услуги и надлежащего качества соединения;</li>
            <li><strong style="color:#fff;">Истечение срока:</strong> Обращение направлено позднее 14 календарных дней с момента совершения оплаты;</li>
            <li><strong style="color:#fff;">Нарушение правил (AUP):</strong> Аккаунт был заблокирован за нарушение правил допустимого использования (спам, сканирование, атаки, реселлинг);</li>
            <li><strong style="color:#fff;">Локальные ограничения клиента:</strong> Серверная инфраструктура исправна, но клиент не может настроить соединение из-за ограничений на стороне своего локального интернет-провайдера либо специфики личного устройства при условии, что служба поддержки предоставила инструкции и альтернативные конфигурации;</li>
            <li><strong style="color:#fff;">Анонимные транзакции:</strong> Платежи, совершенные в криптовалюте, в силу необратимости блокчейн-транзакций возврату не подлежат (возможна компенсация дополнительными днями доступа).</li>
          </ul>

          <h3 style="color: #fff; font-size: 19px; margin-top: 24px;">3. Регламент и процедура оформления возврата</h3>
          <p class="muted">3.1. Для оформления возврата направьте запрос по официальному адресу <a href="mailto:{html.escape(self.settings.support_email)}" style="color: var(--green); text-decoration: underline;">{html.escape(self.settings.support_email)}</a> либо через верифицированный <a href="{html.escape(self.support_url)}" style="color: var(--green); text-decoration: underline;" target="_blank">Telegram-бот поддержки</a>.</p>
          <p class="muted">3.2. В обращении необходимо указать:</p>
          <ul class="muted" style="padding-left: 20px; line-height: 1.8;">
            <li>Номер заказа (#ord_...) и контактный Email или Telegram ID;</li>
            <li>Дату и сумму оплаты, приложив чек или электронную квитанцию;</li>
            <li>Краткую причину обращения.</li>
          </ul>
          <p class="muted">3.3. Единственным объективным доказательством факта использования услуги являются серверные счетчики биллинга трафика. Скриншоты замера скорости сторонних утилит не требуются.</p>
          <p class="muted">3.4. Срок рассмотрения заявления службой поддержки составляет <strong style="color:#fff;">до 48 часов</strong> (не более 3 рабочих дней).</p>
          <p class="muted">3.5. Выплата денежных средств осуществляется тем же способом, которым производилась оплата: через Систему быстрых платежей (СБП / НСПК) по номеру телефона плательщика либо на банковскую карту. Срок зачисления банком получателя составляет <strong style="color:#fff;">от 1 до 3 банковских дней</strong>.</p>

          <h3 style="color: #fff; font-size: 19px; margin-top: 24px;">4. Контакты службы поддержки</h3>
          <p class="muted">
            Электронная почта: <a href="mailto:{html.escape(self.settings.support_email)}" style="color: var(--green); text-decoration: underline;">{html.escape(self.settings.support_email)}</a><br>
            Telegram-бот поддержки: <a href="{html.escape(self.support_url)}" style="color: var(--green); text-decoration: underline;" target="_blank">{html.escape(self.support_url)}</a>
          </p>
        </div>
        """
        return self.render_page("Политика возвратов", body)

    def render_about(self) -> bytes:
        body = f"""
        <div class="card page-card">
          <div style="margin-bottom: 20px;">
            <a class="btn secondary" href="/" style="display: inline-flex; width: auto; min-height: 38px; padding: 6px 14px; font-size: 14px;">← На главную к тарифам</a>
          </div>
          <h1 class="page-title">О сервисе SilentConnect</h1>
          <p class="muted" style="margin-bottom: 24px;">Передовой сервис приватного сетевого доступа нового поколения, созданный для безопасного и стабильного интернета.</p>
          
          <h3 style="color: #fff; font-size: 20px; margin-top: 24px;">Наша миссия</h3>
          <p class="muted">Мы верим, что свободный и безопасный доступ к информации — это фундаментальное право каждого человека. SilentConnect создавался с нуля для работы в сложных сетевых условиях, где стандартные методы подключения легко распознаются и замедляются провайдерами.</p>

          <h3 style="color: #2fbf71; font-size: 20px; margin-top: 24px;">Инфраструктура и технологии:</h3>
          <ul class="muted" style="padding-left: 20px; line-height: 1.8;">
            <li><strong style="color:#fff;">Современное защищенное шифрование:</strong> Наш трафик маскируется под стандартный защищенный протокол веб-сервисов. Для сетевых фильтров ваше подключение выглядит как обычный визит на веб-сайт.</li>
            <li><strong style="color:#fff;">Европейские гигабитные узлы:</strong> Серверы размещены в современных дата-центрах Нидерландов и Финляндии с прямыми магистральными каналами связи и минимальным пингом.</li>
            <li><strong style="color:#fff;">Умная доставка и личный кабинет:</strong> Мгновенная генерация подписки, отправка чеков и ключей на Email, удобное управление через веб-интерфейс и Telegram-бота.</li>
            <li><strong style="color:#fff;">Поддержка любых устройств:</strong> Готовые мастера установки под iOS (Happ, Streisand), Android (Happ, V2RayTun), Windows, macOS, Linux, Android TV и Apple TV.</li>
          </ul>

          <p class="muted" style="margin-top: 28px;">Техническая поддержка: <a href="mailto:{html.escape(self.settings.support_email)}" style="color: var(--green); text-decoration: underline;">{html.escape(self.settings.support_email)}</a></p>
        </div>
        """
        return self.render_page("О сервисе", body)

    def render_contact(self) -> bytes:
        body = f"""
        <div class="card page-card">
          <div style="margin-bottom: 20px;">
            <a class="btn secondary" href="/" style="display: inline-flex; width: auto; min-height: 38px; padding: 6px 14px; font-size: 14px;">← На главную к тарифам</a>
          </div>
          <h1 class="page-title">Контакты &amp; Поддержка</h1>
          <p class="muted" style="margin-bottom: 24px;">Мы работаем круглосуточно и готовы оперативно помочь с любыми вопросами по настройке и оплате.</p>

          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin: 24px 0;">
            <div style="background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; padding: 20px;">
              <h3 style="color: #2fbf71; margin-top:0; font-size: 18px;">✉️ Электронная почта</h3>
              <p class="muted" style="font-size: 14px; margin-bottom: 12px;">Вопросы по заказам, чекам, возвратам и корпоративным подпискам:</p>
              <a href="mailto:{html.escape(self.settings.support_email)}" style="color: #fff; font-weight: bold; font-size: 16px; text-decoration: underline;">{html.escape(self.settings.support_email)}</a>
            </div>

            <div style="background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; padding: 20px;">
              <h3 style="color: #0088cc; margin-top:0; font-size: 18px;">✈️ Telegram Поддержка</h3>
              <p class="muted" style="font-size: 14px; margin-bottom: 12px;">Мгновенная помощь специалиста, проверка статуса ключей и продление доступа:</p>
              <a href="{html.escape(self.support_url)}" style="color: #fff; font-weight: bold; font-size: 16px; text-decoration: underline;" target="_blank">{html.escape(self.support_url)}</a>
            </div>
          </div>

          <h3 style="color: #fff; font-size: 18px; margin-top: 24px;">Режим работы поддержки:</h3>
          <p class="muted">Консультации и техническая помощь предоставляются круглосуточно (24/7/365). Среднее время ответа в Telegram — 2–5 минут, по электронной почте — до 15–30 минут.</p>
        </div>
        """
        return self.render_page("Контакты & Поддержка", body)

    def render_home(
        self,
        *,
        active_discount: dict[str, Any] | None = None,
        promo_code: str = "",
        flash: str = "",
        ref_code: str = "",
    ) -> bytes:
        discount_percent = int(active_discount["discount_percent"]) if active_discount else 0
        ref_banner = ""
        clean_ref = ref_code.strip()
        if clean_ref:
            ref_referrer = self.store.get_referrer_by_code(clean_ref)
            if ref_referrer:
                ref_banner = '<div class="notice" style="background: rgba(47, 191, 113, 0.15); border-color: rgba(47, 191, 113, 0.4); color: #2fbf71; font-weight: 600; margin-bottom: 12px;">🎁 Реферальный бонус: вам доступна скидка 10% на первую подписку!</div>'
                discount_percent = max(discount_percent, REFERRAL_INVITEE_DISCOUNT_PERCENT)
        escaped_promo_code = html.escape(promo_code.strip())
        flash_html = f'<div class="notice">{html.escape(flash)}</div>' if flash else ""
        promo_hidden = f'<input type="hidden" name="promo_code" value="{escaped_promo_code}">' if active_discount else ""
        ref_hidden = f'<input type="hidden" name="ref_code" value="{html.escape(clean_ref)}">' if clean_ref else ""
        discount_line = f" Активна скидка {discount_percent}%." if discount_percent > 0 else ""

        plans: dict[str, dict[str, Any]] = {}
        for device_limit in (3, 6, 9):
            for duration_days in (30, 90, 180, 360):
                for mode in ("tcp", "hybrid"):
                    offer_code = f"{mode}_{device_limit}_{duration_days}"
                    offer = self.offers.get(offer_code) or self.offers.get(f"tcp_{device_limit}_{duration_days}")
                    if not offer:
                        continue
                    final_price = max(offer.price_rub * (100 - discount_percent) // 100, 0)
                    plans[offer.code] = {
                        "code": offer.code,
                        "title": "Универсальный" if mode == "hybrid" else "Стандартный",
                        "deviceTitle": {3: "Личный", 6: "Домашний", 9: "Расширенный"}[device_limit],
                        "deviceLimit": device_limit,
                        "duration": {30: "1 месяц", 90: "3 месяца", 180: "6 месяцев", 360: "12 месяцев"}[duration_days],
                        "price": final_price,
                        "basePrice": offer.price_rub,
                        "discount": discount_percent,
                    }
        plans_json = json.dumps(plans, ensure_ascii=False)
        initial_price = int(plans["tcp_3_30"]["price"])

        body = f"""
        <section class="hero">
          <div>
            <h1>Приватный доступ, который просто работает</h1>
            <p class="lead">Включили один раз — и забыли. Выберите тариф, получите готовую ссылку для приложения на почту и пользуйтесь открытым интернетом.</p>
            {ref_banner}
            <div class="notice">Ссылка на подписку придёт на электронную почту и появится на сайте сразу после оплаты</div>
          </div>
          <img class="hero-img" src="/assets/telegram/welcome.png" alt="SilentConnect">
        </section>
        <section class="section" style="padding-top: 0;">
          <div class="advantage-grid">
            <div class="advantage">
              <b>Готовая подписка</b>
              <span>Одна ссылка для телефона и ПК с автообновлением профилей.</span>
            </div>
            <div class="advantage">
              <b>Устойчивые режимы</b>
              <span>Стандартный и универсальный доступ обеспечивают высокую стабильность соединения.</span>
            </div>
            <div class="advantage">
              <b>Доставка на Email</b>
              <span>Ваши ссылки никогда не потеряются и останутся в ящике.</span>
            </div>
            <div class="advantage">
              <b>Живая поддержка</b>
              <span>Помогаем с настройкой на iOS, Android и Windows 24/7.</span>
            </div>
          </div>
        </section>
        <section class="section order">
          <div class="card">
            <div>
              <strong>Есть промокод?</strong>
              <p class="muted" style="margin-bottom: 14px;">Введите код здесь. Скидочный код пересчитает тарифы, а подарочный зафиксирует подписку.</p>
              <div id="promo-status" style="margin-bottom: 12px; font-size: 13.5px; display: none; line-height: 1.4;"></div>
            </div>
            <form onsubmit="submitPromoAjax(event);" style="display: flex; flex-direction: column; gap: 10px; margin-top: auto;">
              <input class="field" id="promo_code_input" name="promo_code" value="{escaped_promo_code}" placeholder="PROMO-XXXX-XXXX" autocomplete="off" style="text-transform: uppercase;">
              <button type="submit" id="promo_submit_btn" style="min-height: 44px; font-size: 14.5px;">Применить промокод</button>
            </form>
          </div>
          <div class="card">
            <div>
              <strong>Поддержка и Telegram-бот</strong>
              <p class="muted" style="margin-bottom: 14px;">Вы можете привязать подписку в Telegram-боте для удобного продления и уведомлений.</p>
            </div>
            <div style="margin-top: auto;">
              <a class="btn secondary" href="{html.escape(self.bot_url)}" style="min-height: 44px; font-size: 14.5px;">Открыть Telegram-бота</a>
            </div>
          </div>
        </section>
        <section id="tariffs" class="section">
          <div class="section-head">
            <h2>Выберите тариф</h2>
            <p class="muted">Выберите количество устройств и срок доступа.{html.escape(discount_line)}</p>
          </div>
          <div class="builder">
            <div class="card">
              <div class="choice-section">
                <div class="choice-title">Количество устройств</div>
                <div class="choice-grid">
                  <button type="button" class="choice active" data-choice data-group="device" data-value="3">Личный<span>до 3 устройств</span></button>
                  <button type="button" class="choice" data-choice data-group="device" data-value="6">Домашний<span>до 6 устройств</span></button>
                  <button type="button" class="choice" data-choice data-group="device" data-value="9">Расширенный<span>до 9 устройств</span></button>
                </div>
              </div>
              <div class="choice-section">
                <div class="choice-title">Срок доступа</div>
                <div class="choice-grid choice-grid-durations">
                  <button type="button" class="choice active" data-choice data-group="duration" data-value="30">1 месяц<span>помесячно</span></button>
                  <button type="button" class="choice" data-choice data-group="duration" data-value="90"><span class="badge" style="position: absolute; top: -7px; right: 2px; font-size: 9px; padding: 1px 5px; z-index: 2;">−10%</span>3 месяца<span>экономия</span></button>
                  <button type="button" class="choice" data-choice data-group="duration" data-value="180"><span class="badge" style="position: absolute; top: -7px; right: 2px; font-size: 9px; padding: 1px 5px; z-index: 2;">−20%</span>6 месяцев<span>выгодно</span></button>
                  <button type="button" class="choice" data-choice data-group="duration" data-value="360"><span class="badge" style="position: absolute; top: -7px; right: 2px; font-size: 9px; padding: 1px 5px; z-index: 2;">−30%</span>12 месяцев<span>максимум</span></button>
                </div>
              </div>
            </div>
            <form class="card summary-box" method="post" action="/order" onsubmit="return handleOrderSubmit(event);">
              <strong id="builder-title">Личный</strong>
              <p class="summary-note" id="builder-subtitle">До 3 устройств · 1 месяц</p>
              <div class="summary-row"><span>Устройства</span><b id="builder-devices">до 3</b></div>
              <div class="summary-row"><span>Срок</span><b id="builder-duration">1 месяц</b></div>
              <div class="summary-price" id="builder-price">{initial_price} ₽</div>
              
              <div style="margin-bottom: 14px;">
                <label style="color:var(--muted); font-size:13px; font-weight:600; display:block; margin-bottom:6px;">Электронная почта (для отправки ссылки подписки)</label>
                <input class="field" type="email" name="customer_email" placeholder="pochta@gmail.com" required autocomplete="email">
              </div>

              <div style="font-size:12px; color:var(--muted); margin-bottom:14px;">
                <input type="checkbox" name="terms_ack" id="terms_ack" checked required style="margin-right:6px;">
                <label for="terms_ack">Согласен с <a href="/legal/privacy" target="_blank" style="color:var(--green); text-decoration:underline;">политикой конфиденциальности</a> и <a href="/legal/terms" target="_blank" style="color:var(--green); text-decoration:underline;">офертой</a></label>
              </div>

              <div style="font-size:12px; color:var(--muted); margin-bottom:14px;">
                <input type="checkbox" name="email_reminders" id="email_reminders" value="1" checked style="margin-right:6px;">
                <label for="email_reminders">Напоминать об окончании подписки за 24ч и 1ч на почту</label>
              </div>

              <input id="builder-offer" type="hidden" name="offer" value="tcp_3_30">
              {promo_hidden}
              {ref_hidden}
              <div class="cf-turnstile" data-sitekey="{html.escape(self.settings.cf_turnstile_site_key)}" data-theme="dark" data-refresh-expired="auto" style="margin: 14px 0; display: flex; justify-content: center;"></div>
              <div id="orderFormStatus" style="margin: -6px 0 10px; font-size: 13px; color: #ef4444; display: none; text-align: center; line-height: 1.4;"></div>
              <button type="submit">Перейти к оплате</button>
            </form>
          </div>
        </section>
        <section class="section">
          <div class="section-head">
            <h2>3 простых шага к свободному интернету</h2>
            <p class="muted">Всё настраивается за 2 минуты.</p>
          </div>
          <div class="grid">
            <div class="card">
              <strong style="color: var(--green); font-size: 32px; margin-bottom: 12px;">01</strong>
              <strong>Выберите тариф и укажите почту</strong>
              <p class="muted" style="font-size: 15px;">Выберите количество устройств, срок подписки и укажите ваш Email. На него мы отправим готовые ссылки доступа.</p>
            </div>
            <div class="card">
              <strong style="color: var(--green); font-size: 32px; margin-bottom: 12px;">02</strong>
              <strong>Скачайте приложение</strong>
              <p class="muted" style="font-size: 15px;">Страница заказа и письмо на почте определят ваше устройство и покажут кнопку скачивания Happ / Streisand / v2rayN.</p>
            </div>
            <div class="card">
              <strong style="color: var(--green); font-size: 32px; margin-bottom: 12px;">03</strong>
              <strong>Импортируйте ссылку</strong>
              <p class="muted" style="font-size: 15px;">Нажмите кнопку «Импортировать» или скопируйте ссылку подписки из письма. Всё готово!</p>
            </div>
          </div>
        </section>
        <section class="section">
          <div class="section-head">
            <h2>Ответы на вопросы (FAQ)</h2>
            <p class="muted">Простые ответы для всех пользователей.</p>
          </div>
          <div style="display: grid; gap: 12px;">
            <details class="card faq-card" style="padding: 16px 20px; cursor: pointer;">
              <summary style="font-weight: 700; font-size: 16px; color: #fff; list-style: none; display: flex; justify-content: space-between; align-items: center; font-family: 'Outfit', sans-serif;">
                Действительно ли трафик безлимитный?
                <span class="faq-arrow">▼</span>
              </summary>
              <div class="faq-content">
                <div class="faq-content-inner">
                  <p class="muted" style="font-size: 14.5px; margin-top: 10px; margin-bottom: 0; line-height: 1.55;">Да, мы не ограничиваем гигабайты и скорость передачи данных. Действует прозрачная политика добросовестного использования (Fair Use Policy) — сервис рассчитан на комфортное личное и семейное применение (браузинг, просмотр 4K-видео, игры, стриминг, повседневная загрузка файлов). Не допускается использование инфраструктуры для коммерческого парсинга, спам-рассылок, непрерывных торрент-ферм и иных сценариев, создающих паразитную перегрузку каналов связи.</p>
                </div>
              </div>
            </details>
            <details class="card faq-card" style="padding: 16px 20px; cursor: pointer;">
              <summary style="font-weight: 700; font-size: 16px; color: #fff; list-style: none; display: flex; justify-content: space-between; align-items: center; font-family: 'Outfit', sans-serif;">
                Будут ли работать нужные мне сайты?
                <span class="faq-arrow">▼</span>
              </summary>
              <div class="faq-content">
                <div class="faq-content-inner">
                  <p class="muted" style="font-size: 14.5px; margin-top: 10px; margin-bottom: 0; line-height: 1.55;">Да! Наш сервис использует современное защищенное шифрование. Все популярные ресурсы будут открываться мгновенно и стабильно.</p>
                </div>
              </div>
            </details>
            <details class="card faq-card" style="padding: 16px 20px; cursor: pointer;">
              <summary style="font-weight: 700; font-size: 16px; color: #fff; list-style: none; display: flex; justify-content: space-between; align-items: center; font-family: 'Outfit', sans-serif;">
                На каких устройствах работает SilentConnect?
                <span class="faq-arrow">▼</span>
              </summary>
              <div class="faq-content">
                <div class="faq-content-inner">
                  <p class="muted" style="font-size: 14.5px; margin-top: 10px; margin-bottom: 0; line-height: 1.55;">На любых! Вы можете настроить подключение на iPhone, iPad, Android-смартфоны, планшеты, а также на компьютеры Windows, macOS и Linux.</p>
                </div>
              </div>
            </details>
            <details class="card faq-card" style="padding: 16px 20px; cursor: pointer;">
              <summary style="font-weight: 700; font-size: 16px; color: #fff; list-style: none; display: flex; justify-content: space-between; align-items: center; font-family: 'Outfit', sans-serif;">
                Зачем указывать почту?
                <span class="faq-arrow">▼</span>
              </summary>
              <div class="faq-content">
                <div class="faq-content-inner">
                  <p class="muted" style="font-size: 14.5px; margin-top: 10px; margin-bottom: 0; line-height: 1.55;">Мы отправляем ссылки доступа на вашу электронную почту, чтобы вы могли легко найти их с любого нового устройства и не потеряли доступ.</p>
                </div>
              </div>
            </details>
            <details class="card faq-card" style="padding: 16px 20px; cursor: pointer;">
              <summary style="font-weight: 700; font-size: 16px; color: #fff; list-style: none; display: flex; justify-content: space-between; align-items: center; font-family: 'Outfit', sans-serif;">
                Сколько устройств можно подключить одновременно?
                <span class="faq-arrow">▼</span>
              </summary>
              <div class="faq-content">
                <div class="faq-content-inner">
                  <p class="muted" style="font-size: 14.5px; margin-top: 10px; margin-bottom: 0; line-height: 1.55;">В зависимости от вашего тарифа — от 3 до 9 устройств одновременно (смартфоны, планшеты, ПК, Smart TV). Каждое устройство получит персональный высокоскоростной тоннель.</p>
                </div>
              </div>
            </details>
            <details class="card faq-card" style="padding: 16px 20px; cursor: pointer;">
              <summary style="font-weight: 700; font-size: 16px; color: #fff; list-style: none; display: flex; justify-content: space-between; align-items: center; font-family: 'Outfit', sans-serif;">
                Сохранится ли подписка при смене или сбросе телефона?
                <span class="faq-arrow">▼</span>
              </summary>
              <div class="faq-content">
                <div class="faq-content-inner">
                  <p class="muted" style="font-size: 14.5px; margin-top: 10px; margin-bottom: 0; line-height: 1.55;">Да! Ваша подписка привязана к вашему e-mail и Telegram-аккаунту. Достаточно открыть письмо или зайти в Telegram-бота с нового устройства и нажать «Добавить подписку».</p>
                </div>
              </div>
            </details>
            <details class="card faq-card" style="padding: 16px 20px; cursor: pointer;">
              <summary style="font-weight: 700; font-size: 16px; color: #fff; list-style: none; display: flex; justify-content: space-between; align-items: center; font-family: 'Outfit', sans-serif;">
                Почему у SilentConnect высокая скорость и стабильное соединение?
                <span class="faq-arrow">▼</span>
              </summary>
              <div class="faq-content">
                <div class="faq-content-inner">
                  <p class="muted" style="font-size: 14.5px; margin-top: 10px; margin-bottom: 0; line-height: 1.55;">Мы используем современный оптимизированный стек протоколов REALITY и XHTTP со сквозным шифрованием TLS. Трафик направляется по выделенным скоростным каналам европейских дата-центров, обеспечивая максимальную отзывчивость без потери пакетов.</p>
                </div>
              </div>
            </details>
            <details class="card faq-card" style="padding: 16px 20px; cursor: pointer;">
              <summary style="font-weight: 700; font-size: 16px; color: #fff; list-style: none; display: flex; justify-content: space-between; align-items: center; font-family: 'Outfit', sans-serif;">
                Что делать, если возникнут трудности?
                <span class="faq-arrow">▼</span>
              </summary>
              <div class="faq-content">
                <div class="faq-content-inner">
                  <p class="muted" style="font-size: 14.5px; margin-top: 10px; margin-bottom: 0; line-height: 1.55;">Нажмите кнопку «Поддержка» или напишите нам в Telegram. Наша команда поможет вам настроить подключение на любом устройстве.</p>
                </div>
              </div>
            </details>
          </div>
        </section>
        <script>
        window.addEventListener("pageshow", function(event) {{
          if (window.turnstile) {{
            try {{ window.turnstile.reset(); }} catch(err) {{}}
          }}
        }});

        function handleOrderSubmit(e) {{
          const form = e.target;
          const tokenInput = form.querySelector('[name="cf-turnstile-response"]');
          const turnstileToken = (tokenInput && tokenInput.value) || (window.turnstile ? window.turnstile.getResponse() : "");
          const statusDiv = document.getElementById("orderFormStatus");
          if (!turnstileToken) {{
            e.preventDefault();
            if (window.turnstile) {{
              try {{ window.turnstile.reset(); }} catch(err) {{}}
            }}
            if (statusDiv) {{
              statusDiv.style.display = "block";
              statusDiv.textContent = "Пожалуйста, подтвердите, что вы человек (поставьте галочку Cloudflare).";
            }}
            return false;
          }}
          if (statusDiv) statusDiv.style.display = "none";
          return true;
        }}
        async function submitPromoAjax(e) {{
          e.preventDefault();
          const inp = document.getElementById("promo_code_input");
          const btn = document.getElementById("promo_submit_btn");
          const statusDiv = document.getElementById("promo-status");
          const code = (inp ? inp.value : "").trim();
          if (!code) return;

          btn.disabled = true;
          btn.textContent = "Проверка...";
          statusDiv.style.display = "block";
          statusDiv.style.color = "#8ea89a";
          statusDiv.textContent = "Проверяем промокод...";

          try {{
            const res = await fetch("/api/check-promo", {{
              method: "POST",
              headers: {{ "Content-Type": "application/json" }},
              body: JSON.stringify({{ code: code }})
            }});
            const data = await res.json();
            if (data.ok) {{
              statusDiv.style.color = "#2fbf71";
              statusDiv.innerHTML = data.message;
              
              if (data.type === "gift") {{
                const submitBtn = document.querySelector('.summary-box button[type="submit"]');
                if (submitBtn) submitBtn.textContent = "Активировать подписку 🎁";
                const priceBox = document.getElementById("builder-price");
                if (priceBox) priceBox.textContent = "0 ₽ (Подарок)";
                const offerInput = document.getElementById("builder-offer");
                if (offerInput) offerInput.value = "tcp_3_30";
                let promoHiddenInp = document.getElementById("builder-promo-hidden");
                if (!promoHiddenInp) {{
                  promoHiddenInp = document.createElement("input");
                  promoHiddenInp.type = "hidden";
                  promoHiddenInp.name = "promo_code";
                  promoHiddenInp.id = "builder-promo-hidden";
                  const form = document.querySelector('.summary-box');
                  if (form) form.appendChild(promoHiddenInp);
                }}
                promoHiddenInp.value = data.code;
              }} else if (data.type === "discount") {{
                let promoHiddenInp = document.getElementById("builder-promo-hidden");
                if (!promoHiddenInp) {{
                  promoHiddenInp = document.createElement("input");
                  promoHiddenInp.type = "hidden";
                  promoHiddenInp.name = "promo_code";
                  promoHiddenInp.id = "builder-promo-hidden";
                  const form = document.querySelector('.summary-box');
                  if (form) form.appendChild(promoHiddenInp);
                }}
                promoHiddenInp.value = data.code;
                
                if (window.applyDiscountToPlans) {{
                  window.applyDiscountToPlans(data.discount_percent);
                }}
              }}
              const builderSec = document.querySelector('.builder');
              if (builderSec) builderSec.scrollIntoView({{ behavior: "smooth" }});
            }} else {{
              statusDiv.style.color = "#ef4444";
              statusDiv.textContent = data.message || "Промокод не найден.";
            }}
          }} catch (err) {{
            statusDiv.style.color = "#ef4444";
            statusDiv.textContent = "Ошибка соединения. Попробуйте снова.";
          }} finally {{
            btn.disabled = false;
            btn.textContent = "Применить промокод";
          }}
        }}
        (() => {{
          const plans = {plans_json};
          const state = {{ device: "3", duration: "30", mode: "tcp" }};
          const rub = new Intl.NumberFormat("ru-RU").format;
          const el = (id) => document.getElementById(id);

          window.applyDiscountToPlans = function(discountPct) {{
            for (const key in plans) {{
              const base = plans[key].basePrice || plans[key].price;
              plans[key].basePrice = base;
              plans[key].price = Math.max(Math.floor(base * (100 - discountPct) / 100), 0);
              plans[key].discount = discountPct;
            }}
            update();
          }};

          function setActive(group, value) {{
            document.querySelectorAll('[data-choice][data-group="' + group + '"]').forEach((button) => {{
              button.classList.toggle("active", button.dataset.value === value);
            }});
          }}

          function update() {{
            const code = state.mode + "_" + state.device + "_" + state.duration;
            const plan = plans[code];
            if (!plan) return;
            el("builder-title").textContent = plan.deviceTitle;
            el("builder-subtitle").textContent = "До " + plan.deviceLimit + " устройств · " + plan.duration;
            el("builder-devices").textContent = "до " + plan.deviceLimit;
            el("builder-duration").textContent = plan.duration;
            el("builder-offer").value = plan.code;
            el("builder-price").textContent = rub(plan.price) + " ₽";
            if (plan.discount) {{
              el("builder-price").textContent = rub(plan.price) + " ₽ вместо " + rub(plan.basePrice) + " ₽";
            }}
          }}

          document.querySelectorAll("[data-choice]").forEach((button) => {{
            button.addEventListener("click", () => {{
              state[button.dataset.group] = button.dataset.value;
              setActive(button.dataset.group, button.dataset.value);
              update();
            }});
          }});
          update();
        }})();
        </script>
        """
        return self.render_page("Приватный доступ", body)

    def render_order(self, headers: Any, order: dict[str, Any], *, flash: str = "") -> bytes:
        meta = order.get("meta_json") or {}
        order_url = self.order_url(headers, order)
        flash_html = f'<div class="notice">{html.escape(flash)}</div>' if flash else ""
        status = str(order.get("status") or "")
        customer_email = str(order.get("customer_email") or meta.get("customer_email") or "").strip()
        customer_email_row = f'<div style="display:flex; justify-content:space-between; font-size:14px;"><span style="color:var(--muted);">Email</span><span style="font-weight:600; color:#fff;">{html.escape(customer_email)}</span></div>' if customer_email else ""

        if status == "delivered":
            status_badge = '<span style="background:rgba(16,185,129,0.15); border:1px solid rgba(16,185,129,0.4); color:#10b981; padding:4px 10px; border-radius:8px; font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:0.5px; white-space:nowrap;">Оплачен ✓</span>'
            price_label = "Оплаченная сумма:"
        elif status in ("cancelled", "canceled"):
            status_badge = '<span style="background:rgba(239,68,68,0.15); border:1px solid rgba(239,68,68,0.4); color:#ef4444; padding:4px 10px; border-radius:8px; font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:0.5px; white-space:nowrap;">Отменён ✖</span>'
            price_label = "Сумма заказа:"
        else:
            status_badge = '<span style="background:rgba(245,158,11,0.15); border:1px solid rgba(245,158,11,0.4); color:#f59e0b; padding:4px 10px; border-radius:8px; font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:0.5px; white-space:nowrap;">Ожидает оплаты</span>'
            price_label = "Сумма к оплате:"

        summary = f"""
        <div class="card order-summary-card">
          <div>
            <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:14px; gap:8px; flex-wrap:wrap;">
              <div>
                <div style="font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:0.8px; color:var(--muted); margin-bottom:4px;">Информация о заказе</div>
                <div style="font-size:20px; font-weight:800; color:#fff;">Заказ #{html.escape(str(order['public_id']))}</div>
              </div>
              {status_badge}
            </div>
            <div style="display:flex; flex-direction:column; gap:10px; border-top:1px solid var(--line); border-bottom:1px solid var(--line); padding:14px 0; margin-bottom:16px;">
              <div style="display:flex; justify-content:space-between; font-size:14px;">
                <span style="color:var(--muted);">Тариф / Протокол</span>
                <span style="font-weight:600; color:#fff;">{html.escape(transport_label(str(order['transport'])))}</span>
              </div>
              <div style="display:flex; justify-content:space-between; font-size:14px;">
                <span style="color:var(--muted);">Срок доступа</span>
                <span style="font-weight:600; color:#fff;">{int(order['duration_days'])} дней</span>
              </div>
              <div style="display:flex; justify-content:space-between; font-size:14px;">
                <span style="color:var(--muted);">Лимит устройств</span>
                <span style="font-weight:600; color:#fff;">{html.escape(device_limit_label(meta.get('device_limit')))}</span>
              </div>
              {customer_email_row}
            </div>
            <div style="margin-bottom:18px;">
              <div style="font-size:12px; color:var(--muted); margin-bottom:2px;">{price_label}</div>
              <div style="font-size:36px; font-weight:800; color:var(--green); line-height:1.1;">{html.escape(money(order['final_price_rub']))}</div>
            </div>
          </div>
          <div style="margin-top:auto; padding-top:14px; border-top:1px solid var(--line);">
            <div style="font-size:12.5px; color:var(--muted); margin-bottom:8px;">Ссылка на этот заказ:</div>
            <div style="display:flex; flex-direction:column; gap:8px;">
              <input id="order-link" class="order-link-input" type="text" readonly value="{html.escape(order_url)}" />
              <button type="button" class="btn secondary" onclick="copyText('order-link')" style="min-height:38px; padding:8px 14px; font-size:13.5px; font-weight:600;">
                📋 Скопировать ссылку заказа
              </button>
            </div>
            <div style="font-size:11.5px; color:var(--muted); margin-top:8px;">Сохраните страницу, чтобы в любой момент проверить статус или получить доступ.</div>
          </div>
        </div>
        """
        if status == "waiting_payment":
            platega_url = self.get_or_create_platega_payment_url(
                order,
                return_url=order_url,
                failed_url=order_url,
            )
            support_url = html.escape(self.support_url, quote=True)
            if platega_url:
                platega_cta = f"""
                <a class="btn-platega-primary" href="{html.escape(platega_url, quote=True)}" target="_blank" rel="noopener">
                  <span>Оплатить онлайн {html.escape(money(order['final_price_rub']))}</span>
                  <span style="font-size:19px; font-weight:800;">→</span>
                </a>
                """
            else:
                platega_cta = f"""
                <a class="btn-platega-primary" href="{support_url}" target="_blank" rel="noopener">
                  <span>Оплатить онлайн {html.escape(money(order['final_price_rub']))}</span>
                  <span style="font-size:19px; font-weight:800;">→</span>
                </a>
                """

            platega_card = f"""
            <div class="card order-primary-card">
              <div>
                <div style="display:flex; align-items:center; gap:8px; margin-bottom:8px;">
                  <span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:#10b981; box-shadow:0 0 10px #10b981;"></span>
                  <span style="font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:0.8px; color:#10b981;">Быстрая онлайн-оплата</span>
                </div>
                <div style="font-size:19px; font-weight:700; color:#fff; margin-bottom:6px;">Моментальное зачисление</div>
                <p style="color:var(--muted); font-size:13.5px; margin:0 0 16px; line-height:1.45;">
                  Банковские карты РФ (МИР, Visa, Mastercard), СБП или криптовалюта. Моментальное зачисление сразу после оплаты:
                </p>
                <div style="display:flex; gap:8px; flex-wrap:wrap; margin-bottom:20px;">
                  <span style="background:rgba(255,255,255,0.06); border:1px solid rgba(255,255,255,0.12); color:#e2e8f0; font-size:12px; font-weight:600; padding:4px 10px; border-radius:6px;">⚡ СБП</span>
                  <span style="background:rgba(255,255,255,0.06); border:1px solid rgba(255,255,255,0.12); color:#e2e8f0; font-size:12px; font-weight:600; padding:4px 10px; border-radius:6px;">💳 Карты РФ</span>
                  <span style="background:rgba(255,255,255,0.06); border:1px solid rgba(255,255,255,0.12); color:#e2e8f0; font-size:12px; font-weight:600; padding:4px 10px; border-radius:6px;">🪙 USDT / Crypto</span>
                </div>
              </div>
              <div>
                {platega_cta}
                <div style="text-align:center; color:var(--muted); font-size:12px; margin-top:10px;">
                  🔒 Защищенный шлюз · Доступ выдается автоматически сразу после оплаты
                </div>
              </div>
            </div>
            """

            operator_card = f"""
            <div class="card order-secondary-card">
              <div style="font-size:14.5px; font-weight:700; color:#fff; margin-bottom:6px;">Оплата через оператора / Поддержка</div>
              <p style="color:var(--muted); font-size:13px; line-height:1.5; margin:0 0 14px;">
                Хотите оплатить переводом без комиссии шлюза напрямую менеджеру или у вас есть вопрос? Напишите нам в поддержку, указав номер заказа <code>#{html.escape(str(order['public_id']))}</code>.
              </p>
              <div style="display:flex; gap:10px; flex-wrap:wrap;">
                <a class="btn secondary" href="{support_url}" target="_blank" rel="noopener" style="flex:1; min-width:180px; min-height:42px; font-size:13.5px; display:inline-flex; align-items:center; justify-content:center;">
                  💬 Написать оператору для оплаты (@SilentConnectSupport)
                </a>
                <form method="post" action="/order/{html.escape(str(order['public_id']))}/{html.escape(str(meta.get('web_token') or ''))}/cancel" style="margin:0; flex:1; min-width:130px;">
                  <button type="submit" class="btn secondary" style="width:100%; min-height:42px; font-size:13.5px; background:rgba(239,68,68,0.08); color:#ef4444; border:1px solid rgba(239,68,68,0.25); cursor:pointer;">
                    Отменить заказ ✖
                  </button>
                </form>
              </div>
            </div>
            """

            body = f"""
            <div style="max-width: 960px; margin: 0 auto; padding: 0 16px;">
              <section class="section" style="padding: 24px 0 16px;"><h2>Оплата заказа</h2>{flash_html}</section>
              <section class="order">
                {summary}
                <div class="payment-options">
                  {platega_card}
                  {operator_card}
                </div>
              </section>
            </div>
            {self.order_poll_script(order)}
            """
            return self.render_page("Оплата заказа", body)

        if status == "delivered":
            subscription_url = self.recover_subscription(order)
            if not subscription_url:
                body = f"<div style=\"max-width: 860px; margin: 0 auto;\"><section class=\"section\"><h2>Доступ подтверждён</h2>{flash_html}<div class=\"notice\">Профиль создан, но ссылка не восстановилась. Напишите в поддержку.</div></section></div>"
                return self.render_page("Доступ подтверждён", body)
            setup_url = subscription_setup_url(subscription_url)
            claim_url = self.claim_url(order)
            body = f"""
            <div style="max-width: 860px; margin: 0 auto;">
              <section class="section" style="padding: 24px 0 16px;"><h2>Доступ готов</h2>{flash_html}</section>
              <section class="order">
                {summary}
                <div class="card">
                  <strong>Активировать доступ</strong>
                  <p class="muted">Откройте страницу подключения. Она определит устройство, предложит подходящие приложения и покажет запасной способ через копирование.</p>
                  <div class="actions">
                    <a class="btn" href="{html.escape(setup_url)}">Подключить</a>
                  </div>
                  <textarea id="sub-link" readonly>{html.escape(subscription_url)}</textarea>
                  <p class="muted">Привяжите покупку в Telegram: бот узнает эту подписку, включит продление и напомнит за сутки и за час до окончания.</p>
                  <div class="actions">
                    <button type="button" class="btn secondary" onclick="copyText('sub-link')">📋 Скопировать ссылку</button>
                    <a class="btn secondary" href="{html.escape(claim_url)}">Привязать в Telegram для продления</a>
                  </div>
                </div>
              </section>
            </div>
            """
            return self.render_page("Доступ готов", body)

        if status == "cancelled":
            body = f"""
            <div style="max-width: 860px; margin: 0 auto;">
              <section class="section" style="padding: 24px 0 16px;"><h2>Заказ отменён</h2>{flash_html}</section>
              <section class="order">{summary}<div class="card"><p class="muted">Можно оформить новый заказ или написать в поддержку.</p><div class="actions"><a class="btn" href="/">Выбрать тариф</a><a class="btn secondary" href="{html.escape(self.support_url)}">Поддержка</a></div></div></section>
            </div>
            """
            return self.render_page("Заказ отменён", body)

        body = f"<div style=\"max-width: 860px; margin: 0 auto;\"><section class=\"section\" style=\"padding: 24px 0 16px;\"><h2>Заказ обрабатывается</h2>{flash_html}</section><section class=\"order\">{summary}<div class=\"notice\">Статус: {html.escape(status)}</div></section></div>"
        body += self.order_poll_script(order)
        return self.render_page("Заказ обрабатывается", body, refresh_seconds=12)

    def render_not_found(self) -> bytes:
        body = '<section class="section"><h2>Страница не найдена</h2><p class="muted">Проверьте ссылку или откройте главную страницу.</p><a class="btn" href="/">На главную</a></section>'
        return self.render_page("Не найдено", body)


class RequestHandler(BaseHTTPRequestHandler):
    server_version = "SilentConnectWeb/1.0"
    checkout: WebCheckout
    timeout = 15.0

    def setup(self) -> None:
        if hasattr(self.request, "settimeout"):
            self.request.settimeout(15.0)
        super().setup()

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _get_cookie(self, name: str) -> str:
        raw_cookie = self.headers.get("Cookie", "") if self.headers else ""
        if not raw_cookie:
            return ""
        try:
            c = SimpleCookie()
            c.load(raw_cookie)
            if name in c:
                return c[name].value.strip()
        except Exception:
            pass
        return ""

    def _send(
        self,
        status: HTTPStatus,
        body: bytes,
        content_type: str = "text/html; charset=utf-8",
        extra_headers: list[tuple[str, str]] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        for name, value in SECURITY_HEADERS:
            self.send_header(name, value)
        if extra_headers:
            for name, value in extra_headers:
                self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(self, status: HTTPStatus, body: bytes) -> None:
        self._send(status, body, "application/json; charset=utf-8")

    def _redirect(self, location: str, extra_headers: list[tuple[str, str]] | None = None) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        for name, value in SECURITY_HEADERS:
            self.send_header(name, value)
        if extra_headers:
            for name, value in extra_headers:
                self.send_header(name, value)
        self.end_headers()

    def _read_form(self) -> dict[str, str]:
        length = int(self.headers.get("Content-Length") or 0)
        raw_bytes = self.rfile.read(min(length, 65_536))
        content_type = self.headers.get("Content-Type", "")

        result: dict[str, str] = {}
        if "multipart/form-data" in content_type:
            boundary = ""
            for part in content_type.split(";"):
                part = part.strip()
                if part.startswith("boundary="):
                    boundary = part[len("boundary="):].strip('"\'')
            if boundary:
                b_boundary = f"--{boundary}".encode("ascii")
                parts = raw_bytes.split(b_boundary)
                for part in parts:
                    if not part or part in (b"--\r\n", b"--", b"\r\n", b"--\r\n\r\n"):
                        continue
                    if b"\r\n\r\n" in part:
                        header_part, body_part = part.split(b"\r\n\r\n", 1)
                        header_str = header_part.decode("utf-8", errors="replace")
                        m = re.search(r'name="([^"]+)"', header_str)
                        if m:
                            key = m.group(1)
                            val = body_part.decode("utf-8", errors="replace").strip()
                            result[key] = val
        if not result:
            raw_str = raw_bytes.decode("utf-8", errors="replace")
            parsed = parse_qs(raw_str, keep_blank_values=True)
            result = {key: values[-1] if values else "" for key, values in parsed.items()}
        return result

    def _serve_asset(self, path: list[str]) -> bool:
        if len(path) == 3 and path[0] == "assets" and path[1] == "telegram":
            asset_name = path[2]
            if asset_name in {"welcome.png", "avatar.png", "telegram_icon.png", "telegram_official.png"}:
                asset = self.checkout.settings.root_dir / "assets" / "telegram" / asset_name
                if asset.is_file():
                    content_type = "image/svg+xml" if asset_name.endswith(".svg") else "image/png"
                    body = asset.read_bytes()
                    self._send(HTTPStatus.OK, body, content_type)
                    return True
        return False

    def do_GET(self) -> None:
        try:
            try:
                self.headers.peer_ip = self.client_address[0] if self.client_address else None
            except (AttributeError, TypeError):
                pass
            parsed = urlsplit(self.path)
            path = [segment for segment in parsed.path.split("/") if segment]
            if path == ["api", "payment", "platega", "callback"]:
                self._send_json(HTTPStatus.OK, b'{"status":"active","gateway":"platega"}')
                return
            if not path:
                query = parse_qs(parsed.query)
                promo_code = query.get("promo", [""])[0].strip()
                active_discount = None
                flash = ""
                if promo_code:
                    try:
                        promo = self.checkout.load_valid_promo(promo_code)
                        if self.checkout.promo_type(promo) == "discount":
                            active_discount = promo
                            flash = f"Промокод {promo_code.upper()} применён! Скидка {int(promo['discount_percent'])}%."
                    except Exception:
                        pass

                url_ref = query.get("ref", [""])[0].strip()
                cookie_ref = self._get_cookie(REFERRAL_COOKIE_NAME)
                ref_code = ""
                extra_headers: list[tuple[str, str]] = []

                if url_ref:
                    referrer = self.checkout.store.get_referrer_by_code(url_ref)
                    if referrer:
                        ref_code = url_ref
                        extra_headers.append(
                            ("Set-Cookie", f"{REFERRAL_COOKIE_NAME}={ref_code}; Path=/; Max-Age={REFERRAL_COOKIE_MAX_AGE}; SameSite=Lax; HttpOnly")
                        )
                elif cookie_ref:
                    referrer = self.checkout.store.get_referrer_by_code(cookie_ref)
                    if referrer:
                        ref_code = cookie_ref

                self._send(
                    HTTPStatus.OK,
                    self.checkout.render_home(
                        active_discount=active_discount,
                        promo_code=promo_code,
                        flash=flash,
                        ref_code=ref_code,
                    ),
                    extra_headers=extra_headers if extra_headers else None,
                )
                return
            if path == ["legal", "privacy"]:
                self._send(HTTPStatus.OK, self.checkout.render_legal_privacy())
                return
            if path == ["legal", "terms"]:
                self._send(HTTPStatus.OK, self.checkout.render_legal_terms())
                return
            if path == ["legal", "refund"]:
                self._send(HTTPStatus.OK, self.checkout.render_legal_refund())
                return
            if path == ["about"]:
                self._send(HTTPStatus.OK, self.checkout.render_about())
                return
            if path == ["contact"]:
                self._send(HTTPStatus.OK, self.checkout.render_contact())
                return
            if self._serve_asset(path):
                return
            if len(path) == 4 and path[0] == "order" and path[3] == "status":
                order = self.checkout.load_web_order(path[1], path[2])
                if not order:
                    self._send_json(HTTPStatus.NOT_FOUND, b'{"ok":false}')
                    return
                self._send_json(HTTPStatus.OK, self.checkout.order_status_json(order))
                return
            if len(path) == 3 and path[0] == "order":
                order = self.checkout.load_web_order(path[1], path[2])
                if not order:
                    self._send(HTTPStatus.NOT_FOUND, self.checkout.render_not_found())
                    return
                self._send(HTTPStatus.OK, self.checkout.render_order(self.headers, order))
                return
            if len(path) == 2 and path[0] == "cabinet":
                token = path[1]
                payload = verify_token(token, purpose="magic_link")
                email = self.checkout.store.consume_magic_link(token, single_use=False) if payload else None
                if not payload or not email or email != str(payload.get("email") or ""):
                    self._send(HTTPStatus.NOT_FOUND, self.checkout.render_page(
                        "Ссылка недействительна",
                        '<section class="section"><h2>Ссылка недействительна или устарела</h2>'
                        '<p class="muted">Ссылка для входа в личный кабинет действует 30 минут с момента отправки или была отменена более новым запросом (активна только последняя отправленная ссылка). Пожалуйста, используйте последнее полученное письмо или запросите новую ссылку на главной странице.</p>'
                        '<p style="margin-top: 16px;"><a class="btn primary" href="/" style="display: inline-flex; width: auto; padding: 10px 20px;">На главную</a></p></section>',
                    ))
                    return
                self._send(HTTPStatus.OK, self.checkout.render_cabinet(email, self.checkout.cabinet_profiles_for_email(email)))
                return
            self._send(HTTPStatus.NOT_FOUND, self.checkout.render_not_found())
        except Exception:
            LOGGER.exception("GET failed")
            body = self.checkout.render_page("Ошибка", '<section class="section"><h2>Ошибка</h2><p class="muted">Попробуйте обновить страницу или напишите в поддержку.</p></section>')
            self._send(HTTPStatus.INTERNAL_SERVER_ERROR, body)

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_POST(self) -> None:
        try:
            try:
                self.headers.peer_ip = self.client_address[0] if self.client_address else None
            except (AttributeError, TypeError):
                pass
            parsed = urlsplit(self.path)
            path = [segment for segment in parsed.path.split("/") if segment]
            if path == ["api", "payment", "platega", "callback"]:
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length) if length > 0 else b""
                if not raw.strip() or raw.strip() == b"{}":
                    LOGGER.info("Received Platega empty verification ping. Responding 200 OK.")
                    self._send_json(HTTPStatus.OK, b'{"status":"ok","message":"verification_ping_received"}')
                    return
                if not self.checkout.platega.verify_webhook_signature(self.headers, raw):
                    LOGGER.warning("Platega callback unauthorized request from %s", self.client_address)
                    self._send_json(HTTPStatus.UNAUTHORIZED, b'{"error":"unauthorized"}')
                    return
                try:
                    data = json.loads(raw.decode("utf-8"))
                except Exception:
                    LOGGER.warning("Platega callback invalid JSON: %r", raw[:200])
                    self._send_json(HTTPStatus.BAD_REQUEST, b'{"error":"invalid_json"}')
                    return
                if data.get("test") is True or data.get("type") == "test":
                    LOGGER.info("Received Platega ping/test probe. Responding 200 OK.")
                    self._send_json(HTTPStatus.OK, b'{"status":"ok","message":"test_probe_accepted"}')
                    return
                res = self.checkout.handle_platega_callback(data, raw_body=raw)
                status_code = HTTPStatus.OK if res.get("status") == "ok" else HTTPStatus.BAD_REQUEST
                self._send_json(status_code, json.dumps(res).encode("utf-8"))
                return
            if path == ["order"]:
                form = self._read_form()
                customer_email = form.get("customer_email", "").strip()
                turnstile_token = form.get("cf-turnstile-response", "")
                client_ip = client_ip_from_headers(self.headers, self.client_address[0] if self.client_address else None)
                ref_code = form.get("ref_code", "").strip() or self._get_cookie(REFERRAL_COOKIE_NAME)
                if self.checkout.settings.cf_turnstile_secret_key:
                    if not verify_cf_turnstile(self.checkout.settings.cf_turnstile_secret_key, turnstile_token, client_ip):
                        self._send(
                            HTTPStatus.OK,
                            self.checkout.render_home(
                                flash="Пожалуйста, подтвердите, что вы человек (пройдите проверку Cloudflare Turnstile).",
                                ref_code=ref_code,
                            ),
                        )
                        return
                order = self.checkout.create_order(
                    form.get("offer", "tcp_3_30"),
                    form.get("promo_code", ""),
                    customer_email=customer_email,
                    ref_code=ref_code,
                )
                self._redirect(self.checkout.order_url(self.headers, order))
                return
            if path == ["promo"]:
                form = self._read_form()
                promo_code = form.get("promo_code", "").strip()
                customer_email = form.get("customer_email", "").strip()
                promo = self.checkout.load_valid_promo(promo_code)
                if self.checkout.promo_type(promo) == "discount":
                    self._send(
                        HTTPStatus.OK,
                        self.checkout.render_home(
                            active_discount=promo,
                            promo_code=promo_code,
                            flash=f"Промокод принят. Скидка {int(promo['discount_percent'])}% применится к выбранному тарифу.",
                        ),
                    )
                    return
                order = self.checkout.create_promo_order(promo_code, customer_email=customer_email)
                self._redirect(self.checkout.order_url(self.headers, order))
                return
            if len(path) == 4 and path[0] == "order" and path[3] == "paid":
                order = self.checkout.load_web_order(path[1], path[2])
                if not order:
                    self._send(HTTPStatus.NOT_FOUND, self.checkout.render_not_found())
                    return
                flash = self.checkout.mark_paid(self.headers, order)
                order = self.checkout.load_web_order(path[1], path[2]) or order
                self._send(HTTPStatus.OK, self.checkout.render_order(self.headers, order, flash=flash))
                return
            if len(path) == 4 and path[0] == "order" and path[3] == "cancel":
                order = self.checkout.load_web_order(path[1], path[2])
                if not order:
                    self._send(HTTPStatus.NOT_FOUND, self.checkout.render_not_found())
                    return
                flash = self.checkout.cancel_order(order)
                order = self.checkout.load_web_order(path[1], path[2]) or order
                self._send(HTTPStatus.OK, self.checkout.render_order(self.headers, order, flash=flash))
                return
            if path == ["api", "check-promo"]:
                length = int(self.headers.get("Content-Length", 0) or 0)
                if length > MAX_JSON_BODY_BYTES:
                    self._send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, b'{"ok":false,"error":"body_too_large"}')
                    return
                raw = self.rfile.read(length) if length > 0 else b""
                try:
                    payload = json.loads(raw.decode("utf-8")) if raw else {}
                except Exception:
                    payload = {}
                code = str(payload.get("code") or "")
                res = self.checkout.check_promo_code(self.headers, code)
                self._send_json(HTTPStatus.OK, json.dumps(res, ensure_ascii=False).encode("utf-8"))
                return
            if path == ["api", "cabinet", "request-link"]:
                length = int(self.headers.get("Content-Length", 0) or 0)
                if length > MAX_JSON_BODY_BYTES:
                    self._send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, b'{"ok":false,"error":"body_too_large"}')
                    return
                raw = self.rfile.read(length) if length > 0 else b""
                try:
                    payload = json.loads(raw.decode("utf-8")) if raw else {}
                except Exception:
                    payload = {}
                email = str(payload.get("email") or "")
                turnstile_token = str(payload.get("turnstile_token") or "")
                res = self.checkout.request_cabinet_access_link(self.headers, email, turnstile_token)
                self._send_json(HTTPStatus.OK, json.dumps(res, ensure_ascii=False).encode("utf-8"))
                return
            self._send(HTTPStatus.NOT_FOUND, self.checkout.render_not_found())
        except ValueError as exc:
            message = str(exc) or "Не удалось обработать запрос."
            self._send(
                HTTPStatus.BAD_REQUEST,
                self.checkout.render_home(flash=message),
            )
        except Exception:
            LOGGER.exception("POST failed")
            body = self.checkout.render_page("Ошибка", '<section class="section"><h2>Ошибка</h2><p class="muted">Попробуйте ещё раз или напишите в поддержку.</p></section>')
            self._send(HTTPStatus.INTERNAL_SERVER_ERROR, body)


def serve(settings: Settings, store: Store) -> None:
    checkout = WebCheckout(settings, store)
    RequestHandler.checkout = checkout
    server = ThreadingHTTPServer((settings.web_listen_host, settings.web_listen_port), RequestHandler)
    LOGGER.info("Serving web checkout on %s:%s", settings.web_listen_host, settings.web_listen_port)
    server.serve_forever()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = load_settings(Path(__file__).resolve().parents[1])
    store = Store(settings.database_path)
    serve(settings, store)


if __name__ == "__main__":
    main()
