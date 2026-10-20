"""Digiseller / Plati.market API Client and Webhook Handler for SilentConnect.

Provides programmatic integration with Digiseller REST API (https://api.digiseller.com):
- Token-based API authentication with automatic refresh (apilogin)
- Webhook notification signature verification (SHA256 / HMAC / MD5)
- Product creation with compliant white-hat terminology
- Inventory stock management (content text / keys)
- Purchase details retrieval
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
import urllib.error
import urllib.request
from typing import Any

LOGGER = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://api.digiseller.com"


class DigisellerApiError(Exception):
    """Raised when Digiseller API returns an error or non-zero retval."""

    def __init__(self, message: str, retval: int | None = None, response_body: str = ""):
        super().__init__(message)
        self.retval = retval
        self.response_body = response_body


class DigisellerClient:
    """Client for Digiseller REST API."""

    def __init__(
        self,
        seller_id: str | int,
        api_key: str,
        secret_key: str = "",
        base_url: str = DEFAULT_BASE_URL,
    ) -> None:
        self.seller_id = str(seller_id).strip()
        self.api_key = api_key.strip()
        self.secret_key = secret_key.strip()
        self.base_url = base_url.rstrip("/")
        self._token: str | None = None
        self._token_expires_at: float = 0.0

    def get_token(self, force_refresh: bool = False) -> str:
        """Obtain a valid bearer/session token from Digiseller apilogin.

        Tokens are cached for 110 minutes (official lifetime is 120 minutes).
        """
        now = time.time()
        if not force_refresh and self._token and now < self._token_expires_at:
            return self._token

        if not self.seller_id or not self.api_key:
            raise DigisellerApiError("Cannot authenticate: seller_id and api_key must be configured.")

        ts = int(now)
        raw_sig = f"{self.api_key}{ts}".encode("utf-8")
        sign = hashlib.sha256(raw_sig).hexdigest()

        payload = {
            "seller_id": int(self.seller_id),
            "timestamp": ts,
            "sign": sign,
        }

        url = f"{self.base_url}/api/apilogin"
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            raise DigisellerApiError(f"HTTP error during Digiseller apilogin: {exc.code} {err_body}", response_body=err_body) from exc
        except Exception as exc:
            raise DigisellerApiError(f"Network error during Digiseller apilogin: {exc}") from exc

        retval = data.get("retval")
        if retval != 0:
            desc = data.get("desc") or data.get("retdesc") or "Unknown error"
            raise DigisellerApiError(f"Digiseller apilogin failed: {desc} (retval={retval})", retval=retval)

        token = data.get("token")
        if not token:
            raise DigisellerApiError("Digiseller apilogin response missing token")

        self._token = str(token)
        self._token_expires_at = now + (110 * 60)
        return self._token

    def request(
        self,
        endpoint: str,
        method: str = "GET",
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        timeout: int = 20,
    ) -> Any:
        """Execute an authenticated request to Digiseller API."""
        token = self.get_token()
        query_parts = [f"token={token}"]
        if params:
            for k, v in params.items():
                if v is not None:
                    query_parts.append(f"{k}={urllib.request.quote(str(v))}")

        query_str = "&".join(query_parts)
        url = f"{self.base_url}{endpoint}"
        if "?" in endpoint:
            url = f"{url}&{query_str}"
        else:
            url = f"{url}?{query_str}"

        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
        }

        body_bytes = None
        if data is not None:
            headers["Content-Type"] = "application/json"
            body_bytes = json.dumps(data).encode("utf-8")

        req = urllib.request.Request(url, data=body_bytes, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                resp_bytes = resp.read()
                if not resp_bytes:
                    return {}
                return json.loads(resp_bytes.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            raise DigisellerApiError(f"HTTP {exc.code} on {endpoint}: {err_body}", response_body=err_body) from exc
        except Exception as exc:
            raise DigisellerApiError(f"Network error on {endpoint}: {exc}") from exc

    def verify_webhook_signature(
        self,
        payload: dict[str, Any],
        secret_key: str | None = None,
    ) -> bool:
        """Verify the signature of an incoming Digiseller notification.

        Digiseller notifications include a 'sign' or 'signature' parameter.
        The signature is verified against the configured secret key.
        """
        secret = (secret_key or self.secret_key or self.api_key).strip()
        if not secret:
            LOGGER.warning("Digiseller webhook signature verification skipped: no secret configured")
            return False

        incoming_sign = str(
            payload.get("sign")
            or payload.get("signature")
            or payload.get("Sign")
            or payload.get("SHA256")
            or payload.get("sha256")
            or ""
        ).strip().lower()

        if not incoming_sign:
            return False

        # Digiseller notification signature formats:
        # Format 0 (Official Notification Settings):
        # "хэш от строки, состоящей из вашего пароля в нижнем регистре, номера заказа и идентификатора товара через ';'"
        # sha256(lowercase(password);id_i;id_d)

        id_goods = str(payload.get("id_goods") or payload.get("product_id") or payload.get("id_d") or payload.get("ID_D") or "").strip()
        id_invoice = str(payload.get("id_invoice") or payload.get("invoice_id") or payload.get("id_i") or payload.get("ID_I") or "").strip()
        date_pay = str(payload.get("date_pay") or payload.get("date") or payload.get("Date") or "").strip()
        amount = str(payload.get("amount") or payload.get("pay_amount") or payload.get("Amount") or "").strip()

        # Format 0: Official Digiseller SHA256(lowercase(secret);id_invoice;id_goods)
        candidate0 = hashlib.sha256(f"{secret.lower()};{id_invoice};{id_goods}".encode("utf-8")).hexdigest().lower()
        if hmac.compare_digest(candidate0, incoming_sign):
            return True

        # Format 0b: Case-preserved secret;id_invoice;id_goods
        candidate0b = hashlib.sha256(f"{secret};{id_invoice};{id_goods}".encode("utf-8")).hexdigest().lower()
        if hmac.compare_digest(candidate0b, incoming_sign):
            return True

        # Format 1: Canonical Digiseller SHA256(id_goods + id_invoice + date_pay + amount + secret)
        if id_goods or date_pay or amount:
            candidate1 = hashlib.sha256(f"{id_goods}{id_invoice}{date_pay}{amount}{secret}".encode("utf-8")).hexdigest().lower()
            if hmac.compare_digest(candidate1, incoming_sign):
                return True

        # Format 3: HMAC-SHA256 of sorted parameters
        sorted_keys = sorted([k for k in payload.keys() if k.lower() not in {"sign", "signature", "sha256"}])
        data_str = ";".join(f"{k}:{payload[k]}" for k in sorted_keys) + ";"
        candidate3 = hmac.new(secret.encode("utf-8"), data_str.encode("utf-8"), hashlib.sha256).hexdigest().lower()
        if hmac.compare_digest(candidate3, incoming_sign):
            return True

        return False

    def get_purchase_info(self, invoice_id: int | str, timeout: int = 5) -> dict[str, Any]:
        """Fetch purchase details by invoice ID."""
        return self.request(f"/api/purchase/info/{invoice_id}", timeout=timeout)

    @staticmethod
    def parse_purchase_info(resp: dict[str, Any]) -> dict[str, Any]:
        """Extract verified purchase parameters from Digiseller purchase/info API response.
        
        Digiseller wraps actual sale data in a nested 'content' object:
        {
            "retval": 0,
            "retdesc": null,
            "content": {
                "invoice_id": 12345,
                "item_id": 5031262,
                "amount": 149.0,
                "currency": "RUB",
                "profit": 145.27,
                "date_pay": "2026-10-17T12:00:00",
                "buyer_info": {"email": "buyer@example.com"},
                "lock_state": "free"
            }
        }
        """
        if not isinstance(resp, dict):
            return {"valid": False, "reason": "invalid_response_format"}
        if resp.get("retval") != 0:
            return {"valid": False, "reason": resp.get("retdesc") or resp.get("desc") or "api_error"}

        content = resp.get("content")
        data = content if isinstance(content, dict) else resp

        invoice_state = data.get("invoice_state")
        if invoice_state is not None:
            try:
                state_int = int(invoice_state)
                if state_int != 3:
                    state_names = {
                        1: "payment_expected",
                        2: "payment_cancelled",
                        4: "payment_overdue",
                        5: "refunded",
                        35: "refund_pending",
                    }
                    reason = state_names.get(state_int, f"unsuccessful_state_{state_int}")
                    return {"valid": False, "reason": reason}
            except (ValueError, TypeError):
                pass

        date_pay = str(data.get("date_pay") or data.get("purchase_date") or "").strip()
        if not date_pay and invoice_state != 3:
            return {"valid": False, "reason": "not_paid_missing_date_pay"}

        lock_state = str(data.get("lock_state") or "").strip().lower()
        if lock_state in ("blocked", "locked", "disputed"):
            return {"valid": False, "reason": f"payment_locked_{lock_state}"}

        item_id = str(data.get("item_id") or data.get("product_id") or data.get("id_goods") or "").strip()
        buyer_info = data.get("buyer_info") or {}
        email = ""
        if isinstance(buyer_info, dict):
            email = str(buyer_info.get("email") or "").strip()
        if not email:
            email = str(data.get("email") or data.get("email_buyer") or "").strip()

        amount = float(data.get("amount") or 0.0)
        currency = str(data.get("currency") or data.get("currency_type") or "RUB").strip().upper()
        profit = float(data.get("profit") or 0.0)

        return {
            "valid": True,
            "invoice_id": str(data.get("invoice_id") or "").strip(),
            "item_id": item_id,
            "email": email,
            "amount": amount,
            "currency": currency,
            "profit": profit,
            "date_pay": date_pay,
            "invoice_state": invoice_state,
            "raw": data,
        }

    def get_stock_count(self, product_id: int) -> int:
        """Return the count of available codes/lines in a product's inventory."""
        res = self.request("/api/product/content/code/count", params={"product_id": product_id})
        if isinstance(res, dict):
            return int(res.get("cnt") or res.get("count") or 0)
        return int(res) if str(res).isdigit() else 0

    def add_content_text(self, product_id: int, lines: list[str]) -> dict[str, Any]:
        """Add lines of text/links to a unique-content product inventory."""
        if not lines:
            return {}
        content_items = [{"text": line.strip()} for line in lines if line.strip()]
        data = {
            "product_id": product_id,
            "content": content_items,
        }
        return self.request("/api/product/content/add/text", method="POST", data=data)

    def get_seller_goods(self, currency: str = "RUR") -> list[dict[str, Any]]:
        """Return list of products belonging to the seller."""
        payload = {"id_seller": int(self.seller_id), "currency": currency}
        res = self.request("/api/seller-goods", method="POST", data=payload)
        if isinstance(res, dict):
            return res.get("rows") or []
        return []

    def get_unique_code_info(self, unique_code: str) -> dict[str, Any]:
        """Fetch purchase details by unique code."""
        code = str(unique_code).strip()
        return self.request(f"/api/purchases/unique-code/{code}", method="GET")

    def deliver_unique_code(self, unique_code: str, content: str) -> dict[str, Any]:
        """Mark a unique code as delivered and attach delivery content/text."""
        code = str(unique_code).strip()
        return self.request(
            f"/api/purchases/unique-code/{code}/deliver",
            method="PUT",
            data={"content": content},
        )

    def create_tunnel_product(
        self,
        name_ru: str,
        name_en: str,
        description_ru: str,
        description_en: str,
        price_rub: float,
        category_id: int = 33111,
        guarantee_days: int = 30,
        bonus_percent: int = 0,
    ) -> dict[str, Any]:
        """Create a fixed-price unique-content product compliant with Digiseller rules."""
        data = {
            "category_id": category_id,
            "price": price_rub,
            "currency": "RUB",
            "name": [
                {"locale": "ru-RU", "value": name_ru},
                {"locale": "en-US", "value": name_en},
            ],
            "description": [
                {"locale": "ru-RU", "value": description_ru},
                {"locale": "en-US", "value": description_en},
            ],
            "guarantee": guarantee_days,
            "bonus_percent": bonus_percent,
        }
        return self.request("/api/product/create/uniquefixed", method="POST", data=data)

    create_vpn_product = create_tunnel_product


def build_default_listing_content() -> dict[str, str]:
    """Generate professional, fully compliant white-hat descriptions for Plati/Digiseller.

    Strictly adheres to policy rules:
    - Neutral terminology: 'персональный защищённый туннель', 'сетевой шлюз', 'шифрование'.
    - Zero mention of blocked resources, circumvention, or regulatory bypass.
    - Highlights speed (1 Gbps), protocols (VLESS Reality, AmneziaWG, Hysteria 2 Gecko), and 3-device limits.
    """
    name_ru = "Приватный защищённый туннель (VLESS Reality / AmneziaWG / Hysteria 2) | 1 Gbps (3 устройства, 30 дней)"
    name_en = "Private Secure Tunnel (VLESS Reality / AmneziaWG / Hysteria 2) | 1 Gbps (3 Devices, 30 Days)"

    description_ru = """<h3>🔒 SilentConnect: Персональный зашифрованный сетевой туннель</h3>
<p>Премиальный доступ к современным протоколам шифрования нового поколения для надёжной защиты ваших данных, безопасного интернет-серфинга и стабильного стриминга на максимальной скорости.</p>

<hr/>
<h4>🚀 Ключевые преимущества и технические характеристики:</h4>
<ul>
  <li><b>3 независимых слота устройств</b>: подключайте смартфон, ноутбук и домашний роутер одновременно без взаимных помех.</li>
  <li><b>1 Gbps порты без задержек</b>: высокоскоростные выделенные серверы в Нидерландах и Польше.</li>
  <li><b>Стек протоколов нового поколения</b>:
    <ul>
      <li><b>AmneziaWG</b> — современный обфусцированный WireGuard с защитой от сигнатурного анализа заголовков.</li>
      <li><b>VLESS Reality</b> — маскировка под доверенные веб-сервисы с нулевой задержкой.</li>
      <li><b>Hysteria 2 (Gecko)</b> — скоростной UDP-протокол на базе QUIC для стабильной работы на мобильном интернете.</li>
    </ul>
  </li>
  <li><b>Поддержка всех операционных систем</b>: iOS, Android, Windows, macOS, Linux, Keenetic и OpenWrt.</li>
</ul>

<hr/>
<h4>⚡ Быстрое подключение в 1 клик:</h4>
<ol>
  <li>Сразу после оплаты вы мгновенно получаете персональную ссылку на Личный кабинет.</li>
  <li>В Личном кабинете выберите ваше приложение (sing-box MT, Happ, Streisand, AmneziaWG).</li>
  <li>Нажмите кнопку импорта профиля или отсканируйте готовый QR-код.</li>
</ol>

<hr/>
<h4>🛡️ Гарантия и техническая поддержка:</h4>
<p>Гарантия бесперебойной работы на весь оплаченный период (30 дней). При любых технических вопросах наша служба поддержки готова помочь через Telegram @SilentConnectVPNBot.</p>
"""

    description_en = """<h3>🔒 SilentConnect: Personal High-Speed Encrypted Network Tunnel</h3>
<p>Premium access to next-generation encryption protocols ensuring total data privacy, secure Wi-Fi browsing, and seamless streaming at maximum line speeds.</p>

<hr/>
<h4>🚀 Key Features & Specifications:</h4>
<ul>
  <li><b>3 Independent Device Slots</b>: connect phone, laptop, and router simultaneously.</li>
  <li><b>1 Gbps Uplinks</b>: dedicated European nodes in the Netherlands and Poland.</li>
  <li><b>Next-Gen Protocol Stack</b>: AmneziaWG (obfuscated WireGuard), VLESS Reality, and Hysteria 2 (QUIC/Gecko).</li>
  <li><b>Multi-Platform Support</b>: iOS, Android, Windows, macOS, Linux, and OpenWrt routers.</li>
</ul>

<hr/>
<h4>⚡ Instant 1-Click Setup:</h4>
<ol>
  <li>Receive your personal dashboard link immediately upon purchase.</li>
  <li>Choose your client app (sing-box MT, Happ, Streisand, AmneziaWG).</li>
  <li>Click 1-button import or scan the generated QR code.</li>
</ol>
"""

    return {
        "name_ru": name_ru,
        "name_en": name_en,
        "description_ru": description_ru,
        "description_en": description_en,
    }
