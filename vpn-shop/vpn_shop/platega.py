from __future__ import annotations

import json
import logging
import secrets
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Mapping

LOGGER = logging.getLogger("vpn-shop.platega")


class PlategaError(RuntimeError):
    """Base exception for Platega payment gateway operations."""
    pass


class PlategaApiError(PlategaError):
    """Raised when Platega API responds with an error status code."""
    def __init__(self, message: str, status_code: int | None = None, response_body: str = "") -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


class PlategaAuthError(PlategaApiError):
    """Raised when authentication with Platega fails (401 Unauthorized)."""
    pass


class PlategaClient:
    """Client for interacting with Platega.io Payment Gateway API."""

    def __init__(
        self,
        merchant_id_bot: str = "",
        merchant_id_web: str = "",
        secret: str = "",
        base_url: str = "https://app.platega.io",
        timeout_seconds: int = 15,
    ) -> None:
        self.merchant_id_bot = (merchant_id_bot or "").strip()
        self.merchant_id_web = (merchant_id_web or "").strip()
        self.secret = (secret or "").strip()
        self.base_url = (base_url or "https://app.platega.io").rstrip("/")
        self.timeout_seconds = max(3, int(timeout_seconds))

    @property
    def is_configured(self) -> bool:
        """Returns True if the secret key and at least one merchant ID are present."""
        return bool(self.secret and (self.merchant_id_bot or self.merchant_id_web))

    def _get_merchant_id(self, is_bot: bool) -> str:
        merchant_id = self.merchant_id_bot if is_bot else self.merchant_id_web
        if not merchant_id:
            # Fallback to the other merchant ID if only one is configured
            merchant_id = self.merchant_id_web if is_bot else self.merchant_id_bot
        if not merchant_id:
            raise PlategaError(f"Platega merchant ID is not configured (is_bot={is_bot})")
        return merchant_id

    def _request(
        self,
        method: str,
        path: str,
        merchant_id: str,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not self.secret:
            raise PlategaAuthError("Platega secret key (X-Secret) is not configured")

        url = f"{self.base_url}/{path.lstrip('/')}"
        headers = {
            "X-MerchantId": merchant_id,
            "X-Secret": self.secret,
            "Accept": "application/json",
            "User-Agent": "SilentConnect-Shop/2.0",
        }

        data: bytes | None = None
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json; charset=utf-8"

        req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                raw_bytes = resp.read()
                content_type = resp.headers.get("Content-Type", "")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            LOGGER.warning(
                "Platega API error %d for %s %s: %s",
                exc.code,
                method,
                path,
                body[:300],
            )
            if exc.code == 401:
                raise PlategaAuthError(f"Platega authentication failed (401): {body}", status_code=401, response_body=body) from exc
            raise PlategaApiError(f"Platega HTTP {exc.code} for {path}: {body}", status_code=exc.code, response_body=body) from exc
        except urllib.error.URLError as exc:
            LOGGER.error("Platega connection error for %s %s: %s", method, path, exc)
            raise PlategaError(f"Platega connection failed for {path}: {exc}") from exc

        if not raw_bytes:
            return {}

        try:
            return json.loads(raw_bytes.decode("utf-8"))
        except Exception as exc:
            LOGGER.error("Platega response JSON decode failed: %r", raw_bytes[:200])
            raise PlategaError(f"Invalid JSON received from Platega API: {exc}") from exc

    def create_transaction(
        self,
        amount: int | float,
        currency: str = "RUB",
        description: str = "",
        payload: str = "",
        return_url: str = "",
        failed_url: str = "",
        metadata: dict[str, Any] | None = None,
        is_bot: bool = True,
    ) -> dict[str, Any]:
        """
        Creates a payment transaction via POST /v2/transaction/process.
        Returns a dict containing transactionId, url, status, etc.
        """
        merchant_id = self._get_merchant_id(is_bot)
        request_body: dict[str, Any] = {
            "paymentDetails": {
                "amount": int(amount),
                "currency": currency.upper(),
            },
            "description": description or "Оплата сервиса",
            "return": return_url or "",
            "failedUrl": failed_url or "",
            "payload": payload or "",
            "metadata": metadata or {},
        }

        # Filter out empty string redirect URLs if not set to avoid API validation errors
        if not request_body["return"]:
            request_body.pop("return", None)
        if not request_body["failedUrl"]:
            request_body.pop("failedUrl", None)

        LOGGER.info(
            "Creating Platega transaction: merchant=%s is_bot=%s amount=%s %s payload=%s",
            merchant_id,
            is_bot,
            amount,
            currency,
            payload,
        )
        resp = self._request("POST", "/v2/transaction/process", merchant_id, payload=request_body)
        LOGGER.info("Platega transaction response: id=%s url=%s", resp.get("transactionId"), resp.get("url"))
        return resp

    def get_transaction_status(self, transaction_id: str, is_bot: bool = True) -> dict[str, Any]:
        """
        Checks transaction status via GET /transaction/{id}.
        """
        if not transaction_id:
            raise ValueError("transaction_id is required")
        merchant_id = self._get_merchant_id(is_bot)
        return self._request("GET", f"/transaction/{urllib.parse.quote(str(transaction_id))}", merchant_id)

    def verify_webhook_signature(self, headers: Any, body: bytes | str | None = None) -> bool:
        """
        Verifies incoming webhook authentication headers against configured Platega credentials.
        Matches X-MerchantId to either bot or web merchant, and X-Secret using constant-time digest comparison.
        """
        if not self.secret:
            return False

        merchant_id: str | None = None
        secret: str | None = None

        if hasattr(headers, "get"):
            merchant_id = (
                headers.get("X-MerchantId")
                or headers.get("x-merchantid")
                or headers.get("X-Merchant-Id")
                or headers.get("x-merchant-id")
            )
            secret = headers.get("X-Secret") or headers.get("x-secret")
        elif isinstance(headers, Mapping):
            for key, val in headers.items():
                clean_key = str(key).lower().replace("-", "").replace("_", "")
                if clean_key == "xmerchantid":
                    merchant_id = str(val)
                elif clean_key == "xsecret":
                    secret = str(val)

        if not merchant_id or not secret:
            LOGGER.warning("Missing X-MerchantId or X-Secret in webhook headers: %r", headers)
            return False

        merchant_id_clean = merchant_id.strip()
        secret_clean = secret.strip()

        allowed_merchants = {self.merchant_id_bot, self.merchant_id_web} - {""}
        if merchant_id_clean not in allowed_merchants:
            LOGGER.warning(
                "X-MerchantId mismatch in webhook: got %s, allowed %s",
                merchant_id_clean,
                allowed_merchants,
            )
            return False

        if not secrets.compare_digest(secret_clean, self.secret):
            LOGGER.warning("X-Secret mismatch in Platega webhook")
            return False

        return True
