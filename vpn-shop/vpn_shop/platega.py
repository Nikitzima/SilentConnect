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
        secret_bot: str = "",
        secret_web: str = "",
        base_url: str = "https://app.platega.io",
        timeout_seconds: int = 15,
    ) -> None:
        self.merchant_id_bot = (merchant_id_bot or "").strip()
        self.merchant_id_web = (merchant_id_web or "").strip()
        self.secret = (secret or "").strip()
        self.secret_bot = (secret_bot or "").strip() or self.secret
        self.secret_web = (secret_web or "").strip() or self.secret
        self.base_url = (base_url or "https://app.platega.io").rstrip("/")
        self.timeout_seconds = max(3, int(timeout_seconds))

    @property
    def is_configured(self) -> bool:
        """Returns True if at least one secret key and at least one merchant ID are present."""
        has_secret = bool(self.secret or self.secret_bot or self.secret_web)
        has_merchant = bool(self.merchant_id_bot or self.merchant_id_web)
        return has_secret and has_merchant

    def _get_merchant_candidates(self, is_bot: bool) -> list[tuple[str, str]]:
        candidates: list[tuple[str, str]] = []
        if is_bot:
            if self.merchant_id_bot and self.secret_bot:
                candidates.append((self.merchant_id_bot, self.secret_bot))
            if self.merchant_id_web and self.secret_web:
                candidates.append((self.merchant_id_web, self.secret_web))
        else:
            if self.merchant_id_web and self.secret_web:
                candidates.append((self.merchant_id_web, self.secret_web))
            if self.merchant_id_bot and self.secret_bot:
                candidates.append((self.merchant_id_bot, self.secret_bot))
        return candidates

    def _request(
        self,
        method: str,
        path: str,
        merchant_id: str,
        secret: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        active_secret = (secret or "").strip() or self.secret
        if not active_secret:
            raise PlategaAuthError("Platega secret key (X-Secret) is not configured")

        url = f"{self.base_url}/{path.lstrip('/')}"
        headers = {
            "X-MerchantId": merchant_id,
            "X-Secret": active_secret,
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

        candidates = self._get_merchant_candidates(is_bot)
        if not candidates:
            raise PlategaError(f"Platega merchant ID or secret is not configured (is_bot={is_bot})")

        last_error: Exception | None = None
        for merchant_id, secret in candidates:
            try:
                LOGGER.info(
                    "Creating Platega transaction: merchant=%s is_bot=%s amount=%s %s payload=%s",
                    merchant_id,
                    is_bot,
                    amount,
                    currency,
                    payload,
                )
                resp = self._request("POST", "/v2/transaction/process", merchant_id, secret=secret, payload=request_body)
                LOGGER.info("Platega transaction response: id=%s url=%s", resp.get("transactionId"), resp.get("url"))
                return resp
            except PlategaAuthError as exc:
                LOGGER.warning("Platega auth failed for merchant %s, trying fallback candidate if available: %s", merchant_id, exc)
                last_error = exc
            except Exception as exc:
                LOGGER.error("Platega transaction creation failed for merchant %s: %s", merchant_id, exc)
                last_error = exc
                break

        if last_error:
            raise last_error
        raise PlategaError("Failed to create Platega transaction")

    def get_transaction_status(self, transaction_id: str, is_bot: bool = True) -> dict[str, Any]:
        """
        Checks transaction status via GET /transaction/{id}.
        """
        if not transaction_id:
            raise ValueError("transaction_id is required")
        candidates = self._get_merchant_candidates(is_bot)
        if not candidates:
            raise PlategaError(f"Platega merchant ID or secret is not configured (is_bot={is_bot})")
        last_error: Exception | None = None
        for merchant_id, secret in candidates:
            try:
                return self._request("GET", f"/transaction/{urllib.parse.quote(str(transaction_id))}", merchant_id, secret=secret)
            except PlategaAuthError as exc:
                last_error = exc
            except Exception as exc:
                last_error = exc
                break
        if last_error:
            raise last_error
        raise PlategaError("Failed to check Platega transaction status")

    def verify_webhook_signature(self, headers: Any, body: bytes | str | None = None) -> bool:
        """
        Verifies incoming webhook authentication headers against configured Platega credentials.
        Matches X-MerchantId to either bot or web merchant, and X-Secret using constant-time digest comparison.
        """
        all_secrets = {s for s in (self.secret, self.secret_bot, self.secret_web) if s}
        if not all_secrets:
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

        expected_secret = ""
        if merchant_id_clean == self.merchant_id_bot:
            expected_secret = self.secret_bot or self.secret
        elif merchant_id_clean == self.merchant_id_web:
            expected_secret = self.secret_web or self.secret

        if expected_secret and secrets.compare_digest(secret_clean, expected_secret):
            return True

        for s in all_secrets:
            if secrets.compare_digest(secret_clean, s):
                return True

        LOGGER.warning("X-Secret mismatch in Platega webhook")
        return False
