from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import string
import time
from typing import Any, Iterable


ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
ALPHABET_LOWER = string.ascii_lowercase + string.digits

DEFAULT_SERVER_PEPPER = "silentconnect-pepper-secret-v1"
SERVER_PEPPER = os.environ.get("SERVER_PEPPER", DEFAULT_SERVER_PEPPER).encode("utf-8")


def _get_effective_pepper() -> bytes:
    raw = os.environ.get("SERVER_PEPPER", "").encode("utf-8")
    return raw if raw else SERVER_PEPPER


def validate_production_secrets() -> None:
    is_prod = (
        os.environ.get("ENV", "").strip().lower() == "production"
        or os.environ.get("PRODUCTION", "").strip() in ("1", "true", "yes")
    )
    if is_prod:
        raw_pepper = os.environ.get("SERVER_PEPPER", "").strip()
        if not raw_pepper or raw_pepper == DEFAULT_SERVER_PEPPER:
            raise RuntimeError(
                "Production environment detected (ENV=production / PRODUCTION=1), "
                "but default or empty SERVER_PEPPER is configured. "
                "A secure, unique SERVER_PEPPER must be configured in production."
            )


validate_production_secrets()


def now_ts() -> int:
    return int(time.time())


def days_from_now(days: int) -> int:
    return now_ts() + days * 24 * 60 * 60


def to_xui_ms(timestamp_s: int) -> int:
    return timestamp_s * 1000


def hash_secret(value: str) -> str:
    effective_pepper = _get_effective_pepper()
    return hmac.new(effective_pepper, value.encode("utf-8"), hashlib.sha256).hexdigest()


def hash_token(token: str, *, purpose: str) -> str:
    """Storage-side hash for bearer tokens. Domain-separated by ``purpose``."""
    msg = f"{purpose}\x00{token}".encode("utf-8")
    effective_pepper = _get_effective_pepper()
    return hmac.new(effective_pepper, msg, hashlib.sha256).hexdigest()


def constant_time_equals(a: str | bytes | None, b: str | bytes | None) -> bool:
    if a is None or b is None:
        return False
    if isinstance(a, str):
        a = a.encode("utf-8")
    if isinstance(b, str):
        b = b.encode("utf-8")
    return hmac.compare_digest(a, b)


# ---------------------------------------------------------------------------
# Signed expiring tokens (magic links, order access links)
# ---------------------------------------------------------------------------

def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def sign_token(payload: dict[str, Any], *, purpose: str, ttl_seconds: int) -> str:
    """Create an opaque, tamper-proof token with an embedded expiry.

    Format: ``<b64(json)>.<b64(hmac)>``. The purpose is mixed into the MAC so a
    token minted for one feature can never be replayed against another.
    """
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")
    body = dict(payload)
    body["exp"] = now_ts() + int(ttl_seconds)
    body["n"] = secrets.token_hex(8)
    raw = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    effective_pepper = _get_effective_pepper()
    mac = hmac.new(effective_pepper, f"{purpose}\x00".encode("utf-8") + raw, hashlib.sha256).digest()
    return f"{_b64e(raw)}.{_b64e(mac)}"


def verify_token(token: str, *, purpose: str) -> dict[str, Any] | None:
    """Return the payload if the token is authentic and not expired, else None."""
    try:
        raw_b64, mac_b64 = token.split(".", 1)
        raw = _b64d(raw_b64)
        mac = _b64d(mac_b64)
    except Exception:
        return None
    effective_pepper = _get_effective_pepper()
    expected = hmac.new(effective_pepper, f"{purpose}\x00".encode("utf-8") + raw, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        return None
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    if int(payload.get("exp") or 0) < now_ts():
        return None
    return payload


# ---------------------------------------------------------------------------
# Random identifiers
# ---------------------------------------------------------------------------

def random_code(prefix: str, groups: tuple[int, ...] = (4, 4, 4)) -> str:
    chunks = []
    for size in groups:
        chunks.append("".join(secrets.choice(ALPHABET) for _ in range(size)))
    return f"{prefix}-" + "-".join(chunks)


def masked_code(code: str) -> str:
    if not code:
        return ""
    if "-" in code:
        prefix = code.split("-", 1)[0]
        return f"{prefix}-..."
    if len(code) <= 4:
        return f"{code[:1]}..."
    return f"{code[:3]}..."


def public_id(prefix: str, size: int = 10) -> str:
    token = "".join(secrets.choice(ALPHABET_LOWER) for _ in range(size))
    return f"{prefix}_{token}"


def random_alias(prefix: str = "anon", size: int = 10) -> str:
    token = "".join(secrets.choice(ALPHABET_LOWER) for _ in range(size))
    return f"{prefix}-{token}"


def random_subscription_id(size: int = 16) -> str:
    return "".join(secrets.choice(ALPHABET_LOWER) for _ in range(size))


def random_web_token() -> str:
    """192-bit URL-safe bearer token for order pages."""
    return secrets.token_urlsafe(24)


def normalize_username(username: str | None) -> str:
    return (username or "").strip().lstrip("@").lower()


# ---------------------------------------------------------------------------
# HTTP hardening helpers
# ---------------------------------------------------------------------------

def _parse_networks(raw: str) -> list[ipaddress._BaseNetwork]:
    networks: list[ipaddress._BaseNetwork] = []
    for chunk in (raw or "").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            networks.append(ipaddress.ip_network(chunk, strict=False))
        except ValueError:
            continue
    return networks


DEFAULT_TRUSTED_PROXIES = "127.0.0.0/8,::1/128"
TRUSTED_PROXY_NETWORKS = _parse_networks(os.environ.get("TRUSTED_PROXY_CIDRS", DEFAULT_TRUSTED_PROXIES))


def _is_trusted_proxy(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # Re-read network list if TRUSTED_PROXY_CIDRS dynamically changed in tests
    custom_cidrs = os.environ.get("TRUSTED_PROXY_CIDRS")
    nets = _parse_networks(custom_cidrs) if custom_cidrs else TRUSTED_PROXY_NETWORKS
    return any(addr in net for net in nets)


def client_ip_from_headers(headers: Any, peer_ip: str | None) -> str:
    """Resolve the real client IP without trusting spoofable headers.

    Rules:
      * If the TCP peer is *not* a trusted proxy, headers are ignored entirely.
      * ``CF-Connecting-IP`` is honoured only when the peer is trusted.
      * Otherwise walk ``X-Forwarded-For`` from the right, skipping trusted hops;
        the first untrusted address is the client (RFC 7239 semantics).
    """
    peer = (peer_ip or "").strip() or "unknown"
    if not _is_trusted_proxy(peer):
        return peer
    cf_ip = str(headers.get("CF-Connecting-IP") or "").strip()
    if cf_ip:
        try:
            return str(ipaddress.ip_address(cf_ip))
        except ValueError:
            pass
    xff = str(headers.get("X-Forwarded-For") or "")
    hops = [h.strip() for h in xff.split(",") if h.strip()]
    for hop in reversed(hops):
        try:
            candidate = str(ipaddress.ip_address(hop))
        except ValueError:
            continue
        if not _is_trusted_proxy(candidate):
            return candidate
    return peer


def is_allowed_host(host: str | None, allowed_hosts: Iterable[str]) -> bool:
    """Validate a Host / X-Forwarded-Host value against an allow-list."""
    if not host:
        return False
    hostname = host.strip().lower().split(":", 1)[0]
    if not hostname or "/" in hostname or "\\" in hostname or "@" in hostname:
        return False
    for allowed in allowed_hosts:
        allowed = (allowed or "").strip().lower()
        if not allowed:
            continue
        if allowed.startswith("*."):
            if hostname.endswith(allowed[1:]) or hostname == allowed[2:]:
                return True
        elif hostname == allowed:
            return True
    return False

