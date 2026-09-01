from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import string
import time


ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
ALPHABET_LOWER = string.ascii_lowercase + string.digits

SERVER_PEPPER = os.environ.get("SERVER_PEPPER", "silentconnect-pepper-secret-v1").encode("utf-8")


def now_ts() -> int:
    return int(time.time())


def days_from_now(days: int) -> int:
    return now_ts() + days * 24 * 60 * 60


def to_xui_ms(timestamp_s: int) -> int:
    return timestamp_s * 1000


def hash_secret(value: str) -> str:
    effective_pepper = os.environ.get("SERVER_PEPPER", "").encode("utf-8") or SERVER_PEPPER
    return hmac.new(effective_pepper, value.encode("utf-8"), hashlib.sha256).hexdigest()


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


def normalize_username(username: str | None) -> str:
    return (username or "").strip().lstrip("@").lower()

