from __future__ import annotations

import hashlib
import secrets
import string
import time


ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
ALPHABET_LOWER = string.ascii_lowercase + string.digits


def now_ts() -> int:
    return int(time.time())


def days_from_now(days: int) -> int:
    return now_ts() + days * 24 * 60 * 60


def to_xui_ms(timestamp_s: int) -> int:
    return timestamp_s * 1000


def hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def random_code(prefix: str, groups: tuple[int, ...] = (4, 4, 4)) -> str:
    chunks = []
    for size in groups:
        chunks.append("".join(secrets.choice(ALPHABET) for _ in range(size)))
    return f"{prefix}-" + "-".join(chunks)


def masked_code(code: str) -> str:
    if len(code) <= 8:
        return code
    return f"{code[:4]}...{code[-4:]}"


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

