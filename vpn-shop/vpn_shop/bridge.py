from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
import time
from typing import Any
import urllib.parse

LOGGER = logging.getLogger(__name__)

ALLOWED_BRIDGE_ACTIONS = {
    "ping", "status", "server_status", "reconcile_xui", "find_client_by_email",
    "find_client_by_sub_id", "get_client_traffic", "list_client_traffic",
    "provision_profile", "renew_profile", "set_profile_enabled",
    "build_warp_conf", "send_subscription_email"
}


def _is_approved_email_url(url_str: str, approved_hosts: set[str] | None = None) -> bool:
    """Validate that redirect/email URL only points to approved domains (*.silentconnect.net, public host) or https://t.me/ (SC-24).  # PLACEHOLDER"""
    if not url_str or not url_str.strip():
        return True
    try:
        parsed = urllib.parse.urlparse(url_str.strip())
    except Exception:
        return False

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return False

    hostname = (parsed.hostname or "").lower().strip()
    if not hostname:
        return False

    # Telegram links must be https://t.me/
    if hostname == "t.me" or hostname.endswith(".t.me"):
        return scheme == "https"

    # Approved domains: *.silentconnect.net or silentconnect.net  # PLACEHOLDER
    if hostname == "silentconnect.net" or hostname.endswith(".silentconnect.net"):  # PLACEHOLDER
        return True

    # Host from public settings (e.g. custom domain or node host)
    if approved_hosts and hostname in approved_hosts:
        return True

    return False

MAX_CLOCK_SKEW_SECONDS = 300
_REPLAY_LOCK = threading.Lock()
_REPLAY_CACHE: dict[str, int] = {}
_REPLAY_MAX_ENTRIES = 10000


def _check_and_record_replay(replay_key: str, now_ts: int) -> bool:
    """Return True if request is fresh, False if replayed within window."""
    cutoff = now_ts - (MAX_CLOCK_SKEW_SECONDS * 2)
    with _REPLAY_LOCK:
        if len(_REPLAY_CACHE) > _REPLAY_MAX_ENTRIES or any(ts < cutoff for ts in list(_REPLAY_CACHE.values())[:64]):
            expired = [k for k, ts in _REPLAY_CACHE.items() if ts < cutoff]
            for k in expired:
                _REPLAY_CACHE.pop(k, None)
        if replay_key in _REPLAY_CACHE:
            return False
        _REPLAY_CACHE[replay_key] = now_ts
        return True


def sign_bridge_payload(secret: str, timestamp: int, raw_body: bytes) -> str:
    msg = f"{timestamp}.".encode("utf-8") + raw_body
    return hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def verify_and_dispatch_bridge(
    *,
    headers: dict[str, str] | Any,
    raw_body: bytes,
    secret: str,
    provisioner: Any,
    awg_manager: Any,
    now_fn=time.time,
) -> tuple[int, dict[str, Any]]:
    """Обработчик запросов к серверному мосту /api/bridge."""
    if not secret:
        LOGGER.error("Bridge secret is not configured on this server")
        return 503, {"ok": False, "error": "bridge_not_configured"}

    # Support case-insensitive header lookup if dict or mapping
    def get_h(k: str) -> str:
        if hasattr(headers, "get"):
            return str(headers.get(k) or headers.get(k.lower()) or headers.get(k.title()) or "")
        return ""

    ts_raw = get_h("X-Bridge-Timestamp").strip()
    sig = get_h("X-Bridge-Signature").strip()
    if not ts_raw or not sig:
        return 401, {"ok": False, "error": "missing_auth_headers"}

    try:
        ts = int(ts_raw)
    except ValueError:
        return 401, {"ok": False, "error": "invalid_timestamp"}

    now = int(now_fn())
    if abs(now - ts) > MAX_CLOCK_SKEW_SECONDS:
        return 401, {"ok": False, "error": "timestamp_out_of_window"}

    expected_sig = sign_bridge_payload(secret, ts, raw_body)
    if not hmac.compare_digest(sig, expected_sig):
        return 403, {"ok": False, "error": "invalid_signature"}

    if not _check_and_record_replay(f"{ts}:{sig}", now):
        return 409, {"ok": False, "error": "replay_detected"}

    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except Exception:
        return 400, {"ok": False, "error": "invalid_json"}

    action = payload.get("action")
    params = payload.get("params") if isinstance(payload.get("params"), dict) else payload

    if action not in ALLOWED_BRIDGE_ACTIONS:
        return 400, {"ok": False, "error": f"action_not_allowed:{action}"}

    if action in ("ping", "status", "server_status"):
        return 200, {
            "ok": True,
            "result": "pong",
            "status": "ok",
            "text": f"Node active\nTime: {int(now_fn())}",
            "ts": int(now_fn()),
        }

    if action == "reconcile_xui":
        from .xui_reconciler import XuiReconciler, notify_local_reconciler
        if notify_local_reconciler():
            return 200, {"ok": True, "result": "signaled_daemon"}
        rec = XuiReconciler(provisioner.settings, provisioner.store)
        res = rec.reconcile_once(dry_run=False)
        return 200, {"ok": True, "result": res}

    if action == "find_client_by_email":
        email = str(params.get("email") or params.get("xui_email") or "").strip()
        if not email:
            return 400, {"ok": False, "error": "missing_email"}
        found = provisioner.xui_db.find_client_by_email(email)
        return 200, {"ok": True, "result": found, "found": found}

    if action == "find_client_by_sub_id":
        sub_id = str(params.get("sub_id") or "").strip()
        if not sub_id:
            return 400, {"ok": False, "error": "missing_sub_id"}
        found = provisioner.xui_db.find_client_by_sub_id(sub_id)
        return 200, {"ok": True, "result": found, "found": found}

    if action == "get_client_traffic":
        email = str(params.get("email") or params.get("xui_email") or "").strip()
        if not email:
            return 400, {"ok": False, "error": "missing_email"}
        traffic = provisioner.xui_db.get_client_traffic(email)
        return 200, {"ok": True, "result": traffic, "traffic": traffic}

    if action == "list_client_traffic":
        limit = int(params.get("limit") or 20)
        rows = provisioner.xui_db.list_client_traffic(limit=limit)
        return 200, {"ok": True, "result": rows, "rows": rows}

    if action == "provision_profile":
        order = params.get("order")
        if isinstance(order, dict) and order.get("public_id"):
            try:
                res = provisioner.create_profile_for_order(order)
                return 200, {"ok": True, "result": res}
            except Exception:
                LOGGER.exception("create_profile_for_order failed, falling back to _provision_profile")
                transport = str(order.get("transport") or params.get("transport") or "tcp")
                duration_days = int(order.get("duration_days") or params.get("duration_days") or 30)
                profile_mode = str(params.get("profile_mode") or order.get("profile_mode") or "standard")
                family_label = params.get("family_label")
                alias = str(params.get("alias") or order.get("public_id") or "")
                notes = str(params.get("notes") or "")
                device_limit = int(order.get("device_limit") or params.get("device_limit") or 0)
                res = provisioner._provision_profile(
                    transport=transport,
                    duration_days=duration_days,
                    profile_mode=profile_mode,
                    family_label=family_label,
                    alias=alias,
                    notes=notes,
                    device_limit=device_limit,
                )
                return 200, {"ok": True, "result": res}
        else:
            transport = str(params.get("transport") or "tcp")
            duration_days = int(params.get("duration_days") or 30)
            profile_mode = str(params.get("profile_mode") or "standard")
            family_label = params.get("family_label")
            alias = str(params.get("alias") or "")
            notes = str(params.get("notes") or "")
            device_limit = int(params.get("device_limit") or 0)
            res = provisioner._provision_profile(
                transport=transport,
                duration_days=duration_days,
                profile_mode=profile_mode,
                family_label=family_label,
                alias=alias,
                notes=notes,
                device_limit=device_limit,
            )
            if getattr(provisioner.store, "_replica_mgr", None) is not None:
                try:
                    provisioner.store._replica_mgr.force_sync()
                except Exception:
                    pass
            return 200, {"ok": True, "result": res}

    if action == "renew_profile":
        profile_public_id = str(params.get("profile_public_id") or "").strip()
        duration_days = params.get("duration_days")
        device_limit = params.get("device_limit", 3)
        xui_email = str(params.get("xui_email") or "").strip()
        inbound_id = params.get("inbound_id")

        if duration_days is None:
            return 400, {"ok": False, "error": "missing_duration_days"}

        res = None
        if profile_public_id:
            try:
                res = provisioner.renew_profile(
                    profile_public_id,
                    int(duration_days),
                    device_limit=int(device_limit) if device_limit is not None else None,
                )
            except Exception as ex:
                LOGGER.warning("provisioner.renew_profile failed for %s: %s", profile_public_id, ex)

        if not res and xui_email:
            found = provisioner.xui_db.find_client_by_email(xui_email)
            if found:
                client = dict(found["client"])
                inb_id = int(inbound_id or found.get("inbound_id") or 1)
                client_expiry_ms = int(client.get("expiryTime") or 0)
                client_expiry_s = client_expiry_ms // 1000 if client_expiry_ms > 0 else 0
                base_expires_at = max(int(now_fn()), client_expiry_s)
                new_expires_at = base_expires_at + int(duration_days) * 86400
                new_expiry_ms = new_expires_at * 1000
                provisioner.xui_db.update_client_expiry_direct(
                    inb_id,
                    xui_email,
                    new_expiry_ms,
                    enable=True,
                    device_limit=int(device_limit) if device_limit is not None else None,
                )
                sub_id = str(client.get("subId") or "")
                res = {
                    "profile": {"public_id": profile_public_id or xui_email, "expires_at": new_expires_at},
                    "subscription_url": f"{provisioner.settings.subscription_base_url}/{sub_id}",
                    "xui_email": xui_email,
                    "sub_id": sub_id,
                    "expires_at": new_expires_at,
                }

        if not res:
            return 400, {"ok": False, "error": "missing_renewal_params_or_profile_not_found"}

        if getattr(provisioner.store, "_replica_mgr", None) is not None:
            try:
                provisioner.store._replica_mgr.force_sync()
            except Exception:
                pass
        return 200, {"ok": True, "result": res}

    if action == "set_profile_enabled":
        profile_public_id = str(params.get("profile_public_id") or "").strip()
        enabled = bool(params.get("enabled", True))
        xui_email = str(params.get("xui_email") or "").strip()
        inbound_id = params.get("inbound_id")

        res = None
        if profile_public_id:
            try:
                res = provisioner.set_profile_enabled(profile_public_id, enabled)
            except Exception as ex:
                LOGGER.warning("provisioner.set_profile_enabled failed for %s: %s", profile_public_id, ex)

        if not res and xui_email:
            found = provisioner.xui_db.find_client_by_email(xui_email)
            if found:
                inb_id = int(inbound_id or found.get("inbound_id") or 1)
                client = dict(found["client"])
                provisioner.xui_db.update_client_expiry_direct(
                    inb_id,
                    xui_email,
                    int(client.get("expiryTime") or 0),
                    enable=enabled,
                )
                res = {
                    "profile": {"public_id": profile_public_id or xui_email},
                    "xui_email": xui_email,
                    "inbound_id": inb_id,
                    "enabled": enabled,
                }

        if not res:
            return 400, {"ok": False, "error": "profile_not_found"}

        return 200, {"ok": True, "result": res}

    if action == "build_warp_conf":
        sub_id = str(params.get("sub_id") or "").strip()
        server_code = str(params.get("server_code") or "nl").strip().lower()
        if not sub_id:
            return 400, {"ok": False, "error": "missing_sub_id"}
        peer = awg_manager.get_peer(sub_id, server_code=server_code)
        if peer is None:
            awg_manager.create_peer(sub_id, server_code=server_code)
        elif not peer.get("active"):
            awg_manager.readd_peer(sub_id, server_code=server_code)
        conf_text = awg_manager.build_conf(sub_id, server_code=server_code)
        return 200, {
            "ok": True,
            "conf": conf_text,
            "conf_text": conf_text,
            "caption": None,
            "server_code": server_code,
            "result": {
                "conf": conf_text,
                "conf_text": conf_text,
                "caption": None,
                "server_code": server_code,
            },
        }

    if action == "send_subscription_email":
        customer_email = str(params.get("customer_email") or "").strip()
        order_public_id = str(params.get("order_public_id") or "").strip()
        if not customer_email or not order_public_id:
            return 400, {"ok": False, "error": "missing_email_params"}

        setup_url = str(params.get("setup_url") or "").strip()
        json_url = str(params.get("json_url") or "").strip()
        cabinet_url = str(params.get("cabinet_url") or "").strip()
        bind_tg_url = str(params.get("bind_tg_url") or "").strip()

        approved_hosts: set[str] = set()
        if getattr(provisioner, "settings", None):
            for base_val in (
                getattr(provisioner.settings, "web_public_base_url", None),
                getattr(provisioner.settings, "subscription_base_url", None),
            ):
                if base_val:
                    try:
                        h = urllib.parse.urlparse(str(base_val)).hostname
                        if h:
                            approved_hosts.add(h.lower().strip())
                    except Exception:
                        pass

        for url_name, url_val in (
            ("setup_url", setup_url),
            ("json_url", json_url),
            ("cabinet_url", cabinet_url),
            ("bind_tg_url", bind_tg_url),
        ):
            if url_val and not _is_approved_email_url(url_val, approved_hosts):
                return 400, {"ok": False, "error": f"invalid_or_unapproved_url:{url_name}"}

        try:
            from . import mailer
            mailer.send_subscription_email_async(
                provisioner.settings,
                customer_email=customer_email,
                order_public_id=order_public_id,
                plan_name=str(params.get("plan_name") or "SilentConnect"),
                duration_days=int(params.get("duration_days") or 30),
                setup_url=setup_url,
                json_url=json_url,
                cabinet_url=cabinet_url,
                bind_tg_url=bind_tg_url,
                expires_ts=params.get("expires_ts"),
            )
            return 200, {"ok": True, "result": "queued"}
        except Exception as e:
            LOGGER.exception("Failed to send subscription email via bridge: %s", e)
            return 200, {"ok": True, "warning": str(e)}

    return 400, {"ok": False, "error": f"action_not_allowed:{action}"}
