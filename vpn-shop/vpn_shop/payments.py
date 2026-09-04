"""Manual payment confirmation processor (audit fix C-01/C-02/C-03/A-03).

Business constraint: payments are confirmed *manually* by an operator (no
acquiring provider is connected). The processor makes that manual step as
robust as an automated webhook would be:

    ┌──────────────┐  claim (BEGIN IMMEDIATE)  ┌──────────────┐
    │waiting_payment│ ───────────────────────▶ │ provisioning │
    └──────────────┘  CAS + promo/invite +      └──────┬───────┘
                      payment_confirmations           │ x-ui side effects
                                        ┌─────────────┴─────────────┐
                                        ▼                           ▼
                                 ┌───────────┐               ┌───────────┐
                                 │ delivered │               │  failed   │ ← reservations released,
                                 └───────────┘               └───────────┘   confirmation row removed,
                                                                             operator may retry

Guarantees:
  * Exactly one confirmation can ever claim an order (UNIQUE(order_public_id)
    in ``payment_confirmations`` + FSM compare-and-swap). Two admins pressing
    "confirm" concurrently -> one succeeds, the other gets a clear error.
  * A confirmation carries an *idempotency key* (e.g. Telegram callback id or
    ``order:<id>:<admin>:<minute>``) so retries of the same action are no-ops.
  * Amount check: the confirmed amount must cover ``final_price_rub``.
  * The x-ui side effect is executed *after* the claim is durably committed. If
    the process dies mid-provisioning the order stays in ``provisioning`` and
    :meth:`recover_stale` either re-links an already created profile or rolls
    the order back to ``failed`` for a safe manual retry.
  * Renewals are idempotent: the target expiry is computed once and stored in
    the confirmation meta; a retry re-applies the *same* expiry rather than
    adding another period.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Callable

from .security import now_ts
from .store import OrderStateError, Store

LOGGER = logging.getLogger(__name__)

STALE_PROVISIONING_SECONDS = 600


@dataclass(frozen=True)
class ConfirmationRequest:
    order_public_id: str
    actor: str
    idempotency_key: str
    amount_rub: int
    actor_id: str | None = None
    method: str = "manual_sbp"
    reference: str | None = None


@dataclass
class ConfirmationResult:
    order: dict[str, Any]
    result: dict[str, Any]
    completed_now: bool
    message: str


class PaymentConfirmationError(RuntimeError):
    pass


class ManualPaymentProcessor:
    def __init__(
        self,
        store: Store,
        provisioner: Any,
        *,
        subscription_recover: Callable[[dict[str, Any]], dict[str, Any]],
        hybrid_url_builder: Callable[[str, str], str] | None = None,
        default_device_limit: int = 3,
    ) -> None:
        self.store = store
        self.provisioner = provisioner
        self._recover = subscription_recover
        self._hybrid_url = hybrid_url_builder
        self.default_device_limit = int(default_device_limit)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def confirm(self, request: ConfirmationRequest) -> ConfirmationResult:
        order = self.store.get_order(request.order_public_id)
        if not order:
            raise PaymentConfirmationError(f"Заказ {request.order_public_id} не найден.")

        # Idempotent replay: already delivered -> just re-send the access data.
        if order.get("status") == "delivered":
            existing = self.store.get_payment_confirmation(order["public_id"])
            if existing and existing.get("idempotency_key") == request.idempotency_key:
                LOGGER.info("Idempotent replay of confirmation %s", request.idempotency_key)
            return ConfirmationResult(
                order=order,
                result=self._recover(order),
                completed_now=False,
                message="Заказ уже был доставлен ранее; доступ повторно отправлен.",
            )
        if order.get("status") in {"cancelled", "expired"}:
            raise PaymentConfirmationError(
                f"Заказ {order['public_id']} в состоянии {order['status']} и не может быть подтверждён. "
                "Если деньги поступили — создайте новый заказ или оформите возврат."
            )
        if order.get("status") == "provisioning":
            raise PaymentConfirmationError(
                f"Заказ {order['public_id']} уже подтверждается другим оператором. Подождите."
            )

        # Phase 1 – durable claim.
        try:
            claimed = self.store.claim_order_for_provisioning(
                order["public_id"],
                actor=request.actor,
                idempotency_key=request.idempotency_key,
                amount_rub=int(request.amount_rub),
                confirmed_by_id=request.actor_id,
                method=request.method,
                reference=request.reference,
            )
        except OrderStateError as exc:
            raise PaymentConfirmationError(str(exc)) from exc

        # Phase 2 – side effects (x-ui). Any exception -> compensation.
        try:
            if claimed.get("kind") == "renewal":
                result, meta_update, message = self._provision_renewal(claimed)
            else:
                result, meta_update, message = self._provision_purchase(claimed)
        except Exception as exc:  # noqa: BLE001 – we must compensate on *any* failure
            LOGGER.exception("Provisioning failed for order %s", claimed["public_id"])
            try:
                self.store.fail_order_provisioning(
                    claimed["public_id"],
                    actor=request.actor,
                    error=f"{type(exc).__name__}: {exc}",
                    release_reservations=True,
                )
            except Exception:  # noqa: BLE001
                LOGGER.exception("Compensation failed for order %s – needs operator attention", claimed["public_id"])
            raise PaymentConfirmationError(
                f"Провижининг заказа {claimed['public_id']} не удался: {exc}. Заказ переведён в 'failed', "
                "резервы возвращены; можно повторить подтверждение."
            ) from exc

        # Phase 3 – finalize.
        profile_public_id = str((result.get("profile") or {}).get("public_id") or "") or None
        final_order = self.store.finalize_order_delivered(
            claimed["public_id"],
            profile_public_id=profile_public_id,
            actor=request.actor,
            meta_update=meta_update,
        )
        self.store.record_admin_action(
            action_type="complete_renewal" if claimed.get("kind") == "renewal" else "complete_order",
            target_type="order",
            target_public_id=claimed["public_id"],
            actor=request.actor,
            meta={
                "transport": claimed.get("transport"),
                "profile_public_id": profile_public_id,
                "xhttp_profile_public_id": (result.get("xhttp_profile") or {}).get("public_id"),
                "expires_at": result.get("expires_at"),
                "idempotency_key": request.idempotency_key,
                "amount_rub": int(request.amount_rub),
            },
        )
        self._accrue_referral(final_order)
        if not result.get("subscription_url"):
            result = self._recover(final_order)
        return ConfirmationResult(order=final_order, result=result, completed_now=True, message=message)

    def recover_stale(self, *, older_than_seconds: int = STALE_PROVISIONING_SECONDS) -> list[dict[str, Any]]:
        """Crash recovery for orders stuck in ``provisioning``.

        Called from the background maintenance worker. If x-ui already has a
        client for the order (created before the crash) we finalize; otherwise
        we fail the order and release reservations so an operator can retry.
        """
        recovered: list[dict[str, Any]] = []
        for order in self.store.list_stale_provisioning_orders(older_than_seconds):
            public_id = str(order["public_id"])
            try:
                profile = self.store.get_profile_for_order(public_id)
                if profile and profile.get("public_id"):
                    final = self.store.finalize_order_delivered(
                        public_id,
                        profile_public_id=str(profile["public_id"]),
                        actor="system-recovery",
                        meta_update={"recovered_at": now_ts()},
                    )
                    recovered.append({"order": public_id, "action": "finalized"})
                    self._accrue_referral(final)
                else:
                    self.store.fail_order_provisioning(
                        public_id,
                        actor="system-recovery",
                        error="stale provisioning claim without profile",
                        release_reservations=True,
                    )
                    recovered.append({"order": public_id, "action": "failed_for_retry"})
            except Exception:  # noqa: BLE001
                LOGGER.exception("Stale order recovery failed for %s", public_id)
                recovered.append({"order": public_id, "action": "error"})
        return recovered

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _device_limit(self, meta: dict[str, Any]) -> int:
        raw = meta.get("device_limit", self.default_device_limit)
        return int(self.default_device_limit if raw is None else raw)

    def _provision_purchase(self, order: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], str]:
        result = self.provisioner.create_profile_for_order(order)
        return result, {}, "Оплата подтверждена. Ваша ссылка:"

    def _provision_renewal(self, order: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], str]:
        meta = dict(order.get("meta_json") or {})
        profile_public_id = str(meta.get("renewal_profile_public_id") or "")
        if not profile_public_id:
            raise PaymentConfirmationError(f"Renewal order {order['public_id']} has no target profile")
        device_limit = self._device_limit(meta)
        duration_days = int(order["duration_days"])
        # Idempotent target expiry: computed once per confirmation and persisted.
        confirmation = self.store.get_payment_confirmation(order["public_id"]) or {}
        conf_meta: dict[str, Any] = {}
        try:
            conf_meta = json.loads(confirmation.get("meta_json") or "{}")
        except json.JSONDecodeError:
            conf_meta = {}
        target_expiry = conf_meta.get("target_expires_at")

        is_hybrid = str(order.get("transport") or "") == "hybrid" or bool(meta.get("hybrid"))
        if is_hybrid:
            xhttp_profile_public_id = str(
                meta.get("renewal_xhttp_profile_public_id") or meta.get("xhttp_profile_public_id") or ""
            )
            if not xhttp_profile_public_id:
                raise PaymentConfirmationError(f"Hybrid renewal order {order['public_id']} has no xhttp target profile")
            tcp_result = self.provisioner.renew_profile(
                profile_public_id, duration_days, device_limit=device_limit, target_expires_at=target_expiry
            )
            xhttp_result = self.provisioner.renew_profile(
                xhttp_profile_public_id,
                duration_days,
                device_limit=device_limit,
                target_expires_at=target_expiry or tcp_result["expires_at"],
            )
            sub_url = ""
            if self._hybrid_url:
                sub_url = self._hybrid_url(str(tcp_result["sub_id"]), str(xhttp_result["sub_id"]))
            result = {
                "profile": tcp_result["profile"],
                "xhttp_profile": xhttp_result["profile"],
                "subscription_url": sub_url,
                "sub_id": f"{tcp_result['sub_id']}~{xhttp_result['sub_id']}",
                "expires_at": min(int(tcp_result["expires_at"]), int(xhttp_result["expires_at"])),
            }
            meta_update = {
                "hybrid": True,
                "tcp_profile_public_id": tcp_result["profile"]["public_id"],
                "xhttp_profile_public_id": xhttp_result["profile"]["public_id"],
                "tcp_sub_id": tcp_result["sub_id"],
                "xhttp_sub_id": xhttp_result["sub_id"],
                "target_expires_at": result["expires_at"],
            }
        else:
            result = self.provisioner.renew_profile(
                profile_public_id, duration_days, device_limit=device_limit, target_expires_at=target_expiry
            )
            meta_update = {"target_expires_at": int(result["expires_at"])}
        message = (
            "Оплата подтверждена. Лимит подписки обновлён, ссылка прежняя:"
            if meta.get("upgrade_only")
            else "Оплата подтверждена. Подписка продлена, ссылка прежняя:"
        )
        return result, meta_update, message

    def _accrue_referral(self, order: dict[str, Any]) -> None:
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
        except Exception:  # noqa: BLE001
            LOGGER.exception("Failed to create referral accrual for order %s", order.get("public_id"))
