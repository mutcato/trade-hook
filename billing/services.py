"""Credit accounting.

Everything that moves credits goes through here so that locking and the
append-only ledger stay in one place. Three invariants matter:

* A HookSet execution consumes exactly one credit, free quota first.
* An order never hands out more credits than it has earned, however many times
  the provider repeats a callback — each grant is the difference against
  `Order.credits_granted`.
* Underpaying does not forfeit the money. A shortfall within
  `settings.BILLING_PARTIAL_PAYMENT_TOLERANCE` counts as paid in full (exchange
  withdrawal fees land here); a larger one earns credits in proportion.
"""

import logging
from dataclasses import dataclass
from decimal import ROUND_FLOOR, Decimal, InvalidOperation

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from .models import LedgerEntry, Order, Wallet
from .providers import NowPaymentsProvider

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ConsumeResult:
    """Outcome of trying to bill one execution."""

    charged: bool
    source: str  # "free", "credit" or "none"
    remaining: int


def get_wallet(user):
    wallet, _ = Wallet.objects.get_or_create(user=user)
    return wallet


def has_available_executions(user):
    """True when `user` could still pay for at least one execution.

    Read-only guard for gating actions up front; the actual spend goes through
    `consume_execution`, which locks the row.
    """
    return get_wallet(user).total_available > 0


def _record(wallet, delta, reason, order=None, hookset=None, note=""):
    return LedgerEntry.objects.create(
        wallet=wallet,
        delta=delta,
        balance_after=wallet.balance,
        reason=reason,
        order=order,
        hookset=hookset,
        note=note,
    )


@transaction.atomic
def consume_execution(user, hookset=None):
    """Bill one execution to `user`, spending free quota before paid credits.

    Returns a `ConsumeResult`; `charged=False` means the user is out of both and
    the caller must not perform the execution.
    """
    Wallet.objects.get_or_create(user=user)
    wallet = Wallet.objects.select_for_update().get(user=user)

    if wallet.free_executions_remaining > 0:
        wallet.free_executions_used += 1
        wallet.save(update_fields=["free_executions_used", "updated_at"])
        _record(wallet, 0, LedgerEntry.Reason.FREE_EXECUTION, hookset=hookset)
        return ConsumeResult(True, "free", wallet.total_available)

    if wallet.balance > 0:
        wallet.balance -= 1
        wallet.save(update_fields=["balance", "updated_at"])
        _record(wallet, -1, LedgerEntry.Reason.EXECUTION, hookset=hookset)
        return ConsumeResult(True, "credit", wallet.total_available)

    return ConsumeResult(False, "none", 0)


def _as_decimal(value):
    """Coerce a provider amount to Decimal, or None when it isn't a number.

    Provider payloads carry amounts as JSON strings. Django only converts on
    save/refresh, not on assignment, so anything read back off an in-memory
    instance has to be coerced here or the arithmetic sees a str.
    """
    if value is None:
        return None
    try:
        return Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        return None


def credits_owed_for(order, actually_paid):
    """Credits `order` has earned for `actually_paid` units of its pay currency.

    Both amounts are in the crypto the invoice asked for — never the USD price —
    so the ratio is against `order.pay_amount`. Returns None when that cannot be
    judged (no invoice amount recorded yet), which means "do not grant anything".
    """
    expected = _as_decimal(order.pay_amount)
    paid = _as_decimal(actually_paid)
    if expected is None or expected <= 0 or paid is None:
        return None

    ratio = paid / expected

    if ratio <= 0:
        return 0
    if ratio >= settings.BILLING_PARTIAL_PAYMENT_TOLERANCE:
        return order.credits
    return int(
        (Decimal(order.credits) * ratio).to_integral_value(rounding=ROUND_FLOOR)
    )


@transaction.atomic
def grant_order_credits(order, credits_owed):
    """Top this order's grants up to `credits_owed`. Returns credits actually added.

    Granting the *difference* rather than a flat amount is what makes repeated
    callbacks harmless and still lets a topped-up partial payment release its
    remainder later.
    """
    order = Order.objects.select_for_update().get(pk=order.pk)
    delta = min(credits_owed, order.credits) - order.credits_granted
    if delta <= 0:
        return 0

    Wallet.objects.get_or_create(user=order.user)
    wallet = Wallet.objects.select_for_update().get(user=order.user)
    wallet.balance += delta
    wallet.save(update_fields=["balance", "updated_at"])

    order.credits_granted += delta
    if order.credited_at is None:
        order.credited_at = timezone.now()
    order.status = (
        Order.Status.CONFIRMED
        if order.credits_granted >= order.credits
        else Order.Status.PARTIALLY_PAID
    )
    order.save(
        update_fields=["credits_granted", "credited_at", "status", "updated_at"]
    )

    _record(wallet, delta, LedgerEntry.Reason.PURCHASE, order=order)
    logger.info("Credited %s credits to %s (order %s)", delta, order.user, order.uuid)
    return delta


def credit_order(order):
    """Grant `order` its full credits — the fully-paid path."""
    return grant_order_credits(order, order.credits)


def create_order(user, pack, provider=None):
    """Open an order for `pack` and attach a hosted invoice from the provider.

    The row is only written once the provider has issued an invoice, so a
    provider outage leaves no unpayable orders behind. The instance already
    carries its `uuid` default unsaved, which is what the provider echoes back
    as `order_id`.
    """
    provider = provider or NowPaymentsProvider()

    order = Order(
        user=user,
        pack=pack,
        credits=pack.credits,
        price_usd=pack.price_usd,
        provider=provider.name,
    )

    frontend = settings.FRONTEND_BASE_URL.rstrip("/")
    payload = provider.create_invoice(
        order,
        success_url=f"{frontend}/credits?order={order.uuid}&status=success",
        cancel_url=f"{frontend}/credits?order={order.uuid}&status=cancelled",
        ipn_callback_url=settings.NOWPAYMENTS_IPN_CALLBACK_URL,
    )

    order.provider_invoice_id = str(payload.get("id", ""))
    order.invoice_url = payload.get("invoice_url", "")
    order.save()
    return order


def apply_ipn(payload, provider=None):
    """Fold one verified provider callback into the matching order.

    Returns the order, or None when the callback names an order we don't know.
    """
    provider = provider or NowPaymentsProvider()

    order_id = payload.get("order_id") or ""
    try:
        order = Order.objects.filter(uuid=order_id).first()
    except (ValueError, TypeError, ValidationError):
        # A malformed order_id must read as "unknown order", not a 500.
        order = None
    if order is None:
        logger.warning("NOWPayments IPN for unknown order_id %r", order_id)
        return None

    payment_status = (payload.get("payment_status") or "").lower()

    updates = {}
    if payload.get("payment_id"):
        updates["provider_payment_id"] = str(payload["payment_id"])
    if payload.get("pay_currency"):
        updates["pay_currency"] = str(payload["pay_currency"])
    # Coerced here so the in-memory instance holds numbers, not JSON strings.
    pay_amount = _as_decimal(payload.get("pay_amount"))
    if pay_amount is not None:
        updates["pay_amount"] = pay_amount
    actually_paid = _as_decimal(payload.get("actually_paid"))
    if actually_paid is not None:
        updates["actually_paid"] = actually_paid

    def apply_updates():
        for field, value in updates.items():
            setattr(order, field, value)
        if updates:
            order.save(update_fields=[*updates, "updated_at"])

    if payment_status in provider.SETTLED_STATUSES:
        apply_updates()
        credit_order(order)
        # The grant works on its own locked copy, so re-read before handing the
        # order back or callers would see a stale pending status.
        order.refresh_from_db()
        return order

    if payment_status == "partially_paid":
        # The money is already in the payout wallet — forfeiting it would just
        # turn an underpayment into a support ticket. Absorb a fee-sized
        # shortfall, otherwise credit what was actually paid for.
        apply_updates()
        owed = credits_owed_for(order, order.actually_paid)
        if owed is None:
            logger.warning(
                "Order %s is partially paid but has no invoice amount to judge it against",
                order.uuid,
            )
        else:
            granted = grant_order_credits(order, owed)
            if owed < order.credits:
                logger.warning(
                    "Order %s short by more than tolerance (%s of %s %s): "
                    "granted %s of %s credits",
                    order.uuid,
                    order.actually_paid,
                    order.pay_amount,
                    order.pay_currency,
                    owed,
                    order.credits,
                )
            else:
                logger.info(
                    "Order %s settled within tolerance (%s of %s %s)",
                    order.uuid,
                    order.actually_paid,
                    order.pay_amount,
                    order.pay_currency,
                )
            if granted == 0 and order.credits_granted == 0:
                order.status = Order.Status.PARTIALLY_PAID
                order.save(update_fields=["status", "updated_at"])
        order.refresh_from_db()
        return order

    if payment_status == "failed":
        updates["status"] = Order.Status.FAILED
    elif payment_status == "expired":
        updates["status"] = Order.Status.EXPIRED
    elif payment_status == "refunded":
        updates["status"] = Order.Status.REFUNDED

    # An order that already released credits must not be walked backwards by a
    # late callback.
    if order.credits_granted > 0:
        updates.pop("status", None)

    apply_updates()
    return order
