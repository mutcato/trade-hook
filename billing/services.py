"""Credit accounting.

Everything that moves credits goes through here so that locking and the
append-only ledger stay in one place. Two invariants matter:

* A HookSet execution consumes exactly one credit, free quota first.
* A provider may deliver the same IPN repeatedly, so an order grants its
  credits at most once (guarded by `Order.credited_at`).
"""

import logging
from dataclasses import dataclass

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


@transaction.atomic
def credit_order(order):
    """Grant `order`'s credits, exactly once. True if this call did the granting."""
    order = Order.objects.select_for_update().get(pk=order.pk)
    if order.credited_at is not None:
        return False

    Wallet.objects.get_or_create(user=order.user)
    wallet = Wallet.objects.select_for_update().get(user=order.user)
    wallet.balance += order.credits
    wallet.save(update_fields=["balance", "updated_at"])

    order.credited_at = timezone.now()
    order.status = Order.Status.CONFIRMED
    order.save(update_fields=["credited_at", "status", "updated_at"])

    _record(wallet, order.credits, LedgerEntry.Reason.PURCHASE, order=order)
    logger.info("Credited %s credits to %s (order %s)", order.credits, order.user, order.uuid)
    return True


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
    if payload.get("pay_amount") is not None:
        updates["pay_amount"] = payload["pay_amount"]
    if payload.get("actually_paid") is not None:
        updates["actually_paid"] = payload["actually_paid"]

    if payment_status in provider.SETTLED_STATUSES:
        for field, value in updates.items():
            setattr(order, field, value)
        if updates:
            order.save(update_fields=[*updates, "updated_at"])
        credit_order(order)
        # credit_order works on its own locked copy, so re-read before handing
        # the order back or callers would see a stale pending status.
        order.refresh_from_db()
        return order

    if payment_status == "partially_paid":
        updates["status"] = Order.Status.PARTIALLY_PAID
    elif payment_status == "failed":
        updates["status"] = Order.Status.FAILED
    elif payment_status == "expired":
        updates["status"] = Order.Status.EXPIRED
    elif payment_status == "refunded":
        updates["status"] = Order.Status.REFUNDED

    # A settled order must never be walked backwards by a late callback.
    if order.credited_at is not None:
        updates.pop("status", None)

    if updates:
        for field, value in updates.items():
            setattr(order, field, value)
        order.save(update_fields=[*updates, "updated_at"])

    return order
