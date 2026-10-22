import uuid
from decimal import Decimal

from django.conf import settings
from django.db import models


class CreditPack(models.Model):
    """A purchasable bundle of execution credits.

    Packs exist as rows rather than constants so pricing can be tuned in the
    admin without a deploy. The unit price is expected to fall as `credits`
    grows — see the seed migration for the current curve.
    """

    credits = models.PositiveIntegerField(unique=True)
    price_usd = models.DecimalField(max_digits=10, decimal_places=2)
    is_active = models.BooleanField(default=True)
    sort_order = models.PositiveSmallIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["sort_order", "credits"]

    def __str__(self):
        return f"{self.credits} credits — ${self.price_usd}"

    @property
    def unit_price_usd(self):
        return (self.price_usd / self.credits).quantize(Decimal("0.0001"))


class Wallet(models.Model):
    """A user's execution credit balance plus their free-tier counter.

    `free_executions_used` is a lifetime counter, not a monthly one: the free
    tier is a trial of `settings.FREE_EXECUTION_QUOTA` executions, after which
    the user tops up.
    """

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="wallet"
    )
    balance = models.PositiveIntegerField(default=0)
    free_executions_used = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user} — {self.balance} credits"

    @property
    def free_executions_remaining(self):
        return max(settings.FREE_EXECUTION_QUOTA - self.free_executions_used, 0)

    @property
    def total_available(self):
        return self.free_executions_remaining + self.balance


class Order(models.Model):
    """One credit top-up attempt against a payment provider.

    `credits` and `price_usd` are snapshotted off the pack at creation time so
    that later pricing changes never rewrite what a user actually bought.
    `credited_at` is the idempotency marker — a provider may deliver the same
    IPN several times, and credits must only ever be granted once.
    """

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        CONFIRMED = "confirmed", "Confirmed"
        PARTIALLY_PAID = "partially_paid", "Partially paid"
        FAILED = "failed", "Failed"
        EXPIRED = "expired", "Expired"
        REFUNDED = "refunded", "Refunded"

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="orders"
    )
    pack = models.ForeignKey(
        CreditPack, on_delete=models.SET_NULL, null=True, blank=True
    )
    credits = models.PositiveIntegerField()
    price_usd = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(
        max_length=20, choices=Status.choices, default=Status.PENDING
    )

    provider = models.CharField(max_length=32, default="nowpayments")
    provider_invoice_id = models.CharField(max_length=64, blank=True)
    provider_payment_id = models.CharField(max_length=64, blank=True)
    invoice_url = models.URLField(blank=True)
    pay_currency = models.CharField(max_length=20, blank=True)
    pay_amount = models.DecimalField(
        max_digits=30, decimal_places=12, null=True, blank=True
    )
    actually_paid = models.DecimalField(
        max_digits=30, decimal_places=12, null=True, blank=True
    )

    # Running total of credits already handed out for this order. Callbacks grant
    # the difference against it, so a partial payment that is later topped up
    # releases only the remainder — and a repeated callback releases nothing.
    credits_granted = models.PositiveIntegerField(default=0)
    credited_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["provider", "provider_payment_id"]),
        ]

    def __str__(self):
        return f"{self.uuid} — {self.credits} credits ({self.status})"


class LedgerEntry(models.Model):
    """Append-only audit trail of every credit movement.

    Every grant and every consumption lands here, so "where did my credits go"
    is always answerable. Free-tier executions are recorded with `delta=0`
    because they do not touch the paid balance but still need to be auditable.
    """

    class Reason(models.TextChoices):
        PURCHASE = "purchase", "Purchase"
        EXECUTION = "execution", "Execution"
        FREE_EXECUTION = "free_execution", "Free execution"
        ADJUSTMENT = "adjustment", "Manual adjustment"

    wallet = models.ForeignKey(
        Wallet, on_delete=models.CASCADE, related_name="entries"
    )
    delta = models.IntegerField()
    balance_after = models.PositiveIntegerField()
    reason = models.CharField(max_length=20, choices=Reason.choices)
    order = models.ForeignKey(
        Order, on_delete=models.SET_NULL, null=True, blank=True, related_name="entries"
    )
    hookset = models.ForeignKey(
        "trader.HookSet", on_delete=models.SET_NULL, null=True, blank=True
    )
    note = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        verbose_name_plural = "Ledger entries"

    def __str__(self):
        return f"{self.wallet_id}: {self.delta:+d} ({self.reason})"
