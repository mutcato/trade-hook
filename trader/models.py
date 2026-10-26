import json
import logging
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import time

from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.utils import timezone

logger = logging.getLogger(__name__)

# TradingView fails a webhook it cannot get an answer to within 3 seconds and
# does not retry, so an alert send must never eat the whole budget.
TELEGRAM_SEND_TIMEOUT_SECONDS = 2

# Create your models here.


class Hook(models.Model):
    """A hook is a webhook that is used to receive data from the trading platform."""

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    name = models.CharField(max_length=255)
    hookset = models.ForeignKey("HookSet", on_delete=models.CASCADE)
    is_triggered = models.BooleanField(default=False)
    triggered_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.uuid)

    def trigger(self):
        self.is_triggered = True
        self.triggered_at = timezone.now()
        self.save()


def _http_status_of(exc):
    """The HTTP status an exception carries, or None.

    `urllib.error.HTTPError` exposes `.code`; connection and timeout failures do
    not. Validated rather than trusted because this runs inside `notify`'s
    except block — a bad value reaching the DB insert would raise there and turn
    a handled delivery failure into a 500.
    """
    code = getattr(exc, "code", None)
    if isinstance(code, int) and 100 <= code <= 599:
        return code
    return None


@dataclass(frozen=True)
class DeliveryResult:
    """Outcome of one `HookSet.notify()` fan-out.

    Deliberately not truthiness-based: callers must read `.delivered`, because a
    `(0 delivered, 2 channels)` result is a *failure* and a bare `if result:` on
    a tuple or object would read as success and bill for an undelivered alert.
    """

    delivered: int
    total: int


class HookSet(models.Model):
    """A hook set is a set of hooks that are used to receive data from the trading platform."""

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    name = models.CharField(max_length=255)
    timewindow = models.TimeField(default=time(1, 0))
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    def set_notification_channels(self, channels):
        """Replace the notification targets for this hookset with the given channel instances.

        `channels` can mix any model that has a `.send(message)` method (Telegram
        today, Email later) — NotificationTarget's GenericForeignKey means HookSet
        never needs a new field/migration when another channel type is added.
        """
        self.notification_targets.all().delete()
        NotificationTarget.objects.bulk_create(
            NotificationTarget(
                hookset=self,
                content_type=ContentType.objects.get_for_model(channel),
                object_id=channel.pk,
            )
            for channel in channels
        )

    def notify(self, message):
        """Fan `message` out to every channel and report what got through.

        One unreachable channel must not fail the response or stop the remaining
        channels, so failures are isolated per channel. `delivered` is what the
        caller bills on — a zero has to mean "nobody got the alert" — and each
        target's outcome is recorded so the owner can see a channel has died.
        """
        delivered = 0
        total = 0
        for target in self.notification_targets.select_related("content_type"):
            channel = target.channel
            if channel is None:
                continue
            total += 1
            try:
                channel.send(message)
            except Exception as exc:
                logger.exception(
                    "Notification channel %s failed for hookset %s", channel, self.uuid
                )
                NotificationTargetLog.objects.create(
                    target=target,
                    success=False,
                    error=str(exc)[:255] or exc.__class__.__name__,
                    status_code=_http_status_of(exc),
                )
            else:
                delivered += 1
                NotificationTargetLog.objects.create(target=target, success=True)
        return DeliveryResult(delivered=delivered, total=total)


class NotificationTarget(models.Model):
    """Links a HookSet to one notification channel (Telegram, Email, ...) via a generic FK.

    This is what lets a HookSet fan out to any number of channel *types* through a
    single relation instead of gaining a new ManyToManyField every time a channel
    type (Telegram, Email, ...) is added.
    """

    hookset = models.ForeignKey(
        HookSet, on_delete=models.CASCADE, related_name="notification_targets"
    )
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveIntegerField()
    channel = GenericForeignKey("content_type", "object_id")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("hookset", "content_type", "object_id")

    def __str__(self):
        return f"{self.hookset} -> {self.channel}"

class NotificationTargetLog(models.Model):
    """One delivery attempt on one notification target, successful or not.

    A partial delivery still bills the owner for the execution — one credit buys
    the execution, not one copy per channel — so a broken channel has to be
    visible or they would keep paying full price for alerts half of which never
    arrive.

    Because successes are recorded too, health is simply "is the newest row a
    success?" and recovery needs no separate resolution flag. Rows are ordered
    newest-first, so the first entry is the channel's current state.
    """

    target = models.ForeignKey(
        NotificationTarget, on_delete=models.CASCADE, related_name="logs"
    )
    success = models.BooleanField()
    error = models.CharField(max_length=255, blank=True)
    # Null whenever no HTTP response was ever received — an unconfigured token,
    # a refused connection or a read timeout all fail before a status exists —
    # and on a success, since `send()` does not report the response code back.
    # Populated for an HTTPError, where it is the most diagnostic field there
    # is: 401 means a bad bot token, 403 the bot was blocked or kicked, 400 a
    # bad chat_id, 429 rate limiting.
    status_code = models.PositiveSmallIntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        indexes = [
            models.Index(fields=["target", "-created_at"]),
        ]

    def __str__(self):
        outcome = "ok" if self.success else f"failed: {self.error}"
        return f"{self.target_id}: {outcome}"


ACTION_CHOICES = [
    ("LONG", "Long"),
    ("SHORT", "Short"),
]


class Trade(models.Model):
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    name = models.CharField(max_length=255)
    pair = models.CharField(max_length=10)
    action = models.CharField(max_length=10, choices=ACTION_CHOICES)
    hookset = models.ForeignKey(
        "HookSet", on_delete=models.CASCADE, related_name="trades"
    )
    is_triggered = models.BooleanField(default=False)
    triggered_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    def validate_pair(self, pair):
        assets = pair.split("/")

        if len(assets) != 2:
            raise ValidationError(
                "Invalid pair. Must be in the format of 'asset1/asset2'."
            )

        if len(assets[0]) < 2 or len(assets[1]) < 2:
            raise ValidationError("Invalid pair. Must be at least 2 characters long.")

        if len(assets[0]) > 5 or len(assets[1]) > 5:
            raise ValidationError("Invalid pair. Must be less than 5 characters long.")

        # Inverted before: this fired when an asset *was* alphabetic, so every
        # ordinary pair like BTC/USDT failed its own "must be alphanumeric" rule.
        if not (assets[0].isalnum() and assets[1].isalnum()):
            raise ValidationError("Invalid pair. Must be alphanumeric.")

        return pair

    @transaction.atomic
    def trigger(self):
        self.is_triggered = True
        self.triggered_at = timezone.now()
        self.save()
        # TODO: Implement trade API calls


PLATFORM_CHOICES = [
    ("BINANCE", "Binance"),
    ("KUCOIN", "Kucoin"),
    ("OKX", "OKX"),
    ("BITGET", "Bitget"),
    ("BITFINEX", "Bitfinex"),
    ("BITSTAMP", "Bitstamp"),
]

class Exchange(models.Model):
    """An exchange is a trading platform that is used to trade."""

    platform = models.CharField(choices=PLATFORM_CHOICES, max_length=255)
    api_key = models.CharField(max_length=255)
    api_secret = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.get_platform_display()


class Telegram(models.Model):
    """A Telegram destination that a HookSet can notify when it executes (see NotificationTarget)."""

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    name = models.CharField(max_length=255)
    chat_id = models.CharField(max_length=64)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    def send(self, message):
        """Post `message` to this chat. Raises if it could not be delivered.

        Failures must propagate rather than be swallowed here: `HookSet.notify`
        counts a clean return as a delivery, and the owner is only charged for
        alerts that actually went out. Catching and logging in this method made
        every failure look like a success and billed for alerts nobody received.
        `notify` is the one place that catches, logs and counts.
        """
        token = settings.TELEGRAM_BOT_TOKEN
        if not token:
            raise RuntimeError(
                f"TELEGRAM_BOT_TOKEN is not configured; cannot alert {self.name}"
            )

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        body = json.dumps({"chat_id": self.chat_id, "text": message}).encode("utf-8")
        request = urllib.request.Request(
            url, data=body, headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(request, timeout=TELEGRAM_SEND_TIMEOUT_SECONDS)
