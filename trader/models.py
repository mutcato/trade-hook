import json
import logging
import urllib.error
import urllib.request
import uuid
from datetime import timedelta

from django.conf import settings
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.utils import timezone

logger = logging.getLogger(__name__)

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
        return self.uuid

    def trigger(self):
        self.is_triggered = True
        self.triggered_at = timezone.now()
        self.save()


class HookSet(models.Model):
    """A hook set is a set of hooks that are used to receive data from the trading platform."""

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    name = models.CharField(max_length=255)
    timewindow = models.TimeField(default=timedelta(hours=1))
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
        for target in self.notification_targets.select_related("content_type"):
            channel = target.channel
            if channel is not None:
                channel.send(message)


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

        if assets[0].isalpha() or assets[1].isalpha():
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
        return self.name


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
        token = settings.TELEGRAM_BOT_TOKEN
        if not token:
            logger.warning(
                "TELEGRAM_BOT_TOKEN is not configured; skipping alert to %s", self.name
            )
            return

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        body = json.dumps({"chat_id": self.chat_id, "text": message}).encode("utf-8")
        request = urllib.request.Request(
            url, data=body, headers={"Content-Type": "application/json"}
        )
        try:
            urllib.request.urlopen(request, timeout=10)
        except urllib.error.URLError:
            logger.exception("Failed to send Telegram alert to %s (%s)", self.name, self.chat_id)
