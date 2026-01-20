from datetime import timedelta
import uuid
from django.conf import settings
from django.db import models, transaction
from django.core.exceptions import ValidationError
from django.utils import timezone
# Create your models here.

class Hook(models.Model):
    """A hook is a webhook that is used to receive data from the trading platform."""

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    name = models.CharField(max_length=255)
    hook_set = models.ForeignKey("HookSet", on_delete=models.CASCADE)
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



ACTION_CHOICES = [
    ("LONG", "Long"),
    ("SHORT", "Short"),
]

class Trade(models.Model):
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    name = models.CharField(max_length=255)
    pair = models.CharField(max_length=10)
    action = models.CharField(max_length=10, choices=ACTION_CHOICES)
    hookset = models.ForeignKey("HookSet", on_delete=models.CASCADE, related_name='trades')
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
            raise ValidationError("Invalid pair. Must be in the format of 'asset1/asset2'.")

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