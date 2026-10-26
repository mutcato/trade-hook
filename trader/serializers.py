from rest_framework import serializers

from authentication.serializers import UserSerializer

from .models import (
    Hook,
    HookSet,
    NotificationTarget,
    NotificationTargetLog,
    Telegram,
    Trade,
)


class OwnedPrimaryKeyRelatedField(serializers.PrimaryKeyRelatedField):
    """A related field that only resolves objects the requesting user owns.

    The ViewSets' `get_queryset()` filters what a user can *look up*, but it does
    not constrain an id sent as a related field on write. Without this, a user
    could attach their Hook/Trade to someone else's HookSet — stealing that
    owner's execution credits, or wedging their strategy permanently with a
    sibling hook the owner cannot see or delete — or point their own HookSet at
    another user's Telegram chat.
    """

    def get_queryset(self):
        queryset = super().get_queryset()
        request = self.context.get("request")
        if request is None or not request.user.is_authenticated:
            return queryset.none()
        return queryset.filter(created_by=request.user)


class TelegramCreateUpdateSerializer(serializers.ModelSerializer):
    created_by = serializers.HiddenField(default=serializers.CurrentUserDefault())

    class Meta:
        model = Telegram
        fields = ["id", "name", "chat_id", "created_by"]


class TelegramSerializer(serializers.ModelSerializer):
    created_by = UserSerializer(read_only=True)

    class Meta:
        model = Telegram
        fields = [
            "id",
            "uuid",
            "name",
            "chat_id",
            "created_by",
            "created_at",
            "updated_at",
        ]


class HookCreateUpdateSerializer(serializers.ModelSerializer):
    created_by = serializers.HiddenField(default=serializers.CurrentUserDefault())
    hookset = OwnedPrimaryKeyRelatedField(queryset=HookSet.objects.all())

    class Meta:
        model = Hook
        fields = ["id", "name", "hookset", "created_by"]


class HookSerializer(serializers.ModelSerializer):
    created_by = UserSerializer(read_only=True)

    class Meta:
        model = Hook
        fields = [
            "id",
            "uuid",
            "name",
            "hookset",
            "is_triggered",
            "triggered_at",
            "created_by",
            "created_at",
            "updated_at",
        ]


class HookSetCreateUpdateSerializer(serializers.ModelSerializer):
    """Accepts one write-only `*_ids` field per notification channel type.

    Each type gets its own explicit input field for a clear API contract, but they
    all funnel into the same generic `HookSet.set_notification_channels()` — adding
    Email later means adding one `email_ids` field here, not a new HookSet column.
    """

    created_by = serializers.HiddenField(default=serializers.CurrentUserDefault())
    telegram_ids = OwnedPrimaryKeyRelatedField(
        source="telegrams",
        many=True,
        queryset=Telegram.objects.all(),
        required=False,
        write_only=True,
    )

    class Meta:
        model = HookSet
        fields = ["id", "name", "timewindow", "telegram_ids", "created_by"]

    def create(self, validated_data):
        telegrams = validated_data.pop("telegrams", [])
        hookset = super().create(validated_data)
        hookset.set_notification_channels(telegrams)
        return hookset

    def update(self, instance, validated_data):
        telegrams = validated_data.pop("telegrams", None)
        hookset = super().update(instance, validated_data)
        if telegrams is not None:
            hookset.set_notification_channels(telegrams)
        return hookset


class NotificationTargetSerializer(serializers.ModelSerializer):
    """Per-channel delivery health, so a dead channel is visible to its owner.

    Derived from `NotificationTargetLog` rather than stored on the target. Every
    attempt is logged, so the newest row *is* the channel's current state and no
    separate resolution flag is needed.
    """

    name = serializers.SerializerMethodField()
    is_healthy = serializers.SerializerMethodField()
    failure_count = serializers.SerializerMethodField()
    last_error = serializers.SerializerMethodField()
    last_error_at = serializers.SerializerMethodField()
    last_status_code = serializers.SerializerMethodField()
    last_success_at = serializers.SerializerMethodField()

    class Meta:
        model = NotificationTarget
        fields = [
            "id",
            "name",
            "is_healthy",
            "failure_count",
            "last_error",
            "last_error_at",
            "last_status_code",
            "last_success_at",
        ]
        read_only_fields = fields

    def get_name(self, target):
        channel = target.channel
        return getattr(channel, "name", None)

    def _logs(self, target):
        """Newest first, per the log model's Meta.ordering."""
        return target.logs.all()

    def _latest(self, target):
        return next(iter(self._logs(target)), None)

    def get_is_healthy(self, target):
        """Healthy when the most recent attempt succeeded.

        A channel that has never fired counts as healthy too — nothing is wrong
        with it yet, and flagging it would cry wolf on every new strategy.
        """
        latest = self._latest(target)
        return latest is None or latest.success

    def get_failure_count(self, target):
        """Consecutive failures since the channel last worked."""
        count = 0
        for log in self._logs(target):
            if log.success:
                break
            count += 1
        return count

    def _latest_failure(self, target):
        latest = self._latest(target)
        return None if latest is None or latest.success else latest

    def get_last_error(self, target):
        log = self._latest_failure(target)
        return log.error if log else None

    def get_last_error_at(self, target):
        log = self._latest_failure(target)
        return log.created_at if log else None

    def get_last_status_code(self, target):
        """None when the failure never got as far as an HTTP response."""
        log = self._latest_failure(target)
        return log.status_code if log else None

    def get_last_success_at(self, target):
        """When an alert last actually reached this channel."""
        log = next((log for log in self._logs(target) if log.success), None)
        return log.created_at if log else None


class NotificationTargetLogSerializer(serializers.ModelSerializer):
    """One delivery attempt, flattened for a reverse-chronological feed."""

    channel = serializers.SerializerMethodField()
    strategy = serializers.SerializerMethodField()
    strategy_id = serializers.IntegerField(source="target.hookset_id", read_only=True)

    class Meta:
        model = NotificationTargetLog
        fields = [
            "id",
            "channel",
            "strategy",
            "strategy_id",
            "success",
            "error",
            "status_code",
            "created_at",
        ]
        read_only_fields = fields

    def get_channel(self, log):
        return getattr(log.target.channel, "name", None)

    def get_strategy(self, log):
        return log.target.hookset.name


class HookSetSerializer(serializers.ModelSerializer):
    created_by = UserSerializer(read_only=True)
    hooks = HookSerializer(many=True, read_only=True, source="hook_set")
    telegrams = serializers.SerializerMethodField()
    channels = NotificationTargetSerializer(
        many=True, read_only=True, source="notification_targets"
    )

    class Meta:
        model = HookSet
        fields = [
            "id",
            "name",
            "timewindow",
            "hooks",
            "telegrams",
            "channels",
            "created_by",
            "created_at",
            "updated_at",
        ]

    def get_telegrams(self, obj):
        channels = [
            target.channel
            for target in obj.notification_targets.select_related("content_type")
        ]
        telegrams = [c for c in channels if isinstance(c, Telegram)]
        return TelegramSerializer(telegrams, many=True, context=self.context).data


class TradeCreateUpdateSerializer(serializers.ModelSerializer):
    created_by = serializers.HiddenField(default=serializers.CurrentUserDefault())
    hookset = OwnedPrimaryKeyRelatedField(queryset=HookSet.objects.all())

    class Meta:
        model = Trade
        fields = ["id", "name", "pair", "action", "hookset", "created_by"]


class TradeSerializer(serializers.ModelSerializer):
    created_by = UserSerializer(read_only=True)
    hookset = HookSetSerializer(read_only=True)

    class Meta:
        model = Trade
        fields = [
            "id",
            "name",
            "pair",
            "action",
            "hookset",
            "is_triggered",
            "triggered_at",
            "created_by",
            "created_at",
            "updated_at",
        ]
