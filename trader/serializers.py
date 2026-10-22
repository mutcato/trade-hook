from rest_framework import serializers

from authentication.serializers import UserSerializer

from .models import Hook, HookSet, Telegram, Trade


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


class HookSetSerializer(serializers.ModelSerializer):
    created_by = UserSerializer(read_only=True)
    hooks = HookSerializer(many=True, read_only=True, source="hook_set")
    telegrams = serializers.SerializerMethodField()

    class Meta:
        model = HookSet
        fields = [
            "id",
            "name",
            "timewindow",
            "hooks",
            "telegrams",
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
