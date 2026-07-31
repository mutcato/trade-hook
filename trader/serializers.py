from rest_framework import serializers

from authentication.serializers import UserSerializer

from .models import Hook, HookSet, Trade


class HookCreateUpdateSerializer(serializers.ModelSerializer):
    created_by = serializers.HiddenField(default=serializers.CurrentUserDefault())

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
    created_by = serializers.HiddenField(default=serializers.CurrentUserDefault())

    class Meta:
        model = HookSet
        fields = ["id", "name", "timewindow", "created_by"]


class HookSetSerializer(serializers.ModelSerializer):
    created_by = UserSerializer(read_only=True)
    hooks = HookSerializer(many=True, read_only=True, source="hook_set")

    class Meta:
        model = HookSet
        fields = [
            "id",
            "name",
            "timewindow",
            "hooks",
            "created_by",
            "created_at",
            "updated_at",
        ]


class TradeCreateUpdateSerializer(serializers.ModelSerializer):
    created_by = serializers.HiddenField(default=serializers.CurrentUserDefault())

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
