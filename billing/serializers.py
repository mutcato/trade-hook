from django.conf import settings
from rest_framework import serializers

from .models import CreditPack, LedgerEntry, Order, Wallet


class CreditPackSerializer(serializers.ModelSerializer):
    unit_price_usd = serializers.DecimalField(
        max_digits=10, decimal_places=4, read_only=True
    )
    discount_percent = serializers.SerializerMethodField()

    class Meta:
        model = CreditPack
        fields = ["id", "credits", "price_usd", "unit_price_usd", "discount_percent"]

    def get_discount_percent(self, pack):
        """Saving per credit against the smallest pack, which is the list price."""
        baseline = self.context.get("baseline_unit_price")
        if not baseline or pack.unit_price_usd >= baseline:
            return 0
        return int(round((1 - pack.unit_price_usd / baseline) * 100))


class WalletSerializer(serializers.ModelSerializer):
    free_executions_remaining = serializers.IntegerField(read_only=True)
    total_available = serializers.IntegerField(read_only=True)
    free_quota = serializers.SerializerMethodField()

    class Meta:
        model = Wallet
        fields = [
            "balance",
            "free_executions_used",
            "free_executions_remaining",
            "total_available",
            "free_quota",
        ]

    def get_free_quota(self, wallet):
        return settings.FREE_EXECUTION_QUOTA


class OrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Order
        fields = [
            "uuid",
            "credits",
            "price_usd",
            "status",
            "invoice_url",
            "pay_currency",
            "pay_amount",
            "actually_paid",
            "created_at",
            "credited_at",
        ]
        read_only_fields = fields


class OrderCreateSerializer(serializers.Serializer):
    """Write side of order creation — the client only picks a pack."""

    pack = serializers.PrimaryKeyRelatedField(
        queryset=CreditPack.objects.filter(is_active=True)
    )


class LedgerEntrySerializer(serializers.ModelSerializer):
    hookset_name = serializers.CharField(source="hookset.name", default=None, read_only=True)

    class Meta:
        model = LedgerEntry
        fields = [
            "id",
            "delta",
            "balance_after",
            "reason",
            "note",
            "hookset_name",
            "created_at",
        ]
        read_only_fields = fields
