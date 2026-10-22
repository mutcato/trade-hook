from django.contrib import admin

from .models import CreditPack, LedgerEntry, Order, Wallet


@admin.register(CreditPack)
class CreditPackAdmin(admin.ModelAdmin):
    list_display = ["credits", "price_usd", "unit_price_usd", "is_active", "sort_order"]
    list_editable = ["price_usd", "is_active", "sort_order"]
    ordering = ["sort_order", "credits"]


@admin.register(Wallet)
class WalletAdmin(admin.ModelAdmin):
    list_display = ["user", "balance", "free_executions_used", "updated_at"]
    search_fields = ["user__email"]
    # Balances move through billing.services so the ledger stays truthful;
    # editing them here would silently desync the audit trail.
    readonly_fields = ["user", "balance", "free_executions_used"]


@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    list_display = ["uuid", "user", "credits", "price_usd", "status", "credited_at", "created_at"]
    list_filter = ["status", "provider"]
    search_fields = ["uuid", "user__email", "provider_payment_id", "provider_invoice_id"]
    readonly_fields = ["uuid", "credited_at", "created_at", "updated_at"]


@admin.register(LedgerEntry)
class LedgerEntryAdmin(admin.ModelAdmin):
    list_display = ["created_at", "wallet", "delta", "balance_after", "reason", "hookset"]
    list_filter = ["reason"]
    search_fields = ["wallet__user__email"]
    # Append-only: the ledger is the audit trail, so nothing here is editable.
    readonly_fields = [field.name for field in LedgerEntry._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
