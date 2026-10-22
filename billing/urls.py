from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import (
    CreditPackViewSet,
    LedgerEntryListView,
    NowPaymentsIPNView,
    OrderViewSet,
    WalletView,
)

app_name = "billing"

router = DefaultRouter()
router.register(r"packs", CreditPackViewSet, basename="pack")
router.register(r"orders", OrderViewSet, basename="order")

urlpatterns = [
    path("wallet/", WalletView.as_view(), name="wallet"),
    path("ledger/", LedgerEntryListView.as_view(), name="ledger"),
    path("nowpayments/ipn/", NowPaymentsIPNView.as_view(), name="nowpayments-ipn"),
    path("", include(router.urls)),
]
