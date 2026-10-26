from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import (
    HookSetViewSet,
    HookViewSet,
    NotificationTargetLogViewSet,
    TelegramViewSet,
    TradeViewSet,
)

app_name = "trader"

router = DefaultRouter()
router.register(r"hooksets", HookSetViewSet, basename="hookset")
router.register(r"hooks", HookViewSet, basename="hook")
router.register(r"trades", TradeViewSet, basename="trade")
router.register(r"telegrams", TelegramViewSet, basename="telegram")
router.register(
    r"notification-logs", NotificationTargetLogViewSet, basename="notificationlog"
)

urlpatterns = [
    path("", include(router.urls)),
]
