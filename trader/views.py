from datetime import timedelta

from django.db.models import Q
from django.utils import timezone
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from .models import Hook, HookSet, Trade
from .serializers import (
    HookCreateUpdateSerializer,
    HookSerializer,
    HookSetCreateUpdateSerializer,
    HookSetSerializer,
    TradeCreateUpdateSerializer,
    TradeSerializer,
)


class HookSetViewSet(viewsets.ModelViewSet):
    queryset = HookSet.objects.all()

    def get_serializer_class(self):
        if self.action in ["create", "update", "partial_update"]:
            return HookSetCreateUpdateSerializer
        return HookSetSerializer


class HookViewSet(viewsets.ModelViewSet):
    queryset = Hook.objects.select_related("hookset")

    def get_serializer_class(self):
        if self.action in ["create", "update", "partial_update"]:
            return HookCreateUpdateSerializer
        return HookSerializer

    @action(detail=True, methods=["post"])
    def trigger(self, request, pk=None):
        hook = self.get_object()
        hook.trigger()

        # Convert TimeField to timedelta for comparison
        timewindow = hook.hookset.timewindow
        window_delta = timedelta(
            hours=timewindow.hour, minutes=timewindow.minute, seconds=timewindow.second
        )
        cutoff_time = timezone.now() - window_delta

        # Check if any sibling hook is not triggered or expired (using ORM)
        invalid_sibling = (
            Hook.objects.filter(hookset=hook.hookset)
            .exclude(id=hook.id)
            .filter(Q(is_triggered=False) | Q(triggered_at__lt=cutoff_time))
        )

        # If all siblings are valid, bulk trigger untriggered trades
        if not invalid_sibling.exists():
            trades = Trade.objects.filter(hookset=hook.hookset, is_triggered=False)
            for trade in trades:
                trade.trigger()

        return Response(
            {"detail": "Hook triggered successfully"}, status=status.HTTP_200_OK
        )


class TradeViewSet(viewsets.ModelViewSet):
    queryset = Trade.objects.all()

    def get_serializer_class(self):
        if self.action in ["create", "update", "partial_update"]:
            return TradeCreateUpdateSerializer
        return TradeSerializer
