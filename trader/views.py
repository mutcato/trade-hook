from datetime import datetime, timedelta

from django.db.models import Q
from django.utils import timezone
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from .models import HookSet, Hook, Trade
from .serializers import (
    HookSetSerializer,
    HookSetCreateUpdateSerializer,
    HookSerializer,
    HookCreateUpdateSerializer,
    TradeSerializer,
    TradeCreateUpdateSerializer,
)


class HookSetViewSet(viewsets.ModelViewSet):
    queryset = HookSet.objects.all()

    def get_serializer_class(self):
        if self.action in ['create', 'update', 'partial_update']:
            return HookSetCreateUpdateSerializer
        return HookSetSerializer


class HookViewSet(viewsets.ModelViewSet):
    queryset = Hook.objects.select_related('hook_set')

    def get_serializer_class(self):
        if self.action in ['create', 'update', 'partial_update']:
            return HookCreateUpdateSerializer
        return HookSerializer

    @action(detail=True, methods=['post'])
    def trigger(self, request, pk=None):
        hook = self.get_object()
        hook.trigger()

        # Convert TimeField to timedelta for comparison
        timewindow = hook.hook_set.timewindow
        window_delta = timedelta(
            hours=timewindow.hour,
            minutes=timewindow.minute,
            seconds=timewindow.second
        )
        cutoff_time = timezone.now() - window_delta

        # Check if any sibling hook is not triggered or expired (using ORM)
        invalid_sibling = Hook.objects.filter(
            hook_set=hook.hook_set
        ).exclude(
            id=hook.id
        ).filter(
            Q(is_triggered=False) | Q(triggered_at__lt=cutoff_time)
        )

        # If all siblings are valid, bulk trigger untriggered trades
        if not invalid_sibling.exists():
            now = timezone.now()
            trades = Trade.objects.filter(
                hookset=hook.hook_set,
                is_triggered=False
            )
            for trade in trades:
                trade.trigger()

        return Response({'detail': 'Hook triggered successfully'}, status=status.HTTP_200_OK)

class TradeViewSet(viewsets.ModelViewSet):
    queryset = Trade.objects.all()

    def get_serializer_class(self):
        if self.action in ['create', 'update', 'partial_update']:
            return TradeCreateUpdateSerializer
        return TradeSerializer
