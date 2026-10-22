import logging
from datetime import timedelta

from django.conf import settings
from django.db.models import Q
from django.utils import timezone
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from billing.exceptions import InsufficientCredits
from billing.services import consume_execution, has_available_executions

from .models import Hook, HookSet, Telegram, Trade
from .serializers import (
    HookCreateUpdateSerializer,
    HookSerializer,
    HookSetCreateUpdateSerializer,
    HookSetSerializer,
    TelegramCreateUpdateSerializer,
    TelegramSerializer,
    TradeCreateUpdateSerializer,
    TradeSerializer,
)

logger = logging.getLogger(__name__)


class HookSetViewSet(viewsets.ModelViewSet):
    queryset = HookSet.objects.all()

    def get_queryset(self):
        return self.queryset.filter(created_by=self.request.user)

    def perform_create(self, serializer):
        # A strategy with nothing left to pay for its executions could never
        # fire, so refuse to create it and let the client send the user to a
        # top-up instead of silently building something inert.
        if not has_available_executions(self.request.user):
            raise InsufficientCredits()
        serializer.save()

    def get_serializer_class(self):
        if self.action in ["create", "update", "partial_update"]:
            return HookSetCreateUpdateSerializer
        return HookSetSerializer


class HookViewSet(viewsets.ModelViewSet):
    queryset = Hook.objects.select_related("hookset")
    lookup_field = "uuid"

    def get_queryset(self):
        if self.action == "trigger":
            # The public webhook has no request.user — the unguessable UUID is
            # the credential, so this action is deliberately unscoped.
            return self.queryset
        return self.queryset.filter(created_by=self.request.user)

    def get_serializer_class(self):
        if self.action in ["create", "update", "partial_update"]:
            return HookCreateUpdateSerializer
        return HookSerializer

    @action(
        detail=True,
        methods=["post"],
        permission_classes=[AllowAny],
        authentication_classes=[],
    )
    def trigger(self, request, uuid=None):
        """Public webhook endpoint — the unguessable UUID in the URL is the credential.

        External signal sources (TradingView et al.) call this with no auth header,
        so it opts out of the project-wide IsAuthenticated default.
        """
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

        # A completed set is the billable event: one execution costs one credit,
        # charged to the owner of the set rather than to whoever called the hook.
        payload = {"detail": "Hook triggered successfully", "executed": False}

        if not invalid_sibling.exists():
            hookset = hook.hookset
            result = consume_execution(hookset.created_by, hookset=hookset)

            if result.charged:
                hookset.notify(f"{hookset.name} triggered.")
                payload["executed"] = True
            else:
                # Stay on 200: the caller is an external signal source that would
                # disable the webhook on an error status, and the account problem
                # is the owner's to fix, not the caller's.
                payload["reason"] = "insufficient_credits"
                logger.warning(
                    "HookSet %s completed but %s has no credits left; alert skipped",
                    hookset.uuid,
                    hookset.created_by,
                )

            # Clear the set either way so the next full round of signals starts a
            # fresh cycle instead of re-alerting on every subsequent trigger — and
            # so an unpaid cycle cannot sit armed and fire on the next top-up.
            Hook.objects.filter(hookset=hookset).update(
                is_triggered=False, triggered_at=None
            )

        return Response(payload, status=status.HTTP_200_OK)


class TradeViewSet(viewsets.ModelViewSet):
    queryset = Trade.objects.all()

    def get_queryset(self):
        return self.queryset.filter(created_by=self.request.user)

    def get_serializer_class(self):
        if self.action in ["create", "update", "partial_update"]:
            return TradeCreateUpdateSerializer
        return TradeSerializer


class TelegramViewSet(viewsets.ModelViewSet):
    queryset = Telegram.objects.all()

    def get_queryset(self):
        return self.queryset.filter(created_by=self.request.user)

    def get_serializer_class(self):
        if self.action in ["create", "update", "partial_update"]:
            return TelegramCreateUpdateSerializer
        return TelegramSerializer

    @action(detail=False, methods=["get"])
    def bot_info(self, request):
        bot_name = settings.TELEGRAM_BOT_NAME
        return Response(
            {
                "bot_name": bot_name,
                "bot_url": f"https://t.me/{bot_name}" if bot_name else None,
            }
        )
