import logging
from datetime import timedelta

from django.conf import settings
from django.db.models import Q
from django.utils import timezone
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.pagination import CursorPagination
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from billing.exceptions import InsufficientCredits
from billing.services import consume_execution, has_available_executions

from .models import Hook, HookSet, NotificationTargetLog, Telegram, Trade
from .serializers import (
    HookCreateUpdateSerializer,
    HookSerializer,
    HookSetCreateUpdateSerializer,
    HookSetSerializer,
    NotificationTargetLogSerializer,
    TelegramCreateUpdateSerializer,
    TelegramSerializer,
    TradeCreateUpdateSerializer,
    TradeSerializer,
)

logger = logging.getLogger(__name__)


class HookSetViewSet(viewsets.ModelViewSet):
    queryset = HookSet.objects.all()

    def get_queryset(self):
        # The channel-health fields walk each target's logs, so prefetch
        # them rather than paying a query per channel per hookset.
        return self.queryset.filter(created_by=self.request.user).prefetch_related(
            "notification_targets__logs"
        )

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
            owner = hookset.created_by

            # Clear the set before delivering, not after. The next full round of
            # signals must start a fresh cycle instead of re-alerting on every
            # subsequent trigger, an unpaid cycle must not sit armed waiting for
            # the next top-up, and — critically — a delivery failure must not
            # leave the set armed: TradingView retries a 5xx three times, and
            # each retry would re-complete the set.
            Hook.objects.filter(hookset=hookset).update(
                is_triggered=False, triggered_at=None
            )

            # Deliver first, bill second: a credit is only spent once an alert
            # has actually reached somebody. Every branch answers 200 — a 4xx
            # would make TradingView drop the signal with no retry and no
            # report, so the owner would never learn anything went wrong.
            if not has_available_executions(owner):
                payload["reason"] = "insufficient_credits"
                logger.warning(
                    "HookSet %s completed but %s has no credits left; alert skipped",
                    hookset.uuid,
                    owner,
                )
            else:
                delivery = hookset.notify(f"{hookset.name} executed.")
                # Reported so a partial delivery is visible to whoever reads the
                # response: one credit buys the execution, not one copy per
                # channel, so delivered < channels still costs full price.
                payload["delivered"] = delivery.delivered
                payload["channels"] = delivery.total

                # Read `.delivered`, not the result's truthiness: a
                # (0 delivered, 2 channels) object would read as success and
                # bill for an alert nobody received.
                if not delivery.delivered:
                    # Nothing reached any channel, so nothing is charged.
                    payload["reason"] = "delivery_failed"
                    logger.warning(
                        "HookSet %s completed but no channel accepted the alert; "
                        "%s was not charged",
                        hookset.uuid,
                        owner,
                    )
                else:
                    consume_execution(owner, hookset=hookset)
                    payload["executed"] = True

        return Response(payload, status=status.HTTP_200_OK)


class NotificationLogPagination(CursorPagination):
    """Cursor, not page number.

    The log is append-only and ordered newest-first, so page numbers would drift
    as new attempts arrive while the user is paging. Applied to this view only —
    turning on global pagination would change every existing list endpoint from
    a bare array to a wrapped object and break the frontend.
    """

    page_size = 25
    ordering = "-created_at"


class NotificationTargetLogViewSet(viewsets.ReadOnlyModelViewSet):
    """The caller's own delivery attempts, newest first.

    Scoped through the target to the hookset's owner — the log has no `user` of
    its own, so this is what keeps one account's delivery history private.
    """

    serializer_class = NotificationTargetLogSerializer
    pagination_class = NotificationLogPagination
    queryset = NotificationTargetLog.objects.all()

    def get_queryset(self):
        queryset = self.queryset.filter(
            target__hookset__created_by=self.request.user
        ).select_related("target__hookset").prefetch_related("target__channel")

        # `?success=false` is the diagnostic view: just the failures.
        success = self.request.query_params.get("success")
        if success is not None:
            queryset = queryset.filter(success=success.lower() not in ("false", "0"))
        return queryset


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
