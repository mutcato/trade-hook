import logging

from rest_framework import mixins, status, viewsets
from rest_framework.generics import ListAPIView, RetrieveAPIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from . import services
from .models import CreditPack, LedgerEntry, Order
from .providers import NowPaymentsError, NowPaymentsProvider
from .serializers import (
    CreditPackSerializer,
    LedgerEntrySerializer,
    OrderCreateSerializer,
    OrderSerializer,
    WalletSerializer,
)

logger = logging.getLogger(__name__)


class CreditPackViewSet(viewsets.ReadOnlyModelViewSet):
    """The top-up menu. Read-only — pricing is changed in the admin."""

    serializer_class = CreditPackSerializer
    queryset = CreditPack.objects.filter(is_active=True)

    def get_serializer_context(self):
        context = super().get_serializer_context()
        packs = list(self.get_queryset())
        # The smallest pack is the list price every discount is measured against.
        baseline = min(packs, key=lambda pack: pack.credits) if packs else None
        context["baseline_unit_price"] = baseline.unit_price_usd if baseline else None
        return context


class WalletView(RetrieveAPIView):
    """The caller's own balance and remaining free executions."""

    serializer_class = WalletSerializer

    def get_object(self):
        return services.get_wallet(self.request.user)


class OrderViewSet(
    mixins.CreateModelMixin,
    mixins.RetrieveModelMixin,
    mixins.ListModelMixin,
    viewsets.GenericViewSet,
):
    """Top-up orders, always scoped to the caller."""

    serializer_class = OrderSerializer
    lookup_field = "uuid"

    def get_queryset(self):
        return Order.objects.filter(user=self.request.user)

    def create(self, request, *args, **kwargs):
        serializer = OrderCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            order = services.create_order(
                request.user, serializer.validated_data["pack"]
            )
        except NowPaymentsError as exc:
            logger.exception("Could not open a NOWPayments invoice")
            return Response(
                {"detail": str(exc)}, status=status.HTTP_502_BAD_GATEWAY
            )

        return Response(
            OrderSerializer(order).data, status=status.HTTP_201_CREATED
        )


class LedgerEntryListView(ListAPIView):
    """Credit history for the caller."""

    serializer_class = LedgerEntrySerializer

    def get_queryset(self):
        return LedgerEntry.objects.filter(
            wallet__user=self.request.user
        ).select_related("hookset")


class NowPaymentsIPNView(APIView):
    """Provider callback — authenticated by HMAC signature, not by a token.

    Mirrors the public-webhook shape already used by `trader.HookViewSet.trigger`:
    it opts out of the project-wide IsAuthenticated default because the caller is
    a machine with no account. Here the credential is the `x-nowpayments-sig`
    header over the raw body.
    """

    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        signature = request.headers.get("x-nowpayments-sig", "")
        provider = NowPaymentsProvider()

        if not provider.verify_ipn_signature(request.body, signature):
            logger.warning("Rejected NOWPayments IPN with a bad signature")
            return Response(
                {"detail": "Invalid signature"}, status=status.HTTP_400_BAD_REQUEST
            )

        order = services.apply_ipn(request.data, provider=provider)
        if order is None:
            # 200 so the provider stops retrying a callback we can never match.
            return Response({"detail": "Unknown order"}, status=status.HTTP_200_OK)

        return Response({"detail": "Processed"}, status=status.HTTP_200_OK)
