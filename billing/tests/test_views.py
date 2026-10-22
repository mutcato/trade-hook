import hashlib
import hmac
import json
from decimal import Decimal
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import override_settings
from django.urls import reverse
from model_bakery import baker
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken

from billing import services
from billing.models import CreditPack, LedgerEntry, Order
from billing.providers import NowPaymentsError, NowPaymentsProvider

User = get_user_model()

IPN_SECRET = "test-ipn-secret"


class AuthenticatedAPITestCase(APITestCase):
    """Shared auth setup — mirrors the trader test suite's token pattern."""

    @classmethod
    def setUpTestData(cls):
        cls.user = baker.make(User)
        cls.other_user = baker.make(User)

    def setUp(self):
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")


class CreditPackViewTests(AuthenticatedAPITestCase):
    """Tests for the top-up menu endpoint."""

    def test_list_packs(self):
        """Test the seeded packs are listed with per-credit pricing."""
        response = self.client.get(reverse("billing:pack-list"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data), 2)
        for field in ["id", "credits", "price_usd", "unit_price_usd", "discount_percent"]:
            self.assertIn(field, response.data[0])

    def test_discount_percent_is_zero_for_the_entry_pack(self):
        """Test the smallest pack is the baseline every discount is measured from."""
        response = self.client.get(reverse("billing:pack-list"))

        by_credits = {pack["credits"]: pack for pack in response.data}
        self.assertEqual(by_credits[10]["discount_percent"], 0)
        self.assertGreater(by_credits[500]["discount_percent"], 0)

    def test_inactive_packs_are_hidden(self):
        """Test a deactivated pack drops off the menu."""
        CreditPack.objects.filter(credits=10).update(is_active=False)

        response = self.client.get(reverse("billing:pack-list"))

        self.assertNotIn(10, [pack["credits"] for pack in response.data])

    def test_packs_require_authentication(self):
        """Test the menu is not public."""
        self.client.credentials()
        response = self.client.get(reverse("billing:pack-list"))

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


@override_settings(FREE_EXECUTION_QUOTA=3)
class WalletViewTests(AuthenticatedAPITestCase):
    """Tests for the caller's balance endpoint."""

    def test_wallet_is_created_on_first_read(self):
        """Test a user with no wallet row still gets a zeroed wallet back."""
        response = self.client.get(reverse("billing:wallet"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["balance"], 0)
        self.assertEqual(response.data["free_executions_remaining"], 3)
        self.assertEqual(response.data["free_quota"], 3)
        self.assertEqual(response.data["total_available"], 3)

    def test_wallet_reflects_consumption(self):
        """Test spending shows up on the endpoint."""
        services.consume_execution(self.user)

        response = self.client.get(reverse("billing:wallet"))

        self.assertEqual(response.data["free_executions_used"], 1)
        self.assertEqual(response.data["free_executions_remaining"], 2)

    def test_wallet_requires_authentication(self):
        """Test the balance is not public."""
        self.client.credentials()
        response = self.client.get(reverse("billing:wallet"))

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class OrderViewTests(AuthenticatedAPITestCase):
    """Tests for opening and listing top-up orders."""

    def setUp(self):
        super().setUp()
        self.pack = CreditPack.objects.get(credits=10)
        self.list_url = reverse("billing:order-list")

    def test_create_order_returns_an_invoice_url(self):
        """Test ordering a pack opens a provider invoice the client can redirect to."""
        invoice = {"id": "4942455206", "invoice_url": "https://nowpayments.io/payment/?iid=4942455206"}

        with patch.object(
            NowPaymentsProvider, "create_invoice", return_value=invoice
        ) as create_invoice:
            response = self.client.post(self.list_url, {"pack": self.pack.pk})

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        create_invoice.assert_called_once()
        self.assertEqual(response.data["invoice_url"], invoice["invoice_url"])
        self.assertEqual(response.data["credits"], 10)
        self.assertEqual(response.data["status"], Order.Status.PENDING)

        order = Order.objects.get(uuid=response.data["uuid"])
        self.assertEqual(order.user, self.user)
        self.assertEqual(order.provider_invoice_id, "4942455206")
        self.assertIsNone(order.credited_at)

    def test_create_order_snapshots_the_price(self):
        """Test later pricing changes do not rewrite an existing order."""
        invoice = {"id": "1", "invoice_url": "https://example.com/pay"}

        with patch.object(NowPaymentsProvider, "create_invoice", return_value=invoice):
            response = self.client.post(self.list_url, {"pack": self.pack.pk})

        order = Order.objects.get(uuid=response.data["uuid"])
        self.pack.price_usd = Decimal("99.00")
        self.pack.save()
        order.refresh_from_db()

        self.assertEqual(order.price_usd, Decimal("8.45"))

    def test_provider_failure_returns_502(self):
        """Test an unreachable provider surfaces as a gateway error, not a 500."""
        with patch.object(
            NowPaymentsProvider,
            "create_invoice",
            side_effect=NowPaymentsError("NOWPayments is unreachable"),
        ), self.assertLogs("billing.views", level="ERROR") as logs:
            response = self.client.post(self.list_url, {"pack": self.pack.pk})

        self.assertIn("Could not open a NOWPayments invoice", logs.output[0])
        self.assertEqual(response.status_code, status.HTTP_502_BAD_GATEWAY)
        # No unpayable order may be left behind when the provider is down.
        self.assertFalse(Order.objects.filter(user=self.user).exists())

    def test_create_order_rejects_an_inactive_pack(self):
        """Test a deactivated pack cannot be ordered."""
        self.pack.is_active = False
        self.pack.save()

        response = self.client.post(self.list_url, {"pack": self.pack.pk})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_orders_are_scoped_to_the_caller(self):
        """Test another user's orders are not listed."""
        baker.make(Order, user=self.other_user, credits=10, price_usd=Decimal("8.45"))
        mine = baker.make(Order, user=self.user, credits=10, price_usd=Decimal("8.45"))

        response = self.client.get(self.list_url)

        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["uuid"], str(mine.uuid))

    def test_cannot_retrieve_another_users_order(self):
        """Test someone else's order is invisible."""
        theirs = baker.make(
            Order, user=self.other_user, credits=10, price_usd=Decimal("8.45")
        )

        response = self.client.get(
            reverse("billing:order-detail", kwargs={"uuid": theirs.uuid})
        )

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


@override_settings(NOWPAYMENTS_IPN_SECRET=IPN_SECRET)
class NowPaymentsIPNViewTests(APITestCase):
    """Tests for the provider callback endpoint."""

    def setUp(self):
        self.user = baker.make(User)
        self.order = baker.make(
            Order, user=self.user, credits=10, price_usd=Decimal("8.45")
        )
        self.url = reverse("billing:nowpayments-ipn")

    def post_ipn(self, payload, signature=None):
        body = json.dumps(payload)
        if signature is None:
            canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            signature = hmac.new(
                IPN_SECRET.encode(), canonical.encode(), hashlib.sha512
            ).hexdigest()
        return self.client.post(
            self.url,
            data=body,
            content_type="application/json",
            HTTP_X_NOWPAYMENTS_SIG=signature,
        )

    def test_valid_finished_callback_credits_the_wallet(self):
        """Test a signed 'finished' callback tops the user up."""
        response = self.post_ipn(
            {"order_id": str(self.order.uuid), "payment_status": "finished"}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(services.get_wallet(self.user).balance, 10)

    def test_callback_needs_no_authentication(self):
        """Test the provider, which has no account, is not asked for a token."""
        self.client.credentials()
        response = self.post_ipn(
            {"order_id": str(self.order.uuid), "payment_status": "finished"}
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_bad_signature_is_rejected_and_grants_nothing(self):
        """Test a forged callback cannot mint credits, and is logged."""
        with self.assertLogs("billing.views", level="WARNING") as logs:
            response = self.post_ipn(
                {"order_id": str(self.order.uuid), "payment_status": "finished"},
                signature="deadbeef",
            )

        self.assertIn("bad signature", logs.output[0])
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(services.get_wallet(self.user).balance, 0)
        self.order.refresh_from_db()
        self.assertIsNone(self.order.credited_at)

    def test_missing_signature_is_rejected(self):
        """Test an unsigned callback is refused."""
        with self.assertLogs("billing.views", level="WARNING"):
            response = self.client.post(
                self.url,
                data=json.dumps(
                    {"order_id": str(self.order.uuid), "payment_status": "finished"}
                ),
                content_type="application/json",
            )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(services.get_wallet(self.user).balance, 0)

    def test_duplicate_callback_credits_once(self):
        """Test provider retries are idempotent end to end."""
        payload = {"order_id": str(self.order.uuid), "payment_status": "finished"}
        self.post_ipn(payload)
        self.post_ipn(payload)

        self.assertEqual(services.get_wallet(self.user).balance, 10)
        self.assertEqual(
            LedgerEntry.objects.filter(reason=LedgerEntry.Reason.PURCHASE).count(), 1
        )

    def test_unknown_order_returns_200_to_stop_retries(self):
        """Test an unmatchable callback is acknowledged rather than retried forever."""
        with self.assertLogs("billing.services", level="WARNING"):
            response = self.post_ipn(
                {
                    "order_id": "00000000-0000-0000-0000-000000000000",
                    "payment_status": "finished",
                }
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK)


class LedgerViewTests(AuthenticatedAPITestCase):
    """Tests for the credit history endpoint."""

    def test_ledger_is_scoped_to_the_caller(self):
        """Test another user's credit history is not visible."""
        services.consume_execution(self.user)
        services.consume_execution(self.other_user)

        response = self.client.get(reverse("billing:ledger"))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["reason"], LedgerEntry.Reason.FREE_EXECUTION)

    def test_ledger_requires_authentication(self):
        """Test credit history is not public."""
        self.client.credentials()
        response = self.client.get(reverse("billing:ledger"))

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
