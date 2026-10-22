from datetime import time
from decimal import Decimal

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from model_bakery import baker

from billing import services
from billing.models import CreditPack, LedgerEntry, Order, Wallet
from billing.providers import NowPaymentsError, NowPaymentsProvider
from trader.models import HookSet

User = get_user_model()


@override_settings(FREE_EXECUTION_QUOTA=3)
class ConsumeExecutionTests(TestCase):
    """Tests for spending free quota and paid credits on executions."""

    def setUp(self):
        self.user = baker.make(User)

    def test_free_quota_is_spent_before_credits(self):
        """Test the three free executions are used before the paid balance."""
        wallet = services.get_wallet(self.user)
        wallet.balance = 5
        wallet.save()

        for expected_used in (1, 2, 3):
            result = services.consume_execution(self.user)
            self.assertTrue(result.charged)
            self.assertEqual(result.source, "free")
            wallet.refresh_from_db()
            self.assertEqual(wallet.free_executions_used, expected_used)
            self.assertEqual(wallet.balance, 5)

    def test_credits_are_spent_once_free_quota_is_exhausted(self):
        """Test the paid balance is debited after the free tier runs out."""
        wallet = services.get_wallet(self.user)
        wallet.balance = 2
        wallet.free_executions_used = 3
        wallet.save()

        result = services.consume_execution(self.user)

        self.assertTrue(result.charged)
        self.assertEqual(result.source, "credit")
        wallet.refresh_from_db()
        self.assertEqual(wallet.balance, 1)

    def test_consume_fails_when_out_of_free_quota_and_credits(self):
        """Test an empty wallet refuses to bill an execution."""
        wallet = services.get_wallet(self.user)
        wallet.free_executions_used = 3
        wallet.save()

        result = services.consume_execution(self.user)

        self.assertFalse(result.charged)
        self.assertEqual(result.source, "none")
        self.assertEqual(result.remaining, 0)

    def test_consumption_is_recorded_in_the_ledger(self):
        """Test free and paid executions both leave an audit trail."""
        # HookSet.timewindow is a TimeField with a timedelta default, so it has
        # to be set explicitly — same workaround the trader tests use.
        hookset = baker.make(HookSet, created_by=self.user, timewindow=time(1, 0, 0))
        wallet = services.get_wallet(self.user)
        wallet.balance = 1
        wallet.free_executions_used = 2
        wallet.save()

        services.consume_execution(self.user, hookset=hookset)  # last free one
        services.consume_execution(self.user, hookset=hookset)  # first paid one

        entries = list(LedgerEntry.objects.filter(wallet=wallet).order_by("id"))
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].reason, LedgerEntry.Reason.FREE_EXECUTION)
        self.assertEqual(entries[0].delta, 0)
        self.assertEqual(entries[1].reason, LedgerEntry.Reason.EXECUTION)
        self.assertEqual(entries[1].delta, -1)
        self.assertEqual(entries[1].balance_after, 0)
        self.assertEqual(entries[1].hookset, hookset)

    def test_total_available_sums_free_quota_and_balance(self):
        """Test the wallet reports free quota and credits as one spendable figure."""
        wallet = services.get_wallet(self.user)
        wallet.balance = 7
        wallet.free_executions_used = 1
        wallet.save()

        self.assertEqual(wallet.free_executions_remaining, 2)
        self.assertEqual(wallet.total_available, 9)


class CreditOrderTests(TestCase):
    """Tests for granting an order's credits exactly once."""

    def setUp(self):
        self.user = baker.make(User)
        self.pack = CreditPack.objects.get(credits=10)
        self.order = baker.make(
            Order,
            user=self.user,
            pack=self.pack,
            credits=10,
            price_usd=Decimal("8.45"),
            status=Order.Status.PENDING,
        )

    def test_credit_order_grants_credits_and_confirms(self):
        """Test a settled order tops up the balance and flips to confirmed."""
        granted = services.credit_order(self.order)

        self.assertTrue(granted)
        self.order.refresh_from_db()
        self.assertEqual(self.order.status, Order.Status.CONFIRMED)
        self.assertIsNotNone(self.order.credited_at)
        self.assertEqual(services.get_wallet(self.user).balance, 10)

    def test_credit_order_is_idempotent(self):
        """Test a repeated callback cannot grant the same credits twice."""
        self.assertTrue(services.credit_order(self.order))
        self.assertFalse(services.credit_order(self.order))

        self.assertEqual(services.get_wallet(self.user).balance, 10)
        self.assertEqual(
            LedgerEntry.objects.filter(reason=LedgerEntry.Reason.PURCHASE).count(), 1
        )


class ApplyIPNTests(TestCase):
    """Tests for folding a verified provider callback into an order."""

    def setUp(self):
        self.user = baker.make(User)
        self.order = baker.make(
            Order,
            user=self.user,
            credits=30,
            price_usd=Decimal("23.90"),
            status=Order.Status.PENDING,
        )

    def payload(self, payment_status, **extra):
        return {
            "order_id": str(self.order.uuid),
            "payment_status": payment_status,
            "payment_id": "123456789",
            "pay_currency": "usdttrc20",
            "pay_amount": "23.90",
            "actually_paid": "23.90",
            **extra,
        }

    def test_finished_payment_returns_a_fresh_order(self):
        """Test the returned order reflects the crediting, not a stale read."""
        returned = services.apply_ipn(self.payload("finished"))

        self.assertEqual(returned.status, Order.Status.CONFIRMED)
        self.assertIsNotNone(returned.credited_at)

    def test_finished_payment_credits_the_wallet(self):
        """Test 'finished' is the status that releases credits."""
        services.apply_ipn(self.payload("finished"))

        self.order.refresh_from_db()
        self.assertEqual(self.order.status, Order.Status.CONFIRMED)
        self.assertEqual(self.order.provider_payment_id, "123456789")
        self.assertEqual(self.order.pay_currency, "usdttrc20")
        self.assertEqual(services.get_wallet(self.user).balance, 30)

    def test_confirmed_payment_does_not_credit_yet(self):
        """Test 'confirmed' means chain-confirmed, not yet paid out."""
        services.apply_ipn(self.payload("confirmed"))

        self.order.refresh_from_db()
        self.assertIsNone(self.order.credited_at)
        self.assertEqual(services.get_wallet(self.user).balance, 0)

    def test_failed_payment_marks_the_order_failed(self):
        """Test a failed payment is recorded without granting credits."""
        services.apply_ipn(self.payload("failed"))

        self.order.refresh_from_db()
        self.assertEqual(self.order.status, Order.Status.FAILED)
        self.assertEqual(services.get_wallet(self.user).balance, 0)

    def test_late_callback_cannot_unsettle_a_credited_order(self):
        """Test an out-of-order 'expired' callback cannot revoke a paid order."""
        services.apply_ipn(self.payload("finished"))
        services.apply_ipn(self.payload("expired"))

        self.order.refresh_from_db()
        self.assertEqual(self.order.status, Order.Status.CONFIRMED)
        self.assertEqual(services.get_wallet(self.user).balance, 30)

    def test_duplicate_finished_callback_credits_once(self):
        """Test provider retries do not multiply the balance."""
        services.apply_ipn(self.payload("finished"))
        services.apply_ipn(self.payload("finished"))

        self.assertEqual(services.get_wallet(self.user).balance, 30)

    def test_unknown_order_id_is_ignored(self):
        """Test a callback for an order we don't have returns None, and warns."""
        with self.assertLogs("billing.services", level="WARNING") as logs:
            result = services.apply_ipn(
                {
                    "order_id": "00000000-0000-0000-0000-000000000000",
                    "payment_status": "finished",
                }
            )

        self.assertIsNone(result)
        self.assertIn("unknown order_id", logs.output[0])

    def test_malformed_order_id_is_ignored(self):
        """Test a non-UUID order_id reads as unknown instead of raising."""
        with self.assertLogs("billing.services", level="WARNING"):
            result = services.apply_ipn(
                {"order_id": "not-a-uuid", "payment_status": "finished"}
            )

        self.assertIsNone(result)


@override_settings(BILLING_PARTIAL_PAYMENT_TOLERANCE=Decimal("0.97"))
class PartialPaymentTests(TestCase):
    """Tests for underpayment — the common case when paying from an exchange.

    The ratio is always `actually_paid / pay_amount` in the invoice's crypto,
    never against the USD price.
    """

    def setUp(self):
        self.user = baker.make(User)
        self.order = baker.make(
            Order,
            user=self.user,
            credits=10,
            price_usd=Decimal("8.45"),
            pay_amount=Decimal("8.45"),
            pay_currency="usdttrc20",
            status=Order.Status.PENDING,
        )

    def ipn(self, actually_paid, payment_status="partially_paid"):
        return {
            "order_id": str(self.order.uuid),
            "payment_status": payment_status,
            "payment_id": "1",
            "pay_currency": "usdttrc20",
            "pay_amount": "8.45",
            "actually_paid": str(actually_paid),
        }

    def test_fee_sized_shortfall_counts_as_paid_in_full(self):
        """Test a 1% shortfall is absorbed rather than becoming a support ticket."""
        services.apply_ipn(self.ipn("8.37"))  # 99.1%

        self.order.refresh_from_db()
        self.assertEqual(self.order.status, Order.Status.CONFIRMED)
        self.assertEqual(self.order.credits_granted, 10)
        self.assertEqual(services.get_wallet(self.user).balance, 10)

    def test_shortfall_just_inside_the_tolerance_is_full(self):
        """Test the tolerance boundary is inclusive."""
        services.apply_ipn(self.ipn(Decimal("8.45") * Decimal("0.97")))

        self.assertEqual(services.get_wallet(self.user).balance, 10)

    def test_larger_shortfall_is_credited_proportionally(self):
        """Test paying 70% of the invoice earns 7 of 10 credits."""
        with self.assertLogs("billing.services", level="WARNING"):
            services.apply_ipn(self.ipn("5.915"))  # exactly 70%

        self.order.refresh_from_db()
        self.assertEqual(self.order.credits_granted, 7)
        self.assertEqual(self.order.status, Order.Status.PARTIALLY_PAID)
        self.assertEqual(services.get_wallet(self.user).balance, 7)

    def test_proportional_credit_rounds_down(self):
        """Test a part-credit is never rounded up in the customer's favour."""
        with self.assertLogs("billing.services", level="WARNING"):
            services.apply_ipn(self.ipn("6.76"))  # 80%

        self.order.refresh_from_db()
        self.assertEqual(self.order.credits_granted, 8)

    def test_topping_up_releases_only_the_remainder(self):
        """Test a later full payment grants the difference, not another full pack."""
        with self.assertLogs("billing.services", level="WARNING"):
            services.apply_ipn(self.ipn("5.915"))  # 70% -> 7 credits
        self.assertEqual(services.get_wallet(self.user).balance, 7)

        services.apply_ipn(self.ipn("8.45", payment_status="finished"))

        self.order.refresh_from_db()
        self.assertEqual(self.order.credits_granted, 10)
        self.assertEqual(self.order.status, Order.Status.CONFIRMED)
        self.assertEqual(services.get_wallet(self.user).balance, 10)

    def test_repeated_partial_callback_grants_once(self):
        """Test the provider repeating the same partial callback adds nothing."""
        with self.assertLogs("billing.services", level="WARNING"):
            services.apply_ipn(self.ipn("5.915"))
            services.apply_ipn(self.ipn("5.915"))

        self.assertEqual(services.get_wallet(self.user).balance, 7)
        self.assertEqual(
            LedgerEntry.objects.filter(reason=LedgerEntry.Reason.PURCHASE).count(), 1
        )

    def test_dust_payment_grants_nothing_but_is_recorded(self):
        """Test a payment too small for even one credit is flagged, not credited."""
        with self.assertLogs("billing.services", level="WARNING"):
            services.apply_ipn(self.ipn("0.10"))

        self.order.refresh_from_db()
        self.assertEqual(self.order.credits_granted, 0)
        self.assertEqual(self.order.status, Order.Status.PARTIALLY_PAID)
        self.assertEqual(self.order.actually_paid, Decimal("0.10"))
        self.assertEqual(services.get_wallet(self.user).balance, 0)

    def test_overpayment_never_grants_more_than_the_pack(self):
        """Test sending too much does not inflate the pack."""
        services.apply_ipn(self.ipn("20.00"))

        self.order.refresh_from_db()
        self.assertEqual(self.order.credits_granted, 10)
        self.assertEqual(services.get_wallet(self.user).balance, 10)

    def test_partial_without_an_invoice_amount_grants_nothing(self):
        """Test an unjudgeable payment is never guessed at."""
        self.order.pay_amount = None
        self.order.save()

        with self.assertLogs("billing.services", level="WARNING"):
            services.apply_ipn(
                {
                    "order_id": str(self.order.uuid),
                    "payment_status": "partially_paid",
                    "actually_paid": "5.00",
                }
            )

        self.assertEqual(services.get_wallet(self.user).balance, 0)

    def test_late_expiry_cannot_revoke_a_partial_grant(self):
        """Test credits already released survive a later failure callback."""
        with self.assertLogs("billing.services", level="WARNING"):
            services.apply_ipn(self.ipn("5.915"))
            services.apply_ipn(self.ipn("5.915", payment_status="expired"))

        self.order.refresh_from_db()
        self.assertEqual(self.order.status, Order.Status.PARTIALLY_PAID)
        self.assertEqual(services.get_wallet(self.user).balance, 7)


class CreditsOwedTests(TestCase):
    """Unit tests for the ratio maths."""

    def order(self, credits=10, pay_amount="8.45"):
        return Order(
            credits=credits,
            price_usd=Decimal("8.45"),
            pay_amount=Decimal(pay_amount) if pay_amount is not None else None,
        )

    def test_none_when_no_invoice_amount(self):
        """Test a missing pay_amount is unjudgeable rather than zero."""
        self.assertIsNone(services.credits_owed_for(self.order(pay_amount=None), 5))

    def test_none_when_nothing_paid_is_reported(self):
        """Test a missing actually_paid is unjudgeable."""
        self.assertIsNone(services.credits_owed_for(self.order(), None))

    def test_zero_for_a_zero_payment(self):
        """Test a zero payment earns nothing."""
        self.assertEqual(services.credits_owed_for(self.order(), Decimal("0")), 0)

    def test_exact_payment_earns_the_whole_pack(self):
        """Test paying the invoice earns every credit."""
        self.assertEqual(
            services.credits_owed_for(self.order(), Decimal("8.45")), 10
        )


class IPNSignatureTests(TestCase):
    """Tests for the HMAC-SHA512 signature that authenticates callbacks."""

    def setUp(self):
        self.provider = NowPaymentsProvider(
            api_key="key", ipn_secret="secret", sandbox=True
        )

    def signed(self, body):
        import hashlib
        import hmac
        import json

        canonical = json.dumps(json.loads(body), sort_keys=True, separators=(",", ":"))
        return hmac.new(
            b"secret", canonical.encode(), hashlib.sha512
        ).hexdigest()

    def test_valid_signature_accepted(self):
        """Test a correctly signed body passes verification."""
        body = b'{"payment_status": "finished", "order_id": "abc"}'
        self.assertTrue(self.provider.verify_ipn_signature(body, self.signed(body)))

    def test_signature_is_order_independent(self):
        """Test key order in the body does not change the signature."""
        body = b'{"order_id": "abc", "payment_status": "finished"}'
        other = b'{"payment_status": "finished", "order_id": "abc"}'
        self.assertTrue(self.provider.verify_ipn_signature(body, self.signed(other)))

    def test_tampered_body_rejected(self):
        """Test editing the body after signing invalidates the signature."""
        body = b'{"payment_status": "finished", "order_id": "abc"}'
        signature = self.signed(body)
        tampered = b'{"payment_status": "finished", "order_id": "xyz"}'
        self.assertFalse(self.provider.verify_ipn_signature(tampered, signature))

    def test_missing_signature_rejected(self):
        """Test an unsigned callback is refused."""
        body = b'{"payment_status": "finished"}'
        self.assertFalse(self.provider.verify_ipn_signature(body, ""))

    def test_unconfigured_secret_rejects_everything(self):
        """Test a provider with no IPN secret never accepts a callback."""
        provider = NowPaymentsProvider(api_key="key", ipn_secret="", sandbox=True)
        body = b'{"payment_status": "finished"}'
        self.assertFalse(provider.verify_ipn_signature(body, "whatever"))


class InvoiceConfigurationTests(TestCase):
    """Tests that an unusable configuration is refused before taking money."""

    def setUp(self):
        self.order = baker.make(
            Order, user=baker.make(User), credits=10, price_usd=Decimal("8.45")
        )

    def test_missing_api_key_is_refused(self):
        """Test no API key means no invoice."""
        provider = NowPaymentsProvider(api_key="", ipn_secret="s", sandbox=True)

        with self.assertRaises(NowPaymentsError):
            provider.create_invoice(
                self.order, "https://x/ok", "https://x/no", "https://x/ipn"
            )

    def test_missing_ipn_callback_url_is_refused(self):
        """Test an invoice is refused when no callback could ever credit it.

        Otherwise the customer pays, the IPN goes nowhere, and the credits
        silently never arrive.
        """
        provider = NowPaymentsProvider(api_key="key", ipn_secret="s", sandbox=True)

        with self.assertRaises(NowPaymentsError) as caught:
            provider.create_invoice(self.order, "https://x/ok", "https://x/no", "")

        self.assertIn("IPN_CALLBACK_URL", str(caught.exception))


class CreditPackTests(TestCase):
    """Tests for the seeded pricing curve."""

    def test_seeded_packs_have_a_declining_unit_price(self):
        """Test every larger pack is cheaper per credit than the one below it."""
        packs = list(CreditPack.objects.filter(is_active=True).order_by("credits"))

        self.assertGreaterEqual(len(packs), 2)
        unit_prices = [pack.unit_price_usd for pack in packs]
        self.assertEqual(unit_prices, sorted(unit_prices, reverse=True))

    def test_entry_pack_is_priced_as_agreed(self):
        """Test the 10-credit anchor pack is $8.45."""
        pack = CreditPack.objects.get(credits=10)
        self.assertEqual(pack.price_usd, Decimal("8.45"))
        self.assertEqual(pack.unit_price_usd, Decimal("0.8450"))
