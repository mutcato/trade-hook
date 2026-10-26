from datetime import time, timedelta
from unittest.mock import patch
from urllib.error import HTTPError

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from model_bakery import baker
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken
from trader.models import (
    Hook,
    HookSet,
    NotificationTarget,
    NotificationTargetLog,
    Telegram,
    Trade,
)
from billing.models import LedgerEntry
from billing.services import get_wallet


User = get_user_model()

# Default timewindow value for HookSet
DEFAULT_TIMEWINDOW = time(1, 0, 0)


class HookSetViewSetTests(APITestCase):
    """Tests for HookSet API endpoints."""

    @classmethod
    def setUpTestData(cls):
        cls.user = baker.make(User)
        cls.other_user = baker.make(User)
        cls.hookset = baker.make(
            HookSet,
            name="Test HookSet",
            timewindow=DEFAULT_TIMEWINDOW,
            created_by=cls.user,
        )
        cls.other_hookset = baker.make(
            HookSet,
            timewindow=DEFAULT_TIMEWINDOW,
            created_by=cls.other_user,
        )
        cls.list_url = reverse("trader:hookset-list")
        cls.detail_url = reverse("trader:hookset-detail", kwargs={"pk": cls.hookset.pk})

    def setUp(self):
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")

    def test_list_hooksets(self):
        """Test listing hooksets returns only the caller's own."""
        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["id"], self.hookset.pk)

    def test_cannot_retrieve_another_users_hookset(self):
        """Another user's hookset must be invisible, not merely uneditable."""
        url = reverse("trader:hookset-detail", kwargs={"pk": self.other_hookset.pk})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_cannot_delete_another_users_hookset(self):
        """Test that deleting someone else's hookset is not possible."""
        url = reverse("trader:hookset-detail", kwargs={"pk": self.other_hookset.pk})
        response = self.client.delete(url)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertTrue(HookSet.objects.filter(pk=self.other_hookset.pk).exists())

    def test_list_hooksets_unauthenticated(self):
        """Test listing hooksets requires authentication."""
        self.client.credentials()
        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_retrieve_hookset(self):
        """Test retrieving a single hookset with all serializer fields matching model."""
        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Check all HookSetSerializer fields exist
        expected_fields = [
            "id",
            "name",
            "timewindow",
            "created_by",
            "created_at",
            "updated_at",
        ]
        for field in expected_fields:
            self.assertIn(
                field, response.data, f"Field '{field}' not found in response"
            )
        # Verify all field values match model
        self.assertEqual(response.data["id"], self.hookset.pk)
        self.assertEqual(response.data["name"], self.hookset.name)
        self.assertEqual(
            response.data["timewindow"], self.hookset.timewindow.strftime("%H:%M:%S")
        )
        self.assertEqual(response.data["created_by"]["id"], self.hookset.created_by.pk)
        self.assertEqual(
            response.data["created_at"],
            self.hookset.created_at.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
        )
        self.assertEqual(
            response.data["updated_at"],
            self.hookset.updated_at.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
        )

    def test_create_hookset(self):
        """Test creating a new hookset."""
        data = {
            "name": "New HookSet",
            "timewindow": "02:00:00",
        }
        response = self.client.post(self.list_url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["name"], "New HookSet")
        self.assertTrue(HookSet.objects.filter(name="New HookSet").exists())

    def test_create_hookset_empty_data(self):
        """Test creating a hookset with empty data fails."""
        response = self.client.post(self.list_url, {})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_hookset_put(self):
        """Test full update of hookset."""
        data = {
            "name": "Updated HookSet",
            "timewindow": "03:00:00",
        }
        response = self.client.put(self.detail_url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.hookset.refresh_from_db()
        self.assertEqual(self.hookset.name, "Updated HookSet")

    def test_update_hookset_patch(self):
        """Test partial update of hookset."""
        data = {"name": "Patched HookSet"}
        response = self.client.patch(self.detail_url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.hookset.refresh_from_db()
        self.assertEqual(self.hookset.name, "Patched HookSet")

    def test_delete_hookset(self):
        """Test deleting a hookset."""
        response = self.client.delete(self.detail_url)

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(HookSet.objects.filter(pk=self.hookset.pk).exists())

    def test_retrieve_nonexistent_hookset(self):
        """Test retrieving a non-existent hookset returns 404."""
        url = reverse("trader:hookset-detail", kwargs={"pk": 99999})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_post_to_detail_url_not_allowed(self):
        """Test that POST to detail URL returns 405 Method Not Allowed."""
        response = self.client.post(self.detail_url, {})

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)


class HookViewSetTests(APITestCase):
    """Tests for Hook API endpoints."""

    @classmethod
    def setUpTestData(cls):
        cls.user = baker.make(User)
        cls.hookset = baker.make(
            HookSet,
            timewindow=DEFAULT_TIMEWINDOW,
            created_by=cls.user,
        )
        cls.hook = baker.make(
            Hook,
            name="Test Hook",
            hookset=cls.hookset,
            created_by=cls.user,
            is_triggered=False,
        )
        cls.list_url = reverse("trader:hook-list")
        cls.detail_url = reverse(
            "trader:hook-detail", kwargs={"uuid": cls.hook.uuid}
        )

    def setUp(self):
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")

    def test_list_hooks(self):
        """Test listing all hooks."""
        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

    def test_list_hooks_unauthenticated(self):
        """Test listing hooks requires authentication."""
        self.client.credentials()
        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_retrieve_hook(self):
        """Test retrieving a single hook with all serializer fields matching model."""
        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Check all HookSerializer fields exist
        expected_fields = [
            "id",
            "name",
            "hookset",
            "is_triggered",
            "triggered_at",
            "created_by",
            "created_at",
            "updated_at",
        ]
        for field in expected_fields:
            self.assertIn(
                field, response.data, f"Field '{field}' not found in response"
            )
        # Verify all field values match model
        self.assertEqual(response.data["id"], self.hook.pk)
        self.assertEqual(response.data["name"], self.hook.name)
        self.assertEqual(response.data["hookset"], self.hook.hookset.pk)
        self.assertEqual(response.data["is_triggered"], self.hook.is_triggered)
        self.assertEqual(response.data["triggered_at"], self.hook.triggered_at)
        self.assertEqual(response.data["created_by"]["id"], self.hook.created_by.pk)
        self.assertEqual(
            response.data["created_at"],
            self.hook.created_at.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
        )
        self.assertEqual(
            response.data["updated_at"],
            self.hook.updated_at.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
        )

    def test_create_hook(self):
        """Test creating a new hook."""
        data = {
            "name": "New Hook",
            "hookset": self.hookset.pk,
        }
        response = self.client.post(self.list_url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Hook.objects.count(), 2)

    def test_create_hook_invalid_hookset(self):
        """Test creating a hook with invalid hookset fails."""
        data = {
            "name": "Bad Hook",
            "hookset": 99999,
        }
        response = self.client.post(self.list_url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_delete_hook(self):
        """Test deleting a hook."""
        response = self.client.delete(self.detail_url)

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Hook.objects.filter(pk=self.hook.pk).exists())

    def test_retrieve_nonexistent_hook(self):
        """Test retrieving a non-existent hook returns 404."""
        url = reverse(
            "trader:hook-detail",
            kwargs={"uuid": "00000000-0000-0000-0000-000000000000"},
        )
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class HookTriggerActionTests(APITestCase):
    """Tests for Hook trigger action endpoint."""

    @classmethod
    def setUpTestData(cls):
        cls.user = baker.make(User)
        cls.hookset = baker.make(
            HookSet,
            timewindow=DEFAULT_TIMEWINDOW,
            created_by=cls.user,
        )

    def setUp(self):
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")
        # Create fresh hooks for each test
        self.hook1 = baker.make(
            Hook,
            name="Hook 1",
            hookset=self.hookset,
            created_by=self.user,
            is_triggered=False,
        )
        self.hook2 = baker.make(
            Hook,
            name="Hook 2",
            hookset=self.hookset,
            created_by=self.user,
            is_triggered=False,
        )
        self.trade = baker.make(
            Trade,
            name="Test Trade",
            pair="BTC/USD",
            action="LONG",
            hookset=self.hookset,
            created_by=self.user,
            is_triggered=False,
        )

    def test_trigger_hook_success(self):
        """Test triggering a hook returns 200."""
        url = reverse("trader:hook-trigger", kwargs={"uuid": self.hook1.uuid})
        response = self.client.post(url, {})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("triggered successfully", response.data["detail"])

    def test_trigger_hooksets_triggered_flag(self):
        """Test triggering a hook sets is_triggered to True."""
        url = reverse("trader:hook-trigger", kwargs={"uuid": self.hook1.uuid})
        self.client.post(url, {})

        self.hook1.refresh_from_db()
        self.assertTrue(self.hook1.is_triggered)
        self.assertIsNotNone(self.hook1.triggered_at)

    def test_trigger_hook_unauthenticated(self):
        """Test triggering a hook is public — external signal sources send no auth."""
        self.client.credentials()
        url = reverse("trader:hook-trigger", kwargs={"uuid": self.hook1.uuid})
        response = self.client.post(url, {})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.hook1.refresh_from_db()
        self.assertTrue(self.hook1.is_triggered)

    def test_trigger_nonexistent_hook(self):
        """Test triggering a non-existent hook returns 404."""
        url = reverse(
            "trader:hook-trigger",
            kwargs={"uuid": "00000000-0000-0000-0000-000000000000"},
        )
        response = self.client.post(url, {})

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_trigger_partial_hooks_does_not_trigger_trades(self):
        """Test that triggering only some hooks does not trigger trades."""
        # Only trigger hook1, leave hook2 untriggered
        url = reverse("trader:hook-trigger", kwargs={"uuid": self.hook1.uuid})
        self.client.post(url, {})

        self.trade.refresh_from_db()
        self.assertFalse(self.trade.is_triggered)

    def test_trigger_expired_sibling_does_not_trigger_trades(self):
        """Test that expired sibling hook prevents trade triggering."""
        # Set hook1 as triggered but expired (beyond timewindow)
        self.hook1.is_triggered = True
        self.hook1.triggered_at = timezone.now() - timedelta(hours=2)
        self.hook1.save()

        # Trigger hook2
        url = reverse("trader:hook-trigger", kwargs={"uuid": self.hook2.uuid})
        self.client.post(url, {})

        self.trade.refresh_from_db()
        self.assertFalse(self.trade.is_triggered)


class HookTriggerAlertTests(APITestCase):
    """Tests that a completed hookset sends a Telegram alert."""

    def setUp(self):
        self.user = baker.make(User)
        self.hookset = baker.make(
            HookSet, timewindow=DEFAULT_TIMEWINDOW, created_by=self.user
        )
        self.telegram = baker.make(Telegram, created_by=self.user)
        self.hookset.set_notification_channels([self.telegram])
        self.hook1 = baker.make(
            Hook, hookset=self.hookset, created_by=self.user, is_triggered=False
        )
        self.hook2 = baker.make(
            Hook, hookset=self.hookset, created_by=self.user, is_triggered=False
        )

    def trigger(self, hook):
        url = reverse("trader:hook-trigger", kwargs={"uuid": hook.uuid})
        return self.client.post(url, {})

    def test_alert_sent_when_all_hooks_fire_within_window(self):
        with patch.object(Telegram, "send") as send:
            self.trigger(self.hook1)
            send.assert_not_called()  # set incomplete

            self.trigger(self.hook2)
            send.assert_called_once()

        self.assertIn(self.hookset.name, send.call_args[0][0])

    def test_no_alert_when_sibling_fired_outside_window(self):
        self.hook1.is_triggered = True
        self.hook1.triggered_at = timezone.now() - timedelta(hours=2)
        self.hook1.save()

        with patch.object(Telegram, "send") as send:
            self.trigger(self.hook2)
            send.assert_not_called()

    def test_cycle_resets_so_alert_is_not_repeated(self):
        with patch.object(Telegram, "send") as send:
            self.trigger(self.hook1)
            self.trigger(self.hook2)
            self.assertEqual(send.call_count, 1)

            # Same hook firing again must not re-alert on the already-completed set
            self.trigger(self.hook1)
            self.assertEqual(send.call_count, 1)

            # A fresh full round alerts again
            self.trigger(self.hook2)
            self.assertEqual(send.call_count, 2)


@override_settings(FREE_EXECUTION_QUOTA=3)
class HookSetCreationPaywallTests(APITestCase):
    """Tests that a strategy cannot be created without credits behind it."""

    def setUp(self):
        self.user = baker.make(User)
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")
        self.telegram = baker.make(Telegram, created_by=self.user)
        self.list_url = reverse("trader:hookset-list")

    def payload(self, name="New strategy"):
        return {
            "name": name,
            "timewindow": "01:00:00",
            "telegram_ids": [self.telegram.id],
        }

    def test_create_allowed_while_free_quota_remains(self):
        """Test a fresh account can create a strategy."""
        response = self.client.post(self.list_url, self.payload(), format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_create_blocked_once_free_quota_and_credits_are_gone(self):
        """Test an empty wallet gets 402 instead of an unusable strategy."""
        wallet = get_wallet(self.user)
        wallet.free_executions_used = 3
        wallet.save()

        response = self.client.post(self.list_url, self.payload(), format="json")

        self.assertEqual(response.status_code, status.HTTP_402_PAYMENT_REQUIRED)
        self.assertFalse(HookSet.objects.filter(created_by=self.user).exists())

    def test_create_allowed_again_after_a_top_up(self):
        """Test buying credits restores the ability to create strategies."""
        wallet = get_wallet(self.user)
        wallet.free_executions_used = 3
        wallet.save()
        self.assertEqual(
            self.client.post(self.list_url, self.payload(), format="json").status_code,
            status.HTTP_402_PAYMENT_REQUIRED,
        )

        wallet.balance = 10
        wallet.save()

        response = self.client.post(self.list_url, self.payload(), format="json")

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_existing_strategy_stays_editable_without_credits(self):
        """Test the paywall gates creation only — existing work is not locked."""
        hookset = baker.make(
            HookSet, created_by=self.user, timewindow=DEFAULT_TIMEWINDOW
        )
        wallet = get_wallet(self.user)
        wallet.free_executions_used = 3
        wallet.save()

        response = self.client.patch(
            reverse("trader:hookset-detail", kwargs={"pk": hookset.pk}),
            {"name": "Renamed"},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)


@override_settings(FREE_EXECUTION_QUOTA=1)
class HookTriggerCreditTests(APITestCase):
    """Tests that a completed hookset is billed one execution credit."""

    def setUp(self):
        self.user = baker.make(User)
        self.hookset = baker.make(
            HookSet, timewindow=DEFAULT_TIMEWINDOW, created_by=self.user
        )
        self.telegram = baker.make(Telegram, created_by=self.user)
        self.hookset.set_notification_channels([self.telegram])
        self.hook1 = baker.make(
            Hook, hookset=self.hookset, created_by=self.user, is_triggered=False
        )
        self.hook2 = baker.make(
            Hook, hookset=self.hookset, created_by=self.user, is_triggered=False
        )

    def complete_set(self):
        for hook in (self.hook1, self.hook2):
            url = reverse("trader:hook-trigger", kwargs={"uuid": hook.uuid})
            response = self.client.post(url, {})
        return response

    def test_execution_spends_the_free_quota_first(self):
        """Test the first execution is free and leaves the paid balance alone."""
        wallet = get_wallet(self.user)
        wallet.balance = 2
        wallet.save()

        with patch.object(Telegram, "send") as send:
            response = self.complete_set()

        send.assert_called_once()
        self.assertTrue(response.data["executed"])
        wallet.refresh_from_db()
        self.assertEqual(wallet.free_executions_used, 1)
        self.assertEqual(wallet.balance, 2)

    def test_execution_spends_a_credit_once_free_quota_is_gone(self):
        """Test the second execution debits the paid balance."""
        wallet = get_wallet(self.user)
        wallet.balance = 2
        wallet.free_executions_used = 1
        wallet.save()

        with patch.object(Telegram, "send") as send:
            self.complete_set()

        send.assert_called_once()
        wallet.refresh_from_db()
        self.assertEqual(wallet.balance, 1)

    def test_no_alert_is_sent_when_the_owner_is_out_of_credits(self):
        """Test an unfunded account completes the set but sends nothing."""
        wallet = get_wallet(self.user)
        wallet.free_executions_used = 1
        wallet.save()

        with patch.object(Telegram, "send") as send, self.assertLogs(
            "trader.views", level="WARNING"
        ) as logs:
            response = self.complete_set()

        send.assert_not_called()
        self.assertIn("no credits left", logs.output[0])
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["executed"])
        self.assertEqual(response.data["reason"], "insufficient_credits")

    def test_incomplete_set_is_not_billed(self):
        """Test a partial set costs nothing — only a completed one is an execution."""
        url = reverse("trader:hook-trigger", kwargs={"uuid": self.hook1.uuid})

        with patch.object(Telegram, "send") as send:
            response = self.client.post(url, {})

        send.assert_not_called()
        self.assertFalse(response.data["executed"])
        wallet = get_wallet(self.user)
        self.assertEqual(wallet.free_executions_used, 0)

    def test_the_hookset_owner_is_billed_not_the_caller(self):
        """Test the unauthenticated caller does not shift the cost elsewhere."""
        other_user = baker.make(User)
        other_wallet = get_wallet(other_user)

        with patch.object(Telegram, "send"):
            self.complete_set()

        other_wallet.refresh_from_db()
        self.assertEqual(other_wallet.free_executions_used, 0)
        self.assertEqual(get_wallet(self.user).free_executions_used, 1)


@override_settings(FREE_EXECUTION_QUOTA=0)
class HookTriggerDeliveryFailureTests(APITestCase):
    """Tests that a credit is spent only when an alert actually reaches someone.

    TradingView allows 3 seconds, does not retry a timeout or 4xx, and retries a
    5xx three times. An undelivered alert must therefore neither surface as a
    5xx nor cost the owner anything.
    """

    def setUp(self):
        self.user = baker.make(User)
        self.hookset = baker.make(
            HookSet, timewindow=DEFAULT_TIMEWINDOW, created_by=self.user
        )
        self.telegram = baker.make(Telegram, created_by=self.user)
        self.hookset.set_notification_channels([self.telegram])
        self.hook1 = baker.make(
            Hook, hookset=self.hookset, created_by=self.user, is_triggered=False
        )
        self.hook2 = baker.make(
            Hook, hookset=self.hookset, created_by=self.user, is_triggered=False
        )
        wallet = get_wallet(self.user)
        wallet.balance = 10
        wallet.save()

    def fire(self, hook):
        url = reverse("trader:hook-trigger", kwargs={"uuid": hook.uuid})
        return self.client.post(url, {}, format="json")

    def complete_set(self):
        self.fire(self.hook1)
        return self.fire(self.hook2)

    def test_read_timeout_does_not_become_a_500(self):
        """Test a stalled Telegram read is absorbed rather than escaping.

        A read timeout raises bare TimeoutError, which is not a URLError — it
        used to escape send() and surface as a 500.
        """
        with patch.object(Telegram, "send", side_effect=TimeoutError("timed out")):
            with self.assertLogs("trader", level="WARNING"):
                response = self.complete_set()

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_failed_delivery_charges_nothing(self):
        """Test the owner keeps every credit when no alert got through."""
        with patch.object(Telegram, "send", side_effect=TimeoutError("timed out")):
            with self.assertLogs("trader", level="WARNING"):
                response = self.complete_set()

        self.assertFalse(response.data["executed"])
        self.assertEqual(response.data["reason"], "delivery_failed")
        self.assertEqual(get_wallet(self.user).balance, 10)

    def test_failed_delivery_leaves_no_ledger_entry(self):
        """Test an uncharged execution is absent from the audit trail."""
        with patch.object(Telegram, "send", side_effect=TimeoutError("timed out")):
            with self.assertLogs("trader", level="WARNING"):
                self.complete_set()

        self.assertFalse(
            LedgerEntry.objects.filter(
                reason=LedgerEntry.Reason.EXECUTION, wallet__user=self.user
            ).exists()
        )

    def test_failed_delivery_disarms_the_set(self):
        """Test the cycle resets even when delivery failed.

        An armed set plus a TradingView retry is what produced repeat billing.
        """
        with patch.object(Telegram, "send", side_effect=TimeoutError("timed out")):
            with self.assertLogs("trader", level="WARNING"):
                self.complete_set()

        self.assertFalse(
            Hook.objects.filter(hookset=self.hookset, is_triggered=True).exists()
        )

    def test_tradingview_retries_cannot_accumulate_charges(self):
        """Test replaying the completing trigger three times still costs zero."""
        with patch.object(Telegram, "send", side_effect=TimeoutError("timed out")):
            with self.assertLogs("trader", level="WARNING"):
                self.complete_set()
                for _ in range(3):
                    self.fire(self.hook2)

        self.assertEqual(get_wallet(self.user).balance, 10)

    def test_successful_delivery_charges_exactly_one(self):
        """Test the happy path still bills — the fix must not stop charging."""
        with patch.object(Telegram, "send") as send:
            response = self.complete_set()

        send.assert_called_once()
        self.assertTrue(response.data["executed"])
        self.assertEqual(get_wallet(self.user).balance, 9)

    def test_partial_delivery_counts_as_delivered(self):
        """Test one healthy channel earns the charge despite a dead sibling."""
        healthy = baker.make(Telegram, created_by=self.user)
        self.hookset.set_notification_channels([self.telegram, healthy])
        dead_pk = self.telegram.pk
        received = []

        def send(channel_self, message):
            if channel_self.pk == dead_pk:
                raise TimeoutError("timed out")
            received.append(message)

        with patch.object(Telegram, "send", send):
            with self.assertLogs("trader.models", level="ERROR"):
                response = self.complete_set()

        self.assertEqual(len(received), 1)
        self.assertTrue(response.data["executed"])
        self.assertEqual(get_wallet(self.user).balance, 9)

    def test_hookset_with_no_channels_is_not_charged(self):
        """Test a strategy that alerts nobody costs nothing."""
        self.hookset.set_notification_channels([])

        with self.assertLogs("trader.views", level="WARNING"):
            response = self.complete_set()

        self.assertFalse(response.data["executed"])
        self.assertEqual(response.data["reason"], "delivery_failed")
        self.assertEqual(get_wallet(self.user).balance, 10)

    def test_no_delivery_is_attempted_without_credits(self):
        """Test an unfunded owner gets no alert — the paywall still holds."""
        wallet = get_wallet(self.user)
        wallet.balance = 0
        wallet.save()

        with patch.object(Telegram, "send") as send:
            with self.assertLogs("trader.views", level="WARNING"):
                response = self.complete_set()

        send.assert_not_called()
        self.assertEqual(response.data["reason"], "insufficient_credits")


@override_settings(FREE_EXECUTION_QUOTA=0, TELEGRAM_BOT_TOKEN="test-token")
class RealTelegramSendBillingTests(APITestCase):
    """Tests the *real* `Telegram.send`, not a mock of it.

    The other delivery tests patch `Telegram.send` with a raising mock, so they
    verify `notify`'s counting but never the method itself. `send` used to catch
    its own failures and return normally, which `notify` counted as a delivery —
    billing the owner for an alert that never left the building. These tests
    patch one level lower, at `urllib.request.urlopen`.
    """

    def setUp(self):
        self.user = baker.make(User)
        self.hookset = baker.make(
            HookSet, timewindow=DEFAULT_TIMEWINDOW, created_by=self.user
        )
        self.hookset.set_notification_channels(
            [baker.make(Telegram, created_by=self.user)]
        )
        self.hook1 = baker.make(
            Hook, hookset=self.hookset, created_by=self.user, is_triggered=False
        )
        self.hook2 = baker.make(
            Hook, hookset=self.hookset, created_by=self.user, is_triggered=False
        )
        wallet = get_wallet(self.user)
        wallet.balance = 10
        wallet.save()

    def complete_set(self):
        for hook in (self.hook1, self.hook2):
            url = reverse("trader:hook-trigger", kwargs={"uuid": hook.uuid})
            response = self.client.post(url, {}, format="json")
        return response

    def assertNotCharged(self, response):
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data["executed"])
        self.assertEqual(response.data["reason"], "delivery_failed")
        self.assertEqual(get_wallet(self.user).balance, 10)
        self.assertFalse(
            LedgerEntry.objects.filter(
                reason=LedgerEntry.Reason.EXECUTION, wallet__user=self.user
            ).exists()
        )

    @override_settings(TELEGRAM_BOT_TOKEN="")
    def test_unconfigured_token_is_not_billable(self):
        """Test a missing bot token cannot be counted as a delivery.

        This is the live configuration today — an empty token in .env — so the
        app would otherwise charge for every execution while sending nothing.
        """
        with self.assertLogs("trader", level="WARNING"):
            response = self.complete_set()

        self.assertNotCharged(response)

    def test_network_failure_is_not_billable(self):
        """Test a connection-level failure is reported as undelivered."""
        with patch(
            "urllib.request.urlopen", side_effect=OSError("connection refused")
        ):
            with self.assertLogs("trader", level="WARNING"):
                response = self.complete_set()

        self.assertNotCharged(response)

    def test_read_timeout_is_not_billable(self):
        """Test a stalled response is reported as undelivered.

        A read timeout raises bare TimeoutError, which is not a URLError.
        """
        with patch("urllib.request.urlopen", side_effect=TimeoutError("timed out")):
            with self.assertLogs("trader", level="WARNING"):
                response = self.complete_set()

        self.assertNotCharged(response)

    def test_successful_send_is_billed_once(self):
        """Test a genuine delivery through the real send() costs one credit."""
        with patch("urllib.request.urlopen") as urlopen:
            response = self.complete_set()

        urlopen.assert_called_once()
        self.assertTrue(response.data["executed"])
        self.assertEqual(get_wallet(self.user).balance, 9)


@override_settings(FREE_EXECUTION_QUOTA=0)
class ChannelHealthTests(APITestCase):
    """Tests that a dead channel becomes visible to its owner.

    A partial delivery still costs a full credit — one credit buys the
    execution, not one copy per channel — so without a health record a broken
    channel could go unnoticed indefinitely while the owner kept paying.
    """

    def setUp(self):
        self.user = baker.make(User)
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")
        self.hookset = baker.make(
            HookSet, timewindow=DEFAULT_TIMEWINDOW, created_by=self.user
        )
        self.dead = baker.make(Telegram, created_by=self.user, name="Dead chat")
        self.alive = baker.make(Telegram, created_by=self.user, name="Live chat")
        self.hookset.set_notification_channels([self.dead, self.alive])
        self.hook1 = baker.make(
            Hook, hookset=self.hookset, created_by=self.user, is_triggered=False
        )
        self.hook2 = baker.make(
            Hook, hookset=self.hookset, created_by=self.user, is_triggered=False
        )
        wallet = get_wallet(self.user)
        wallet.balance = 10
        wallet.save()

    def complete_set(self):
        self.client.credentials()  # the webhook is public
        for hook in (self.hook1, self.hook2):
            url = reverse("trader:hook-trigger", kwargs={"uuid": hook.uuid})
            response = self.client.post(url, {}, format="json")
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")
        return response

    def half_broken_send(self):
        dead_pk = self.dead.pk

        def send(channel_self, message):
            if channel_self.pk == dead_pk:
                raise TimeoutError("timed out")

        return send

    def target_for(self, telegram):
        return NotificationTarget.objects.get(
            hookset=self.hookset, object_id=telegram.pk
        )

    def logs_for(self, telegram):
        """Newest first, matching the log model's ordering."""
        return NotificationTargetLog.objects.filter(target=self.target_for(telegram))

    def failures_for(self, telegram):
        return self.logs_for(telegram).filter(success=False)

    def test_partial_delivery_is_reported_in_the_response(self):
        """Test the response says how many of how many channels got the alert."""
        with patch.object(Telegram, "send", self.half_broken_send()):
            with self.assertLogs("trader.models", level="ERROR"):
                response = self.complete_set()

        self.assertEqual(response.data["delivered"], 1)
        self.assertEqual(response.data["channels"], 2)
        self.assertTrue(response.data["executed"])

    def test_failure_is_recorded_on_the_dead_channel(self):
        """Test the broken channel keeps the error that explains it."""
        with patch.object(Telegram, "send", self.half_broken_send()):
            with self.assertLogs("trader.models", level="ERROR"):
                self.complete_set()

        logs = self.failures_for(self.dead)
        self.assertEqual(logs.count(), 1)
        self.assertIn("timed out", logs.first().error)
        # The hookset is reachable through the target, not duplicated here.
        self.assertEqual(logs.first().target.hookset, self.hookset)

    def test_success_is_recorded_on_the_live_channel(self):
        """Test the healthy channel is not tarred by its sibling's failure."""
        with patch.object(Telegram, "send", self.half_broken_send()):
            with self.assertLogs("trader.models", level="ERROR"):
                self.complete_set()

        # The healthy channel gets a success row, not an error one.
        logs = self.logs_for(self.alive)
        self.assertEqual(logs.count(), 1)
        self.assertTrue(logs.first().success)
        self.assertEqual(logs.first().error, "")

    def test_consecutive_failures_accumulate(self):
        """Test repeated failures build a count, so a dead channel stands out."""
        with patch.object(Telegram, "send", self.half_broken_send()):
            with self.assertLogs("trader.models", level="ERROR"):
                self.complete_set()
                self.complete_set()
                self.complete_set()

        self.assertEqual(self.failures_for(self.dead).count(), 3)

    def test_recovery_clears_the_error(self):
        """Test a channel that starts working again stops being flagged."""
        with patch.object(Telegram, "send", self.half_broken_send()):
            with self.assertLogs("trader.models", level="ERROR"):
                self.complete_set()
        self.assertEqual(self.failures_for(self.dead).count(), 1)

        with patch.object(Telegram, "send"):
            self.complete_set()

        # The failure stays as history; the newer success row is what makes the
        # channel read healthy again.
        self.assertEqual(self.failures_for(self.dead).count(), 1)
        logs = self.logs_for(self.dead)
        self.assertEqual(logs.count(), 2)
        self.assertTrue(logs.first().success)  # newest first

    def test_http_failure_records_its_status_code(self):
        """Test an HTTP error keeps the status, which is the diagnostic bit.

        401 means a bad bot token, 403 blocked or kicked, 400 a bad chat_id —
        all of which need different fixes from the owner.
        """
        http_error = HTTPError(
            "https://api.telegram.org/botX/sendMessage",
            403,
            "Forbidden",
            {},
            None,
        )
        dead_pk = self.dead.pk

        def send(channel_self, message):
            if channel_self.pk == dead_pk:
                raise http_error

        with patch.object(Telegram, "send", send):
            with self.assertLogs("trader.models", level="ERROR"):
                self.complete_set()

        log = self.failures_for(self.dead).first()
        self.assertEqual(log.status_code, 403)

    def test_non_http_failure_records_no_status_code(self):
        """Test a timeout leaves the status null — no response ever arrived."""
        with patch.object(Telegram, "send", self.half_broken_send()):
            with self.assertLogs("trader.models", level="ERROR"):
                self.complete_set()

        self.assertIsNone(self.failures_for(self.dead).first().status_code)

    def test_unconfigured_token_records_no_status_code(self):
        """Test a configuration failure is logged without inventing a status."""
        # With no token every channel fails, so the view logs too — the parent
        # "trader" logger captures both children.
        with override_settings(TELEGRAM_BOT_TOKEN=""):
            with self.assertLogs("trader", level="WARNING"):
                self.complete_set()

        log = self.failures_for(self.dead).first()
        self.assertIsNone(log.status_code)
        self.assertIn("TELEGRAM_BOT_TOKEN", log.error)

    def test_bogus_code_attribute_does_not_break_the_request(self):
        """Test a channel raising a junk `.code` is still handled, not a 500.

        The extraction runs inside notify's except block, so an unvalidated
        value reaching the insert would turn a handled failure into a 500.
        """
        class WeirdError(Exception):
            code = "not-a-status"

        with patch.object(Telegram, "send", side_effect=WeirdError("boom")):
            with self.assertLogs("trader", level="WARNING"):
                response = self.complete_set()

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNone(self.failures_for(self.dead).first().status_code)

    def test_health_is_exposed_on_the_hookset_endpoint(self):
        """Test the owner can actually see the failure through the API."""
        with patch.object(Telegram, "send", self.half_broken_send()):
            with self.assertLogs("trader.models", level="ERROR"):
                self.complete_set()

        response = self.client.get(
            reverse("trader:hookset-detail", kwargs={"pk": self.hookset.pk})
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        by_name = {c["name"]: c for c in response.data["channels"]}
        self.assertFalse(by_name["Dead chat"]["is_healthy"])
        self.assertEqual(by_name["Dead chat"]["failure_count"], 1)
        self.assertIn("timed out", by_name["Dead chat"]["last_error"])
        self.assertIsNotNone(by_name["Dead chat"]["last_error_at"])
        self.assertIsNone(by_name["Dead chat"]["last_status_code"])
        self.assertTrue(by_name["Live chat"]["is_healthy"])
        self.assertIsNotNone(by_name["Live chat"]["last_success_at"])

    def test_untouched_channel_is_reported_healthy(self):
        """Test a channel that has never fired is not flagged as broken."""
        response = self.client.get(
            reverse("trader:hookset-detail", kwargs={"pk": self.hookset.pk})
        )

        for channel in response.data["channels"]:
            self.assertTrue(channel["is_healthy"])
            self.assertEqual(channel["failure_count"], 0)
            self.assertIsNone(channel["last_error"])
            self.assertIsNone(channel["last_success_at"])

    def test_success_is_logged_for_every_delivery(self):
        """Test a delivery leaves a success row, not just failures."""
        with patch.object(Telegram, "send"):
            self.complete_set()
            self.complete_set()

        logs = self.logs_for(self.alive)
        self.assertEqual(logs.count(), 2)
        self.assertTrue(all(log.success for log in logs))

    def test_last_success_at_is_exposed(self):
        """Test the owner can see when a channel last actually worked."""
        with patch.object(Telegram, "send", self.half_broken_send()):
            with self.assertLogs("trader.models", level="ERROR"):
                self.complete_set()

        response = self.client.get(
            reverse("trader:hookset-detail", kwargs={"pk": self.hookset.pk})
        )

        by_name = {c["name"]: c for c in response.data["channels"]}
        self.assertIsNotNone(by_name["Live chat"]["last_success_at"])
        # The dead channel has never succeeded, so it has no last success.
        self.assertIsNone(by_name["Dead chat"]["last_success_at"])


@override_settings(FREE_EXECUTION_QUOTA=0)
class NotificationLogEndpointTests(APITestCase):
    """Tests the delivery-history feed the owner reads in the UI."""

    def setUp(self):
        self.user = baker.make(User)
        self.other = baker.make(User)
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")
        self.list_url = reverse("trader:notificationlog-list")

        self.hookset = baker.make(
            HookSet, timewindow=DEFAULT_TIMEWINDOW, created_by=self.user, name="Mine"
        )
        self.target = baker.make(
            NotificationTarget,
            hookset=self.hookset,
            content_type=ContentType.objects.get_for_model(Telegram),
            object_id=baker.make(Telegram, created_by=self.user, name="My chat").pk,
        )

    def make_log(self, success=True, error="", status_code=None, target=None):
        return baker.make(
            NotificationTargetLog,
            target=target or self.target,
            success=success,
            error=error,
            status_code=status_code,
        )

    def test_logs_are_listed_newest_first(self):
        """Test the feed reads backwards in time, as the UI needs."""
        first = self.make_log()
        second = self.make_log()
        third = self.make_log()

        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        ids = [row["id"] for row in response.data["results"]]
        self.assertEqual(ids, [third.id, second.id, first.id])

    def test_log_carries_channel_and_strategy_names(self):
        """Test a row is readable on its own, without extra lookups."""
        self.make_log(success=False, error="HTTP Error 403", status_code=403)

        row = self.client.get(self.list_url).data["results"][0]

        self.assertEqual(row["channel"], "My chat")
        self.assertEqual(row["strategy"], "Mine")
        self.assertEqual(row["strategy_id"], self.hookset.id)
        self.assertFalse(row["success"])
        self.assertEqual(row["status_code"], 403)

    def test_another_users_logs_are_invisible(self):
        """Test delivery history is private to the hookset's owner."""
        their_hookset = baker.make(
            HookSet, timewindow=DEFAULT_TIMEWINDOW, created_by=self.other
        )
        their_target = baker.make(
            NotificationTarget,
            hookset=their_hookset,
            content_type=ContentType.objects.get_for_model(Telegram),
            object_id=baker.make(Telegram, created_by=self.other).pk,
        )
        self.make_log(target=their_target)
        mine = self.make_log()

        response = self.client.get(self.list_url)

        ids = [row["id"] for row in response.data["results"]]
        self.assertEqual(ids, [mine.id])

    def test_cannot_retrieve_another_users_log(self):
        """Test a direct id lookup is scoped too, not just the list."""
        their_hookset = baker.make(
            HookSet, timewindow=DEFAULT_TIMEWINDOW, created_by=self.other
        )
        their_target = baker.make(
            NotificationTarget,
            hookset=their_hookset,
            content_type=ContentType.objects.get_for_model(Telegram),
            object_id=baker.make(Telegram, created_by=self.other).pk,
        )
        theirs = self.make_log(target=their_target)

        response = self.client.get(
            reverse("trader:notificationlog-detail", kwargs={"pk": theirs.pk})
        )

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_failures_can_be_isolated(self):
        """Test `?success=false` gives just the diagnostic rows."""
        self.make_log(success=True)
        failure = self.make_log(success=False, error="timed out")

        response = self.client.get(self.list_url, {"success": "false"})

        ids = [row["id"] for row in response.data["results"]]
        self.assertEqual(ids, [failure.id])

    def test_results_are_paginated(self):
        """Test the feed pages, since the log grows without bound."""
        for _ in range(30):
            self.make_log()

        response = self.client.get(self.list_url)

        self.assertEqual(len(response.data["results"]), 25)
        self.assertIsNotNone(response.data["next"])

    def test_next_cursor_returns_the_remainder(self):
        """Test paging forward reaches the older rows."""
        for _ in range(30):
            self.make_log()

        first = self.client.get(self.list_url)
        second = self.client.get(first.data["next"])

        self.assertEqual(len(second.data["results"]), 5)
        first_ids = {row["id"] for row in first.data["results"]}
        second_ids = {row["id"] for row in second.data["results"]}
        self.assertEqual(first_ids & second_ids, set())

    def test_endpoint_requires_authentication(self):
        """Test delivery history is not public."""
        self.client.credentials()

        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_endpoint_is_read_only(self):
        """Test the log cannot be written through the API."""
        response = self.client.post(self.list_url, {"success": True}, format="json")

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)


class CrossUserAttachmentTests(APITestCase):
    """Tests that a user cannot attach anything to another user's resources.

    The ViewSets' get_queryset() only scopes lookups; an id passed as a related
    field on write needs scoping of its own. Left open, a user could add a hook
    to someone else's hookset — which both spends that owner's credits and, with
    a hook the owner can never see or delete, wedges their strategy so it never
    completes again.
    """

    def setUp(self):
        self.attacker = baker.make(User)
        self.victim = baker.make(User)
        refresh = RefreshToken.for_user(self.attacker)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")

        self.victim_hookset = baker.make(
            HookSet, created_by=self.victim, timewindow=DEFAULT_TIMEWINDOW
        )
        self.victim_telegram = baker.make(Telegram, created_by=self.victim)
        self.own_hookset = baker.make(
            HookSet, created_by=self.attacker, timewindow=DEFAULT_TIMEWINDOW
        )
        self.own_telegram = baker.make(Telegram, created_by=self.attacker)

    def test_cannot_create_hook_on_another_users_hookset(self):
        """Test a hook cannot be injected into someone else's strategy."""
        response = self.client.post(
            reverse("trader:hook-list"),
            {"name": "injected", "hookset": self.victim_hookset.id},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(Hook.objects.filter(hookset=self.victim_hookset).exists())

    def test_can_create_hook_on_own_hookset(self):
        """Test the scoping does not block the legitimate case."""
        response = self.client.post(
            reverse("trader:hook-list"),
            {"name": "mine", "hookset": self.own_hookset.id},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_cannot_move_own_hook_onto_another_users_hookset(self):
        """Test an update cannot reparent a hook across owners."""
        hook = baker.make(
            Hook, hookset=self.own_hookset, created_by=self.attacker
        )

        response = self.client.patch(
            reverse("trader:hook-detail", kwargs={"uuid": hook.uuid}),
            {"hookset": self.victim_hookset.id},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        hook.refresh_from_db()
        self.assertEqual(hook.hookset, self.own_hookset)

    def test_cannot_create_trade_on_another_users_hookset(self):
        """Test a trade cannot be attached to someone else's strategy."""
        response = self.client.post(
            reverse("trader:trade-list"),
            {
                "name": "injected",
                "pair": "BTC/USDT",
                "action": "LONG",
                "hookset": self.victim_hookset.id,
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(Trade.objects.filter(hookset=self.victim_hookset).exists())

    def test_cannot_attach_another_users_telegram_to_own_hookset(self):
        """Test alerts cannot be pointed at a chat belonging to someone else."""
        response = self.client.post(
            reverse("trader:hookset-list"),
            {
                "name": "attacker set",
                "timewindow": "01:00:00",
                "telegram_ids": [self.victim_telegram.id],
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_can_attach_own_telegram_to_own_hookset(self):
        """Test the scoping does not block the legitimate case."""
        response = self.client.post(
            reverse("trader:hookset-list"),
            {
                "name": "attacker set",
                "timewindow": "01:00:00",
                "telegram_ids": [self.own_telegram.id],
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        hookset = HookSet.objects.get(pk=response.data["id"])
        self.assertEqual(hookset.notification_targets.count(), 1)

    def test_cannot_swap_in_another_users_telegram_on_update(self):
        """Test an update cannot redirect alerts to someone else's chat."""
        self.own_hookset.set_notification_channels([self.own_telegram])

        response = self.client.patch(
            reverse("trader:hookset-detail", kwargs={"pk": self.own_hookset.pk}),
            {"telegram_ids": [self.victim_telegram.id]},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        targets = self.own_hookset.notification_targets.all()
        self.assertEqual(targets.count(), 1)
        self.assertEqual(targets.first().channel, self.own_telegram)


class TradeViewSetTests(APITestCase):
    """Tests for Trade API endpoints."""

    @classmethod
    def setUpTestData(cls):
        cls.user = baker.make(User)
        cls.hookset = baker.make(
            HookSet,
            timewindow=DEFAULT_TIMEWINDOW,
            created_by=cls.user,
        )
        cls.trade = baker.make(
            Trade,
            name="Test Trade",
            pair="BTC/USD",
            action="LONG",
            hookset=cls.hookset,
            created_by=cls.user,
        )
        cls.list_url = reverse("trader:trade-list")
        cls.detail_url = reverse("trader:trade-detail", kwargs={"pk": cls.trade.pk})

    def setUp(self):
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")

    def test_list_trades(self):
        """Test listing all trades."""
        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

    def test_list_trades_unauthenticated(self):
        """Test listing trades requires authentication."""
        self.client.credentials()
        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_retrieve_trade(self):
        """Test retrieving a single trade with all serializer fields matching model."""
        response = self.client.get(self.detail_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Check all TradeSerializer fields exist
        expected_fields = [
            "id",
            "name",
            "pair",
            "action",
            "hookset",
            "is_triggered",
            "triggered_at",
            "created_by",
            "created_at",
            "updated_at",
        ]
        for field in expected_fields:
            self.assertIn(
                field, response.data, f"Field '{field}' not found in response"
            )
        # Verify all field values match model
        self.assertEqual(response.data["id"], self.trade.pk)
        self.assertEqual(response.data["name"], self.trade.name)
        self.assertEqual(response.data["pair"], self.trade.pair)
        self.assertEqual(response.data["action"], self.trade.action)
        self.assertEqual(response.data["hookset"]["id"], self.trade.hookset.pk)
        self.assertEqual(response.data["is_triggered"], self.trade.is_triggered)
        self.assertEqual(response.data["triggered_at"], self.trade.triggered_at)
        self.assertEqual(response.data["created_by"]["id"], self.trade.created_by.pk)
        self.assertEqual(
            response.data["created_at"],
            self.trade.created_at.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
        )
        self.assertEqual(
            response.data["updated_at"],
            self.trade.updated_at.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
        )

    def test_create_trade_long(self):
        """Test creating a new long trade."""
        data = {
            "name": "New Long Trade",
            "pair": "ETH/USD",
            "action": "LONG",
            "hookset": self.hookset.pk,
        }
        response = self.client.post(self.list_url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["name"], "New Long Trade")
        self.assertEqual(response.data["action"], "LONG")

    def test_create_trade_short(self):
        """Test creating a new short trade."""
        data = {
            "name": "New Short Trade",
            "pair": "ETH/USD",
            "action": "SHORT",
            "hookset": self.hookset.pk,
        }
        response = self.client.post(self.list_url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["action"], "SHORT")

    def test_create_trade_invalid_action(self):
        """Test creating a trade with invalid action fails."""
        data = {
            "name": "Invalid Trade",
            "pair": "BTC/USD",
            "action": "INVALID",
            "hookset": self.hookset.pk,
        }
        response = self.client.post(self.list_url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_trade_missing_required_fields(self):
        """Test creating a trade without required fields fails."""
        data = {"name": "Incomplete Trade"}
        response = self.client.post(self.list_url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_trade_patch(self):
        """Test partial update of trade."""
        data = {"name": "Patched Trade"}
        response = self.client.patch(self.detail_url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.trade.refresh_from_db()
        self.assertEqual(self.trade.name, "Patched Trade")

    def test_delete_trade(self):
        """Test deleting a trade."""
        response = self.client.delete(self.detail_url)

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Trade.objects.filter(pk=self.trade.pk).exists())

    def test_retrieve_nonexistent_trade(self):
        """Test retrieving a non-existent trade returns 404."""
        url = reverse("trader:trade-detail", kwargs={"pk": 99999})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
