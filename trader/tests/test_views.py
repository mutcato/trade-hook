from datetime import time, timedelta

from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from model_bakery import baker
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken

from trader.models import Hook, HookSet, Trade

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
            name='Test HookSet',
            timewindow=DEFAULT_TIMEWINDOW,
            created_by=cls.user,
        )
        cls.other_hookset = baker.make(
            HookSet,
            timewindow=DEFAULT_TIMEWINDOW,
            created_by=cls.other_user,
        )
        cls.list_url = reverse('trader:hookset-list')
        cls.detail_url = reverse('trader:hookset-detail', kwargs={'pk': cls.hookset.pk})

    def setUp(self):
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

    def test_list_hooksets(self):
        """Test listing all hooksets."""
        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)

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
        expected_fields = ['id', 'name', 'timewindow', 'hook_set', 'created_by', 'created_at', 'updated_at']
        for field in expected_fields:
            self.assertIn(field, response.data, f"Field '{field}' not found in response")
        # Verify all field values match model
        self.assertEqual(response.data['id'], self.hookset.pk)
        self.assertEqual(response.data['name'], self.hookset.name)
        self.assertEqual(response.data['timewindow'], self.hookset.timewindow.strftime('%H:%M:%S'))
        self.assertIsInstance(response.data['hook_set'], list)
        self.assertEqual(response.data['created_by']['id'], self.hookset.created_by.pk)
        self.assertEqual(response.data['created_at'], self.hookset.created_at.strftime('%Y-%m-%dT%H:%M:%S.%f') + 'Z')
        self.assertEqual(response.data['updated_at'], self.hookset.updated_at.strftime('%Y-%m-%dT%H:%M:%S.%f') + 'Z')

    def test_create_hookset(self):
        """Test creating a new hookset."""
        data = {
            'name': 'New HookSet',
            'timewindow': '02:00:00',
        }
        response = self.client.post(self.list_url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['name'], 'New HookSet')
        self.assertTrue(HookSet.objects.filter(name='New HookSet').exists())

    def test_create_hookset_empty_data(self):
        """Test creating a hookset with empty data fails."""
        response = self.client.post(self.list_url, {})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_hookset_put(self):
        """Test full update of hookset."""
        data = {
            'name': 'Updated HookSet',
            'timewindow': '03:00:00',
        }
        response = self.client.put(self.detail_url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.hookset.refresh_from_db()
        self.assertEqual(self.hookset.name, 'Updated HookSet')

    def test_update_hookset_patch(self):
        """Test partial update of hookset."""
        data = {'name': 'Patched HookSet'}
        response = self.client.patch(self.detail_url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.hookset.refresh_from_db()
        self.assertEqual(self.hookset.name, 'Patched HookSet')

    def test_delete_hookset(self):
        """Test deleting a hookset."""
        response = self.client.delete(self.detail_url)

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(HookSet.objects.filter(pk=self.hookset.pk).exists())

    def test_retrieve_nonexistent_hookset(self):
        """Test retrieving a non-existent hookset returns 404."""
        url = reverse('trader:hookset-detail', kwargs={'pk': 99999})
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
            name='Test Hook',
            hook_set=cls.hookset,
            created_by=cls.user,
            is_triggered=False,
        )
        cls.list_url = reverse('trader:hook-list')
        cls.detail_url = reverse('trader:hook-detail', kwargs={'pk': cls.hook.pk})

    def setUp(self):
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

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
        expected_fields = ['id', 'hook_set', 'is_triggered', 'triggered_at', 'created_by', 'created_at', 'updated_at']
        for field in expected_fields:
            self.assertIn(field, response.data, f"Field '{field}' not found in response")
        # Verify all field values match model
        self.assertEqual(response.data['id'], self.hook.pk)
        self.assertEqual(response.data['hook_set'], self.hook.hook_set.pk)
        self.assertEqual(response.data['is_triggered'], self.hook.is_triggered)
        self.assertEqual(response.data['triggered_at'], self.hook.triggered_at)
        self.assertEqual(response.data['created_by']['id'], self.hook.created_by.pk)
        self.assertEqual(response.data['created_at'], self.hook.created_at.strftime('%Y-%m-%dT%H:%M:%S.%f') + 'Z')
        self.assertEqual(response.data['updated_at'], self.hook.updated_at.strftime('%Y-%m-%dT%H:%M:%S.%f') + 'Z')

    def test_create_hook(self):
        """Test creating a new hook."""
        data = {
            'hook_set': self.hookset.pk,
        }
        response = self.client.post(self.list_url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Hook.objects.count(), 2)

    def test_create_hook_invalid_hookset(self):
        """Test creating a hook with invalid hookset fails."""
        data = {
            'hook_set': 99999,
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
        url = reverse('trader:hook-detail', kwargs={'pk': 99999})
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
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
        # Create fresh hooks for each test
        self.hook1 = baker.make(
            Hook,
            name='Hook 1',
            hook_set=self.hookset,
            created_by=self.user,
            is_triggered=False,
        )
        self.hook2 = baker.make(
            Hook,
            name='Hook 2',
            hook_set=self.hookset,
            created_by=self.user,
            is_triggered=False,
        )
        self.trade = baker.make(
            Trade,
            name='Test Trade',
            pair='BTC/USD',
            action='LONG',
            hookset=self.hookset,
            created_by=self.user,
            is_triggered=False,
        )

    def test_trigger_hook_success(self):
        """Test triggering a hook returns 200."""
        url = reverse('trader:hook-trigger', kwargs={'pk': self.hook1.pk})
        response = self.client.post(url, {})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('triggered successfully', response.data['detail'])

    def test_trigger_hook_sets_triggered_flag(self):
        """Test triggering a hook sets is_triggered to True."""
        url = reverse('trader:hook-trigger', kwargs={'pk': self.hook1.pk})
        self.client.post(url, {})

        self.hook1.refresh_from_db()
        self.assertTrue(self.hook1.is_triggered)
        self.assertIsNotNone(self.hook1.triggered_at)

    def test_trigger_hook_unauthenticated(self):
        """Test triggering a hook requires authentication."""
        self.client.credentials()
        url = reverse('trader:hook-trigger', kwargs={'pk': self.hook1.pk})
        response = self.client.post(url, {})

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_trigger_nonexistent_hook(self):
        """Test triggering a non-existent hook returns 404."""
        url = reverse('trader:hook-trigger', kwargs={'pk': 99999})
        response = self.client.post(url, {})

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_trigger_partial_hooks_does_not_trigger_trades(self):
        """Test that triggering only some hooks does not trigger trades."""
        # Only trigger hook1, leave hook2 untriggered
        url = reverse('trader:hook-trigger', kwargs={'pk': self.hook1.pk})
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
        url = reverse('trader:hook-trigger', kwargs={'pk': self.hook2.pk})
        self.client.post(url, {})

        self.trade.refresh_from_db()
        self.assertFalse(self.trade.is_triggered)


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
            name='Test Trade',
            pair='BTC/USD',
            action='LONG',
            hookset=cls.hookset,
            created_by=cls.user,
        )
        cls.list_url = reverse('trader:trade-list')
        cls.detail_url = reverse('trader:trade-detail', kwargs={'pk': cls.trade.pk})

    def setUp(self):
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

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
        expected_fields = ['id', 'name', 'pair', 'action', 'hookset', 'is_triggered', 'triggered_at', 'created_by', 'created_at', 'updated_at']
        for field in expected_fields:
            self.assertIn(field, response.data, f"Field '{field}' not found in response")
        # Verify all field values match model
        self.assertEqual(response.data['id'], self.trade.pk)
        self.assertEqual(response.data['name'], self.trade.name)
        self.assertEqual(response.data['pair'], self.trade.pair)
        self.assertEqual(response.data['action'], self.trade.action)
        self.assertEqual(response.data['hookset']['id'], self.trade.hookset.pk)
        self.assertEqual(response.data['is_triggered'], self.trade.is_triggered)
        self.assertEqual(response.data['triggered_at'], self.trade.triggered_at)
        self.assertEqual(response.data['created_by']['id'], self.trade.created_by.pk)
        self.assertEqual(response.data['created_at'], self.trade.created_at.strftime('%Y-%m-%dT%H:%M:%S.%f') + 'Z')
        self.assertEqual(response.data['updated_at'], self.trade.updated_at.strftime('%Y-%m-%dT%H:%M:%S.%f') + 'Z')

    def test_create_trade_long(self):
        """Test creating a new long trade."""
        data = {
            'name': 'New Long Trade',
            'pair': 'ETH/USD',
            'action': 'LONG',
            'hookset': self.hookset.pk,
        }
        response = self.client.post(self.list_url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['name'], 'New Long Trade')
        self.assertEqual(response.data['action'], 'LONG')

    def test_create_trade_short(self):
        """Test creating a new short trade."""
        data = {
            'name': 'New Short Trade',
            'pair': 'ETH/USD',
            'action': 'SHORT',
            'hookset': self.hookset.pk,
        }
        response = self.client.post(self.list_url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['action'], 'SHORT')

    def test_create_trade_invalid_action(self):
        """Test creating a trade with invalid action fails."""
        data = {
            'name': 'Invalid Trade',
            'pair': 'BTC/USD',
            'action': 'INVALID',
            'hookset': self.hookset.pk,
        }
        response = self.client.post(self.list_url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_create_trade_missing_required_fields(self):
        """Test creating a trade without required fields fails."""
        data = {'name': 'Incomplete Trade'}
        response = self.client.post(self.list_url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_update_trade_patch(self):
        """Test partial update of trade."""
        data = {'name': 'Patched Trade'}
        response = self.client.patch(self.detail_url, data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.trade.refresh_from_db()
        self.assertEqual(self.trade.name, 'Patched Trade')

    def test_delete_trade(self):
        """Test deleting a trade."""
        response = self.client.delete(self.detail_url)

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(Trade.objects.filter(pk=self.trade.pk).exists())

    def test_retrieve_nonexistent_trade(self):
        """Test retrieving a non-existent trade returns 404."""
        url = reverse('trader:trade-detail', kwargs={'pk': 99999})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
