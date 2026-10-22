from datetime import time

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase
from model_bakery import baker

from trader.models import Exchange, Hook, HookSet, Trade

User = get_user_model()


class StrTests(TestCase):
    """Tests that every model renders as a string.

    `__str__` must return a str, and may only touch fields the model has —
    both of these used to raise, which broke the admin and any log line or
    f-string that mentioned the object.
    """

    def test_hook_str_returns_a_string(self):
        """Test Hook.__str__ returns its uuid as text, not a UUID object."""
        hook = baker.make(Hook, hookset=baker.make(HookSet, timewindow=time(1, 0)))

        self.assertEqual(str(hook), str(hook.uuid))

    def test_exchange_str_returns_the_platform_label(self):
        """Test Exchange.__str__ does not reach for a field that doesn't exist."""
        self.assertEqual(str(Exchange(platform="BINANCE")), "Binance")


class HookSetDefaultsTests(TestCase):
    """Tests the timewindow default."""

    def test_hookset_can_be_created_without_an_explicit_timewindow(self):
        """Test the model default is a valid time, so the insert succeeds."""
        hookset = HookSet.objects.create(name="defaults", created_by=baker.make(User))

        self.assertEqual(hookset.timewindow, time(1, 0))

    def test_default_survives_a_reload(self):
        """Test the stored value round-trips as a time."""
        hookset = HookSet.objects.create(name="defaults", created_by=baker.make(User))
        hookset.refresh_from_db()

        self.assertEqual(hookset.timewindow, time(1, 0))


class ValidatePairTests(TestCase):
    """Tests for Trade.validate_pair."""

    def setUp(self):
        self.trade = Trade(name="t", pair="BTC/USDT", action="LONG")

    def test_ordinary_pair_is_accepted(self):
        """Test a normal pair passes — it used to fail its own alphanumeric rule."""
        self.assertEqual(self.trade.validate_pair("BTC/USDT"), "BTC/USDT")

    def test_alphanumeric_asset_is_accepted(self):
        """Test digits in a ticker are allowed."""
        self.assertEqual(self.trade.validate_pair("1INCH/USDT"), "1INCH/USDT")

    def test_non_alphanumeric_asset_is_rejected(self):
        """Test punctuation in an asset is refused."""
        with self.assertRaises(ValidationError):
            self.trade.validate_pair("BT-C/USDT")

    def test_missing_separator_is_rejected(self):
        """Test a pair must have exactly two sides."""
        with self.assertRaises(ValidationError):
            self.trade.validate_pair("BTCUSDT")

    def test_too_short_asset_is_rejected(self):
        """Test a one-character asset is refused."""
        with self.assertRaises(ValidationError):
            self.trade.validate_pair("B/USDT")

    def test_too_long_asset_is_rejected(self):
        """Test an asset beyond the length cap is refused."""
        with self.assertRaises(ValidationError):
            self.trade.validate_pair("BITCOIN/USDT")
