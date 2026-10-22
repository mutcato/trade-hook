"""NOWPayments adapter.

NOWPayments is non-custodial: the customer pays an address and the funds settle
straight to the payout wallet configured in the NOWPayments dashboard, so no
balance accumulates at the provider.

Only `_request` touches the network, which keeps the house test idiom
(`patch.object(NowPaymentsProvider, "create_invoice")`) workable and means the
transport is never exercised in tests.
"""

import hashlib
import hmac
import json
import logging
import urllib.error
import urllib.request

from django.conf import settings

logger = logging.getLogger(__name__)


class NowPaymentsError(Exception):
    """Raised when NOWPayments rejects a call or is unreachable."""


class NowPaymentsProvider:
    name = "nowpayments"

    SANDBOX_BASE = "https://api-sandbox.nowpayments.io/v1"
    PRODUCTION_BASE = "https://api.nowpayments.io/v1"

    # NOWPayments reports `confirmed` once the chain confirms but before the
    # payout has actually been forwarded, so only `finished` may grant credits.
    SETTLED_STATUSES = frozenset({"finished"})
    PENDING_STATUSES = frozenset({"waiting", "confirming", "confirmed", "sending"})
    FAILED_STATUSES = frozenset({"failed", "expired", "refunded"})

    def __init__(self, api_key=None, ipn_secret=None, sandbox=None):
        self.api_key = (
            api_key if api_key is not None else settings.NOWPAYMENTS_API_KEY
        )
        self.ipn_secret = (
            ipn_secret if ipn_secret is not None else settings.NOWPAYMENTS_IPN_SECRET
        )
        self.sandbox = (
            sandbox if sandbox is not None else settings.NOWPAYMENTS_SANDBOX
        )

    @property
    def base_url(self):
        return self.SANDBOX_BASE if self.sandbox else self.PRODUCTION_BASE

    def create_invoice(self, order, success_url, cancel_url, ipn_callback_url):
        """Create a hosted invoice for `order` and return the provider payload.

        A hosted invoice (rather than a raw payment address) keeps every coin,
        network and exchange-rate concern on the provider's page, so nothing
        crypto-specific leaks into this codebase.
        """
        if not self.api_key:
            raise NowPaymentsError("NOWPAYMENTS_API_KEY is not configured")
        if not ipn_callback_url:
            # Without a callback the payment would succeed and the credits would
            # never arrive, with nothing in the logs to explain it. Fail loudly
            # at order time instead of taking money for nothing.
            raise NowPaymentsError(
                "NOWPAYMENTS_IPN_CALLBACK_URL is not configured; "
                "credits could never be granted"
            )

        payload = {
            "price_amount": str(order.price_usd),
            "price_currency": "usd",
            "order_id": str(order.uuid),
            "order_description": f"{order.credits} execution credits",
            "ipn_callback_url": ipn_callback_url,
            "success_url": success_url,
            "cancel_url": cancel_url,
        }
        return self._request("/invoice", payload)

    def verify_ipn_signature(self, raw_body, signature):
        """Check the `x-nowpayments-sig` header against the raw request body.

        NOWPayments signs the JSON body with its keys sorted, so the body has to
        be re-serialised in that exact form before the HMAC is computed.
        """
        if not self.ipn_secret or not signature:
            return False

        try:
            parsed = json.loads(raw_body)
        except (TypeError, ValueError):
            return False

        canonical = json.dumps(parsed, sort_keys=True, separators=(",", ":"))
        expected = hmac.new(
            self.ipn_secret.encode("utf-8"),
            canonical.encode("utf-8"),
            hashlib.sha512,
        ).hexdigest()
        return hmac.compare_digest(expected, signature)

    def _request(self, path, payload):
        url = f"{self.base_url}{path}"
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "x-api-key": self.api_key,
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            logger.error("NOWPayments %s failed: %s %s", path, exc.code, detail)
            raise NowPaymentsError(f"NOWPayments returned {exc.code}") from exc
        except urllib.error.URLError as exc:
            logger.exception("NOWPayments %s unreachable", path)
            raise NowPaymentsError("NOWPayments is unreachable") from exc
