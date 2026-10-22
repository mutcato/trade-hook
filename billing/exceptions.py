from rest_framework import status
from rest_framework.exceptions import APIException


class InsufficientCredits(APIException):
    """Raised when an action needs an execution credit the user doesn't have.

    402 rather than 403 so the frontend can tell "you must pay" apart from
    "you may not do this" and route the user to a top-up.
    """

    status_code = status.HTTP_402_PAYMENT_REQUIRED
    default_detail = (
        "You're out of execution credits. Top up to create another strategy."
    )
    default_code = "insufficient_credits"
