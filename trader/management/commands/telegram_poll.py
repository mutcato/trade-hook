import json
import time
import urllib.error
import urllib.parse
import urllib.request

from django.conf import settings
from django.core.management.base import BaseCommand

API_TIMEOUT_SECONDS = 30


class Command(BaseCommand):
    help = (
        "Long-polls the Telegram Bot API for incoming messages and replies with the "
        "sender's chat ID, so users can find the value to paste into a Telegram "
        "notification destination."
    )

    def handle(self, *args, **options):
        token = settings.TELEGRAM_BOT_TOKEN
        if not token:
            self.stderr.write("TELEGRAM_BOT_TOKEN is not configured.")
            return

        base_url = f"https://api.telegram.org/bot{token}"
        offset = None
        self.stdout.write(self.style.SUCCESS("Listening for Telegram messages… (Ctrl+C to stop)"))

        while True:
            for update in self._get_updates(base_url, offset):
                offset = update["update_id"] + 1
                message = update.get("message")
                if message:
                    self._reply_with_chat_id(base_url, message["chat"]["id"])

    def _get_updates(self, base_url, offset):
        params = {"timeout": API_TIMEOUT_SECONDS}
        if offset is not None:
            params["offset"] = offset
        url = f"{base_url}/getUpdates?{urllib.parse.urlencode(params)}"

        try:
            with urllib.request.urlopen(url, timeout=API_TIMEOUT_SECONDS + 5) as response:
                data = json.loads(response.read())
        except (urllib.error.URLError, OSError) as exc:
            self.stderr.write(f"getUpdates failed: {exc}")
            time.sleep(3)
            return []

        return data.get("result", [])

    def _reply_with_chat_id(self, base_url, chat_id):
        text = (
            f"Your chat ID is: {chat_id}\n\n"
            "Paste this into the Telegram destination form in AlphaBot to receive alerts here."
        )
        body = json.dumps({"chat_id": chat_id, "text": text}).encode("utf-8")
        request = urllib.request.Request(
            f"{base_url}/sendMessage", data=body, headers={"Content-Type": "application/json"}
        )
        try:
            urllib.request.urlopen(request, timeout=10)
        except (urllib.error.URLError, OSError) as exc:
            self.stderr.write(f"Failed to reply to chat {chat_id}: {exc}")
