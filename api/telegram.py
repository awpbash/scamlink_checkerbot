"""Vercel serverless entrypoint. Telegram pushes each update here via webhook
instead of the bot polling for them. See setup_webhook.py for one-time setup.
"""
import asyncio
import hmac
import json
import os
import sys
from http.server import BaseHTTPRequestHandler
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from telegram import Update  # noqa: E402

from bot import build_application  # noqa: E402


class handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        expected = os.environ.get("TELEGRAM_WEBHOOK_SECRET")
        got = self.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
        if expected and not hmac.compare_digest(got, expected):
            # Wrong/missing secret, so reject before touching the network at all.
            # Anyone who finds this public URL can otherwise POST fake updates.
            self.send_response(401)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        update_data = json.loads(body)
        asyncio.run(_process(update_data))

        self.send_response(200)
        self.end_headers()


async def _process(update_data: dict) -> None:
    application = build_application()
    await application.initialize()
    try:
        update = Update.de_json(update_data, application.bot)
        await application.process_update(update)
    finally:
        await application.shutdown()
