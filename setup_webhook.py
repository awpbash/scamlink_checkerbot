"""One-off setup for a webhook deployment (e.g. Vercel): points Telegram at
the deployed URL and sets the bot's profile (name/description/commands).
Run once after each deploy. This is a manual script, not part of the app.

Usage:
    .venv/bin/python setup_webhook.py https://<your-app>.vercel.app/api/telegram
"""
import asyncio
import os
import sys

from bot import _load_dotenv, _setup_profile, build_application


async def _run(url: str) -> None:
    app = build_application()
    secret = os.environ.get("TELEGRAM_WEBHOOK_SECRET")
    await app.bot.set_webhook(url, secret_token=secret or None)
    await _setup_profile(app)
    if secret:
        print(f"Webhook set to {url} (secret token configured)")
    else:
        print(
            f"Webhook set to {url}. WARNING: no TELEGRAM_WEBHOOK_SECRET set, "
            "anyone who finds this URL can POST fake updates to it."
        )


if __name__ == "__main__":
    _load_dotenv()
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python setup_webhook.py <https-webhook-url>")
    asyncio.run(_run(sys.argv[1]))
