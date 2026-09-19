import html
import logging
import os
from urllib.parse import urlsplit, urlunsplit

from telegram import BotCommand, Update
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

import extractor
import registry
from resolver import ResolveError, resolve

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BOT_NAME = "Gov.sg Checker Bot"
BOT_DESCRIPTION = (
    "Gov.sg Checker Bot verifies links forwarded to it against Singapore's official government "
    "and trusted-partner domains, traces redirects and shortened URLs to their real "
    "destination, and flags known scam patterns such as look-alike domains and "
    "disguised links."
)
BOT_SHORT_DESCRIPTION = "Verifies links against Singapore's official domains and flags scam patterns."
START_MESSAGE = (
    f"<b>{BOT_NAME}</b>\nSingapore Link Verification\n\n"
    "Forward a message here. I will check every link it contains against Singapore's "
    "verified government and trusted-partner domains, trace redirects and shortened "
    "URLs to their real destination, and flag known scam patterns."
)


def _esc(value) -> str:
    return html.escape(str(value), quote=False)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(START_MESSAGE, parse_mode="HTML")


async def check_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.effective_message
    if not (message.text or message.caption):
        # Forwarded albums send each photo as a separate message, but only one
        # carries the caption. The rest have nothing to check, so stay silent
        # on those instead of replying "No links found" once per photo.
        return

    links = extractor.extract_links(message)
    if not links:
        await message.reply_text("This message contains no links to verify.")
        return

    lines = [await _verdict_line(link) for link in links]
    await message.reply_text(
        "\n\n".join(lines), parse_mode="HTML", disable_web_page_preview=True
    )


def _strip_query(url: str) -> str:
    """Drop query string/fragment for display. Trust checks use hostname only anyway."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _alarm_bells(url: str) -> str:
    """Deterministic red flags beyond the registry/resolve checks. Catches
    look-alike domains and gov.sg-looking text stuffed into a link's path.
    Runs independently of whether the link even resolves.
    """
    hostname = (urlsplit(url).hostname or "").lower()
    alarms = []

    lookalike = registry.find_lookalike(hostname)
    if lookalike:
        alarms.append(
            f"<code>{_esc(hostname)}</code> imitates the official "
            f"<code>{_esc(lookalike['domain'])}</code> domain through character "
            "substitution (e.g. 0 for o). It is not the genuine site."
        )

    fake_path = registry.find_impersonation_in_path(url, hostname)
    if fake_path:
        alarms.append(
            f"<code>{_esc(fake_path)}</code> appears in the link's path, not its "
            f"domain. The real destination is <code>{_esc(hostname)}</code>."
        )

    return "".join(f"\n🚨 {a}" for a in alarms)


async def _verdict_line(link: dict) -> str:
    display, url = link["display"], link["url"]
    shown = display if display != url else _strip_query(url)
    header = f"🔗 {_esc(shown)}"
    alarms = _alarm_bells(url)

    if link["text_mismatch"]:
        verdict = (
            "The visible text does not match the real destination. This is a "
            "disguised-link scam pattern. Do not open it."
        )
        return (
            f"{header}\n⚠️ <b>MISMATCH</b>\n{_esc(verdict)}\n"
            f"Actual link: <code>{_esc(_strip_query(url))}</code>{alarms}"
        )

    try:
        result = await resolve(url)
    except ResolveError as e:
        verdict = f"This link could not be safely checked ({e.reason}). Do not open it."
        return f"{header}\n⚠️ <b>UNVERIFIABLE</b>\n{_esc(verdict)}{alarms}"

    final_domain = urlsplit(result["final_url"]).hostname
    entry = registry.is_trusted(final_domain) if final_domain else None

    hop_note = ""
    if len(result["hops"]) > 1:
        hop_note = (
            f"\nRedirected via {len(result['hops'])} hop(s) to: "
            f"<code>{_esc(_strip_query(result['final_url']))}</code>"
        )

    if entry:
        return f"{header}\n✅ <b>VERIFIED</b>\n{_esc(entry['name'])}.{hop_note}{alarms}"

    verdict = (
        "This domain is not on Singapore's official or trusted-partner list. "
        "Do not enter personal or financial information."
    )
    return f"{header}\n❌ <b>UNVERIFIED</b>\n{_esc(verdict)}{hop_note}{alarms}"


def _load_dotenv(path: str = ".env") -> None:
    """Minimal .env loader (stdlib-only). Sets vars not already in the environment."""
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                os.environ.setdefault(key.strip(), value.strip())
    except FileNotFoundError:
        pass


async def _setup_profile(app: Application) -> None:
    """Set the bot's Telegram-visible name/description/commands.
    Idempotent, so it's safe to call on every polling startup, or once manually via
    setup_webhook.py for a webhook deployment.
    """
    bot = app.bot
    await bot.set_my_name(BOT_NAME)
    await bot.set_my_description(BOT_DESCRIPTION)
    await bot.set_my_short_description(BOT_SHORT_DESCRIPTION)
    await bot.set_my_commands([BotCommand("start", "About this bot and how it works")])


def build_application(*, for_polling: bool = False) -> Application:
    """Wire up the handlers. Shared by the local polling entrypoint (main,
    below) and the Vercel webhook handler (api/telegram.py) so both run the
    exact same bot logic.
    """
    token = os.environ.get("BOT_TOKEN")
    if not token:
        raise SystemExit("Set BOT_TOKEN in the environment before running.")

    builder = Application.builder().token(token)
    if for_polling:
        builder = builder.post_init(_setup_profile)
    app = builder.build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(
        MessageHandler(filters.ChatType.PRIVATE & ~filters.COMMAND, check_message)
    )
    return app


def main() -> None:
    _load_dotenv()
    build_application(for_polling=True).run_polling()


if __name__ == "__main__":
    main()
