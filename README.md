# Gov.sg Checker Bot

A Telegram bot that checks links in forwarded messages against Singapore's
official government and trusted-partner domains, and flags common scam
patterns (disguised links, look-alike domains, fake `.gov.sg` text stuffed
into a shortened URL's path).

Forward it a message. It replies with a verdict for every link it finds.

## How it works

- **`extractor.py`** pulls every link out of a message and flags it if the
  visible text claims to be one domain while the actual link goes elsewhere.
- **`resolver.py`** follows redirects (shorteners included) to the real final
  destination, safely, rejecting any hop that resolves to a private/internal
  IP.
- **`registry.py`** / **`registry.json`** hold ~200 verified Singapore
  government, statutory board, and trusted-partner domains, and detect
  look-alike domains (e.g. `g0v.sg`) and impersonation stuffed into a URL's
  path.
- **`bot.py`** wires all of this into Telegram replies. No external API
  calls, no LLM, everything is deterministic.

## Run it locally (polling)

```
pip install -r requirements.txt
cp .env.example .env   # fill in BOT_TOKEN
python bot.py
```

Get a `BOT_TOKEN` from [@BotFather](https://t.me/BotFather) on Telegram.

## Run the tests

```
python test_checker.py
```

## Deploy on Vercel (webhook)

Polling needs a process that's always running, which Vercel doesn't offer.
Deploying there means switching to webhooks instead: Telegram pushes each
message to your URL, rather than the bot continuously asking for updates.

1. Push this repo to GitHub and import it into Vercel.
2. In the Vercel project's environment variables, set `BOT_TOKEN` and a
   `TELEGRAM_WEBHOOK_SECRET` (any random string, e.g. from
   `python -c "import secrets; print(secrets.token_urlsafe(32))"`).
3. Deploy. Vercel automatically picks up `api/telegram.py`.
4. Run this once, locally, pointed at your deployed URL, to tell Telegram
   where to send updates and set the bot's profile:
   ```
   python setup_webhook.py https://<your-project>.vercel.app/api/telegram
   ```

## Environment variables

| Variable | Required | Purpose |
|---|---|---|
| `BOT_TOKEN` | Yes | Your bot's token from BotFather |
| `TELEGRAM_WEBHOOK_SECRET` | Only for webhook/Vercel deployment | Rejects fake requests sent to your public webhook URL |
