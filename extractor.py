from urllib.parse import urlsplit


def _hostname_of(text: str) -> str | None:
    """Best-effort hostname if `text` itself looks like a URL/domain, else None."""
    text = text.strip()
    candidate = text if "://" in text else "//" + text
    host = urlsplit(candidate).hostname
    return host.lower() if host and "." in host else None


def _slice_utf16(text: str, offset: int, length: int) -> str:
    """Telegram entity offset/length are UTF-16 code units, not Python chars.
    Slicing `text` directly misaligns after any emoji/surrogate-pair character."""
    encoded = text.encode("utf-16-le")
    return encoded[offset * 2 : (offset + length) * 2].decode("utf-16-le")


def _with_scheme(url: str) -> str:
    return url if "://" in url else "https://" + url


def extract_links(message) -> list[dict]:
    """Pull every url/text_link entity out of a Telegram message.

    Works on message.entities (plain text) and message.caption_entities
    (media captions) so a hidden hyperlink can't hide behind either.
    Each result also flags `text_mismatch`: True when the *displayed* text
    looks like a domain that differs from where the link actually goes.
    This is the classic disguised-link scam pattern.
    """
    text = message.text or message.caption or ""
    entities = list(message.entities or []) + list(message.caption_entities or [])

    results = []
    for entity in entities:
        if entity.type not in ("url", "text_link"):
            continue
        display = _slice_utf16(text, entity.offset, entity.length)
        target = entity.url if entity.type == "text_link" else _with_scheme(display)

        display_host = _hostname_of(display)
        target_host = urlsplit(target).hostname
        mismatch = bool(
            display_host and target_host and display_host != target_host.lower()
        )

        results.append({"display": display, "url": target, "text_mismatch": mismatch})
    return results
