import json
import re
from pathlib import Path
from urllib.parse import urlsplit

REGISTRY_PATH = Path(__file__).parent / "registry.json"
_CONFUSABLES = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "8": "b"})
_GOV_SG_LIKE = re.compile(r"[a-z0-9-]+\.gov\.sg", re.IGNORECASE)


def load_registry(path: Path = REGISTRY_PATH) -> list[dict]:
    return json.loads(path.read_text())


def is_trusted(domain: str, registry: list[dict] | None = None) -> dict | None:
    """Return the most specific matching registry entry for `domain`, or None if untrusted.

    "Most specific" = longest domain match, so e.g. lta.gov.sg picks the LTA
    entry over the generic gov.sg fallback regardless of list order.
    """
    registry = registry if registry is not None else load_registry()
    domain = domain.lower().rstrip(".")
    best = None
    for entry in registry:
        d = entry["domain"].lower()
        if (domain == d or domain.endswith("." + d)) and (best is None or len(d) > len(best["domain"])):
            best = entry
    return best


def find_lookalike(domain: str, registry: list[dict] | None = None) -> dict | None:
    """Return the trusted entry `domain` is impersonating via character
    substitution (0/o, 1/l, 3/e, 5/s, 8/b), or None if it isn't a look-alike.

    Only fires when the raw domain isn't already trusted, e.g. cdc.g0v.sg
    normalizes to cdc.gov.sg, which matches the trusted gov.sg entry.
    """
    domain = domain.lower().rstrip(".")
    if is_trusted(domain, registry):
        return None
    normalized = domain.translate(_CONFUSABLES)
    if normalized == domain:
        return None
    return is_trusted(normalized, registry)


def find_impersonation_in_path(url: str, hostname: str | None) -> str | None:
    """Return a `.gov.sg`-looking substring found in the URL's path/query when
    the actual hostname isn't a gov.sg domain. This is the classic trick of hiding a
    shortener behind link text stuffed with a fake-looking gov.sg path.
    """
    if hostname and (hostname == "gov.sg" or hostname.endswith(".gov.sg")):
        return None
    parts = urlsplit(url)
    match = _GOV_SG_LIKE.search(f"{parts.path}?{parts.query}")
    return match.group(0) if match else None
