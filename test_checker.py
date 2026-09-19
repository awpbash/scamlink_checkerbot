from dataclasses import dataclass

import extractor
import registry
from resolver import ResolveError, _check_host_safe


@dataclass
class FakeEntity:
    type: str
    offset: int
    length: int
    url: str = ""


@dataclass
class FakeMessage:
    text: str = None
    caption: str = None
    entities: list = None
    caption_entities: list = None


def test_registry_suffix_match():
    assert registry.is_trusted("gov.sg")
    assert registry.is_trusted("cdcvouchers.gov.sg")
    assert registry.is_trusted("life.gov.sg")
    assert registry.is_trusted("evil-gov.sg.scam.com") is None
    assert registry.is_trusted("gov.sg.evil.com") is None
    assert registry.is_trusted("random-site.com") is None


def test_registry_finds_lookalike_domain():
    # cdc.g0v.sg substitutes a zero for the "o" in gov.sg
    assert registry.find_lookalike("cdc.g0v.sg")["domain"] == "gov.sg"
    assert registry.find_lookalike("lta.gov.sg") is None  # already trusted, not a look-alike
    assert registry.find_lookalike("random-site.com") is None  # no confusable chars to normalize


def test_registry_finds_impersonation_in_path():
    hostname = "dub.sh"
    url = "https://dub.sh/govbenfits.gov.sg"
    assert registry.find_impersonation_in_path(url, hostname) == "govbenfits.gov.sg"
    # a real gov.sg hostname isn't flagged just because its own path matches
    assert registry.find_impersonation_in_path("https://www.gov.sg/schemes.gov.sg", "www.gov.sg") is None


def test_registry_picks_most_specific_entry():
    # lta.gov.sg should resolve to the LTA entry, not the generic gov.sg fallback,
    # regardless of which one appears first in the registry list.
    assert registry.is_trusted("lta.gov.sg")["name"] == "Land Transport Authority"
    assert registry.is_trusted("www.lta.gov.sg")["name"] == "Land Transport Authority"
    assert registry.is_trusted("mystery-agency.gov.sg")["name"] == "Singapore Government (unlisted agency)"


def test_extractor_plain_url_no_mismatch():
    text = "check https://gov.sg now"
    entities = [FakeEntity(type="url", offset=6, length=len("https://gov.sg"))]
    msg = FakeMessage(text=text, entities=entities)
    [link] = extractor.extract_links(msg)
    assert link["url"] == "https://gov.sg"
    assert link["text_mismatch"] is False


def test_extractor_disguised_text_link_mismatch():
    text = "visit gov.sg for vouchers"
    entities = [FakeEntity(type="text_link", offset=6, length=6, url="https://evil-scam.example")]
    msg = FakeMessage(text=text, entities=entities)
    [link] = extractor.extract_links(msg)
    assert link["display"] == "gov.sg"
    assert link["url"] == "https://evil-scam.example"
    assert link["text_mismatch"] is True


def test_extractor_utf16_offset_after_emoji():
    # "🏠" is a surrogate pair in UTF-16 (2 code units) but 1 Python char, and
    # entity offsets are UTF-16 units, so naive text[offset:] misaligns here.
    text = "🏠 go.gov.sg/ndr2026"
    entities = [FakeEntity(type="url", offset=3, length=len("go.gov.sg/ndr2026"))]
    msg = FakeMessage(text=text, entities=entities)
    [link] = extractor.extract_links(msg)
    assert link["display"] == "go.gov.sg/ndr2026"
    # bare domain (no scheme) must be normalised so the resolver doesn't reject it
    assert link["url"] == "https://go.gov.sg/ndr2026"


def test_extractor_reads_caption_entities_too():
    caption = "gov.sg"
    entities = [FakeEntity(type="text_link", offset=0, length=6, url="https://evil-scam.example")]
    msg = FakeMessage(caption=caption, caption_entities=entities)
    [link] = extractor.extract_links(msg)
    assert link["text_mismatch"] is True


def test_resolver_blocks_private_ip():
    try:
        _check_host_safe("localhost")
    except ResolveError as e:
        assert e.reason == "blocked_internal_address"
    else:
        raise AssertionError("expected localhost to be blocked")


def test_resolver_allows_public_host_shape():
    # 8.8.8.8 is public; just confirms non-private IPs pass without raising.
    _check_host_safe("8.8.8.8")


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_")]
    for test in tests:
        test()
        print(f"ok  {test.__name__}")
    print(f"\n{len(tests)} tests passed")
