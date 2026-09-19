import ipaddress
import socket
from urllib.parse import urljoin, urlsplit

import httpx

MAX_REDIRECTS = 5
TIMEOUT = 5.0


class ResolveError(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def _check_host_safe(hostname: str) -> None:
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        raise ResolveError("dns_failed")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            raise ResolveError("blocked_internal_address")


async def resolve(url: str) -> dict:
    """Manually follow redirects, validating each hop before connecting.

    Never reads the response body (Phase 1 only needs headers), and rejects
    any hop that resolves to a private/internal IP (SSRF guard).
    Returns {"final_url": str, "hops": [str, ...]} or raises ResolveError.
    """
    hops = []
    current = url
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        for _ in range(MAX_REDIRECTS + 1):
            parts = urlsplit(current)
            if parts.scheme not in ("http", "https"):
                raise ResolveError("unsupported_scheme")
            if not parts.hostname:
                raise ResolveError("no_hostname")
            _check_host_safe(parts.hostname)

            hops.append(current)
            try:
                async with client.stream("GET", current) as response:
                    if not response.is_redirect:
                        return {"final_url": current, "hops": hops}
                    location = response.headers.get("location")
                    if not location:
                        raise ResolveError("redirect_missing_location")
                    current = urljoin(current, location)
            except httpx.HTTPError:
                raise ResolveError("unreachable")
    raise ResolveError("too_many_redirects")
