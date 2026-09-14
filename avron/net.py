"""Outbound proxy for everything this gateway sends.

Both the LLM detection pass and the forward proxy's upstream calls go through
here, so all egress can be pushed out of a single exit IP.

Configured in the console under Network, not the environment: the proxy URL
carries credentials and belongs in the encrypted settings table with the rest of
the secrets.
"""

import logging
from typing import Optional
from urllib.parse import urlsplit

import httpx

import db

logger = logging.getLogger(__name__)


def proxy_url() -> str:
    if db.get_setting("proxy_enabled", "false") != "true":
        return ""
    return db.get_secret("proxy_url")


def bypass_list() -> list:
    raw = db.get_setting(
        "proxy_bypass", "localhost,127.0.0.1,avron"
    )
    return [h.strip().lower() for h in raw.split(",") if h.strip()]


def _bypassed(url: str) -> bool:
    """Internal container-to-container traffic must not take the long way out.

    Sending a sibling container through an external proxy fails in a way that
    looks like a broken network rather than a proxy misconfiguration.
    """
    host = (urlsplit(url).hostname or "").lower()
    if not host:
        return True
    for entry in bypass_list():
        if entry.startswith("."):
            if host.endswith(entry):
                return True
        elif host == entry or host.endswith("." + entry):
            return True
    return False


def client(timeout: float, target_url: str = "") -> httpx.AsyncClient:
    """An httpx client that honours the configured proxy, unless bypassed."""
    proxy = proxy_url()
    if proxy and target_url and _bypassed(target_url):
        proxy = ""
    kwargs = {"timeout": timeout, "trust_env": False}
    if proxy:
        kwargs["proxy"] = proxy
    return httpx.AsyncClient(**kwargs)


async def check(url: Optional[str] = None) -> dict:
    """Report the exit IP, with and without the proxy, so the console can show
    whether egress is actually leaving where you think it is."""
    target = "https://api.ipify.org"
    out = {"proxy_configured": bool(url or proxy_url())}
    try:
        async with httpx.AsyncClient(timeout=20, trust_env=False) as direct:
            out["direct_ip"] = (await direct.get(target)).text.strip()
    except Exception as exc:  # noqa: BLE001
        out["direct_ip"] = f"failed: {exc}"

    proxy = url or proxy_url()
    if not proxy:
        out["proxy_ip"] = ""
        out["ok"] = False
        out["detail"] = "No proxy configured."
        return out
    try:
        async with httpx.AsyncClient(timeout=20, proxy=proxy, trust_env=False) as via:
            out["proxy_ip"] = (await via.get(target)).text.strip()
        out["ok"] = True
        out["detail"] = (
            "Egress is unchanged - the proxy shares this host's address."
            if out["proxy_ip"] == out.get("direct_ip")
            else "Egress is leaving through the proxy."
        )
    except Exception as exc:  # noqa: BLE001
        out["proxy_ip"] = ""
        out["ok"] = False
        out["detail"] = str(exc)
    return out
