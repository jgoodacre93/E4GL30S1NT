"""Breach intelligence provider — HIBP, DeHashed, LeakCheck."""
from __future__ import annotations

import logging
from typing import Any

import requests

from eagleosint.config import settings
from eagleosint.display import (
    BLUE, GREEN, RED, WHITE, YELLOW, SPACE_PREFIX, LINES_SEPARATOR
)
from eagleosint.models import BreachResult
from eagleosint.plugin import BaseProvider, ProviderCategory
from eagleosint.session import session as _session

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# API query functions
# ------------------------------------------------------------------

def _query_hibp(email: str, api_key: str) -> list[BreachResult]:
    """Query Have I Been Pwned API v3.

    HIBP is the gold standard for breach lookups.  The API returns an
    array of breach objects, each describing a single incident where
    this email appeared.  A 404 means the email was NOT found in any
    breach — that's a good thing.

    Rate limit: 1 request per 1.5 seconds (enforced server-side, 429).
    Auth: hibp-api-key header, required since API v3.

    :param email: Email address to query.
    :param api_key: API key for the HIBP service.
    :return: List of BreachResult objects.
    """
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {
        "hibp-api-key": api_key,
        "user-agent": "EagleOSINT-BreachCheck",
        "Accept": "application/json"
    }
    params = {"truncateResponse": "false"}

    try:
        resp = _session.get(url, headers=headers, params=params, timeout=15)

        if resp.status_code == 404:
            return []
        if resp.status_code == 429:
            logger.warning("HIPB rate limit hit, retry later")
            return []
        resp.raise_for_status()

        results = []
        for breach in resp.json():
            results.append(BreachResult(
                query=email,
                source="hibp",
                breach_name=breach.get("Name", "Unknown"),
                breach_date=breach.get("BreachDate"),
                exposed_data=breach.get("DataClasses", []),
                domain=breach.get("Domain"),
                description=breach.get("Description"),
                is_verified=breach.get("IsVerified", True),
                is_sensitive=breach.get("IsSensitive", False),
            ))
        return results

    except requests.exceptions.RequestException as e:
        logger.error("HIPB request failed: %s", e)
        return []


def _query_dehashed(query: str, api_key: str, email: str) -> list[BreachResult]:
    """Query DeHashed API.

    DeHashed is more aggressive than HIBP — it indexes actual leaked
    credentials (hashed passwords, usernames, IPs, names).  Auth uses
    HTTP Basic with your DeHashed account email + API key.

    The search endpoint accepts a query string like:
      email:target@example.com
      username:johndoe
      ip_address:1.2.3.4

    Returns a JSON object with an `entries` array.  Each entry is one
    record from a specific breach database.

    :param query: Query string
    :param api_key: Dehashed API key
    :param email: Email address to search for
    :return: List of BreachResult objects
    """
    url = "https://api.dehashed.com/search"
    params = {"query": f"email:{query}", "size": 100}
    headers = {"Accept": "application/json"}

    try:
        resp = _session.get(
            url, params=params, headers=headers,
            auth=(email, api_key), timeout=15,
        )

        if resp.status_code == 401:
            logger.error("DeHashed: invalid credentials")
            return []
        if resp.status_code == 400:
            logger.warning("DeHashed: bad request for query %r", query)
            return []
        resp.raise_for_status()

        data = resp.json()
        entries = data.get("entries") or []
        results = []
        seen_sources: set[str] = set()

        for entry in entries:
            db_name = entry.get("database_name", "Unknown")
            if db_name in seen_sources:
                continue
            seen_sources.add(db_name)

            exposed = []
            if entry.get("email"):
                exposed.append("Email addresses")
            if entry.get("hashed_password") or entry.get("password"):
                exposed.append("Passwords")
            if entry.get("username"):
                exposed.append("Usernames")
            if entry.get("ip_address"):
                exposed.append("IP addresses")
            if entry.get("name"):
                exposed.append("Names")
            if entry.get("phone"):
                exposed.append("Phone numbers")

            results.append(BreachResult(
                query=query,
                source="dehashed",
                breach_name=db_name,
                exposed_data=exposed,
            ))

        return results

    except requests.exceptions.RequestException as e:
        logger.error("DeHashed request failed: %s", e)
        return []


def _query_leakcheck(query: str, api_key: str) -> list[BreachResult]:
    """

    :param query: Leakcheck query
    :param api_key: Leakcheck API key
    :return: List of BreachResult
    """
    url = "https://leakcheck.io/api/v2/query/{}"
    headers = {
        "X-API-Key": api_key,
        "Accept": "application/json",
    }

    try:
        resp = _session.get(
            url.format(query), headers=headers, timeout=15,
        )

        if resp.status_code == 404:
            return []
        if resp.status_code == 401:
            logger.error("LeakCheck: invalid API key")
            return []
        resp.raise_for_status()

        data = resp.json()
        if not data.get("success"):
            return []

        results = []
        for entry in data.get("result", []):
            sources = entry.get("sources") or []
            if isinstance(sources, list):
                for src in sources:
                    name = src.get("name", "Unknown") if isinstance(src, dict) else str(src)
                    results.append(BreachResult(
                        query=query,
                        source="leakcheck",
                        breach_name=name,
                        breach_date=src.get("date") if isinstance(src, dict) else None,
                    ))
            else:
                results.append(BreachResult(
                    query=query,
                    source="leakcheck",
                    breach_name=str(sources),
                ))

        return results

    except requests.exceptions.RequestException as e:
        logger.error("LeakCheck request failed: %s", e)
        return []


# ------------------------------------------------------------------
# Provider
# ------------------------------------------------------------------

class BreachProvider(BaseProvider):
    name = "breach"
    version = "1.0.0"
    description = "Check email/phone exposure in data breaches"
    category = ProviderCategory.BREACH

    def execute(self, query: str, **kwargs: Any) -> list[BreachResult]:
        query = query.strip().lower()
        all_results: list[BreachResult] = []

        hibp_key = settings.get_key("hibp-api-key")
        if hibp_key:
            all_results.extend(_query_hibp(query, hibp_key))
        else:
            logger.info("HIBP: no API key configured, skipping")

        dehashed_key = settings.get_key("dehashed-api-key")
        dehashed_email = settings.get_key("dehashed-email")
        if dehashed_key and dehashed_email:
            all_results.extend(_query_dehashed(query, dehashed_key, dehashed_email))
        else:
            logger.info("DeHashed: no credentials configured, skipping")

        leakcheck_key = settings.get_key("leakcheck-api-key")
        if leakcheck_key:
            all_results.extend(_query_leakcheck(query, leakcheck_key))
        else:
            logger.info("LeakCheck: no API key configured, skipping")

        if not all_results:
            logger.info("no breach results for %r", query)

        return all_results


# ------------------------------------------------------------------
# Interactive CLI wrapper
# ------------------------------------------------------------------

def breach_check() -> list[BreachResult]:
    """Interactive CLI wrapper for breach intelligence."""
    query = input(
        f"{SPACE_PREFIX}{WHITE}{BLUE}>{WHITE} enter email or phone:{BLUE} "
    ).strip()
    if not query:
        return []

    provider = BreachProvider()
    results: list[BreachResult] = provider.run(query)  # type: ignore[assignment]

    print(f"\n{WHITE}{LINES_SEPARATOR}")

    if not results:
        configured = []
        if settings.get_key("hibp-api-key"):
            configured.append("HIBP")
        if settings.get_key("dehashed-api-key"):
            configured.append("DeHashed")
        if settings.get_key("leakcheck-api-key"):
            configured.append("LeakCheck")

        if configured:
            print(f"{SPACE_PREFIX}{GREEN}no breaches found across {', '.join(configured)}{WHITE}")
        else:
            print(f"{SPACE_PREFIX}{YELLOW}no API keys configured — set them via 'eagleosint settings'{WHITE}")
        print(f"{WHITE}{LINES_SEPARATOR}")
        return []

    sources = sorted(set(r.source for r in results))
    print(f"{SPACE_PREFIX}{RED}found {len(results)} breach(es) via {', '.join(sources)}{WHITE}\n")

    for r in results:
        verified = f"{GREEN}verified{WHITE}" if r.is_verified else f"{YELLOW}unverified{WHITE}"
        sensitive = f" {RED}[sensitive]{WHITE}" if r.is_sensitive else ""

        print(f"{SPACE_PREFIX}{BLUE}breach    :{WHITE} {r.breach_name} [{verified}]{sensitive}")
        if r.breach_date:
            print(f"{SPACE_PREFIX}{BLUE}date      :{WHITE} {r.breach_date}")
        if r.domain:
            print(f"{SPACE_PREFIX}{BLUE}domain    :{WHITE} {r.domain}")
        if r.exposed_data:
            print(f"{SPACE_PREFIX}{BLUE}exposed   :{WHITE} {', '.join(r.exposed_data)}")
        print(f"{SPACE_PREFIX}{BLUE}source    :{WHITE} {r.source}")
        print()

    print(f"{WHITE}{LINES_SEPARATOR}")
    return results