from __future__ import annotations

from typing import Any

import httpx

from breachlens.config import Settings
from breachlens.models import Finding
from breachlens.utils import safe_quote

HIBP_BASE_URL = "https://haveibeenpwned.com/api/v3"


class HIBPNotConfigured(RuntimeError):
    """Raised when the HIBP API key is missing."""


def _headers(settings: Settings) -> dict[str, str]:
    if not settings.hibp_api_key:
        raise HIBPNotConfigured("HIBP_API_KEY is not configured.")
    return {
        "hibp-api-key": settings.hibp_api_key,
        "User-Agent": settings.user_agent,
        "Accept": "application/json",
    }


def _http_error_finding(source: str, status_code: int, details: str) -> Finding:
    severity = "medium" if status_code in {401, 403, 429} else "low"
    return Finding(
        source=source,
        category="api_error",
        title=f"API request failed with HTTP {status_code}",
        severity=severity,
        description=details,
        evidence={"status_code": status_code},
        recommendation="Check API key, permissions, rate limits and the provider terms of use.",
    )


async def breached_account(email: str, settings: Settings, truncate: bool = True) -> list[Finding]:
    """Query HIBP breach metadata by account e-mail. Requires an API key."""
    url = f"{HIBP_BASE_URL}/breachedaccount/{safe_quote(email)}"
    params = {"truncateResponse": "true" if truncate else "false", "includeUnverified": "false"}
    async with httpx.AsyncClient(timeout=settings.timeout, headers=_headers(settings)) as client:
        response = await client.get(url, params=params)

    if response.status_code == 404:
        return [
            Finding(
                source="Have I Been Pwned",
                category="breach_metadata",
                title="Account not found in HIBP breach metadata",
                severity="info",
                description="HIBP did not return breach metadata for this account.",
                evidence={"status_code": 404},
            )
        ]
    if response.status_code >= 400:
        return [_http_error_finding("Have I Been Pwned", response.status_code, response.text[:500])]

    breaches: list[dict[str, Any]] = response.json()
    findings: list[Finding] = []
    for breach in breaches:
        name = breach.get("Name", "Unknown breach")
        data_classes = breach.get("DataClasses", [])
        severity = "high" if any(str(x).lower() in {"passwords", "password hints"} for x in data_classes) else "medium"
        findings.append(
            Finding(
                source="Have I Been Pwned",
                category="breach_metadata",
                title=f"Account present in breach metadata: {name}",
                severity=severity,
                description=(
                    "The queried account appeared in breach metadata. BreachLens does not collect or display "
                    "plaintext passwords or raw leaked data."
                ),
                evidence=breach,
                recommendation=(
                    "Review password reuse risk, enforce password rotation where appropriate, validate MFA, "
                    "and inspect recent login activity."
                ),
            )
        )
    return findings


async def paste_account(email: str, settings: Settings) -> list[Finding]:
    """Query HIBP paste metadata by account e-mail. Requires an API key."""
    url = f"{HIBP_BASE_URL}/pasteaccount/{safe_quote(email)}"
    async with httpx.AsyncClient(timeout=settings.timeout, headers=_headers(settings)) as client:
        response = await client.get(url)

    if response.status_code == 404:
        return []
    if response.status_code >= 400:
        return [_http_error_finding("Have I Been Pwned - Pastes", response.status_code, response.text[:500])]

    pastes: list[dict[str, Any]] = response.json()
    return [
        Finding(
            source="Have I Been Pwned - Pastes",
            category="paste_exposure",
            title=f"Account mentioned in paste source: {paste.get('Source', 'Unknown source')}",
            severity="high",
            description="The account appeared in paste metadata indexed by HIBP.",
            evidence=paste,
            recommendation="Review exposure context, rotate affected credentials and investigate related accounts.",
        )
        for paste in pastes
    ]


async def breached_domain(domain: str, settings: Settings) -> list[Finding]:
    """Query HIBP breach metadata by verified domain. Requires API key and domain verification."""
    url = f"{HIBP_BASE_URL}/breacheddomain/{safe_quote(domain)}"
    async with httpx.AsyncClient(timeout=settings.timeout, headers=_headers(settings)) as client:
        response = await client.get(url)

    if response.status_code == 404:
        return [
            Finding(
                source="Have I Been Pwned",
                category="domain_breach_metadata",
                title="Domain not found in HIBP breach metadata",
                severity="info",
                description="HIBP did not return breached aliases for this domain.",
                evidence={"status_code": 404},
            )
        ]
    if response.status_code >= 400:
        return [_http_error_finding("Have I Been Pwned", response.status_code, response.text[:500])]

    data: dict[str, list[str]] = response.json()
    findings: list[Finding] = []
    for alias, breaches in data.items():
        findings.append(
            Finding(
                source="Have I Been Pwned",
                category="domain_breach_metadata",
                title=f"Domain alias appeared in breach metadata: {alias}@{domain}",
                severity="high" if len(breaches) >= 3 else "medium",
                description="A domain alias has historical exposure in breach metadata.",
                evidence={"alias": alias, "breaches": breaches, "breach_count": len(breaches)},
                recommendation="Identify account owner, validate MFA, rotate credentials and review access logs.",
            )
        )
    return findings
