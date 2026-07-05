from __future__ import annotations

from typing import Any

import httpx

from breachlens.config import Settings
from breachlens.models import Finding

GITHUB_CODE_SEARCH_URL = "https://api.github.com/search/code"
SENSITIVE_TERMS = ["password", "passwd", "secret", "token", "api_key", "client_secret", ".env"]


def _headers(settings: Settings) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": settings.user_agent,
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"
    return headers


def _api_error(source: str, status_code: int, body: str) -> list[Finding]:
    severity = "low" if status_code in {401, 403, 429} else "info"
    recommendation = "Configure GITHUB_TOKEN to improve rate limits, reduce frequency and retry later."
    if status_code == 401:
        recommendation = "Check GITHUB_TOKEN. The token was rejected by GitHub."
    return [
        Finding(
            source=source,
            category="api_error",
            title=f"GitHub request failed or was rate-limited: HTTP {status_code}",
            severity=severity,
            description="The public GitHub search request did not complete. BreachLens does not bypass API limits.",
            evidence={"status_code": status_code, "body_sample": body[:500]},
            recommendation=recommendation,
        )
    ]


def _metadata_items(data: dict[str, Any], limit: int) -> list[dict[str, Any]]:
    metadata: list[dict[str, Any]] = []
    for item in data.get("items", [])[:limit]:
        repo = item.get("repository", {}) or {}
        metadata.append(
            {
                "repository": repo.get("full_name"),
                "path": item.get("path"),
                "html_url": item.get("html_url"),
                "score": item.get("score"),
            }
        )
    return metadata


async def github_code_search_metadata(
    query: str,
    settings: Settings,
    *,
    source_label: str = "GitHub Code Search",
    limit: int = 10,
    severity_on_hit: str = "medium",
    category: str = "public_code_search",
) -> list[Finding]:
    """Run GitHub Code Search and return metadata only; never fetch raw file contents."""
    params = {"q": query, "per_page": min(max(limit, 1), 50)}
    async with httpx.AsyncClient(timeout=settings.timeout, headers=_headers(settings)) as client:
        response = await client.get(GITHUB_CODE_SEARCH_URL, params=params)

    if response.status_code >= 400:
        return _api_error(source_label, response.status_code, response.text)

    data: dict[str, Any] = response.json()
    metadata = _metadata_items(data, limit)
    total = int(data.get("total_count", 0) or 0)

    if not metadata:
        return [
            Finding(
                source=source_label,
                category=category,
                title="No public GitHub code search metadata found",
                severity="info",
                description="No public GitHub code search results were returned for the selected query.",
                evidence={"query": query, "total_count": total},
            )
        ]

    return [
        Finding(
            source=source_label,
            category=category,
            title=f"Public GitHub code search metadata found ({len(metadata)} shown)",
            severity=severity_on_hit,
            description=(
                "Public code search returned metadata for files matching the query. "
                "BreachLens intentionally does not download or print raw file contents."
            ),
            evidence={"query": query, "total_count": total, "results": metadata},
            recommendation="Review the public repository metadata and rotate/remove any confirmed exposed secrets.",
        )
    ]


async def search_domain_exposure(domain: str, settings: Settings, limit: int = 10) -> list[Finding]:
    """Search public GitHub Code Search metadata for target domain + sensitive keywords."""
    query = f'"{domain}" ({" OR ".join(SENSITIVE_TERMS)})'
    return await github_code_search_metadata(
        query,
        settings,
        source_label="GitHub Code Search",
        limit=limit,
        severity_on_hit="high",
        category="public_code_search",
    )


async def search_email_exposure(email: str, settings: Settings, limit: int = 10) -> list[Finding]:
    """Search public GitHub Code Search metadata for an exact e-mail address."""
    query = f'"{email}"'
    return await github_code_search_metadata(
        query,
        settings,
        source_label="GitHub Code Search",
        limit=limit,
        severity_on_hit="medium",
        category="public_email_mention",
    )
