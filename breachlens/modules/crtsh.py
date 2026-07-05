from __future__ import annotations

import re
from typing import Any

import httpx

from breachlens.config import Settings
from breachlens.models import Finding

CRTSH_URL = "https://crt.sh/"
SENSITIVE_HOST_HINTS = ("admin", "vpn", "dev", "stage", "staging", "test", "mail", "portal", "api", "internal")


def _extract_names(rows: list[dict[str, Any]], domain: str) -> list[str]:
    names: set[str] = set()
    for row in rows:
        value = str(row.get("name_value", ""))
        for item in value.splitlines():
            host = item.strip().lower().lstrip("*.")
            if host.endswith(domain) and re.fullmatch(r"[a-z0-9_.-]+", host):
                names.add(host)
    return sorted(names)


async def search_certificates(domain: str, settings: Settings, limit: int = 100) -> list[Finding]:
    """Search public certificate transparency data through crt.sh JSON output."""
    params = {"q": f"%.{domain}", "output": "json"}
    async with httpx.AsyncClient(timeout=settings.timeout, headers={"User-Agent": settings.user_agent}) as client:
        response = await client.get(CRTSH_URL, params=params)

    if response.status_code >= 400:
        return [
            Finding(
                source="crt.sh",
                category="certificate_transparency",
                title=f"crt.sh request failed with HTTP {response.status_code}",
                severity="low",
                description="The certificate transparency source did not return a usable response.",
                evidence={"status_code": response.status_code, "body_sample": response.text[:300]},
            )
        ]

    try:
        rows: list[dict[str, Any]] = response.json()
    except ValueError:
        return [
            Finding(
                source="crt.sh",
                category="certificate_transparency",
                title="crt.sh returned invalid JSON",
                severity="low",
                description="The service may be temporarily unavailable or rate-limiting requests.",
                evidence={"body_sample": response.text[:300]},
            )
        ]

    names = _extract_names(rows, domain)
    sample = names[:limit]
    findings: list[Finding] = [
        Finding(
            source="crt.sh",
            category="certificate_transparency",
            title=f"Certificate Transparency hostnames collected ({len(names)})",
            severity="info",
            description="Public certificate transparency data was used to enumerate observed hostnames.",
            evidence={"hostnames_sample": sample, "total": len(names)},
            recommendation="Review the discovered hostnames and confirm they belong to the authorized scope.",
        )
    ]

    interesting = [host for host in names if any(hint in host.split(".")[0] for hint in SENSITIVE_HOST_HINTS)]
    if interesting:
        findings.append(
            Finding(
                source="crt.sh",
                category="external_surface",
                title=f"Potentially sensitive hostnames observed ({len(interesting)})",
                severity="medium",
                description="Some public certificate names contain words often associated with sensitive services.",
                evidence={"hostnames_sample": interesting[:limit], "total": len(interesting)},
                recommendation="Validate exposure, access controls and whether these names should remain public.",
            )
        )

    return findings
