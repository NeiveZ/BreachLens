from __future__ import annotations

import re
from pathlib import Path

from breachlens.models import Finding
from breachlens.utils import redact_possible_secret

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|senha|secret|token|api[_-]?key|client[_-]?secret|access[_-]?key)\b\s*[:=]\s*['\"]?([^'\"\s]{6,})"
)


def scan_text_file(path: Path, max_lines: int = 20000) -> list[Finding]:
    """Scan an analyst-provided local file and mask possible secrets in output."""
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(path)

    findings: list[Finding] = []
    emails: set[str] = set()
    possible_secrets: list[dict[str, str | int]] = []

    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line_no, line in enumerate(handle, start=1):
            if line_no > max_lines:
                break
            emails.update(match.lower() for match in EMAIL_RE.findall(line))
            for match in SECRET_ASSIGNMENT_RE.finditer(line):
                possible_secrets.append(
                    {
                        "line": line_no,
                        "keyword": match.group(1),
                        "masked_value": redact_possible_secret(match.group(2)),
                    }
                )

    if emails:
        findings.append(
            Finding(
                source="Local authorized file scan",
                category="local_osint",
                title=f"E-mail addresses found in local file ({len(emails)})",
                severity="info",
                description="Potential e-mail addresses were found in a local file supplied by the analyst.",
                evidence={"file": str(path), "emails_sample": sorted(emails)[:50], "total": len(emails)},
            )
        )

    if possible_secrets:
        findings.append(
            Finding(
                source="Local authorized file scan",
                category="local_secret_detection",
                title=f"Possible secret assignments found in local file ({len(possible_secrets)})",
                severity="high",
                description="Patterns similar to secret assignments were found. Values are masked by design.",
                evidence={"file": str(path), "matches": possible_secrets[:100]},
                recommendation="Validate false positives, remove real secrets from files and rotate confirmed credentials.",
            )
        )

    if not findings:
        findings.append(
            Finding(
                source="Local authorized file scan",
                category="local_osint",
                title="No simple indicators found",
                severity="info",
                description="No e-mail addresses or simple secret assignment patterns were found within scan limits.",
                evidence={"file": str(path), "max_lines": max_lines},
            )
        )

    return findings
