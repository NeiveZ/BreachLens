from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from breachlens.models import Finding
from breachlens.utils import mask_email, mask_password, validate_domain, validate_email

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
# Common combo formats: email:password, email;password, email|password, email,password, email<TAB>password.
COMBO_RE = re.compile(
    r"(?P<email>[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\s*[:;|,\t]\s*(?P<password>[^\s:;|,]{1,256})"
)


@dataclass(slots=True)
class ComboEntry:
    line: int
    email: str
    password: str

    @property
    def domain(self) -> str:
        return self.email.rsplit("@", 1)[-1].lower()

    def safe_evidence(self, show_full_email: bool = False) -> dict[str, str | int]:
        return {
            "line": self.line,
            "email": self.email if show_full_email else mask_email(self.email),
            "domain": self.domain,
            "masked_password": mask_password(self.password),
            "password_length": len(self.password),
        }


def parse_combo_file(path: Path, max_lines: int = 250_000) -> list[ComboEntry]:
    """Parse an authorized local combo file. Raw passwords remain in memory only."""
    entries: list[ComboEntry] = []
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line_no, line in enumerate(handle, start=1):
            if line_no > max_lines:
                break
            match = COMBO_RE.search(line.strip())
            if not match:
                continue
            email = match.group("email").lower()
            password = match.group("password")
            try:
                validate_email(email)
            except ValueError:
                continue
            if password:
                entries.append(ComboEntry(line=line_no, email=email, password=password))
    return entries


def scan_combo_file(
    path: Path,
    *,
    email: str | None = None,
    domain: str | None = None,
    show_full_email: bool = False,
    max_lines: int = 250_000,
) -> tuple[list[Finding], list[ComboEntry]]:
    """Scan a local authorized combo file and return safe findings plus internal entries."""
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(path)

    target_email = validate_email(email) if email else None
    target_domain = validate_domain(domain) if domain else None
    entries = parse_combo_file(path, max_lines=max_lines)

    matches = entries
    scope = "all parsed combos"
    if target_email:
        matches = [entry for entry in entries if entry.email == target_email]
        scope = f"target e-mail {mask_email(target_email)}"
    elif target_domain:
        matches = [entry for entry in entries if entry.domain == target_domain]
        scope = f"target domain {target_domain}"

    findings: list[Finding] = []
    summary_evidence = {
        "file": str(path),
        "scope": scope,
        "parsed_combos": len(entries),
        "matched_combos": len(matches),
        "max_lines": max_lines,
        "passwords_masked": True,
    }

    findings.append(
        Finding(
            source="Local authorized combo scan",
            category="local_combo_inventory",
            title=f"Local combo file parsed ({len(entries)} combo-like line(s))",
            severity="info",
            description="A local analyst-provided file was parsed for common email:password style patterns.",
            evidence=summary_evidence,
            recommendation="Only analyze files you own or are explicitly authorized to review.",
        )
    )

    if matches:
        severity = "high" if target_email else "medium"
        if target_domain and len(matches) >= 10:
            severity = "high"
        findings.append(
            Finding(
                source="Local authorized combo scan",
                category="credential_exposure_local",
                title=f"Matching credential-like entries found locally ({len(matches)})",
                severity=severity,
                description=(
                    "Credential-like entries matching the selected scope were found in the local file. "
                    "Passwords are masked and are not sent to external services by this module."
                ),
                evidence={
                    **summary_evidence,
                    "matches_sample": [entry.safe_evidence(show_full_email=show_full_email) for entry in matches[:100]],
                },
                recommendation="Treat confirmed matches as exposed credentials: rotate passwords, review MFA and audit account activity.",
            )
        )
    else:
        findings.append(
            Finding(
                source="Local authorized combo scan",
                category="credential_exposure_local",
                title="No matching credential-like entries found locally",
                severity="info",
                description="No parsed combo entries matched the selected e-mail/domain scope.",
                evidence=summary_evidence,
            )
        )

    return findings, matches
