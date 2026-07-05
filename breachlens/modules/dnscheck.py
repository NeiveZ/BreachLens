from __future__ import annotations

import dns.exception
import dns.resolver

from breachlens.models import Finding


def _query(domain: str, record_type: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=8)
        return sorted({str(item).strip().strip('"') for item in answers})
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.resolver.NoNameservers):
        return []


def _txt(domain: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=8)
        values: set[str] = set()
        for item in answers:
            strings = [part.decode("utf-8", errors="ignore") for part in item.strings]
            values.add("".join(strings))
        return sorted(values)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.resolver.NoNameservers):
        return []


def check_dns(domain: str) -> list[Finding]:
    """Check basic DNS posture relevant to external exposure and e-mail security."""
    mx = _query(domain, "MX")
    txt = _txt(domain)
    caa = _query(domain, "CAA")
    dmarc = _txt(f"_dmarc.{domain}")
    spf = [record for record in txt if record.lower().startswith("v=spf1")]

    findings: list[Finding] = [
        Finding(
            source="DNS",
            category="dns_inventory",
            title="DNS inventory collected",
            severity="info",
            description="Basic MX, TXT, SPF, DMARC and CAA data were collected.",
            evidence={"mx": mx, "spf": spf, "dmarc": dmarc, "caa": caa, "txt_count": len(txt)},
            recommendation="Use this inventory to validate external e-mail and certificate posture.",
        )
    ]

    if not mx:
        findings.append(
            Finding(
                source="DNS",
                category="email_security",
                title="No MX records found",
                severity="low",
                description="The domain does not publish MX records. This may be expected for non-mail domains.",
                evidence={"domain": domain},
                recommendation="Confirm whether the domain is expected to receive e-mail.",
            )
        )
    if mx and not spf:
        findings.append(
            Finding(
                source="DNS",
                category="email_security",
                title="SPF record not found",
                severity="medium",
                description="No SPF record was found in domain TXT records.",
                evidence={"domain": domain},
                recommendation="Publish an SPF policy aligned with authorized mail senders.",
            )
        )
    if mx and not dmarc:
        findings.append(
            Finding(
                source="DNS",
                category="email_security",
                title="DMARC record not found",
                severity="medium",
                description="No DMARC TXT record was found at _dmarc.",
                evidence={"domain": domain},
                recommendation="Publish a DMARC policy and progressively move toward quarantine or reject.",
            )
        )
    elif dmarc and any("p=none" in record.lower() for record in dmarc):
        findings.append(
            Finding(
                source="DNS",
                category="email_security",
                title="DMARC policy is monitoring only",
                severity="low",
                description="A DMARC policy with p=none was observed.",
                evidence={"dmarc": dmarc},
                recommendation="Review aggregate reports and plan a move to quarantine or reject when ready.",
            )
        )
    if not caa:
        findings.append(
            Finding(
                source="DNS",
                category="certificate_posture",
                title="CAA record not found",
                severity="low",
                description="No CAA record was found. CAA can restrict which certificate authorities may issue certificates.",
                evidence={"domain": domain},
                recommendation="Consider publishing CAA records if certificate issuance control is required.",
            )
        )

    return findings
