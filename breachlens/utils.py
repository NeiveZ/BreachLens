from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
)


def normalize_domain(domain: str) -> str:
    value = domain.strip().lower()
    value = re.sub(r"^https?://", "", value)
    value = value.split("/")[0].split(":")[0]
    if value.startswith("www."):
        value = value[4:]
    return value.strip(".")


def validate_domain(domain: str) -> str:
    normalized = normalize_domain(domain)
    if not DOMAIN_RE.match(normalized):
        raise ValueError(f"Invalid domain: {domain}")
    return normalized


def validate_email(email: str) -> str:
    value = email.strip().lower()
    if not EMAIL_RE.match(value):
        raise ValueError(f"Invalid e-mail address: {email}")
    return value


def mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    if len(local) <= 2:
        return f"{local[:1]}***@{domain}"
    return f"{local[:2]}***@{domain}"


def mask_password(value: str, visible: int = 2) -> str:
    """Mask a password-like value. Never use for storage of the original secret."""
    if not value:
        return ""
    if len(value) <= visible * 2:
        return "*" * len(value)
    return f"{value[:visible]}{'*' * 8}{value[-visible:]}"


def redact_possible_secret(value: str, visible: int = 4) -> str:
    if not value:
        return ""
    if len(value) <= visible * 2:
        return "*" * len(value)
    return f"{value[:visible]}{'*' * 8}{value[-visible:]}"


def safe_quote(value: str) -> str:
    return quote(value, safe="")


def safe_filename(prefix: str, target: str, ext: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", target).strip("_")[:120]
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{prefix}_{cleaned}_{timestamp}.{ext}"


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def severity_rank(severity: str) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(severity.lower(), 0)
