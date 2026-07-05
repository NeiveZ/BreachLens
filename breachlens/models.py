from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high", "critical"]


class Finding(BaseModel):
    """A normalized security/OSINT finding."""

    source: str
    category: str
    title: str
    severity: Severity = "info"
    description: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    recommendation: str | None = None


class ScanResult(BaseModel):
    """A complete result for one CLI execution."""

    target: str
    scan_type: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    findings: list[Finding] = Field(default_factory=list)
    skipped: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
