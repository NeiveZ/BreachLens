from __future__ import annotations

from collections import Counter
from typing import Any

from breachlens.models import ScanResult

SEVERITY_POINTS = {
    "info": 0,
    "low": 5,
    "medium": 15,
    "high": 30,
    "critical": 50,
}


def score_result(result: ScanResult) -> int:
    """Calculate a simple capped risk score from normalized findings."""
    score = sum(SEVERITY_POINTS.get(f.severity, 0) for f in result.findings)
    return min(score, 100)


def rating(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    if score >= 10:
        return "low"
    return "informational"


def summarize(result: ScanResult) -> dict[str, Any]:
    score = score_result(result)
    counts = Counter(f.severity for f in result.findings)
    high_plus = counts.get("high", 0) + counts.get("critical", 0)
    return {
        "score": score,
        "rating": rating(score),
        "findings": len(result.findings),
        "severity_counts": dict(counts),
        "high_plus": high_plus,
    }
