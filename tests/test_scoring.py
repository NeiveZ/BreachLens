from breachlens.models import Finding, ScanResult
from breachlens.scoring import rating, score_result, summarize


def test_score_result_caps_at_100():
    result = ScanResult(
        target="example.com",
        scan_type="unit",
        findings=[
            Finding(source="x", category="x", title="critical", severity="critical"),
            Finding(source="x", category="x", title="high", severity="high"),
            Finding(source="x", category="x", title="high", severity="high"),
        ],
    )
    assert score_result(result) == 100
    assert summarize(result)["rating"] == "critical"


def test_rating_boundaries():
    assert rating(0) == "informational"
    assert rating(10) == "low"
    assert rating(35) == "medium"
    assert rating(60) == "high"
    assert rating(80) == "critical"
