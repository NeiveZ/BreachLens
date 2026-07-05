from pathlib import Path

from breachlens.modules.local_combos import parse_combo_file, scan_combo_file


def test_parse_combo_file(tmp_path: Path):
    sample = tmp_path / "combos.txt"
    sample.write_text("user@example.com:Password123!\ninvalid\nadmin@example.com|Secret456\n", encoding="utf-8")
    entries = parse_combo_file(sample)
    assert len(entries) == 2
    assert entries[0].email == "user@example.com"
    assert entries[0].safe_evidence()["masked_password"].startswith("Pa")


def test_scan_combo_domain_filter_masks(tmp_path: Path):
    sample = tmp_path / "combos.txt"
    sample.write_text("user@example.com:Password123!\nother@test.com:abc123\n", encoding="utf-8")
    findings, matches = scan_combo_file(sample, domain="example.com")
    assert len(matches) == 1
    hit = next(f for f in findings if f.category == "credential_exposure_local")
    assert hit.evidence["matched_combos"] == 1
    assert "Password123" not in str(hit.evidence)
