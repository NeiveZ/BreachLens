from pathlib import Path

from breachlens.modules.local_indicators import scan_text_file


def test_local_scan_masks_secret(tmp_path: Path):
    sample = tmp_path / "sample.txt"
    sample.write_text('email=user@example.com\nAPI_KEY="abcd1234efgh5678"\n', encoding="utf-8")

    findings = scan_text_file(sample)
    titles = [finding.title for finding in findings]
    assert any("E-mail addresses" in title for title in titles)
    secret_finding = next(f for f in findings if f.category == "local_secret_detection")
    assert secret_finding.evidence["matches"][0]["masked_value"] == "abcd********5678"
