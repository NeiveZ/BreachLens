from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jinja2 import Template
from pydantic import TypeAdapter

from breachlens.models import ScanResult
from breachlens.scoring import summarize
from breachlens.utils import ensure_dir, safe_filename

HTML_TEMPLATE = Template(
    """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>BreachLens Report - {{ result.target }}</title>
  <style>
    :root { color-scheme: dark; }
    body { margin: 0; font-family: Inter, Arial, sans-serif; background: #0b1020; color: #eef2ff; }
    main { max-width: 1180px; margin: 0 auto; padding: 40px 24px; }
    .hero { border: 1px solid #263554; border-radius: 18px; padding: 28px; background: linear-gradient(135deg, #101a33, #111827); }
    h1 { margin: 0 0 8px; font-size: 32px; }
    .muted { color: #aab6d3; }
    .grid { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 14px; margin: 22px 0; }
    .card { border: 1px solid #263554; border-radius: 14px; padding: 16px; background: #11182a; }
    .value { font-size: 28px; font-weight: 800; }
    table { width: 100%; border-collapse: collapse; overflow: hidden; border-radius: 14px; margin-bottom: 18px; }
    th, td { border-bottom: 1px solid #263554; padding: 12px; text-align: left; vertical-align: top; }
    th { background: #18233b; color: #dbe7ff; }
    tr { background: #10182b; }
    code, pre { background: #080d1a; border: 1px solid #263554; border-radius: 10px; padding: 10px; color: #c7d2fe; overflow-x: auto; }
    .sev-critical { color: #fecaca; font-weight: 800; }
    .sev-high { color: #fed7aa; font-weight: 800; }
    .sev-medium { color: #fde68a; font-weight: 800; }
    .sev-low { color: #bfdbfe; font-weight: 800; }
    .sev-info { color: #bbf7d0; font-weight: 800; }
    @media (max-width: 900px) { .grid { grid-template-columns: 1fr 1fr; } }
  </style>
</head>
<body>
<main>
  <section class="hero">
    <h1>BreachLens Report</h1>
    <p class="muted">Defensive OSINT and exposure assessment report. This report does not include plaintext passwords or raw leaked databases.</p>
    <p><strong>Target:</strong> {{ result.target }}<br><strong>Scan type:</strong> {{ result.scan_type }}<br><strong>Generated:</strong> {{ result.created_at }}</p>
  </section>

  <section class="grid">
    <div class="card"><div class="muted">Risk Score</div><div class="value">{{ summary.score }}/100</div></div>
    <div class="card"><div class="muted">Rating</div><div class="value">{{ summary.rating|upper }}</div></div>
    <div class="card"><div class="muted">Findings</div><div class="value">{{ summary.findings }}</div></div>
    <div class="card"><div class="muted">Skipped</div><div class="value">{{ result.skipped|length }}</div></div>
    <div class="card"><div class="muted">High+</div><div class="value">{{ summary.high_plus }}</div></div>
  </section>

  {% if result.metadata %}
  <section class="card">
    <h2>Metadata</h2>
    <pre>{{ result.metadata | tojson(indent=2) }}</pre>
  </section>
  {% endif %}

  {% if result.skipped %}
  <section class="card">
    <h2>Skipped modules</h2>
    <ul>{% for item in result.skipped %}<li>{{ item }}</li>{% endfor %}</ul>
  </section>
  {% endif %}

  <h2>Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Source</th><th>Category</th><th>Title</th><th>Recommendation</th></tr></thead>
    <tbody>
    {% for finding in result.findings %}
      <tr>
        <td class="sev-{{ finding.severity }}">{{ finding.severity|upper }}</td>
        <td>{{ finding.source }}</td>
        <td>{{ finding.category }}</td>
        <td>{{ finding.title }}</td>
        <td>{{ finding.recommendation or "-" }}</td>
      </tr>
      <tr><td colspan="5"><pre>{{ finding.evidence | tojson(indent=2) }}</pre></td></tr>
    {% endfor %}
    </tbody>
  </table>
</main>
</body>
</html>
"""
)


def _result_to_jsonable(result: ScanResult) -> dict[str, Any]:
    return TypeAdapter(ScanResult).dump_python(result, mode="json")


def write_json(result: ScanResult, output_dir: Path) -> Path:
    ensure_dir(output_dir)
    path = output_dir / safe_filename(result.scan_type, result.target, "json")
    path.write_text(json.dumps(_result_to_jsonable(result), indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def write_html(result: ScanResult, output_dir: Path) -> Path:
    ensure_dir(output_dir)
    path = output_dir / safe_filename(result.scan_type, result.target, "html")
    html = HTML_TEMPLATE.render(result=_result_to_jsonable(result), summary=summarize(result))
    path.write_text(html, encoding="utf-8")
    return path


def write_txt(result: ScanResult, output_dir: Path) -> Path:
    ensure_dir(output_dir)
    path = output_dir / safe_filename(result.scan_type, result.target, "txt")
    summary = summarize(result)
    lines = [
        "BreachLens Report",
        "=================",
        f"Target    : {result.target}",
        f"Scan type : {result.scan_type}",
        f"Generated : {result.created_at}",
        f"Risk      : {summary['score']}/100 - {summary['rating'].upper()}",
        f"Findings  : {summary['findings']}",
        "",
    ]
    if result.skipped:
        lines.append("Skipped modules:")
        for item in result.skipped:
            lines.append(f"- {item}")
        lines.append("")
    lines.append("Findings:")
    for finding in result.findings:
        lines.extend(
            [
                f"[{finding.severity.upper()}] {finding.source} / {finding.category}",
                f"Title: {finding.title}",
                f"Description: {finding.description or '-'}",
                f"Recommendation: {finding.recommendation or '-'}",
                f"Evidence: {json.dumps(finding.evidence, ensure_ascii=False)}",
                "",
            ]
        )
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def pretty_json(result: ScanResult) -> str:
    return json.dumps(_result_to_jsonable(result), indent=2, ensure_ascii=False)
