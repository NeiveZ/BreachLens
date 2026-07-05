from __future__ import annotations

import asyncio
import getpass
from pathlib import Path
from typing import Annotated

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from breachlens import __version__
from breachlens.config import Settings, load_settings
from breachlens.models import Finding, ScanResult
from breachlens.modules.crtsh import search_certificates
from breachlens.modules.dnscheck import check_dns
from breachlens.modules.github import search_domain_exposure, search_email_exposure
from breachlens.modules.hibp import HIBPNotConfigured, breached_account, breached_domain, paste_account
from breachlens.modules.local_combos import ComboEntry, scan_combo_file
from breachlens.modules.local_indicators import scan_text_file
from breachlens.modules.passwords import check_password
from breachlens.reports import pretty_json, write_html, write_json, write_txt
from breachlens.scoring import summarize
from breachlens.utils import mask_email, validate_domain, validate_email

app = typer.Typer(
    name="breachlens",
    help="Defensive exposure toolkit for breaches, passwords, local combo files and public-source metadata.",
    no_args_is_help=True,
)
console = Console()

SEV_STYLES = {
    "critical": "bold red",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "bold blue",
    "info": "bold cyan",
}


def version_callback(value: bool) -> None:
    if value:
        console.print(f"BreachLens v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool | None = typer.Option(
        None,
        "--version",
        callback=version_callback,
        is_eager=True,
        help="Show the BreachLens version.",
    )
) -> None:
    return None


def _run(coro):
    return asyncio.run(coro)


def _status(value: bool, ok_text: str = "OK", bad_text: str = "MISSING") -> Text:
    return Text(ok_text if value else bad_text, style="bold green" if value else "bold yellow")


def _coverage_table(result: ScanResult) -> None:
    coverage = result.metadata.get("coverage") if isinstance(result.metadata, dict) else None
    if not coverage:
        return
    table = Table(title="Coverage", box=box.SIMPLE_HEAVY)
    table.add_column("Module", style="bold")
    table.add_column("Status")
    table.add_column("Notes")
    for item in coverage:
        status = str(item.get("status", "unknown"))
        style = "green" if status in {"executed", "available"} else "yellow" if status in {"optional", "skipped"} else "red"
        table.add_row(str(item.get("module", "-")), Text(status.upper(), style=style), str(item.get("notes", "-")))
    console.print(table)


def _render_result(result: ScanResult, *, show_evidence: bool = False) -> None:
    summary = summarize(result)
    counts = summary.get("severity_counts", {})
    console.print(
        Panel.fit(
            f"[bold]Target:[/bold] {result.target}\n"
            f"[bold]Scan type:[/bold] {result.scan_type}\n"
            f"[bold]Risk score:[/bold] {summary['score']}/100 — {summary['rating'].upper()}\n"
            f"[bold]Findings:[/bold] {summary['findings']}  "
            f"[red]HIGH+:[/red] {summary.get('high_plus', 0)}  "
            f"[yellow]MEDIUM:[/yellow] {counts.get('medium', 0)}  "
            f"[blue]LOW:[/blue] {counts.get('low', 0)}  "
            f"[cyan]INFO:[/cyan] {counts.get('info', 0)}",
            title="BreachLens",
            border_style="cyan",
        )
    )

    _coverage_table(result)

    if result.skipped:
        skipped = Table(title="Skipped Modules", box=box.SIMPLE_HEAVY)
        skipped.add_column("Reason", style="yellow")
        for item in result.skipped:
            skipped.add_row(item)
        console.print(skipped)

    table = Table(title="Findings", box=box.SIMPLE_HEAVY, show_lines=False)
    table.add_column("Severity", style="bold", no_wrap=True)
    table.add_column("Source", no_wrap=True)
    table.add_column("Category", no_wrap=True)
    table.add_column("Title")
    table.add_column("Recommendation")

    if not result.findings:
        table.add_row("INFO", "BreachLens", "none", "No findings produced", "-")
    else:
        sorted_findings = sorted(
            result.findings,
            key=lambda f: {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(f.severity, 0),
            reverse=True,
        )
        for finding in sorted_findings:
            sev = finding.severity.upper()
            table.add_row(
                Text(sev, style=SEV_STYLES.get(finding.severity, "white")),
                finding.source,
                finding.category,
                finding.title,
                finding.recommendation or "-",
            )
    console.print(table)

    if show_evidence and result.findings:
        ev_table = Table(title="Evidence Samples", box=box.SIMPLE_HEAVY)
        ev_table.add_column("Finding")
        ev_table.add_column("Evidence")
        for finding in result.findings:
            ev_table.add_row(finding.title, str(finding.evidence)[:2000])
        console.print(ev_table)


def _save_reports(result: ScanResult, save_json: bool, save_html: bool, save_txt: bool) -> list[Path]:
    settings = load_settings()
    paths: list[Path] = []
    if save_json:
        paths.append(write_json(result, settings.report_dir))
    if save_html:
        paths.append(write_html(result, settings.report_dir))
    if save_txt:
        paths.append(write_txt(result, settings.report_dir))
    return paths


def _print_saved(paths: list[Path]) -> None:
    for path in paths:
        console.print(f"[green]Saved:[/green] {path}")


def _limited_coverage_finding(reason: str) -> Finding:
    return Finding(
        source="BreachLens Coverage",
        category="coverage_limit",
        title="Limited coverage mode",
        severity="low",
        description=reason,
        evidence={"dark_web_scraping": False, "plaintext_password_collection": False},
        recommendation=(
            "Use local authorized combo files, Pwned Passwords checks and public-source metadata. "
            "Configure HIBP_API_KEY only if you need official HIBP account breach metadata."
        ),
    )


@app.command("doctor")
def doctor_command(
    show_paths: bool = typer.Option(False, "--paths", help="Show resolved report and project paths."),
) -> None:
    """Check configuration, optional API keys and safe/free module availability."""
    settings = load_settings()
    settings.report_dir.mkdir(parents=True, exist_ok=True)

    console.print(Panel.fit("BreachLens configuration and module readiness", title="Doctor", border_style="cyan"))
    table = Table(box=box.SIMPLE_HEAVY)
    table.add_column("Severity", style="bold")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Recommendation")

    table.add_row("INFO", "Pwned Passwords", _status(True, "AVAILABLE"), "No API key required; uses k-anonymity.")
    table.add_row("INFO", "Local combo-scan", _status(True, "AVAILABLE"), "No network required; use only authorized files.")
    table.add_row("INFO", "DNS / crt.sh", _status(True, "AVAILABLE"), "Free public-source checks; network required.")
    table.add_row(
        "LOW" if not settings.github_token else "INFO",
        "GITHUB_TOKEN",
        _status(bool(settings.github_token), "CONFIGURED", "OPTIONAL"),
        "Set GITHUB_TOKEN for better GitHub rate limits." if not settings.github_token else "GitHub token is configured.",
    )
    table.add_row(
        "LOW" if not settings.hibp_api_key else "INFO",
        "HIBP_API_KEY",
        _status(bool(settings.hibp_api_key), "CONFIGURED", "OPTIONAL"),
        "Only needed for HIBP account/domain breach metadata." if not settings.hibp_api_key else "HIBP key is configured.",
    )
    table.add_row("INFO", "Report directory", _status(settings.report_dir.exists(), "WRITABLE"), str(settings.report_dir))
    table.add_row("INFO", ".env.example", _status(Path(".env.example").exists(), "PRESENT"), "Copy to .env and customize if needed.")
    console.print(table)

    if show_paths:
        console.print({"report_dir": str(settings.report_dir.resolve()), "cwd": str(Path.cwd())})


@app.command("password")
def password_command(
    password: str | None = typer.Option(None, "--password", "-p", help="Password to test. Prefer prompt to avoid shell history."),
    save_json: bool = typer.Option(False, "--json", help="Save JSON report to ./reports."),
    save_html: bool = typer.Option(False, "--html", help="Save HTML report to ./reports."),
    save_txt: bool = typer.Option(False, "--txt", help="Save TXT report to ./reports."),
    raw_json: bool = typer.Option(False, "--raw-json", help="Print full JSON to stdout."),
    show_evidence: bool = typer.Option(False, "--show-evidence", help="Print evidence sample table."),
) -> None:
    """Check a password against Pwned Passwords using k-anonymity."""
    settings = load_settings()
    supplied = password or getpass.getpass("Password to check: ")
    if not supplied:
        raise typer.BadParameter("Password cannot be empty.")

    finding = _run(check_password(supplied, settings))
    result = ScanResult(target="<hidden password>", scan_type="password", findings=[finding])
    result.metadata["privacy"] = {
        "password_sent": False,
        "full_hash_sent": False,
        "k_anonymity_prefix_only": True,
    }
    if raw_json:
        console.print(pretty_json(result))
    else:
        _render_result(result, show_evidence=show_evidence)
    _print_saved(_save_reports(result, save_json, save_html, save_txt))


@app.command("combo-scan")
def combo_scan_command(
    path: Annotated[Path, typer.Argument(exists=True, dir_okay=False, readable=True, help="Authorized local combo/text file.")],
    email: str | None = typer.Option(None, "--email", help="Filter a specific e-mail."),
    domain: str | None = typer.Option(None, "--domain", help="Filter a specific domain."),
    show_full_email: bool = typer.Option(False, "--show-full-email", help="Show full e-mails in evidence."),
    check_passwords: bool = typer.Option(False, "--check-passwords", help="Also check matched passwords with Pwned Passwords k-anonymity."),
    max_password_checks: int = typer.Option(25, "--max-password-checks", min=1, max=250, help="Maximum unique passwords to check."),
    save_json: bool = typer.Option(True, "--json/--no-json", help="Save JSON report."),
    save_html: bool = typer.Option(True, "--html/--no-html", help="Save HTML report."),
    save_txt: bool = typer.Option(False, "--txt/--no-txt", help="Save TXT report."),
    raw_json: bool = typer.Option(False, "--raw-json", help="Print full JSON to stdout."),
    show_evidence: bool = typer.Option(False, "--show-evidence", help="Print evidence sample table."),
) -> None:
    """Scan an authorized local combo file. Passwords are masked in output."""
    if email and domain:
        raise typer.BadParameter("Use --email or --domain, not both.")

    settings = load_settings()
    findings, matches = scan_combo_file(path, email=email, domain=domain, show_full_email=show_full_email)
    result = ScanResult(target=str(path), scan_type="combo_scan", findings=findings)
    result.metadata["privacy"] = {"plaintext_passwords_in_reports": False, "external_password_check_default": False}
    result.metadata["coverage"] = [
        {"module": "Local combo parser", "status": "executed", "notes": "No network required; values masked."},
        {"module": "Pwned Passwords", "status": "executed" if check_passwords else "optional", "notes": "Uses k-anonymity only when --check-passwords is set."},
    ]

    if check_passwords and matches:
        unique_passwords: list[str] = []
        seen: set[str] = set()
        for entry in matches:
            if entry.password not in seen:
                seen.add(entry.password)
                unique_passwords.append(entry.password)
            if len(unique_passwords) >= max_password_checks:
                break

        checked = 0
        pwned = 0
        samples: list[dict[str, int | str]] = []
        for pwd in unique_passwords:
            finding = _run(check_password(pwd, settings))
            checked += 1
            count = int(finding.evidence.get("pwned_count", 0) or 0)
            if count > 0:
                pwned += 1
                samples.append({"masked_password": "<masked>", "pwned_count": count, "sha1_prefix": finding.evidence.get("sha1_prefix", "")})
        sev = "high" if pwned else "info"
        result.findings.append(
            Finding(
                source="Have I Been Pwned - Pwned Passwords",
                category="password_exposure_local_combo",
                title=f"Matched local passwords checked with k-anonymity ({checked})",
                severity=sev,
                description="Matched local passwords were checked against Pwned Passwords without sending plaintext or full hashes.",
                evidence={"checked_unique_passwords": checked, "pwned_passwords": pwned, "samples": samples[:25]},
                recommendation="Rotate any confirmed pwned passwords and enforce unique passwords plus MFA.",
            )
        )

    if raw_json:
        console.print(pretty_json(result))
    else:
        _render_result(result, show_evidence=show_evidence)
    _print_saved(_save_reports(result, save_json, save_html, save_txt))


@app.command("email")
def email_command(
    email: str = typer.Argument(..., help="Authorized e-mail address to check."),
    show_full_email: bool = typer.Option(False, "--show-full-email", help="Show full e-mail in reports."),
    hibp: bool = typer.Option(True, "--hibp/--no-hibp", help="Use HIBP if HIBP_API_KEY is configured."),
    github: bool = typer.Option(True, "--github/--no-github", help="Search public GitHub metadata for exact e-mail."),
    local_file: list[Path] = typer.Option([], "--local-file", exists=True, dir_okay=False, readable=True, help="Authorized local combo/text file to search."),
    limit: int = typer.Option(10, "--limit", min=1, max=50, help="GitHub metadata result limit."),
    save_json: bool = typer.Option(True, "--json/--no-json", help="Save JSON report."),
    save_html: bool = typer.Option(True, "--html/--no-html", help="Save HTML report."),
    save_txt: bool = typer.Option(False, "--txt/--no-txt", help="Save TXT report."),
    raw_json: bool = typer.Option(False, "--raw-json", help="Print full JSON to stdout."),
    show_evidence: bool = typer.Option(False, "--show-evidence", help="Print evidence sample table."),
) -> None:
    """Check an e-mail using optional HIBP, public metadata and local authorized files."""
    settings = load_settings()
    checked_email = validate_email(email)
    target = checked_email if show_full_email else mask_email(checked_email)
    result = ScanResult(target=target, scan_type="email")
    result.metadata["coverage"] = []

    if hibp and settings.hibp_api_key:
        result.metadata["coverage"].append({"module": "HIBP account/paste", "status": "executed", "notes": "Official HIBP metadata lookup."})
        try:
            result.findings.extend(_run(breached_account(checked_email, settings)))
            result.findings.extend(_run(paste_account(checked_email, settings)))
        except HIBPNotConfigured:
            result.skipped.append("HIBP account and paste lookup skipped: HIBP_API_KEY is not configured.")
    else:
        reason = "HIBP lookup skipped: HIBP_API_KEY is not configured." if hibp else "HIBP lookup disabled by CLI option."
        result.skipped.append(reason)
        result.metadata["coverage"].append({"module": "HIBP account/paste", "status": "skipped", "notes": reason})
        result.findings.append(_limited_coverage_finding("Official HIBP account breach metadata was not queried."))

    if github:
        result.metadata["coverage"].append({"module": "GitHub public metadata", "status": "executed", "notes": "Metadata only; raw file contents are not downloaded."})
        result.findings.extend(_run(search_email_exposure(checked_email, settings, limit=limit)))
    else:
        result.metadata["coverage"].append({"module": "GitHub public metadata", "status": "skipped", "notes": "Disabled by CLI option."})

    for file_path in local_file:
        findings, _ = scan_combo_file(file_path, email=checked_email, show_full_email=show_full_email)
        result.findings.extend(findings)
        result.metadata["coverage"].append({"module": f"Local file: {file_path}", "status": "executed", "notes": "Authorized local combo scan."})

    if raw_json:
        console.print(pretty_json(result))
    else:
        _render_result(result, show_evidence=show_evidence)
    _print_saved(_save_reports(result, save_json, save_html, save_txt))


@app.command("dns")
def dns_command(
    domain: str = typer.Argument(..., help="Domain to inspect."),
    save_json: bool = typer.Option(True, "--json/--no-json", help="Save JSON report."),
    save_html: bool = typer.Option(True, "--html/--no-html", help="Save HTML report."),
    save_txt: bool = typer.Option(False, "--txt/--no-txt", help="Save TXT report."),
    raw_json: bool = typer.Option(False, "--raw-json", help="Print full JSON to stdout."),
    show_evidence: bool = typer.Option(False, "--show-evidence", help="Print evidence sample table."),
) -> None:
    """Inspect basic DNS posture: MX, TXT, SPF, DMARC and CAA."""
    checked_domain = validate_domain(domain)
    result = ScanResult(target=checked_domain, scan_type="dns", findings=check_dns(checked_domain))
    if raw_json:
        console.print(pretty_json(result))
    else:
        _render_result(result, show_evidence=show_evidence)
    _print_saved(_save_reports(result, save_json, save_html, save_txt))


@app.command("crtsh")
def crtsh_command(
    domain: str = typer.Argument(..., help="Domain to inspect through Certificate Transparency."),
    limit: int = typer.Option(100, "--limit", min=1, max=500, help="Maximum hostnames to show in evidence samples."),
    save_json: bool = typer.Option(True, "--json/--no-json", help="Save JSON report."),
    save_html: bool = typer.Option(True, "--html/--no-html", help="Save HTML report."),
    save_txt: bool = typer.Option(False, "--txt/--no-txt", help="Save TXT report."),
    raw_json: bool = typer.Option(False, "--raw-json", help="Print full JSON to stdout."),
    show_evidence: bool = typer.Option(False, "--show-evidence", help="Print evidence sample table."),
) -> None:
    """Enumerate public hostnames from crt.sh Certificate Transparency records."""
    settings = load_settings()
    checked_domain = validate_domain(domain)
    findings = _run(search_certificates(checked_domain, settings, limit=limit))
    result = ScanResult(target=checked_domain, scan_type="crtsh", findings=findings)
    if raw_json:
        console.print(pretty_json(result))
    else:
        _render_result(result, show_evidence=show_evidence)
    _print_saved(_save_reports(result, save_json, save_html, save_txt))


@app.command("github")
def github_command(
    target: str = typer.Argument(..., help="Domain or e-mail to search in public GitHub code metadata."),
    limit: int = typer.Option(10, "--limit", min=1, max=50, help="Maximum metadata results to include."),
    save_json: bool = typer.Option(True, "--json/--no-json", help="Save JSON report."),
    save_html: bool = typer.Option(True, "--html/--no-html", help="Save HTML report."),
    save_txt: bool = typer.Option(False, "--txt/--no-txt", help="Save TXT report."),
    raw_json: bool = typer.Option(False, "--raw-json", help="Print full JSON to stdout."),
    show_evidence: bool = typer.Option(False, "--show-evidence", help="Print evidence sample table."),
) -> None:
    """Search public GitHub Code Search metadata without downloading raw file contents."""
    settings = load_settings()
    if "@" in target:
        checked = validate_email(target)
        findings = _run(search_email_exposure(checked, settings, limit=limit))
        output_target = mask_email(checked)
    else:
        checked = validate_domain(target)
        findings = _run(search_domain_exposure(checked, settings, limit=limit))
        output_target = checked
    result = ScanResult(target=output_target, scan_type="github", findings=findings)
    result.metadata["privacy"] = {"raw_file_contents_downloaded": False, "metadata_only": True}
    if raw_json:
        console.print(pretty_json(result))
    else:
        _render_result(result, show_evidence=show_evidence)
    _print_saved(_save_reports(result, save_json, save_html, save_txt))


@app.command("local-scan")
def local_scan_command(
    path: Annotated[Path, typer.Argument(exists=True, dir_okay=False, readable=True, help="Authorized local text file to inspect.")],
    save_json: bool = typer.Option(True, "--json/--no-json", help="Save JSON report."),
    save_html: bool = typer.Option(True, "--html/--no-html", help="Save HTML report."),
    save_txt: bool = typer.Option(False, "--txt/--no-txt", help="Save TXT report."),
    raw_json: bool = typer.Option(False, "--raw-json", help="Print full JSON to stdout."),
    show_evidence: bool = typer.Option(False, "--show-evidence", help="Print evidence sample table."),
) -> None:
    """Scan an authorized local file for e-mails and simple secret-like assignments."""
    result = ScanResult(target=str(path), scan_type="local_scan", findings=scan_text_file(path))
    result.metadata["privacy"] = {"secrets_masked": True}
    if raw_json:
        console.print(pretty_json(result))
    else:
        _render_result(result, show_evidence=show_evidence)
    _print_saved(_save_reports(result, save_json, save_html, save_txt))


@app.command("domain")
def domain_command(
    domain: str = typer.Argument(..., help="Authorized domain to assess."),
    include_hibp: bool = typer.Option(False, "--hibp", help="Also query HIBP domain metadata. Requires verified domain and API key."),
    include_github: bool = typer.Option(True, "--github/--no-github", help="Include GitHub Code Search metadata."),
    include_crtsh: bool = typer.Option(True, "--crtsh/--no-crtsh", help="Include crt.sh Certificate Transparency data."),
    local_file: list[Path] = typer.Option([], "--local-file", exists=True, dir_okay=False, readable=True, help="Authorized local combo file to filter by domain."),
    limit: int = typer.Option(25, "--limit", min=1, max=100, help="Evidence sample limit for external modules."),
    save_json: bool = typer.Option(True, "--json/--no-json", help="Save JSON report."),
    save_html: bool = typer.Option(True, "--html/--no-html", help="Save HTML report."),
    save_txt: bool = typer.Option(False, "--txt/--no-txt", help="Save TXT report."),
    raw_json: bool = typer.Option(False, "--raw-json", help="Print full JSON to stdout."),
    show_evidence: bool = typer.Option(False, "--show-evidence", help="Print evidence sample table."),
) -> None:
    """Run a defensive external exposure assessment for a domain."""
    settings = load_settings()
    checked_domain = validate_domain(domain)
    result = ScanResult(target=checked_domain, scan_type="domain")
    result.metadata["coverage"] = []

    result.findings.extend(check_dns(checked_domain))
    result.metadata["coverage"].append({"module": "DNS posture", "status": "executed", "notes": "MX/SPF/DMARC/CAA inventory."})

    if include_crtsh:
        result.findings.extend(_run(search_certificates(checked_domain, settings, limit=limit)))
        result.metadata["coverage"].append({"module": "crt.sh", "status": "executed", "notes": "Public certificate transparency."})
    else:
        result.skipped.append("crt.sh lookup skipped by CLI option.")
        result.metadata["coverage"].append({"module": "crt.sh", "status": "skipped", "notes": "Disabled by CLI option."})

    if include_github:
        result.findings.extend(_run(search_domain_exposure(checked_domain, settings, limit=limit)))
        result.metadata["coverage"].append({"module": "GitHub public metadata", "status": "executed", "notes": "Metadata only; raw file contents are not downloaded."})
    else:
        result.skipped.append("GitHub code search skipped by CLI option.")
        result.metadata["coverage"].append({"module": "GitHub public metadata", "status": "skipped", "notes": "Disabled by CLI option."})

    if include_hibp and settings.hibp_api_key:
        try:
            result.findings.extend(_run(breached_domain(checked_domain, settings)))
            result.metadata["coverage"].append({"module": "HIBP domain", "status": "executed", "notes": "Requires verified domain in HIBP."})
        except HIBPNotConfigured:
            result.skipped.append("HIBP domain lookup skipped: HIBP_API_KEY is not configured.")
    else:
        reason = "HIBP domain lookup disabled. Use --hibp with verified domain and API key." if not include_hibp else "HIBP domain lookup skipped: HIBP_API_KEY is not configured."
        result.skipped.append(reason)
        result.metadata["coverage"].append({"module": "HIBP domain", "status": "skipped", "notes": reason})

    for file_path in local_file:
        findings, _ = scan_combo_file(file_path, domain=checked_domain)
        result.findings.extend(findings)
        result.metadata["coverage"].append({"module": f"Local file: {file_path}", "status": "executed", "notes": "Authorized local combo scan filtered by domain."})

    if raw_json:
        console.print(pretty_json(result))
    else:
        _render_result(result, show_evidence=show_evidence)
    _print_saved(_save_reports(result, save_json, save_html, save_txt))


@app.command("demo")
def demo_command() -> None:
    """Run a safe local demo using bundled sample files."""
    sample = Path(__file__).resolve().parents[1] / "examples" / "sample_indicators.txt"
    combo = Path(__file__).resolve().parents[1] / "examples" / "sample_combos.txt"
    findings = []
    if sample.exists():
        findings.extend(scan_text_file(sample))
    if combo.exists():
        combo_findings, _ = scan_combo_file(combo, domain="example.com")
        findings.extend(combo_findings)
    result = ScanResult(target="bundled examples", scan_type="demo", findings=findings)
    result.metadata["privacy"] = {"demo_data_only": True, "secrets_masked": True}
    _render_result(result, show_evidence=True)
    _print_saved(_save_reports(result, save_json=True, save_html=True, save_txt=True))


if __name__ == "__main__":
    app()
