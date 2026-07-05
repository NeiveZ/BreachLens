# BreachLens

> Defensive exposure toolkit for breach metadata, pwned passwords, authorized local combo files and public-source metadata.

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-557C94?style=flat-square&logo=kalilinux&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

---

## Overview

BreachLens helps analysts check credential-exposure signals without scraping dark-web sources or collecting plaintext leaked data.

It is designed for defensive use, authorized assessments and lab work. It does **not** bypass paid APIs, download raw breach dumps, scrape illicit marketplaces or print plaintext passwords.

The tool works in layers:

| Layer | Cost | API key | What it does |
|---|---:|---:|---|
| Pwned Passwords | Free | No | Checks passwords through k-anonymity; only 5 SHA-1 chars are sent |
| Local combo-scan | Free | No | Parses authorized local `email:password` files and masks passwords |
| GitHub public metadata | Free tier | Optional | Searches public code metadata without downloading raw file contents |
| DNS / crt.sh | Free | No | Checks domain posture and public certificate transparency hostnames |
| HIBP account/domain metadata | Paid/optional | Yes | Official account/domain breach metadata when `HIBP_API_KEY` is configured |

---

## Features

- Organized Rich CLI output with risk summary, coverage table, skipped modules and findings table
- `doctor` command to validate optional API keys and free modules
- `password` command using Pwned Passwords k-anonymity
- `combo-scan` for local authorized combo files with masked passwords
- Optional `--check-passwords` for local combos using k-anonymity only
- `email` command combining optional HIBP, GitHub metadata and local files
- `domain` command for DNS, crt.sh, GitHub metadata and optional HIBP domain checks
- `github` command for public metadata search by domain or e-mail
- `local-scan` for e-mails and secret-like assignments in local authorized files
- JSON, HTML and optional TXT reports
- `.env.example` included
- No raw leaked databases, no dark-web scraping, no plaintext password reporting

---

## Installation

```bash
git clone https://github.com/NeiveZ/BreachLens.git
cd BreachLens
chmod +x breachlens.sh
./breachlens.sh --install
source .venv/bin/activate
breachlens doctor
```

Manual install:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .
cp .env.example .env
breachlens doctor
```

---

## Configuration

Copy the example environment file:

```bash
cp .env.example .env
nano .env
```

Optional values:

```env
HIBP_API_KEY=
GITHUB_TOKEN=
BREACHLENS_TIMEOUT=20
BREACHLENS_REPORT_DIR=reports
```

`HIBP_API_KEY` is optional. Without it, official HIBP account/domain breach metadata is skipped, but free/local modules still work.

`GITHUB_TOKEN` is optional. It improves GitHub API rate limits.

---

## Usage

```text
breachlens [command] [options]
```

Commands:

```text
doctor       Check configuration and module readiness
password     Check one password via Pwned Passwords k-anonymity
combo-scan   Scan authorized local email:password-style files
email        Check an e-mail using optional HIBP, GitHub and local files
domain       Assess a domain using DNS, crt.sh, GitHub and optional HIBP
github       Search public GitHub metadata for a domain or e-mail
local-scan   Scan a local text file for e-mails and secret-like assignments
dns          DNS posture check
crtsh        Certificate Transparency hostname collection
demo         Run bundled safe demo data
```

---

## Examples

### Check configuration

```bash
breachlens doctor
```

### Check a password safely

```bash
breachlens password
```

Or non-interactively for lab/demo only:

```bash
breachlens password -p 'Password123!'
```

BreachLens sends only the first 5 SHA-1 hash characters to Pwned Passwords. It does not send the plaintext password or full hash.

---

### Scan a local authorized combo file

```bash
breachlens combo-scan examples/sample_combos.txt
```

Filter by e-mail:

```bash
breachlens combo-scan combos.txt --email user@example.com
```

Filter by domain:

```bash
breachlens combo-scan combos.txt --domain example.com
```

Check matched local passwords against Pwned Passwords with k-anonymity:

```bash
breachlens combo-scan combos.txt --domain example.com --check-passwords --max-password-checks 25
```

Passwords are always masked in output and reports.

---

### Check an e-mail without paying for HIBP

```bash
breachlens email user@example.com --no-hibp
```

Add authorized local files:

```bash
breachlens email user@example.com --no-hibp --local-file combos.txt
```

If `HIBP_API_KEY` is not configured, the HIBP module is skipped and coverage is clearly marked as limited.

---

### Check an e-mail with HIBP when available

```bash
breachlens email user@example.com
```

If `.env` contains `HIBP_API_KEY`, official HIBP account/paste metadata is queried. Otherwise, the free/local modules still run.

---

### Assess a domain

```bash
breachlens domain example.com
```

With local combo evidence:

```bash
breachlens domain example.com --local-file combos.txt
```

With optional HIBP domain metadata:

```bash
breachlens domain example.com --hibp
```

---

### GitHub public metadata only

```bash
breachlens github example.com
breachlens github user@example.com
```

BreachLens only collects metadata returned by GitHub Code Search. It does not download raw file contents.

---

### Show evidence samples in terminal

```bash
breachlens combo-scan combos.txt --domain example.com --show-evidence
```

---

### Save TXT report too

```bash
breachlens domain example.com --txt
```

JSON and HTML are saved by default for most commands.

---

## Output Style

BreachLens uses the same organized output format across modules:

```text
BreachLens
Target: example.com
Scan type: domain
Risk score: 35/100 — MEDIUM
Findings: 5 HIGH+: 1 MEDIUM: 2 LOW: 1 INFO: 1

Coverage
Module                  Status      Notes
DNS posture             EXECUTED    MX/SPF/DMARC/CAA inventory
GitHub public metadata  EXECUTED    Metadata only; raw contents not downloaded
HIBP domain             SKIPPED     HIBP_API_KEY is not configured

Findings
Severity  Source       Category                 Title
HIGH      Local scan   credential_exposure      Matching credential-like entries found locally
LOW       Coverage     coverage_limit           Limited coverage mode
```

---

## Privacy and Safety Guarantees

- No dark-web scraping
- No bypass of paid APIs
- No raw breach database downloads
- No plaintext passwords in reports
- Pwned Passwords uses k-anonymity
- HIBP account/domain lookup is optional
- Local combo scanning is for authorized files only

---

## Limitations

Without `HIBP_API_KEY`, BreachLens cannot honestly confirm whether an e-mail appears in official HIBP breach metadata. It can still check local authorized files, pwned passwords and public-source metadata.

A result like `No matching local entries found` only means the supplied local files did not contain a match. It does not prove that an account was never exposed.

---

## Legal

For use only on accounts, domains and files you own or have explicit written authorization to assess. Unauthorized collection, possession or use of leaked credentials may be illegal.

---

## License

MIT License.
