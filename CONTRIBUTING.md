# Contributing

Thanks for your interest in BreachLens.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

## Quality checks

```bash
pytest -q
ruff check .
```

## Contribution rules

- Keep the project defensive and ethical.
- Do not add modules that download leaked databases or scrape illegal markets.
- Do not add code that prints plaintext credentials.
- Prefer metadata, hashes, redaction, and clear remediation guidance.
- Add tests for new parsing, scoring, and reporting logic.
