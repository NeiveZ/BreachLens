#!/usr/bin/env bash
set -euo pipefail
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
[[ -f .env ]] || cp .env.example .env
echo "[+] BreachLens installed. Run: source .venv/bin/activate && breachlens doctor"
