#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

usage() {
  cat <<'EOF'
BreachLens launcher

Usage:
  ./breachlens.sh --install
  ./breachlens.sh --check
  ./breachlens.sh [breachlens arguments]

Examples:
  ./breachlens.sh doctor
  ./breachlens.sh password
  ./breachlens.sh combo-scan examples/sample_combos.txt --domain example.com
EOF
}

if [[ "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "${1:-}" == "--install" ]]; then
  python3 -m venv .venv
  # shellcheck disable=SC1091
  source .venv/bin/activate
  python -m pip install --upgrade pip
  python -m pip install -e .
  [[ -f .env ]] || cp .env.example .env
  echo "[+] Installation complete"
  echo "[*] Activate with: source .venv/bin/activate"
  echo "[*] Run: breachlens doctor"
  exit 0
fi

if [[ "${1:-}" == "--check" ]]; then
  python3 -m py_compile breachlens/*.py breachlens/modules/*.py
  bash -n breachlens.sh breachlens-setup.sh breachlens-demo.sh
  echo "[+] Syntax checks passed"
  exit 0
fi

if [[ -d .venv && -x .venv/bin/python ]]; then
  exec .venv/bin/python -m breachlens.cli "$@"
fi

exec python3 -m breachlens.cli "$@"
