from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseModel, Field


class Settings(BaseModel):
    """Runtime settings loaded from .env/environment."""

    hibp_api_key: str | None = None
    github_token: str | None = None
    user_agent: str = "BreachLens-Defensive-Exposure-Audit/1.2"
    timeout: float = 20.0
    report_dir: Path = Field(default_factory=lambda: Path("reports"))
    default_json: bool = True
    default_html: bool = True
    default_txt: bool = False


def _float_env(name: str, default: str) -> float:
    try:
        return float(os.getenv(name, default))
    except ValueError:
        return float(default)


def load_settings() -> Settings:
    """Load settings from environment variables and optional .env file."""
    load_dotenv()
    return Settings(
        hibp_api_key=os.getenv("HIBP_API_KEY") or None,
        github_token=os.getenv("GITHUB_TOKEN") or None,
        user_agent=os.getenv("BREACHLENS_USER_AGENT", "BreachLens-Defensive-Exposure-Audit/1.2"),
        timeout=_float_env("BREACHLENS_TIMEOUT", "20"),
        report_dir=Path(os.getenv("BREACHLENS_REPORT_DIR", "reports")),
        default_json=os.getenv("BREACHLENS_DEFAULT_JSON", "true").lower() not in {"0", "false", "no"},
        default_html=os.getenv("BREACHLENS_DEFAULT_HTML", "true").lower() not in {"0", "false", "no"},
        default_txt=os.getenv("BREACHLENS_DEFAULT_TXT", "false").lower() in {"1", "true", "yes"},
    )
