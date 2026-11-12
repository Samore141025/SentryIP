"""
Configuration management and environment variable loading for SentryIP.
Supports both Gemini (Google GenAI) and Claude (Anthropic).
"""

from __future__ import annotations

import os
from pathlib import Path
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# Load from current directory or environment
load_dotenv(override=False)


class Settings(BaseModel):
    # LLM Provider Keys
    gemini_api_key: str = Field(
        default_factory=lambda: os.getenv("GEMINI_API_KEY", "")
    )
    anthropic_api_key: str = Field(
        default_factory=lambda: os.getenv("ANTHROPIC_API_KEY", "")
    )

    # Model Selection
    gemini_model: str = Field(
        default_factory=lambda: os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    )
    sentryip_model: str = Field(
        default_factory=lambda: os.getenv("SENTRYIP_MODEL", "claude-sonnet-4-5")
    )

    max_steps: int = Field(
        default_factory=lambda: int(os.getenv("SENTRYIP_MAX_STEPS", "15"))
    )

    # Threat Intelligence Provider Keys (Optional)
    abuseipdb_api_key: str = Field(
        default_factory=lambda: os.getenv("ABUSEIPDB_API_KEY", "")
    )
    vt_api_key: str = Field(
        default_factory=lambda: os.getenv("VT_API_KEY", "")
    )
    ipinfo_token: str = Field(
        default_factory=lambda: os.getenv("IPINFO_TOKEN", "")
    )
    otx_api_key: str = Field(
        default_factory=lambda: os.getenv("OTX_API_KEY", "")
    )

    # Directories
    home_dir: Path = Field(
        default_factory=lambda: Path(os.getenv("SENTRYIP_HOME", str(Path.home() / ".sentryip")))
    )
    cache_ttl_hours: int = Field(default=12)
    request_timeout_seconds: float = Field(default=12.0)


settings = Settings()

# Ensure base directories exist
settings.home_dir.mkdir(parents=True, exist_ok=True)
(settings.home_dir / "logs").mkdir(parents=True, exist_ok=True)
