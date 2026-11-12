"""
Logging utilities for SentryIP with sensitive secret redaction.
"""

from __future__ import annotations

import logging
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path
from sentryip.config import settings

_SENSITIVE_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|token|secret|password|authorization)[\"']?\s*[:=]\s*[\"']?([a-zA-Z0-9_\-\.]{8,})[\"']?"),
    re.compile(r"sk-ant-[a-zA-Z0-9_\-]{20,}"),
    re.compile(r"[a-fA-F0-9]{64}"),  # Standard 64-char API keys (VT, AbuseIPDB, OTX)
]


class SecretRedactionFilter(logging.Filter):
    """Filters log records to redact potential API keys and tokens."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self.redact(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: self.redact(str(v)) for k, v in record.args.items()}
            elif isinstance(record.args, (list, tuple)):
                record.args = tuple(self.redact(str(v)) for v in record.args)
        return True

    @classmethod
    def redact(cls, text: str) -> str:
        res = text
        for pat in _SENSITIVE_PATTERNS:
            res = pat.sub("[REDACTED_SECRET]", res)
        # Explicit redaction for configured keys if present
        for key in [
            settings.anthropic_api_key,
            settings.abuseipdb_api_key,
            settings.vt_api_key,
            settings.ipinfo_token,
            settings.otx_api_key,
        ]:
            if key and len(key) > 6 and key in res:
                res = res.replace(key, f"{key[:3]}...[REDACTED]")
        return res


def setup_logger(name: str = "sentryip") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)
    log_file = settings.home_dir / "logs" / "sentryip.log"

    try:
        handler = RotatingFileHandler(
            log_file,
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        handler.addFilter(SecretRedactionFilter())
        logger.addHandler(handler)
    except Exception:
        # Fallback to null handler if cannot write to filesystem
        logger.addHandler(logging.NullHandler())

    return logger


logger = setup_logger()

