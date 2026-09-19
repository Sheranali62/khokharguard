"""Khokhar & Son's Antivirus - logging setup.

Creates logs/khokharguard.log plus a console handler. Provides a log
sanitiser so secrets (passwords, tokens, keys) are never written to
log files, per spec section 36.
"""

from __future__ import annotations

import logging
import logging.handlers
import re
import threading
from pathlib import Path
from typing import Optional

from utils import paths

_LOCK = threading.Lock()
_CONFIGURED = False

# Patterns whose values must never reach a log file.
_SECRET_PATTERNS = [
    re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+"),
    re.compile(r"(?i)(token|api[_-]?key|secret|credential)\s*[:=]\s*\S+"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
]

_REDACTED = "<redacted>"


def sanitize(message: str) -> str:
    """Redact secret-looking fragments from a log message."""
    result = message
    for pattern in _SECRET_PATTERNS:
        result = pattern.sub(_REDACTED, result)
    return result


class SanitizingFilter(logging.Filter):
    """Logging filter that removes sensitive data from records."""

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        try:
            record.msg = sanitize(str(record.msg))
            if record.args:
                record.args = tuple(
                    sanitize(str(a)) if isinstance(a, str) else a for a in record.args
                )
        except Exception:  # never let logging itself crash the app
            pass
        return True


def setup_logging(
    level: int = logging.INFO,
    log_path: Optional[Path] = None,
    console: bool = True,
) -> logging.Logger:
    """Configure the application-wide logger (idempotent)."""
    global _CONFIGURED
    with _LOCK:
        if _CONFIGURED:
            return logging.getLogger("khokharguard")

        if log_path is None:
            log_path = paths.log_file_path()

        logger = logging.getLogger("khokharguard")
        logger.setLevel(logging.DEBUG)
        logger.propagate = False

        fmt = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        sanitizer = SanitizingFilter()

        try:
            file_handler = logging.handlers.RotatingFileHandler(
                log_path, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
            )
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(fmt)
            file_handler.addFilter(sanitizer)
            logger.addHandler(file_handler)
        except OSError:
            # Logging must never crash the app (e.g. read-only dir).
            pass

        if console:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(level)
            console_handler.setFormatter(fmt)
            console_handler.addFilter(sanitizer)
            logger.addHandler(console_handler)

        _CONFIGURED = True
        logger.debug("Logging initialised at %s", log_path)
        return logger


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the khokharguard namespace."""
    return logging.getLogger(f"khokharguard.{name}")
