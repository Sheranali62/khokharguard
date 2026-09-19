"""Khokhar & Son's Antivirus - utility package."""

from __future__ import annotations

import logging
from typing import Optional

_EXPOSED = ("paths", "logger", "security_utils", "file_utils", "windows_utils",
            "permissions", "settings", "notify")

__all__ = list(_EXPOSED) + ["get_logger"]


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the khokharguard namespace.

    Importing :mod:`utils` does not import submodules; call
    ``utils.logger.setup_logging()`` early in main to configure output.
    """
    return logging.getLogger(f"khokharguard.{name}")
