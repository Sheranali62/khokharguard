"""LocalGuard Antivirus - application settings manager.

JSON-backed settings layered over config/default_config.json so
missing keys fall back to documented defaults. The instance file is
config/settings.json when running from source.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from utils import get_logger, paths

logger = get_logger("settings")


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge *override* into *base* without mutating inputs."""
    result = json.loads(json.dumps(base))  # deep copy
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


class Settings:
    """Thread-safe JSON settings store with default fallbacks."""

    def __init__(self, instance_path: Optional[Path] = None) -> None:
        self._lock = threading.RLock()
        self._instance_path = instance_path or paths.settings_path()
        self._defaults = self._load_defaults()
        self._data: Dict[str, Any] = {}
        self.load()

    # ------------------------------------------------------------------
    # Loading / saving
    # ------------------------------------------------------------------

    def _load_defaults(self) -> Dict[str, Any]:
        """Load bundled default configuration."""
        try:
            return json.loads(paths.default_config_path().read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Could not load default config: %s", exc)
            return {}

    def load(self) -> None:
        """(Re)load settings from disk, merged over defaults."""
        with self._lock:
            data: Dict[str, Any] = {}
            if self._instance_path.exists():
                try:
                    data = json.loads(self._instance_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    logger.error("Settings file corrupt, using defaults: %s", exc)
                    data = {}
            self._data = _deep_merge(self._defaults, data)

    def save(self) -> None:
        """Persist current settings to JSON."""
        with self._lock:
            try:
                self._instance_path.parent.mkdir(parents=True, exist_ok=True)
                self._instance_path.write_text(
                    json.dumps(self._data, indent=2), encoding="utf-8"
                )
            except OSError as exc:
                logger.error("Could not save settings: %s", exc)

    # ------------------------------------------------------------------
    # Access
    # ------------------------------------------------------------------

    def get(self, dotted_key: str, default: Any = None) -> Any:
        """Read a setting via dotted path, e.g. ``protection.usb_autoscan``."""
        with self._lock:
            node: Any = self._data
            for part in dotted_key.split("."):
                if not isinstance(node, dict) or part not in node:
                    return default
                node = node[part]
            return node

    def set(self, dotted_key: str, value: Union[str, int, float, bool, List[Any], Dict[str, Any], None],
            save: bool = True) -> None:
        """Write a setting via dotted path and persist by default."""
        with self._lock:
            parts = dotted_key.split(".")
            node = self._data
            for part in parts[:-1]:
                node = node.setdefault(part, {})
                if not isinstance(node, dict):
                    raise ValueError(f"Setting path conflict at {dotted_key}")
            node[parts[-1]] = value
        if save:
            self.save()

    def as_dict(self) -> Dict[str, Any]:
        """Return a deep copy of all settings."""
        with self._lock:
            return json.loads(json.dumps(self._data))

    def reset_to_defaults(self) -> None:
        """Reset all settings to bundled defaults."""
        with self._lock:
            self._data = json.loads(json.dumps(self._defaults))
        self.save()


# Module-level shared instance (created lazily so imports stay cheap).
_shared: Optional[Settings] = None
_shared_lock = threading.Lock()


def get_settings() -> Settings:
    """Return the shared Settings instance."""
    global _shared
    with _shared_lock:
        if _shared is None:
            _shared = Settings()
        return _shared
