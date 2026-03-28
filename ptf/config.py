"""Load and expose application configuration from config.json."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_CONFIG: dict[str, Any] | None = None
_ROOT = Path(__file__).resolve().parent.parent


def get_config_path() -> Path:
    env = os.environ.get("PTF_CONFIG_PATH")
    if env:
        return Path(env).expanduser().resolve()
    return _ROOT / "config.json"


def load_config(force_reload: bool = False) -> dict[str, Any]:
    global _CONFIG
    if _CONFIG is not None and not force_reload:
        return _CONFIG
    path = get_config_path()
    try:
        with open(path, encoding="utf-8") as f:
            _CONFIG = json.load(f)
    except FileNotFoundError:
        logger.error("config.json not found at %s", path)
        raise
    except json.JSONDecodeError as e:
        logger.error("Invalid JSON in config: %s", e)
        raise
    return _CONFIG


def project_root() -> Path:
    return _ROOT


def resolve_path(relative: str) -> Path:
    p = Path(relative)
    if p.is_absolute():
        return p
    return (_ROOT / p).resolve()
