"""Configure rotating file + console logging for long-running operation."""

from __future__ import annotations

import logging
import logging.handlers
from typing import Any

from ptf.config import resolve_path


def setup_logging(cfg: dict[str, Any]) -> None:
    log_cfg = cfg.get("logging", {})
    level_name = log_cfg.get("level", "INFO")
    level = getattr(logging, str(level_name).upper(), logging.INFO)

    log_path = resolve_path(log_cfg.get("file", "data/logs/ptf.log"))
    log_path.parent.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(level)
    for h in root.handlers[:]:
        root.removeHandler(h)

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    fh = logging.handlers.RotatingFileHandler(
        log_path,
        maxBytes=int(log_cfg.get("max_bytes", 10 * 1024 * 1024)),
        backupCount=int(log_cfg.get("backup_count", 5)),
        encoding="utf-8",
    )
    fh.setFormatter(fmt)
    fh.setLevel(level)

    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    ch.setLevel(level)

    root.addHandler(fh)
    root.addHandler(ch)

    logging.captureWarnings(True)
