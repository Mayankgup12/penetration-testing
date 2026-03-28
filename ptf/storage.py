"""Persist scan metadata and full results as JSON."""

from __future__ import annotations

import json
import logging
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ptf.config import load_config, resolve_path

logger = logging.getLogger(__name__)
_lock = threading.Lock()


def scans_dir() -> Path:
    cfg = load_config()
    d = resolve_path(cfg["storage"]["scans_dir"])
    d.mkdir(parents=True, exist_ok=True)
    return d


def index_path() -> Path:
    cfg = load_config()
    p = resolve_path(cfg["storage"].get("scan_history_file", "data/scan_history.json"))
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _read_index() -> list[dict[str, Any]]:
    p = index_path()
    if not p.exists():
        return []
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Could not read scan index: %s", e)
        return []


def _write_index(entries: list[dict[str, Any]]) -> None:
    p = index_path()
    tmp = p.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)
    tmp.replace(p)


def append_scan_meta(
    target_url: str,
    status: str,
    summary: dict[str, Any] | None = None,
) -> str:
    scan_id = uuid.uuid4().hex
    entry = {
        "id": scan_id,
        "target_url": target_url,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "summary": summary or {},
    }
    with _lock:
        entries = _read_index()
        entries.insert(0, entry)
        while len(entries) > 500:
            entries.pop()
        _write_index(entries)
    return scan_id


def update_scan_meta(scan_id: str, **fields: Any) -> None:
    with _lock:
        entries = _read_index()
        for e in entries:
            if e.get("id") == scan_id:
                e.update(fields)
                break
        _write_index(entries)


def save_scan_result(scan_id: str, payload: dict[str, Any]) -> Path:
    path = scans_dir() / f"{scan_id}.json"
    tmp = path.with_suffix(".json.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    tmp.replace(path)
    return path


def load_scan_result(scan_id: str) -> dict[str, Any] | None:
    path = scans_dir() / f"{scan_id}.json"
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error("Failed loading scan %s: %s", scan_id, e)
        return None


def list_scan_history(limit: int = 100) -> list[dict[str, Any]]:
    entries = _read_index()
    return entries[:limit]


def get_scan_meta(scan_id: str) -> dict[str, Any] | None:
    for e in _read_index():
        if e.get("id") == scan_id:
            return e
    return None
