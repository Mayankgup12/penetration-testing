"""Minimal session auth backed by JSON file (bonus)."""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any

from werkzeug.security import check_password_hash, generate_password_hash

from ptf.config import load_config, resolve_path

logger = logging.getLogger(__name__)
_lock = threading.Lock()


def users_file() -> Path:
    cfg = load_config()
    p = resolve_path(cfg["storage"]["users_file"])
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _read_users() -> dict[str, Any]:
    p = users_file()
    if not p.exists():
        default = {
            "admin": {
                "password_hash": generate_password_hash("changeme"),
                "role": "admin",
            }
        }
        _write_users(default)
        logger.warning(
            "Created default user admin/changeme — change password in production."
        )
        return default
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError) as e:
        logger.error("users.json corrupt: %s", e)
        return {}


def _write_users(data: dict[str, Any]) -> None:
    p = users_file()
    tmp = p.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    tmp.replace(p)


def verify_user(username: str, password: str) -> bool:
    if not username or not password:
        return False
    users = _read_users()
    rec = users.get(username)
    if not rec or "password_hash" not in rec:
        return False
    try:
        return check_password_hash(str(rec["password_hash"]), password)
    except Exception:
        logger.exception("Password check failed")
        return False


def set_password(username: str, new_password: str) -> None:
    with _lock:
        users = _read_users()
        if username not in users:
            users[username] = {"role": "user"}
        users[username]["password_hash"] = generate_password_hash(new_password)
        _write_users(users)
