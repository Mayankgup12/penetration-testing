"""Flask application factory."""

from __future__ import annotations

import atexit
import logging
import os
from typing import Any

from flask import Flask

from ptf.config import load_config, project_root
from ptf.logging_setup import setup_logging
from ptf.scan_service import shutdown_executor
from ptf.web.routes import bp

logger = logging.getLogger(__name__)


def create_app() -> Flask:
    cfg = load_config()
    setup_logging(cfg)

    app = Flask(
        __name__,
        template_folder=str(project_root() / "templates"),
        static_folder=str(project_root() / "static"),
        static_url_path="/static",
    )

    secret = os.environ.get(
        cfg["app"]["secret_key_env"],
        cfg["app"].get("default_secret_key", "dev"),
    )
    app.secret_key = secret

    app.register_blueprint(bp)

    from werkzeug.exceptions import HTTPException

    @app.errorhandler(Exception)
    def _unhandled(e: Exception) -> Any:
        if isinstance(e, HTTPException):
            return e
        logger.exception("Unhandled error: %s", e)
        from flask import jsonify, render_template

        if app.config.get("JSON_ERRORS"):
            return jsonify(error="internal_error"), 500
        return render_template("error.html", message="Something went wrong."), 500

    atexit.register(shutdown_executor)
    return app
