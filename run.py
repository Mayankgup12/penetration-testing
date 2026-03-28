"""Entry point for the Penetration Testing Framework web UI.

By default this uses Waitress, which is suitable for long-running (multi-month)
local or intranet deployments on Windows/Linux. For quick debugging only, set:

  PTF_DEV_SERVER=1

See config.json → "server" for thread counts and timeouts.
"""

from __future__ import annotations

import logging
import os

from ptf.config import load_config
from ptf.web.app import create_app

logger = logging.getLogger(__name__)

app = create_app()


def _use_dev_server() -> bool:
    v = os.environ.get("PTF_DEV_SERVER", "").strip().lower()
    return v in ("1", "true", "yes", "on")


def main() -> None:
    cfg = load_config()
    a = cfg.get("app", {})
    srv = cfg.get("server", {})
    host = "0.0.0.0"
    port = int(os.environ.get("PORT", 10000))
    listen = f"{host}:{port}"

    if _use_dev_server():
        threaded = bool(a.get("threaded", True))
        logger.warning(
            "Using Flask development server (PTF_DEV_SERVER). "
            "Not for long production-style runs."
        )
        app.run(host=host, port=port, threaded=threaded, use_reloader=False)
        return

    if not srv.get("use_waitress", True):
        threaded = bool(a.get("threaded", True))
        app.run(host=host, port=port, threaded=threaded, use_reloader=False)
        return

    try:
        from waitress import serve
    except ImportError as e:
        raise SystemExit(
            "Waitress is required for long-running mode. "
            "Install: pip install waitress\n"
            "Or set PTF_DEV_SERVER=1 for the Flask dev server only."
        ) from e

    threads = int(srv.get("waitress_threads", 8))
    channel_timeout = int(srv.get("waitress_channel_timeout", 120))
    cleanup_interval = int(srv.get("waitress_cleanup_interval", 30))

    logger.info(
        "Starting Waitress on %s (threads=%s). Safe for extended uptime.",
        listen,
        threads,
    )
    serve(
        app,
        listen=listen,
        threads=max(1, threads),
        channel_timeout=channel_timeout,
        cleanup_interval=cleanup_interval,
    )


if __name__ == "__main__":
    main()
