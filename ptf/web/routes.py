"""HTTP routes for dashboard, scan, reports, auth."""

from __future__ import annotations

import logging
from typing import Any

from flask import (
    Blueprint,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

from ptf.auth import verify_user
from ptf.config import load_config, resolve_path
from ptf.http_client import normalize_target_url
from ptf.pdf_export import export_scan_pdf
from ptf.scan_service import submit_scan
from ptf.storage import get_scan_meta, list_scan_history, load_scan_result

logger = logging.getLogger(__name__)

bp = Blueprint("main", __name__)


def _dashboard_stats(history: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(history)
    completed = sum(1 for h in history if h.get("status") == "completed")
    failed = sum(1 for h in history if h.get("status") == "failed")
    running = sum(1 for h in history if h.get("status") in ("running", "queued"))
    highs = meds = lows = 0
    for h in history:
        s = h.get("summary") or {}
        sev = s.get("severity") or {}
        highs += int(sev.get("High", 0))
        meds += int(sev.get("Medium", 0))
        lows += int(sev.get("Low", 0))
    return {
        "total_scans": total,
        "completed": completed,
        "failed": failed,
        "active": running,
        "findings_high": highs,
        "findings_medium": meds,
        "findings_low": lows,
    }


@bp.route("/")
def index():
    history = list_scan_history(200)
    stats = _dashboard_stats(history)
    return render_template("index.html", history=history, stats=stats)


@bp.route("/login", methods=["GET", "POST"])
def login():
    nxt = request.args.get("next") or url_for("main.index")
    if request.method == "POST":
        user = request.form.get("username", "").strip()
        pw = request.form.get("password", "")
        if verify_user(user, pw):
            session["user"] = user
            flash("Signed in.", "success")
            return redirect(nxt)
        flash("Invalid credentials.", "danger")
    return render_template("login.html", next=nxt)


@bp.route("/logout")
def logout():
    session.pop("user", None)
    flash("Signed out.", "info")
    return redirect(url_for("main.index"))


@bp.route("/history")
def history():
    rows = list_scan_history(200)
    return render_template("history.html", history=rows)


@bp.route("/scan", methods=["POST"])
def start_scan():
    raw = request.form.get("url", "").strip()
    try:
        normalize_target_url(raw)
    except ValueError as e:
        flash(str(e), "danger")
        return redirect(url_for("main.index"))
    scan_id = submit_scan(raw)
    flash("Scan queued. This page refreshes until results are ready.", "success")
    return redirect(url_for("main.scan_status", scan_id=scan_id))


@bp.route("/scan/<scan_id>")
def scan_status(scan_id: str):
    meta = get_scan_meta(scan_id)
    if not meta:
        flash("Scan not found.", "danger")
        return redirect(url_for("main.index"))
    data = load_scan_result(scan_id)
    return render_template("scan_status.html", meta=meta, data=data)


@bp.route("/report/<scan_id>")
def report(scan_id: str):
    data = load_scan_result(scan_id)
    meta = get_scan_meta(scan_id)
    if not data:
        if meta and meta.get("status") in ("queued", "running"):
            return redirect(url_for("main.scan_status", scan_id=scan_id))
        flash("Report not ready or not found.", "warning")
        return redirect(url_for("main.index"))
    return render_template("report.html", report=data, meta=meta)


@bp.route("/api/scan/<scan_id>")
def api_scan(scan_id: str):
    data = load_scan_result(scan_id)
    meta = get_scan_meta(scan_id)
    if not data and not meta:
        return jsonify(error="not_found"), 404
    return jsonify(meta=meta, report=data)


@bp.route("/export/pdf/<scan_id>")
def export_pdf(scan_id: str):
    data = load_scan_result(scan_id)
    if not data:
        flash("No report to export.", "danger")
        return redirect(url_for("main.index"))
    scans = resolve_path(load_config()["storage"]["scans_dir"])
    dest = scans / f"{scan_id}.pdf"
    try:
        export_scan_pdf(data, dest)
        return send_file(dest, as_attachment=True, download_name=f"ptf-report-{scan_id}.pdf")
    except Exception as e:
        logger.exception("PDF export failed")
        flash(f"PDF export failed: {e}", "danger")
        return redirect(url_for("main.report", scan_id=scan_id))


@bp.route("/health")
def health():
    return jsonify(status="ok")
