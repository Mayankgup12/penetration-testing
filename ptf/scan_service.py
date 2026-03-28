"""Orchestrate recon + scanning + persistence (runs in background worker)."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

from ptf.config import load_config, resolve_path
from ptf.http_client import build_session, normalize_target_url
from ptf.recon import run_recon
from ptf.reporter import write_html_report
from ptf.scanner import run_scan
from ptf.storage import append_scan_meta, save_scan_result, update_scan_meta

logger = logging.getLogger(__name__)

_executor: ThreadPoolExecutor | None = None


def get_executor() -> ThreadPoolExecutor:
    global _executor
    if _executor is None:
        cfg = load_config()
        workers = int(cfg.get("scan_executor", {}).get("max_workers", 4))
        _executor = ThreadPoolExecutor(max_workers=max(1, workers), thread_name_prefix="ptf_scan")
    return _executor


def _count_severity(vulns: list[dict[str, Any]]) -> dict[str, int]:
    c: dict[str, int] = {"High": 0, "Medium": 0, "Low": 0}
    for v in vulns:
        s = str(v.get("severity", "Low"))
        if s in c:
            c[s] += 1
        else:
            c["Low"] += 1
    return c


def run_full_scan(scan_id: str, raw_target: str) -> None:
    try:
        target = normalize_target_url(raw_target)
    except ValueError as e:
        logger.warning("Invalid target: %s", e)
        update_scan_meta(
            scan_id,
            status="failed",
            error=str(e),
            completed_at=datetime.now(timezone.utc).isoformat(),
        )
        return

    session = build_session(load_config())
    update_scan_meta(scan_id, status="running", target_url=target)

    report: dict[str, Any] = {
        "meta": {
            "scan_id": scan_id,
            "target_url": target,
            "started_at": datetime.now(timezone.utc).isoformat(),
        },
        "recon": {},
        "vulnerabilities": [],
    }
    scan_failed: str | None = None

    try:
        recon = run_recon(session, target)
        report["recon"] = recon
        headers = recon.get("headers") or {}
        final = recon.get("final_url") or target
        discovered = recon.get("discovered_urls") or []
        vulns = run_scan(session, final, discovered, headers)
        report["vulnerabilities"] = vulns
    except Exception as e:
        logger.exception("Scan failed")
        err = f"{type(e).__name__}: {e}"
        report.setdefault("errors", []).append(err)
        scan_failed = err
    finally:
        try:
            session.close()
        except Exception:
            pass

    report["meta"]["completed_at"] = datetime.now(timezone.utc).isoformat()
    summary = {
        "finding_count": len(report.get("vulnerabilities", [])),
        "severity": _count_severity(report.get("vulnerabilities", [])),
        "urls_discovered": len(report.get("recon", {}).get("discovered_urls") or []),
    }
    report["meta"]["summary"] = summary

    try:
        save_scan_result(scan_id, report)
        html_path = resolve_path(load_config()["storage"]["scans_dir"]) / f"{scan_id}.html"
        write_html_report(html_path, report)
        if scan_failed:
            update_scan_meta(
                scan_id,
                status="failed",
                error=scan_failed,
                completed_at=report["meta"]["completed_at"],
                summary=summary,
            )
        else:
            update_scan_meta(
                scan_id,
                status="completed",
                completed_at=report["meta"]["completed_at"],
                summary=summary,
            )
    except Exception as e:
        logger.exception("Saving results failed")
        update_scan_meta(
            scan_id,
            status="failed",
            error=f"save_error:{e}",
            completed_at=datetime.now(timezone.utc).isoformat(),
        )


def submit_scan(raw_target: str) -> str:
    scan_id = append_scan_meta(raw_target.strip(), "queued")
    get_executor().submit(run_full_scan, scan_id, raw_target)
    return scan_id


def shutdown_executor() -> None:
    global _executor
    if _executor:
        _executor.shutdown(wait=False, cancel_futures=False)
        _executor = None
