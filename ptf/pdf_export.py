"""Export scan summary to PDF (bonus)."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _ascii_safe(text: object) -> str:
    return str(text).encode("ascii", "replace").decode("ascii")


def export_scan_pdf(report: dict[str, Any], dest: Path) -> Path:
    try:
        from fpdf import FPDF
    except ImportError as e:
        logger.error("fpdf2 not available: %s", e)
        raise

    meta = report.get("meta", {})
    recon = report.get("recon", {})
    vulns = report.get("vulnerabilities", [])

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, _ascii_safe("PTF Scan Report"), ln=1)
    pdf.set_font("Helvetica", size=11)
    pdf.multi_cell(
        0,
        7,
        _ascii_safe(
            f"Target: {meta.get('target_url', '')}\n"
            f"Scan ID: {meta.get('scan_id', '')}\n"
            f"Completed: {meta.get('completed_at', '')}\n"
        ),
    )
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, _ascii_safe("Reconnaissance"), ln=1)
    pdf.set_font("Helvetica", size=10)
    pdf.multi_cell(
        0,
        6,
        _ascii_safe(
            f"Final URL: {recon.get('final_url')}\n"
            f"Status: {recon.get('status_code')}\n"
            f"IP: {recon.get('ip_address')}\n"
            f"URLs discovered: {len(recon.get('discovered_urls') or [])}\n"
        ),
    )
    pdf.ln(2)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, _ascii_safe("Findings"), ln=1)
    pdf.set_font("Helvetica", size=10)
    if not vulns:
        pdf.multi_cell(0, 6, _ascii_safe("No vulnerabilities recorded."))
    else:
        for i, v in enumerate(vulns, 1):
            line = _ascii_safe(
                f"{i}. [{v.get('severity')}] {v.get('type')}\n"
                f"   URL: {v.get('affected_url')}\n"
                f"   Fix: {v.get('recommendation')}\n\n"
            )
            pdf.multi_cell(0, 5, line)

    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    pdf.output(name=str(tmp))
    tmp.replace(dest)
    return dest
