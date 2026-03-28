"""Build HTML report files from scan result dicts."""

from __future__ import annotations

import html
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}


def build_html_report(report: dict[str, Any]) -> str:
    meta = report.get("meta", {})
    recon = report.get("recon", {})
    vulns = list(report.get("vulnerabilities", []))
    vulns.sort(
        key=lambda v: _SEVERITY_ORDER.get(str(v.get("severity", "Low")), 9),
    )

    title = html.escape(str(meta.get("target_url", "Scan Report")))
    rows = []
    for v in vulns:
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(v.get('type', '')))}</td>"
            f"<td><span class='sev sev-{html.escape(str(v.get('severity','')).lower())}'>"
            f"{html.escape(str(v.get('severity', '')))}</span></td>"
            f"<td class='url'>{html.escape(str(v.get('affected_url', '')))}</td>"
            f"<td>{html.escape(str(v.get('evidence', '')))}</td>"
            f"<td>{html.escape(str(v.get('recommendation', '')))}</td>"
            "</tr>"
        )
    disc = recon.get("discovered_urls") or []
    disc_li = "".join(f"<li>{html.escape(u)}</li>" for u in disc[:80])
    if len(disc) > 80:
        disc_li += f"<li>… {len(disc) - 80} more</li>"

    ports = recon.get("ports") or []
    port_rows = "".join(
        "<tr><td>{}</td><td>{}</td></tr>".format(
            html.escape(str(p.get("port", ""))), html.escape(str(p.get("state", "")))
        )
        for p in ports
    )

    err_list = "".join(f"<li>{html.escape(str(e))}</li>" for e in (recon.get("errors") or []))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>PTF Report — {title}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; background: #0f1419; color: #e6edf3; }}
    h1, h2 {{ color: #58a6ff; }}
    table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
    th, td {{ border: 1px solid #30363d; padding: 0.5rem 0.75rem; vertical-align: top; }}
    th {{ background: #161b22; text-align: left; }}
    .url {{ word-break: break-all; font-size: 0.9rem; }}
    .sev-high {{ color: #f85149; font-weight: 600; }}
    .sev-medium {{ color: #d29922; font-weight: 600; }}
    .sev-low {{ color: #8b949e; }}
    .meta {{ color: #8b949e; font-size: 0.95rem; }}
    ul {{ max-height: 20rem; overflow: auto; }}
  </style>
</head>
<body>
  <h1>Penetration Testing Framework — Report</h1>
  <p class="meta">Target: {title}<br/>
  Completed: {html.escape(str(meta.get("completed_at", "")))}<br/>
  Scan ID: {html.escape(str(meta.get("scan_id", "")))}</p>

  <h2>Reconnaissance</h2>
  <p>Final URL: {html.escape(str(recon.get("final_url") or ""))}<br/>
  Status: {html.escape(str(recon.get("status_code") or ""))}<br/>
  IP: {html.escape(str(recon.get("ip_address") or ""))}</p>

  <h3>Open ports (probe)</h3>
  <table><thead><tr><th>Port</th><th>State</th></tr></thead><tbody>{port_rows}</tbody></table>

  <h3>Discovered URLs</h3>
  <ul>{disc_li}</ul>

  <h3>Recon errors</h3>
  <ul>{err_list or "<li>None</li>"}</ul>

  <h2>Vulnerabilities</h2>
  <table>
    <thead><tr><th>Type</th><th>Severity</th><th>Affected URL</th><th>Evidence</th><th>Fix</th></tr></thead>
    <tbody>{"".join(rows) if rows else "<tr><td colspan='5'>No issues reported.</td></tr>"}</tbody>
  </table>
  <p class="meta">Educational use only. Verify findings with manual testing.</p>
</body>
</html>
"""


def write_html_report(path: Path, report: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = build_html_report(report)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)
    return path
