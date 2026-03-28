"""Safe, non-destructive checks for common web issues (SQLi/XSS heuristics)."""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ptf.config import load_config
from ptf.http_client import safe_get

logger = logging.getLogger(__name__)

_SQL_ERRORS = (
    "sql syntax",
    "mysql_fetch",
    "mysqli_",
    "postgres query failed",
    "pg_query",
    "warning: sqlite",
    "sqlite_exception",
    "sqlite3.",
    "ora-0",
    "oracle error",
    "driver][sql server",
    "microsoft ole db provider",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "syntax error at or",
)


def _classify_sqli(confidence: str) -> str:
    if confidence == "high":
        return "High"
    if confidence == "medium":
        return "Medium"
    return "Low"


def _classify_xss(reflected: bool, context: str) -> str:
    if reflected and context in ("html", "attr", "js"):
        return "High"
    if reflected:
        return "Medium"
    return "Low"


def _replace_query(url: str, updates: dict[str, str]) -> str:
    p = urlparse(url)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q.update(updates)
    new_q = urlencode(q, doseq=True)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, new_q, p.fragment))


def _get_params(url: str) -> list[str]:
    p = urlparse(url)
    return [k for k, _ in parse_qsl(p.query, keep_blank_values=True)]


def test_sqli_on_url(session: Any, url: str, payloads: list[str]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    params = _get_params(url)
    if not params:
        return findings

    tested = 0
    cfg = load_config()
    max_tests = int(cfg.get("scanner", {}).get("max_param_tests_per_url", 25))

    for param in params:
        if tested >= max_tests:
            break
        for payload in payloads:
            if tested >= max_tests:
                break
            tested += 1
            test_url = _replace_query(url, {param: payload})
            try:
                r = safe_get(session, test_url)
                body = (r.text or "").lower()
                matched = [sig for sig in _SQL_ERRORS if sig in body]
                baseline = safe_get(session, url)
                base_body = (baseline.text or "").lower()
                new_only = [m for m in matched if m not in base_body]
                if new_only:
                    confidence = "high" if len(new_only) >= 2 else "medium"
                    findings.append(
                        {
                            "type": "SQL Injection (heuristic)",
                            "severity": _classify_sqli(confidence),
                            "affected_url": test_url,
                            "parameter": param,
                            "evidence": "Error-style messages after test input: "
                            + ", ".join(new_only[:3]),
                            "recommendation": "Use parameterized queries / prepared statements; "
                            "validate and encode input; apply least-privilege DB accounts.",
                        }
                    )
            except Exception as e:
                logger.debug("SQLi test failed for %s: %s", test_url, e)
    return findings


def test_xss_on_url(session: Any, url: str, payloads: list[str]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    params = _get_params(url)
    if not params:
        return findings

    tested = 0
    cfg = load_config()
    max_tests = int(cfg.get("scanner", {}).get("max_param_tests_per_url", 25))

    for param in params:
        if tested >= max_tests:
            break
        for payload in payloads:
            if tested >= max_tests:
                break
            tested += 1
            marker = f"ptfxss{abs(hash(payload + param)) % 10000}"
            safe_marker_payload = payload.replace("alert(1)", f"alert('{marker}')")
            test_url = _replace_query(url, {param: safe_marker_payload})
            try:
                r = safe_get(session, test_url)
                text = r.text or ""
                if marker in text or payload in text:
                    context = "html"
                    if re.search(r'<[^>]*[\'"][^\'"]*' + re.escape(marker), text):
                        context = "attr"
                    if marker in text and "<script" in text.lower():
                        context = "js"
                    sev = _classify_xss(True, context)
                    findings.append(
                        {
                            "type": "Cross-Site Scripting (reflected, heuristic)",
                            "severity": sev,
                            "affected_url": test_url,
                            "parameter": param,
                            "evidence": "Test payload or marker reflected in response body.",
                            "recommendation": "HTML-encode output by context; use CSP; "
                            "prefer frameworks with auto-escaping; validate input strictly.",
                        }
                    )
            except Exception as e:
                logger.debug("XSS test failed for %s: %s", test_url, e)
    return findings


def test_security_headers(headers: dict[str, str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    hlow = {k.lower(): v for k, v in headers.items()}
    if "x-content-type-options" not in hlow:
        out.append(
            {
                "type": "Missing Security Header",
                "severity": "Low",
                "affected_url": "(response headers)",
                "parameter": "X-Content-Type-Options",
                "evidence": "nosniff not set",
                "recommendation": "Set X-Content-Type-Options: nosniff.",
            }
        )
    if "x-frame-options" not in hlow and "content-security-policy" not in hlow:
        out.append(
            {
                "type": "Clickjacking risk (header)",
                "severity": "Low",
                "affected_url": "(response headers)",
                "parameter": "X-Frame-Options / CSP frame-ancestors",
                "evidence": "No X-Frame-Options or CSP frame control observed",
                "recommendation": "Set X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors.",
            }
        )
    return out


def run_scan(
    session: Any,
    target_url: str,
    discovered_urls: list[str],
    response_headers: dict[str, str],
) -> list[dict[str, Any]]:
    cfg = load_config()
    payloads_sqli = list(cfg.get("scanner", {}).get("sqli_payloads", []))
    payloads_xss = list(cfg.get("scanner", {}).get("xss_payloads", []))

    vulns: list[dict[str, Any]] = []
    vulns.extend(test_security_headers(response_headers))

    urls_to_test = [target_url] + [u for u in discovered_urls if u != target_url]
    seen_pairs: set[tuple[str, str]] = set()

    for u in urls_to_test:
        for item in test_sqli_on_url(session, u, payloads_sqli):
            key = (item["type"], item.get("affected_url", ""), item.get("parameter", ""))
            if key in seen_pairs:
                continue
            seen_pairs.add(key)
            vulns.append(item)
        for item in test_xss_on_url(session, u, payloads_xss):
            key = (item["type"], item.get("affected_url", ""), item.get("parameter", ""))
            if key in seen_pairs:
                continue
            seen_pairs.add(key)
            vulns.append(item)

    return vulns
