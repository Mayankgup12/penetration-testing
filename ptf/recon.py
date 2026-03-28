"""Reconnaissance: headers, DNS/IP, optional port probe, basic crawl."""

from __future__ import annotations

import logging
import socket
from collections import deque
from typing import Any
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from ptf.config import load_config
from ptf.http_client import get_timeout, safe_get, same_registrable_domain

logger = logging.getLogger(__name__)


def _parse_headers(response: Any) -> dict[str, str]:
    return {k: v for k, v in response.headers.items()}


def resolve_ip(host: str) -> str | None:
    host = host.split(":")[0].strip()
    if not host:
        return None
    try:
        return socket.gethostbyname(host)
    except OSError as e:
        logger.info("DNS resolution failed for %s: %s", host, e)
        return None


def probe_open_ports(host: str, ports: list[int], timeout: float) -> list[dict[str, Any]]:
    host = host.split(":")[0]
    results: list[dict[str, Any]] = []
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                results.append({"port": port, "state": "open"})
        except OSError:
            results.append({"port": port, "state": "closed_or_filtered"})
    return results


def extract_links(html: str, base_url: str, target_base: str) -> list[str]:
    out: list[str] = []
    try:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            full = urljoin(base_url, href)
            if not same_registrable_domain(target_base, full):
                continue
            parsed = urlparse(full)
            if parsed.scheme not in ("http", "https"):
                continue
            path = parsed.path or "/"
            clean = f"{parsed.scheme}://{parsed.netloc}{path}"
            if parsed.query:
                clean += f"?{parsed.query}"
            out.append(clean.split("#")[0])
    except Exception as e:
        logger.debug("Link extraction failed: %s", e)
    return out


def crawl(
    session: Any,
    start_url: str,
    max_pages: int,
    max_url_length: int,
) -> tuple[list[str], list[str]]:
    seen: set[str] = set()
    discovered: list[str] = []
    errors: list[str] = []
    q: deque[str] = deque([start_url])

    while q and len(discovered) < max_pages:
        url = q.popleft()
        if url in seen or len(url) > max_url_length:
            continue
        seen.add(url)
        try:
            r = safe_get(session, url)
            if r.ok:
                discovered.append(url)
                for link in extract_links(r.text, r.url, start_url):
                    if link not in seen:
                        q.append(link)
            else:
                errors.append(f"{url} -> HTTP {r.status_code}")
        except Exception as e:
            errors.append(f"{url} -> {type(e).__name__}: {e}")
            logger.debug("Crawl error for %s", url, exc_info=True)

    return discovered, errors


def run_recon(session: Any, target_url: str) -> dict[str, Any]:
    cfg = load_config()
    recon_cfg = cfg.get("recon", {})
    max_pages = int(recon_cfg.get("max_crawl_pages", 40))
    max_len = int(recon_cfg.get("max_url_length", 2048))
    ports = [int(p) for p in recon_cfg.get("common_ports", [80, 443])]
    port_timeout = float(recon_cfg.get("port_scan_timeout", 1.5))

    result: dict[str, Any] = {
        "target_url": target_url,
        "final_url": None,
        "status_code": None,
        "headers": {},
        "server_hint": None,
        "ip_address": None,
        "ports": [],
        "discovered_urls": [],
        "crawl_errors": [],
        "errors": [],
    }

    parsed = urlparse(target_url)
    host = parsed.netloc
    result["ip_address"] = resolve_ip(host)

    try:
        r = safe_get(session, target_url)
        result["final_url"] = r.url
        result["status_code"] = r.status_code
        result["headers"] = _parse_headers(r)
        result["server_hint"] = r.headers.get("Server")
        paths, crawl_errs = crawl(session, r.url, max_pages, max_len)
        result["discovered_urls"] = paths
        result["crawl_errors"] = crawl_errs
    except Exception as e:
        msg = f"Primary request failed: {type(e).__name__}: {e}"
        result["errors"].append(msg)
        logger.warning(msg, exc_info=True)

    if result["ip_address"] and ports:
        try:
            result["ports"] = probe_open_ports(host, ports, port_timeout)
        except Exception as e:
            result["errors"].append(f"Port scan error: {e}")
            logger.debug("Port scan failed", exc_info=True)

    return result
