#!/usr/bin/env python3
"""OOP reflected-XSS and input-reflection scanner for controlled test environments."""
from __future__ import annotations

import argparse
import concurrent.futures
import html
import json
import logging
import re
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import (
    parse_qsl, urlencode, urldefrag, urljoin, urlparse, urlunparse
)

import requests


LOG = logging.getLogger("webvulnscan")


@dataclass(frozen=True)
class ScanConfig:
    target: str
    max_pages: int = 40
    max_depth: int = 2
    workers: int = 4
    delay: float = 0.25
    timeout: float = 8.0
    verify_tls: bool = True
    same_origin_only: bool = True
    user_agent: str = "WebVulnScanner/1.0 (authorized security testing)"


@dataclass
class Finding:
    url: str
    method: str
    parameter: str
    payload: str
    category: str
    evidence: str
    severity: str = "Potential"
    confidence: str = "Medium"
    recommendation: str = (
        "Apply context-aware output encoding; validate input server-side; "
        "avoid inserting untrusted data into HTML/JavaScript contexts."
    )


class LinkParser(HTMLParser):
    """Extract links and forms without executing page content."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._form: Optional[dict] = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag.lower() == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag.lower() == "form":
            self._form = {
                "action": a.get("action", ""),
                "method": (a.get("method") or "get").lower(),
                "inputs": [],
            }
            self.forms.append(self._form)
        elif tag.lower() in {"input", "textarea", "select", "button"} and self._form is not None:
            name = a.get("name")
            if name:
                self._form["inputs"].append({
                    "name": name,
                    "value": a.get("value", ""),
                    "type": a.get("type", "text").lower(),
                })

    def handle_endtag(self, tag):
        if tag.lower() == "form":
            self._form = None


class RateLimiter:
    """Thread-safe minimum interval between request starts."""
    def __init__(self, delay: float):
        self.delay = max(0.0, delay)
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self):
        with self._lock:
            now = time.monotonic()
            wait_for = self.delay - (now - self._last)
            if wait_for > 0:
                time.sleep(wait_for)
            self._last = time.monotonic()


class PayloadLibrary:
    """Non-destructive XSS canaries plus context probes."""
    def __init__(self):
        # Each payload is a harmless proof-of-reflection marker. No network
        # callbacks, data access, persistence, or destructive actions.
        self.payloads = [
            ("marker", "xssprobe_7f3a"),
            ("html_tag", "<xssprobe>probe</xssprobe>"),
            ("attribute_breakout", '" onmouseover="xssprobe'),
            ("script_context_probe", "</script><xssprobe>probe</xssprobe>"),
            ("single_quote_probe", "'xssprobe"),
        ]


class ReflectionAnalyzer:
    """Classifies whether payloads are reflected raw, encoded, or in risky contexts."""
    SCRIPT_RE = re.compile(r"<script\b[^>]*>.*?xssprobe.*?</script\s*>", re.I | re.S)
    EVENT_HANDLER_RE = re.compile(
        r"<[^>]+\bon[a-z]+\s*=\s*['\"][^'\"]*xssprobe", re.I | re.S
    )
    RAW_TAG_RE = re.compile(r"<xssprobe\b[^>]*>.*?</xssprobe\s*>", re.I | re.S)

    def analyze(self, body: str, payload: str) -> Optional[tuple[str, str, str]]:
        if payload not in body:
            # The server may have encoded markup while retaining the marker.
            marker = "xssprobe"
            if marker not in body.lower():
                return None

        lower = body.lower()
        if self.SCRIPT_RE.search(body):
            return ("Executable-looking script context", "High", self._evidence(body, "xssprobe"))
        if self.EVENT_HANDLER_RE.search(body):
            return ("Potential event-handler attribute injection", "High", self._evidence(body, "xssprobe"))
        if self.RAW_TAG_RE.search(body):
            return ("Raw HTML tag reflection", "Medium", self._evidence(body, "xssprobe"))

        escaped = html.escape(payload, quote=True)
        if escaped in body or ("&lt;" in lower and "xssprobe" in lower):
            return ("Reflected but HTML-encoded", "Low", self._evidence(body, "xssprobe"))
        if payload in body or "xssprobe" in lower:
            return ("Input reflected; context requires manual review", "Medium", self._evidence(body, "xssprobe"))
        return None

    @staticmethod
    def _evidence(body: str, needle: str, radius: int = 100) -> str:
        pos = body.lower().find(needle.lower())
        if pos < 0:
            return ""
        snippet = body[max(0, pos-radius): min(len(body), pos+radius)]
        return re.sub(r"\s+", " ", snippet)[:240]


class WebVulnerabilityScanner:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.origin = self._origin(config.target)
        self.limiter = RateLimiter(config.delay)
        self.payloads = PayloadLibrary().payloads
        self.analyzer = ReflectionAnalyzer()
        self.visited: set[str] = set()
        self.findings: list[Finding] = []
        self.errors: list[dict] = []
        self._result_lock = threading.Lock()
        self._session_local = threading.local()

    @staticmethod
    def _origin(url: str) -> tuple[str, str, int]:
        p = urlparse(url)
        default_port = 443 if p.scheme == "https" else 80
        return p.scheme.lower(), (p.hostname or "").lower(), p.port or default_port

    def _session(self) -> requests.Session:
        if not hasattr(self._session_local, "session"):
            s = requests.Session()
            s.headers.update({"User-Agent": self.config.user_agent})
            self._session_local.session = s
        return self._session_local.session

    def _allowed(self, url: str) -> bool:
        p = urlparse(url)
        if p.scheme not in {"http", "https"}:
            return False
        return not self.config.same_origin_only or self._origin(url) == self.origin

    @staticmethod
    def _canonical(url: str) -> str:
        url, _ = urldefrag(url)
        p = urlparse(url)
        # Drop fragments only; retain query parameters because they may be testable.
        return urlunparse((p.scheme, p.netloc, p.path or "/", p.params, p.query, ""))

    def _request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        self.limiter.wait()
        try:
            return self._session().request(
                method, url, timeout=self.config.timeout,
                allow_redirects=True, verify=self.config.verify_tls, **kwargs
            )
        except requests.RequestException as exc:
            with self._result_lock:
                self.errors.append({"url": url, "method": method, "error": str(exc)})
            return None

    def _fetch_page(self, url: str) -> tuple[Optional[str], list[str], list[dict]]:
        response = self._request("GET", url)
        if response is None or response.status_code >= 500:
            return None, [], []
        ctype = response.headers.get("Content-Type", "").lower()
        if "text/html" not in ctype and "<html" not in response.text[:1000].lower():
            return None, [], []
        parser = LinkParser()
        try:
            parser.feed(response.text)
        except Exception:
            pass
        links = []
        for href in parser.links:
            absolute = self._canonical(urljoin(response.url, href))
            if self._allowed(absolute):
                links.append(absolute)
        return response.text, links, parser.forms

    def crawl(self) -> list[tuple[str, str, list[dict]]]:
        queue = deque([(self._canonical(self.config.target), 0)])
        pages: list[tuple[str, str, list[dict]]] = []
        while queue and len(self.visited) < self.config.max_pages:
            url, depth = queue.popleft()
            if url in self.visited or not self._allowed(url):
                continue
            self.visited.add(url)
            body, links, forms = self._fetch_page(url)
            if body is None:
                continue
            pages.append((url, body, forms))
            if depth < self.config.max_depth:
                for link in links:
                    if link not in self.visited and len(self.visited) + len(queue) < self.config.max_pages:
                        queue.append((link, depth + 1))
        return pages

    def _record_response(self, url: str, method: str, parameter: str,
                         payload: str, response: Optional[requests.Response]):
        if response is None:
            return
        result = self.analyzer.analyze(response.text, payload)
        if result is None:
            return
        category, confidence, evidence = result
        # An encoded reflection is recorded as informational, not a confirmed XSS.
        severity = "Informational" if confidence == "Low" else "Potential"
        finding = Finding(
            url=response.url, method=method, parameter=parameter, payload=payload,
            category=category, evidence=evidence, severity=severity, confidence=confidence
        )
        key = (finding.url, finding.method, finding.parameter, finding.payload, finding.category)
        with self._result_lock:
            existing = {
                (f.url, f.method, f.parameter, f.payload, f.category) for f in self.findings
            }
            if key not in existing:
                self.findings.append(finding)

    def _test_query_params(self, url: str):
        parsed = urlparse(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if not pairs:
            return
        for index, (name, old_value) in enumerate(pairs):
            for label, payload in self.payloads:
                changed = list(pairs)
                changed[index] = (name, payload)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path, parsed.params,
                    urlencode(changed, doseq=True), ""
                ))
                response = self._request("GET", test_url)
                self._record_response(test_url, "GET", name, payload, response)

    def _test_forms(self, page_url: str, forms: list[dict]):
        for form in forms:
            action = self._canonical(urljoin(page_url, form.get("action") or page_url))
            if not self._allowed(action):
                continue
            method = form.get("method", "get").upper()
            if method not in {"GET", "POST"}:
                continue
            fields = form.get("inputs", [])
            if not fields:
                continue
            for field_index, field in enumerate(fields):
                name = field["name"]
                if field.get("type") in {"submit", "button", "image", "file", "password"}:
                    continue
                for label, payload in self.payloads:
                    data = {f["name"]: f.get("value", "") for f in fields}
                    data[name] = payload
                    if method == "GET":
                        parsed = urlparse(action)
                        merged = parse_qsl(parsed.query, keep_blank_values=True)
                        merged = [(k, v) for k, v in merged if k not in data]
                        test_url = urlunparse((
                            parsed.scheme, parsed.netloc, parsed.path, parsed.params,
                            urlencode(merged + list(data.items()), doseq=True), ""
                        ))
                        response = self._request("GET", test_url)
                    else:
                        test_url = action
                        response = self._request("POST", action, data=data)
                    self._record_response(test_url, method, name, payload, response)

    def run(self) -> dict:
        LOG.info("Crawling %s (max pages=%d, depth=%d)", self.config.target,
                 self.config.max_pages, self.config.max_depth)
        pages = self.crawl()
        LOG.info("Crawled %d HTML page(s); testing query parameters and forms", len(pages))
        # Page-level parameter probes can run concurrently. A shared rate limiter
        # caps request starts across worker threads.
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, self.config.workers)) as pool:
            futures = [pool.submit(self._test_query_params, url) for url, _, _ in pages]
            for future in futures:
                try:
                    future.result()
                except Exception as exc:
                    self.errors.append({"stage": "query_test", "error": str(exc)})
            futures = [pool.submit(self._test_forms, url, forms) for url, _, forms in pages]
            for future in futures:
                try:
                    future.result()
                except Exception as exc:
                    self.errors.append({"stage": "form_test", "error": str(exc)})
        return {
            "target": self.config.target,
            "scan_time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "pages_crawled": len(pages),
            "config": {
                "max_pages": self.config.max_pages,
                "max_depth": self.config.max_depth,
                "workers": self.config.workers,
                "delay_seconds": self.config.delay,
                "same_origin_only": self.config.same_origin_only,
            },
            "findings": [asdict(f) for f in self.findings],
            "errors": self.errors,
            "limitations": [
                "Static response analysis only; JavaScript is not executed in a browser.",
                "Findings are indicators and require manual validation.",
                "Authenticated flows, JavaScript-generated forms, and DOM-based XSS are not covered.",
            ],
        }


def write_reports(report: dict, output_prefix: str):
    json_path = f"{output_prefix}.json"
    html_path = f"{output_prefix}.html"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    findings = report.get("findings", [])
    rows = []
    for item in findings:
        cells = [
            item.get("severity", ""), item.get("category", ""), item.get("method", ""),
            item.get("url", ""), item.get("parameter", ""), item.get("payload", ""),
            item.get("evidence", ""), item.get("recommendation", ""),
        ]
        rows.append("<tr>" + "".join(
            "<td>" + html.escape(str(cell)) + "</td>" for cell in cells
        ) + "</tr>")
    document = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Web Vulnerability Scan</title>
<style>
body{font:14px system-ui,sans-serif;margin:2rem;color:#222}
table{border-collapse:collapse;width:100%;table-layout:fixed}
th,td{border:1px solid #ccc;padding:.5rem;vertical-align:top;overflow-wrap:anywhere}
th{background:#eee}code{white-space:pre-wrap}
</style></head><body>
<h1>Web Vulnerability Scan Report</h1>
<p><b>Target:</b> """ + html.escape(str(report.get("target", ""))) + """</p>
<p><b>Scan time (UTC):</b> """ + html.escape(str(report.get("scan_time_utc", ""))) + """</p>
<p><b>Pages crawled:</b> """ + str(report.get("pages_crawled", 0)) + """</p>
<p><b>Findings:</b> """ + str(len(findings)) + """</p>
<table><thead><tr><th>Severity</th><th>Category</th><th>Method</th><th>URL</th>
<th>Parameter</th><th>Payload</th><th>Evidence</th><th>Recommendation</th></tr></thead>
<tbody>""" + "".join(rows) + """</tbody></table>
<h2>Limitations</h2><ul>""" + "".join(
        "<li>" + html.escape(str(x)) + "</li>" for x in report.get("limitations", [])
    ) + """</ul>
<h2>Request errors</h2><pre>""" + html.escape(json.dumps(report.get("errors", []), indent=2)) + """</pre>
</body></html>"""
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(document)
    return json_path, html_path


def parse_args():
    parser = argparse.ArgumentParser(
        description="Crawl a controlled web target and detect reflected-XSS/input-reflection indicators."
    )
    parser.add_argument("target", help="Base URL, e.g. http://127.0.0.1:8080/")
    parser.add_argument("--max-pages", type=int, default=40)
    parser.add_argument("--depth", type=int, default=2)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--delay", type=float, default=0.25, help="Minimum seconds between request starts")
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--output", default="scan-report", help="Output prefix for .json and .html reports")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
    parser.add_argument("--allow-external-links", action="store_true",
                        help="Allow crawling outside the starting origin")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    if args.max_pages < 1 or args.depth < 0 or args.workers < 1 or args.delay < 0 or args.timeout <= 0:
        parser.error("max-pages/workers must be >= 1; depth/delay must be >= 0; timeout must be > 0")
    parsed = urlparse(args.target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        parser.error("target must be an absolute http:// or https:// URL")
    return args


def main():
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s"
    )
    config = ScanConfig(
        target=args.target,
        max_pages=args.max_pages,
        max_depth=args.depth,
        workers=args.workers,
        delay=args.delay,
        timeout=args.timeout,
        verify_tls=not args.insecure,
        same_origin_only=not args.allow_external_links,
    )
    scanner = WebVulnerabilityScanner(config)
    report = scanner.run()
    json_path, html_path = write_reports(report, args.output)
    print(f"\nPages crawled: {report['pages_crawled']}")
    print(f"Potential reflection findings: {len(report['findings'])}")
    print(f"Request errors: {len(report['errors'])}")
    print(f"JSON report: {json_path}")
    print(f"HTML report: {html_path}")


if __name__ == "__main__":
    main()
