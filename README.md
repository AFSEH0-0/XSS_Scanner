# Web Vulnerability Scanner

A Python 3, object-oriented scanner for controlled test environments such as DVWA and local training apps. It crawls same-origin HTML pages, probes URL query parameters and basic HTML forms, looks for reflected payloads and risky response contexts, and exports JSON and HTML reports.

## Features

- OOP structure: `WebVulnerabilityScanner`, `ScanConfig`, `Finding`, `PayloadLibrary`, `ReflectionAnalyzer`, `RateLimiter`, and `LinkParser`.
- Data structures: sets for visited URLs, deques for crawl queues, dictionaries for form values/configuration, and dataclasses for findings/configuration.
- Same-origin crawling by default, bounded depth/page count, request timeout, shared rate limiter, and bounded concurrency.
- GET query parameter and basic GET/POST form testing.
- Reports include endpoint, HTTP method, parameter, test payload, evidence snippet, confidence indicator, and remediation.
- No browser execution, external callbacks, credential attacks, or destructive payloads.

## Install on Kali Linux

```bash
sudo apt update
sudo apt install -y python3 python3-venv
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run against a local lab

Start DVWA or your own test application, then run:

```bash
python3 scanner.py http://127.0.0.1/dvwa/ --max-pages 30 --depth 2 --delay 0.3 --workers 4 --output dvwa-report
```

For a local test server on another port:

```bash
python3 scanner.py http://127.0.0.1:8080/ --output local-report
```

Outputs:
- `dvwa-report.json` — machine-readable findings and errors.
- `dvwa-report.html` — human-readable report.

Use `--verbose` for debug logging. Use `--insecure` only for a lab with a self-signed TLS certificate. External crawling is disabled by default; `--allow-external-links` changes that behavior.

## Understanding findings

- **Potential event-handler attribute injection / executable-looking script context**: high-priority indicator, but still requires browser/manual validation.
- **Raw HTML tag reflection**: user input appears to have entered HTML without adequate encoding; assess its actual parsing context.
- **Input reflected; context requires manual review**: reflection was found but static checks cannot determine exploitability.
- **Reflected but HTML-encoded**: usually lower risk in an HTML text context, but context matters.

A reflected string is not automatically XSS. Review the response context and validate in a browser in the lab. The scanner does not execute JavaScript and does not detect all DOM-based or client-side framework issues.

## Limitations

- No login/session workflow configuration; pages behind authentication may not be reached.
- JavaScript-rendered routes/forms and DOM-based XSS are not covered.
- CSRF tokens and unusual form controls may need manual handling.
- Static matching can produce false positives and false negatives.
- Keep page count, depth, concurrency, and delay appropriate for the local lab.
