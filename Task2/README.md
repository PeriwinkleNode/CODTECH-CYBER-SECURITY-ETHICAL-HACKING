# 🔍 Web Application Vulnerability Scanner

A Python-based scanner to identify common vulnerabilities in web applications, including SQL Injection, Cross-Site Scripting (XSS), missing security headers, sensitive file exposure, directory traversal, and open redirects.

> ⚠️ **Legal Disclaimer:** Only scan web applications you own or have **explicit written permission** to test. Unauthorized scanning is illegal.

---

## Features

- 💉 **SQL Injection** — Error-based detection via form inputs and URL parameters
- 🧨 **Reflected XSS** — Payload injection into forms and query strings
- 🗂️ **Sensitive File Exposure** — Probes for `.env`, `.git/config`, `wp-config.php`, backup files, etc.
- 🔐 **Missing Security Headers** — Checks for CSP, HSTS, X-Frame-Options, and more
- 📁 **Directory Traversal** — Tests URL parameters for path traversal vulnerabilities
- 🔀 **Open Redirect** — Detects unvalidated redirect parameters
- 🕷️ **Auto Crawler** — Discovers forms and links on the target page automatically

---

## Requirements

- Python 3.10+
- `requests`
- `beautifulsoup4`

---

## Installation

```bash
git clone https://github.com/yourusername/web-vuln-scanner.git
cd web-vuln-scanner
pip install requests beautifulsoup4
```

---

## Usage

```bash
python web_vuln_scanner.py <url> [options]
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--delay` | `0.3` | Seconds between requests |
| `--timeout` | `10` | Request timeout in seconds |
| `--verbose` | off | Show detailed request logs |

### Examples

```bash
# Basic scan
python web_vuln_scanner.py http://testphp.vulnweb.com

# Verbose mode (shows every request)
python web_vuln_scanner.py http://testphp.vulnweb.com --verbose

# Slower, more polite scan
python web_vuln_scanner.py http://testphp.vulnweb.com --delay 1.0

# Longer timeout for slow servers
python web_vuln_scanner.py http://testphp.vulnweb.com --timeout 20
```

---

## Testing

### ⚠️ Only use legal practice targets

Never test against real websites without permission. Use these intentionally vulnerable targets instead:

---

### Option A — Free Online Target (no setup needed)

```bash
python web_vuln_scanner.py http://testphp.vulnweb.com --verbose
```

This site is maintained by Acunetix specifically for scanner testing.

---

### Option B — DVWA via Docker (recommended local setup)

```bash
# Step 1: Start DVWA
docker run -d -p 80:80 vulnerables/web-dvwa

# Step 2: Scan it
python web_vuln_scanner.py http://localhost --verbose
```

---

### Option C — WebGoat via Docker

```bash
# Step 1: Start WebGoat
docker run -d -p 8080:8080 webgoat/goat-and-wolf

# Step 2: Scan it
python web_vuln_scanner.py http://localhost:8080/WebGoat --verbose
```

---

### What to expect in output

```
[CRITICAL] SQL Injection
    URL    : http://testphp.vulnweb.com/search.php
    Detail : Error-based SQLi via payload: '

[HIGH]     Reflected XSS
    URL    : http://testphp.vulnweb.com/search.php
    Detail : Payload reflected in param 'searchFor'

[MEDIUM]   Missing Security Header
    URL    : http://testphp.vulnweb.com
    Detail : Header 'Content-Security-Policy' is absent

[HIGH]     Sensitive File Exposed
    URL    : http://testphp.vulnweb.com/.env
    Detail : HTTP 200 on /.env
```

---

## Severity Levels

| Level | Description |
|-------|-------------|
| `CRITICAL` | Immediate exploitation possible (SQLi, Traversal) |
| `HIGH` | Significant risk (XSS, Open Redirect, Sensitive Files) |
| `MEDIUM` | Security hardening needed (Missing Headers) |
| `LOW` | Minor issues |
| `INFO` | Informational findings |

---

## Checks Performed

| Check | Method |
|-------|--------|
| SQL Injection | Error-string detection in responses |
| Reflected XSS | Payload reflection in HTML response |
| Security Headers | Response header inspection |
| Sensitive Paths | HTTP 200 on known dangerous paths |
| Directory Traversal | `/etc/passwd` signature detection |
| Open Redirect | Redirect destination inspection |

---

## Limitations

- Does not test stored XSS or DOM-based XSS
- SQL injection is error-based only (not blind/time-based)
- Crawls only the home page (one level deep)
- Does not handle authentication/sessions

---

## License

MIT License — free to use and modify.
