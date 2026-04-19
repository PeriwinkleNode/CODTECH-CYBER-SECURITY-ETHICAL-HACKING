# 🛡️ Penetration Testing Toolkit

A modular, Python-based penetration testing toolkit for security professionals. Includes a port scanner, banner grabber, service detector, network ping sweeper, SSL/TLS checker, HTTP header auditor, and DNS enumerator.

> ⚠️ **Legal Disclaimer:** This toolkit is for **authorized use only**. Only use it on systems you own or have **explicit written permission** to test. Unauthorized use is illegal and unethical.

---

## Modules

| # | Module | Description |
|---|--------|-------------|
| 1 | **Port Scanner** | Threaded TCP connect scan across port ranges |
| 2 | **Banner Grabber** | Retrieves raw service banners from open ports |
| 3 | **Service Detector** | Identifies running services from banner signatures |
| 4 | **Ping Sweeper** | Discovers live hosts on a subnet via ICMP |
| 5 | **SSL/TLS Checker** | Audits certificates, cipher suites, and TLS versions |
| 6 | **HTTP Header Auditor** | Checks for insecure and missing security headers |
| 7 | **DNS Enumerator** | Resolves A, AAAA, MX, NS, TXT, CNAME, SOA records |

---

## Requirements

- Python 3.10+
- `requests`
- `dnspython` *(optional — for full DNS enumeration)*

---

## Installation

```bash
git clone https://github.com/yourusername/pentest-toolkit.git
cd pentest-toolkit
pip install requests dnspython
```

---

## Usage

```bash
python pentest_toolkit.py <module> [target] [options]
```

### Quick Reference

```bash
python pentest_toolkit.py portscan <host> --ports <range>
python pentest_toolkit.py banner   <host> --ports <list>
python pentest_toolkit.py service  <host> --ports <list>
python pentest_toolkit.py sweep    <subnet>
python pentest_toolkit.py ssl      <host> --port <443>
python pentest_toolkit.py headers  <url>
python pentest_toolkit.py dns      <domain>
python pentest_toolkit.py fullscan <host> --ports <range>
```

---

## Testing

### Setup — spin up a local test server

```bash
# Terminal 1: start a test HTTP server
python -m http.server 8080

# Terminal 2: scan it
python pentest_toolkit.py fullscan 127.0.0.1 --ports 8080
```

---

### Module 1 — Port Scanner

```bash
# Scan ports 1–1024 on localhost
python pentest_toolkit.py portscan 127.0.0.1 --ports 1-1024

# Scan specific ports
python pentest_toolkit.py portscan 127.0.0.1 --ports 22,80,443,3306,5432,8080

# Faster scan with more threads
python pentest_toolkit.py portscan 127.0.0.1 --ports 1-1024 --threads 200

# Adjust timeout for slow hosts
python pentest_toolkit.py portscan 127.0.0.1 --ports 1-1024 --timeout 2.0
```

Expected output:
```
  PORT     STATE      SERVICE
  ────────────────────────────
  22       open       SSH
  80       open       HTTP
  8080     open       HTTP-Alt
```

---

### Module 2 — Banner Grabber

```bash
python pentest_toolkit.py banner 127.0.0.1 --ports 22,80,8080
```

Expected output:
```
  ✔  Port 22:   SSH-2.0-OpenSSH_8.9p1
  ✔  Port 8080: HTTP/1.0 200 OK | ...
  ℹ  Port 443:  No banner received
```

---

### Module 3 — Service Detector

```bash
python pentest_toolkit.py service 127.0.0.1 --ports 22,80,443,3306
```

Expected output:
```
  PORT     DETECTED SERVICE     BANNER PREVIEW
  22       SSH                  SSH-2.0-OpenSSH_8.9...
  80       HTTP                 HTTP/1.1 200 OK...
  3306     MySQL                5.7.38-MySQL...
```

---

### Module 4 — Ping Sweeper

```bash
# Sweep your local network
python pentest_toolkit.py sweep 192.168.1.0/24

# Sweep loopback range
python pentest_toolkit.py sweep 127.0.0.0/8

# Adjust thread count for speed
python pentest_toolkit.py sweep 192.168.1.0/24 --threads 100
```

Expected output:
```
  ✔  192.168.1.1   →  ALIVE
  ✔  192.168.1.10  →  ALIVE

  3 live host(s) found out of 254.
```

---

### Module 5 — SSL/TLS Checker

```bash
# Check a domain you own
python pentest_toolkit.py ssl yourdomain.com --port 443
```

Expected output:
```
  ✔  TLS Version  : TLSv1.3
  ✔  Cipher Suite : TLS_AES_256_GCM_SHA384 (256 bits)
  ℹ  Common Name  : yourdomain.com
  ℹ  Issuer       : Let's Encrypt
  ✔  Certificate valid for 87 more day(s)
```

Warning indicators:
```
  ⚠  Certificate expires in 12 day(s) — renew soon!
  ⚠  Deprecated TLS version in use: TLSv1.1
  ⚠  Weak cipher key length: 64 bits
```

---

### Module 6 — HTTP Header Auditor

```bash
# Audit your local dev server
python pentest_toolkit.py headers http://localhost
python pentest_toolkit.py headers http://127.0.0.1:8080
```

Expected output:
```
  [Potentially Revealing Headers]
  ⚠  Server: Apache/2.4.54  (Reveals server software version)
  ⚠  X-Powered-By: PHP/8.1  (Reveals server technology)

  [Missing Security Headers]
  ⚠  Missing: Content-Security-Policy
  ⚠  Missing: Strict-Transport-Security
```

---

### Module 7 — DNS Enumerator

```bash
python pentest_toolkit.py dns yourdomain.com
```

Expected output:
```
  ✔  A        93.184.216.34
  ✔  MX       mail.yourdomain.com.
  ✔  NS       ns1.yourdomain.com.
  ✔  TXT      v=spf1 include:...
  ℹ  AAAA     No record / not found
```

---

### Full Scan (all modules at once)

```bash
python pentest_toolkit.py fullscan 127.0.0.1 --ports 1-1024
```

This runs: Port Scanner → Banner Grabber → Service Detector → SSL Checker → HTTP Header Auditor → DNS Enumerator in sequence.

---

## Port Range Format

| Format | Example | Meaning |
|--------|---------|---------|
| Single | `80` | Port 80 only |
| List | `22,80,443` | Specific ports |
| Range | `1-1024` | All ports 1 to 1024 |
| Mixed | `22,80,8000-8100` | Combined |

---

## License

MIT License — free to use and modify.
