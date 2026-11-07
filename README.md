# 🔎 WebRecon

**Web Application Reconnaissance Toolkit for Bug Bounty** — all-in-one passive-first recon: JS analysis, subdomain enumeration, API fuzzing, secret detection, and security header auditing. Single Python file, zero config.

```
python3 webrecon.py -u https://example.com --deep --probe
```

## ✨ Features

### 🧩 JavaScript Analysis
- Crawls the target page and collects all linked JS files (skips 3rd-party/CDN noise)
- Extracts **API endpoints**, relative paths, and full URLs from JS strings, `fetch`/`axios`/`XHR` calls and template literals
- Parses **endpoint → HTTP method → parameters → Content-Type** mappings (fetch, axios, `$.ajax`, XMLHttpRequest, FormData, GraphQL variables)
- Analyzes **inline scripts**, **webpack chunks**, and **source maps** (`--deep`)
- Filters out SVG/CSS/HTML garbage and framework build artifacts (`_next`, `chunks/`, etc.)

### 🔐 Secret Detection
40+ regex signatures including:
- **Cloud**: AWS keys, Google API keys, Firebase, S3/GCP/Azure buckets, Cloudinary
- **Tokens**: GitHub, Slack, Stripe, Twilio, SendGrid, Mailgun, Shopify, Mapbox, Telegram, Discord webhooks, Heroku
- **Auth**: JWT, Bearer/Basic/Authorization headers, private keys, hardcoded passwords, credentials in URLs

### 🌐 Subdomain Enumeration
Passive collection from **crt.sh**, **Hackertarget**, **RapidDNS**, **urlscan.io**, and **AlienVault OTX**, plus domains discovered in JS. Then:
- Concurrent **alive check** on ports 80/443 + 20+ common web ports (with status, title, server, redirects)
- **IP resolution** with CDN/WAF detection (shared-IP heuristics)
- Auto root-domain detection (`sub.example.com` → `example.com`, handles two-part TLDs like `co.uk`)

### 🎯 API Fuzzing
Auto-fuzzes alive hosts with 100+ curated paths — API docs (Swagger/OpenAPI), GraphQL, Spring Boot actuators, debug endpoints, `.env`/`.git` exposure, admin panels, auth endpoints, cloud metadata — with **wildcard/soft-404 detection** to eliminate false positives.

### 🛡️ Security Audit
- Missing/weak security headers (HSTS, CSP, X-Frame-Options…) with severity ratings
- **CORS misconfiguration**: origin reflection tests (`evil.com`, `null`), `*` + credentials combo
- Cookie flag analysis (Secure / HttpOnly / SameSite)
- Dangerous HTTP methods (TRACE / PUT / DELETE) on the main target **and** alive subdomains
- Tech stack fingerprinting from headers

### 🚀 Endpoint Probing (`--probe`)
Probes every discovered endpoint with 7 HTTP methods: accepted methods, status codes, JSON body previews, CORS, auth requirements (401/403), rate-limit headers — and highlights **writable endpoints** (2xx on POST/PUT/DELETE).

## 📦 Installation

```bash
git clone https://github.com/g00f1x/webrecon.git
cd webrecon
pip install -r requirements.txt
```

**Requirements:** Python 3.9+ · `requests` · `beautifulsoup4` · `colorama`

## 🖥️ Usage

```
python3 webrecon.py -u https://example.com
```

| Flag | Description |
|---|---|
| `-u, --url` | Target URL (page or single `.js` file) |
| `-f, --file` | File with URLs, one per line (batch mode) |
| `-d, --directory` | Local directory of JS/TS files to analyze |
| `--deep` | Webpack chunks, source maps, subdomain JS crawl |
| `--probe` | Probe endpoints: methods, CORS, auth, tech |
| `-t, --threads` | Concurrent threads (default: 10) |
| `--timeout` | HTTP timeout in seconds (default: 15) |
| `--proxy` | HTTP proxy, e.g. `http://127.0.0.1:8080` (Burp) |
| `-H, --headers` | Custom header (repeatable) |
| `-c, --cookies` | Cookie (repeatable), e.g. `session=abc123` |
| `-v, --verbose` | Show findings grouped per source |
| `-o, --output` | Save full JSON report |
| `-e, --endpoints-out` | Save discovered endpoints to a text file |
| `-w, --wordlist` | Generate a path/param wordlist from findings |

### Examples

```bash
# Full recon: JS analysis + subdomains + alive check + API fuzzing
python3 webrecon.py -u https://example.com

# Everything: deep mode + endpoint probing + JSON report
python3 webrecon.py -u https://example.com --deep --probe -o report.json

# Targets a subdomain — root domain auto-detected for subdomain enum
python3 webrecon.py -u https://sub.example.com

# Scan through Burp Suite
python3 webrecon.py -u https://example.com --proxy http://127.0.0.1:8080

# Batch scan a list of URLs
python3 webrecon.py -f urls.txt

# Analyze downloaded JS files offline
python3 webrecon.py -d ./js_files/

# Generate a custom wordlist for ffuf/dirsearch from findings
python3 webrecon.py -u https://example.com -w wordlist.txt
```

## 📄 Output

With `-o report.json` you get a structured report containing endpoints, secrets, sensitive info, discovered domains, endpoint→params mappings, cloud resources, subdomains + alive hosts + IP pool, probe results, and fuzz results. When `-o` is used, `*_subs.txt` and `*_alive.txt` are saved automatically.

## ⚠️ Disclaimer

This tool is for **authorized security testing and bug bounty programs only**. Scanning targets without permission is illegal. The authors are not responsible for any misuse.

## 📜 License

MIT

---
Made by **g00f1x** · Bug Bounty Edition
