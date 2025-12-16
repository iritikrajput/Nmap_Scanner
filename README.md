# 🛡️ Security Scanner Suite

A comprehensive security scanning toolkit with two powerful scanners:

| Scanner | Purpose | Best For |
|---------|---------|----------|
| **Intelligent Scanner** | Nmap + Nuclei smart pipeline | Full security assessments |
| **NSE Scanner** | Nmap Scripting Engine | Quick port/service scans |

---

## 📋 Table of Contents

- [Quick Start](#-quick-start)
- [Intelligent Scanner](#-intelligent-scanner)
- [NSE Scanner](#-nse-scanner)
- [Installation](#-installation)
- [Target File Format](#-target-file-format)
- [Output Files](#-output-files)
- [Legal Disclaimer](#️-legal-disclaimer)

---

## 🚀 Quick Start

```bash
# Clone and setup
cd /home/ritikrajput/Documents/Nmap_Scan
chmod +x *.py

# Quick security scan (Intelligent Scanner - recommended)
sudo python3 intelligent_scanner.py -t example.com

# Quick NSE scan
sudo python3 nse_scanner.py -t example.com --profile security
```

---

## 🧠 Intelligent Scanner

**Production-grade security scanner with Nmap + Nuclei smart pipeline.**

### How It Works

```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│   PHASE 1   │      │   PHASE 2   │      │   PHASE 3   │      │   PHASE 4   │
│    Nmap     │ ───▶ │   Analyze   │ ───▶ │   Nuclei    │ ───▶ │   Report    │
│ Recon Scan  │      │   & Decide  │      │  (Targeted) │      │  Generation │
└─────────────┘      └─────────────┘      └─────────────┘      └─────────────┘
```

### Why Use This?

| Traditional Approach | Intelligent Approach |
|---------------------|---------------------|
| Run Nmap → Run ALL Nuclei templates | Run Nmap → Analyze → Run ONLY relevant templates |
| Slow, noisy, many false positives | Fast, clean, accurate results |
| Wastes time on irrelevant checks | Focuses on actual attack surface |

### Usage

```bash
# Basic scan (single target)
sudo python3 intelligent_scanner.py -t example.com

# Scan multiple targets from file
sudo python3 intelligent_scanner.py -f targets.txt

# Full port scan (all 65535 ports)
sudo python3 intelligent_scanner.py -t example.com --ports "-p-"

# Quick scan (top 100 ports)
sudo python3 intelligent_scanner.py -t example.com --ports "--top-ports 100"

# High severity findings only
sudo python3 intelligent_scanner.py -t example.com --severity high,critical

# Custom output directory
sudo python3 intelligent_scanner.py -t example.com -o ./my_results
```

### Command Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `-t, --target` | - | Single target IP or domain |
| `-f, --file` | - | File containing targets (one per line) |
| `--ports` | `--top-ports 1000` | Nmap port specification |
| `--severity` | `medium,high,critical` | Nuclei severity filter |
| `-o, --output` | `./scan_results` | Output directory |
| `--rate-limit` | `150` | Nuclei requests per second |
| `--timeout` | `300` | Scan timeout in seconds |

### Decision Engine Logic

The scanner analyzes Nmap results and **intelligently decides** which Nuclei templates to run:

```
IF port 443 open
  ├── IF certificate CN ≠ domain
  │     └── 🚨 Flag as potential PHISHING
  ├── IF HSTS header missing
  │     └── Run: http/misconfiguration
  ├── IF TLS < 1.2 detected
  │     └── Run: ssl/misconfigurations
  └── Run: ssl templates + http/exposures

IF port 80 open
  └── Run: http/misconfiguration, http/exposures

IF database port open (MySQL/Redis/MongoDB)
  └── Run: default-logins, network/exposures

IF SSH/FTP open
  └── Run: network/cves, default-logins
```

### Service-to-Template Mapping

| Detected Service | Nuclei Templates Applied |
|-----------------|-------------------------|
| HTTP (80, 8080) | `http/misconfiguration`, `http/exposures`, `http/cves` |
| HTTPS (443, 8443) | `ssl`, `http/misconfiguration`, `http/exposures` |
| MySQL | `network/cves`, `default-logins` |
| MongoDB | `network/cves`, `default-logins`, `network/exposures` |
| Redis | `network/cves`, `default-logins`, `network/exposures` |
| SSH | `network/cves`, `default-logins` |
| FTP | `network/cves`, `default-logins`, `network/exposures` |
| SMTP | `network/cves`, `network/exposures` |

### Security Checks Performed

| Check | Description |
|-------|-------------|
| **Certificate Validation** | CN mismatch detection (phishing indicator) |
| **TLS Version** | Flags weak TLSv1.0/1.1/SSLv3 |
| **Security Headers** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy |
| **Vulnerability Scan** | CVEs, misconfigurations, exposures via Nuclei |

### Risk Scoring

Each target receives a risk score (0-100):

| Score | Level | Indicator | Meaning |
|-------|-------|-----------|---------|
| 0-19 | LOW | 🟢 | Minimal security concerns |
| 20-49 | MEDIUM | 🟡 | Some issues to address |
| 50-79 | HIGH | 🟠 | Significant vulnerabilities |
| 80-100 | CRITICAL | 🔴 | Immediate attention required |

**Score Breakdown:**
- Certificate CN mismatch: +30 points
- Weak TLS version: +20 points
- Each missing security header: +5 points
- Critical Nuclei finding: +40 points
- High Nuclei finding: +25 points
- Medium Nuclei finding: +10 points

### Sample Output

```
══════════════════════════════════════════════════════════════════════════════
🎯 SCANNING: example.com
══════════════════════════════════════════════════════════════════════════════

──────────────────────────────────────────────────────────────────
  Phase 1: Nmap Reconnaissance
──────────────────────────────────────────────────────────────────
  🔍 Running: nmap --open -sV -sC -T4 --top-ports 1000 example.com
  ✅ Found 3 open port(s)

──────────────────────────────────────────────────────────────────
  🧠 Decision Engine Analysis
──────────────────────────────────────────────────────────────────
    → Port 443/https → ssl, http/misconfiguration
    → Port 80/http → http/misconfiguration, http/exposures
    → Missing 3 security headers → http/misconfiguration

──────────────────────────────────────────────────────────────────
  Phase 3: Nuclei Vulnerability Scan
──────────────────────────────────────────────────────────────────
    🎯 Nuclei scanning: https://example.com
    📋 Templates: ssl, http/misconfiguration, http/exposures

══════════════════════════════════════════════════════════════════════════════
📊 SCAN REPORT
══════════════════════════════════════════════════════════════════════════════

  🎯 Target: example.com
  📍 IP: 93.184.216.34
  
  🟡 Risk Score: 35/100 (MEDIUM)

  ✅ Open Ports (3):
      443/tcp   → https (nginx 1.18.0)
      80/tcp    → http (nginx 1.18.0)
      22/tcp    → ssh (OpenSSH 8.2)

  🔐 TLS/Certificate:
      CN: example.com
      Issuer: DigiCert Inc
      Expires: 2025-12-15

  🛡️  Missing Security Headers (3):
      ❌ Content-Security-Policy
      ❌ X-Frame-Options
      ❌ Permissions-Policy

  🔥 Vulnerabilities Found (1):
      🟡 [MEDIUM] Missing X-Frame-Options Header
         └─ https://example.com

  📁 Report saved: ./scan_results/report_example_com_20251216_120000.json
```

---

## 🔧 NSE Scanner

**Nmap Scripting Engine scanner with pre-configured security profiles.**

### Usage

```bash
# Quick scan (top 100 ports)
sudo python3 nse_scanner.py -t example.com --profile quick

# Standard scan (top 1000 ports)
sudo python3 nse_scanner.py -t example.com --profile standard

# Full port scan (all 65535 ports)
sudo python3 nse_scanner.py -t example.com --profile full

# Security scan (SSL + Headers + Vulns)
sudo python3 nse_scanner.py -t example.com --profile security

# HTTPS-only security check
sudo python3 nse_scanner.py -t example.com --profile https

# Web application scan
sudo python3 nse_scanner.py -t example.com --profile web

# Multiple targets from file
sudo python3 nse_scanner.py -f targets.txt --profile security

# Custom scripts
sudo python3 nse_scanner.py -t example.com -s "ssl-cert,http-security-headers" -p 443
```

### Command Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `-t, --target` | - | Single target IP or domain |
| `-f, --file` | - | File containing targets |
| `-s, --scripts` | `default` | NSE scripts to run |
| `-p, --ports` | All ports | Ports to scan |
| `--profile` | - | Use predefined scan profile |
| `-o, --output` | `./scan_results` | Output directory |
| `-e, --extra` | - | Extra nmap arguments |
| `--show-closed` | `false` | Show closed ports |
| `--list-profiles` | - | List available profiles |
| `--list-scripts` | - | List security NSE scripts |

### Scan Profiles

| Profile | Ports | Scripts | Use Case |
|---------|-------|---------|----------|
| `quick` | Top 100 | default | Fast reconnaissance |
| `standard` | Top 1000 | default + sV | General scanning |
| `full` | 1-65535 | default, safe | Complete enumeration |
| `security` | 1-65535 | ssl-*, http-*, vuln | Security assessment |
| `https` | 443, 8443, 4443 | ssl-*, http-security-headers | HTTPS security check |
| `web` | 80, 443, 8080, 8443 | http-*, ssl-* | Web app scanning |

### NSE Scripts Used

**SSL/TLS Scripts:**
| Script | Description |
|--------|-------------|
| `ssl-cert` | Certificate information |
| `ssl-enum-ciphers` | Cipher suite enumeration |
| `ssl-heartbleed` | Heartbleed vulnerability check |
| `ssl-poodle` | POODLE vulnerability check |
| `ssl-dh-params` | Diffie-Hellman parameter check |
| `ssl-ccs-injection` | CCS injection check |

**HTTP Security Scripts:**
| Script | Description |
|--------|-------------|
| `http-security-headers` | Security header analysis |
| `http-headers` | All HTTP headers |
| `http-cookie-flags` | Cookie security flags |
| `http-cors` | CORS configuration |

---

## 📦 Installation

### Requirements

- **Python 3.6+**
- **Nmap** (required for both scanners)
- **Nuclei** (optional, enhances Intelligent Scanner)

### Install Dependencies

```bash
# Install Nmap
sudo apt update && sudo apt install nmap -y

# Install Nuclei (recommended)
# Option 1: Using Go
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Option 2: Download binary
wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.3.7_linux_amd64.zip
unzip nuclei_3.3.7_linux_amd64.zip
sudo mv nuclei /usr/local/bin/

# Update Nuclei templates
nuclei -update-templates
```

### Setup Scanners

```bash
cd /home/ritikrajput/Documents/Nmap_Scan
chmod +x intelligent_scanner.py nse_scanner.py
```

---

## 📄 Target File Format

Create a `targets.txt` file with one target per line:

```
# Comments start with #
# IP addresses
192.168.1.1
10.0.0.1

# CIDR ranges
192.168.1.0/24

# Domain names
example.com
scanme.nmap.org
```

---

## 📁 Output Files

All results are saved in the `scan_results/` directory:

| File Type | Description | Scanner |
|-----------|-------------|---------|
| `nmap_*.xml` | Nmap XML output | Both |
| `nmap_*.txt` | Nmap text output | Both |
| `nmap_*.gnmap` | Nmap grepable output | NSE Scanner |
| `nuclei_*.json` | Nuclei findings | Intelligent Scanner |
| `report_*.json` | Complete JSON report | Intelligent Scanner |

---

## ⚠️ Legal Disclaimer

**Only scan networks and systems you have explicit permission to test!**

Unauthorized scanning is **illegal** and may result in:
- Criminal charges
- Civil liability
- Network bans

### Safe Testing Options:
- Your own systems
- Authorized penetration tests
- `scanme.nmap.org` (Nmap's public test server)
- HackTheBox / TryHackMe labs

---

## 📄 License

MIT License - Use responsibly!

---

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

---

**Made with ❤️ for security professionals**
# Nmap_Scanner
# Nmap_Scanner
