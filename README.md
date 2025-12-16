# NSE Scanner v2.0

A security-focused scanner using **Nmap Scripting Engine (NSE)** with SSL/TLS certificate checking, HTTP security headers analysis, and clean output formatting.

## ✨ Features

- 🔍 **Full Port Scanning** - Scans all 65535 ports by default
- 🔐 **SSL/TLS Certificate Check** - Validates certificates, ciphers, and protocols
- 🛡️ **HTTP Security Headers** - Checks HSTS, CSP, X-Frame-Options, etc.
- ✅ **Clean Output** - Only displays open ports (no closed port clutter)
- 📋 **Scan Profiles** - Pre-configured profiles for common use cases
- 📊 **Formatted Results** - Beautiful, readable scan summaries

## Requirements

- Python 3.6+
- Nmap installed (`sudo apt install nmap`)

## Installation

```bash
cd /home/ritikrajput/Documents/Nmap_Scan
chmod +x nse_scanner.py
```

## Quick Start

```bash
# Security scan with SSL + HTTP headers (recommended)
sudo python3 nse_scanner.py -t example.com --profile security

# HTTPS-only security check
sudo python3 nse_scanner.py -t example.com --profile https

# Full port scan
sudo python3 nse_scanner.py -t 192.168.1.1 --profile full
```

## Usage

### Single Target Scanning

```bash
# Quick scan (top 100 ports)
sudo python3 nse_scanner.py -t example.com --profile quick

# Standard scan (top 1000 ports)
sudo python3 nse_scanner.py -t example.com --profile standard

# Full port scan (all 65535 ports)
sudo python3 nse_scanner.py -t 192.168.1.1 --profile full

# Security scan (SSL + Headers + Vulns)
sudo python3 nse_scanner.py -t example.com --profile security

# HTTPS security check
sudo python3 nse_scanner.py -t example.com --profile https

# Web application scan
sudo python3 nse_scanner.py -t example.com --profile web
```

### Multiple Targets from File

```bash
# Security scan on all targets
sudo python3 nse_scanner.py -f targets.txt --profile security

# Full scan on all targets
sudo python3 nse_scanner.py -f targets.txt --profile full
```

### Custom Scans

```bash
# Custom scripts
sudo python3 nse_scanner.py -t example.com -s "ssl-cert,http-security-headers" -p 443

# Specific ports
sudo python3 nse_scanner.py -t example.com -s vuln -p 80,443,8080

# With extra nmap arguments
sudo python3 nse_scanner.py -t example.com --profile security -e "-A -T5"
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `-t, --target` | Single target IP or domain |
| `-f, --file` | Target file (one per line) |
| `-s, --scripts` | NSE scripts to run |
| `-p, --ports` | Ports to scan (default: ALL) |
| `--profile` | Use predefined scan profile |
| `-o, --output` | Output directory (default: ./scan_results) |
| `-e, --extra` | Extra nmap arguments |
| `--show-closed` | Show closed ports (default: only open) |
| `--list-profiles` | List available scan profiles |
| `--list-scripts` | List security-focused NSE scripts |

## 📋 Scan Profiles

| Profile | Description | Ports |
|---------|-------------|-------|
| `quick` | Fast scan, top 100 ports | Top 100 |
| `standard` | Standard scan | Top 1000 |
| `full` | Complete scan, all ports | 1-65535 |
| `security` | SSL + Headers + Vulnerabilities | 1-65535 |
| `https` | HTTPS security check | 443,8443,8080,4443 |
| `web` | Web application scan | 80,443,8080,8443,8000,3000,5000 |

## 🔐 Security Scripts Included

### SSL/TLS Certificate Scripts
| Script | Description |
|--------|-------------|
| `ssl-cert` | Retrieves SSL certificate information |
| `ssl-enum-ciphers` | Enumerates SSL/TLS ciphers and protocols |
| `ssl-heartbleed` | Checks for Heartbleed vulnerability |
| `ssl-poodle` | Checks for POODLE vulnerability |
| `ssl-dh-params` | Checks Diffie-Hellman parameters |
| `ssl-ccs-injection` | Checks for CCS injection vulnerability |

### HTTP Security Header Scripts
| Script | Description |
|--------|-------------|
| `http-security-headers` | Checks HSTS, CSP, X-Frame-Options, etc. |
| `http-headers` | Retrieves all HTTP headers |
| `http-cookie-flags` | Checks cookie security flags |
| `http-cors` | Checks CORS configuration |

## Output Format

Results are saved in the `scan_results/` directory:
- `target_timestamp.txt` - Human-readable output
- `target_timestamp.xml` - XML format (for tools like Metasploit)
- `target_timestamp.gnmap` - Grepable format

### Sample Output

```
═══════════════════════════════════════════════════════════════════
🔍 SCANNING: example.com
═══════════════════════════════════════════════════════════════════

📊 SCAN RESULTS SUMMARY
───────────────────────────────────────────────────────────────────
🎯 Nmap scan report for example.com (93.184.216.34)
   ├─ ✅ 80/tcp          http
   ├─ ✅ 443/tcp         https
   │  🔐 Subject: CN=example.com
   │  📜 Issuer: DigiCert Inc
   │  ⏰ Not valid after: 2025-12-15
   │  🛡️  HSTS: ✅ Present
   │  🛡️  CSP: ✅ Present
   │  🛡️  X-Frame-Options: ✅ Present
   │  ✅ TLSv1.2
   │  ✅ TLSv1.3
```

## Target File Format

Create a `targets.txt` file:

```
# Comments start with #
192.168.1.1
10.0.0.0/24
example.com
scanme.nmap.org
```

## ⚠️ Legal Disclaimer

**Only scan networks and systems you have permission to test!**

Unauthorized scanning is illegal. Always:
- Get written permission before scanning
- Only scan your own systems or authorized targets
- Use `scanme.nmap.org` for testing (Nmap's public test server)

## License

MIT License - Use responsibly!
# Nmap_Scanner
