# NSE Scanner

A powerful scanner that uses **Nmap Scripting Engine (NSE)** to scan single IP/domain or multiple targets from a file.

## Features

- 🎯 Scan single IP/domain directly from command line
- 📁 Read multiple targets from a file (one per line)
- 🔧 Support for all NSE script categories
- 📊 Real-time scan output
- 💾 Saves results in both TXT and XML formats
- ⚡ Easy to use command-line interface

## Requirements

- Python 3.6+
- Nmap installed (`sudo apt install nmap`)

## Installation

```bash
# Clone or download the scanner
cd /home/ritikrajput/Documents/Nmap_Scan

# Make the script executable
chmod +x nse_scanner.py
```

## Usage

### Single Target Scanning

```bash
# Scan a single IP
sudo python3 nse_scanner.py -t 192.168.1.1

# Scan a domain
sudo python3 nse_scanner.py -t example.com

# Vulnerability scan on single target
sudo python3 nse_scanner.py -t 192.168.1.1 -s vuln

# HTTP scan with specific ports
sudo python3 nse_scanner.py -t example.com -s "http-*" -p 80,443,8080

# Full scan with version detection
sudo python3 nse_scanner.py -t 10.0.0.1 -s vuln -e "-sV -A"
```

### Multiple Targets from File

```bash
# Default scan (uses -sC scripts)
sudo python3 nse_scanner.py -f targets.txt

# Vulnerability scan
sudo python3 nse_scanner.py -f targets.txt -s vuln

# HTTP scripts only
sudo python3 nse_scanner.py -f targets.txt -s "http-*"

# Scan specific ports
sudo python3 nse_scanner.py -f targets.txt -p 80,443,8080

# Combined options
sudo python3 nse_scanner.py -f targets.txt -s vuln -p 1-1000 -e "-sV -T4"
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-t, --target` | Single target IP or domain |
| `-f, --file` | Target file (one per line) |
| `-s, --scripts` | NSE scripts/categories (default: default) |
| `-p, --ports` | Ports to scan (e.g., 80,443 or 1-1000) |
| `-o, --output` | Output directory (default: ./scan_results) |
| `-e, --extra` | Extra nmap arguments |
| `--list-scripts` | List available NSE scripts |

> **Note:** You must use either `-t` (single target) or `-f` (file) - not both.

### NSE Script Categories

| Category | Description |
|----------|-------------|
| `auth` | Authentication related scripts |
| `broadcast` | Discover hosts by broadcasting |
| `brute` | Brute force attacks |
| `default` | Default scripts (-sC) |
| `discovery` | Discovery scripts |
| `dos` | Denial of Service scripts |
| `exploit` | Exploitation scripts |
| `intrusive` | Intrusive scripts (may crash targets) |
| `malware` | Malware detection |
| `safe` | Safe scripts |
| `version` | Version detection |
| `vuln` | Vulnerability detection |

### Target File Format

Create a `targets.txt` file with one target per line:

```
# This is a comment
192.168.1.1
192.168.1.0/24
example.com
scanme.nmap.org
```

## Examples

### 1. Quick Vulnerability Scan

```bash
sudo python3 nse_scanner.py -f targets.txt -s vuln -p 80,443
```

### 2. Full Service Scan with Version Detection

```bash
sudo python3 nse_scanner.py -f targets.txt -s default -e "-sV -A"
```

### 3. Web Application Scan

```bash
sudo python3 nse_scanner.py -f targets.txt -s "http-*" -p 80,443,8080,8443
```

### 4. SSL/TLS Security Scan

```bash
sudo python3 nse_scanner.py -f targets.txt -s "ssl-*" -p 443
```

### 5. SMB Security Scan

```bash
sudo python3 nse_scanner.py -f targets.txt -s "smb-*" -p 445
```

## Output

Results are saved in the `scan_results/` directory:
- `target_timestamp.txt` - Human-readable output
- `target_timestamp.xml` - XML format for parsing

## ⚠️ Legal Disclaimer

**Only scan networks and systems you have permission to test!**

Unauthorized scanning is illegal and unethical. Always:
- Get written permission before scanning
- Only scan your own systems or authorized targets
- Use `scanme.nmap.org` for testing (Nmap's public test server)

## License

MIT License - Use responsibly!

# Nmap_Scanner
# Nmap_Scanner
# Nmap_Scanner
