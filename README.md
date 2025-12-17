# 🛡️ Security Scanner Suite

<p align="center">
  <b>Production-Ready Security Scanning Toolkit</b><br>
  <i>Intelligent Nmap + Nuclei Pipeline with Backend API</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/Nmap-Required-green.svg" alt="Nmap">
  <img src="https://img.shields.io/badge/Nuclei-Optional-yellow.svg" alt="Nuclei">
  <img src="https://img.shields.io/badge/Docker-Ready-blue.svg" alt="Docker">
  <img src="https://img.shields.io/badge/License-MIT-purple.svg" alt="License">
</p>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Quick Start](#-quick-start)
- [Backend Integration](#-backend-integration)
- [API Reference](#-api-reference)
- [Configuration](#-configuration)
- [Docker Deployment](#-docker-deployment)
- [Output Formats](#-output-formats)
- [CLI Tools](#-cli-tools)

---

## 🎯 Overview

Security Scanner Suite is a **production-ready** security scanning toolkit designed for backend integration. It provides:

- **Python API** for programmatic access
- **CLI tools** for manual scanning  
- **Docker support** for containerized deployment
- **Multiple output formats** (JSON, XML, TXT)
- **Configurable** via files or environment variables

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Port Scanning** | Nmap-based port and service discovery |
| 🛡️ **Security Headers** | HTTP security header analysis |
| 🔐 **TLS/SSL** | Certificate validation and cipher checks |
| 🎯 **Vulnerability Scanning** | Nuclei-powered CVE detection |
| 📊 **Risk Scoring** | 0-100 risk assessment |
| 📄 **Multi-format Output** | JSON, XML, TXT reports |
| 🔧 **Configurable** | Environment variables, JSON config |
| 🐳 **Docker Ready** | Production container support |
| 📝 **Logging** | Structured logging for debugging |
| ⚡ **Concurrent** | Multi-target parallel scanning |

---

## 🚀 Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/security-scanner.git
cd security-scanner

# Install system dependencies
sudo apt install nmap -y

# Install Nuclei (optional but recommended)
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates

# Make scripts executable
chmod +x *.py
```

### Basic Usage

```bash
# Quick scan
sudo python3 scanner_api.py -t example.com

# Multiple targets
sudo python3 scanner_api.py -f targets.txt

# JSON output
sudo python3 scanner_api.py -t example.com --json

# With custom config
sudo python3 scanner_api.py -t example.com -c config.json
```

---

## 🔌 Backend Integration

### Python API Usage

```python
from scanner_api import SecurityScanner, ScanResult, ScannerConfig

# Initialize scanner
scanner = SecurityScanner()

# Single target scan
result = scanner.scan("example.com")

# Access results
print(f"Target: {result.target}")
print(f"Risk Score: {result.risk_score}/100")
print(f"Risk Level: {result.risk_level}")
print(f"Open Ports: {len(result.open_ports)}")

# Get JSON for API response
json_data = result.to_json()
dict_data = result.to_dict()
```

### Multiple Targets

```python
from scanner_api import SecurityScanner

scanner = SecurityScanner()

# Concurrent scanning (default: 3 workers)
targets = ["target1.com", "target2.com", "target3.com"]
results = scanner.scan_multiple(targets, max_workers=5)

for result in results:
    print(f"{result.target}: {result.risk_level}")
```

### Custom Configuration

```python
from scanner_api import SecurityScanner
from config import ScannerConfig

# Custom config
config = ScannerConfig(
    nmap_ports="-p-",  # All ports
    nuclei_severity="high,critical",
    output_dir="/var/scans",
    log_level="DEBUG"
)

scanner = SecurityScanner(config)
result = scanner.scan("target.com")
```

### From Environment Variables

```python
from config import ScannerConfig
from scanner_api import SecurityScanner

# Load config from environment
config = ScannerConfig.from_env()
scanner = SecurityScanner(config)
```

Environment variables:
```bash
export SCANNER_OUTPUT_DIR=/var/scans
export SCANNER_LOG_LEVEL=INFO
export SCANNER_NUCLEI_SEVERITY=high,critical
export SCANNER_NMAP_TIMEOUT=600
```

### Flask Integration Example

```python
from flask import Flask, jsonify, request
from scanner_api import SecurityScanner, ScannerConfig

app = Flask(__name__)
scanner = SecurityScanner()

@app.route('/api/scan', methods=['POST'])
def scan_target():
    data = request.json
    target = data.get('target')
    
    if not target:
        return jsonify({"error": "Target required"}), 400
    
    result = scanner.scan(target)
    return jsonify(result.to_dict())

@app.route('/api/scan/batch', methods=['POST'])
def scan_batch():
    data = request.json
    targets = data.get('targets', [])
    
    results = scanner.scan_multiple(targets)
    return jsonify([r.to_dict() for r in results])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

### FastAPI Integration Example

```python
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
from scanner_api import SecurityScanner

app = FastAPI(title="Security Scanner API")
scanner = SecurityScanner()

class ScanRequest(BaseModel):
    target: str

class BatchScanRequest(BaseModel):
    targets: List[str]

@app.post("/scan")
async def scan(request: ScanRequest):
    result = scanner.scan(request.target)
    return result.to_dict()

@app.post("/scan/batch")
async def scan_batch(request: BatchScanRequest):
    results = scanner.scan_multiple(request.targets)
    return [r.to_dict() for r in results]

@app.get("/health")
async def health():
    ok, deps = scanner.check_dependencies()
    return {"status": "ok" if ok else "degraded", "dependencies": deps}
```

---

## 📚 API Reference

### ScanResult Object

```python
@dataclass
class ScanResult:
    target: str           # Scanned target
    status: str           # "completed", "failed", "in_progress"
    scan_time: str        # Scan timestamp
    duration: float       # Scan duration in seconds
    
    ip: str               # Resolved IP
    hostname: str         # Hostname
    
    risk_score: int       # 0-100
    risk_level: str       # LOW, MEDIUM, HIGH, CRITICAL
    
    open_ports: List[PortInfo]
    tls_info: Optional[TLSInfo]
    header_analysis: Optional[HeaderAnalysis]
    vulnerabilities: List[VulnerabilityFinding]
    flags: List[str]      # Security issues
    
    output_files: Dict[str, str]  # Generated report files
    error: Optional[str]  # Error message if failed
```

### Methods

| Method | Description |
|--------|-------------|
| `scanner.scan(target)` | Scan single target |
| `scanner.scan_multiple(targets, max_workers)` | Scan multiple targets |
| `scanner.scan_from_file(filepath)` | Scan from file |
| `scanner.check_dependencies()` | Check if tools are installed |
| `result.to_dict()` | Convert result to dictionary |
| `result.to_json()` | Convert result to JSON string |

---

## ⚙️ Configuration

### Configuration File (config.json)

```json
{
  "nmap_ports": "--top-ports 1000",
  "nmap_timeout": 300,
  "nuclei_enabled": true,
  "nuclei_severity": "medium,high,critical",
  "output_dir": "./scan_results",
  "output_formats": ["json", "xml", "txt"],
  "check_headers": true,
  "log_level": "INFO"
}
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SCANNER_NMAP_PATH` | `nmap` | Path to nmap binary |
| `SCANNER_NMAP_PORTS` | `--top-ports 1000` | Port specification |
| `SCANNER_NMAP_TIMEOUT` | `300` | Nmap timeout (seconds) |
| `SCANNER_NUCLEI_PATH` | `nuclei` | Path to nuclei binary |
| `SCANNER_NUCLEI_ENABLED` | `true` | Enable Nuclei scanning |
| `SCANNER_NUCLEI_SEVERITY` | `medium,high,critical` | Severity filter |
| `SCANNER_OUTPUT_DIR` | `./scan_results` | Output directory |
| `SCANNER_CHECK_HEADERS` | `true` | Enable header checks |
| `SCANNER_LOG_LEVEL` | `INFO` | Logging level |
| `SCANNER_LOG_FILE` | `null` | Log file path |

---

## 🐳 Docker Deployment

### Build and Run

```bash
# Build image
docker build -t security-scanner .

# Run single scan
docker run --rm security-scanner -t example.com --json

# Run with volume for results
docker run --rm \
  -v $(pwd)/scan_results:/app/scan_results \
  security-scanner -t example.com

# Run with custom config
docker run --rm \
  -v $(pwd)/config.json:/app/config.json \
  -v $(pwd)/scan_results:/app/scan_results \
  security-scanner -t example.com -c /app/config.json
```

### Docker Compose

```bash
# Start scanner service
docker-compose up -d

# Run scan
docker-compose run scanner python3 scanner_api.py -t example.com

# View logs
docker-compose logs -f scanner
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: security-scanner
spec:
  replicas: 1
  selector:
    matchLabels:
      app: security-scanner
  template:
    metadata:
      labels:
        app: security-scanner
    spec:
      containers:
      - name: scanner
        image: security-scanner:latest
        env:
        - name: SCANNER_LOG_LEVEL
          value: "INFO"
        - name: SCANNER_OUTPUT_DIR
          value: "/data/scans"
        volumeMounts:
        - name: scan-data
          mountPath: /data/scans
      volumes:
      - name: scan-data
        persistentVolumeClaim:
          claimName: scanner-pvc
```

---

## 📁 Output Formats

### JSON Output

```json
{
  "target": "example.com",
  "status": "completed",
  "risk_score": 44,
  "risk_level": "MEDIUM",
  "open_ports": [
    {"port": 80, "protocol": "tcp", "service": "http", "product": "nginx"},
    {"port": 443, "protocol": "tcp", "service": "https", "product": "nginx"}
  ],
  "header_analysis": {
    "score": 28,
    "found": {"X-Frame-Options": "DENY"},
    "missing": ["Strict-Transport-Security", "Content-Security-Policy"]
  },
  "flags": [
    "HSTS not configured - SSL stripping vulnerability",
    "CSP not configured - XSS risk"
  ],
  "vulnerabilities": []
}
```

### XML Output

```xml
<?xml version="1.0" encoding="UTF-8"?>
<security_scan_report>
  <target>example.com</target>
  <risk_score>44</risk_score>
  <risk_level>MEDIUM</risk_level>
  <open_ports>
    <item>
      <port>80</port>
      <service>http</service>
    </item>
  </open_ports>
</security_scan_report>
```

---

## 🔧 CLI Tools

### scanner_api.py (Recommended)

```bash
# Single target
sudo python3 scanner_api.py -t example.com

# Multiple targets from file
sudo python3 scanner_api.py -f targets.txt

# With config file
sudo python3 scanner_api.py -t example.com -c config.json

# JSON output
sudo python3 scanner_api.py -t example.com --json

# Custom output directory
sudo python3 scanner_api.py -t example.com -o /var/scans
```

### intelligent_scanner.py (Interactive)

```bash
# Full interactive scan
sudo python3 intelligent_scanner.py -t example.com

# With port specification
sudo python3 intelligent_scanner.py -t example.com --ports "-p-"

# High severity only
sudo python3 intelligent_scanner.py -t example.com --severity high,critical
```

### nse_scanner.py (Nmap-only)

```bash
# Quick scan
sudo python3 nse_scanner.py -t example.com --profile quick

# Security scan
sudo python3 nse_scanner.py -t example.com --profile security

# Custom scripts
sudo python3 nse_scanner.py -t example.com -s "ssl-cert,http-headers"
```

---

## 📁 Project Structure

```
security-scanner/
├── scanner_api.py          # Main API module (backend integration)
├── intelligent_scanner.py  # Interactive CLI scanner
├── nse_scanner.py          # Nmap-only scanner
├── config.py               # Configuration module
├── config.example.json     # Sample configuration
├── requirements.txt        # Python dependencies
├── Dockerfile              # Docker build file
├── docker-compose.yml      # Docker Compose config
├── .gitignore              # Git ignore rules
├── README.md               # This documentation
├── CHANGELOG.md            # Version history
├── targets.txt             # Sample targets file
└── scan_results/           # Output directory (gitignored)
```

---

## ⚠️ Security & Legal

**Important**: Only scan systems you own or have explicit permission to test.

- ✅ Your own infrastructure
- ✅ Authorized penetration tests
- ✅ Bug bounty programs (follow rules)
- ❌ Unauthorized systems
- ❌ Production systems without permission

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
# Nmap_Scanner
