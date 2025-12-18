# 🛡️ Security Scanner v2.0

**Lightweight security scanner with REST API using Nmap + httpx**

## 📊 Architecture

```
                         TARGET INPUT
                              │
              ┌───────────────┴───────────────┐
              │      Is it an IP address?     │
              └───────────────┬───────────────┘
                              │
         ┌────────────────────┴────────────────────┐
         │                                         │
    ┌────▼────┐                              ┌─────▼─────┐
    │   IP    │                              │  DOMAIN   │
    └────┬────┘                              └─────┬─────┘
         │                                         │
┌────────▼────────┐                      ┌─────────▼─────────┐
│ Nmap            │                      │ 1. Alive/Dead     │
│ Port Scanning   │                      │    Check          │
└────────┬────────┘                      └─────────┬─────────┘
         │                                         │
         │                               ┌─────────▼─────────┐
         │                               │ 2. Security       │
         │                               │    Headers        │
         │                               └─────────┬─────────┘
         │                                         │
         │                               ┌─────────▼─────────┐
         │                               │ 3. SSL/TLS        │
         │                               │    Certificate    │
         │                               └─────────┬─────────┘
         │                                         │
         └─────────────────┬───────────────────────┘
                           │
                  ┌────────▼────────┐
                  │  JSON + TXT     │
                  │    Report       │
                  └─────────────────┘
```

---

## ✨ Features

| Feature | Tool | Target |
|---------|------|--------|
| **Port Scanning** | Nmap | IP |
| **Dead Domain Check** | httpx/urllib | Domain |
| **Security Headers** | Nmap NSE | Domain |
| **SSL Certificate** | Nmap NSE | Domain |

---

## 🚀 Quick Start

### Installation

```bash
# Install Nmap
sudo apt install nmap

# Install Python dependencies
pip install -r requirements.txt

# Install httpx (optional)
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### Start API Server

```bash
# Start the API server
sudo python3 api_server.py

# Custom port
sudo python3 api_server.py --port 8080

# Listen on all interfaces
sudo python3 api_server.py --host 0.0.0.0 --port 5000
```

### Single Target Scan

```bash
# Scan IP (Port scan)
sudo python3 scanner_api.py -t 192.168.1.1

# Scan Domain (Dead check + Headers + SSL)
sudo python3 scanner_api.py -t example.com
```

### Daily Batch Scan

```bash
# Scan all targets from file
sudo python3 daily_scan.py -f targets.txt

# With custom output directory
sudo python3 daily_scan.py -f ips.txt -o /var/scans

# JSON only output
sudo python3 daily_scan.py -f targets.txt --json-only
```

---

## 📁 Output Format

### File Naming
- IP: `192.168.1.1.json`, `192.168.1.1.txt`
- Domain: `example.com.json`, `example.com.txt`

### JSON Structure (with scan history)
```json
{
  "target": "192.168.1.1",
  "total_scans": 3,
  "last_scan": "2025-12-17 02:00:00",
  "scans": [
    {
      "scan_time": "2025-12-15 02:00:00",
      "status": "completed",
      "risk_score": 25,
      "open_ports": [{"port": 22}, {"port": 80}]
    },
    {
      "scan_time": "2025-12-16 02:00:00",
      "status": "completed",
      "risk_score": 30
    }
  ]
}
```

---

## 🔌 REST API

### Start Server

```bash
sudo python3 api_server.py --host 0.0.0.0 --port 5000
```

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scan` | Start a new scan |
| GET | `/api/scan/<id>` | Get scan result by ID |
| GET | `/api/scans` | List all scans |
| POST | `/api/scan/bulk` | Bulk scan multiple targets |
| GET | `/api/health` | Health check |

### Examples

**Start a scan (returns result directly):**
```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1"}'
```

Response (complete result with ID):
```json
{
  "id": "abc12345",
  "target": "192.168.1.1",
  "status": "completed",
  "started_at": "2025-12-18T10:00:00",
  "completed_at": "2025-12-18T10:01:30",
  "open_ports": [
    {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"},
    {"port": 80, "protocol": "tcp", "state": "filtered", "service": "http"}
  ],
  "security_headers": {...},
  "security_flags": [...]
}
```

**Async scan (get ID, fetch result later):**
```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1", "async": true}'
```

Response:
```json
{
  "id": "abc12345",
  "status": "pending",
  "message": "Scan started in background. Use /api/scan/{id} to get results.",
  "check_status": "/api/scan/abc12345"
}
```

**Get scan result by ID:**
```bash
curl http://localhost:5000/api/scan/abc12345
```

**Bulk scan (always async):**
```bash
curl -X POST http://localhost:5000/api/scan/bulk \
  -H "Content-Type: application/json" \
  -d '{"targets": ["192.168.1.1", "example.com", "10.0.0.1"]}'
```

### API Authentication (Optional)

Set `SCANNER_API_KEY` environment variable to enable authentication:

```bash
export SCANNER_API_KEY="your-secret-key"
sudo python3 api_server.py
```

Then include the key in requests:
```bash
curl -X POST http://localhost:5000/api/scan \
  -H "X-API-Key: your-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1"}'
```

---

## ⏰ Cron Setup (Daily Scan)

```bash
# Edit crontab
crontab -e

# Run daily at 2 AM
0 2 * * * cd /path/to/scanner && sudo python3 daily_scan.py -f targets.txt >> /var/log/scanner.log 2>&1
```

---

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SCANNER_OUTPUT_DIR` | Output directory | `./scan_results` |
| `SCANNER_LOG_LEVEL` | Log level | `INFO` |
| `SCANNER_NMAP_IP_TCP_PORTS` | TCP ports for IP scan | (default top 1000) |
| `SCANNER_NMAP_IP_SCAN_UDP` | Enable UDP scan | `false` |

---

## 📋 IP Scan Details

Default port scan for IP targets (nmap default top 1000 ports):

```bash
nmap -Pn -sS --open -sV -T4 --max-retries 2 --host-timeout 10m <target>
```

| Option | Description |
|--------|-------------|
| `-sS` | TCP SYN scan |
| `-sV` | Service version detection |
| `-T4` | Aggressive timing |
| `--open` | Only show open ports |
| `--host-timeout` | 10 minute timeout |

---

## 🔍 Security Headers Checked

- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- X-XSS-Protection
- Referrer-Policy
- Permissions-Policy
- Cross-Origin-Opener-Policy
- Cross-Origin-Embedder-Policy
- Cross-Origin-Resource-Policy

---

## 📂 Project Structure

```
security-scanner/
├── api_server.py       # REST API server (Flask)
├── scanner_api.py      # Core scanner module
├── daily_scan.py       # Daily batch scan script
├── config.py           # Configuration
├── requirements.txt    # Dependencies
├── Dockerfile          # Docker build
├── targets.txt         # Sample targets
├── scan_results/       # Output directory
│   ├── 192.168.1.1.json
│   ├── 192.168.1.1.txt
│   ├── example.com.json
│   └── example.com.txt
└── README.md
```

---

## 🐳 Docker

```bash
# Build
docker build -t security-scanner .

# Run API server
docker run -d \
  -p 5000:5000 \
  -v $(pwd)/scan_results:/app/scan_results \
  --name scanner-api \
  security-scanner

# Test
curl http://localhost:5000/api/health

# Run CLI scan
docker run --rm \
  -v $(pwd)/scan_results:/app/scan_results \
  --entrypoint python3 \
  security-scanner scanner_api.py -t 192.168.1.1
```

---

## ⚠️ Legal Disclaimer

**Only scan systems you own or have explicit permission to test.**

---

## 📄 License

MIT License
