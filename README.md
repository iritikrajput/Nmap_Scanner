# 🛡️ Security Scanner v3.0 - Production Edition

**Enterprise-grade security scanner with REST API, parallel processing, rate limiting, and Redis queue**

---

## 📊 Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CLIENT REQUEST                                  │
└────────────────────────────────────┬────────────────────────────────────────┘
                                     │
                    ┌────────────────▼────────────────┐
                    │        API GATEWAY (Flask)       │
                    │  ┌─────────────────────────────┐ │
                    │  │ • Authentication (API Key)  │ │
                    │  │ • Rate Limiting (per IP)    │ │
                    │  │ • Policy Check (scan type)  │ │
                    │  └─────────────────────────────┘ │
                    └────────────────┬────────────────┘
                                     │
              ┌──────────────────────┴──────────────────────┐
              │                                             │
     ┌────────▼────────┐                         ┌─────────▼─────────┐
     │  In-Memory Mode │                         │   Redis Queue     │
     │   (Default)     │                         │   (Production)    │
     └────────┬────────┘                         └─────────┬─────────┘
              │                                            │
              └────────────────────┬───────────────────────┘
                                   │
                    ┌──────────────▼──────────────┐
                    │   ProcessPoolExecutor       │
                    │   (50 parallel workers)     │
                    └──────────────┬──────────────┘
                                   │
              ┌────────────────────┴────────────────────┐
              │         Is it an IP address?            │
              └────────────────────┬────────────────────┘
                                   │
         ┌─────────────────────────┴─────────────────────────┐
         │                                                   │
    ┌────▼────┐                                        ┌─────▼─────┐
    │   IP    │                                        │  DOMAIN   │
    └────┬────┘                                        └─────┬─────┘
         │                                                   │
┌────────▼────────────────┐                    ┌─────────────▼─────────────┐
│ Nmap Port Scan          │                    │ 1. Alive/Dead Check       │
│ (Configurable Profile)  │                    │ 2. Security Headers       │
│ • default (top 1000)    │                    │ 3. SSL/TLS Certificate    │
│ • tcp_full (all 65535)  │                    └─────────────┬─────────────┘
│ • udp_common            │                                  │
│ • quick (top 100)       │                                  │
└────────┬────────────────┘                                  │
         │                                                   │
         └─────────────────────┬─────────────────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │   JSON + TXT Report │
                    │   (with history)    │
                    └─────────────────────┘
```

---

## ✨ Features

### Core Scanning
| Feature | Tool | Target |
|---------|------|--------|
| **Port Scanning** | Nmap | IP |
| **Dead Domain Check** | httpx/urllib | Domain |
| **Security Headers** | Nmap NSE | Domain |
| **SSL Certificate** | Nmap NSE | Domain |

### Production Features
| Feature | Description |
|---------|-------------|
| **🔄 ProcessPoolExecutor** | CPU-efficient parallel scanning (50 workers) |
| **⚡ Rate Limiting** | Per-client (IP/API key) request throttling |
| **📋 Scan Profiles** | 6 configurable scan types |
| **🔐 Client Policies** | Access control per client tier |
| **📦 Redis Queue** | Optional production-grade job queue |
| **👷 Worker Processes** | Scalable queue consumers |

---

## 🚀 Quick Start

### One-Line Setup

```bash
# Clone and run (handles all dependencies)
chmod +x setup_and_run.sh
sudo ./setup_and_run.sh
```

### Manual Installation

```bash
# Install system dependencies
sudo apt install nmap python3 python3-pip python3-venv

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Install httpx (optional)
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Install Redis (optional - for production queue)
sudo apt install redis-server
sudo systemctl start redis-server
```

---

## 🔌 REST API

### Start Server

```bash
# Development mode
source venv/bin/activate
python3 api_server.py --host 0.0.0.0 --port 5000

# Production mode (with Gunicorn)
gunicorn -w 8 --threads 4 -b 0.0.0.0:5000 --timeout 600 api_server:app

# With Redis queue enabled
USE_REDIS=true python3 api_server.py
```

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scan` | Start a new scan (sync/async) |
| GET | `/api/scan/<id>` | Get scan result by ID |
| GET | `/api/scans` | List all scans |
| POST | `/api/scan/bulk` | Bulk scan (async, up to 200) |
| POST | `/api/scan/parallel` | Parallel scan (sync, wait for results) |
| GET | `/api/scan/status` | Check multiple scan statuses |
| GET | `/api/scan/profiles` | List available scan profiles |
| GET | `/api/client/info` | Get your policy & rate limit info |
| GET | `/api/health` | Health check |

---

## 📋 Scan Profiles

| Profile | TCP Ports | UDP Ports | Speed | Use Case |
|---------|-----------|-----------|-------|----------|
| `default` | Top 1000 | None | ⚡ Fast | General scanning |
| `tcp_full` | All 65535 | None | 🐢 Slow | Comprehensive TCP |
| `udp_common` | Top 1000 | Common 20 | 🔄 Medium | Include UDP services |
| `udp_full` | None | All 65535 | 🐌 Very Slow | Policy protected |
| `quick` | Top 100 | None | ⚡⚡ Fastest | Quick check |
| `stealth` | Top 1000 | None | 🐢 Slower | Less detectable |

---

## 📡 API Examples

### Single Scan (Synchronous - Default)

```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1"}'
```

Response (direct result):
```json
{
  "id": "a1b2c3d4",
  "target": "192.168.1.1",
  "scan_type": "default",
  "status": "completed",
  "started_at": "2025-12-18T10:00:00",
  "completed_at": "2025-12-18T10:00:15",
  "open_ports": [
    {"port": 22, "state": "open", "service": "ssh"},
    {"port": 80, "state": "open", "service": "http"}
  ]
}
```

### Scan with Profile

```bash
# Full TCP scan
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1", "scan_type": "tcp_full"}'

# Quick scan
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1", "scan_type": "quick"}'
```

### Async Scan

```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1", "async": true}'
```

Response:
```json
{
  "id": "a1b2c3d4",
  "target": "192.168.1.1",
  "status": "pending",
  "message": "Scan started. Use /api/scan/{id} to get results.",
  "check_status": "/api/scan/a1b2c3d4"
}
```

### Bulk Scan (Async)

```bash
curl -X POST http://localhost:5000/api/scan/bulk \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["192.168.1.1", "192.168.1.2", "example.com"],
    "scan_type": "quick"
  }'
```

### Parallel Scan (Wait for All Results)

```bash
curl -X POST http://localhost:5000/api/scan/parallel \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["1.1.1.1", "8.8.8.8", "9.9.9.9"],
    "scan_type": "default"
  }'
```

### Check Your Rate Limit & Policy

```bash
curl http://localhost:5000/api/client/info
```

Response:
```json
{
  "client_id": "192.168...",
  "policy": "default",
  "allowed_scans": ["default", "quick", "stealth"],
  "rate_limit": {
    "max_requests": 20,
    "window_seconds": 60,
    "current_usage": 5
  },
  "max_targets_per_bulk": 50
}
```

### List Scan Profiles

```bash
curl http://localhost:5000/api/scan/profiles
```

---

## 🔐 Authentication & Policies

### API Key Authentication

```bash
# Set API key
export SCANNER_API_KEY="your-secret-key"
python3 api_server.py

# Use in requests
curl -X POST http://localhost:5000/api/scan \
  -H "X-API-Key: your-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1"}'
```

### Client Policies

| Policy | Allowed Scans | Rate Limit | Max Targets |
|--------|---------------|------------|-------------|
| `default` | default, quick, stealth | 10/min | 50 |
| `standard` | + tcp_full, udp_common | 20/min | 100 |
| `premium` | + udp_full | 50/min | 200 |
| `admin` | All | 1000/min | 500 |

Set policy via API keys:
```bash
export ADMIN_API_KEY="admin-key-here"
export PREMIUM_API_KEY="premium-key-here"
export STANDARD_API_KEY="standard-key-here"
```

---

## 📦 Redis Queue (Production)

### Enable Redis Mode

```bash
# Start Redis
sudo systemctl start redis-server

# Start API with Redis
USE_REDIS=true python3 api_server.py

# Start workers (separate terminals)
python3 worker.py --workers 4
```

### Worker Commands

```bash
# Start 4 worker processes
python3 worker.py --workers 4

# Show queue statistics
python3 worker.py --stats

# Clear pending jobs
python3 worker.py --clear
```

### Redis Schema

| Key | Type | Description |
|-----|------|-------------|
| `scan:queue` | List | Pending jobs |
| `scan:result:{id}` | String | Scan result (JSON) |
| `scan:status:{id}` | String | pending/running/completed/failed |

---

## ⚙️ Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SCANNER_API_KEY` | - | API key for authentication |
| `SCANNER_OUTPUT_DIR` | `./scan_results` | Output directory |
| `SCANNER_LOG_LEVEL` | `INFO` | Log level |
| `MAX_PARALLEL_SCANS` | `50` | Max concurrent scans |
| `USE_REDIS` | `false` | Enable Redis queue |
| `REDIS_HOST` | `localhost` | Redis host |
| `REDIS_PORT` | `6379` | Redis port |
| `USE_PROCESS_POOL` | `true` | Use ProcessPool (vs Thread) |
| `ADMIN_API_KEY` | - | Admin tier API key |
| `PREMIUM_API_KEY` | - | Premium tier API key |
| `STANDARD_API_KEY` | - | Standard tier API key |

### config.py Settings

```python
# Nmap settings
nmap_ip_timing = "-T4"          # Timing template
nmap_ip_max_retries = 2         # Max probe retries
nmap_ip_host_timeout = "10m"    # Per-host timeout
nmap_ip_scan_udp = False        # UDP scanning (slow)

# Parallel processing
nmap_min_hostgroup = 100        # Min parallel hosts
nmap_max_hostgroup = 200        # Max parallel hosts
nmap_min_rate = 1500            # Min packets/sec
nmap_max_rate = 5000            # Max packets/sec

# Policy
allow_full_udp = False          # Full UDP scan protection

# Rate limiting
rate_limit_scans = 20           # Scans per window
rate_limit_window = 60          # Window in seconds
```

---

## 📋 Nmap Commands

### Default Profile (Top 1000)
```bash
nmap -Pn -sS -sV -T4 --top-ports 1000 \
  --max-retries 2 --host-timeout 10m \
  --min-hostgroup 100 --max-hostgroup 200 \
  --min-rate 1500 --max-rate 5000 \
  <target>
```

### TCP Full Profile (All Ports)
```bash
nmap -Pn -sS -sV -T4 -p 1-65535 \
  --max-retries 2 --host-timeout 10m \
  <target>
```

### Quick Profile (Top 100)
```bash
nmap -Pn -sS -sV -T4 --top-ports 100 \
  --max-retries 2 --host-timeout 10m \
  <target>
```

---

## 🔍 Security Headers Checked

| Header | Description |
|--------|-------------|
| Strict-Transport-Security | HSTS - Forces HTTPS |
| Content-Security-Policy | CSP - Prevents XSS |
| X-Frame-Options | Clickjacking protection |
| X-Content-Type-Options | MIME sniffing prevention |
| X-XSS-Protection | Legacy XSS filter |
| Referrer-Policy | Controls referrer info |
| Permissions-Policy | Browser features access |
| Cross-Origin-Opener-Policy | COOP isolation |
| Cross-Origin-Embedder-Policy | COEP embedding |
| Cross-Origin-Resource-Policy | CORP sharing |

---

## 📂 Project Structure

```
security-scanner/
├── api_server.py       # REST API server (Flask) - Production hardened
├── scanner_api.py      # Core scanner module + SCAN_PROFILES
├── worker.py           # Redis queue consumer (scalable)
├── daily_scan.py       # Daily batch scan script
├── config.py           # Configuration + CLIENT_POLICIES
├── requirements.txt    # Python dependencies
├── setup_and_run.sh    # One-line setup script
├── Dockerfile          # Docker build
├── targets.txt         # Sample targets
├── venv/               # Virtual environment
├── scan_results/       # Output directory
│   ├── 192.168.1.1.json
│   ├── 192.168.1.1.txt
│   └── example.com.json
└── README.md
```

---

## ⏰ Cron Setup (Daily Scan)

```bash
# Edit crontab
crontab -e

# Run daily at 2 AM
0 2 * * * cd /path/to/scanner && ./venv/bin/python daily_scan.py -f targets.txt >> /var/log/scanner.log 2>&1
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
  -e SCANNER_API_KEY=your-key \
  -e MAX_PARALLEL_SCANS=50 \
  --name scanner-api \
  security-scanner

# Run with Redis
docker run -d \
  -p 5000:5000 \
  -e USE_REDIS=true \
  -e REDIS_HOST=redis-host \
  --name scanner-api \
  security-scanner

# Test
curl http://localhost:5000/api/health
```

---

## 📊 Output Format

### File Naming
- IP: `192.168.1.1.json`, `192.168.1.1.txt`
- Domain: `example.com.json`, `example.com.txt`

### JSON Structure (with history)
```json
{
  "target": "192.168.1.1",
  "total_scans": 3,
  "last_scan": "2025-12-18 10:00:00",
  "scans": [
    {
      "scan_time": "2025-12-18 10:00:00",
      "scan_type": "default",
      "status": "completed",
      "open_ports": [
        {"port": 22, "state": "open", "service": "ssh"},
        {"port": 80, "state": "open", "service": "http"},
        {"port": 443, "state": "filtered", "service": "https"}
      ]
    }
  ]
}
```

---

## 🔧 Troubleshooting

### Rate Limit Exceeded (429)
```bash
# Check your current usage
curl http://localhost:5000/api/client/info
```

### Scan Type Not Allowed (403)
Your client policy doesn't allow that scan type. Check with `/api/scan/profiles`.

### Redis Connection Failed
```bash
# Check if Redis is running
redis-cli ping

# Start Redis
sudo systemctl start redis-server
```

### Nmap Timeout
- Use `quick` profile for faster scans
- Avoid `tcp_full` or `udp_full` for remote hosts

---

## ⚠️ Legal Disclaimer

**Only scan systems you own or have explicit permission to test.**

Unauthorized scanning may be illegal in your jurisdiction.

---

## 📄 License

MIT License

---

## 🏗️ Production Deployment Checklist

- [ ] Set `SCANNER_API_KEY` for authentication
- [ ] Configure client API keys for tiered access
- [ ] Enable Redis for job queue persistence
- [ ] Start multiple workers for scalability
- [ ] Use Gunicorn with multiple workers
- [ ] Set up reverse proxy (nginx) for SSL
- [ ] Configure firewall rules
- [ ] Set up log rotation
- [ ] Monitor with health endpoint
