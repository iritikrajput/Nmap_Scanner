# Security Scanner – Synchronous Edition

**A synchronous security scanning API built on Nmap + Python**

Design principle: **One request → one scan (or small batch) → one response**

No Redis, no job queue, no background workers. Simple, predictable, debuggable.

---

## Architecture

```
Client
  │
  │ POST /api/scan
  │
Flask API Server (Gunicorn)
  │
  │ (parallel threads inside request)
  │
SecurityScanner (scanner_api.py)
  │
  │ subprocess.run()
  │
Nmap
  │
XML output
  │
Parsed JSON result
  │
Returned in HTTP response
```

---

## Quick Start

### One-Line Setup

```bash
chmod +x setup_and_run.sh
./setup_and_run.sh
```

### Manual Setup

```bash
sudo apt install nmap python3 python3-pip python3-venv

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt

# Optional (recommended for domain checks)
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### Start Server

```bash
# Development
python3 api_server.py --host 0.0.0.0 --port 5000

# Production
gunicorn -c gunicorn.conf.py api_server:app
```

---

## API Usage

### Endpoint

```
POST /api/scan
GET  /api/health
```

### Single Target

```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"192.168.1.1"}'
```

### Multiple Targets (max 10)

```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"targets":["1.1.1.1","8.8.8.8"], "scan_type":"quick"}'
```

### Response Format

```json
{
  "total_targets": 2,
  "scan_type": "default",
  "duration_seconds": 6.8,
  "results": [
    {
      "target": "1.1.1.1",
      "status": "completed",
      "ip": "1.1.1.1",
      "open_ports": [...]
    }
  ]
}
```

---

## Scan Profiles

| Profile   | TCP Ports  | Allowed in API | Notes        |
|-----------|------------|----------------|--------------|
| `quick`   | Top 100    | Yes            | Fast scans   |
| `default` | Top 1000   | Yes            | General use  |
| `stealth` | Top 1000   | Yes            | Low-noise    |
| `tcp_full`| 1-65535    | No             | Too slow     |
| `udp_common`| + UDP    | No             | Too slow     |
| `udp_full`| All UDP    | No             | Too slow     |

Long-running profiles (`tcp_full`, `udp_common`, `udp_full`) are blocked because they exceed HTTP timeout limits.

---

## Bulk Scanning Limits

| Feature              | Status |
|----------------------|--------|
| Single IP            | Yes    |
| Small bulk (≤10 IPs) | Yes    |
| Parallel scanning    | Yes (threads) |
| CIDR ranges          | No     |
| 100+ IPs             | No     |

These limits exist because:
- Nmap is CPU + network heavy
- HTTP requests must not block forever
- OS file descriptors & sockets are finite

---

## Components

| File | Purpose |
|------|---------|
| `api_server.py` | Flask API - accepts requests, validates, returns results |
| `scanner_api.py` | Core engine - builds Nmap commands, parses XML, produces JSON |
| `config.py` | All configuration - Nmap timing, rate limits, output settings |
| `daily_scan.py` | Cron script for batch scanning from targets.txt |
| `gunicorn.conf.py` | Production server config |

---

## Configuration

### Environment Variables

| Variable             | Description           |
|----------------------|-----------------------|
| `SCANNER_OUTPUT_DIR` | Output directory      |
| `SCANNER_LOG_LEVEL`  | Logging level (INFO)  |
| `SCANNER_NMAP_TIMEOUT` | Nmap timeout (300s) |

### Nmap Defaults (config.py)

```python
nmap_ip_timing = "-T4"
nmap_ip_max_retries = 2
nmap_ip_host_timeout = "10m"
nmap_min_rate = 800
nmap_max_rate = 2000
```

---

## Project Structure

```
security-scanner/
├── api_server.py       # API layer
├── scanner_api.py      # Nmap engine
├── config.py           # Configuration
├── daily_scan.py       # Cron scanner
├── requirements.txt    # Python deps
├── gunicorn.conf.py    # Server config
├── setup_and_run.sh    # Setup script
├── Dockerfile          # Container
├── targets.txt         # Target list
├── scan_results/       # Output
└── README.md
```

---

## Cron (Daily Scan)

```bash
0 2 * * * cd /path/to/scanner && ./venv/bin/python daily_scan.py -f targets.txt
```

---

## Docker

```bash
docker build -t security-scanner .
docker run -p 5000:5000 security-scanner
```

---

## When to Use This Architecture

**Good for:**
- Internal SOC tools
- University / research projects
- Red-team assessments
- Controlled client networks
- CLI-driven automation

**Not suitable for:**
- Public SaaS
- Large customer base
- Internet-wide scanning
- Long-running UDP scans

For those use cases, async + queue + workers is required.

---

## Legal Notice

**Only scan systems you own or have explicit permission to test.**

---

## Production Checklist

- [ ] Gunicorn deployed
- [ ] Logs rotated
- [ ] Reverse proxy (HTTPS)
- [ ] Rate limits configured
- [ ] Output directory writable
