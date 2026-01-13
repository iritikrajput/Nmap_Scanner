# Security Scanner – Database-First Edition

**A background security scanner with REST API built on Nmap + Python + SQLite**

Design principle: **Background scanner writes to database → API reads from database**

- Scans run continuously in the background (daily)
- All results stored in SQLite database indexed by IP
- API is read-only, never triggers scans, never waits
- Handles 1 to 100,000+ IPs safely

---

## Architecture

```
                ┌───────────────┐
                │   Clients     │
                │ (HTTP API)    │
                └───────┬───────┘
                        │
                        ▼
              ┌─────────────────────┐
              │  API Server (Flask) │
              │  READ-ONLY          │
              └────────┬────────────┘
                       │
                       ▼
              ┌─────────────────────┐
              │   SQLite Database   │◄────────┐
              │   (scan_results)    │         │
              └─────────────────────┘         │
                                              │
              ┌─────────────────────┐         │
              │ Background Scanner  │─────────┘
              │ (runs daily)        │  WRITES
              └────────┬────────────┘
                       │
         ┌─────────────┴─────────────┐
         │   Batch Processor          │
         │   4 batches × 25 IPs       │
         └─────────────┬─────────────┘
                       │
                       ▼
                    Nmap
```

---

## Quick Start

### 1. Setup

```bash
chmod +x setup_and_run.sh
./setup_and_run.shs
```

### 2. Start Background Scanner

```bash
# Run single scan immediately
python3 background_scanner.py --once -f targets.txt

# Run as continuous service (daily scans)
python3 background_scanner.py --continuous
```

### 3. Start API Server

```bash
# Development
python3 api_server.py

# Production
gunicorn -c gunicorn.conf.py api_server:app
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| **POST** | `/api/scan` | **Queue IP(s) for scanning** |
| GET | `/api/result/<ip>` | Get scan results for an IP |
| GET | `/api/queue` | Queue status |
| GET | `/api/stats` | Database statistics |
| GET | `/api/ips` | List all scanned IPs |
| GET | `/api/health` | Health check |

### Queue IPs for Scanning (POST /api/scan)

Push single IP:
```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.1"}'
```

Push multiple IPs:
```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"ips": ["192.168.1.1", "192.168.1.2", "10.0.0.1"]}'
```

Response (HTTP 202 Accepted):
```json
{
  "status": "queued",
  "job_id": "api_20260112_123456_abc123",
  "queued_ips": 3,
  "message": "IPs added to scan queue. Background scanner will process them."
}
```

### Get Scan Result

```bash
curl http://localhost:5000/api/result/8.8.8.8
```

Response:
```json
{
  "ip": "8.8.8.8",
  "last_scanned": "2026-01-12T00:15:00",
  "ports": [
    {
      "port": 53,
      "protocol": "udp",
      "state": "open",
      "service": "dns",
      "product": "Google DNS",
      "version": ""
    }
  ]
}
```

### Get Statistics

```bash
curl http://localhost:5000/api/stats
```

---

## Database Schema

### `scan_results` table

| Column | Type | Description |
|--------|------|-------------|
| ip | TEXT | IP address (indexed) |
| port | INT | Port number |
| protocol | TEXT | tcp / udp |
| state | TEXT | open / filtered |
| service_name | TEXT | http, ssh, dns |
| service_product | TEXT | nginx, openssh |
| service_version | TEXT | 1.18.0 |
| scanned_at | TIMESTAMP | Last scan time |

---

## Background Scanner

### Run Modes

```bash
# Single scan (immediate)
python3 background_scanner.py --once -f targets.txt

# Continuous service (daily)
python3 background_scanner.py --continuous

# Check status
python3 background_scanner.py --status
```

### Batch Processing

| Setting | Default | Description |
|---------|---------|-------------|
| `BATCH_SIZE` | 25 | IPs per batch |
| `MAX_PARALLEL_BATCHES` | 4 | Concurrent batches |
| `SCAN_INTERVAL_HOURS` | 24 | Hours between scans |

Maximum active scans: 4 batches × 25 IPs = **100 concurrent**

---

## Components

| File | Purpose |
|------|---------|
| `api_server.py` | Read-only REST API |
| `background_scanner.py` | Batch processor & scheduler |
| `database.py` | SQLite database layer |
| `scanner_api.py` | Nmap engine |
| `config.py` | Configuration |

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_PATH` | `./scan_results/scanner.db` | Database path |
| `BATCH_SIZE` | 25 | IPs per batch |
| `MAX_PARALLEL_BATCHES` | 4 | Concurrent batches |
| `SCAN_INTERVAL_HOURS` | 24 | Scan frequency |
| `TARGETS_FILE` | `targets.txt` | IP list file |

---

## Scaling

| IPs | Batches | Time (approx) |
|-----|---------|---------------|
| 100 | 4 | ~2 min |
| 1,000 | 40 | ~20 min |
| 10,000 | 400 | ~3 hours |
| 100,000 | 4,000 | ~30 hours |

System scales linearly, never collapses.

---

## Project Structure

```
security-scanner/
├── api_server.py           # Read-only API
├── background_scanner.py   # Background service
├── database.py             # SQLite layer
├── scanner_api.py          # Nmap engine
├── config.py               # Configuration
├── requirements.txt        # Dependencies
├── gunicorn.conf.py        # Server config
├── setup_and_run.sh        # Setup script
├── Dockerfile              # Container
├── targets.txt             # IP list
└── scan_results/
    └── scanner.db          # SQLite database
```

---

## Systemd Service (Production)

Create `/etc/systemd/system/scanner.service`:

```ini
[Unit]
Description=Security Scanner Background Service
After=network.target

[Service]
Type=simple
User=scanner
WorkingDirectory=/opt/scanner
ExecStart=/opt/scanner/venv/bin/python background_scanner.py --continuous
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable scanner
sudo systemctl start scanner
```

---

## Docker

```bash
# Build
docker build -t security-scanner .

# Run API
docker run -p 5000:5000 -v ./scan_results:/app/scan_results security-scanner

# Run background scanner
docker run -v ./scan_results:/app/scan_results security-scanner \
  python background_scanner.py --continuous
```

---

## When to Use This Architecture

**Good for:**
- Internal SOC tools
- Enterprise asset scanning
- Continuous security monitoring
- Large IP ranges (1-100,000+)
- Production deployments

**Key benefits:**
- API never blocks
- Results always available
- Controlled resource usage
- Simple failure recovery

---

## Legal Notice

**Only scan systems you own or have explicit permission to test.**

---

## Production Checklist

- [ ] Background scanner running as service
- [ ] API server behind reverse proxy (HTTPS)
- [ ] Database backups configured
- [ ] Logs rotated
- [ ] targets.txt populated
- [ ] Monitoring/alerting configured
