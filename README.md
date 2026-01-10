Great work — this README is **very polished**, but it no longer fully matches the **final, fixed architecture** we implemented together.

Below is a **COMPLETE, CORRECTED README (v3.1 – FINAL)** that:

✅ Matches **Gunicorn + gthread**
✅ Removes **ProcessPoolExecutor references**
✅ Uses **safe Nmap rates**
✅ Aligns with **Redis worker design**
✅ Matches **actual code behavior**
✅ Is **academically + industry defensible**

You can **replace your `README.md` entirely** with this.

---

# 🛡️ Security Scanner v3.1 – Production Edition

**Enterprise-grade security scanner with REST API, parallel execution, rate limiting, and Redis-backed job queue**

---

## 📊 Architecture (FINAL)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CLIENT REQUEST                                 │
└────────────────────────────────────┬────────────────────────────────────────┘
                                     │
                    ┌────────────────▼────────────────┐
                    │        API GATEWAY (Flask)       │
                    │  ┌─────────────────────────────┐ │
                    │  │ • API Key Authentication    │ │
                    │  │ • Rate Limiting (per IP)    │ │
                    │  │ • Policy Enforcement        │ │
                    │  └─────────────────────────────┘ │
                    └────────────────┬────────────────┘
                                     │
              ┌──────────────────────┴──────────────────────┐
              │                                             │
     ┌────────▼────────┐                         ┌─────────▼─────────┐
     │ In-Memory Mode  │                         │   Redis Queue     │
     │ (Default)       │                         │ (Production)      │
     └────────┬────────┘                         └─────────┬─────────┘
              │                                            │
              └────────────────────┬───────────────────────┘
                                   │
                    ┌──────────────▼──────────────┐
                    │ Gunicorn (gthread workers)  │
                    │  • Multiple workers         │
                    │  • Thread-based concurrency │
                    └──────────────┬──────────────┘
                                   │
              ┌────────────────────┴────────────────────┐
              │         Is target an IP address?        │
              └────────────────────┬────────────────────┘
                                   │
         ┌─────────────────────────┴─────────────────────────┐
         │                                                   │
    ┌────▼────┐                                        ┌─────▼─────┐
    │   IP    │                                        │  DOMAIN   │
    └────┬────┘                                        └─────┬─────┘
         │                                                   │
┌────────▼────────────────┐                    ┌─────────────▼─────────────┐
│ Nmap Port Scan          │                    │ 1. Alive / Dead Check     │
│ (Profile-based)         │                    │ 2. Security Headers       │
│ • default / quick       │                    │ 3. SSL/TLS Certificate    │
│ • tcp_full              │                    └─────────────┬─────────────┘
│ • udp_common             │                                  │
└────────┬────────────────┘                                  │
         │                                                   │
         └─────────────────────┬─────────────────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │   JSON / TXT Report │
                    │   (Historical)      │
                    └─────────────────────┘
```

---

## ✨ Features

### Core Scanning

| Feature             | Tool           | Target |
| ------------------- | -------------- | ------ |
| Port Scanning       | Nmap           | IP     |
| Alive / Dead Check  | httpx / urllib | Domain |
| Security Headers    | Nmap NSE       | Domain |
| SSL/TLS Certificate | Nmap NSE       | Domain |

---

### Production Features

| Feature                      | Description                   |
| ---------------------------- | ----------------------------- |
| ⚡ **Threaded API Execution** | Gunicorn `gthread` workers    |
| 🚦 **Rate Limiting**         | Per-IP / per-client           |
| 📋 **Scan Profiles**         | 6 predefined profiles         |
| 🔐 **Client Policies**       | Tiered access control         |
| 📦 **Redis Queue**           | Optional persistent job queue |
| 👷 **Worker Processes**      | Horizontal scaling via Redis  |

---

## 🚀 Quick Start

### One-Line Setup

```bash
chmod +x setup_and_run.sh
./setup_and_run.sh
```

(No forced reinstallation of httpx)

---

### Manual Setup

```bash
sudo apt install nmap python3 python3-pip python3-venv

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt

# Optional (recommended)
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

---

## 🔌 REST API

### Start Server

```bash
# Development
python3 api_server.py --host 0.0.0.0 --port 5000

# Production
gunicorn -c gunicorn.conf.py api_server:app
```

---

### API Endpoints

| Method | Endpoint             | Description       |
| ------ | -------------------- | ----------------- |
| POST   | `/api/scan`          | Single scan       |
| POST   | `/api/scan/bulk`     | Bulk scan (sync)  |
| POST   | `/api/scan/parallel` | Parallel scan     |
| GET    | `/api/scan/<id>`     | Fetch scan result |
| GET    | `/api/scans`         | List scans        |
| GET    | `/api/scan/profiles` | Scan profiles     |
| GET    | `/api/client/info`   | Rate limit info   |
| GET    | `/api/health`        | Health check      |

---

## 📋 Scan Profiles (FINAL)

| Profile      | TCP      | UDP     | Speed | Use              |
| ------------ | -------- | ------- | ----- | ---------------- |
| `default`    | Top 1000 | ❌       | ⚡     | General          |
| `quick`      | Top 100  | ❌       | ⚡⚡    | Fast             |
| `tcp_full`   | 1–65535  | ❌       | 🐢    | Full TCP         |
| `udp_common` | Top 1000 | Common  | 🔄    | UDP services     |
| `udp_full`   | ❌        | 1–65535 | 🐌    | Policy protected |
| `stealth`    | Top 1000 | ❌       | 🐢    | Low-noise        |

---

## 📡 API Examples

### Single Scan

```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"192.168.1.1"}'
```

---

### Bulk Scan

```bash
curl -X POST http://localhost:5000/api/scan/bulk \
  -H "Content-Type: application/json" \
  -d '{"targets":["1.1.1.1","8.8.8.8"],"scan_type":"quick"}'
```

---

## 📦 Redis Queue (Production Mode)

### Enable Redis

```bash
sudo systemctl start redis-server
USE_REDIS=true gunicorn -c gunicorn.conf.py api_server:app
```

### Start Workers

```bash
python3 worker.py --workers 4
```

### Worker Utilities

```bash
python3 worker.py --stats
python3 worker.py --clear
```

---

## ⚙️ Configuration (FINAL)

### Environment Variables

| Variable             | Description        |
| -------------------- | ------------------ |
| `SCANNER_API_KEY`    | API authentication |
| `SCANNER_OUTPUT_DIR` | Output directory   |
| `SCANNER_LOG_LEVEL`  | Logging            |
| `USE_REDIS`          | Enable Redis       |
| `REDIS_HOST`         | Redis host         |
| `MAX_PARALLEL_SCANS` | API concurrency    |

---

### Safe Nmap Defaults

```python
nmap_ip_timing = "-T4"
nmap_ip_max_retries = 2
nmap_ip_host_timeout = "10m"

# SAFE for threaded execution
nmap_min_hostgroup = 32
nmap_max_hostgroup = 64
nmap_min_rate = 800
nmap_max_rate = 2000
```

---

## 📂 Project Structure

```
security-scanner/
├── api_server.py
├── scanner_api.py
├── worker.py
├── daily_scan.py
├── config.py
├── requirements.txt
├── gunicorn.conf.py
├── setup_and_run.sh
├── Dockerfile
├── scan_results/
└── README.md
```

---

## ⏰ Cron (Daily Scan)

```bash
0 2 * * * cd /path/to/scanner && ./venv/bin/python daily_scan.py -f targets.txt
```

---

## ⚠️ Legal Notice

**Only scan systems you own or have explicit permission to test.**

---

## 🏁 Production Checklist

* [ ] API key configured
* [ ] Redis enabled (optional)
* [ ] Workers running
* [ ] Gunicorn deployed
* [ ] Logs rotated
* [ ] Reverse proxy (HTTPS)

---