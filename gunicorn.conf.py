# gunicorn.conf.py
# Security Scanner Suite – Gunicorn Configuration
# Optimized for Nmap + ThreadPoolExecutor

bind = "0.0.0.0:5000"

# ─────────────────────────────────────────────
# Workers & Threads
# ─────────────────────────────────────────────
# API is I/O bound, scanning happens in threads
workers = 4
threads = 2
worker_class = "gthread"

# ─────────────────────────────────────────────
# Timeouts
# ─────────────────────────────────────────────
# Nmap scans can take time
timeout = 600
keepalive = 5

# ─────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────
loglevel = "info"
accesslog = "-"
errorlog = "-"

# ─────────────────────────────────────────────
# Stability (prevents memory leaks)
# ─────────────────────────────────────────────
max_requests = 1000
max_requests_jitter = 50
