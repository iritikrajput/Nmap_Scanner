# Security Scanner Suite - Dockerfile (Database-First Edition)
# Nmap + httpx + SQLite + Gunicorn
# Background scanner writes to DB, API reads from DB

FROM python:3.11-slim

LABEL maintainer="Security Scanner Suite"
LABEL description="Database-First Security Scanner: Nmap + SQLite + Gunicorn"
LABEL version="4.0.0"

# ─────────────────────────────────────────────
# System dependencies
# ─────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    wget \
    unzip \
    ca-certificates \
    tini \
    && rm -rf /var/lib/apt/lists/*

# ─────────────────────────────────────────────
# Install httpx (optional, for domain checks)
# ─────────────────────────────────────────────
ENV HTTPX_VERSION=1.6.6

RUN if ! command -v httpx >/dev/null 2>&1; then \
        echo "httpx not found, installing version ${HTTPX_VERSION}"; \
        wget -q https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_amd64.zip && \
        unzip httpx_${HTTPX_VERSION}_linux_amd64.zip && \
        mv httpx /usr/local/bin/httpx && \
        chmod +x /usr/local/bin/httpx && \
        rm httpx_${HTTPX_VERSION}_linux_amd64.zip; \
    else \
        echo "httpx already installed, skipping download"; \
    fi

# ─────────────────────────────────────────────
# App setup
# ─────────────────────────────────────────────
WORKDIR /app

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code
COPY config.py .
COPY database.py .
COPY scanner_api.py .
COPY api_server.py .
COPY background_scanner.py .
COPY daily_scan.py .
COPY gunicorn.conf.py .
COPY targets.txt .

# Output directory (contains SQLite DB)
RUN mkdir -p /app/scan_results

# ─────────────────────────────────────────────
# Environment
# ─────────────────────────────────────────────
ENV SCANNER_OUTPUT_DIR=/app/scan_results
ENV DB_PATH=/app/scan_results/scanner.db
ENV SCANNER_LOG_LEVEL=INFO
ENV PYTHONUNBUFFERED=1
ENV BATCH_SIZE=25
ENV MAX_PARALLEL_BATCHES=4

# API port
EXPOSE 5000

# ─────────────────────────────────────────────
# Volume for persistent data
# ─────────────────────────────────────────────
VOLUME ["/app/scan_results"]

# ─────────────────────────────────────────────
# Init (PID 1)
# ─────────────────────────────────────────────
ENTRYPOINT ["/usr/bin/tini", "--"]

# Default: run API server
# Override with: docker run ... python background_scanner.py --continuous
CMD ["gunicorn", "-c", "gunicorn.conf.py", "api_server:app"]
