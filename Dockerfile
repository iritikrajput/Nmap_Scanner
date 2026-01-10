# Security Scanner Suite v2.1 - Dockerfile (Gunicorn Optimized)
# Nmap + httpx + Gunicorn

FROM python:3.11-slim

LABEL maintainer="Security Scanner Suite"
LABEL description="Parallel Security Scanner: Nmap + httpx + Gunicorn"
LABEL version="2.1.1"

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
# Install httpx ONLY if not already present
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
COPY scanner_api.py .
COPY api_server.py .
COPY daily_scan.py .
COPY gunicorn.conf.py .

# Output directory
RUN mkdir -p /app/scan_results

# ─────────────────────────────────────────────
# Environment
# ─────────────────────────────────────────────
ENV SCANNER_OUTPUT_DIR=/app/scan_results
ENV SCANNER_LOG_LEVEL=INFO
ENV PYTHONUNBUFFERED=1

# API port
EXPOSE 5000

# ─────────────────────────────────────────────
# Init + Gunicorn (PID 1)
# ─────────────────────────────────────────────
ENTRYPOINT ["/usr/bin/tini", "--"]

CMD ["gunicorn", "-c", "gunicorn.conf.py", "api_server:app"]
