# Security Scanner Suite v2.0 - Dockerfile
# Nmap + httpx architecture

FROM python:3.11-slim

LABEL maintainer="Security Scanner Suite"
LABEL description="Lightweight security scanner: Nmap + httpx"
LABEL version="2.0.0"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    wget \
    curl \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install httpx (ProjectDiscovery)
RUN HTTPX_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/httpx/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/') \
    && echo "Installing httpx version: ${HTTPX_VERSION}" \
    && wget -q "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_amd64.zip" -O httpx.zip \
    && unzip httpx.zip -d /usr/local/bin/ \
    && rm httpx.zip \
    && chmod +x /usr/local/bin/httpx

# Create app directory
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY config.py .
COPY scanner_api.py .
COPY daily_scan.py .
COPY api_server.py .

# Create output directory
RUN mkdir -p /app/scan_results

# Set environment variables
ENV SCANNER_OUTPUT_DIR=/app/scan_results
ENV SCANNER_LOG_LEVEL=INFO

# Expose API port
EXPOSE 5000

# Default command - start API server
ENTRYPOINT ["python3", "api_server.py"]
CMD ["--host", "0.0.0.0", "--port", "5000"]
