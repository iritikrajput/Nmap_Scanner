# Security Scanner Suite - Dockerfile
# Production-ready container with Nmap and Nuclei

FROM python:3.11-slim

# Labels
LABEL maintainer="Security Scanner Suite"
LABEL description="Production-ready security scanner with Nmap + Nuclei"
LABEL version="1.1.0"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    wget \
    unzip \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei - fetch latest version dynamically
RUN NUCLEI_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/') \
    && echo "Installing Nuclei version: ${NUCLEI_VERSION}" \
    && wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" -O nuclei.zip \
    && unzip nuclei.zip -d /usr/local/bin/ \
    && rm nuclei.zip \
    && chmod +x /usr/local/bin/nuclei

# Update Nuclei templates
RUN nuclei -update-templates || true

# Create app directory
WORKDIR /app

# Copy application files
COPY config.py .
COPY scanner_api.py .
COPY intelligent_scanner.py .
COPY nse_scanner.py .

# Create output directory
RUN mkdir -p /app/scan_results

# Set environment variables
ENV SCANNER_OUTPUT_DIR=/app/scan_results
ENV SCANNER_LOG_LEVEL=INFO
ENV SCANNER_SHODAN_ENABLED=true
# SHODAN_API_KEY should be passed at runtime: docker run -e SHODAN_API_KEY=xxx ...

# Default command
ENTRYPOINT ["python3", "scanner_api.py"]
CMD ["--help"]
