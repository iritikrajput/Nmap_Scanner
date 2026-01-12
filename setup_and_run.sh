#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# Security Scanner API - Setup & Run Script (Synchronous Edition)
# No Redis, no background workers - simple request/response model
# ═══════════════════════════════════════════════════════════════════════════════

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "═══════════════════════════════════════════════════════════════════════════════"
echo "           Security Scanner API - Setup & Run (Synchronous Edition)            "
echo "═══════════════════════════════════════════════════════════════════════════════"
echo -e "${NC}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ─────────────────────────────────────────────
# Privilege check
# ─────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}⚠ Not running as root (OK). Sudo will be used only when required.${NC}"
fi

# ─────────────────────────────────────────────
# 1. Package manager
# ─────────────────────────────────────────────
echo -e "${BLUE}[1/6] Detecting package manager...${NC}"
if command -v apt-get &>/dev/null; then
    PKG_MANAGER="apt"
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf"
elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum"
else
    PKG_MANAGER="unknown"
fi
echo -e "${GREEN}✓ Package manager: ${PKG_MANAGER}${NC}"

# ─────────────────────────────────────────────
# 2. Python
# ─────────────────────────────────────────────
echo -e "${BLUE}[2/6] Checking Python...${NC}"
command -v python3 >/dev/null || {
    echo -e "${RED}Python3 not found. Install it manually.${NC}"
    exit 1
}
echo -e "${GREEN}✓ Python: $(python3 --version)${NC}"

# ─────────────────────────────────────────────
# 3. Nmap
# ─────────────────────────────────────────────
echo -e "${BLUE}[3/6] Checking Nmap...${NC}"
if ! command -v nmap &>/dev/null; then
    echo "Installing Nmap..."
    case $PKG_MANAGER in
        apt) sudo apt-get install -y nmap ;;
        dnf) sudo dnf install -y nmap ;;
        yum) sudo yum install -y nmap ;;
    esac
fi
echo -e "${GREEN}✓ Nmap installed${NC}"

# ─────────────────────────────────────────────
# 4. httpx (optional)
# ─────────────────────────────────────────────
echo -e "${BLUE}[4/6] Checking httpx...${NC}"
if command -v httpx &>/dev/null; then
    echo -e "${GREEN}✓ httpx already installed: $(httpx -version 2>&1 | head -1)${NC}"
else
    echo -e "${YELLOW}⚠ httpx not installed (optional but recommended).${NC}"
    echo -e "${YELLOW}  Install manually if needed:${NC}"
    echo -e "${YELLOW}  https://github.com/projectdiscovery/httpx${NC}"
fi

# ─────────────────────────────────────────────
# 5. Virtual environment
# ─────────────────────────────────────────────
echo -e "${BLUE}[5/6] Setting up Python virtual environment...${NC}"
VENV_DIR="$SCRIPT_DIR/venv"

if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"
pip install --upgrade pip >/dev/null
pip install -r requirements.txt >/dev/null
echo -e "${GREEN}✓ Virtualenv ready${NC}"

# ─────────────────────────────────────────────
# 6. Directories
# ─────────────────────────────────────────────
echo -e "${BLUE}[6/6] Preparing directories...${NC}"
mkdir -p scan_results
echo -e "${GREEN}✓ scan_results ready${NC}"

# ─────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ Setup complete${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Components:"
echo " • Python: $(python3 --version)"
echo " • Nmap:   $(nmap --version | head -1)"
command -v httpx &>/dev/null && echo " • httpx:  $(httpx -version 2>&1 | head -1)"
echo " • Venv:   $VENV_DIR"
echo ""
echo "Architecture: Synchronous (no Redis, no background workers)"
echo ""

# ─────────────────────────────────────────────
# Start API server
# ─────────────────────────────────────────────
echo -e "${BLUE}Starting Security Scanner API...${NC}"
echo -e "${YELLOW}URL: http://0.0.0.0:5000${NC}"
echo -e "${YELLOW}Endpoint: POST /api/scan${NC}"
echo ""

# Run Gunicorn (NO sudo, uses config file)
if [ -f "$VENV_DIR/bin/gunicorn" ]; then
    echo -e "${GREEN}Running with Gunicorn (production)${NC}"
    exec "$VENV_DIR/bin/gunicorn" -c gunicorn.conf.py api_server:app
else
    echo -e "${YELLOW}Running Flask dev server${NC}"
    exec "$VENV_DIR/bin/python" api_server.py --host 0.0.0.0 --port 5000
fi
