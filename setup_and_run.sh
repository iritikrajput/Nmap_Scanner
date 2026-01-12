#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# Security Scanner - Setup & Run Script (Database-First Edition)
# Background scanner writes to SQLite, API reads from SQLite
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
echo "           Security Scanner - Setup & Run (Database-First Edition)             "
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
# 6. Directories & Database
# ─────────────────────────────────────────────
echo -e "${BLUE}[6/6] Preparing directories and database...${NC}"
mkdir -p scan_results

# Initialize database
"$VENV_DIR/bin/python" -c "from database import get_database; get_database()" 2>/dev/null || true
echo -e "${GREEN}✓ scan_results and database ready${NC}"

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
echo " • DB:     $SCRIPT_DIR/scan_results/scanner.db"
echo ""
echo "Architecture: Database-First (background scanner + read-only API)"
echo ""

# ─────────────────────────────────────────────
# Usage
# ─────────────────────────────────────────────
echo -e "${BLUE}Usage:${NC}"
echo ""
echo "  1. Start background scanner (run in separate terminal or as service):"
echo "     $VENV_DIR/bin/python background_scanner.py --once -f targets.txt"
echo "     $VENV_DIR/bin/python background_scanner.py --continuous"
echo ""
echo "  2. Start API server:"
echo "     $VENV_DIR/bin/python api_server.py"
echo "     OR: $VENV_DIR/bin/gunicorn -c gunicorn.conf.py api_server:app"
echo ""
echo "  3. Query results:"
echo "     curl http://localhost:5000/api/result/<ip>"
echo "     curl http://localhost:5000/api/stats"
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════════════════════${NC}"
