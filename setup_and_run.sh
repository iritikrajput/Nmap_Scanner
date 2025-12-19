#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# Security Scanner API - Setup & Run Script
# ═══════════════════════════════════════════════════════════════════════════════

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "═══════════════════════════════════════════════════════════════════════════════"
echo "                    Security Scanner API - Setup Script                         "
echo "═══════════════════════════════════════════════════════════════════════════════"
echo -e "${NC}"

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ─────────────────────────────────────────────────────────────────────────────────
# Check if running as root
# ─────────────────────────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}⚠ Not running as root. Some installations may require sudo.${NC}"
fi

# ─────────────────────────────────────────────────────────────────────────────────
# 1. Update package manager
# ─────────────────────────────────────────────────────────────────────────────────
echo -e "${BLUE}[1/5] Updating package manager...${NC}"
if command -v apt-get &> /dev/null; then
    sudo apt-get update -qq
    PKG_MANAGER="apt"
elif command -v yum &> /dev/null; then
    sudo yum update -y -q
    PKG_MANAGER="yum"
elif command -v dnf &> /dev/null; then
    sudo dnf update -y -q
    PKG_MANAGER="dnf"
else
    echo -e "${YELLOW}⚠ Unknown package manager. Please install dependencies manually.${NC}"
    PKG_MANAGER="unknown"
fi
echo -e "${GREEN}✓ Package manager updated${NC}"

# ─────────────────────────────────────────────────────────────────────────────────
# 2. Install Python3 & pip
# ─────────────────────────────────────────────────────────────────────────────────
echo -e "${BLUE}[2/5] Checking Python3 & pip...${NC}"
if ! command -v python3 &> /dev/null; then
    echo "Installing Python3..."
    case $PKG_MANAGER in
        apt) sudo apt-get install -y python3 python3-pip python3-venv ;;
        yum) sudo yum install -y python3 python3-pip ;;
        dnf) sudo dnf install -y python3 python3-pip ;;
    esac
fi

if ! command -v pip3 &> /dev/null && ! command -v pip &> /dev/null; then
    echo "Installing pip..."
    case $PKG_MANAGER in
        apt) sudo apt-get install -y python3-pip ;;
        yum) sudo yum install -y python3-pip ;;
        dnf) sudo dnf install -y python3-pip ;;
    esac
fi
echo -e "${GREEN}✓ Python3: $(python3 --version)${NC}"

# ─────────────────────────────────────────────────────────────────────────────────
# 3. Install Nmap
# ─────────────────────────────────────────────────────────────────────────────────
echo -e "${BLUE}[3/5] Checking Nmap...${NC}"
if ! command -v nmap &> /dev/null; then
    echo "Installing Nmap..."
    case $PKG_MANAGER in
        apt) sudo apt-get install -y nmap ;;
        yum) sudo yum install -y nmap ;;
        dnf) sudo dnf install -y nmap ;;
    esac
fi
echo -e "${GREEN}✓ Nmap: $(nmap --version | head -1)${NC}"

# ─────────────────────────────────────────────────────────────────────────────────
# 4. Install httpx (optional but recommended)
# ─────────────────────────────────────────────────────────────────────────────────
echo -e "${BLUE}[4/5] Checking httpx...${NC}"
if ! command -v httpx &> /dev/null; then
    echo "Installing httpx..."
    
    # Try to download pre-built binary
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) HTTPX_ARCH="amd64" ;;
        aarch64) HTTPX_ARCH="arm64" ;;
        *) HTTPX_ARCH="amd64" ;;
    esac
    
    # Get latest version
    HTTPX_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/httpx/releases/latest | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    
    if [ -n "$HTTPX_VERSION" ]; then
        HTTPX_URL="https://github.com/projectdiscovery/httpx/releases/download/${HTTPX_VERSION}/httpx_${HTTPX_VERSION#v}_linux_${HTTPX_ARCH}.zip"
        
        # Install unzip if needed
        if ! command -v unzip &> /dev/null; then
            case $PKG_MANAGER in
                apt) sudo apt-get install -y unzip ;;
                yum) sudo yum install -y unzip ;;
                dnf) sudo dnf install -y unzip ;;
            esac
        fi
        
        # Download and install
        curl -sL "$HTTPX_URL" -o /tmp/httpx.zip
        unzip -o /tmp/httpx.zip -d /tmp/httpx_bin
        sudo mv /tmp/httpx_bin/httpx /usr/local/bin/
        sudo chmod +x /usr/local/bin/httpx
        rm -rf /tmp/httpx.zip /tmp/httpx_bin
        echo -e "${GREEN}✓ httpx installed${NC}"
    else
        echo -e "${YELLOW}⚠ Could not fetch httpx version. Skipping...${NC}"
    fi
else
    echo -e "${GREEN}✓ httpx: $(httpx -version 2>&1 | head -1)${NC}"
fi

# ─────────────────────────────────────────────────────────────────────────────────
# 5. Install Redis (optional - for production queue)
# ─────────────────────────────────────────────────────────────────────────────────
echo -e "${BLUE}[5/7] Checking Redis (optional)...${NC}"
if ! command -v redis-server &> /dev/null; then
    echo -e "${YELLOW}Redis not installed. Install for production queue? (y/n)${NC}"
    read -t 10 -n 1 INSTALL_REDIS || INSTALL_REDIS="n"
    echo
    if [[ "$INSTALL_REDIS" =~ ^[Yy]$ ]]; then
        case $PKG_MANAGER in
            apt) sudo apt-get install -y redis-server ;;
            yum) sudo yum install -y redis ;;
            dnf) sudo dnf install -y redis ;;
        esac
        sudo systemctl enable redis-server 2>/dev/null || true
        sudo systemctl start redis-server 2>/dev/null || true
        echo -e "${GREEN}✓ Redis installed and started${NC}"
    else
        echo -e "${YELLOW}⚠ Redis skipped (in-memory mode will be used)${NC}"
    fi
else
    echo -e "${GREEN}✓ Redis: $(redis-server --version | head -1)${NC}"
fi

# ─────────────────────────────────────────────────────────────────────────────────
# 6. Create Virtual Environment & Install Python dependencies
# ─────────────────────────────────────────────────────────────────────────────────
echo -e "${BLUE}[6/7] Setting up Python virtual environment...${NC}"

VENV_DIR="$SCRIPT_DIR/venv"

# Create venv if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

# Activate venv and install dependencies
source "$VENV_DIR/bin/activate"
pip install -q --upgrade pip
pip install -q -r requirements.txt
echo -e "${GREEN}✓ Virtual environment created: $VENV_DIR${NC}"
echo -e "${GREEN}✓ Python dependencies installed${NC}"

# ─────────────────────────────────────────────────────────────────────────────────
# 7. Create directories
# ─────────────────────────────────────────────────────────────────────────────────
echo -e "${BLUE}[7/7] Creating directories...${NC}"
mkdir -p scan_results
echo -e "${GREEN}✓ scan_results directory created${NC}"

# ─────────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}                         ✓ Setup Complete!                                     ${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "Dependencies installed:"
echo -e "  • Python3: $(python3 --version 2>&1)"
echo -e "  • Nmap:    $(nmap --version 2>&1 | head -1)"
if command -v httpx &> /dev/null; then
    echo -e "  • httpx:   $(httpx -version 2>&1 | head -1)"
else
    echo -e "  • httpx:   ${YELLOW}Not installed (optional)${NC}"
fi
if command -v redis-server &> /dev/null; then
    echo -e "  • Redis:   $(redis-server --version 2>&1 | head -1)"
else
    echo -e "  • Redis:   ${YELLOW}Not installed (in-memory mode)${NC}"
fi
echo -e "  • Venv:    $VENV_DIR"
echo ""
echo -e "Production Features:"
echo -e "  • ProcessPoolExecutor for CPU-efficient parallel scans"
echo -e "  • Rate limiting per client (IP/API key)"
echo -e "  • Scan profiles: default, tcp_full, udp_common, quick, stealth"
echo -e "  • Client access policies"
echo ""

# ─────────────────────────────────────────────────────────────────────────────────
# Start the server
# ─────────────────────────────────────────────────────────────────────────────────
echo -e "${BLUE}Starting Security Scanner API Server...${NC}"
echo -e "${YELLOW}Server will run on: http://0.0.0.0:5000${NC}"
echo -e "${YELLOW}Press Ctrl+C to stop${NC}"
echo ""

# Ensure venv is activated
source "$VENV_DIR/bin/activate"

# Check if Redis should be enabled
if command -v redis-cli &> /dev/null && redis-cli ping 2>/dev/null | grep -q PONG; then
    export USE_REDIS=true
    echo -e "${GREEN}✓ Redis detected and running - queue mode enabled${NC}"
else
    export USE_REDIS=false
    echo -e "${YELLOW}⚠ Redis not running - using in-memory mode${NC}"
fi

# Use gunicorn if available, otherwise flask dev server
if [ -f "$VENV_DIR/bin/gunicorn" ]; then
    echo -e "${GREEN}Running with Gunicorn (production mode)${NC}"
    echo -e "${GREEN}  Workers: 8 | Threads: 4 | Max Parallel Scans: 50${NC}"
    # -w 8 = 8 worker processes
    # --threads 4 = 4 threads per worker (8x4 = 32 concurrent requests)
    # --timeout 600 = 10 minutes (for parallel scans)
    # --graceful-timeout 300 = graceful shutdown timeout
    sudo -E "$VENV_DIR/bin/gunicorn" \
        -w 8 \
        --threads 4 \
        -b 0.0.0.0:5000 \
        --timeout 600 \
        --graceful-timeout 300 \
        --keep-alive 5 \
        api_server:app
else
    echo -e "${YELLOW}Running with Flask dev server${NC}"
    sudo -E "$VENV_DIR/bin/python" api_server.py --host 0.0.0.0 --port 5000
fi

