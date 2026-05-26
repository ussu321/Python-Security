#!/bin/bash

# ══════════════════════════════════════════════════════════════════════════════
#  ETHICAL HACKING PYTHON — Advanced Linux Installer
#  Developed by Ussu
#  GitHub: https://github.com/ussu321/Python-Security
# ══════════════════════════════════════════════════════════════════════════════

set -e

# =========================
# COLORS
# =========================
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m'

clear

# ============================================================
# BANNER
# ============================================================

if [ -f assets/banner.txt ]; then
    echo -e "${CYAN}"
    cat assets/banner.txt
    echo -e "${NC}"
else
    echo -e "${CYAN}"
    echo "███████╗████████╗██╗  ██╗██╗ ██████╗ █████╗ ██╗         ██╗  ██╗ █████╗  ██████╗██╗  ██╗██╗███╗   ██╗ ██████╗ "
    echo "██╔════╝╚══██╔══╝██║  ██║██║██╔════╝██╔══██╗██║         ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██║████╗  ██║██╔════╝ "
    echo "█████╗     ██║   ███████║██║██║     ███████║██║         ███████║███████║██║     █████╔╝ ██║██╔██╗ ██║██║  ███╗"
    echo "██╔══╝     ██║   ██╔══██║██║██║     ██╔══██║██║         ██╔══██║██╔══██║██║     ██╔═██╗ ██║██║╚██╗██║██║   ██║"
    echo "███████╗   ██║   ██║  ██║██║╚██████╗██║  ██║███████╗    ██║  ██║██║  ██║╚██████╗██║  ██╗██║██║ ╚████║╚██████╔╝"
    echo "╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝ "
    echo -e "${NC}"
fi

echo ""
echo -e "${MAGENTA}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}║              🛡️ ETHICAL HACKING PYTHON 🛡️                  ║${NC}"
echo -e "${MAGENTA}║                                                            ║${NC}"
echo -e "${MAGENTA}║        Advanced Cyber Security Python Framework            ║${NC}"
echo -e "${MAGENTA}║                                                            ║${NC}"
echo -e "${MAGENTA}║                  Developed by Ussu                         ║${NC}"
echo -e "${MAGENTA}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "⚔️  Ethical Hacking Utilities"
echo -e "🛡️  Penetration Testing Modules"
echo -e "💀 Kali Linux Optimized Environment"
echo -e "🐍 Python Security Automation"
echo -e "⚡ Streamlit Hacker Dashboard"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ============================================================
# PYTHON CHECK
# ============================================================

if ! command -v python3 >/dev/null 2>&1; then
    echo -e "${RED}[ERROR]${NC} Python3 is not installed."
    echo "Install Python 3.11+ first and run installer again."
    exit 1
fi

echo -e "${GREEN}[OK]${NC} Python detected: $(python3 --version)"
echo ""

# ============================================================
# VENV NOTICE
# ============================================================

echo -e "${YELLOW}[IMPORTANT NOTICE]${NC}"
echo ""
echo "Python Virtual Environment (venv) is REQUIRED."
echo ""
echo "Auto-creating venv is intentionally disabled."
echo "Manual isolated environments are safer and more stable."
echo ""
echo "Before continuing:"
echo " • Create a Python virtual environment manually"
echo " • Activate the venv"
echo " • Keep environment isolated from other projects"
echo ""

echo -e "${GREEN}Recommended Commands:${NC}"
echo "--------------------------------------------------"
echo "python3 -m venv venv"
echo "source venv/bin/activate"
echo "bash install.sh"
echo "--------------------------------------------------"
echo ""

echo -e "Type ${GREEN}yes${NC}  -> Continue installation"
echo -e "Type ${RED}exit${NC} -> Stop installer"
echo ""

read -p "Enter choice (yes/exit): " USER_INPUT

# ============================================================
# EXIT SAFELY
# ============================================================

if [ "$USER_INPUT" = "exit" ]; then
    echo ""
    echo -e "${RED}[EXIT]${NC} Installation terminated by user."
    echo ""
    exit 1
fi

# ============================================================
# INVALID INPUT
# ============================================================

if [ "$USER_INPUT" != "yes" ]; then
    echo ""
    echo -e "${RED}[ERROR]${NC} Invalid input detected."
    echo "Run installer again and type only: yes or exit"
    echo ""
    exit 1
fi

echo ""
echo -e "${GREEN}[ACCESS GRANTED]${NC} Initializing Ethical Hacking Framework..."
echo ""

# ============================================================
# INSTALLATION PROCESS
# ============================================================

echo -e "${BLUE}[1/5]${NC} Upgrading pip package manager..."
pip install --upgrade pip -q

echo ""
echo -e "${BLUE}[2/5]${NC} Installing dependencies..."
pip install -r requirements.txt -q

echo ""
echo -e "${BLUE}[3/5]${NC} Verifying security modules..."
sleep 1

echo ""
echo -e "${BLUE}[4/5]${NC} Checking Scapy environment..."

if ! python3 -c "import scapy" >/dev/null 2>&1; then
    echo -e "${YELLOW}[WARN]${NC} Scapy may require additional system packages."
    echo -e "${YELLOW}[WARN]${NC} Kali/Debian users may run:"
    echo "sudo apt-get install libpcap-dev"
else
    echo -e "${GREEN}[OK]${NC} Scapy environment verified"
fi

echo ""
echo -e "${BLUE}[5/5]${NC} Finalizing Streamlit environment..."
sleep 1

# ============================================================
# INSTALLATION COMPLETE
# ============================================================

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║               ✅ INSTALLATION COMPLETE ✅                   ║${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║          ETHICAL HACKING PYTHON IS READY                    ║${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}[SUCCESS]${NC} Security framework installed successfully"
echo -e "${GREEN}[READY]${NC} Hacker environment initialized"
echo -e "${GREEN}[GITHUB]${NC} https://github.com/ussu321/Python-Security"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ============================================================
# LAUNCH APPLICATION
# ============================================================

echo -e "${MAGENTA}🚀 Launching Ethical Hacking Dashboard...${NC}"
echo ""

python3 -m streamlit run app.py