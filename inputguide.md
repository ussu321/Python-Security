# 📖 Input Guide

**Ethical Hacking Python** — Security Intelligence Platform  
Developed by issu321 | [GitHub](https://github.com/issu321/Ethical-Hacking-Python)

---

## Table of Contents

1. [Scan Examples](#scan-examples)
2. [Domain Examples](#domain-examples)
3. [Upload Examples](#upload-examples)
4. [Analytics Examples](#analytics-examples)
5. [Linux Usage](#linux-usage)
6. [Windows Usage](#windows-usage)
7. [Troubleshooting](#troubleshooting)

---

## Scan Examples

### Basic Localhost Scan
- **Target IP:** `127.0.0.1`
- **Port Range:** Common Ports (Top 20)
- **Timeout:** 1.0s
- **Workers:** 50
- **Expected:** SSH (22), HTTP (80), HTTPS (443) may appear open depending on local services

### Custom Web Server Scan
- **Target IP:** `192.168.1.1` (your router)
- **Port Range:** Web Services (80, 443, 8080, 8443)
- **Use case:** Verify exposed web management interfaces

### Database Port Audit
- **Target IP:** Internal server IP
- **Port Range:** Database Ports (3306, 5432, 27017, 6379, 9200)
- **Use case:** Check for exposed database services in lab environment

### Full Custom Range
- **Target IP:** `10.0.0.5`
- **Custom Ports:** `21,22,23,25,53,80,110,143,443,445,3306,3389,5432,5900,8080`
- **Timeout:** 2.0s for slower networks

> ⚠️ **Only scan systems you own or have explicit written authorization to test.**

---

## Domain Examples

### WHOIS Lookup
- **Domain:** `example.com`
- **Output:** Registrar, creation date, expiration, name servers, organization

### DNS Intelligence
- **Domain:** `google.com`
- **Record Types:** A, MX, NS, TXT
- **Output:** IP addresses, mail servers, name servers, SPF records

### SSL Certificate Analysis
- **Domain:** `github.com`
- **Port:** 443 (default)
- **Output:** SSL version, cipher suite, expiry date, serial number

### Subdomain Enumeration
- **Domain:** `example.com`
- **Max Subdomains:** 50
- **Output:** Resolved subdomains with IP mappings and relationship graph

---

## Upload Examples

### Threat Log Analysis
- **File:** `threat_logs.json`
- **Action:** Upload in Upload Center
- **Output:** JSON parsed and displayed with structured formatting

### CSV Data Import
- **File:** `security_data.csv`
- **Format:** Header row with numeric columns
- **Action:** Upload in Upload Center
- **Output:** DataFrame view + automatic bar chart for numeric columns

### Log File Inspection
- **File:** `server.log` or `auth.log`
- **Action:** Upload in Upload Center
- **Output:** Terminal-style display of log contents

### File Security Analysis
- **File:** Any file (`.exe`, `.pdf`, `.zip`, etc.)
- **Action:** Upload in File Security Analyzer
- **Output:** Entropy, hashes, extension analysis, MIME detection, risk scoring

---

## Analytics Examples

### Custom Radar Chart
- **Categories:** `Speed,Security,Reliability,Scalability,Usability`
- **Values:** `85,70,90,65,80`
- **Output:** 5-axis radar chart for benchmark visualization

### Custom Bar Chart
- **Data (JSON):** `[{"name":"Firewall","value":45},{"name":"IDS","value":30},{"name":"SIEM","value":25}]`
- **X Key:** `name`
- **Y Key:** `value`
- **Output:** Colored bar chart with cyberpunk theme

### Custom Pie Chart
- **Labels:** `Malware,Phishing,DDoS,Insider`
- **Values:** `35,25,20,20`
- **Output:** Donut chart with threat category distribution

### Custom Line Chart
- **X Values:** `Mon,Tue,Wed,Thu,Fri,Sat,Sun`
- **Y Values:** `12,19,15,22,18,10,8`
- **Output:** Trend line with area fill

---

## Linux Usage

### Kali Linux / Debian / Ubuntu

```bash
# Clone repository
git clone https://github.com/issu321/Ethical-Hacking-Python.git
cd Ethical-Hacking-Python

# Run installer (creates venv + installs deps + launches app)
bash install.sh

# Or manually:
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

### Required System Packages (if scapy fails)
```bash
sudo apt-get update
sudo apt-get install -y libpcap-dev tcpdump
```

### Running without install script
```bash
source venv/bin/activate
streamlit run app.py --server.port 8501
```

### Accessing from remote
```bash
streamlit run app.py --server.address 0.0.0.0 --server.port 8501
```
Then access via `http://<your-ip>:8501`

---

## Windows Usage

### Windows 10 / 11

```powershell
# Clone repository
git clone https://github.com/issu321/Ethical-Hacking-Python.git
cd Ethical-Hacking-Python

# Run installer
.\install.bat

# Or manually:
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

### Windows Terminal / PowerShell
```powershell
# Activate venv
.\venv\Scripts\Activate.ps1

# Launch
streamlit run app.py --server.port 8501
```

### CMD
```cmd
venv\Scripts\activate.bat
streamlit run app.py
```

> **Note:** On Windows, some features (packet sniffing, raw sockets) require Administrator privileges. The app gracefully degrades to simulated data when privileges are insufficient.

---

## Troubleshooting

### Module Import Errors
```bash
# Ensure venv is activated
source venv/bin/activate  # Linux
venv\Scripts\activate     # Windows

# Reinstall requirements
pip install -r requirements.txt
```

### Streamlit not found
```bash
# Use python module syntax
python -m streamlit run app.py

# Or use full venv path
./venv/bin/python -m streamlit run app.py
```

### Scapy Installation Issues (Linux)
```bash
sudo apt-get install libpcap-dev
pip install scapy
```

### Scapy Installation Issues (Windows)
- Install [Npcap](https://npcap.com/) or [WinPcap](https://www.winpcap.org/)
- Run terminal as Administrator for full packet features

### Port Scan Returns All Closed
- Check firewall settings on target
- Increase timeout (try 2.0s or 3.0s)
- Verify target IP is reachable: `ping <target>`
- Some ports require root/admin for accurate detection

### WHOIS Lookup Fails
- Check internet connectivity
- Some domains have rate-limited WHOIS servers
- Try again after a few seconds

### DNS Resolution Errors
- Verify domain spelling
- Check if DNS resolver is configured correctly
- Try using Google's DNS: `8.8.8.8`

### File Upload Too Large
- Default limit is reasonable for most files
- For very large files (>100MB), use File Security Analyzer which has size checks

### CSS/Theme Not Loading
- CSS is embedded in app.py and injected automatically
- Ensure browser allows inline styles
- Clear browser cache and reload

### Permission Denied on Linux
```bash
chmod +x install.sh
bash install.sh
```

### General Debug
```bash
# Check Python version (need 3.11+)
python --version

# Check installed packages
pip list

# Run with verbose errors
streamlit run app.py --logger.level=debug
```

---

## Quick Reference

| Feature | Input Example | Page |
|---------|--------------|------|
| Port Scan | `127.0.0.1` | Advanced Network Scanner |
| WHOIS | `example.com` | Domain Intelligence |
| DNS | `google.com` | DNS Intelligence |
| Subdomains | `example.com` | Subdomain Intelligence |
| Password | `MyStr0ng!P@ss` | Password Analyzer |
| Hash Text | `hello world` | Hashing Laboratory |
| Hash File | `document.pdf` | Hashing Laboratory |
| File Analysis | `suspicious.exe` | File Security Analyzer |
| Vuln Scan | Use scan results | Vulnerability Intelligence |
| System Stats | (auto-detected) | System Monitor |
| Upload Logs | `threat_logs.json` | Upload Center |
| Export Data | Any report | Download Center |

---

**Developed by issu321** | [github.com/issu321/Ethical-Hacking-Python](https://github.com/issu321/Ethical-Hacking-Python)
