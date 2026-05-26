"""
Ethical Hacking Python - Utility Module
Developed by issu321
https://github.com/issu321/Ethical-Hacking-Python

Core utilities, helpers, export systems, logging, and reusable components.
"""

import os
import sys
import re
import json
import csv
import io
import logging
import hashlib
import random
import string
import time
import datetime
import ipaddress
from typing import Dict, List, Any, Optional, Tuple, Union
from pathlib import Path

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("ethical_hacking_python")

# ═══════════════════════════════════════════════════════════
# VALIDATION UTILITIES
# ═══════════════════════════════════════════════════════════

def validate_ip(ip: str) -> bool:
    """Validate IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_domain(domain: str) -> bool:
    """Validate domain name format."""
    pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$"
    if re.match(pattern, domain) and "." in domain:
        return True
    return False


def validate_email(email: str) -> bool:
    """Basic email validation."""
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


# ═══════════════════════════════════════════════════════════
# FORMATTING UTILITIES
# ═══════════════════════════════════════════════════════════

def format_bytes(size: int) -> str:
    """Convert bytes to human-readable format."""
    for unit in ["B", "KB", "MB", "GB", "TB", "PB"]:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} EB"


def format_duration(seconds: float) -> str:
    """Format duration in human-readable form."""
    if seconds < 60:
        return f"{seconds:.2f}s"
    elif seconds < 3600:
        return f"{seconds/60:.2f}m"
    else:
        return f"{seconds/3600:.2f}h"


def truncate_string(s: str, max_len: int = 100) -> str:
    """Truncate string with ellipsis."""
    return s if len(s) <= max_len else s[:max_len-3] + "..."


# ═══════════════════════════════════════════════════════════
# EXPORT UTILITIES
# ═══════════════════════════════════════════════════════════

def export_to_csv(data: List[Dict[str, Any]], filename: str = "report.csv") -> bytes:
    """Export list of dicts to CSV bytes."""
    if not data:
        return b""
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=data[0].keys())
    writer.writeheader()
    writer.writerows(data)
    return output.getvalue().encode("utf-8")


def export_to_json(data: Any, filename: str = "report.json") -> bytes:
    """Export data to JSON bytes."""
    return json.dumps(data, indent=2, default=str).encode("utf-8")


def export_to_txt(content: str, filename: str = "report.txt") -> bytes:
    """Export string to TXT bytes."""
    return content.encode("utf-8")


def generate_security_report(
    title: str,
    findings: List[Dict[str, Any]],
    recommendations: List[str],
    metadata: Dict[str, Any]
) -> str:
    """Generate a formatted security report text."""
    lines = [
        "=" * 70,
        f"  ETHICAL HACKING PYTHON - SECURITY REPORT",
        f"  {title}",
        "=" * 70,
        f"  Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Platform: Ethical Hacking & Security Intelligence Platform",
        f"  Developer: issu321 | https://github.com/issu321/Ethical-Hacking-Python",
        "=" * 70,
        "",
        "[METADATA]",
    ]
    for k, v in metadata.items():
        lines.append(f"  {k}: {v}")
    lines.extend(["", "[FINDINGS]", "-" * 70])
    for i, finding in enumerate(findings, 1):
        lines.append(f"  #{i}")
        for k, v in finding.items():
            lines.append(f"    {k}: {v}")
        lines.append("")
    lines.extend(["-" * 70, "", "[RECOMMENDATIONS]", "-" * 70])
    for i, rec in enumerate(recommendations, 1):
        lines.append(f"  {i}. {rec}")
    lines.extend(["", "=" * 70, "  END OF REPORT", "=" * 70])
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════
# LOGGING & EVENT SYSTEM
# ═══════════════════════════════════════════════════════════

def log_event(event_type: str, message: str, level: str = "info") -> Dict[str, Any]:
    """Log a security event and return the event dict."""
    event = {
        "timestamp": datetime.datetime.now().isoformat(),
        "type": event_type,
        "message": message,
        "level": level.upper()
    }
    if level.lower() == "critical":
        logger.critical(f"[{event_type}] {message}")
    elif level.lower() == "error":
        logger.error(f"[{event_type}] {message}")
    elif level.lower() == "warning":
        logger.warning(f"[{event_type}] {message}")
    else:
        logger.info(f"[{event_type}] {message}")
    return event


def save_threat_log(event: Dict[str, Any], filepath: str = "threat_logs.json") -> None:
    """Append event to threat_logs.json."""
    try:
        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        else:
            data = []
        data.append(event)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
    except Exception as e:
        logger.error(f"Failed to save threat log: {e}")


# ═══════════════════════════════════════════════════════════
# FAKE SOC FEED GENERATOR
# ═══════════════════════════════════════════════════════════

SOC_ALERTS = [
    ("INTRUSION_DETECTION", "Suspicious login attempt blocked from {ip}", "warning"),
    ("FIREWALL", "Outbound connection to known C2 domain flagged: {domain}", "critical"),
    ("MALWARE_SCAN", "Heuristic match on file hash: {hash}", "warning"),
    ("NETWORK", "Anomalous traffic spike detected on port {port}", "warning"),
    ("AUTH", "Multiple failed authentication attempts from {ip}", "error"),
    ("SYSTEM", "Unexpected process elevation detected: {proc}", "critical"),
    ("DNS", "DNS tunneling pattern detected from {ip}", "error"),
    ("WEB", "SQL injection attempt blocked on endpoint /api/login", "warning"),
    ("EMAIL", "Phishing email campaign detected targeting internal users", "warning"),
    ("CRYPTO", "Cryptomining activity detected on host {ip}", "error"),
    ("PATCH", "Critical vulnerability CVE-2024-{cve} scan completed", "info"),
    ("AI_SOC", "AI anomaly model flagged behavioral deviation", "warning"),
]

SOC_IPS = ["192.168.1.105", "10.0.0.23", "172.16.0.5", "203.0.113.44", "198.51.100.12"]
SOC_DOMAINS = ["evil-c2.xyz", "phish-bank.tk", "darknet-node.onion", "malware-dl.cc"]
SOC_PROCS = ["svch0st.exe", "crss.exe", "lsass_clone.exe", "winlogon_helper.exe"]


def generate_soc_alert() -> Dict[str, str]:
    """Generate a single fake SOC alert for educational simulation."""
    alert_type, template, level = random.choice(SOC_ALERTS)
    msg = template.format(
        ip=random.choice(SOC_IPS),
        domain=random.choice(SOC_DOMAINS),
        hash=hashlib.md5(os.urandom(16)).hexdigest()[:16],
        port=random.choice([22, 23, 25, 53, 80, 443, 3389, 8080]),
        proc=random.choice(SOC_PROCS),
        cve=random.randint(1000, 9999)
    )
    return {
        "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
        "type": alert_type,
        "message": msg,
        "level": level.upper()
    }


def get_soc_feed(count: int = 20) -> List[Dict[str, str]]:
    """Generate multiple fake SOC alerts."""
    random.seed(int(time.time() // 30))  # Change every 30s for "live" feel
    return [generate_soc_alert() for _ in range(count)]


# ═══════════════════════════════════════════════════════════
# TERMINAL / BOOT UTILITIES
# ═══════════════════════════════════════════════════════════

def get_banner() -> str:
    """Return the ASCII banner."""
    banner_path = os.path.join("assets", "banner.txt")
    if os.path.exists(banner_path):
        with open(banner_path, "r", encoding="utf-8") as f:
            return f.read()
    return """
╔══════════════════════════════════════════════════════════════════════╗
║     ███████╗████████╗██╗  ██╗██╗ ██████╗ █████╗ ██╗     ██╗            ║
║     ██╔════╝╚══██╔══╝██║  ██║██║██╔════╝██╔══██╗██║     ██║            ║
║     █████╗     ██║   ███████║██║██║     ███████║██║     ██║            ║
║     ██╔══╝     ██║   ██╔══██║██║██║     ██╔══██║██║     ██║            ║
║     ███████╗   ██║   ██║  ██║██║╚██████╗██║  ██║███████╗██║            ║
║     ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝            ║
║                                                                      ║
║     HACKING    PYTHON    SECURITY    INTELLIGENCE    PLATFORM        ║
║                                                                      ║
║     Developed by issu321  |  github.com/issu321/Ethical-Hacking-Python ║
╚══════════════════════════════════════════════════════════════════════╝
"""


def get_boot_sequence() -> List[str]:
    """Generate fake boot sequence lines."""
    return [
        "[BOOT] Initializing Ethical Hacking Python Kernel...",
        "[BOOT] Loading security modules...",
        "[BOOT] Mounting threat intelligence database...",
        "[BOOT] Initializing neural heuristic engine...",
        "[BOOT] Calibrating OSINT sensors...",
        "[BOOT] Loading packet analytics submodule...",
        "[BOOT] Establishing secure telemetry channel...",
        "[BOOT] Handshake with SOC grid: ESTABLISHED",
        "[BOOT] Threat feed synchronization: ACTIVE",
        "[BOOT] AI Security Insight Engine: ONLINE",
        "[BOOT] Cyber visualization engine: RENDERING",
        "[BOOT] System integrity check: PASSED",
        "[BOOT] All defensive modules armed.",
        "[BOOT] Welcome to the Ethical Hacking & Security Intelligence Platform",
    ]


# ═══════════════════════════════════════════════════════════
# MISC HELPERS
# ═══════════════════════════════════════════════════════════

def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy += - p_x * (p_x).bit_length()  # rough approximation
    # Better calculation:
    from math import log2
    entropy = 0.0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy -= p_x * log2(p_x)
    return entropy


def get_common_passwords() -> List[str]:
    """Return a list of common weak passwords for educational comparison."""
    return [
        "123456", "password", "12345678", "qwerty", "123456789",
        "letmein", "1234567", "football", "iloveyou", "admin",
        "welcome", "monkey", "login", "abc123", "111111",
        "123123", "password123", "1234", "baseball", "qwertyuiop"
    ]


def get_dangerous_extensions() -> List[str]:
    """Return potentially dangerous file extensions for educational warning."""
    return [
        ".exe", ".dll", ".bat", ".cmd", ".sh", ".bin",
        ".scr", ".msi", ".vbs", ".js", ".jar", ".ps1",
        ".php", ".asp", ".aspx", ".jsp", ".cgi", ".pl"
    ]


def safe_file_read(filepath: str, max_size: int = 10 * 1024 * 1024) -> Optional[bytes]:
    """Safely read file with size limit."""
    try:
        size = os.path.getsize(filepath)
        if size > max_size:
            return None
        with open(filepath, "rb") as f:
            return f.read()
    except Exception:
        return None


def get_platform_info() -> Dict[str, str]:
    """Get basic platform information."""
    return {
        "system": os.name,
        "platform": sys.platform,
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "cwd": os.getcwd(),
    }


# ═══════════════════════════════════════════════════════════
# COLOR / THEME UTILITIES FOR STREAMLIT
# ═══════════════════════════════════════════════════════════

def get_cyberpunk_css() -> str:
    """Return cyberpunk CSS for Streamlit injection."""
    css_path = os.path.join("assets", "styles.css")
    if os.path.exists(css_path):
        with open(css_path, "r", encoding="utf-8") as f:
            return f"<style>{f.read()}</style>"
    return ""


def severity_color(severity: str) -> str:
    """Return hex color for severity level."""
    colors = {
        "critical": "#ff0040",
        "high": "#ff4500",
        "medium": "#ffaa00",
        "low": "#00ff41",
        "info": "#00f0ff",
        "safe": "#00ff41",
        "warning": "#ffaa00",
        "error": "#ff0040",
    }
    return colors.get(severity.lower(), "#00f0ff")


def severity_badge(severity: str) -> str:
    """Return HTML badge for severity."""
    color = severity_color(severity)
    return f"""
    <span style="
        background-color: {color}22;
        color: {color};
        border: 1px solid {color};
        border-radius: 4px;
        padding: 2px 8px;
        font-size: 0.75rem;
        font-weight: bold;
        text-transform: uppercase;
    ">{severity.upper()}</span>
    """


# ═══════════════════════════════════════════════════════════
# AI-LIKE INSIGHT GENERATOR
# ═══════════════════════════════════════════════════════════

def generate_ai_insight(context: str, metrics: Dict[str, Any]) -> str:
    """Generate an AI-like security insight based on context and metrics."""
    insights = []

    if context == "password":
        score = metrics.get("score", 0)
        entropy = metrics.get("entropy", 0)
        if score < 30:
            insights.append("Password exhibits critically low entropy and appears in common dictionary patterns. Immediate rotation recommended.")
        elif score < 60:
            insights.append("Password entropy is moderate. Consider increasing length and adding special characters to resist brute-force attacks.")
        else:
            insights.append("Password demonstrates strong entropy characteristics. Maintain this complexity standard across all credentials.")
        if entropy < 25:
            insights.append("Shannon entropy analysis reveals predictable character distribution. Attackers using Markov chains could reduce cracking time significantly.")

    elif context == "network":
        open_ports = metrics.get("open_ports", [])
        risk_score = metrics.get("risk_score", 0)
        if len(open_ports) > 5:
            insights.append(f"Attack surface is expanded with {len(open_ports)} exposed services. Each open port represents a potential ingress vector.")
        if risk_score > 70:
            insights.append("Network risk profile is elevated. Consider implementing additional segmentation and ingress filtering rules.")
        elif risk_score < 30:
            insights.append("Network posture appears defensive. Minimal exposed services reduce lateral movement opportunities for adversaries.")

    elif context == "file":
        suspicious = metrics.get("suspicious", False)
        if suspicious:
            insights.append("File extension and entropy analysis suggest potentially executable payload. Quarantine and sandbox analysis recommended.")
        else:
            insights.append("File structure appears benign based on extension and entropy baseline. Standard defensive monitoring sufficient.")

    elif context == "vulnerability":
        count = metrics.get("count", 0)
        if count == 0:
            insights.append("No simulated vulnerabilities detected in current scan scope. Maintain regular assessment cadence.")
        elif count > 5:
            insights.append(f"Concentration of {count} simulated vulnerabilities indicates systemic configuration drift. Prioritize patch management cycle.")
        else:
            insights.append("Moderate vulnerability count detected. Address high-severity findings before medium and low priority items.")

    elif context == "domain":
        age_days = metrics.get("age_days", 0)
        if age_days < 30:
            insights.append("Domain registration is recent. Phishing campaigns frequently utilize newly registered domains. Elevate monitoring.")
        else:
            insights.append("Domain exhibits established registration history. Reputation-based filtering likely permits standard traffic.")

    else:
        insights.append("Security metrics analyzed. Maintain defense-in-depth strategy with layered controls.")

    return " ".join(insights)


# ═══════════════════════════════════════════════════════════
# SESSION / STATE HELPERS
# ═══════════════════════════════════════════════════════════

def init_session_state(st_module, defaults: Dict[str, Any]) -> None:
    """Initialize Streamlit session state variables."""
    for key, val in defaults.items():
        if key not in st_module.session_state:
            st_module.session_state[key] = val
