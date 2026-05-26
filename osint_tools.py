"""
Ethical Hacking Python - OSINT Intelligence Module
Developed by issu321
https://github.com/issu321/Ethical-Hacking-Python

OSINT-inspired tools: WHOIS, DNS, subdomain intelligence, IP intel, metadata.
"""

import socket
import json
import re
import random
import hashlib
import ipaddress
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse

# Optional imports with graceful fallback
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from utils import validate_domain, validate_ip, log_event

# ═══════════════════════════════════════════════════════════
# WHOIS LOOKUP
# ═══════════════════════════════════════════════════════════

def whois_lookup(domain: str) -> Dict[str, Any]:
    """Perform WHOIS lookup on a domain. Educational/defensive use only."""
    if not validate_domain(domain):
        return {"error": "Invalid domain format", "domain": domain}

    result = {
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "name_servers": [],
        "status": [],
        "emails": [],
        "org": None,
        "country": None,
        "raw_available": False
    }

    if not WHOIS_AVAILABLE:
        result["error"] = "python-whois not installed. Run: pip install python-whois"
        return result

    try:
        w = whois.whois(domain)
        result["registrar"] = w.registrar if hasattr(w, "registrar") else None
        result["creation_date"] = str(w.creation_date) if hasattr(w, "creation_date") else None
        result["expiration_date"] = str(w.expiration_date) if hasattr(w, "expiration_date") else None
        result["name_servers"] = w.name_servers if hasattr(w, "name_servers") else []
        result["status"] = w.status if hasattr(w, "status") else []
        result["emails"] = w.emails if hasattr(w, "emails") else []
        result["org"] = w.org if hasattr(w, "org") else None
        result["country"] = w.country if hasattr(w, "country") else None
        result["raw_available"] = True

        # Calculate domain age if possible
        if result["creation_date"]:
            try:
                cd = w.creation_date
                if isinstance(cd, list):
                    cd = cd[0]
                if hasattr(cd, "year"):
                    age_days = (datetime.now() - cd).days
                    result["age_days"] = age_days
            except Exception:
                pass

    except Exception as e:
        result["error"] = str(e)
        log_event("WHOIS", f"Lookup failed for {domain}: {e}", "warning")

    return result


# ═══════════════════════════════════════════════════════════
# DNS INTELLIGENCE
# ═══════════════════════════════════════════════════════════

def dns_lookup(domain: str, record_types: List[str] = None) -> Dict[str, Any]:
    """Perform DNS resolution for multiple record types."""
    if not validate_domain(domain):
        return {"error": "Invalid domain", "domain": domain}

    if record_types is None:
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]

    result = {
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "records": {},
        "resolvable": False
    }

    if not DNS_AVAILABLE:
        result["error"] = "dnspython not installed. Run: pip install dnspython"
        # Fallback to socket.gethostbyname for A records
        try:
            ip = socket.gethostbyname(domain)
            result["records"]["A"] = [ip]
            result["resolvable"] = True
        except Exception as e:
            result["records"]["A"] = [f"Error: {e}"]
        return result

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            records = []
            for rdata in answers:
                records.append(str(rdata))
            result["records"][rtype] = records
            result["resolvable"] = True
        except dns.resolver.NXDOMAIN:
            result["records"][rtype] = ["NXDOMAIN"]
        except dns.resolver.NoAnswer:
            result["records"][rtype] = ["NoAnswer"]
        except Exception as e:
            result["records"][rtype] = [f"Error: {e}"]

    return result


def reverse_dns(ip: str) -> Dict[str, Any]:
    """Perform reverse DNS lookup."""
    if not validate_ip(ip):
        return {"error": "Invalid IP", "ip": ip}

    result = {"ip": ip, "timestamp": datetime.now().isoformat(), "hostnames": []}
    try:
        hostnames = socket.gethostbyaddr(ip)
        result["hostnames"] = [hostnames[0]]
    except Exception as e:
        result["error"] = str(e)
    return result


# ═══════════════════════════════════════════════════════════
# SUBDOMAIN INTELLIGENCE (SIMULATED EDUCATIONAL)
# ═══════════════════════════════════════════════════════════

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "blog", "shop", "api", "dev", "test",
    "staging", "portal", "vpn", "remote", "webmail", "secure", "cdn",
    "media", "static", "docs", "support", "help", "forum", "chat",
    "app", "mobile", "download", "downloads", "news", "beta", "alpha",
    "demo", "internal", "extranet", "intranet", "git", "repo", "ci",
    "jenkins", "jira", "confluence", "wiki", "monitor", "grafana",
    "prometheus", "kibana", "elastic", "db", "database", "sql", "mysql",
    "postgres", "redis", "mongo", "rabbitmq", "kafka", "backend",
    "frontend", "proxy", "gateway", "lb", "loadbalancer", "dns",
    "ns1", "ns2", "mx", "smtp", "imap", "pop", "webdav", "caldav",
    "autodiscover", "autoconfig", "m", "s", "t", "i", "o", "p", "v"
]


def subdomain_enumeration(domain: str, wordlist: List[str] = None, max_subs: int = 50) -> Dict[str, Any]:
    """Simulate subdomain enumeration with DNS resolution. Educational only."""
    if not validate_domain(domain):
        return {"error": "Invalid domain", "domain": domain}

    if wordlist is None:
        wordlist = COMMON_SUBDOMAINS[:max_subs]

    result = {
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "subdomains": [],
        "total_tested": len(wordlist),
        "found_count": 0
    }

    found = []
    for sub in wordlist[:max_subs]:
        full_domain = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(full_domain)
            found.append({
                "subdomain": full_domain,
                "ip": ip,
                "status": "resolved"
            })
        except socket.gaierror:
            pass
        except Exception as e:
            found.append({
                "subdomain": full_domain,
                "ip": None,
                "status": f"error: {e}"
            })

    result["subdomains"] = found
    result["found_count"] = len([s for s in found if s.get("ip")])
    return result


# ═══════════════════════════════════════════════════════════
# IP INTELLIGENCE
# ═══════════════════════════════════════════════════════════

def ip_intelligence(ip: str) -> Dict[str, Any]:
    """Gather IP intelligence. Educational simulation with real basics."""
    if not validate_ip(ip):
        return {"error": "Invalid IP", "ip": ip}

    result = {
        "ip": ip,
        "timestamp": datetime.now().isoformat(),
        "version": None,
        "is_private": False,
        "is_loopback": False,
        "is_multicast": False,
        "reverse_dns": None,
        "asn_simulated": None,
        "country_simulated": None,
        "threat_score_simulated": 0
    }

    try:
        addr = ipaddress.ip_address(ip)
        result["version"] = f"IPv{addr.version}"
        result["is_private"] = addr.is_private
        result["is_loopback"] = addr.is_loopback
        result["is_multicast"] = addr.is_multicast
        result["is_reserved"] = addr.is_reserved
        result["is_link_local"] = addr.is_link_local
    except Exception as e:
        result["error"] = str(e)
        return result

    # Reverse DNS
    try:
        rdns = socket.gethostbyaddr(ip)
        result["reverse_dns"] = rdns[0]
    except Exception:
        pass

    # Simulated threat intelligence for educational visualization
    # In production, this would query real threat intelligence APIs
    random.seed(int(hashlib.md5(ip.encode()).hexdigest(), 16) % 10000)
    result["asn_simulated"] = f"AS{random.randint(1000, 65000)}"
    countries = ["US", "DE", "GB", "FR", "NL", "SG", "JP", "CA", "AU", "BR"]
    result["country_simulated"] = random.choice(countries)
    result["threat_score_simulated"] = random.randint(0, 100)
    result["reputation_simulated"] = random.choice(["clean", "suspicious", "malicious", "clean", "clean"])

    return result


# ═══════════════════════════════════════════════════════════
# SSL / CERTIFICATE ANALYSIS
# ═══════════════════════════════════════════════════════════

def ssl_certificate_info(domain: str, port: int = 443) -> Dict[str, Any]:
    """Analyze SSL certificate. Educational basic analysis."""
    if not validate_domain(domain):
        return {"error": "Invalid domain", "domain": domain}

    result = {
        "domain": domain,
        "port": port,
        "timestamp": datetime.now().isoformat(),
        "has_ssl": False,
        "issuer": None,
        "subject": None,
        "not_before": None,
        "not_after": None,
        "serial_number": None,
        "version": None,
        "cipher": None
    }

    try:
        import ssl
        import certifi
        context = ssl.create_default_context(cafile=certifi.where())
        with socket.create_connection((domain, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                result["has_ssl"] = True
                result["subject"] = cert.get("subject")
                result["issuer"] = cert.get("issuer")
                result["not_before"] = cert.get("notBefore")
                result["not_after"] = cert.get("notAfter")
                result["serial_number"] = cert.get("serialNumber")
                result["version"] = version
                result["cipher"] = cipher[0] if cipher else None

                # Check expiration
                if cert.get("notAfter"):
                    try:
                        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                        days_left = (not_after - datetime.utcnow()).days
                        result["days_until_expiry"] = days_left
                        result["expired"] = days_left < 0
                    except Exception:
                        pass
    except Exception as e:
        result["error"] = str(e)
        result["has_ssl"] = False

    return result


# ═══════════════════════════════════════════════════════════
# METADATA EXTRACTION
# ═══════════════════════════════════════════════════════════

def extract_file_metadata(file_content: bytes, filename: str) -> Dict[str, Any]:
    """Extract basic metadata from file bytes. Educational."""
    result = {
        "filename": filename,
        "size_bytes": len(file_content),
        "md5": hashlib.md5(file_content).hexdigest(),
        "sha1": hashlib.sha1(file_content).hexdigest(),
        "sha256": hashlib.sha256(file_content).hexdigest(),
        "entropy": None,
        "mime_guess": None,
        "extension": None,
        "magic_bytes": None
    }

    # Extension
    if "." in filename:
        result["extension"] = filename.split(".")[-1].lower()

    # Magic bytes (first 8 bytes hex)
    if len(file_content) >= 8:
        result["magic_bytes"] = file_content[:8].hex().upper()

    # Simple MIME guess based on magic bytes
    magic = result["magic_bytes"] or ""
    mime_map = {
        "89504E47": "image/png",
        "FFD8FF": "image/jpeg",
        "47494638": "image/gif",
        "25504446": "application/pdf",
        "504B0304": "application/zip",
        "52617221": "application/x-rar",
        "7F454C46": "application/x-elf",
        "4D5A": "application/x-dosexec",
        "1F8B08": "application/gzip",
    }
    for sig, mime in mime_map.items():
        if magic.startswith(sig):
            result["mime_guess"] = mime
            break

    # Entropy
    from math import log2
    if file_content:
        entropy = 0.0
        for x in range(256):
            p_x = float(file_content.count(bytes([x]))) / len(file_content)
            if p_x > 0:
                entropy -= p_x * log2(p_x)
        result["entropy"] = round(entropy, 4)

    return result


# ═══════════════════════════════════════════════════════════
# DOMAIN REPUTATION SIMULATION
# ═══════════════════════════════════════════════════════════

def domain_reputation_simulation(domain: str) -> Dict[str, Any]:
    """Simulate domain reputation scoring for educational visualization."""
    if not validate_domain(domain):
        return {"error": "Invalid domain", "domain": domain}

    # Deterministic pseudo-random based on domain hash
    h = int(hashlib.md5(domain.encode()).hexdigest(), 16)
    random.seed(h)

    result = {
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "reputation_score": random.randint(0, 100),
        "malware_score_simulated": random.randint(0, 100),
        "phishing_score_simulated": random.randint(0, 100),
        "spam_score_simulated": random.randint(0, 100),
        "categories_simulated": random.sample(
            ["Business", "Technology", "Education", "Suspicious", "Hosting", "CDN", "News"],
            k=random.randint(1, 3)
        ),
        "risk_level": random.choice(["Low", "Medium", "High", "Critical"]),
        "note": "Simulated data for educational threat intelligence visualization only."
    }

    return result
