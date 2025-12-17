#!/usr/bin/env python3
"""
Intelligent Security Scanner v1.0
Nmap + Nuclei Smart Pipeline with Decision Engine

Flow: Nmap → Analyze → Decide → Nuclei (targeted)
"""

import subprocess
import argparse
import os
import sys
import json
import xml.etree.ElementTree as ET
from datetime import datetime
import urllib.request
import urllib.error
import ssl
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
import re


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ScanConfig:
    """Scanner configuration"""
    nmap_ports: str = "--top-ports 1000"
    nmap_extra: str = "-sV -T4"
    nmap_scripts: str = "default,http-headers,http-security-headers,ssl-cert,ssl-enum-ciphers"
    nuclei_severity: str = "medium,high,critical"
    nuclei_rate_limit: int = 150
    output_dir: str = "./scan_results"
    timeout: int = 300
    check_headers: bool = True  # Enable HTTP security header checking


# Nuclei template mapping based on service detection
NUCLEI_TEMPLATE_MAP = {
    # Web services
    "http": ["http/misconfiguration", "http/exposures", "http/cves"],
    "https": ["http/misconfiguration", "http/exposures", "ssl", "http/cves"],
    "http-proxy": ["http/misconfiguration", "http/exposures"],
    
    # SSL/TLS
    "ssl": ["ssl/detect", "ssl/misconfigurations"],
    "tls": ["ssl/detect", "ssl/misconfigurations"],
    
    # Databases
    "mysql": ["network/cves", "default-logins"],
    "postgresql": ["network/cves", "default-logins"],
    "mongodb": ["network/cves", "default-logins", "network/exposures"],
    "redis": ["network/cves", "default-logins", "network/exposures"],
    "elasticsearch": ["network/cves", "network/exposures"],
    
    # Remote access
    "ssh": ["network/cves", "default-logins"],
    "ftp": ["network/cves", "default-logins", "network/exposures"],
    "telnet": ["network/cves", "default-logins"],
    "rdp": ["network/cves"],
    "vnc": ["network/cves", "default-logins"],
    
    # Mail
    "smtp": ["network/cves", "network/exposures"],
    "imap": ["network/cves"],
    "pop3": ["network/cves"],
    
    # Other
    "dns": ["dns"],
    "ldap": ["network/cves", "default-logins"],
    "smb": ["network/cves", "network/exposures"],
    "snmp": ["network/cves", "network/exposures"],
}

# Security header checks
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy", 
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]

# Security header descriptions for reporting
HEADER_DESCRIPTIONS = {
    "Strict-Transport-Security": "HSTS - Forces HTTPS connections",
    "Content-Security-Policy": "CSP - Prevents XSS and injection attacks",
    "X-Frame-Options": "Clickjacking protection",
    "X-Content-Type-Options": "MIME type sniffing prevention",
    "X-XSS-Protection": "XSS filter (legacy browsers)",
    "Referrer-Policy": "Controls referrer information",
    "Permissions-Policy": "Controls browser features access",
}


# ═══════════════════════════════════════════════════════════════════════════════
# HTTP SECURITY HEADER CHECKER
# ═══════════════════════════════════════════════════════════════════════════════

def check_http_security_headers(target: str, ports: list) -> dict:
    """
    Check HTTP security headers by making actual HTTP requests
    PRIORITIZES HTTPS over HTTP for security header checking
    Returns dict with headers found, missing headers, and analysis
    """
    result = {
        "checked": False,
        "url": "",
        "protocol": "",
        "headers_found": {},
        "missing_headers": [],
        "security_issues": [],
        "score": 0,
        "https_available": False,
        "http_to_https_redirect": False,
    }
    
    # Separate HTTPS and HTTP URLs - HTTPS takes priority
    https_urls = []
    http_urls = []
    
    for port in ports:
        if port in [443, 8443, 4443]:
            https_urls.append(f"https://{target}:{port}" if port != 443 else f"https://{target}")
        elif port in [80, 8080, 8000, 3000, 5000]:
            http_urls.append(f"http://{target}:{port}" if port != 80 else f"http://{target}")
    
    # PRIORITIZE HTTPS - check HTTPS first, then HTTP only if HTTPS fails
    urls_to_check = https_urls + http_urls
    
    if not urls_to_check:
        return result
    
    # Check if HTTP redirects to HTTPS
    if http_urls and https_urls:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            req = urllib.request.Request(
                http_urls[0],
                headers={'User-Agent': 'Mozilla/5.0 (Security Scanner)'}
            )
            
            with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
                final_url = response.geturl()
                if final_url.startswith('https://'):
                    result["http_to_https_redirect"] = True
        except:
            pass
    
    # Try HTTPS URLs first, then HTTP
    for url in urls_to_check:
        is_https = url.startswith('https://')
        
        try:
            # Create SSL context that doesn't verify (for self-signed certs)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            req = urllib.request.Request(
                url,
                headers={'User-Agent': 'Mozilla/5.0 (Security Scanner)'}
            )
            
            with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
                headers = dict(response.headers)
                result["checked"] = True
                result["url"] = url
                result["protocol"] = "HTTPS" if is_https else "HTTP"
                result["https_available"] = is_https
                
                # Check for each security header
                for sec_header in SECURITY_HEADERS:
                    # Case-insensitive header check
                    found = False
                    for h_name, h_value in headers.items():
                        if h_name.lower() == sec_header.lower():
                            result["headers_found"][sec_header] = h_value
                            found = True
                            break
                    
                    if not found:
                        # HSTS only makes sense over HTTPS
                        if sec_header == "Strict-Transport-Security" and not is_https:
                            continue  # Don't flag HSTS as missing on HTTP
                        result["missing_headers"].append(sec_header)
                
                # HTTPS-specific security checks
                if is_https:
                    # Check HSTS (only relevant for HTTPS)
                    if "Strict-Transport-Security" in result["headers_found"]:
                        hsts_value = result["headers_found"]["Strict-Transport-Security"]
                        if "max-age" in hsts_value.lower():
                            try:
                                max_age = int(hsts_value.split("max-age=")[1].split(";")[0].strip())
                                if max_age < 31536000:  # Less than 1 year
                                    result["security_issues"].append(f"HSTS max-age too short ({max_age}s, should be >= 31536000)")
                            except:
                                pass
                        if "includesubdomains" not in hsts_value.lower():
                            result["security_issues"].append("HSTS missing includeSubDomains")
                        if "preload" not in hsts_value.lower():
                            result["security_issues"].append("HSTS missing preload directive")
                    else:
                        # HSTS missing on HTTPS is critical
                        result["security_issues"].append("🚨 CRITICAL: HSTS not configured on HTTPS - Vulnerable to SSL stripping attacks")
                else:
                    # HTTP-only site warnings
                    if not https_urls:
                        result["security_issues"].append("🚨 CRITICAL: No HTTPS available - All traffic is unencrypted")
                    elif not result["http_to_https_redirect"]:
                        result["security_issues"].append("⚠️ HTTP does not redirect to HTTPS")
                
                # Check X-Frame-Options
                if "X-Frame-Options" in result["headers_found"]:
                    xfo = result["headers_found"]["X-Frame-Options"].upper()
                    if xfo not in ["DENY", "SAMEORIGIN"]:
                        result["security_issues"].append(f"X-Frame-Options should be DENY or SAMEORIGIN, got: {xfo}")
                
                # Check X-Content-Type-Options
                if "X-Content-Type-Options" in result["headers_found"]:
                    xcto = result["headers_found"]["X-Content-Type-Options"].lower()
                    if xcto != "nosniff":
                        result["security_issues"].append("X-Content-Type-Options should be 'nosniff'")
                
                # Check Content-Security-Policy
                if "Content-Security-Policy" in result["headers_found"]:
                    csp = result["headers_found"]["Content-Security-Policy"].lower()
                    if "unsafe-inline" in csp:
                        result["security_issues"].append("CSP contains 'unsafe-inline' - XSS risk")
                    if "unsafe-eval" in csp:
                        result["security_issues"].append("CSP contains 'unsafe-eval' - XSS risk")
                
                # Calculate score (out of 100)
                total_headers = len(SECURITY_HEADERS)
                found_count = len(result["headers_found"])
                result["score"] = int((found_count / total_headers) * 100)
                
                # Bonus/penalty for HTTPS
                if is_https and "Strict-Transport-Security" in result["headers_found"]:
                    result["score"] = min(100, result["score"] + 10)  # Bonus for HSTS on HTTPS
                
                # Found a working URL, stop checking
                break
                
        except urllib.error.HTTPError as e:
            # Even on HTTP errors, we can check headers
            if hasattr(e, 'headers'):
                headers = dict(e.headers)
                result["checked"] = True
                result["url"] = url
                result["protocol"] = "HTTPS" if is_https else "HTTP"
                result["https_available"] = is_https
                
                for sec_header in SECURITY_HEADERS:
                    found = False
                    for h_name, h_value in headers.items():
                        if h_name.lower() == sec_header.lower():
                            result["headers_found"][sec_header] = h_value
                            found = True
                            break
                    if not found:
                        # HSTS only makes sense over HTTPS
                        if sec_header == "Strict-Transport-Security" and not is_https:
                            continue
                        result["missing_headers"].append(sec_header)
                
                # HTTPS-specific: Flag missing HSTS
                if is_https and "Strict-Transport-Security" not in result["headers_found"]:
                    result["security_issues"].append("🚨 CRITICAL: HSTS not configured on HTTPS")
                
                total_headers = len(SECURITY_HEADERS)
                found_count = len(result["headers_found"])
                result["score"] = int((found_count / total_headers) * 100)
                break
        except Exception as e:
            continue
    
    # Final check: If we only checked HTTP and HTTPS was available, note it
    if result["checked"] and not result["https_available"] and https_urls:
        result["security_issues"].append("⚠️ HTTPS available but could not connect - check SSL/TLS configuration")
    
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class PortInfo:
    """Information about a discovered port"""
    port: int
    protocol: str
    state: str
    service: str
    product: str = ""
    version: str = ""
    extra_info: str = ""
    scripts: Dict[str, str] = field(default_factory=dict)


@dataclass
class TLSInfo:
    """TLS/SSL information"""
    version: str = ""
    cipher: str = ""
    cert_subject: str = ""
    cert_issuer: str = ""
    cert_expiry: str = ""
    cert_cn: str = ""
    vulnerabilities: List[str] = field(default_factory=list)


@dataclass
class HostInfo:
    """Complete host scan information"""
    target: str
    ip: str = ""
    hostname: str = ""
    state: str = ""
    ports: List[PortInfo] = field(default_factory=list)
    tls_info: Optional[TLSInfo] = None
    http_headers: Dict[str, str] = field(default_factory=dict)
    missing_headers: List[str] = field(default_factory=list)
    findings: List[Dict] = field(default_factory=list)
    nuclei_templates: Set[str] = field(default_factory=set)
    risk_score: int = 0
    flags: List[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════════
# BANNER & UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

def print_banner():
    """Print scanner banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║            🧠 INTELLIGENT SECURITY SCANNER v1.0                              ║
║                  Nmap + Nuclei Smart Pipeline                                ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Flow: Nmap → Analyze → Decide → Nuclei (targeted)                           ║
║                                                                              ║
║  ✓ Service-based template selection    ✓ Phishing detection                  ║
║  ✓ Security header analysis            ✓ TLS/Certificate validation          ║
║  ✓ Intelligent decision engine         ✓ Severity-based filtering            ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_section(title: str, icon: str = "📌"):
    """Print section header"""
    print(f"\n{'═' * 80}")
    print(f"{icon} {title}")
    print(f"{'═' * 80}")


def print_subsection(title: str):
    """Print subsection header"""
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}")


def check_tool(tool: str) -> bool:
    """Check if a tool is installed"""
    try:
        result = subprocess.run(
            [tool, "--version"] if tool != "nuclei" else [tool, "-version"],
            capture_output=True, text=True
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False


def read_targets(filepath: str) -> List[str]:
    """Read targets from file"""
    if not os.path.exists(filepath):
        print(f"[!] Error: File '{filepath}' not found")
        sys.exit(1)
    
    targets = []
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                targets.append(line)
    return targets


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1: NMAP SCANNING
# ═══════════════════════════════════════════════════════════════════════════════

def run_nmap(target: str, config: ScanConfig, output_dir: str) -> str:
    """Run Nmap scan and return XML output path"""
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = re.sub(r'[^\w\-.]', '_', target)
    xml_output = os.path.join(output_dir, f"nmap_{safe_target}_{timestamp}.xml")
    txt_output = os.path.join(output_dir, f"nmap_{safe_target}_{timestamp}.txt")
    
    cmd = [
        "nmap",
        "--open",  # Only open ports
        "-oX", xml_output,
        "-oN", txt_output,
    ]
    
    # Add port specification
    if config.nmap_ports:
        cmd.extend(config.nmap_ports.split())
    
    # Add scripts (including security header scripts)
    if config.nmap_scripts:
        cmd.extend(["--script", config.nmap_scripts])
    
    # Add extra arguments
    if config.nmap_extra:
        cmd.extend(config.nmap_extra.split())
    
    # Add target
    cmd.append(target)
    
    print(f"\n  🔍 Running: {' '.join(cmd)}")
    
    try:
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=config.timeout
        )
        
        if process.returncode == 0:
            print(f"  ✅ Nmap completed")
            return xml_output
        else:
            print(f"  ⚠️  Nmap warning: {process.stderr[:200]}")
            return xml_output if os.path.exists(xml_output) else ""
            
    except subprocess.TimeoutExpired:
        print(f"  ⏰ Nmap timeout after {config.timeout}s")
        return ""
    except Exception as e:
        print(f"  ❌ Nmap error: {e}")
        return ""


def parse_nmap_xml(xml_path: str, target: str) -> Optional[HostInfo]:
    """Parse Nmap XML output into HostInfo"""
    
    if not os.path.exists(xml_path):
        return None
    
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"  ⚠️  XML parse error: {e}")
        return None
    
    host_info = HostInfo(target=target)
    
    # Find host
    for host in root.findall('.//host'):
        # Get state
        state = host.find('status')
        if state is not None:
            host_info.state = state.get('state', 'unknown')
        
        # Get IP address
        for addr in host.findall('address'):
            if addr.get('addrtype') == 'ipv4':
                host_info.ip = addr.get('addr', '')
        
        # Get hostname
        for hostname in host.findall('.//hostname'):
            host_info.hostname = hostname.get('name', '')
        
        # Parse ports
        for port in host.findall('.//port'):
            port_state = port.find('state')
            if port_state is None or port_state.get('state') != 'open':
                continue
            
            service = port.find('service')
            port_info = PortInfo(
                port=int(port.get('portid', 0)),
                protocol=port.get('protocol', 'tcp'),
                state=port_state.get('state', 'unknown'),
                service=service.get('name', 'unknown') if service is not None else 'unknown',
                product=service.get('product', '') if service is not None else '',
                version=service.get('version', '') if service is not None else '',
            )
            
            # Parse scripts
            for script in port.findall('script'):
                script_id = script.get('id', '')
                script_output = script.get('output', '')
                port_info.scripts[script_id] = script_output
                
                # Extract TLS info
                if 'ssl-cert' in script_id:
                    host_info.tls_info = parse_ssl_cert(script_output, target)
                
                # Extract HTTP headers
                if 'http-headers' in script_id or 'http-security-headers' in script_id:
                    parse_http_headers(script_output, host_info)
            
            host_info.ports.append(port_info)
    
    return host_info


def parse_ssl_cert(output: str, target: str) -> TLSInfo:
    """Parse SSL certificate script output"""
    tls = TLSInfo()
    
    lines = output.split('\n')
    for line in lines:
        line = line.strip()
        if 'Subject:' in line:
            tls.cert_subject = line.split('Subject:', 1)[-1].strip()
            # Extract CN
            cn_match = re.search(r'CN[=:]([^,/]+)', tls.cert_subject, re.IGNORECASE)
            if cn_match:
                tls.cert_cn = cn_match.group(1).strip()
        elif 'Issuer:' in line:
            tls.cert_issuer = line.split('Issuer:', 1)[-1].strip()
        elif 'Not valid after:' in line:
            tls.cert_expiry = line.split(':', 1)[-1].strip()
    
    return tls


def parse_http_headers(output: str, host_info: HostInfo):
    """Parse HTTP headers and check for missing security headers"""
    lines = output.split('\n')
    
    for line in lines:
        if ':' in line:
            parts = line.split(':', 1)
            if len(parts) == 2:
                header_name = parts[0].strip()
                header_value = parts[1].strip()
                host_info.http_headers[header_name] = header_value
    
    # Check for missing security headers
    for header in SECURITY_HEADERS:
        found = any(h.lower() == header.lower() for h in host_info.http_headers.keys())
        if not found:
            host_info.missing_headers.append(header)


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 2: DECISION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_and_decide(host_info: HostInfo) -> HostInfo:
    """Analyze Nmap results and decide which Nuclei templates to run"""
    
    print_subsection("🧠 Decision Engine Analysis")
    
    # Track decisions
    decisions = []
    
    # Analyze each open port
    for port in host_info.ports:
        service = port.service.lower()
        
        # Map service to templates
        for svc_pattern, templates in NUCLEI_TEMPLATE_MAP.items():
            if svc_pattern in service:
                host_info.nuclei_templates.update(templates)
                decisions.append(f"Port {port.port}/{service} → {', '.join(templates)}")
        
        # Special port-based decisions
        if port.port in [80, 8080, 8000, 3000, 5000]:
            host_info.nuclei_templates.add("http/misconfiguration")
            host_info.nuclei_templates.add("http/exposures")
            decisions.append(f"Port {port.port} (HTTP) → http/misconfiguration, http/exposures")
        
        if port.port in [443, 8443, 4443]:
            host_info.nuclei_templates.add("ssl")
            host_info.nuclei_templates.add("http/misconfiguration")
            decisions.append(f"Port {port.port} (HTTPS) → ssl, http/misconfiguration")
    
    # TLS/Certificate analysis
    if host_info.tls_info:
        tls = host_info.tls_info
        
        # Check certificate CN mismatch (potential phishing)
        if tls.cert_cn:
            target_domain = host_info.hostname or host_info.target
            if tls.cert_cn.lower() not in target_domain.lower() and target_domain.lower() not in tls.cert_cn.lower():
                host_info.flags.append(f"⚠️  CERT MISMATCH: CN={tls.cert_cn} vs Target={target_domain}")
                host_info.risk_score += 30
                host_info.nuclei_templates.add("ssl/misconfigurations")
                decisions.append("Certificate CN mismatch detected → Potential phishing")
        
        # Check for weak TLS
        if any(v in str(host_info.ports) for v in ['TLSv1.0', 'TLSv1.1', 'SSLv3']):
            host_info.flags.append("⚠️  Weak TLS version detected")
            host_info.risk_score += 20
            host_info.nuclei_templates.add("ssl/misconfigurations")
            decisions.append("Weak TLS detected → ssl/misconfigurations")
    
    # Security header analysis - only add template decision (flags already added in Phase 1.5)
    if host_info.missing_headers:
        host_info.nuclei_templates.add("http/misconfiguration")
        decisions.append(f"Missing {len(host_info.missing_headers)} security headers → http/misconfiguration")
    
    # Print decisions
    if decisions:
        for d in decisions:
            print(f"    → {d}")
    else:
        print("    → No specific templates matched, using defaults")
        host_info.nuclei_templates.add("http/misconfiguration")
    
    return host_info


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3: NUCLEI SCANNING
# ═══════════════════════════════════════════════════════════════════════════════

def run_nuclei(host_info: HostInfo, config: ScanConfig, output_dir: str) -> List[Dict]:
    """Run Nuclei with selected templates"""
    
    if not host_info.nuclei_templates:
        print("    ⏭️  No Nuclei templates selected, skipping")
        return []
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = re.sub(r'[^\w\-.]', '_', host_info.target)
    json_output = os.path.join(output_dir, f"nuclei_{safe_target}_{timestamp}.json")
    
    # Determine URL scheme
    has_https = any(p.port in [443, 8443, 4443] or 'ssl' in p.service.lower() for p in host_info.ports)
    has_http = any(p.port in [80, 8080, 8000, 3000, 5000] for p in host_info.ports)
    
    targets = []
    if has_https:
        targets.append(f"https://{host_info.target}")
    if has_http:
        targets.append(f"http://{host_info.target}")
    if not targets:
        targets.append(host_info.target)
    
    # Build template arguments
    template_args = []
    for template in host_info.nuclei_templates:
        template_args.extend(["-t", template])
    
    findings = []
    
    for target_url in targets:
        cmd = [
            "nuclei",
            "-u", target_url,
            "-severity", config.nuclei_severity,
            "-rate-limit", str(config.nuclei_rate_limit),
            "-json-export", json_output,
            "-silent",
        ] + template_args
        
        print(f"\n    🎯 Nuclei scanning: {target_url}")
        print(f"    📋 Templates: {', '.join(host_info.nuclei_templates)}")
        
        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=config.timeout
            )
            
            # Parse JSON output (Nuclei uses JSON Lines format)
            if os.path.exists(json_output):
                with open(json_output, 'r') as f:
                    content = f.read().strip()
                    
                    # Try parsing as JSON array first
                    try:
                        data = json.loads(content)
                        if isinstance(data, list):
                            for item in data:
                                if isinstance(item, dict):
                                    findings.append(item)
                        elif isinstance(data, dict):
                            findings.append(data)
                    except json.JSONDecodeError:
                        # Parse as JSON Lines (one JSON object per line)
                        for line in content.split('\n'):
                            line = line.strip()
                            if line:
                                try:
                                    finding = json.loads(line)
                                    if isinstance(finding, dict):
                                        findings.append(finding)
                                    elif isinstance(finding, list):
                                        for item in finding:
                                            if isinstance(item, dict):
                                                findings.append(item)
                                except json.JSONDecodeError:
                                    pass
            
            # Also parse stdout for real-time results
            for line in process.stdout.split('\n'):
                if line.strip():
                    print(f"    💡 {line}")
                    
        except subprocess.TimeoutExpired:
            print(f"    ⏰ Nuclei timeout")
        except Exception as e:
            print(f"    ❌ Nuclei error: {e}")
    
    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 4: REPORTING
# ═══════════════════════════════════════════════════════════════════════════════

def save_xml_report(report_data: dict, filepath: str):
    """Save report in XML format"""
    
    def dict_to_xml(data, parent_tag="root"):
        """Convert dictionary to XML string"""
        xml_lines = [f'<?xml version="1.0" encoding="UTF-8"?>']
        xml_lines.append(f'<{parent_tag}>')
        
        def add_element(key, value, indent=1):
            prefix = "  " * indent
            # Sanitize key for XML tag
            tag = re.sub(r'[^a-zA-Z0-9_]', '_', str(key))
            
            if isinstance(value, dict):
                xml_lines.append(f'{prefix}<{tag}>')
                for k, v in value.items():
                    add_element(k, v, indent + 1)
                xml_lines.append(f'{prefix}</{tag}>')
            elif isinstance(value, list):
                xml_lines.append(f'{prefix}<{tag}>')
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        xml_lines.append(f'{prefix}  <item index="{i}">')
                        for k, v in item.items():
                            add_element(k, v, indent + 2)
                        xml_lines.append(f'{prefix}  </item>')
                    else:
                        # Escape XML special characters
                        escaped = str(item).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                        xml_lines.append(f'{prefix}  <item>{escaped}</item>')
                xml_lines.append(f'{prefix}</{tag}>')
            else:
                # Escape XML special characters
                escaped = str(value).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                xml_lines.append(f'{prefix}<{tag}>{escaped}</{tag}>')
        
        for key, value in data.items():
            add_element(key, value)
        
        xml_lines.append(f'</{parent_tag}>')
        return '\n'.join(xml_lines)
    
    xml_content = dict_to_xml(report_data, "security_scan_report")
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(xml_content)


def save_txt_report(report_data: dict, host_info, findings: list, filepath: str):
    """Save report in human-readable TXT format"""
    
    lines = []
    lines.append("=" * 80)
    lines.append("                    SECURITY SCAN REPORT")
    lines.append("=" * 80)
    lines.append("")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    
    # Target Information
    lines.append("-" * 80)
    lines.append("TARGET INFORMATION")
    lines.append("-" * 80)
    lines.append(f"  Target:     {report_data['target']}")
    lines.append(f"  IP:         {report_data['ip']}")
    lines.append(f"  Hostname:   {report_data['hostname']}")
    lines.append(f"  Scan Time:  {report_data['scan_time']}")
    lines.append("")
    
    # Risk Assessment
    lines.append("-" * 80)
    lines.append("RISK ASSESSMENT")
    lines.append("-" * 80)
    lines.append(f"  Risk Score: {report_data['risk_score']}/100")
    lines.append(f"  Risk Level: {report_data['risk_level']}")
    lines.append("")
    
    # Open Ports
    lines.append("-" * 80)
    lines.append("OPEN PORTS")
    lines.append("-" * 80)
    if report_data['open_ports']:
        lines.append(f"  {'PORT':<15} {'SERVICE':<20} {'PRODUCT'}")
        lines.append(f"  {'-'*15} {'-'*20} {'-'*30}")
        for port in report_data['open_ports']:
            lines.append(f"  {port['port']:<15} {port['service']:<20} {port.get('product', '')}")
    else:
        lines.append("  No open ports found")
    lines.append("")
    
    # TLS/Certificate Info
    if report_data['tls_info']['cn']:
        lines.append("-" * 80)
        lines.append("TLS/CERTIFICATE INFORMATION")
        lines.append("-" * 80)
        lines.append(f"  Common Name (CN): {report_data['tls_info']['cn']}")
        lines.append(f"  Issuer:           {report_data['tls_info']['issuer']}")
        lines.append(f"  Expiry:           {report_data['tls_info']['expiry']}")
        lines.append("")
    
    # Security Headers
    lines.append("-" * 80)
    lines.append("SECURITY HEADERS")
    lines.append("-" * 80)
    headers_data = report_data['security_headers']
    lines.append(f"  Header Security Score: {headers_data['score']}/100")
    lines.append("")
    
    if headers_data['found']:
        lines.append("  PRESENT HEADERS:")
        for header, value in headers_data['found'].items():
            lines.append(f"    [+] {header}")
            lines.append(f"        Value: {value[:60]}{'...' if len(str(value)) > 60 else ''}")
        lines.append("")
    
    if headers_data['missing']:
        lines.append("  MISSING HEADERS:")
        for header in headers_data['missing']:
            desc = HEADER_DESCRIPTIONS.get(header, "")
            lines.append(f"    [-] {header}")
            if desc:
                lines.append(f"        Purpose: {desc}")
        lines.append("")
    
    # Security Flags/Issues
    if report_data['flags']:
        lines.append("-" * 80)
        lines.append("SECURITY FLAGS & ISSUES")
        lines.append("-" * 80)
        for flag in report_data['flags']:
            lines.append(f"  [!] {flag}")
        lines.append("")
    
    # Nuclei Findings
    lines.append("-" * 80)
    lines.append("VULNERABILITY FINDINGS (Nuclei)")
    lines.append("-" * 80)
    if findings:
        for finding in findings:
            info = finding.get('info', {}) if isinstance(finding.get('info'), dict) else {}
            severity = info.get('severity', 'unknown').upper()
            name = info.get('name', 'Unknown')
            description = info.get('description', '')
            matched = finding.get('matched-at', '') or finding.get('matched', '')
            
            lines.append(f"  [{severity}] {name}")
            if matched:
                lines.append(f"      URL: {matched}")
            if description:
                lines.append(f"      Description: {description[:100]}{'...' if len(description) > 100 else ''}")
            lines.append("")
    else:
        lines.append("  No vulnerabilities found")
        lines.append("")
    
    # Summary
    lines.append("=" * 80)
    lines.append("SUMMARY")
    lines.append("=" * 80)
    lines.append(f"  Total Open Ports:     {len(report_data['open_ports'])}")
    lines.append(f"  Security Headers:     {len(headers_data['found'])}/{len(headers_data['found']) + len(headers_data['missing'])}")
    lines.append(f"  Security Issues:      {len(report_data['flags'])}")
    lines.append(f"  Vulnerabilities:      {len(findings)}")
    lines.append(f"  Overall Risk Score:   {report_data['risk_score']}/100 ({report_data['risk_level']})")
    lines.append("")
    lines.append("=" * 80)
    lines.append("                    END OF REPORT")
    lines.append("=" * 80)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))


def generate_report(host_info: HostInfo, nuclei_findings: List[Dict], output_dir: str):
    """Generate comprehensive scan report"""
    
    print_section("SCAN REPORT", "📊")
    
    # Cap risk score at 100
    host_info.risk_score = min(host_info.risk_score, 100)
    
    # Deduplicate flags (keep unique entries only)
    unique_flags = []
    seen_flags = set()
    for flag in host_info.flags:
        # Normalize flag for comparison (lowercase, strip emojis for matching)
        normalized = flag.lower().strip()
        # Extract key content for deduplication
        if "hsts" in normalized or "strict-transport" in normalized:
            key = "hsts"
        elif "csp" in normalized or "content-security-policy" in normalized:
            key = "csp"
        elif "x-frame" in normalized:
            key = "xframe"
        elif "x-content-type" in normalized:
            key = "xcontent"
        elif "x-xss" in normalized:
            key = "xxss"
        elif "referrer" in normalized:
            key = "referrer"
        elif "permissions" in normalized:
            key = "permissions"
        elif "cert" in normalized and "mismatch" in normalized:
            key = "certmismatch"
        elif "tls" in normalized or "ssl" in normalized:
            key = "tls"
        else:
            key = normalized[:50]  # Use first 50 chars as key for other flags
        
        if key not in seen_flags:
            seen_flags.add(key)
            unique_flags.append(flag)
    
    host_info.flags = unique_flags
    
    # Target info
    print(f"\n  🎯 Target: {host_info.target}")
    print(f"  📍 IP: {host_info.ip}")
    if host_info.hostname:
        print(f"  🏷️  Hostname: {host_info.hostname}")
    print(f"  📊 Status: {host_info.state}")
    
    # Risk score
    risk_level = "LOW" if host_info.risk_score < 20 else "MEDIUM" if host_info.risk_score < 50 else "HIGH" if host_info.risk_score < 80 else "CRITICAL"
    risk_color = "🟢" if risk_level == "LOW" else "🟡" if risk_level == "MEDIUM" else "🟠" if risk_level == "HIGH" else "🔴"
    print(f"\n  {risk_color} Risk Score: {host_info.risk_score}/100 ({risk_level})")
    
    # Open ports
    if host_info.ports:
        print(f"\n  ✅ Open Ports ({len(host_info.ports)}):")
        for port in host_info.ports:
            service_info = f"{port.service}"
            if port.product:
                service_info += f" ({port.product}"
                if port.version:
                    service_info += f" {port.version}"
                service_info += ")"
            print(f"      {port.port}/{port.protocol:<5} → {service_info}")
    
    # TLS/Certificate info
    if host_info.tls_info:
        tls = host_info.tls_info
        print(f"\n  🔐 TLS/Certificate:")
        if tls.cert_cn:
            print(f"      CN: {tls.cert_cn}")
        if tls.cert_issuer:
            print(f"      Issuer: {tls.cert_issuer[:50]}...")
        if tls.cert_expiry:
            print(f"      Expires: {tls.cert_expiry}")
    
    # Security headers summary
    if host_info.http_headers or host_info.missing_headers:
        total_headers = len(SECURITY_HEADERS)
        found_headers = len(host_info.http_headers)
        print(f"\n  🛡️  Security Headers ({found_headers}/{total_headers}):")
        
        # Show found headers
        for header in SECURITY_HEADERS:
            if header in host_info.http_headers:
                print(f"      ✅ {header}")
            else:
                desc = HEADER_DESCRIPTIONS.get(header, "")
                print(f"      ❌ {header} - {desc}")
    
    # Flags/Warnings
    if host_info.flags:
        print(f"\n  ⚠️  Security Flags:")
        for flag in host_info.flags:
            print(f"      {flag}")
    
    # Nuclei findings
    valid_findings = []
    if nuclei_findings:
        for finding in nuclei_findings:
            if isinstance(finding, dict):
                valid_findings.append(finding)
    
    if valid_findings:
        print(f"\n  🔥 Vulnerabilities Found ({len(valid_findings)}):")
        for finding in valid_findings:
            info = finding.get('info', {}) if isinstance(finding.get('info'), dict) else {}
            severity = info.get('severity', 'unknown').upper()
            name = info.get('name', 'Unknown')
            matched = finding.get('matched-at', '') or finding.get('matched', '')
            
            sev_icon = "🔴" if severity == "CRITICAL" else "🟠" if severity == "HIGH" else "🟡" if severity == "MEDIUM" else "🟢"
            print(f"      {sev_icon} [{severity}] {name}")
            if matched:
                print(f"         └─ {matched}")
    else:
        print(f"\n  ✅ No vulnerabilities found by Nuclei")
    
    # Save reports in multiple formats
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = re.sub(r'[^\w\-.]', '_', host_info.target)
    report_base = os.path.join(output_dir, f"report_{safe_target}_{timestamp}")
    
    report_data = {
        "target": host_info.target,
        "ip": host_info.ip,
        "hostname": host_info.hostname,
        "scan_time": timestamp,
        "risk_score": host_info.risk_score,
        "risk_level": risk_level,
        "open_ports": [{"port": p.port, "service": p.service, "product": p.product} for p in host_info.ports],
        "tls_info": {
            "cn": host_info.tls_info.cert_cn if host_info.tls_info else "",
            "issuer": host_info.tls_info.cert_issuer if host_info.tls_info else "",
            "expiry": host_info.tls_info.cert_expiry if host_info.tls_info else "",
        },
        "security_headers": {
            "found": host_info.http_headers,
            "missing": host_info.missing_headers,
            "score": int((len(host_info.http_headers) / len(SECURITY_HEADERS)) * 100) if host_info.http_headers else 0,
        },
        "flags": host_info.flags,
        "nuclei_findings": valid_findings,
    }
    
    # 1. Save JSON report
    json_path = f"{report_base}.json"
    with open(json_path, 'w') as f:
        json.dump(report_data, f, indent=2)
    
    # 2. Save XML report
    xml_path = f"{report_base}.xml"
    save_xml_report(report_data, xml_path)
    
    # 3. Save TXT report
    txt_path = f"{report_base}.txt"
    save_txt_report(report_data, host_info, valid_findings, txt_path)
    
    print(f"\n  📁 Reports saved:")
    print(f"      📄 JSON: {json_path}")
    print(f"      📄 XML:  {xml_path}")
    print(f"      📄 TXT:  {txt_path}")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

def scan_target(target: str, config: ScanConfig) -> Dict:
    """Complete scan pipeline for a single target"""
    
    print_section(f"SCANNING: {target}", "🎯")
    
    # Create output directory
    os.makedirs(config.output_dir, exist_ok=True)
    
    # Phase 1: Nmap
    print_subsection("Phase 1: Nmap Reconnaissance")
    xml_output = run_nmap(target, config, config.output_dir)
    
    if not xml_output:
        print("  ❌ Nmap scan failed")
        return {"target": target, "status": "failed", "error": "Nmap failed"}
    
    # Parse results
    host_info = parse_nmap_xml(xml_output, target)
    
    if not host_info or not host_info.ports:
        print("  ⚠️  No open ports found")
        return {"target": target, "status": "no_open_ports"}
    
    print(f"  ✅ Found {len(host_info.ports)} open port(s)")
    
    # Phase 1.5: HTTP Security Header Check
    if config.check_headers:
        print_subsection("Phase 1.5: HTTP Security Header Analysis")
        http_ports = [p.port for p in host_info.ports if p.port in [80, 443, 8080, 8443, 8000, 3000, 5000, 4443]]
        https_ports = [p for p in http_ports if p in [443, 8443, 4443]]
        
        if http_ports:
            print(f"  🔍 Checking security headers on ports: {http_ports}")
            if https_ports:
                print(f"  🔐 HTTPS ports detected: {https_ports} (prioritized)")
            
            header_result = check_http_security_headers(target, http_ports)
            
            if header_result["checked"]:
                protocol = header_result.get("protocol", "HTTP")
                protocol_icon = "🔐" if protocol == "HTTPS" else "⚠️"
                print(f"  {protocol_icon} Protocol: {protocol}")
                print(f"  ✅ Headers checked at: {header_result['url']}")
                
                # HTTPS status
                if header_result.get("https_available"):
                    print(f"  🔐 HTTPS: Available and checked")
                else:
                    print(f"  ⚠️  HTTPS: Not available or not checked")
                
                # HTTP to HTTPS redirect
                if header_result.get("http_to_https_redirect"):
                    print(f"  ✅ HTTP→HTTPS redirect: Configured")
                elif http_ports and https_ports:
                    print(f"  ⚠️  HTTP→HTTPS redirect: Not configured")
                
                # Update host_info with header results
                host_info.http_headers = header_result["headers_found"]
                host_info.missing_headers = header_result["missing_headers"]
                
                # Print found headers
                if header_result["headers_found"]:
                    print(f"\n  🛡️  Security Headers Found ({len(header_result['headers_found'])}):")
                    for header, value in header_result["headers_found"].items():
                        print(f"      ✅ {header}: {value[:50]}{'...' if len(value) > 50 else ''}")
                
                # Print missing headers
                if header_result["missing_headers"]:
                    print(f"\n  ⚠️  Missing Security Headers ({len(header_result['missing_headers'])}):")
                    for header in header_result["missing_headers"]:
                        desc = HEADER_DESCRIPTIONS.get(header, "")
                        print(f"      ❌ {header} - {desc}")
                    
                    # Add to risk score based on missing headers (3 points each)
                    host_info.risk_score += len(header_result["missing_headers"]) * 3
                    
                    # Extra penalty for critical missing headers on HTTPS
                    if protocol == "HTTPS":
                        if "Strict-Transport-Security" in header_result["missing_headers"]:
                            host_info.risk_score += 10
                            host_info.flags.append("❌ HSTS not configured - SSL stripping vulnerability")
                    
                    if "Content-Security-Policy" in header_result["missing_headers"]:
                        host_info.risk_score += 8
                        host_info.flags.append("❌ CSP not configured - XSS risk")
                    
                    if "X-Frame-Options" in header_result["missing_headers"]:
                        host_info.risk_score += 5
                        host_info.flags.append("⚠️ X-Frame-Options missing - Clickjacking risk")
                
                # Report additional security issues (from header analysis)
                if header_result["security_issues"]:
                    print(f"\n  🚨 Security Issues Found:")
                    for issue in header_result["security_issues"]:
                        # Skip the generic HSTS message if we already flagged it
                        if "HSTS not configured" in issue and any("HSTS" in f for f in host_info.flags):
                            print(f"      {issue}")
                            continue
                        print(f"      {issue}")
                        host_info.flags.append(issue)
                        host_info.risk_score += 3
                
                print(f"\n  📊 Header Security Score: {header_result['score']}/100")
            else:
                print("  ⚠️  Could not connect to check headers")
        else:
            print("  ℹ️  No HTTP/HTTPS ports found, skipping header check")
    
    # Phase 2: Decision Engine
    host_info = analyze_and_decide(host_info)
    
    # Phase 3: Nuclei (if available)
    nuclei_findings = []
    if check_tool("nuclei"):
        print_subsection("Phase 3: Nuclei Vulnerability Scan")
        nuclei_findings = run_nuclei(host_info, config, config.output_dir)
        host_info.findings = nuclei_findings
        
        # Add to risk score
        for finding in nuclei_findings:
            # Handle different Nuclei output formats
            if isinstance(finding, dict):
                info = finding.get('info', {})
                if isinstance(info, dict):
                    severity = info.get('severity', '').lower()
                else:
                    severity = ''
            else:
                continue  # Skip non-dict findings
            
            if severity == 'critical':
                host_info.risk_score += 40
            elif severity == 'high':
                host_info.risk_score += 25
            elif severity == 'medium':
                host_info.risk_score += 10
    else:
        print("\n  ⚠️  Nuclei not installed, skipping vulnerability scan")
        print("  💡 Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
    
    # Phase 4: Report (this also caps risk_score at 100 and deduplicates flags)
    generate_report(host_info, nuclei_findings, config.output_dir)
    
    return {
        "target": target,
        "status": "completed",
        "risk_score": min(host_info.risk_score, 100),  # Cap at 100
        "open_ports": len(host_info.ports),
        "findings": len(nuclei_findings),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Intelligent Security Scanner - Nmap + Nuclei Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single target scan
  %(prog)s -t example.com
  
  # Multiple targets from file
  %(prog)s -f targets.txt
  
  # Full port scan
  %(prog)s -t example.com --ports "-p-"
  
  # Quick scan (top 100)
  %(prog)s -t example.com --ports "--top-ports 100"
  
  # Custom severity
  %(prog)s -t example.com --severity high,critical
        """
    )
    
    # Target options
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument("-t", "--target", help="Single target")
    target_group.add_argument("-f", "--file", help="File with targets")
    
    # Scan options
    parser.add_argument("--ports", default="--top-ports 1000",
                       help="Nmap port specification (default: --top-ports 1000)")
    parser.add_argument("--severity", default="medium,high,critical",
                       help="Nuclei severity filter (default: medium,high,critical)")
    parser.add_argument("-o", "--output", default="./scan_results",
                       help="Output directory")
    parser.add_argument("--rate-limit", type=int, default=150,
                       help="Nuclei rate limit (default: 150)")
    parser.add_argument("--timeout", type=int, default=300,
                       help="Scan timeout in seconds (default: 300)")
    
    args = parser.parse_args()
    
    print_banner()
    
    # Validate
    if not args.target and not args.file:
        parser.error("Specify -t/--target or -f/--file")
    
    # Check tools
    print("\n🔧 Checking tools...")
    if not check_tool("nmap"):
        print("  ❌ Nmap not found. Install: sudo apt install nmap")
        sys.exit(1)
    print("  ✅ Nmap found")
    
    if check_tool("nuclei"):
        print("  ✅ Nuclei found")
    else:
        print("  ⚠️  Nuclei not found (will skip vuln scanning)")
    
    # Build config
    config = ScanConfig(
        nmap_ports=args.ports,
        nuclei_severity=args.severity,
        nuclei_rate_limit=args.rate_limit,
        output_dir=args.output,
        timeout=args.timeout,
    )
    
    # Get targets
    if args.target:
        targets = [args.target]
    else:
        targets = read_targets(args.file)
    
    print(f"\n🎯 Targets: {len(targets)}")
    for t in targets:
        print(f"   • {t}")
    
    # Confirm
    print(f"\n❓ Press Enter to start or Ctrl+C to abort...")
    try:
        input()
    except KeyboardInterrupt:
        print("\n❌ Aborted")
        sys.exit(0)
    
    # Scan all targets
    results = []
    start_time = datetime.now()
    
    for i, target in enumerate(targets, 1):
        print(f"\n{'▓' * 80}")
        print(f"  Progress: {i}/{len(targets)}")
        print(f"{'▓' * 80}")
        
        result = scan_target(target, config)
        results.append(result)
    
    # Final summary
    duration = datetime.now() - start_time
    
    print_section("FINAL SUMMARY", "🏁")
    print(f"\n  Total targets: {len(targets)}")
    print(f"  Completed: {sum(1 for r in results if r['status'] == 'completed')}")
    print(f"  Failed: {sum(1 for r in results if r['status'] == 'failed')}")
    print(f"  Duration: {duration}")
    print(f"  Results: {config.output_dir}")
    
    # Risk summary
    print(f"\n  Risk Summary:")
    for r in results:
        if r['status'] == 'completed':
            risk = r.get('risk_score', 0)
            level = "LOW" if risk < 20 else "MEDIUM" if risk < 50 else "HIGH" if risk < 80 else "CRITICAL"
            icon = "🟢" if level == "LOW" else "🟡" if level == "MEDIUM" else "🟠" if level == "HIGH" else "🔴"
            print(f"      {icon} {r['target']}: {risk}/100 ({level}) - {r.get('findings', 0)} findings")


if __name__ == "__main__":
    main()

