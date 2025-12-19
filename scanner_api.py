#!/usr/bin/env python3

import subprocess
import os
import sys
import json
import logging
import re
import ssl
import socket
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Import configuration
from config import (
    ScannerConfig,
    SECURITY_HEADERS,
    HEADER_DESCRIPTIONS,
    HEADER_INSECURE_VALUES,
    RISK_WEIGHTS,
    DEFAULT_CONFIG
)


# ═══════════════════════════════════════════════════════════════════════════════
# SCAN PROFILES - Production-ready scan type configurations
# ═══════════════════════════════════════════════════════════════════════════════

SCAN_PROFILES = {
    "default": {
        "name": "Default (Top 1000 TCP)",
        "tcp": "--top-ports 1000",
        "udp": None,
        "description": "Quick scan of most common ports"
    },
    "tcp_full": {
        "name": "Full TCP Scan",
        "tcp": "1-65535",
        "udp": None,
        "description": "Complete TCP port scan (all 65535 ports)"
    },
    "udp_common": {
        "name": "UDP Common Ports",
        "tcp": "--top-ports 1000",
        "udp": "53,67,68,69,123,135,137,138,139,161,162,389,445,500,514,520,1434,1900,4500,5353",
        "description": "TCP top 1000 + common UDP services"
    },
    "udp_full": {
        "name": "Full UDP Scan",
        "tcp": None,
        "udp": "1-65535",
        "description": "Complete UDP port scan (policy protected)"
    },
    "quick": {
        "name": "Quick Scan",
        "tcp": "--top-ports 100",
        "udp": None,
        "description": "Fast scan of top 100 ports"
    },
    "stealth": {
        "name": "Stealth Scan",
        "tcp": "--top-ports 1000",
        "udp": None,
        "timing": "-T2",
        "description": "Slower, less detectable scan"
    }
}


# ═══════════════════════════════════════════════════════════════════════════════
# LOGGING SETUP
# ═══════════════════════════════════════════════════════════════════════════════

def setup_logging(level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    """Setup logging for the scanner"""
    logger = logging.getLogger("SecurityScanner")
    if logger.handlers:
        return logger
    
    logger.setLevel(getattr(logging, level.upper()))
    
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    console_format = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)
    
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(console_format)
        logger.addHandler(file_handler)
    
    return logger


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


@dataclass
class SSLInfo:
    """SSL/TLS scan results"""
    cn: str = ""
    issuer: str = ""
    expiry: str = ""
    expired: bool = False
    self_signed: bool = False
    tls_versions: List[str] = field(default_factory=list)
    weak_ciphers: List[str] = field(default_factory=list)
    issues: List[str] = field(default_factory=list)


@dataclass
class HeaderAnalysis:
    """HTTP security header analysis results"""
    url: str = ""
    protocol: str = ""
    status_code: int = 0
    found: Dict[str, str] = field(default_factory=dict)
    missing: List[str] = field(default_factory=list)
    issues: List[str] = field(default_factory=list)
    score: int = 0


@dataclass
class DomainStatus:
    """Domain alive/dead status from httpx"""
    alive: bool = False
    status_code: int = 0
    title: str = ""
    tech: List[str] = field(default_factory=list)
    content_length: int = 0
    response_time: str = ""
    redirect_url: str = ""


@dataclass
class ScanResult:
    """Complete scan result - main output structure"""
    target: str
    status: str  # "alive", "dead", "failed"
    scan_time: str = ""
    duration: float = 0.0
    
    # Target info
    ip: str = ""
    hostname: str = ""
    
    # Risk assessment
    risk_score: int = 0
    risk_level: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    
    # Domain status (httpx)
    domain_status: Optional[DomainStatus] = None
    
    # Nmap findings
    open_ports: List[PortInfo] = field(default_factory=list)
    ssl_info: Optional[SSLInfo] = None
    header_analysis: Optional[HeaderAnalysis] = None
    
    # Flags & issues
    flags: List[str] = field(default_factory=list)
    
    # Output files
    output_files: Dict[str, str] = field(default_factory=dict)
    
    # Error info
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "scan_time": self.scan_time,
            "ip": self.ip,
            "hostname": self.hostname,
            "duration": self.duration,
            "domain_status": asdict(self.domain_status) if self.domain_status else None,
            "open_ports": [asdict(p) for p in self.open_ports],
            "header_analysis": asdict(self.header_analysis) if self.header_analysis else None,
            "flags": self.flags,
            "error": self.error,
        }
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=2)


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN SCANNER CLASS
# ═══════════════════════════════════════════════════════════════════════════════

class SecurityScanner:
    """
    Lightweight security scanner using Nmap + httpx
    
    Usage:
        scanner = SecurityScanner()
        result = scanner.scan("example.com")
        print(result.to_json())
    """
    
    def __init__(self, config: Optional[ScannerConfig] = None):
        """Initialize scanner with configuration"""
        self.config = config or DEFAULT_CONFIG
        self.logger = setup_logging(
            self.config.log_level,
            self.config.log_file
        )
        self._lock = threading.Lock()
        os.makedirs(self.config.output_dir, exist_ok=True)
    
    def check_dependencies(self) -> Tuple[bool, Dict[str, bool]]:
        """Check if required tools are installed"""
        deps = {"nmap": False, "httpx": False}
        
        try:
            subprocess.run(["nmap", "--version"], capture_output=True, check=True)
            deps["nmap"] = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        
        try:
            subprocess.run(["httpx", "-version"], capture_output=True, check=True)
            deps["httpx"] = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        
        return deps["nmap"], deps
    
    def _is_ip_address(self, target: str) -> bool:
        """Check if target is an IP address"""
        return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target))
    
    def scan(self, target: str, scan_type: str = "default") -> ScanResult:
        """
        Perform security scan with different flows for IP vs Domain.
        
        IP Flow:
        1. Nmap → Port scanning (configurable scan type)
        
        Domain Flow:
        1. Check if alive/dead
        2. Check security headers (missing)
        3. Check SSL certificate
        
        Args:
            target: IP address or domain name
            scan_type: Scan profile name (default, tcp_full, udp_common, etc.)
        """
        start_time = datetime.now()
        is_ip = self._is_ip_address(target)
        target_type = "IP" if is_ip else "Domain"
        
        self.logger.info(f"Starting scan for: {target} ({target_type}) [profile: {scan_type}]")
        
        result = ScanResult(
            target=target,
            status="in_progress",
            scan_time=start_time.strftime("%Y-%m-%d %H:%M:%S")
        )
        
        try:
            if is_ip:
                # ═══════════════════════════════════════════════════════════════
                # IP ADDRESS FLOW
                # ═══════════════════════════════════════════════════════════════
                result.ip = target
                
                # Nmap - Port Scanning (with configurable scan type)
                self.logger.info(f"[{target}] Running Nmap port scan ({scan_type})")
                nmap_data = self._run_nmap_ports_only(target, scan_type=scan_type)
                
                if nmap_data:
                    result.open_ports = nmap_data.get("ports", [])
                    result.output_files["nmap_xml"] = nmap_data.get("xml_file", "")
                    result.output_files["nmap_txt"] = nmap_data.get("txt_file", "")
                
                result.status = "completed"
                
            else:
                # ═══════════════════════════════════════════════════════════════
                # DOMAIN FLOW
                # ═══════════════════════════════════════════════════════════════
                
                # Phase 1: Check if domain is alive/dead
                self.logger.info(f"[{target}] Phase 1: Checking domain status")
                domain_status = self._check_domain_status(target)
                result.domain_status = domain_status
                
                if not domain_status.alive:
                    result.status = "dead"
                    result.flags.append("Domain is dead or unreachable")
                    result.risk_score += RISK_WEIGHTS.get("dead_domain", 5)
                    self.logger.warning(f"[{target}] Domain is DEAD")
                else:
                    self.logger.info(f"[{target}] Domain is ALIVE (HTTP {domain_status.status_code})")
                    result.status = "alive"
                
                # Phase 2: Security Headers + SSL Certificate
                if domain_status.alive or not self.config.skip_dead_domains:
                    self.logger.info(f"[{target}] Phase 2: Security headers & SSL check")
                    nmap_data = self._run_nmap(target)
                    
                    if nmap_data:
                        result.ip = nmap_data.get("ip", "")
                        result.hostname = nmap_data.get("hostname", "")
                        result.open_ports = nmap_data.get("ports", [])
                        result.ssl_info = nmap_data.get("ssl_info")
                        result.header_analysis = nmap_data.get("header_analysis")
                        result.output_files["nmap_xml"] = nmap_data.get("xml_file", "")
                        result.output_files["nmap_txt"] = nmap_data.get("txt_file", "")
                        
                        # Process SSL issues
                        if result.ssl_info:
                            self._process_ssl_results(result)
                        
                        # Process header issues
                        if result.header_analysis:
                            self._process_header_results(result)
            
            # ─────────────────────────────────────────────────────────────────
            # Finalize
            # ─────────────────────────────────────────────────────────────────
            result.risk_score = min(result.risk_score, 100)
            result.risk_level = self._get_risk_level(result.risk_score)
            
            # Save reports
            self._save_reports(result)
            
        except Exception as e:
            self.logger.error(f"[{target}] Scan failed: {str(e)}")
            result.status = "failed"
            result.error = str(e)
        
        result.duration = (datetime.now() - start_time).total_seconds()
        self.logger.info(f"[{target}] Scan completed in {result.duration:.2f}s - Risk: {result.risk_level}")
        
        return result
    
    def scan_multiple(self, targets: List[str], max_workers: int = 3) -> List[ScanResult]:
        """Scan multiple targets concurrently"""
        results = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_target = {executor.submit(self.scan, t): t for t in targets}
            
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    results.append(future.result())
                except Exception as e:
                    self.logger.error(f"[{target}] Exception: {e}")
                    results.append(ScanResult(target=target, status="failed", error=str(e)))
        
        return results
    
    def scan_from_file(self, filepath: str, max_workers: int = 3) -> List[ScanResult]:
        """Scan targets from a file"""
        targets = []
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    targets.append(line)
        return self.scan_multiple(targets, max_workers)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # HTTPX - Dead Domain Detection
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _check_domain_status(self, target: str) -> DomainStatus:
        """Check if domain is alive using httpx"""
        status = DomainStatus()
        
        # Try httpx first
        try:
            cmd = [
                "httpx",
                "-u", target,
                "-silent",
                "-status-code",
                "-title",
                "-tech-detect",
                "-response-time",
                "-follow-redirects",
                "-json"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.stdout.strip():
                data = json.loads(result.stdout.strip())
                status.alive = True
                status.status_code = data.get("status_code", 0)
                status.title = data.get("title", "")
                status.tech = data.get("tech", [])
                status.response_time = data.get("response_time", "")
                status.redirect_url = data.get("final_url", "")
                return status
                
        except FileNotFoundError:
            self.logger.warning("httpx not installed, falling back to urllib")
        except subprocess.TimeoutExpired:
            pass
        except json.JSONDecodeError:
            pass
        except Exception as e:
            self.logger.debug(f"httpx error: {e}")
        
        # Fallback: use urllib
        for scheme in ["https", "http"]:
            try:
                url = f"{scheme}://{target}"
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                
                req = urllib.request.Request(
                    url,
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                )
                
                with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                    status.alive = True
                    status.status_code = resp.status
                    return status
                    
            except urllib.error.HTTPError as e:
                # 401, 403, 404, 500 etc. = domain is alive, just returning error
                status.alive = True
                status.status_code = e.code
                return status
            except urllib.error.URLError as e:
                # Connection refused, DNS failure = try next scheme
                continue
            except Exception:
                continue
        
        return status
    
    # ═══════════════════════════════════════════════════════════════════════════
    # NMAP - Active Scanning (Ports + SSL + Headers)
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _run_nmap(self, target: str) -> Optional[Dict]:
        """Run Nmap for ports, SSL, and security headers"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = re.sub(r'[^\w\-.]', '_', target)
        
        xml_file = os.path.join(self.config.output_dir, f"nmap_{safe_target}_{timestamp}.xml")
        txt_file = os.path.join(self.config.output_dir, f"nmap_{safe_target}_{timestamp}.txt")
        
        # Nmap command with SSL and security header scripts
        cmd = [
            "nmap",
            "-Pn",
            "-oX", xml_file,
            "-oN", txt_file,
            "-sV",
            "-T4",
        ]
        
        # Port specification
        if self.config.nmap_ports:
            cmd.extend(self.config.nmap_ports.split())
        
        # NSE Scripts: SSL + Security Headers
        scripts = [
            "ssl-cert",
            "ssl-enum-ciphers",
            "ssl-dh-params",
            "http-security-headers",
            "http-headers",
        ]
        cmd.extend(["--script", ",".join(scripts)])
        
        cmd.append(target)
        
        try:
            subprocess.run(cmd, capture_output=True, timeout=self.config.nmap_timeout)
        except subprocess.TimeoutExpired:
            self.logger.error(f"[{target}] Nmap timeout")
            return None
        except Exception as e:
            self.logger.error(f"[{target}] Nmap error: {e}")
            return None
        
        return self._parse_nmap_xml(xml_file, txt_file)
    
    def _run_nmap_ports_only(self, target: str, scan_type: str = "default") -> Optional[Dict]:
        """
        Run Nmap port scan with configurable scan profiles.
        
        Scan Types:
          default     -> TCP top 1000 ports (fast, comprehensive)
          tcp_full    -> TCP all 65535 ports (thorough, slow)
          udp_common  -> TCP top 1000 + common UDP services
          udp_full    -> UDP all ports (policy protected, very slow)
          quick       -> TCP top 100 ports (fastest)
          stealth     -> TCP top 1000 with slower timing (less detectable)
        
        Args:
            target: IP address or hostname to scan
            scan_type: Profile name from SCAN_PROFILES
            
        Returns:
            Dict with scan results or None on failure
        """
        # Validate scan type
        if scan_type not in SCAN_PROFILES:
            self.logger.error(f"[{target}] Invalid scan_type: {scan_type}")
            raise ValueError(f"Invalid scan_type: {scan_type}. Valid: {list(SCAN_PROFILES.keys())}")
        
        # Policy enforcement for full UDP scans
        if scan_type == "udp_full":
            allow_full_udp = getattr(self.config, 'allow_full_udp', False)
            if not allow_full_udp:
                self.logger.warning(f"[{target}] Full UDP scan blocked by policy")
                raise PermissionError("Full UDP scan disabled by policy. Set allow_full_udp=True in config.")
        
        profile = SCAN_PROFILES[scan_type]
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = re.sub(r'[^\w\-.]', '_', target)
        
        xml_file = os.path.join(self.config.output_dir, f"nmap_{safe_target}_{timestamp}.xml")
        txt_file = os.path.join(self.config.output_dir, f"nmap_{safe_target}_{timestamp}.txt")
        
        # ═══════════════════════════════════════════════════════════════════════
        # BUILD NMAP COMMAND
        # ═══════════════════════════════════════════════════════════════════════
        
        cmd = [
            "nmap",
            "-Pn",           # Skip host discovery (treat all as online)
            "-sV",           # Service version detection
            "-oX", xml_file,
            "-oN", txt_file,
        ]
        
        # TCP scan
        if profile.get("tcp"):
            cmd.append("-sS")  # TCP SYN scan
            tcp_spec = profile["tcp"]
            if tcp_spec.startswith("--"):
                # e.g., "--top-ports 1000"
                cmd.extend(tcp_spec.split())
            else:
                # e.g., "1-65535"
                cmd.extend(["-p", tcp_spec])
        
        # UDP scan
        if profile.get("udp"):
            cmd.append("-sU")  # UDP scan
            udp_spec = profile["udp"]
            if udp_spec == "1-65535":
                cmd.append("-p-")  # All UDP ports
            else:
                # Specific UDP ports
                if profile.get("tcp"):
                    # Combined TCP+UDP port specification
                    tcp_spec = profile["tcp"]
                    if tcp_spec.startswith("--"):
                        # Can't combine --top-ports with explicit UDP, use default
                        cmd.extend(["-pU:" + udp_spec])
                    else:
                        cmd.extend(["-p", f"T:{tcp_spec},U:{udp_spec}"])
                else:
                    cmd.extend(["-pU:" + udp_spec])
        
        # Timing template (use profile-specific or default to T4)
        timing = profile.get("timing", getattr(self.config, 'nmap_ip_timing', '-T4'))
        cmd.append(timing)
        
        # Retries
        max_retries = getattr(self.config, 'nmap_ip_max_retries', 2)
        cmd.extend(["--max-retries", str(max_retries)])
        
        # Host timeout
        host_timeout = getattr(self.config, 'nmap_ip_host_timeout', '10m')
        cmd.extend(["--host-timeout", host_timeout])
        
        # ═══════════════════════════════════════════════════════════════════════
        # PARALLEL PROCESSING FLAGS
        # ═══════════════════════════════════════════════════════════════════════
        
        min_hostgroup = getattr(self.config, 'nmap_min_hostgroup', 100)
        max_hostgroup = getattr(self.config, 'nmap_max_hostgroup', 200)
        cmd.extend(["--min-hostgroup", str(min_hostgroup)])
        cmd.extend(["--max-hostgroup", str(max_hostgroup)])
        
        min_rate = getattr(self.config, 'nmap_min_rate', 1500)
        max_rate = getattr(self.config, 'nmap_max_rate', 5000)
        cmd.extend(["--min-rate", str(min_rate)])
        cmd.extend(["--max-rate", str(max_rate)])
        
        # Target
        cmd.append(target)
        
        self.logger.info(f"[{target}] Nmap ({scan_type}): {' '.join(cmd)}")
        
        try:
            # Timeout: 10 min default, 30 min for full scans
            scan_timeout = 1800 if scan_type in ["tcp_full", "udp_full"] else 600
            subprocess.run(cmd, capture_output=True, timeout=scan_timeout)
        except subprocess.TimeoutExpired:
            self.logger.error(f"[{target}] Nmap timeout ({scan_timeout//60}m)")
            return None
        except Exception as e:
            self.logger.error(f"[{target}] Nmap error: {e}")
            return None
        
        return self._parse_nmap_xml(xml_file, txt_file)
    
    def _parse_nmap_xml(self, xml_file: str, txt_file: str) -> Optional[Dict]:
        """Parse Nmap XML output"""
        if not os.path.exists(xml_file):
            return None
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
        except ET.ParseError:
            return None
        
        result = {
            "ip": "",
            "hostname": "",
            "ports": [],
            "ssl_info": None,
            "header_analysis": None,
            "xml_file": xml_file,
            "txt_file": txt_file,
        }
        
        for host in root.findall('.//host'):
            # Get IP
            for addr in host.findall('address'):
                if addr.get('addrtype') == 'ipv4':
                    result["ip"] = addr.get('addr', '')
            
            # Get hostname
            for hostname in host.findall('.//hostname'):
                result["hostname"] = hostname.get('name', '')
            
            # Get ports and scripts
            ssl_info = SSLInfo()
            header_analysis = HeaderAnalysis()
            
            for port in host.findall('.//port'):
                port_state = port.find('state')
                if port_state is None:
                    continue
                
                state = port_state.get('state', 'unknown')
                
                service = port.find('service')
                port_info = PortInfo(
                    port=int(port.get('portid', 0)),
                    protocol=port.get('protocol', 'tcp'),
                    state=state,  # open, closed, or filtered
                    service=service.get('name', 'unknown') if service is not None else 'unknown',
                    product=service.get('product', '') if service is not None else '',
                    version=service.get('version', '') if service is not None else '',
                )
                result["ports"].append(port_info)
                
                # Parse NSE script outputs
                for script in port.findall('script'):
                    script_id = script.get('id', '')
                    output = script.get('output', '')
                    
                    # SSL Certificate
                    if script_id == 'ssl-cert':
                        self._parse_ssl_cert(ssl_info, output, script)
                    
                    # SSL Ciphers
                    elif script_id == 'ssl-enum-ciphers':
                        self._parse_ssl_ciphers(ssl_info, output, script)
                    
                    # Security Headers
                    elif script_id == 'http-security-headers':
                        self._parse_security_headers(header_analysis, output, script)
            
            if ssl_info.cn or ssl_info.tls_versions:
                result["ssl_info"] = ssl_info
            
            if header_analysis.missing or header_analysis.found:
                result["header_analysis"] = header_analysis
        
        return result
    
    def _parse_ssl_cert(self, ssl_info: SSLInfo, output: str, script_elem):
        """Parse ssl-cert script output"""
        for line in output.split('\n'):
            line = line.strip()
            if 'Subject:' in line:
                cn_match = re.search(r'commonName[=:]([^,/\n]+)', line, re.IGNORECASE)
                if cn_match:
                    ssl_info.cn = cn_match.group(1).strip()
            elif 'Issuer:' in line:
                ssl_info.issuer = line.split(':', 1)[-1].strip()[:60]
            elif 'Not valid after:' in line:
                ssl_info.expiry = line.split(':', 1)[-1].strip()
                # Check if expired
                try:
                    exp_date = datetime.strptime(ssl_info.expiry.split('T')[0], '%Y-%m-%d')
                    if exp_date < datetime.now():
                        ssl_info.expired = True
                        ssl_info.issues.append("Certificate expired")
                except:
                    pass
        
        # Check self-signed
        if ssl_info.cn and ssl_info.issuer:
            if ssl_info.cn.lower() in ssl_info.issuer.lower():
                ssl_info.self_signed = True
                ssl_info.issues.append("Self-signed certificate")
    
    def _parse_ssl_ciphers(self, ssl_info: SSLInfo, output: str, script_elem):
        """Parse ssl-enum-ciphers script output"""
        current_version = ""
        weak_ciphers = []
        
        for line in output.split('\n'):
            line = line.strip()
            
            # TLS version
            if line.startswith('TLSv') or line.startswith('SSLv'):
                version = line.rstrip(':')
                ssl_info.tls_versions.append(version)
                current_version = version
                
                # Flag weak versions
                if 'SSLv' in version or version in ['TLSv1.0', 'TLSv1.1']:
                    ssl_info.issues.append(f"Weak TLS version: {version}")
            
            # Weak ciphers
            if 'RC4' in line or 'DES' in line or 'NULL' in line or 'EXPORT' in line:
                weak_ciphers.append(line.strip())
        
        ssl_info.weak_ciphers = weak_ciphers[:5]  # Limit to 5
        if weak_ciphers:
            ssl_info.issues.append(f"Weak ciphers detected: {len(weak_ciphers)}")
    
    def _parse_security_headers(self, header_analysis: HeaderAnalysis, output: str, script_elem):
        """Parse http-security-headers script output"""
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # Check for missing headers
            for header in SECURITY_HEADERS:
                header_lower = header.lower().replace('-', '_')
                if header_lower in line.lower() and 'not' in line.lower():
                    if header not in header_analysis.missing:
                        header_analysis.missing.append(header)
                elif header_lower in line.lower():
                    # Header found - try to extract value
                    header_analysis.found[header] = "Present"
        
        # Also check table elements if present
        for table in script_elem.findall('.//table'):
            for elem in table.findall('.//elem'):
                key = elem.get('key', '')
                if key:
                    # Convert to proper header name
                    header_name = key.replace('_', '-').title()
                    if 'missing' not in (elem.text or '').lower():
                        header_analysis.found[header_name] = elem.text or "Present"
    
    # ═══════════════════════════════════════════════════════════════════════════
    # RESULT PROCESSING
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _process_ssl_results(self, result: ScanResult):
        """Process SSL scan results and update risk score"""
        ssl = result.ssl_info
        if not ssl:
            return
        
        if ssl.expired:
            result.risk_score += RISK_WEIGHTS.get("cert_expired", 20)
            result.flags.append("SSL certificate expired")
        
        if ssl.self_signed:
            result.risk_score += RISK_WEIGHTS.get("cert_self_signed", 15)
            result.flags.append("Self-signed certificate detected")
        
        if ssl.weak_ciphers:
            result.risk_score += RISK_WEIGHTS.get("weak_ciphers", 10)
            result.flags.append(f"Weak SSL ciphers: {len(ssl.weak_ciphers)} found")
        
        # Check for weak TLS versions
        for ver in ssl.tls_versions:
            if 'SSLv' in ver or ver in ['TLSv1.0', 'TLSv1.1']:
                result.risk_score += RISK_WEIGHTS.get("weak_tls", 15)
                result.flags.append(f"Weak TLS version: {ver}")
                break
    
    def _process_header_results(self, result: ScanResult):
        """Process security header results and update risk score"""
        headers = result.header_analysis
        if not headers:
            return
        
        # Missing headers
        for header in headers.missing:
            result.risk_score += RISK_WEIGHTS.get("missing_header", 3)
            result.flags.append(f"{header} header not implemented")
        
        # Critical headers
        if "Strict-Transport-Security" in headers.missing:
            result.risk_score += RISK_WEIGHTS.get("missing_hsts_https", 7)
        
        if "Content-Security-Policy" in headers.missing:
            result.risk_score += RISK_WEIGHTS.get("missing_csp", 5)
        
        if "X-Frame-Options" in headers.missing:
            result.risk_score += RISK_WEIGHTS.get("missing_xframe", 3)
    
    def _get_risk_level(self, score: int) -> str:
        """Get risk level from score"""
        if score < 20:
            return "LOW"
        elif score < 50:
            return "MEDIUM"
        elif score < 80:
            return "HIGH"
        else:
            return "CRITICAL"
    
    # ═══════════════════════════════════════════════════════════════════════════
    # REPORT GENERATION
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _save_reports(self, result: ScanResult):
        """Save reports - append to existing file if it exists"""
        safe_target = re.sub(r'[^\w\-.]', '_', result.target)
        
        # JSON - Always save, append to existing file
        json_path = os.path.join(self.config.output_dir, f"{safe_target}.json")
        self._save_json_append(result, json_path)
        result.output_files["report_json"] = json_path
        
        # TXT (optional)
        if "txt" in self.config.output_formats:
            txt_path = os.path.join(self.config.output_dir, f"{safe_target}.txt")
            self._save_txt_report(result, txt_path)
            result.output_files["report_txt"] = txt_path
        
        # XML (optional)
        if "xml" in self.config.output_formats:
            xml_path = os.path.join(self.config.output_dir, f"{safe_target}.xml")
            self._save_xml_report(result, xml_path)
            result.output_files["report_xml"] = xml_path
    
    def _save_json_append(self, result: ScanResult, filepath: str):
        """Save JSON result - append to existing file, preserving scan history"""
        scan_data = result.to_dict()
        
        # Load existing data if file exists
        existing_data = {"target": result.target, "scans": []}
        
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as f:
                    existing_data = json.load(f)
                    # Handle old format (single scan) - convert to new format
                    if "scans" not in existing_data:
                        old_scan = existing_data.copy()
                        existing_data = {"target": result.target, "scans": [old_scan]}
            except (json.JSONDecodeError, IOError):
                existing_data = {"target": result.target, "scans": []}
        
        # Append new scan
        existing_data["scans"].append(scan_data)
        existing_data["last_scan"] = scan_data["scan_time"]
        existing_data["total_scans"] = len(existing_data["scans"])
        
        # Save
        with open(filepath, 'w') as f:
            json.dump(existing_data, f, indent=2)
    
    def _save_txt_report(self, result: ScanResult, filepath: str):
        """Save report as human-readable TXT"""
        lines = [
            "=" * 80,
            "                    SECURITY SCAN REPORT",
            "=" * 80,
            "",
            f"Target:     {result.target}",
            f"IP:         {result.ip}",
            f"Status:     {result.status.upper()}",
            f"Scan Time:  {result.scan_time}",
            f"Duration:   {result.duration:.2f} seconds",
            "",
            "-" * 80,
            "RISK ASSESSMENT",
            "-" * 80,
            f"Risk Score: {result.risk_score}/100",
            f"Risk Level: {result.risk_level}",
        ]
        
        # Open Ports
        if result.open_ports:
            lines.extend([
                "",
                "-" * 80,
                "OPEN PORTS (Nmap)",
                "-" * 80,
            ])
            for port in result.open_ports:
                svc = f"{port.service}"
                if port.product:
                    svc += f" ({port.product} {port.version})"
                lines.append(f"  {port.port}/{port.protocol} - {svc}")
        
        # SSL Info
        if result.ssl_info:
            lines.extend([
                "",
                "-" * 80,
                "SSL/TLS ANALYSIS",
                "-" * 80,
                f"Certificate CN: {result.ssl_info.cn}",
                f"Issuer:         {result.ssl_info.issuer}",
                f"Expiry:         {result.ssl_info.expiry}",
                f"TLS Versions:   {', '.join(result.ssl_info.tls_versions)}",
            ])
            if result.ssl_info.issues:
                lines.append("Issues:")
                for issue in result.ssl_info.issues:
                    lines.append(f"  [!] {issue}")
        
        # Security Headers
        if result.header_analysis:
            lines.extend([
                "",
                "-" * 80,
                "SECURITY HEADERS",
                "-" * 80,
            ])
            if result.header_analysis.found:
                lines.append("Present:")
                for h in result.header_analysis.found:
                    lines.append(f"  [+] {h}")
            if result.header_analysis.missing:
                lines.append("Missing:")
                for h in result.header_analysis.missing:
                    lines.append(f"  [-] {h}")
        
        # Flags
        if result.flags:
            lines.extend([
                "",
                "-" * 80,
                "SECURITY FLAGS",
                "-" * 80,
            ])
            seen = set()
            for flag in result.flags:
                if flag not in seen:
                    lines.append(f"  [!] {flag}")
                    seen.add(flag)
        
        lines.extend([
            "",
            "=" * 80,
            "                    END OF REPORT",
            "=" * 80,
        ])
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
    
    def _save_xml_report(self, result: ScanResult, filepath: str):
        """Save report as XML"""
        def dict_to_xml(data, parent_tag="root"):
            lines = ['<?xml version="1.0" encoding="UTF-8"?>']
            lines.append(f'<{parent_tag}>')
            
            def add_element(key, value, indent=1):
                prefix = "  " * indent
                tag = re.sub(r'[^a-zA-Z0-9_]', '_', str(key))
                
                if isinstance(value, dict):
                    lines.append(f'{prefix}<{tag}>')
                    for k, v in value.items():
                        add_element(k, v, indent + 1)
                    lines.append(f'{prefix}</{tag}>')
                elif isinstance(value, list):
                    lines.append(f'{prefix}<{tag}>')
                    for item in value:
                        if isinstance(item, dict):
                            lines.append(f'{prefix}  <item>')
                            for k, v in item.items():
                                add_element(k, v, indent + 2)
                            lines.append(f'{prefix}  </item>')
                        else:
                            escaped = str(item).replace('&', '&amp;').replace('<', '&lt;')
                            lines.append(f'{prefix}  <item>{escaped}</item>')
                    lines.append(f'{prefix}</{tag}>')
                elif value is not None:
                    escaped = str(value).replace('&', '&amp;').replace('<', '&lt;')
                    lines.append(f'{prefix}<{tag}>{escaped}</{tag}>')
            
            for key, value in data.items():
                add_element(key, value)
            
            lines.append(f'</{parent_tag}>')
            return '\n'.join(lines)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(dict_to_xml(result.to_dict(), "security_scan_report"))


# ═══════════════════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Security Scanner v2.0 - Nmap + httpx",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scanner_api.py -t example.com
  python3 scanner_api.py -t 1.2.3.4 --json
  python3 scanner_api.py -f targets.txt
        """
    )
    parser.add_argument("-t", "--target", help="Single target (IP or domain)")
    parser.add_argument("-f", "--file", help="File with targets (one per line)")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    
    args = parser.parse_args()
    
    # Load config
    config = ScannerConfig.from_env()
    
    if args.output:
        config.output_dir = args.output
    
    scanner = SecurityScanner(config)
    
    # Check dependencies
    nmap_ok, deps = scanner.check_dependencies()
    if not nmap_ok:
        print("Error: Nmap not found. Install with: sudo apt install nmap")
        sys.exit(1)
    
    if not deps.get("httpx"):
        print("Warning: httpx not found. Install with: go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
    
    # Run scan
    if args.target:
        result = scanner.scan(args.target)
        results = [result]
    elif args.file:
        results = scanner.scan_from_file(args.file)
    else:
        parser.print_help()
        sys.exit(1)
    
    # Output
    if args.json:
        print(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        for r in results:
            status_icon = "✅" if r.status == "alive" else "💀" if r.status == "dead" else "❌"
            print(f"\n{status_icon} {r.target}: {r.risk_level} ({r.risk_score}/100)")
            if r.open_ports:
                print(f"   Ports: {', '.join(str(p.port) for p in r.open_ports[:10])}")
            if r.flags:
                for flag in r.flags[:5]:
                    print(f"   - {flag}")
