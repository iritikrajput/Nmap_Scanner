#!/usr/bin/env python3
"""
Security Scanner Suite - API Wrapper
Production-ready API for backend integration

This module provides:
1. SecurityScanner class - Main scanner interface
2. ScanResult dataclass - Structured scan results
3. Async support for non-blocking scans
4. Logging integration
5. Error handling
"""

import subprocess
import os
import sys
import json
import logging
import re
import ssl
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
    NUCLEI_TEMPLATE_MAP,
    RISK_WEIGHTS,
    DEFAULT_CONFIG
)


# ═══════════════════════════════════════════════════════════════════════════════
# LOGGING SETUP
# ═══════════════════════════════════════════════════════════════════════════════

def setup_logging(level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    """Setup logging for the scanner"""
    logger = logging.getLogger("SecurityScanner")
    logger.setLevel(getattr(logging, level.upper()))
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    console_format = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)
    
    # File handler (optional)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(file_format)
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
class TLSInfo:
    """TLS/SSL certificate information"""
    cn: str = ""
    issuer: str = ""
    expiry: str = ""
    version: str = ""


@dataclass
class HeaderAnalysis:
    """HTTP security header analysis results"""
    url: str = ""
    protocol: str = ""
    found: Dict[str, str] = field(default_factory=dict)
    missing: List[str] = field(default_factory=list)
    issues: List[str] = field(default_factory=list)
    score: int = 0


@dataclass
class CVEInfo:
    """CVE/CWE information"""
    cve_id: str = ""
    cwe_id: List[str] = field(default_factory=list)
    cvss_score: float = 0.0
    cvss_vector: str = ""
    references: List[str] = field(default_factory=list)


@dataclass
class VulnerabilityFinding:
    """Nuclei vulnerability finding with CVE/CWE"""
    name: str
    severity: str
    url: str = ""
    description: str = ""
    template: str = ""
    cve: Optional[CVEInfo] = None
    tags: List[str] = field(default_factory=list)


@dataclass
class ShodanData:
    """Shodan enrichment data"""
    ip: str = ""
    org: str = ""
    asn: str = ""
    isp: str = ""
    os: str = ""
    hostnames: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    vulns: List[str] = field(default_factory=list)  # CVE IDs from Shodan
    tags: List[str] = field(default_factory=list)
    last_update: str = ""
    country: str = ""
    city: str = ""


@dataclass
class ScanResult:
    """Complete scan result - main output structure"""
    target: str
    status: str  # "completed", "failed", "in_progress"
    scan_time: str = ""
    duration: float = 0.0
    
    # Target info
    ip: str = ""
    hostname: str = ""
    
    # Risk assessment
    risk_score: int = 0
    risk_level: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    
    # Scan findings
    open_ports: List[PortInfo] = field(default_factory=list)
    tls_info: Optional[TLSInfo] = None
    header_analysis: Optional[HeaderAnalysis] = None
    vulnerabilities: List[VulnerabilityFinding] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    
    # Shodan enrichment
    shodan_data: Optional[ShodanData] = None
    
    # CVE summary
    cve_list: List[str] = field(default_factory=list)
    cwe_list: List[str] = field(default_factory=list)
    
    # Output files
    output_files: Dict[str, str] = field(default_factory=dict)
    
    # Error info (if failed)
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        # Convert vulnerabilities with CVE info
        vulns_list = []
        for v in self.vulnerabilities:
            vuln_dict = {
                "name": v.name,
                "severity": v.severity,
                "url": v.url,
                "description": v.description,
                "template": v.template,
                "tags": v.tags,
            }
            if v.cve:
                vuln_dict["cve"] = asdict(v.cve)
            vulns_list.append(vuln_dict)
        
        result = {
            "target": self.target,
            "status": self.status,
            "scan_time": self.scan_time,
            "duration": self.duration,
            "ip": self.ip,
            "hostname": self.hostname,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "open_ports": [asdict(p) for p in self.open_ports],
            "tls_info": asdict(self.tls_info) if self.tls_info else None,
            "header_analysis": asdict(self.header_analysis) if self.header_analysis else None,
            "vulnerabilities": vulns_list,
            "cve_list": self.cve_list,
            "cwe_list": self.cwe_list,
            "shodan_data": asdict(self.shodan_data) if self.shodan_data else None,
            "flags": self.flags,
            "output_files": self.output_files,
            "error": self.error,
        }
        return result
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=2)


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN SCANNER CLASS
# ═══════════════════════════════════════════════════════════════════════════════

class SecurityScanner:
    """
    Production-ready security scanner for backend integration.
    
    Usage:
        scanner = SecurityScanner()
        result = scanner.scan("example.com")
        print(result.to_json())
    
    Or with custom config:
        config = ScannerConfig(nmap_ports="-p-")
        scanner = SecurityScanner(config)
        results = scanner.scan_multiple(["target1.com", "target2.com"])
    """
    
    def __init__(self, config: Optional[ScannerConfig] = None):
        """Initialize scanner with configuration"""
        self.config = config or DEFAULT_CONFIG
        self.logger = setup_logging(
            self.config.log_level,
            self.config.log_file
        )
        self._lock = threading.Lock()
        
        # Ensure output directory exists
        os.makedirs(self.config.output_dir, exist_ok=True)
    
    def check_dependencies(self) -> Tuple[bool, Dict[str, bool]]:
        """Check if required tools are installed"""
        deps = {"nmap": False, "nuclei": False}
        
        try:
            subprocess.run(
                [self.config.nmap_path, "--version"],
                capture_output=True, check=True
            )
            deps["nmap"] = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        
        try:
            subprocess.run(
                [self.config.nuclei_path, "-version"],
                capture_output=True, check=True
            )
            deps["nuclei"] = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        
        all_ok = deps["nmap"]  # Nmap is required, Nuclei is optional
        return all_ok, deps
    
    def scan(self, target: str) -> ScanResult:
        """
        Perform a complete security scan on a single target.
        
        Args:
            target: IP address or domain name
            
        Returns:
            ScanResult object with all findings
        """
        start_time = datetime.now()
        self.logger.info(f"Starting scan for: {target}")
        
        result = ScanResult(
            target=target,
            status="in_progress",
            scan_time=start_time.strftime("%Y-%m-%d %H:%M:%S")
        )
        
        try:
            # Phase 1: Nmap scan
            self.logger.info(f"[{target}] Phase 1: Nmap reconnaissance")
            nmap_data = self._run_nmap(target)
            
            if nmap_data is None:
                result.status = "failed"
                result.error = "Nmap scan failed"
                return result
            
            result.ip = nmap_data.get("ip", "")
            result.hostname = nmap_data.get("hostname", "")
            result.open_ports = nmap_data.get("ports", [])
            result.tls_info = nmap_data.get("tls_info")
            result.output_files["nmap_xml"] = nmap_data.get("xml_file", "")
            result.output_files["nmap_txt"] = nmap_data.get("txt_file", "")
            
            if not result.open_ports:
                result.status = "completed"
                result.risk_level = "LOW"
                self.logger.warning(f"[{target}] No open ports found")
                return result
            
            # Phase 2: Security header check
            if self.config.check_headers:
                self.logger.info(f"[{target}] Phase 2: Security header analysis")
                http_ports = [p.port for p in result.open_ports 
                            if p.port in [80, 443, 8080, 8443, 8000, 3000, 5000, 4443]]
                
                if http_ports:
                    header_result = self._check_headers(target, http_ports)
                    result.header_analysis = header_result
                    
                    # Add flags and calculate risk
                    self._process_header_results(result, header_result)
            
            # Phase 3: Shodan enrichment
            if self.config.shodan_enabled and self.config.shodan_api_key:
                self.logger.info(f"[{target}] Phase 3: Shodan enrichment")
                ip_to_query = result.ip if result.ip else target
                shodan_data = self._query_shodan(ip_to_query)
                
                if shodan_data:
                    result.shodan_data = shodan_data
                    # Add Shodan CVEs to cve_list
                    result.cve_list.extend(shodan_data.vulns)
                    
                    # Add risk for Shodan CVEs
                    for cve in shodan_data.vulns:
                        result.risk_score += RISK_WEIGHTS.get("shodan_cve", 15)
                        result.flags.append(f"Shodan CVE: {cve}")
            
            # Phase 4: Nuclei scan
            if self.config.nuclei_enabled:
                self.logger.info(f"[{target}] Phase 4: Nuclei vulnerability scan")
                templates = self._select_templates(result.open_ports)
                vulns = self._run_nuclei(target, templates, result.open_ports)
                result.vulnerabilities = vulns
                result.output_files["nuclei_json"] = self._get_nuclei_output_path(target)
                
                # Add vulnerability risk and collect CVE/CWE
                for vuln in vulns:
                    if vuln.severity.lower() == "critical":
                        result.risk_score += RISK_WEIGHTS["nuclei_critical"]
                    elif vuln.severity.lower() == "high":
                        result.risk_score += RISK_WEIGHTS["nuclei_high"]
                    elif vuln.severity.lower() == "medium":
                        result.risk_score += RISK_WEIGHTS["nuclei_medium"]
                    
                    # Collect CVE/CWE from Nuclei findings
                    if vuln.cve:
                        if vuln.cve.cve_id and vuln.cve.cve_id not in result.cve_list:
                            result.cve_list.append(vuln.cve.cve_id)
                        for cwe in vuln.cve.cwe_id:
                            if cwe and cwe not in result.cwe_list:
                                result.cwe_list.append(cwe)
            
            # Cap risk score and set level
            result.risk_score = min(result.risk_score, 100)
            result.risk_level = self._get_risk_level(result.risk_score)
            
            # Save reports
            self._save_reports(result)
            
            result.status = "completed"
            
        except Exception as e:
            self.logger.error(f"[{target}] Scan failed: {str(e)}")
            result.status = "failed"
            result.error = str(e)
        
        # Calculate duration
        result.duration = (datetime.now() - start_time).total_seconds()
        self.logger.info(f"[{target}] Scan completed in {result.duration:.2f}s - Risk: {result.risk_level}")
        
        return result
    
    def scan_multiple(self, targets: List[str], max_workers: int = 3) -> List[ScanResult]:
        """
        Scan multiple targets concurrently.
        
        Args:
            targets: List of IPs or domains
            max_workers: Maximum concurrent scans
            
        Returns:
            List of ScanResult objects
        """
        results = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_target = {
                executor.submit(self.scan, target): target 
                for target in targets
            }
            
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    self.logger.error(f"[{target}] Exception: {e}")
                    results.append(ScanResult(
                        target=target,
                        status="failed",
                        error=str(e)
                    ))
        
        return results
    
    def scan_from_file(self, filepath: str, max_workers: int = 3) -> List[ScanResult]:
        """
        Scan targets from a file.
        
        Args:
            filepath: Path to file with targets (one per line)
            max_workers: Maximum concurrent scans
            
        Returns:
            List of ScanResult objects
        """
        targets = []
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    targets.append(line)
        
        return self.scan_multiple(targets, max_workers)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # PRIVATE METHODS
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _run_nmap(self, target: str) -> Optional[Dict]:
        """Run Nmap scan and parse results"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = re.sub(r'[^\w\-.]', '_', target)
        
        xml_file = os.path.join(self.config.output_dir, f"nmap_{safe_target}_{timestamp}.xml")
        txt_file = os.path.join(self.config.output_dir, f"nmap_{safe_target}_{timestamp}.txt")
        
        cmd = [
            self.config.nmap_path,
            "--open",
            "-oX", xml_file,
            "-oN", txt_file,
        ]
        
        if self.config.nmap_ports:
            cmd.extend(self.config.nmap_ports.split())
        
        if self.config.nmap_scripts:
            cmd.extend(["--script", self.config.nmap_scripts])
        
        if self.config.nmap_extra_args:
            cmd.extend(self.config.nmap_extra_args.split())
        
        cmd.append(target)
        
        try:
            subprocess.run(
                cmd,
                capture_output=True,
                timeout=self.config.nmap_timeout
            )
        except subprocess.TimeoutExpired:
            self.logger.error(f"[{target}] Nmap timeout")
            return None
        except Exception as e:
            self.logger.error(f"[{target}] Nmap error: {e}")
            return None
        
        # Parse XML
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
            "tls_info": None,
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
            
            # Get ports
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
                result["ports"].append(port_info)
                
                # Check for TLS info
                for script in port.findall('script'):
                    if 'ssl-cert' in script.get('id', ''):
                        tls_info = TLSInfo()
                        output = script.get('output', '')
                        
                        # Parse certificate info
                        for line in output.split('\n'):
                            if 'Subject:' in line:
                                cn_match = re.search(r'CN[=:]([^,/]+)', line, re.IGNORECASE)
                                if cn_match:
                                    tls_info.cn = cn_match.group(1).strip()
                            elif 'Issuer:' in line:
                                tls_info.issuer = line.split(':', 1)[-1].strip()[:50]
                            elif 'Not valid after:' in line:
                                tls_info.expiry = line.split(':', 1)[-1].strip()
                        
                        result["tls_info"] = tls_info
        
        return result
    
    def _check_headers(self, target: str, ports: List[int]) -> HeaderAnalysis:
        """Check HTTP security headers"""
        result = HeaderAnalysis()
        
        # Build URLs (HTTPS first)
        https_urls = [f"https://{target}:{p}" if p != 443 else f"https://{target}" 
                     for p in ports if p in [443, 8443, 4443]]
        http_urls = [f"http://{target}:{p}" if p != 80 else f"http://{target}" 
                    for p in ports if p in [80, 8080, 8000, 3000, 5000]]
        
        urls = https_urls + http_urls
        
        for url in urls:
            is_https = url.startswith('https://')
            
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                
                req = urllib.request.Request(
                    url,
                    headers={'User-Agent': 'Mozilla/5.0 (Security Scanner)'}
                )
                
                with urllib.request.urlopen(req, timeout=self.config.header_timeout, context=ctx) as response:
                    headers = dict(response.headers)
                    result.url = url
                    result.protocol = "HTTPS" if is_https else "HTTP"
                    
                    # Check each security header
                    for sec_header in SECURITY_HEADERS:
                        found = False
                        for h_name, h_value in headers.items():
                            if h_name.lower() == sec_header.lower():
                                result.found[sec_header] = h_value
                                found = True
                                
                                # Check for insecure values
                                if sec_header in HEADER_INSECURE_VALUES:
                                    insecure_vals = HEADER_INSECURE_VALUES[sec_header]
                                    for insecure in insecure_vals:
                                        if insecure.lower() in h_value.lower():
                                            result.issues.append(
                                                f"{sec_header} has insecure value: {insecure}"
                                            )
                                break
                        
                        if not found:
                            # Skip HSTS check for HTTP
                            if sec_header == "Strict-Transport-Security" and not is_https:
                                continue
                            # Skip CORS header if not applicable
                            if sec_header == "Access-Control-Allow-Origin":
                                continue  # Only flag if present but insecure
                            result.missing.append(sec_header)
                    
                    # HTTPS-specific checks
                    if is_https and "Strict-Transport-Security" not in result.found:
                        result.issues.append("HSTS not configured on HTTPS")
                    
                    # Check CORS wildcard
                    if "Access-Control-Allow-Origin" in result.found:
                        if result.found["Access-Control-Allow-Origin"] == "*":
                            result.issues.append("CORS allows all origins (*) - insecure")
                    
                    # Check CSP for unsafe directives
                    if "Content-Security-Policy" in result.found:
                        csp = result.found["Content-Security-Policy"].lower()
                        if "unsafe-inline" in csp:
                            result.issues.append("CSP contains unsafe-inline - weakens XSS protection")
                        if "unsafe-eval" in csp:
                            result.issues.append("CSP contains unsafe-eval - allows code execution")
                    
                    # Calculate score (penalize for issues too)
                    base_score = len(result.found) / len(SECURITY_HEADERS)
                    penalty = len(result.issues) * 0.05  # 5% penalty per issue
                    result.score = max(0, int((base_score - penalty) * 100))
                    break
                    
            except Exception:
                continue
        
        return result
    
    def _process_header_results(self, scan_result: ScanResult, header_result: HeaderAnalysis):
        """Process header results and update risk score"""
        # Add risk for missing headers
        scan_result.risk_score += len(header_result.missing) * RISK_WEIGHTS["missing_header"]
        
        # Critical missing headers
        if header_result.protocol == "HTTPS":
            if "Strict-Transport-Security" in header_result.missing:
                scan_result.risk_score += RISK_WEIGHTS["missing_hsts_https"]
                scan_result.flags.append("Strict-Transport-Security header not implemented")
        
        if "Content-Security-Policy" in header_result.missing:
            scan_result.risk_score += RISK_WEIGHTS["missing_csp"]
            scan_result.flags.append("Content-Security-Policy header not implemented")
        
        if "X-Frame-Options" in header_result.missing:
            scan_result.risk_score += RISK_WEIGHTS["missing_xframe"]
            scan_result.flags.append("X-Frame-Options header not implemented")
        
        if "X-Content-Type-Options" in header_result.missing:
            scan_result.flags.append("X-Content-Type-Options header not implemented")
        
        if "Referrer-Policy" in header_result.missing:
            scan_result.flags.append("Referrer-Policy header not implemented")
        
        if "Permissions-Policy" in header_result.missing:
            scan_result.flags.append("Permissions-Policy header not implemented")
        
        if "Cross-Origin-Opener-Policy" in header_result.missing:
            scan_result.risk_score += RISK_WEIGHTS["missing_coop"]
            scan_result.flags.append("Cross-Origin-Opener-Policy header not implemented")
        
        if "Cross-Origin-Embedder-Policy" in header_result.missing:
            scan_result.risk_score += RISK_WEIGHTS["missing_coep"]
            scan_result.flags.append("Cross-Origin-Embedder-Policy header not implemented")
        
        # Check for insecure configurations
        for issue in header_result.issues:
            if "CORS allows all origins" in issue:
                scan_result.risk_score += RISK_WEIGHTS["insecure_cors"]
                scan_result.flags.append("Access-Control-Allow-Origin header is insecure (allows *)")
            elif "unsafe-inline" in issue:
                scan_result.risk_score += RISK_WEIGHTS["csp_unsafe_inline"]
                scan_result.flags.append(issue)
            elif "unsafe-eval" in issue:
                scan_result.risk_score += RISK_WEIGHTS["csp_unsafe_eval"]
                scan_result.flags.append(issue)
            else:
                scan_result.flags.append(issue)
                scan_result.risk_score += RISK_WEIGHTS["security_issue"]
    
    def _select_templates(self, ports: List[PortInfo]) -> List[str]:
        """Select Nuclei templates based on discovered services"""
        templates = set()
        
        for port in ports:
            service = port.service.lower()
            
            for svc_pattern, tmpl_list in NUCLEI_TEMPLATE_MAP.items():
                if svc_pattern in service:
                    templates.update(tmpl_list)
            
            # Port-based selection
            if port.port in [80, 8080, 8000]:
                templates.update(["http/misconfiguration", "http/exposures"])
            if port.port in [443, 8443]:
                templates.update(["ssl", "http/misconfiguration"])
        
        return list(templates) if templates else ["http/misconfiguration"]
    
    def _run_nuclei(self, target: str, templates: List[str], ports: List[PortInfo]) -> List[VulnerabilityFinding]:
        """Run Nuclei vulnerability scan"""
        findings = []
        
        # Determine URLs
        has_https = any(p.port in [443, 8443] for p in ports)
        has_http = any(p.port in [80, 8080] for p in ports)
        
        urls = []
        if has_https:
            urls.append(f"https://{target}")
        if has_http:
            urls.append(f"http://{target}")
        if not urls:
            urls.append(target)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = re.sub(r'[^\w\-.]', '_', target)
        json_output = os.path.join(self.config.output_dir, f"nuclei_{safe_target}_{timestamp}.json")
        
        for url in urls:
            cmd = [
                self.config.nuclei_path,
                "-u", url,
                "-severity", self.config.nuclei_severity,
                "-rate-limit", str(self.config.nuclei_rate_limit),
                "-json-export", json_output,
                "-silent",
            ]
            
            for tmpl in templates:
                cmd.extend(["-t", tmpl])
            
            try:
                subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=self.config.nuclei_timeout
                )
            except Exception as e:
                self.logger.warning(f"Nuclei error: {e}")
                continue
        
        # Parse results
        if os.path.exists(json_output):
            with open(json_output, 'r') as f:
                content = f.read().strip()
                
                try:
                    data = json.loads(content)
                    items = data if isinstance(data, list) else [data]
                except json.JSONDecodeError:
                    items = []
                    for line in content.split('\n'):
                        if line.strip():
                            try:
                                items.append(json.loads(line))
                            except:
                                pass
                
                for item in items:
                    if isinstance(item, dict):
                        info = item.get('info', {})
                        if isinstance(info, dict):
                            # Extract CVE/CWE info
                            cve_info = None
                            classification = info.get('classification', {}) or {}
                            cve_ids = classification.get('cve-id', []) or []
                            cwe_ids = classification.get('cwe-id', []) or []
                            cvss_metrics = classification.get('cvss-metrics', '') or ''
                            cvss_score = classification.get('cvss-score', 0) or 0
                            
                            # Extract CVE from tags if not in classification
                            tags = info.get('tags', []) or []
                            if not cve_ids:
                                for tag in tags:
                                    if tag.upper().startswith('CVE-'):
                                        cve_ids.append(tag.upper())
                            
                            # Create CVE info if we have data
                            if cve_ids or cwe_ids:
                                refs = info.get('reference', []) or []
                                cve_info = CVEInfo(
                                    cve_id=cve_ids[0] if cve_ids else '',
                                    cwe_id=cwe_ids if cwe_ids else [],
                                    cvss_score=float(cvss_score) if cvss_score else 0.0,
                                    cvss_vector=cvss_metrics,
                                    references=refs[:5] if refs else [],  # Limit to 5 refs
                                )
                            
                            findings.append(VulnerabilityFinding(
                                name=info.get('name', 'Unknown'),
                                severity=info.get('severity', 'unknown'),
                                url=item.get('matched-at', ''),
                                description=info.get('description', ''),
                                template=item.get('template-id', ''),
                                cve=cve_info,
                                tags=tags,
                            ))
        
        return findings
    
    def _get_nuclei_output_path(self, target: str) -> str:
        """Get the Nuclei output file path"""
        safe_target = re.sub(r'[^\w\-.]', '_', target)
        # Return the most recent nuclei file for this target
        files = [f for f in os.listdir(self.config.output_dir) 
                if f.startswith(f"nuclei_{safe_target}") and f.endswith('.json')]
        if files:
            return os.path.join(self.config.output_dir, sorted(files)[-1])
        return ""
    
    def _query_shodan(self, ip: str) -> Optional[ShodanData]:
        """Query Shodan API for host enrichment"""
        if not self.config.shodan_enabled or not self.config.shodan_api_key:
            return None
        
        try:
            import socket
            # Resolve domain to IP if needed
            try:
                resolved_ip = socket.gethostbyname(ip) if not ip.replace('.', '').isdigit() else ip
            except:
                resolved_ip = ip
            
            # Shodan API call
            api_url = f"https://api.shodan.io/shodan/host/{resolved_ip}?key={self.config.shodan_api_key}"
            
            req = urllib.request.Request(
                api_url,
                headers={'User-Agent': 'SecurityScanner/1.0'}
            )
            
            with urllib.request.urlopen(req, timeout=self.config.shodan_timeout) as response:
                data = json.loads(response.read().decode())
                
                shodan_data = ShodanData(
                    ip=data.get('ip_str', resolved_ip),
                    org=data.get('org', ''),
                    asn=data.get('asn', ''),
                    isp=data.get('isp', ''),
                    os=data.get('os', '') or '',
                    hostnames=data.get('hostnames', []),
                    ports=data.get('ports', []),
                    vulns=list(data.get('vulns', {}).keys()) if 'vulns' in data else [],
                    tags=data.get('tags', []),
                    last_update=data.get('last_update', ''),
                    country=data.get('country_name', ''),
                    city=data.get('city', '') or '',
                )
                
                self.logger.info(f"[Shodan] Found {len(shodan_data.vulns)} CVEs for {resolved_ip}")
                return shodan_data
                
        except urllib.error.HTTPError as e:
            if e.code == 404:
                self.logger.info(f"[Shodan] No data found for {ip}")
            else:
                self.logger.warning(f"[Shodan] API error: {e.code}")
            return None
        except Exception as e:
            self.logger.warning(f"[Shodan] Query failed: {e}")
            return None
    
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
    
    def _save_reports(self, result: ScanResult):
        """Save reports in configured formats"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = re.sub(r'[^\w\-.]', '_', result.target)
        base_path = os.path.join(self.config.output_dir, f"report_{safe_target}_{timestamp}")
        
        # JSON
        if "json" in self.config.output_formats:
            json_path = f"{base_path}.json"
            with open(json_path, 'w') as f:
                json.dump(result.to_dict(), f, indent=2)
            result.output_files["report_json"] = json_path
        
        # XML
        if "xml" in self.config.output_formats:
            xml_path = f"{base_path}.xml"
            self._save_xml_report(result, xml_path)
            result.output_files["report_xml"] = xml_path
        
        # TXT
        if "txt" in self.config.output_formats:
            txt_path = f"{base_path}.txt"
            self._save_txt_report(result, txt_path)
            result.output_files["report_txt"] = txt_path
    
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
                    for i, item in enumerate(value):
                        if isinstance(item, dict):
                            lines.append(f'{prefix}  <item>')
                            for k, v in item.items():
                                add_element(k, v, indent + 2)
                            lines.append(f'{prefix}  </item>')
                        else:
                            escaped = str(item).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                            lines.append(f'{prefix}  <item>{escaped}</item>')
                    lines.append(f'{prefix}</{tag}>')
                elif value is not None:
                    escaped = str(value).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                    lines.append(f'{prefix}<{tag}>{escaped}</{tag}>')
            
            for key, value in data.items():
                add_element(key, value)
            
            lines.append(f'</{parent_tag}>')
            return '\n'.join(lines)
        
        xml_content = dict_to_xml(result.to_dict(), "security_scan_report")
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(xml_content)
    
    def _save_txt_report(self, result: ScanResult, filepath: str):
        """Save report as human-readable TXT"""
        lines = [
            "=" * 80,
            "                    SECURITY SCAN REPORT",
            "=" * 80,
            "",
            f"Target:     {result.target}",
            f"IP:         {result.ip}",
            f"Hostname:   {result.hostname}",
            f"Scan Time:  {result.scan_time}",
            f"Duration:   {result.duration:.2f} seconds",
            "",
            "-" * 80,
            "RISK ASSESSMENT",
            "-" * 80,
            f"Risk Score: {result.risk_score}/100",
            f"Risk Level: {result.risk_level}",
            "",
            "-" * 80,
            "OPEN PORTS",
            "-" * 80,
        ]
        
        for port in result.open_ports:
            lines.append(f"  {port.port}/{port.protocol} - {port.service} ({port.product})")
        
        if result.header_analysis:
            lines.extend([
                "",
                "-" * 80,
                "SECURITY HEADERS",
                "-" * 80,
                f"Score: {result.header_analysis.score}/100",
                "",
                "Present:",
            ])
            for h in result.header_analysis.found:
                lines.append(f"  [+] {h}")
            lines.append("")
            lines.append("Missing:")
            for h in result.header_analysis.missing:
                lines.append(f"  [-] {h}")
        
        if result.flags:
            lines.extend([
                "",
                "-" * 80,
                "SECURITY FLAGS",
                "-" * 80,
            ])
            for flag in result.flags:
                lines.append(f"  [!] {flag}")
        
        if result.shodan_data:
            lines.extend([
                "",
                "-" * 80,
                "SHODAN ENRICHMENT",
                "-" * 80,
                f"Organization: {result.shodan_data.org}",
                f"ASN:          {result.shodan_data.asn}",
                f"ISP:          {result.shodan_data.isp}",
                f"Location:     {result.shodan_data.city}, {result.shodan_data.country}",
                f"OS:           {result.shodan_data.os or 'Unknown'}",
                f"Ports:        {', '.join(map(str, result.shodan_data.ports))}",
            ])
            if result.shodan_data.vulns:
                lines.append(f"Known CVEs:   {len(result.shodan_data.vulns)}")
                for cve in result.shodan_data.vulns[:10]:  # Show first 10
                    lines.append(f"  - {cve}")
        
        if result.vulnerabilities:
            lines.extend([
                "",
                "-" * 80,
                "VULNERABILITIES",
                "-" * 80,
            ])
            for vuln in result.vulnerabilities:
                lines.append(f"  [{vuln.severity.upper()}] {vuln.name}")
                if vuln.url:
                    lines.append(f"       URL: {vuln.url}")
                if vuln.cve and vuln.cve.cve_id:
                    lines.append(f"       CVE: {vuln.cve.cve_id}")
                    if vuln.cve.cvss_score:
                        lines.append(f"       CVSS: {vuln.cve.cvss_score}")
                    if vuln.cve.cwe_id:
                        lines.append(f"       CWE: {', '.join(vuln.cve.cwe_id)}")
        
        if result.cve_list:
            lines.extend([
                "",
                "-" * 80,
                "CVE SUMMARY",
                "-" * 80,
                f"Total CVEs Found: {len(result.cve_list)}",
            ])
            for cve in sorted(set(result.cve_list)):
                lines.append(f"  - {cve}")
        
        if result.cwe_list:
            lines.extend([
                "",
                "-" * 80,
                "CWE SUMMARY",
                "-" * 80,
            ])
            for cwe in sorted(set(result.cwe_list)):
                lines.append(f"  - {cwe}")
        
        lines.extend([
            "",
            "=" * 80,
            "                    END OF REPORT",
            "=" * 80,
        ])
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))


# ═══════════════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def quick_scan(target: str) -> ScanResult:
    """Quick scan with default settings"""
    scanner = SecurityScanner()
    return scanner.scan(target)


def scan_targets(targets: List[str], config: Optional[ScannerConfig] = None) -> List[ScanResult]:
    """Scan multiple targets"""
    scanner = SecurityScanner(config)
    return scanner.scan_multiple(targets)


# ═══════════════════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Security Scanner API")
    parser.add_argument("-t", "--target", help="Single target")
    parser.add_argument("-f", "--file", help="Targets file")
    parser.add_argument("-c", "--config", help="Config file")
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    
    args = parser.parse_args()
    
    # Load config
    if args.config:
        config = ScannerConfig.from_file(args.config)
    else:
        config = ScannerConfig.from_env()
    
    if args.output:
        config.output_dir = args.output
    
    scanner = SecurityScanner(config)
    
    # Check dependencies
    ok, deps = scanner.check_dependencies()
    if not ok:
        print("Error: Nmap not found. Install with: sudo apt install nmap")
        sys.exit(1)
    
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
        output = [r.to_dict() for r in results]
        print(json.dumps(output, indent=2))
    else:
        for r in results:
            print(f"\n{r.target}: {r.risk_level} ({r.risk_score}/100)")
            if r.flags:
                for flag in r.flags:
                    print(f"  - {flag}")


