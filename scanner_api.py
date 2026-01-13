#!/usr/bin/env python3
"""
Security Scanner API - Synchronous Edition
Nmap + httpx (safe, thread-aware, Gunicorn compatible)

Design: One request -> one scan -> one response
No Redis, no job queue, no background workers.
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
import threading

from config import (
    ScannerConfig,
    SECURITY_HEADERS,
    RISK_WEIGHTS,
    DEFAULT_CONFIG
)

# ─────────────────────────────────────────────
# Scan Profiles
# ─────────────────────────────────────────────
SCAN_PROFILES = {
    "default": {"tcp": "--top-ports 1000", "udp": None},
    "quick": {"tcp": "--top-ports 100", "udp": None},
    "tcp_full": {"tcp": "1-65535", "udp": None},
    "udp_common": {
        "tcp": "--top-ports 1000",
        "udp": "53,67,68,69,123,161,389,445,500"
    },
    "udp_full": {"tcp": None, "udp": "1-65535"},
    "stealth": {"tcp": "--top-ports 1000", "udp": None, "timing": "-T2"},
}

# ─────────────────────────────────────────────
# Allowed Profiles for Synchronous API
# Long-running scans (tcp_full, udp_common, udp_full)
# are blocked because they exceed HTTP timeout limits.
# ─────────────────────────────────────────────
ALLOWED_SYNC_PROFILES = ["quick", "default", "stealth"]

# ─────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────
def setup_logging(level: str, log_file: Optional[str]):
    logger = logging.getLogger("SecurityScanner")
    if logger.handlers:
        return logger
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s"
    ))
    logger.addHandler(h)
    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setFormatter(h.formatter)
        logger.addHandler(fh)
    return logger

# ─────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────
@dataclass
class PortInfo:
    port: int
    protocol: str
    state: str
    service: str
    product: str = ""
    version: str = ""

@dataclass
class SSLInfo:
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
    found: Dict[str, str] = field(default_factory=dict)
    missing: List[str] = field(default_factory=list)

@dataclass
class DomainStatus:
    alive: bool = False
    status_code: int = 0

@dataclass
class ScanResult:
    target: str
    status: str
    scan_time: str
    duration: float = 0.0
    ip: str = ""
    hostname: str = ""
    risk_score: int = 0
    risk_level: str = "LOW"
    domain_status: Optional[DomainStatus] = None
    open_ports: List[PortInfo] = field(default_factory=list)
    ssl_info: Optional[SSLInfo] = None
    header_analysis: Optional[HeaderAnalysis] = None
    flags: List[str] = field(default_factory=list)
    output_files: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self):
        return {
            "target": self.target,
            "status": self.status,
            "scan_time": self.scan_time,
            "duration": self.duration,
            "ip": self.ip,
            "hostname": self.hostname,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "domain_status": asdict(self.domain_status) if self.domain_status else None,
            "open_ports": [asdict(p) for p in self.open_ports],
            "ssl_info": asdict(self.ssl_info) if self.ssl_info else None,
            "header_analysis": asdict(self.header_analysis) if self.header_analysis else None,
            "flags": self.flags,
            "output_files": self.output_files,
            "error": self.error,
        }

# ─────────────────────────────────────────────
# Main Scanner
# ─────────────────────────────────────────────
class SecurityScanner:

    def __init__(self, config: Optional[ScannerConfig] = None):
        self.config = config or DEFAULT_CONFIG
        self.logger = setup_logging(self.config.log_level, self.config.log_file)
        self._lock = threading.Lock()
        os.makedirs(self.config.output_dir, exist_ok=True)

    def check_dependencies(self) -> Tuple[bool, Dict[str, bool]]:
        deps = {"nmap": False, "httpx": False}
        try:
            subprocess.run(["nmap", "--version"], capture_output=True, check=True)
            deps["nmap"] = True
        except Exception:
            pass
        try:
            subprocess.run(["httpx", "-version"], capture_output=True, check=True)
            deps["httpx"] = True
        except Exception:
            pass
        return deps["nmap"], deps

    def _is_ip(self, t: str) -> bool:
        return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", t))

    # ─────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────
    def scan(self, target: str, scan_type: str = "default") -> ScanResult:
        start = datetime.now()
        result = ScanResult(
            target=target,
            status="in_progress",
            scan_time=start.strftime("%Y-%m-%d %H:%M:%S")
        )

        try:
            if self._is_ip(target):
                nmap = self._run_nmap_ports_only(target, scan_type)
                if nmap:
                    result.ip = target
                    result.open_ports = nmap["ports"]
                result.status = "completed"
            else:
                status = self._check_domain_status(target)
                result.domain_status = status
                result.status = "alive" if status.alive else "dead"
                if not status.alive:
                    result.risk_score += RISK_WEIGHTS["dead_domain"]

                nmap = self._run_nmap(target)
                if nmap:
                    result.ip = nmap.get("ip", "")
                    result.open_ports = nmap.get("ports", [])
                    result.ssl_info = nmap.get("ssl_info")
                    result.header_analysis = nmap.get("header_analysis")

                self._process_ssl(result)
                self._process_headers(result)

            result.risk_score = min(result.risk_score, 100)
            result.risk_level = self._risk_level(result.risk_score)
            self._save_reports(result)

        except Exception as e:
            result.status = "failed"
            result.error = str(e)

        result.duration = (datetime.now() - start).total_seconds()
        return result

    # ─────────────────────────────────────────
    # httpx (SAFE parsing)
    # ─────────────────────────────────────────
    def _check_domain_status(self, target: str) -> DomainStatus:
        status = DomainStatus()
        try:
            p = subprocess.run(
                ["httpx", "-u", target, "-json", "-silent"],
                capture_output=True,
                text=True,
                timeout=20
            )
            for line in p.stdout.splitlines():
                try:
                    data = json.loads(line)
                    status.alive = True
                    status.status_code = data.get("status_code", 0)
                    return status
                except json.JSONDecodeError:
                    continue
        except Exception:
            pass

        for scheme in ("https", "http"):
            try:
                with urllib.request.urlopen(f"{scheme}://{target}", timeout=5):
                    status.alive = True
                    return status
            except urllib.error.HTTPError as e:
                status.alive = True
                status.status_code = e.code
                return status
            except Exception:
                continue
        return status

    # ─────────────────────────────────────────
    # Nmap
    # ─────────────────────────────────────────
    def _run_nmap_ports_only(self, target: str, scan_type: str):
        if scan_type not in SCAN_PROFILES:
            raise ValueError("Invalid scan type")

        profile = SCAN_PROFILES[scan_type]
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^\w\-\.]", "_", target)
        xml = f"{self.config.output_dir}/nmap_{safe}_{ts}.xml"

        # Core Nmap command: -Pn (no ping), -sV (service version detection)
        # --version-intensity 9 for maximum service/version detection (slower but more thorough)
        cmd = ["nmap", "-Pn", "-sV", "--version-intensity", "9", "-oX", xml]

        # Add port specification
        if profile.get("tcp"):
            if profile["tcp"].startswith("--"):
                cmd.extend(profile["tcp"].split())
            else:
                cmd.extend(["-p", profile["tcp"]])

        if profile.get("udp"):
            if scan_type == "udp_full" and not self.config.allow_full_udp:
                raise PermissionError("UDP full scan disabled")
            cmd.append("-sU")
            cmd.extend(["-pU:" + profile["udp"]])

        # Add timing (default -T4)
        cmd.append(profile.get("timing", "-T4"))
        cmd.append(target)

        self.logger.info(f"Running Nmap: {' '.join(cmd)}")
        subprocess.run(cmd, timeout=900, capture_output=True)
        return self._parse_nmap_xml(xml)

    def _run_nmap(self, target: str):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^\w\-\.]", "_", target)
        xml = f"{self.config.output_dir}/nmap_{safe}_{ts}.xml"

        # Core Nmap command: -Pn (no ping), -sV (service version detection)
        # --version-intensity 9 for maximum service/version detection
        cmd = [
            "nmap", "-Pn", "-sV", "--version-intensity", "9", "-T4",
            "--script", "ssl-cert,ssl-enum-ciphers,http-security-headers",
            "-oX", xml,
            target
        ]
        self.logger.info(f"Running Nmap: {' '.join(cmd)}")
        subprocess.run(cmd, timeout=900, capture_output=True)
        return self._parse_nmap_xml(xml)

    def _parse_nmap_xml(self, xml: str):
        if not os.path.exists(xml):
            return None
        tree = ET.parse(xml)
        root = tree.getroot()

        ports = []
        ssl = SSLInfo()
        headers = HeaderAnalysis()
        ip = ""

        for host in root.findall("host"):
            for addr in host.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    ip = addr.get("addr")

            for port in host.findall(".//port"):
                state_elem = port.find("state")
                if state_elem is not None and state_elem.get("state") == "open":
                    svc = port.find("service")
                    ports.append(PortInfo(
                        port=int(port.get("portid")),
                        protocol=port.get("protocol"),
                        state="open",
                        service=svc.get("name", "") if svc is not None else "",
                        product=svc.get("product", "") if svc is not None else "",
                        version=svc.get("version", "") if svc is not None else ""
                    ))

                for script in port.findall("script"):
                    if script.get("id") == "ssl-cert":
                        if "Not valid after" in script.get("output", ""):
                            ssl.expired = True

                    if script.get("id") == "http-security-headers":
                        for h in SECURITY_HEADERS:
                            if h.lower() not in script.get("output", "").lower():
                                headers.missing.append(h)

        return {
            "ip": ip,
            "ports": ports,
            "ssl_info": ssl if ssl.expired else None,
            "header_analysis": headers if headers.missing else None,
        }

    # ─────────────────────────────────────────
    # Risk processing
    # ─────────────────────────────────────────
    def _process_ssl(self, r: ScanResult):
        if r.ssl_info and r.ssl_info.expired:
            r.risk_score += RISK_WEIGHTS["cert_expired"]
            r.flags.append("SSL certificate expired")

    def _process_headers(self, r: ScanResult):
        if r.header_analysis:
            for _ in r.header_analysis.missing:
                r.risk_score += RISK_WEIGHTS["missing_header"]

    def _risk_level(self, s: int):
        if s < 20:
            return "LOW"
        if s < 50:
            return "MEDIUM"
        if s < 80:
            return "HIGH"
        return "CRITICAL"

    # ─────────────────────────────────────────
    # Reports (thread-safe)
    # ─────────────────────────────────────────
    def _save_reports(self, r: ScanResult):
        safe = re.sub(r"[^\w\-\.]", "_", r.target)
        path = f"{self.config.output_dir}/{safe}.json"
        with self._lock:
            data = {"target": r.target, "scans": []}
            if os.path.exists(path):
                try:
                    with open(path) as f:
                        data = json.load(f)
                except Exception:
                    pass
            data["scans"].append(r.to_dict())
            with open(path, "w") as f:
                json.dump(data, f, indent=2)
