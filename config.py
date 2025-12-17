#!/usr/bin/env python3
"""
Security Scanner Suite - Configuration
Centralized configuration for production deployment
"""

import os
from dataclasses import dataclass, field
from typing import List, Optional
import json


@dataclass
class ScannerConfig:
    """Main scanner configuration"""
    
    # Nmap settings
    nmap_path: str = "nmap"
    nmap_ports: str = "--top-ports 1000"
    nmap_extra_args: str = "-sV -T4"
    nmap_scripts: str = "default,http-headers,http-security-headers,ssl-cert,ssl-enum-ciphers"
    nmap_timeout: int = 300
    
    # Nuclei settings
    nuclei_path: str = "nuclei"
    nuclei_enabled: bool = True
    nuclei_severity: str = "medium,high,critical"
    nuclei_rate_limit: int = 150
    nuclei_timeout: int = 300
    nuclei_templates: List[str] = field(default_factory=lambda: [
        "http/misconfiguration",
        "http/exposures",
        "http/cves",
        "ssl",
        "network/cves",
    ])
    
    # Output settings
    output_dir: str = "./scan_results"
    output_formats: List[str] = field(default_factory=lambda: ["json", "xml", "txt"])
    
    # Security header checking
    check_headers: bool = True
    header_timeout: int = 10
    
    # Logging
    log_level: str = "INFO"
    log_file: Optional[str] = None
    
    # API settings (for backend integration)
    api_enabled: bool = False
    api_host: str = "0.0.0.0"
    api_port: int = 8080
    api_auth_token: Optional[str] = None
    
    # Shodan settings
    shodan_enabled: bool = True
    shodan_api_key: Optional[str] = None
    shodan_timeout: int = 30
    
    @classmethod
    def from_file(cls, filepath: str) -> "ScannerConfig":
        """Load configuration from JSON file"""
        if not os.path.exists(filepath):
            return cls()
        
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        return cls(**data)
    
    @classmethod
    def from_env(cls) -> "ScannerConfig":
        """Load configuration from environment variables"""
        config = cls()
        
        # Map environment variables to config fields
        env_mapping = {
            "SCANNER_NMAP_PATH": "nmap_path",
            "SCANNER_NMAP_PORTS": "nmap_ports",
            "SCANNER_NMAP_TIMEOUT": ("nmap_timeout", int),
            "SCANNER_NUCLEI_PATH": "nuclei_path",
            "SCANNER_NUCLEI_ENABLED": ("nuclei_enabled", lambda x: x.lower() == "true"),
            "SCANNER_NUCLEI_SEVERITY": "nuclei_severity",
            "SCANNER_NUCLEI_RATE_LIMIT": ("nuclei_rate_limit", int),
            "SCANNER_OUTPUT_DIR": "output_dir",
            "SCANNER_CHECK_HEADERS": ("check_headers", lambda x: x.lower() == "true"),
            "SCANNER_LOG_LEVEL": "log_level",
            "SCANNER_LOG_FILE": "log_file",
            "SCANNER_API_ENABLED": ("api_enabled", lambda x: x.lower() == "true"),
            "SCANNER_API_HOST": "api_host",
            "SCANNER_API_PORT": ("api_port", int),
            "SCANNER_API_AUTH_TOKEN": "api_auth_token",
            "SHODAN_API_KEY": "shodan_api_key",
            "SCANNER_SHODAN_ENABLED": ("shodan_enabled", lambda x: x.lower() == "true"),
            "SCANNER_SHODAN_TIMEOUT": ("shodan_timeout", int),
        }
        
        for env_var, field_info in env_mapping.items():
            value = os.environ.get(env_var)
            if value is not None:
                if isinstance(field_info, tuple):
                    field_name, converter = field_info
                    setattr(config, field_name, converter(value))
                else:
                    setattr(config, field_info, value)
        
        return config
    
    def to_dict(self) -> dict:
        """Convert configuration to dictionary"""
        return {
            "nmap_path": self.nmap_path,
            "nmap_ports": self.nmap_ports,
            "nmap_extra_args": self.nmap_extra_args,
            "nmap_scripts": self.nmap_scripts,
            "nmap_timeout": self.nmap_timeout,
            "nuclei_path": self.nuclei_path,
            "nuclei_enabled": self.nuclei_enabled,
            "nuclei_severity": self.nuclei_severity,
            "nuclei_rate_limit": self.nuclei_rate_limit,
            "nuclei_timeout": self.nuclei_timeout,
            "nuclei_templates": self.nuclei_templates,
            "output_dir": self.output_dir,
            "output_formats": self.output_formats,
            "check_headers": self.check_headers,
            "header_timeout": self.header_timeout,
            "log_level": self.log_level,
            "log_file": self.log_file,
            "api_enabled": self.api_enabled,
            "api_host": self.api_host,
            "api_port": self.api_port,
            "shodan_enabled": self.shodan_enabled,
            "shodan_api_key": self.shodan_api_key,
            "shodan_timeout": self.shodan_timeout,
        }
    
    def save(self, filepath: str):
        """Save configuration to JSON file"""
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)


# Default configuration instance
DEFAULT_CONFIG = ScannerConfig()


# Security headers to check
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Resource-Policy",
    "Access-Control-Allow-Origin",
]

# Header descriptions
HEADER_DESCRIPTIONS = {
    "Strict-Transport-Security": "HSTS - Forces HTTPS connections",
    "Content-Security-Policy": "CSP - Prevents XSS and injection attacks",
    "X-Frame-Options": "Clickjacking protection",
    "X-Content-Type-Options": "MIME type sniffing prevention",
    "X-XSS-Protection": "XSS filter (legacy browsers)",
    "Referrer-Policy": "Controls referrer information",
    "Permissions-Policy": "Controls browser features access",
    "Cross-Origin-Opener-Policy": "COOP - Isolates browsing context",
    "Cross-Origin-Embedder-Policy": "COEP - Controls cross-origin embedding",
    "Cross-Origin-Resource-Policy": "CORP - Controls resource sharing",
    "Access-Control-Allow-Origin": "CORS - Controls cross-origin access",
}

# Headers that indicate security issues when misconfigured
HEADER_INSECURE_VALUES = {
    "Access-Control-Allow-Origin": ["*"],  # Wildcard is insecure
    "X-Frame-Options": [],  # Any value is fine, missing is the issue
    "Content-Security-Policy": ["unsafe-inline", "unsafe-eval"],  # These weaken CSP
}

# Nuclei template mapping based on service detection
NUCLEI_TEMPLATE_MAP = {
    "http": ["http/misconfiguration", "http/exposures", "http/cves"],
    "https": ["http/misconfiguration", "http/exposures", "ssl", "http/cves"],
    "ssl": ["ssl/detect", "ssl/misconfigurations"],
    "mysql": ["network/cves", "default-logins"],
    "postgresql": ["network/cves", "default-logins"],
    "mongodb": ["network/cves", "default-logins", "network/exposures"],
    "redis": ["network/cves", "default-logins", "network/exposures"],
    "ssh": ["network/cves", "default-logins"],
    "ftp": ["network/cves", "default-logins", "network/exposures"],
}

# Risk scoring weights
RISK_WEIGHTS = {
    "missing_header": 3,
    "missing_hsts_https": 10,
    "missing_csp": 8,
    "missing_xframe": 5,
    "missing_coop": 3,
    "missing_coep": 3,
    "insecure_cors": 8,
    "csp_unsafe_inline": 6,
    "csp_unsafe_eval": 8,
    "cert_mismatch": 30,
    "weak_tls": 20,
    "nuclei_critical": 40,
    "nuclei_high": 25,
    "nuclei_medium": 10,
    "security_issue": 3,
    "shodan_cve": 15,  # Per CVE found in Shodan
}


if __name__ == "__main__":
    # Generate sample config file
    config = ScannerConfig()
    config.save("config.json")
    print("Sample configuration saved to config.json")


