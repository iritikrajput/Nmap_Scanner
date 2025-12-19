#!/usr/bin/env python3
"""
Security Scanner Suite v2.0 - Configuration
Nmap + httpx architecture
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
    nmap_timeout: int = 300
    
    # Nmap IP scan settings
    nmap_ip_tcp_ports: str = ""  # Empty = use --top-ports 1000 (includes high ports like 5060)
    nmap_ip_udp_ports: str = "53,123,161,500"  # Common UDP ports
    nmap_ip_timing: str = "-T4"  # Aggressive timing
    nmap_ip_max_retries: int = 2
    nmap_ip_host_timeout: str = "10m"  # 10 minutes per host
    nmap_ip_scan_udp: bool = False  # UDP disabled by default
    
    # Parallel processing settings
    nmap_min_hostgroup: int = 100  # Min hosts to scan in parallel
    nmap_max_hostgroup: int = 200  # Max hosts to scan in parallel
    nmap_min_rate: int = 1500      # Min packets per second
    nmap_max_rate: int = 5000      # Max packets per second
    
    # Policy settings
    allow_full_udp: bool = False   # Full UDP scan policy protection
    default_scan_type: str = "default"  # Default scan profile
    
    # httpx settings (dead domain detection)
    httpx_path: str = "httpx"
    httpx_timeout: int = 30
    skip_dead_domains: bool = False  # If True, skip Nmap on dead domains
    
    # Redis settings (for production queue)
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: Optional[str] = None
    use_redis: bool = False  # Enable Redis queue mode
    
    # Rate limiting
    rate_limit_scans: int = 20     # Max scans per window
    rate_limit_window: int = 60    # Window in seconds
    
    # Output settings
    output_dir: str = "./scan_results"
    output_formats: List[str] = field(default_factory=lambda: ["json", "txt"])
    
    # Logging
    log_level: str = "INFO"
    log_file: Optional[str] = None
    
    @classmethod
    def from_file(cls, filepath: str) -> "ScannerConfig":
        """Load configuration from JSON file"""
        if not os.path.exists(filepath):
            return cls()
        
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        return cls(**{k: v for k, v in data.items() if hasattr(cls, k)})
    
    @classmethod
    def from_env(cls) -> "ScannerConfig":
        """Load configuration from environment variables"""
        config = cls()
        
        env_mapping = {
            "SCANNER_NMAP_PORTS": "nmap_ports",
            "SCANNER_NMAP_TIMEOUT": ("nmap_timeout", int),
            "SCANNER_NMAP_IP_TCP_PORTS": "nmap_ip_tcp_ports",
            "SCANNER_NMAP_IP_UDP_PORTS": "nmap_ip_udp_ports",
            "SCANNER_NMAP_IP_TIMING": "nmap_ip_timing",
            "SCANNER_NMAP_IP_SCAN_UDP": ("nmap_ip_scan_udp", lambda x: x.lower() == "true"),
            "SCANNER_OUTPUT_DIR": "output_dir",
            "SCANNER_SKIP_DEAD": ("skip_dead_domains", lambda x: x.lower() == "true"),
            "SCANNER_LOG_LEVEL": "log_level",
            "SCANNER_LOG_FILE": "log_file",
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
            "nmap_ports": self.nmap_ports,
            "nmap_timeout": self.nmap_timeout,
            "httpx_timeout": self.httpx_timeout,
            "skip_dead_domains": self.skip_dead_domains,
            "output_dir": self.output_dir,
            "output_formats": self.output_formats,
            "log_level": self.log_level,
        }
    
    def save(self, filepath: str):
        """Save configuration to JSON file"""
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)


# Default configuration instance
DEFAULT_CONFIG = ScannerConfig()


# ═══════════════════════════════════════════════════════════════════════════════
# CLIENT POLICIES - Enterprise-Grade Access Control
# ═══════════════════════════════════════════════════════════════════════════════

CLIENT_POLICIES = {
    "default": {
        "name": "Default Client",
        "allowed_scans": ["default", "quick", "stealth"],
        "rate_limit": 10,  # scans per minute
        "max_targets": 50,  # max targets per bulk request
        "priority": 1,
    },
    "standard": {
        "name": "Standard Client",
        "allowed_scans": ["default", "tcp_full", "udp_common", "quick", "stealth"],
        "rate_limit": 20,
        "max_targets": 100,
        "priority": 2,
    },
    "premium": {
        "name": "Premium Client",
        "allowed_scans": ["default", "tcp_full", "udp_common", "udp_full", "quick", "stealth"],
        "rate_limit": 50,
        "max_targets": 200,
        "priority": 3,
    },
    "admin": {
        "name": "Administrator",
        "allowed_scans": ["default", "tcp_full", "udp_common", "udp_full", "quick", "stealth"],
        "rate_limit": 1000,  # effectively unlimited
        "max_targets": 500,
        "priority": 10,
    }
}


# Security headers to check (comprehensive list)
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

# Header descriptions for reporting
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

# Insecure header values to flag
HEADER_INSECURE_VALUES = {
    "Access-Control-Allow-Origin": ["*"],
    "Content-Security-Policy": ["unsafe-inline", "unsafe-eval"],
}

# Risk scoring weights
RISK_WEIGHTS = {
    # Security headers
    "missing_header": 3,
    "missing_hsts_https": 7,
    "hsts_inconsistent": 5,
    "missing_csp": 5,
    "missing_xframe": 3,
    "insecure_cors": 8,
    
    # SSL/TLS
    "cert_expired": 20,
    "cert_self_signed": 15,
    "cert_mismatch": 25,
    "weak_tls": 15,
    "weak_ciphers": 10,
    
    # Domain
    "dead_domain": 5,
}


if __name__ == "__main__":
    config = ScannerConfig()
    config.save("config.json")
    print("Sample configuration saved to config.json")
