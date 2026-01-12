#!/usr/bin/env python3
"""
Security Scanner Suite - Configuration (Synchronous Edition)
Nmap + httpx architecture

Design: Simple, predictable, no external dependencies (no Redis).
"""

import os
import json
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ScannerConfig:
    """
    Main scanner configuration

    Optimized for:
    - Gunicorn (gthread)
    - ThreadPoolExecutor
    - External Nmap processes
    - Synchronous request/response model
    """

    # ─────────────────────────────────────────────
    # Nmap core settings
    # ─────────────────────────────────────────────
    nmap_path: str = "nmap"
    nmap_ports: str = "--top-ports 1000"
    nmap_timeout: int = 300

    # ─────────────────────────────────────────────
    # Nmap IP scan settings
    # ─────────────────────────────────────────────
    nmap_ip_tcp_ports: str = ""
    nmap_ip_udp_ports: str = "53,123,161,500"
    nmap_ip_timing: str = "-T4"
    nmap_ip_max_retries: int = 2
    nmap_ip_host_timeout: str = "10m"
    nmap_ip_scan_udp: bool = False

    # ─────────────────────────────────────────────
    # Nmap parallelism (SAFE VALUES)
    # IMPORTANT: Python threads handle parallelism,
    # Nmap must be kept conservative
    # ─────────────────────────────────────────────
    nmap_min_hostgroup: int = 32
    nmap_max_hostgroup: int = 64
    nmap_min_rate: int = 800
    nmap_max_rate: int = 2000

    # ─────────────────────────────────────────────
    # Scan policy
    # ─────────────────────────────────────────────
    allow_full_udp: bool = False
    default_scan_type: str = "default"

    # ─────────────────────────────────────────────
    # httpx (dead domain detection)
    # ─────────────────────────────────────────────
    httpx_path: str = "httpx"
    httpx_timeout: int = 30
    skip_dead_domains: bool = False

    # ─────────────────────────────────────────────
    # Rate limiting (API level)
    # ─────────────────────────────────────────────
    rate_limit_scans: int = 20
    rate_limit_window: int = 60

    # ─────────────────────────────────────────────
    # Output
    # ─────────────────────────────────────────────
    output_dir: str = "./scan_results"
    output_formats: List[str] = field(default_factory=lambda: ["json", "txt"])

    # ─────────────────────────────────────────────
    # Logging
    # ─────────────────────────────────────────────
    log_level: str = "INFO"
    log_file: Optional[str] = None

    # ─────────────────────────────────────────────
    # Loaders
    # ─────────────────────────────────────────────
    @classmethod
    def from_file(cls, filepath: str) -> "ScannerConfig":
        if not os.path.exists(filepath):
            return cls()

        with open(filepath, "r") as f:
            data = json.load(f)

        return cls(**{k: v for k, v in data.items() if hasattr(cls, k)})

    @classmethod
    def from_env(cls) -> "ScannerConfig":
        """
        Load configuration from environment variables
        (Production & Docker friendly)
        """
        config = cls()

        env_mapping = {
            # Nmap
            "SCANNER_NMAP_PORTS": "nmap_ports",
            "SCANNER_NMAP_TIMEOUT": ("nmap_timeout", int),
            "SCANNER_NMAP_TIMING": "nmap_ip_timing",

            # Parallel tuning
            "SCANNER_NMAP_MIN_HOSTGROUP": ("nmap_min_hostgroup", int),
            "SCANNER_NMAP_MAX_HOSTGROUP": ("nmap_max_hostgroup", int),
            "SCANNER_NMAP_MIN_RATE": ("nmap_min_rate", int),
            "SCANNER_NMAP_MAX_RATE": ("nmap_max_rate", int),

            # UDP
            "SCANNER_ALLOW_FULL_UDP": ("allow_full_udp", lambda x: x.lower() == "true"),
            "SCANNER_SCAN_UDP": ("nmap_ip_scan_udp", lambda x: x.lower() == "true"),

            # httpx
            "SCANNER_HTTPX_TIMEOUT": ("httpx_timeout", int),
            "SCANNER_SKIP_DEAD": ("skip_dead_domains", lambda x: x.lower() == "true"),

            # Output
            "SCANNER_OUTPUT_DIR": "output_dir",

            # Logging
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
        return {
            "nmap_ports": self.nmap_ports,
            "nmap_timeout": self.nmap_timeout,
            "nmap_min_hostgroup": self.nmap_min_hostgroup,
            "nmap_max_hostgroup": self.nmap_max_hostgroup,
            "nmap_min_rate": self.nmap_min_rate,
            "nmap_max_rate": self.nmap_max_rate,
            "httpx_timeout": self.httpx_timeout,
            "skip_dead_domains": self.skip_dead_domains,
            "output_dir": self.output_dir,
            "output_formats": self.output_formats,
            "log_level": self.log_level,
        }

    def save(self, filepath: str):
        with open(filepath, "w") as f:
            json.dump(self.to_dict(), f, indent=2)


# Default instance
DEFAULT_CONFIG = ScannerConfig()

# ─────────────────────────────────────────────
# Security headers & risk weights
# ─────────────────────────────────────────────
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

HEADER_INSECURE_VALUES = {
    "Access-Control-Allow-Origin": ["*"],
    "Content-Security-Policy": ["unsafe-inline", "unsafe-eval"],
}

RISK_WEIGHTS = {
    "missing_header": 3,
    "missing_hsts_https": 7,
    "hsts_inconsistent": 5,
    "missing_csp": 5,
    "missing_xframe": 3,
    "insecure_cors": 8,
    "cert_expired": 20,
    "cert_self_signed": 15,
    "cert_mismatch": 25,
    "weak_tls": 15,
    "weak_ciphers": 10,
    "dead_domain": 5,
}


if __name__ == "__main__":
    cfg = ScannerConfig()
    cfg.save("config.json")
    print("Sample configuration saved to config.json")
