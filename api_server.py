#!/usr/bin/env python3
"""
Security Scanner API Server - Synchronous Edition
One request -> one scan (or small batch) -> one response
No Redis, no job queue, no background workers.
"""

import os
import sys
import threading
from time import time
from datetime import datetime
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify
from scanner_api import SecurityScanner, ScanResult, SCAN_PROFILES, ALLOWED_SYNC_PROFILES
from config import ScannerConfig

# ─────────────────────────────────────────────────────────────
# APP
# ─────────────────────────────────────────────────────────────
app = Flask(__name__)
config = ScannerConfig.from_env()

# ─────────────────────────────────────────────────────────────
# THREAD-LOCAL SCANNER (reused per thread)
# ─────────────────────────────────────────────────────────────
thread_local = threading.local()


def get_scanner() -> SecurityScanner:
    if not hasattr(thread_local, "scanner"):
        thread_local.scanner = SecurityScanner(config)
    return thread_local.scanner


# ─────────────────────────────────────────────────────────────
# RATE LIMITING
# ─────────────────────────────────────────────────────────────
client_requests: Dict[str, List[float]] = defaultdict(list)
rate_limit_lock = threading.Lock()


def get_client_id() -> str:
    return request.remote_addr or "unknown"


def check_rate_limit() -> Optional[tuple]:
    client_id = get_client_id()
    now = time()

    with rate_limit_lock:
        client_requests[client_id] = [
            t for t in client_requests[client_id]
            if now - t < config.rate_limit_window
        ]

        if len(client_requests[client_id]) >= config.rate_limit_scans:
            return jsonify({
                "error": "Rate limit exceeded",
                "limit": config.rate_limit_scans,
                "window_seconds": config.rate_limit_window
            }), 429

        client_requests[client_id].append(now)

    return None


# ─────────────────────────────────────────────────────────────
# SCAN EXECUTION
# ─────────────────────────────────────────────────────────────
MAX_TARGETS = 10
MAX_THREADS = 5


def scan_single_target(target: str, scan_type: str) -> Dict[str, Any]:
    """Execute a single scan and return result dict."""
    scanner = get_scanner()

    try:
        result: ScanResult = scanner.scan(target, scan_type)
        return {
            "target": target,
            "status": result.status,
            **result.to_dict()
        }
    except PermissionError as e:
        return {
            "target": target,
            "status": "blocked",
            "error": str(e)
        }
    except Exception as e:
        return {
            "target": target,
            "status": "failed",
            "error": str(e)
        }


def run_parallel_scans(targets: List[str], scan_type: str) -> List[Dict[str, Any]]:
    """Run scans in parallel using ThreadPoolExecutor."""
    results = []
    num_threads = min(MAX_THREADS, len(targets))

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = {
            executor.submit(scan_single_target, t.strip(), scan_type): t
            for t in targets
        }

        for future in as_completed(futures):
            results.append(future.result())

    return results


# ─────────────────────────────────────────────────────────────
# FLASK HOOKS
# ─────────────────────────────────────────────────────────────
@app.before_request
def before_request():
    if request.method == "POST" and request.path == "/api/scan":
        return check_rate_limit()


# ─────────────────────────────────────────────────────────────
# API ENDPOINTS
# ─────────────────────────────────────────────────────────────
@app.route("/api/health", methods=["GET"])
def health():
    """Health check endpoint."""
    return jsonify({
        "status": "ok",
        "mode": "synchronous"
    })


@app.route("/api/scan", methods=["POST"])
def scan():
    """
    Main scan endpoint.

    Accepts:
        {"target": "1.1.1.1"}
    or:
        {"targets": ["1.1.1.1", "8.8.8.8"], "scan_type": "default"}

    Returns scan results directly in response.
    """
    data = request.get_json() or {}

    # Parse targets
    if "target" in data:
        targets = [data["target"]]
    elif "targets" in data:
        targets = data["targets"]
    else:
        return jsonify({"error": "Missing 'target' or 'targets'"}), 400

    # Validate targets
    if not targets:
        return jsonify({"error": "No targets provided"}), 400

    if len(targets) > MAX_TARGETS:
        return jsonify({
            "error": f"Too many targets (max {MAX_TARGETS})",
            "provided": len(targets),
            "max_allowed": MAX_TARGETS
        }), 400

    # Validate scan type
    scan_type = data.get("scan_type", "default")

    if scan_type not in SCAN_PROFILES:
        return jsonify({
            "error": "Invalid scan_type",
            "allowed": list(SCAN_PROFILES.keys())
        }), 400

    if scan_type not in ALLOWED_SYNC_PROFILES:
        return jsonify({
            "error": f"Scan type '{scan_type}' not allowed in sync mode",
            "reason": "Long-running scans exceed HTTP timeout limits",
            "allowed": ALLOWED_SYNC_PROFILES
        }), 400

    # Execute scan(s)
    start = datetime.now()

    if len(targets) == 1:
        results = [scan_single_target(targets[0].strip(), scan_type)]
    else:
        results = run_parallel_scans(targets, scan_type)

    duration = (datetime.now() - start).total_seconds()

    return jsonify({
        "total_targets": len(targets),
        "scan_type": scan_type,
        "duration_seconds": round(duration, 2),
        "results": results
    })


# ─────────────────────────────────────────────────────────────
# MAIN (Development only)
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Security Scanner API")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind")
    parser.add_argument("--debug", action="store_true", help="Debug mode")

    args = parser.parse_args()

    print(f"\nSecurity Scanner API (Synchronous)")
    print(f"=" * 50)
    print(f"Endpoint: http://{args.host}:{args.port}/api/scan")
    print(f"Health:   http://{args.host}:{args.port}/api/health")
    print(f"=" * 50)

    app.run(host=args.host, port=args.port, debug=args.debug)
