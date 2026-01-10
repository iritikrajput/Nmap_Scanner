#!/usr/bin/env python3
"""
Security Scanner API Server - Synchronous Edition (Gunicorn Optimized)
All scan results are returned in the same request
"""

import os
import sys
import json
import uuid
import threading
from time import time
from datetime import datetime
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify
from scanner_api import SecurityScanner, ScanResult, SCAN_PROFILES
from config import ScannerConfig

# ─────────────────────────────────────────────────────────────
# APP
# ─────────────────────────────────────────────────────────────
app = Flask(__name__)
config = ScannerConfig.from_env()

# ─────────────────────────────────────────────────────────────
# REDIS (OPTIONAL)
# ─────────────────────────────────────────────────────────────
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None

USE_REDIS = os.environ.get("USE_REDIS", "false").lower() == "true"
redis_client = None

if USE_REDIS and REDIS_AVAILABLE:
    try:
        redis_client = redis.Redis(
            host=os.environ.get("REDIS_HOST", "localhost"),
            port=int(os.environ.get("REDIS_PORT", 6379)),
            decode_responses=True
        )
        redis_client.ping()
    except Exception:
        redis_client = None

# ─────────────────────────────────────────────────────────────
# EXECUTOR (THREAD ONLY – SAFE FOR NMAP)
# ─────────────────────────────────────────────────────────────
MAX_PARALLEL_SCANS = int(os.environ.get("MAX_PARALLEL_SCANS", 8))
executor = ThreadPoolExecutor(max_workers=MAX_PARALLEL_SCANS)
EXECUTOR_TYPE = "ThreadPool"

# ─────────────────────────────────────────────────────────────
# GLOBAL STATE
# ─────────────────────────────────────────────────────────────
scan_results: Dict[str, Dict[str, Any]] = {}
results_lock = threading.Lock()
rate_limit_lock = threading.Lock()

# ─────────────────────────────────────────────────────────────
# RATE LIMITING
# ─────────────────────────────────────────────────────────────
client_requests: Dict[str, List[float]] = defaultdict(list)
RATE_LIMIT_DEFAULT = config.rate_limit_scans
RATE_WINDOW = config.rate_limit_window


def get_client_id() -> str:
    return request.remote_addr or "unknown"


def check_rate_limit() -> Optional[tuple]:
    client_id = get_client_id()
    now = time()

    with rate_limit_lock:
        client_requests[client_id] = [
            t for t in client_requests[client_id]
            if now - t < RATE_WINDOW
        ]

        if len(client_requests[client_id]) >= RATE_LIMIT_DEFAULT:
            return jsonify({
                "error": "Rate limit exceeded",
                "limit": RATE_LIMIT_DEFAULT,
                "window_seconds": RATE_WINDOW
            }), 429

        client_requests[client_id].append(now)

    return None


def check_targets_limit(targets: List[str]) -> Optional[tuple]:
    if len(targets) > 200:
        return jsonify({
            "error": "Too many targets",
            "max_allowed": 200
        }), 400
    return None

# ─────────────────────────────────────────────────────────────
# REDIS HELPERS
# ─────────────────────────────────────────────────────────────
def redis_store_result(scan_id: str, result: Dict[str, Any]):
    if redis_client:
        redis_client.setex(
            f"scan:result:{scan_id}",
            86400,
            json.dumps(result)
        )


# ─────────────────────────────────────────────────────────────
# SCANNER (REUSED PER THREAD)
# ─────────────────────────────────────────────────────────────
thread_local = threading.local()


def get_scanner() -> SecurityScanner:
    if not hasattr(thread_local, "scanner"):
        thread_local.scanner = SecurityScanner(config)
    return thread_local.scanner


def scan_single_target(target: str, scan_id: str, scan_type: str) -> Dict[str, Any]:
    started_at = datetime.now().isoformat()
    scanner = get_scanner()

    try:
        result: ScanResult = scanner.scan(target, scan_type)
        data = {
            "id": scan_id,
            "target": target,
            "scan_type": scan_type,
            "status": "completed",
            "started_at": started_at,
            "completed_at": datetime.now().isoformat(),
            **result.to_dict()
        }
    except PermissionError as e:
        data = {
            "id": scan_id,
            "target": target,
            "scan_type": scan_type,
            "status": "blocked",
            "error": str(e)
        }
    except Exception as e:
        data = {
            "id": scan_id,
            "target": target,
            "scan_type": scan_type,
            "status": "failed",
            "error": str(e)
        }

    redis_store_result(scan_id, data)
    with results_lock:
        scan_results[scan_id] = data

    return data


def run_parallel_scans(targets: List[str], scan_type: str) -> List[Dict[str, Any]]:
    futures = []
    results = []

    for t in targets:
        scan_id = str(uuid.uuid4())[:8]
        futures.append(
            executor.submit(scan_single_target, t.strip(), scan_id, scan_type)
        )

    for f in as_completed(futures):
        results.append(f.result())

    return results

# ─────────────────────────────────────────────────────────────
# FLASK HOOKS
# ─────────────────────────────────────────────────────────────
@app.before_request
def before_request():
    if request.method == "POST" and request.path.startswith("/api/scan"):
        return check_rate_limit()

# ─────────────────────────────────────────────────────────────
# API ENDPOINTS
# ─────────────────────────────────────────────────────────────
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "executor": EXECUTOR_TYPE,
        "workers": MAX_PARALLEL_SCANS,
        "redis": bool(redis_client)
    })


@app.route("/api/scan", methods=["POST"])
def scan_single():
    data = request.get_json() or {}
    target = data.get("target")
    scan_type = data.get("scan_type", "default")

    if not target:
        return jsonify({"error": "Missing target"}), 400

    if scan_type not in SCAN_PROFILES:
        return jsonify({"error": "Invalid scan_type"}), 400

    scan_id = str(uuid.uuid4())[:8]
    result = scan_single_target(target.strip(), scan_id, scan_type)
    return jsonify(result), 200


@app.route("/api/scan/bulk", methods=["POST"])
def bulk_scan():
    data = request.get_json() or {}
    targets = data.get("targets", [])
    scan_type = data.get("scan_type", "default")

    if not targets:
        return jsonify({"error": "Missing targets"}), 400

    limit_error = check_targets_limit(targets)
    if limit_error:
        return limit_error

    if scan_type not in SCAN_PROFILES:
        return jsonify({"error": "Invalid scan_type"}), 400

    start = datetime.now()
    results = run_parallel_scans(targets, scan_type)

    return jsonify({
        "total": len(targets),
        "completed": len(results),
        "duration_seconds": round((datetime.now() - start).total_seconds(), 2),
        "results": results
    })


# ─────────────────────────────────────────────────────────────
# GUNICORN ENTRY
# ─────────────────────────────────────────────────────────────
# Run with:
# gunicorn -k gthread -w 4 --threads 2 api_server:app
