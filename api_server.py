#!/usr/bin/env python3
"""
Security Scanner API Server - Synchronous Edition
All scan results are returned in the same request (no async/queue pattern)
"""

import os
import sys
import json
import uuid
import threading
from time import time
from datetime import datetime
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify

from scanner_api import SecurityScanner, ScanResult, SCAN_PROFILES
from config import ScannerConfig

# ═══════════════════════════════════════════════════════════════════════════════
# REDIS (OPTIONAL)
# ═══════════════════════════════════════════════════════════════════════════════

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None

app = Flask(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

config = ScannerConfig.from_env()

# Storage for history (optional)
scan_results: Dict[str, Dict[str, Any]] = {}
results_lock = threading.Lock()
rate_limit_lock = threading.Lock()

MAX_PARALLEL_SCANS = int(os.environ.get("MAX_PARALLEL_SCANS", 50))

# Redis
USE_REDIS = os.environ.get("USE_REDIS", "false").lower() == "true"
REDIS_HOST = os.environ.get("REDIS_HOST", config.redis_host)
REDIS_PORT = int(os.environ.get("REDIS_PORT", config.redis_port))
REDIS_DB = int(os.environ.get("REDIS_DB", config.redis_db))
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD", config.redis_password)

redis_client = None
if USE_REDIS and REDIS_AVAILABLE:
    try:
        redis_client = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            db=REDIS_DB,
            password=REDIS_PASSWORD,
            decode_responses=True
        )
        redis_client.ping()
        print(f"✓ Redis connected: {REDIS_HOST}:{REDIS_PORT}")
    except Exception as e:
        print(f"⚠ Redis connection failed: {e}")
        redis_client = None

# ═══════════════════════════════════════════════════════════════════════════════
# EXECUTOR
# ═══════════════════════════════════════════════════════════════════════════════

USE_PROCESS_POOL = os.environ.get("USE_PROCESS_POOL", "true").lower() == "true"

if USE_PROCESS_POOL:
    executor = ProcessPoolExecutor(max_workers=min(MAX_PARALLEL_SCANS, 50))
    EXECUTOR_TYPE = "ProcessPool"
else:
    executor = ThreadPoolExecutor(max_workers=MAX_PARALLEL_SCANS)
    EXECUTOR_TYPE = "ThreadPool"

# ═══════════════════════════════════════════════════════════════════════════════
# RATE LIMITING
# ═══════════════════════════════════════════════════════════════════════════════

client_requests: Dict[str, List[float]] = defaultdict(list)
RATE_LIMIT_DEFAULT = config.rate_limit_scans
RATE_WINDOW = config.rate_limit_window


def get_client_id() -> str:
    return request.remote_addr


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
                "window_seconds": RATE_WINDOW,
                "retry_after": int(RATE_WINDOW - (now - client_requests[client_id][0]))
            }), 429

        client_requests[client_id].append(now)

    return None


def check_targets_limit(targets: List[str]) -> Optional[tuple]:
    max_targets = 200
    
    if len(targets) > max_targets:
        return jsonify({
            "error": f"Too many targets. Maximum {max_targets} allowed.",
            "requested": len(targets),
            "max_allowed": max_targets
        }), 400

    return None

# ═══════════════════════════════════════════════════════════════════════════════
# REDIS STORAGE
# ═══════════════════════════════════════════════════════════════════════════════


def redis_store_result(scan_id: str, result: Dict[str, Any]):
    if not redis_client:
        return False
    redis_client.set(f"scan:result:{scan_id}", json.dumps(result))
    redis_client.expire(f"scan:result:{scan_id}", 86400)
    return True


def redis_get_result(scan_id: str) -> Optional[Dict[str, Any]]:
    if not redis_client:
        return None
    data = redis_client.get(f"scan:result:{scan_id}")
    if not data:
        return None
    return json.loads(data)

# ═══════════════════════════════════════════════════════════════════════════════
# SCANNER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════


def scan_single_target(target: str, scan_id: str, scan_type: str = "default") -> Dict[str, Any]:
    """Scan single target and return result dict"""
    started_at = datetime.now().isoformat()

    try:
        scanner_config = ScannerConfig.from_env()
        scanner = SecurityScanner(scanner_config)
        result: ScanResult = scanner.scan(target, scan_type=scan_type)
        result_dict = result.to_dict()

        return {
            "id": scan_id,
            "target": target,
            "scan_type": scan_type,
            "status": "completed",
            "started_at": started_at,
            "completed_at": datetime.now().isoformat(),
            **result_dict
        }
    except PermissionError as e:
        return {
            "id": scan_id,
            "target": target,
            "scan_type": scan_type,
            "status": "blocked",
            "started_at": started_at,
            "completed_at": datetime.now().isoformat(),
            "error": str(e)
        }
    except Exception as e:
        return {
            "id": scan_id,
            "target": target,
            "scan_type": scan_type,
            "status": "failed",
            "started_at": started_at,
            "completed_at": datetime.now().isoformat(),
            "error": str(e)
        }


def run_parallel_scans(targets: List[str], scan_type: str = "default") -> List[Dict[str, Any]]:
    """Run multiple scans in parallel and return ALL results"""
    results: List[Dict[str, Any]] = []
    futures = {}

    for target in targets:
        target = str(target).strip()
        if not target:
            continue
        scan_id = str(uuid.uuid4())[:8]
        future = executor.submit(scan_single_target, target, scan_id, scan_type)
        futures[future] = {"scan_id": scan_id, "target": target}

    # Wait for ALL scans to complete
    for future in as_completed(futures):
        try:
            result = future.result(timeout=600)  # 10 min timeout
            scan_id = result["id"]
            results.append(result)

            # Store in Redis and memory
            if redis_client:
                redis_store_result(scan_id, result)
            with results_lock:
                scan_results[scan_id] = result
        except Exception as e:
            info = futures[future]
            error_result = {
                "id": info["scan_id"],
                "target": info["target"],
                "scan_type": scan_type,
                "status": "failed",
                "error": str(e)
            }
            results.append(error_result)

    return results

# ═══════════════════════════════════════════════════════════════════════════════
# HOOKS
# ═══════════════════════════════════════════════════════════════════════════════


@app.before_request
def before_request():
    if request.path.startswith("/api/scan") and request.method == "POST":
        rate_error = check_rate_limit()
        if rate_error:
            return rate_error

# ═══════════════════════════════════════════════════════════════════════════════
# API ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════


@app.route("/api/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    scanner = SecurityScanner(config)
    nmap_ok, deps = scanner.check_dependencies()

    return jsonify({
        "status": "healthy" if nmap_ok else "degraded",
        "timestamp": datetime.now().isoformat(),
        "dependencies": {
            "nmap": nmap_ok,
            "httpx": deps.get("httpx", False),
            "redis": redis_client is not None
        },
        "executor": EXECUTOR_TYPE,
        "max_parallel_scans": MAX_PARALLEL_SCANS,
        "completed_scans": len(scan_results),
        "redis_enabled": redis_client is not None
    })


@app.route("/api/scan/profiles", methods=["GET"])
def list_profiles():
    """List available scan profiles"""
    return jsonify({
        "profiles": SCAN_PROFILES
    })


@app.route("/api/scan", methods=["POST"])
def start_scan():
    """
    Single scan - returns result in same response
    
    Body: {"target": "192.168.1.1", "scan_type": "default"}
    """
    data = request.get_json() or {}

    target = data.get("target") or request.args.get("target")
    if not target:
        return jsonify({"error": "Missing 'target' parameter"}), 400

    target = target.strip()
    if not target:
        return jsonify({"error": "Empty target"}), 400

    scan_type = data.get("scan_type", "default")

    if scan_type not in SCAN_PROFILES:
        return jsonify({
            "error": f"Invalid scan_type: {scan_type}",
            "valid_types": list(SCAN_PROFILES.keys())
        }), 400

    scan_id = str(uuid.uuid4())[:8]
    result = scan_single_target(target, scan_id, scan_type)

    if redis_client:
        redis_store_result(scan_id, result)
    with results_lock:
        scan_results[scan_id] = result

    status_code = 200 if result.get("status") == "completed" else 500
    return jsonify(result), status_code


@app.route("/api/scan/bulk", methods=["POST"])
def bulk_scan():
    """
    Bulk scan - returns ALL results in same response
    
    Body: {"targets": ["1.1.1.1", "8.8.8.8"], "scan_type": "default"}
    """
    data = request.get_json() or {}
    targets = data.get("targets", [])
    scan_type = data.get("scan_type", "default")

    if not targets:
        return jsonify({"error": "Missing 'targets' array"}), 400

    limit_error = check_targets_limit(targets)
    if limit_error:
        return limit_error

    if scan_type not in SCAN_PROFILES:
        return jsonify({
            "error": f"Invalid scan_type: {scan_type}",
            "valid_types": list(SCAN_PROFILES.keys())
        }), 400

    # Run ALL scans and WAIT for completion
    start_time = datetime.now()
    results = run_parallel_scans(targets, scan_type)
    duration = (datetime.now() - start_time).total_seconds()

    completed = len([r for r in results if r.get("status") == "completed"])
    failed = len([r for r in results if r.get("status") == "failed"])
    blocked = len([r for r in results if r.get("status") == "blocked"])

    return jsonify({
        "message": f"Bulk scan completed: {completed} successful, {failed} failed, {blocked} blocked",
        "total_targets": len(targets),
        "scan_type": scan_type,
        "completed": completed,
        "failed": failed,
        "blocked": blocked,
        "duration_seconds": round(duration, 2),
        "executor": EXECUTOR_TYPE,
        "results": results
    }), 200


@app.route("/api/scan/parallel", methods=["POST"])
def parallel_scan():
    """Alias for bulk_scan"""
    return bulk_scan()


@app.route("/api/scan/<scan_id>", methods=["GET"])
def get_scan(scan_id: str):
    """Get historical scan by ID"""
    if redis_client:
        result = redis_get_result(scan_id)
        if result:
            return jsonify(result), 200

    with results_lock:
        if scan_id in scan_results:
            return jsonify(scan_results[scan_id]), 200

    return jsonify({"error": "Scan not found"}), 404


@app.route("/api/scans", methods=["GET"])
def list_scans():
    """List all historical scans"""
    status_filter = request.args.get("status")
    limit = int(request.args.get("limit", 100))

    with results_lock:
        all_scans = list(scan_results.values())

    if status_filter:
        all_scans = [s for s in all_scans if s.get("status") == status_filter]

    all_scans.sort(key=lambda x: x.get("started_at", ""), reverse=True)
    all_scans = all_scans[:limit]

    return jsonify({
        "total": len(scan_results),
        "completed": len([s for s in scan_results.values() if s.get("status") == "completed"]),
        "failed": len([s for s in scan_results.values() if s.get("status") == "failed"]),
        "scans": all_scans
    })


@app.route("/api/scan/status", methods=["GET"])
def scan_status():
    """Check multiple scan IDs (historical)"""
    ids = request.args.get("ids", "").split(",")
    ids = [i.strip() for i in ids if i.strip()]

    if not ids:
        return jsonify({"error": "Missing 'ids' parameter"}), 400

    statuses = []
    with results_lock:
        for scan_id in ids:
            if redis_client:
                result = redis_get_result(scan_id)
                if result:
                    statuses.append(result)
                    continue
            if scan_id in scan_results:
                statuses.append(scan_results[scan_id])
            else:
                statuses.append({"id": scan_id, "status": "not_found"})

    return jsonify({
        "total": len(ids),
        "completed": len([s for s in statuses if s.get("status") == "completed"]),
        "failed": len([s for s in statuses if s.get("status") == "failed"]),
        "statuses": statuses
    })


@app.route("/api/client/info", methods=["GET"])
def client_info():
    """Get rate limit info"""
    client_id = get_client_id()

    with rate_limit_lock:
        recent_requests = len([
            t for t in client_requests.get(client_id, [])
            if time() - t < RATE_WINDOW
        ])

    return jsonify({
        "client_id": client_id,
        "rate_limit": {
            "max_requests": RATE_LIMIT_DEFAULT,
            "window_seconds": RATE_WINDOW,
            "current_usage": recent_requests
        },
        "max_targets_per_bulk": 200
    })

# ═══════════════════════════════════════════════════════════════════════════════
# ERROR HANDLERS
# ═══════════════════════════════════════════════════════════════════════════════


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(429)
def rate_limited(e):
    return jsonify({"error": "Rate limit exceeded"}), 429


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error", "details": str(e)}), 500

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Security Scanner API Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Port (default: 5000)")
    parser.add_argument("--debug", action="store_true", help="Debug mode")

    args = parser.parse_args()

    print()
    print("═" * 70)
    print("  SECURITY SCANNER API SERVER - Synchronous Edition")
    print("═" * 70)
    print(f"  Host:              {args.host}")
    print(f"  Port:              {args.port}")
    print(f"  Executor:          {EXECUTOR_TYPE} (max {MAX_PARALLEL_SCANS} workers)")
    print(f"  Redis:             {'✓ Connected' if redis_client else '✗ Disabled'}")
    print(f"  Rate Limit:        {RATE_LIMIT_DEFAULT} scans / {RATE_WINDOW}s")
    print("═" * 70)
    print()
    print("Scan Profiles:")
    for name, profile in SCAN_PROFILES.items():
        print(f"  • {name:15} - {profile.get('description', 'No description')}")
    print()
    print("Endpoints:")
    print("  POST /api/scan              - Single scan (sync)")
    print("  POST /api/scan/bulk         - Bulk scan (sync, all results)")
    print("  POST /api/scan/parallel     - Alias for bulk")
    print("  GET  /api/scan/<id>         - Historical lookup")
    print("  GET  /api/scans             - List all scans")
    print("  GET  /api/scan/profiles     - List profiles")
    print("  GET  /api/health            - Health check")
    print()
    print("Examples:")
    print()
    print("  # Single scan")
    print(f'  curl -X POST http://{args.host}:{args.port}/api/scan \\')
    print('       -H "Content-Type: application/json" \\')
    print('       -d \'{"target": "192.168.1.1"}\'')
    print()
    print("  # Bulk scan (waits for ALL results)")
    print(f'  curl -X POST http://{args.host}:{args.port}/api/scan/bulk \\')
    print('       -H "Content-Type: application/json" \\')
    print('       -d \'{"targets": ["1.1.1.1", "8.8.8.8"]}\'')
    print()

    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)
