#!/usr/bin/env python3
"""
Security Scanner API Server - Production Edition
Enterprise-grade REST API with parallel processing, rate limiting, and Redis queue

Features:
  - ProcessPoolExecutor for CPU-efficient parallel scanning
  - Per-client rate limiting (IP/API key)
  - Redis-backed job queue (optional)
  - Scan type profiles (default, tcp_full, udp_common, etc.)
  - Client access policies

Usage:
  python3 api_server.py                    # Start server on port 5000
  python3 api_server.py --port 8080        # Custom port
  python3 api_server.py --host 0.0.0.0     # Listen on all interfaces
  USE_REDIS=true python3 api_server.py     # Enable Redis queue

API Endpoints:
  POST /api/scan              - Single scan (sync/async)
  GET  /api/scan/<id>         - Get scan result by ID
  GET  /api/scans             - List all scans
  POST /api/scan/bulk         - Bulk scan (async, up to 200)
  POST /api/scan/parallel     - Parallel scan (sync, wait for results)
  GET  /api/scan/status       - Check multiple scan statuses
  GET  /api/scan/profiles     - List available scan profiles
  GET  /api/health            - Health check
"""

import os
import sys
import json
import uuid
import threading
from time import time
from datetime import datetime
from functools import wraps
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify

# Import scanner components
from scanner_api import SecurityScanner, ScanResult, SCAN_PROFILES
from config import ScannerConfig, CLIENT_POLICIES

# ═══════════════════════════════════════════════════════════════════════════════
# OPTIONAL: Redis Import
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

# Load scanner config
config = ScannerConfig.from_env()

# In-memory storage for scan results (Redis used when available/enabled)
scan_results = {}
scan_queue = {}

# Thread-safe locks
results_lock = threading.Lock()
rate_limit_lock = threading.Lock()

# API Key for authentication (optional)
API_KEY = os.environ.get("SCANNER_API_KEY", None)

# Maximum parallel scans (reduced for ProcessPool efficiency)
MAX_PARALLEL_SCANS = int(os.environ.get("MAX_PARALLEL_SCANS", 50))

# Redis configuration
USE_REDIS = os.environ.get("USE_REDIS", "false").lower() == "true"
REDIS_HOST = os.environ.get("REDIS_HOST", config.redis_host)
REDIS_PORT = int(os.environ.get("REDIS_PORT", config.redis_port))
REDIS_DB = int(os.environ.get("REDIS_DB", config.redis_db))
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD", config.redis_password)

# Initialize Redis client if available and enabled
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
        redis_client.ping()  # Test connection
        print(f"✓ Redis connected: {REDIS_HOST}:{REDIS_PORT}")
    except Exception as e:
        print(f"⚠ Redis connection failed: {e}")
        redis_client = None

# ═══════════════════════════════════════════════════════════════════════════════
# EXECUTOR - ProcessPoolExecutor for CPU-heavy Nmap scans
# ═══════════════════════════════════════════════════════════════════════════════

# Use ProcessPoolExecutor for better CPU utilization with Nmap
# ThreadPoolExecutor as fallback for systems where multiprocessing is problematic
USE_PROCESS_POOL = os.environ.get("USE_PROCESS_POOL", "true").lower() == "true"

if USE_PROCESS_POOL:
    # ProcessPoolExecutor: Better for CPU-bound tasks like Nmap
    # Note: max_workers reduced to 50 for stability (vs 200 threads)
    executor = ProcessPoolExecutor(max_workers=min(MAX_PARALLEL_SCANS, 50))
    EXECUTOR_TYPE = "ProcessPool"
else:
    # ThreadPoolExecutor: Fallback option
    executor = ThreadPoolExecutor(max_workers=MAX_PARALLEL_SCANS)
    EXECUTOR_TYPE = "ThreadPool"

# ═══════════════════════════════════════════════════════════════════════════════
# RATE LIMITING - Per Client (IP / API Key)
# ═══════════════════════════════════════════════════════════════════════════════

# In-memory rate limit tracking
client_requests: Dict[str, List[float]] = defaultdict(list)

RATE_LIMIT_DEFAULT = config.rate_limit_scans  # scans per window
RATE_WINDOW = config.rate_limit_window  # seconds


def get_client_id() -> str:
    """Get unique client identifier from API key or IP address"""
    return request.headers.get("X-API-Key") or request.remote_addr


def get_client_policy(client_id: str) -> Dict:
    """Get client policy based on client ID or API key"""
    # Check if client ID matches a known policy
    # In production, this would query a database
    api_key = request.headers.get("X-API-Key", "")
    
    # Map API keys to policies (in production: use database)
    key_policy_map = {
        os.environ.get("ADMIN_API_KEY", ""): "admin",
        os.environ.get("PREMIUM_API_KEY", ""): "premium",
        os.environ.get("STANDARD_API_KEY", ""): "standard",
    }
    
    policy_name = key_policy_map.get(api_key, "default")
    return CLIENT_POLICIES.get(policy_name, CLIENT_POLICIES["default"])


def check_rate_limit() -> Optional[tuple]:
    """
    Check if client has exceeded rate limit.
    Returns error response tuple if exceeded, None if OK.
    """
    client_id = get_client_id()
    policy = get_client_policy(client_id)
    rate_limit = policy.get("rate_limit", RATE_LIMIT_DEFAULT)
    
    now = time()
    
    with rate_limit_lock:
        # Clean old entries outside the window
        client_requests[client_id] = [
            t for t in client_requests[client_id]
            if now - t < RATE_WINDOW
        ]
        
        # Check if limit exceeded
        if len(client_requests[client_id]) >= rate_limit:
            return jsonify({
                "error": "Rate limit exceeded",
                "limit": rate_limit,
                "window_seconds": RATE_WINDOW,
                "retry_after": int(RATE_WINDOW - (now - client_requests[client_id][0]))
            }), 429
        
        # Record this request
        client_requests[client_id].append(now)
    
    return None


def check_scan_policy(scan_type: str) -> Optional[tuple]:
    """
    Check if client is allowed to perform the requested scan type.
    Returns error response tuple if not allowed, None if OK.
    """
    client_id = get_client_id()
    policy = get_client_policy(client_id)
    allowed_scans = policy.get("allowed_scans", ["default"])
    
    if scan_type not in allowed_scans:
        return jsonify({
            "error": f"Scan type '{scan_type}' not allowed for your access level",
            "allowed_scans": allowed_scans,
            "policy": policy.get("name", "unknown")
        }), 403
    
    return None


def check_targets_limit(targets: List[str]) -> Optional[tuple]:
    """Check if number of targets exceeds client limit"""
    client_id = get_client_id()
    policy = get_client_policy(client_id)
    max_targets = policy.get("max_targets", 50)
    
    if len(targets) > max_targets:
        return jsonify({
            "error": f"Too many targets. Maximum {max_targets} allowed for your access level.",
            "requested": len(targets),
            "max_allowed": max_targets,
            "policy": policy.get("name", "unknown")
        }), 400
    
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# AUTHENTICATION
# ═══════════════════════════════════════════════════════════════════════════════

def require_api_key(f):
    """Decorator to require API key if configured"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if API_KEY:
            provided_key = request.headers.get("X-API-Key") or request.args.get("api_key")
            if provided_key != API_KEY:
                return jsonify({"error": "Invalid or missing API key"}), 401
        return f(*args, **kwargs)
    return decorated


# ═══════════════════════════════════════════════════════════════════════════════
# REDIS QUEUE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def redis_enqueue(scan_id: str, target: str, scan_type: str, client_id: str):
    """Enqueue scan job to Redis"""
    if not redis_client:
        return False
    
    job = {
        "id": scan_id,
        "target": target,
        "scan_type": scan_type,
        "client": client_id,
        "enqueued_at": datetime.now().isoformat()
    }
    
    redis_client.lpush("scan:queue", json.dumps(job))
    redis_client.set(f"scan:status:{scan_id}", "pending")
    return True


def redis_get_result(scan_id: str) -> Optional[Dict]:
    """Get scan result from Redis"""
    if not redis_client:
        return None
    
    result = redis_client.get(f"scan:result:{scan_id}")
    if result:
        return json.loads(result)
    return None


def redis_get_status(scan_id: str) -> Optional[str]:
    """Get scan status from Redis"""
    if not redis_client:
        return None
    return redis_client.get(f"scan:status:{scan_id}")


def redis_store_result(scan_id: str, result: Dict):
    """Store scan result in Redis"""
    if not redis_client:
        return False
    
    redis_client.set(f"scan:result:{scan_id}", json.dumps(result))
    redis_client.set(f"scan:status:{scan_id}", "completed")
    # Expire results after 24 hours
    redis_client.expire(f"scan:result:{scan_id}", 86400)
    redis_client.expire(f"scan:status:{scan_id}", 86400)
    return True


# ═══════════════════════════════════════════════════════════════════════════════
# SCANNER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def scan_single_target(target: str, scan_id: str, scan_type: str = "default") -> Dict[str, Any]:
    """
    Scan a single target and return result dict.
    This function is designed to run in a separate process.
    """
    started_at = datetime.now().isoformat()
    
    try:
        # Create new scanner instance (required for ProcessPool)
        scanner_config = ScannerConfig.from_env()
        scanner = SecurityScanner(scanner_config)
        result = scanner.scan(target, scan_type=scan_type)
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


def run_scan_background(scan_id: str, target: str, scan_type: str = "default"):
    """Run scan in background and store result"""
    result = scan_single_target(target, scan_id, scan_type)
    
    # Store in Redis if available
    if redis_client:
        redis_store_result(scan_id, result)
    
    # Also store in memory
    with results_lock:
        scan_results[scan_id] = result
        if scan_id in scan_queue:
            del scan_queue[scan_id]


def run_parallel_scans(targets: List[str], scan_type: str = "default") -> List[Dict[str, Any]]:
    """
    Run multiple scans in parallel using ProcessPoolExecutor.
    Returns list of scan results.
    """
    results = []
    futures = {}
    
    for target in targets:
        target = str(target).strip()
        if not target:
            continue
        
        scan_id = str(uuid.uuid4())[:8]
        future = executor.submit(scan_single_target, target, scan_id, scan_type)
        futures[future] = {"id": scan_id, "target": target}
    
    # Collect results as they complete
    for future in as_completed(futures):
        try:
            result = future.result(timeout=600)  # 10 min timeout per scan
            results.append(result)
            
            # Store results
            if redis_client:
                redis_store_result(result["id"], result)
            
            with results_lock:
                scan_results[result["id"]] = result
        except Exception as e:
            info = futures[future]
            error_result = {
                "id": info["id"],
                "target": info["target"],
                "scan_type": scan_type,
                "status": "failed",
                "error": str(e)
            }
            results.append(error_result)
    
    return results


# ═══════════════════════════════════════════════════════════════════════════════
# API ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.before_request
def before_request():
    """Apply rate limiting to scan endpoints"""
    if request.path.startswith("/api/scan") and request.method == "POST":
        rate_error = check_rate_limit()
        if rate_error:
            return rate_error


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
        "pending_scans": len(scan_queue),
        "completed_scans": len(scan_results),
        "redis_enabled": redis_client is not None
    })


@app.route("/api/scan/profiles", methods=["GET"])
def list_profiles():
    """List available scan profiles"""
    client_id = get_client_id()
    policy = get_client_policy(client_id)
    allowed_scans = policy.get("allowed_scans", ["default"])
    
    profiles = {}
    for name, profile in SCAN_PROFILES.items():
        profiles[name] = {
            **profile,
            "allowed": name in allowed_scans
        }
    
    return jsonify({
        "profiles": profiles,
        "client_policy": policy.get("name", "default"),
        "allowed_scans": allowed_scans
    })


@app.route("/api/scan", methods=["POST"])
@require_api_key
def start_scan():
    """
    Start a new scan
    
    Request body:
    {
        "target": "192.168.1.1",      # Required: IP or domain
        "scan_type": "default",        # Optional: Scan profile
        "async": false                 # Optional: Run async (default: false)
    }
    """
    data = request.get_json() or {}
    
    target = data.get("target") or request.args.get("target")
    if not target:
        return jsonify({"error": "Missing 'target' parameter"}), 400
    
    target = target.strip()
    if not target:
        return jsonify({"error": "Empty target"}), 400
    
    scan_type = data.get("scan_type", "default")
    
    # Validate scan type
    if scan_type not in SCAN_PROFILES:
        return jsonify({
            "error": f"Invalid scan_type: {scan_type}",
            "valid_types": list(SCAN_PROFILES.keys())
        }), 400
    
    # Check policy
    policy_error = check_scan_policy(scan_type)
    if policy_error:
        return policy_error
    
    run_async = data.get("async", False)
    scan_id = str(uuid.uuid4())[:8]
    started_at = datetime.now().isoformat()
    
    # Synchronous mode (default)
    if not run_async:
        result = scan_single_target(target, scan_id, scan_type)
        
        # Store result
        if redis_client:
            redis_store_result(scan_id, result)
        with results_lock:
            scan_results[scan_id] = result
        
        return jsonify(result), 200 if result["status"] == "completed" else 500
    
    # Async mode
    with results_lock:
        scan_queue[scan_id] = {
            "id": scan_id,
            "target": target,
            "scan_type": scan_type,
            "status": "pending",
            "started_at": started_at
        }
    
    # Use Redis queue if available
    if redis_client:
        redis_enqueue(scan_id, target, scan_type, get_client_id())
    
    executor.submit(run_scan_background, scan_id, target, scan_type)
    
    return jsonify({
        "id": scan_id,
        "target": target,
        "scan_type": scan_type,
        "status": "pending",
        "message": "Scan started. Use /api/scan/{id} to get results.",
        "check_status": f"/api/scan/{scan_id}"
    }), 202


@app.route("/api/scan/<scan_id>", methods=["GET"])
@require_api_key
def get_scan(scan_id: str):
    """Get scan result by ID"""
    # Check Redis first
    if redis_client:
        result = redis_get_result(scan_id)
        if result:
            return jsonify(result), 200
        
        status = redis_get_status(scan_id)
        if status == "pending" or status == "running":
            return jsonify({
                "id": scan_id,
                "status": status,
                "message": "Scan is still in progress"
            }), 202
    
    # Check memory
    with results_lock:
        if scan_id in scan_results:
            return jsonify(scan_results[scan_id]), 200
        
        if scan_id in scan_queue:
            return jsonify({
                **scan_queue[scan_id],
                "status": "running",
                "message": "Scan is still in progress"
            }), 202
    
    return jsonify({"error": "Scan not found"}), 404


@app.route("/api/scans", methods=["GET"])
@require_api_key
def list_scans():
    """List all scans"""
    status_filter = request.args.get("status")
    limit = int(request.args.get("limit", 100))
    
    with results_lock:
        all_scans = []
        
        for scan_id, scan in scan_queue.items():
            all_scans.append({**scan, "status": "running"})
        
        for scan_id, scan in scan_results.items():
            all_scans.append(scan)
    
    if status_filter:
        all_scans = [s for s in all_scans if s.get("status") == status_filter]
    
    all_scans.sort(key=lambda x: x.get("started_at", ""), reverse=True)
    all_scans = all_scans[:limit]
    
    return jsonify({
        "total": len(scan_results) + len(scan_queue),
        "pending": len(scan_queue),
        "completed": len([s for s in scan_results.values() if s.get("status") == "completed"]),
        "failed": len([s for s in scan_results.values() if s.get("status") == "failed"]),
        "scans": all_scans
    })


@app.route("/api/scan/bulk", methods=["POST"])
@require_api_key
def bulk_scan():
    """
    Start multiple scans in background (async)
    
    Request body:
    {
        "targets": ["192.168.1.1", "example.com", ...],
        "scan_type": "default"  # Optional
    }
    
    Response: Returns immediately with scan IDs
    """
    data = request.get_json() or {}
    targets = data.get("targets", [])
    scan_type = data.get("scan_type", "default")
    
    if not targets:
        return jsonify({"error": "Missing 'targets' array"}), 400
    
    # Check targets limit
    limit_error = check_targets_limit(targets)
    if limit_error:
        return limit_error
    
    # Check policy
    policy_error = check_scan_policy(scan_type)
    if policy_error:
        return policy_error
    
    started_scans = []
    client_id = get_client_id()
    
    for target in targets:
        target = str(target).strip()
        if not target:
            continue
        
        scan_id = str(uuid.uuid4())[:8]
        started_at = datetime.now().isoformat()
        
        with results_lock:
            scan_queue[scan_id] = {
                "id": scan_id,
                "target": target,
                "scan_type": scan_type,
                "status": "pending",
                "started_at": started_at
            }
        
        # Use Redis queue if available
        if redis_client:
            redis_enqueue(scan_id, target, scan_type, client_id)
        
        executor.submit(run_scan_background, scan_id, target, scan_type)
        
        started_scans.append({
            "id": scan_id,
            "target": target,
            "scan_type": scan_type,
            "status": "pending"
        })
    
    return jsonify({
        "message": f"{len(started_scans)} scans started (parallel processing)",
        "executor": EXECUTOR_TYPE,
        "max_parallel": MAX_PARALLEL_SCANS,
        "scans": started_scans
    }), 202


@app.route("/api/scan/parallel", methods=["POST"])
@require_api_key
def parallel_scan():
    """
    Run parallel scans and WAIT for all results (synchronous bulk)
    
    Request body:
    {
        "targets": ["192.168.1.1", "example.com", ...],
        "scan_type": "default"  # Optional
    }
    
    Response: Returns when ALL scans complete with full results
    
    ⚠️ WARNING: This endpoint blocks until all scans finish.
    For large batches, use /api/scan/bulk instead.
    """
    data = request.get_json() or {}
    targets = data.get("targets", [])
    scan_type = data.get("scan_type", "default")
    
    if not targets:
        return jsonify({"error": "Missing 'targets' array"}), 400
    
    # Check targets limit
    limit_error = check_targets_limit(targets)
    if limit_error:
        return limit_error
    
    # Check policy
    policy_error = check_scan_policy(scan_type)
    if policy_error:
        return policy_error
    
    # Run all scans in parallel and wait for results
    start_time = datetime.now()
    results = run_parallel_scans(targets, scan_type)
    duration = (datetime.now() - start_time).total_seconds()
    
    completed = len([r for r in results if r.get("status") == "completed"])
    failed = len([r for r in results if r.get("status") == "failed"])
    blocked = len([r for r in results if r.get("status") == "blocked"])
    
    return jsonify({
        "message": f"Parallel scan completed: {completed} successful, {failed} failed, {blocked} blocked",
        "total_targets": len(targets),
        "scan_type": scan_type,
        "completed": completed,
        "failed": failed,
        "blocked": blocked,
        "duration_seconds": round(duration, 2),
        "executor": EXECUTOR_TYPE,
        "results": results
    }), 200


@app.route("/api/scan/status", methods=["GET"])
@require_api_key
def scan_status():
    """Get status of multiple scans by IDs"""
    ids = request.args.get("ids", "").split(",")
    ids = [i.strip() for i in ids if i.strip()]
    
    if not ids:
        return jsonify({"error": "Missing 'ids' parameter"}), 400
    
    statuses = []
    with results_lock:
        for scan_id in ids:
            # Check Redis first
            if redis_client:
                result = redis_get_result(scan_id)
                if result:
                    statuses.append(result)
                    continue
                status = redis_get_status(scan_id)
                if status:
                    statuses.append({"id": scan_id, "status": status})
                    continue
            
            # Check memory
            if scan_id in scan_results:
                statuses.append(scan_results[scan_id])
            elif scan_id in scan_queue:
                statuses.append({**scan_queue[scan_id], "status": "running"})
            else:
                statuses.append({"id": scan_id, "status": "not_found"})
    
    return jsonify({
        "total": len(ids),
        "completed": len([s for s in statuses if s.get("status") == "completed"]),
        "running": len([s for s in statuses if s.get("status") in ["pending", "running"]]),
        "failed": len([s for s in statuses if s.get("status") == "failed"]),
        "statuses": statuses
    })


@app.route("/api/client/info", methods=["GET"])
@require_api_key
def client_info():
    """Get current client's policy and rate limit info"""
    client_id = get_client_id()
    policy = get_client_policy(client_id)
    
    with rate_limit_lock:
        recent_requests = len([
            t for t in client_requests.get(client_id, [])
            if time() - t < RATE_WINDOW
        ])
    
    return jsonify({
        "client_id": client_id[:8] + "..." if len(client_id) > 8 else client_id,
        "policy": policy.get("name", "default"),
        "allowed_scans": policy.get("allowed_scans", []),
        "rate_limit": {
            "max_requests": policy.get("rate_limit", RATE_LIMIT_DEFAULT),
            "window_seconds": RATE_WINDOW,
            "current_usage": recent_requests
        },
        "max_targets_per_bulk": policy.get("max_targets", 50)
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
    
    parser = argparse.ArgumentParser(description="Security Scanner API Server - Production Edition")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind (default: 5000)")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    
    args = parser.parse_args()
    
    print()
    print("═" * 70)
    print("  SECURITY SCANNER API SERVER - Production Edition")
    print("═" * 70)
    print(f"  Host:              {args.host}")
    print(f"  Port:              {args.port}")
    print(f"  Executor:          {EXECUTOR_TYPE} (max {MAX_PARALLEL_SCANS} workers)")
    print(f"  Redis:             {'✓ Connected' if redis_client else '✗ Disabled'}")
    print(f"  API Key:           {'✓ Required' if API_KEY else '✗ Disabled'}")
    print(f"  Rate Limit:        {RATE_LIMIT_DEFAULT} scans / {RATE_WINDOW}s")
    print("═" * 70)
    print()
    print("Scan Profiles Available:")
    for name, profile in SCAN_PROFILES.items():
        print(f"  • {name:15} - {profile.get('description', 'No description')}")
    print()
    print("Endpoints:")
    print("  POST /api/scan              - Single scan (sync/async)")
    print("  GET  /api/scan/<id>         - Get scan result")
    print("  GET  /api/scans             - List all scans")
    print("  POST /api/scan/bulk         - Bulk scan (async)")
    print("  POST /api/scan/parallel     - Parallel scan (sync, wait)")
    print("  GET  /api/scan/status       - Check scan statuses")
    print("  GET  /api/scan/profiles     - List scan profiles")
    print("  GET  /api/client/info       - Get client policy info")
    print("  GET  /api/health            - Health check")
    print()
    print("Examples:")
    print()
    print("  # Single scan (default profile)")
    print(f'  curl -X POST http://{args.host}:{args.port}/api/scan \\')
    print('       -H "Content-Type: application/json" \\')
    print('       -d \'{"target": "192.168.1.1"}\'')
    print()
    print("  # Full TCP scan")
    print(f'  curl -X POST http://{args.host}:{args.port}/api/scan \\')
    print('       -H "Content-Type: application/json" \\')
    print('       -d \'{"target": "192.168.1.1", "scan_type": "tcp_full"}\'')
    print()
    print("  # Bulk scan (50 IPs parallel)")
    print(f'  curl -X POST http://{args.host}:{args.port}/api/scan/bulk \\')
    print('       -H "Content-Type: application/json" \\')
    print('       -d \'{"targets": ["1.1.1.1", "8.8.8.8", ...], "scan_type": "quick"}\'')
    print()
    
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)
