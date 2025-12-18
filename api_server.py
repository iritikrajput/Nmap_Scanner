#!/usr/bin/env python3
"""
Security Scanner API Server
REST API for triggering scans via HTTP requests

Features:
  - Parallel scanning up to 200 concurrent scans
  - Async and sync modes
  - Bulk scan endpoint

Usage:
  python3 api_server.py                    # Start server on port 5000
  python3 api_server.py --port 8080        # Custom port
  python3 api_server.py --host 0.0.0.0     # Listen on all interfaces

API Endpoints:
  POST /api/scan          - Start a new scan
  GET  /api/scan/<id>     - Get scan result by ID
  GET  /api/scans         - List all scans
  POST /api/scan/bulk     - Bulk scan (up to 200 parallel)
  POST /api/scan/parallel - Parallel scan with results
  GET  /api/health        - Health check
"""

import os
import sys
import json
import uuid
import threading
from datetime import datetime
from functools import wraps
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify
from scanner_api import SecurityScanner, ScanResult
from config import ScannerConfig

app = Flask(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# Load scanner config
config = ScannerConfig.from_env()

# In-memory storage for scan results (use Redis/DB in production)
scan_results = {}
scan_queue = {}

# Thread-safe lock for results
results_lock = threading.Lock()

# API Key for authentication (optional)
API_KEY = os.environ.get("SCANNER_API_KEY", None)

# Maximum parallel scans
MAX_PARALLEL_SCANS = int(os.environ.get("MAX_PARALLEL_SCANS", 200))

# Global thread pool for parallel scanning
executor = ThreadPoolExecutor(max_workers=MAX_PARALLEL_SCANS)

# ═══════════════════════════════════════════════════════════════════════════════
# AUTHENTICATION (Optional)
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
# SCANNER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def scan_single_target(target: str, scan_id: str) -> Dict[str, Any]:
    """Scan a single target and return result dict"""
    started_at = datetime.now().isoformat()
    
    try:
        scanner = SecurityScanner(config)
        result = scanner.scan(target)
        result_dict = result.to_dict()
        
        return {
            "id": scan_id,
            "target": target,
            "status": "completed",
            "started_at": started_at,
            "completed_at": datetime.now().isoformat(),
            **result_dict
        }
    except Exception as e:
        return {
            "id": scan_id,
            "target": target,
            "status": "failed",
            "started_at": started_at,
            "completed_at": datetime.now().isoformat(),
            "error": str(e)
        }


def run_scan_background(scan_id: str, target: str):
    """Run scan in background thread and store result"""
    result = scan_single_target(target, scan_id)
    
    with results_lock:
        scan_results[scan_id] = result
        if scan_id in scan_queue:
            del scan_queue[scan_id]


def run_parallel_scans(targets: List[str]) -> List[Dict[str, Any]]:
    """
    Run multiple scans in parallel using ThreadPoolExecutor.
    Returns list of scan results.
    """
    results = []
    futures = {}
    
    for target in targets:
        target = str(target).strip()
        if not target:
            continue
        
        scan_id = str(uuid.uuid4())[:8]
        future = executor.submit(scan_single_target, target, scan_id)
        futures[future] = {"id": scan_id, "target": target}
    
    # Collect results as they complete
    for future in as_completed(futures):
        try:
            result = future.result(timeout=600)  # 10 min timeout per scan
            results.append(result)
            
            # Store in global results
            with results_lock:
                scan_results[result["id"]] = result
        except Exception as e:
            info = futures[future]
            results.append({
                "id": info["id"],
                "target": info["target"],
                "status": "failed",
                "error": str(e)
            })
    
    return results


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
            "httpx": deps.get("httpx", False)
        },
        "max_parallel_scans": MAX_PARALLEL_SCANS,
        "pending_scans": len(scan_queue),
        "completed_scans": len(scan_results),
        "executor_threads": executor._max_workers
    })


@app.route("/api/scan", methods=["POST"])
@require_api_key
def start_scan():
    """
    Start a new scan
    
    Request body:
    {
        "target": "192.168.1.1",      # Required: IP or domain
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
    
    run_async = data.get("async", False)
    scan_id = str(uuid.uuid4())[:8]
    started_at = datetime.now().isoformat()
    
    # Synchronous mode (default)
    if not run_async:
        result = scan_single_target(target, scan_id)
        with results_lock:
            scan_results[scan_id] = result
        return jsonify(result), 200 if result["status"] == "completed" else 500
    
    # Async mode
    with results_lock:
        scan_queue[scan_id] = {
            "id": scan_id,
            "target": target,
            "status": "pending",
            "started_at": started_at
        }
    
    executor.submit(run_scan_background, scan_id, target)
    
    return jsonify({
        "id": scan_id,
        "target": target,
        "status": "pending",
        "message": "Scan started in background. Use /api/scan/{id} to get results.",
        "check_status": f"/api/scan/{scan_id}"
    }), 202


@app.route("/api/scan/<scan_id>", methods=["GET"])
@require_api_key
def get_scan(scan_id: str):
    """Get scan result by ID"""
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
        "targets": ["192.168.1.1", "example.com", ...]  # Up to 200 targets
    }
    
    Response: Returns immediately with scan IDs
    """
    data = request.get_json() or {}
    targets = data.get("targets", [])
    
    if not targets:
        return jsonify({"error": "Missing 'targets' array"}), 400
    
    if len(targets) > MAX_PARALLEL_SCANS:
        return jsonify({"error": f"Maximum {MAX_PARALLEL_SCANS} targets per request"}), 400
    
    started_scans = []
    
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
                "status": "pending",
                "started_at": started_at
            }
        
        executor.submit(run_scan_background, scan_id, target)
        
        started_scans.append({
            "id": scan_id,
            "target": target,
            "status": "pending"
        })
    
    return jsonify({
        "message": f"{len(started_scans)} scans started (parallel processing)",
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
        "targets": ["192.168.1.1", "example.com", ...]  # Up to 200 targets
    }
    
    Response: Returns when ALL scans complete with full results
    
    ⚠️ WARNING: This endpoint blocks until all scans finish.
    For large batches, use /api/scan/bulk instead.
    """
    data = request.get_json() or {}
    targets = data.get("targets", [])
    
    if not targets:
        return jsonify({"error": "Missing 'targets' array"}), 400
    
    if len(targets) > MAX_PARALLEL_SCANS:
        return jsonify({"error": f"Maximum {MAX_PARALLEL_SCANS} targets per request"}), 400
    
    # Run all scans in parallel and wait for results
    start_time = datetime.now()
    results = run_parallel_scans(targets)
    duration = (datetime.now() - start_time).total_seconds()
    
    completed = len([r for r in results if r.get("status") == "completed"])
    failed = len([r for r in results if r.get("status") == "failed"])
    
    return jsonify({
        "message": f"Parallel scan completed: {completed} successful, {failed} failed",
        "total_targets": len(targets),
        "completed": completed,
        "failed": failed,
        "duration_seconds": round(duration, 2),
        "results": results
    }), 200


@app.route("/api/scan/status", methods=["GET"])
@require_api_key
def scan_status():
    """Get status of all scans by IDs"""
    ids = request.args.get("ids", "").split(",")
    ids = [i.strip() for i in ids if i.strip()]
    
    if not ids:
        return jsonify({"error": "Missing 'ids' parameter"}), 400
    
    statuses = []
    with results_lock:
        for scan_id in ids:
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


# ═══════════════════════════════════════════════════════════════════════════════
# ERROR HANDLERS
# ═══════════════════════════════════════════════════════════════════════════════

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error"}), 500

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Security Scanner API Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind (default: 5000)")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    
    args = parser.parse_args()
    
    print("=" * 70)
    print("  SECURITY SCANNER API SERVER - Parallel Processing Edition")
    print("=" * 70)
    print(f"  Host:              {args.host}")
    print(f"  Port:              {args.port}")
    print(f"  Max Parallel:      {MAX_PARALLEL_SCANS} scans")
    print(f"  API Key:           {'Enabled' if API_KEY else 'Disabled'}")
    print("=" * 70)
    print()
    print("Endpoints:")
    print("  POST /api/scan          - Single scan (sync/async)")
    print("  GET  /api/scan/<id>     - Get scan result")
    print("  GET  /api/scans         - List all scans")
    print("  POST /api/scan/bulk     - Bulk scan (async, up to 200)")
    print("  POST /api/scan/parallel - Parallel scan (sync, wait for results)")
    print("  GET  /api/scan/status   - Check multiple scan statuses")
    print("  GET  /api/health        - Health check")
    print()
    print("Examples:")
    print()
    print("  # Single scan")
    print(f'  curl -X POST http://{args.host}:{args.port}/api/scan \\')
    print('       -H "Content-Type: application/json" \\')
    print('       -d \'{"target": "192.168.1.1"}\'')
    print()
    print("  # Bulk scan (200 IPs async)")
    print(f'  curl -X POST http://{args.host}:{args.port}/api/scan/bulk \\')
    print('       -H "Content-Type: application/json" \\')
    print('       -d \'{"targets": ["1.1.1.1", "8.8.8.8", ...]}\'')
    print()
    print("  # Parallel scan (wait for all results)")
    print(f'  curl -X POST http://{args.host}:{args.port}/api/scan/parallel \\')
    print('       -H "Content-Type: application/json" \\')
    print('       -d \'{"targets": ["1.1.1.1", "8.8.8.8", ...]}\'')
    print()
    
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)
