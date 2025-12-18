#!/usr/bin/env python3
"""
Security Scanner API Server
REST API for triggering scans via HTTP requests

Usage:
  python3 api_server.py                    # Start server on port 5000
  python3 api_server.py --port 8080        # Custom port
  python3 api_server.py --host 0.0.0.0     # Listen on all interfaces

API Endpoints:
  POST /api/scan          - Start a new scan
  GET  /api/scan/<id>     - Get scan result by ID
  GET  /api/scans         - List all scans
  GET  /api/health        - Health check
"""

import os
import sys
import json
import uuid
import threading
from datetime import datetime
from functools import wraps

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

# API Key for authentication (optional)
API_KEY = os.environ.get("SCANNER_API_KEY", None)

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
# BACKGROUND SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

def run_scan_background(scan_id: str, target: str):
    """Run scan in background thread"""
    try:
        scanner = SecurityScanner(config)
        result = scanner.scan(target)
        
        scan_results[scan_id] = {
            "id": scan_id,
            "target": target,
            "status": "completed",
            "started_at": scan_queue[scan_id]["started_at"],
            "completed_at": datetime.now().isoformat(),
            "result": result.to_dict()
        }
    except Exception as e:
        scan_results[scan_id] = {
            "id": scan_id,
            "target": target,
            "status": "failed",
            "started_at": scan_queue[scan_id]["started_at"],
            "completed_at": datetime.now().isoformat(),
            "error": str(e)
        }
    finally:
        # Remove from queue
        if scan_id in scan_queue:
            del scan_queue[scan_id]

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
        "pending_scans": len(scan_queue),
        "completed_scans": len(scan_results)
    })


@app.route("/api/scan", methods=["POST"])
@require_api_key
def start_scan():
    """
    Start a new scan
    
    Request body:
    {
        "target": "192.168.1.1",      # Required: IP or domain
        "async": false                 # Optional: Run async (default: false - returns result directly)
    }
    
    Response (sync mode - default):
    Returns complete scan result directly with id included.
    
    Response (async mode):
    {
        "id": "uuid",
        "target": "192.168.1.1",
        "status": "pending",
        "message": "Scan started"
    }
    """
    data = request.get_json() or {}
    
    # Get target
    target = data.get("target") or request.args.get("target")
    if not target:
        return jsonify({"error": "Missing 'target' parameter"}), 400
    
    # Clean target
    target = target.strip()
    if not target:
        return jsonify({"error": "Empty target"}), 400
    
    # Check if async (default: synchronous - returns result directly)
    run_async = data.get("async", False)
    
    # Generate scan ID
    scan_id = str(uuid.uuid4())[:8]
    started_at = datetime.now().isoformat()
    
    # Default: Synchronous mode - return result directly with ID
    if not run_async:
        try:
            scanner = SecurityScanner(config)
            result = scanner.scan(target)
            result_dict = result.to_dict()
            
            # Include ID in the response for reference
            response = {
                "id": scan_id,
                "target": target,
                "status": "completed",
                "started_at": started_at,
                "completed_at": datetime.now().isoformat(),
                **result_dict  # Spread the result directly (open_ports, security_headers, etc.)
            }
            
            # Also store for later retrieval
            scan_results[scan_id] = response
            
            return jsonify(response), 200
        except Exception as e:
            return jsonify({
                "id": scan_id,
                "target": target,
                "status": "failed",
                "error": str(e)
            }), 500
    
    # Async mode: Return ID and run in background
    else:
        scan_queue[scan_id] = {
            "id": scan_id,
            "target": target,
            "status": "pending",
            "started_at": started_at
        }
        
        thread = threading.Thread(
            target=run_scan_background,
            args=(scan_id, target),
            daemon=True
        )
        thread.start()
        
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
    """
    Get scan result by ID
    
    Response:
    {
        "id": "uuid",
        "target": "192.168.1.1",
        "status": "completed",
        "result": { ... }
    }
    """
    # Check if in results
    if scan_id in scan_results:
        return jsonify(scan_results[scan_id]), 200
    
    # Check if still in queue
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
    """
    List all scans
    
    Query params:
    - status: Filter by status (pending, running, completed, failed)
    - limit: Max results (default: 50)
    
    Response:
    {
        "total": 10,
        "pending": 2,
        "completed": 8,
        "scans": [ ... ]
    }
    """
    status_filter = request.args.get("status")
    limit = int(request.args.get("limit", 50))
    
    # Combine queue and results
    all_scans = []
    
    for scan_id, scan in scan_queue.items():
        all_scans.append({**scan, "status": "running"})
    
    for scan_id, scan in scan_results.items():
        all_scans.append(scan)
    
    # Filter by status
    if status_filter:
        all_scans = [s for s in all_scans if s.get("status") == status_filter]
    
    # Sort by started_at (newest first)
    all_scans.sort(key=lambda x: x.get("started_at", ""), reverse=True)
    
    # Limit
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
    Start multiple scans at once
    
    Request body:
    {
        "targets": ["192.168.1.1", "example.com", "10.0.0.1"]
    }
    
    Response:
    {
        "message": "3 scans started",
        "scans": [
            {"id": "abc123", "target": "192.168.1.1", "status": "pending"},
            ...
        ]
    }
    """
    data = request.get_json() or {}
    targets = data.get("targets", [])
    
    if not targets:
        return jsonify({"error": "Missing 'targets' array"}), 400
    
    if len(targets) > 100:
        return jsonify({"error": "Maximum 100 targets per request"}), 400
    
    started_scans = []
    
    for target in targets:
        target = str(target).strip()
        if not target:
            continue
        
        scan_id = str(uuid.uuid4())[:8]
        started_at = datetime.now().isoformat()
        
        scan_queue[scan_id] = {
            "id": scan_id,
            "target": target,
            "status": "pending",
            "started_at": started_at
        }
        
        thread = threading.Thread(
            target=run_scan_background,
            args=(scan_id, target),
            daemon=True
        )
        thread.start()
        
        started_scans.append({
            "id": scan_id,
            "target": target,
            "status": "pending"
        })
    
    return jsonify({
        "message": f"{len(started_scans)} scans started",
        "scans": started_scans
    }), 202


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
    
    print("=" * 60)
    print("  SECURITY SCANNER API SERVER")
    print("=" * 60)
    print(f"  Host:     {args.host}")
    print(f"  Port:     {args.port}")
    print(f"  API Key:  {'Enabled' if API_KEY else 'Disabled'}")
    print("=" * 60)
    print()
    print("Endpoints:")
    print("  POST /api/scan          - Start a new scan")
    print("  GET  /api/scan/<id>     - Get scan result")
    print("  GET  /api/scans         - List all scans")
    print("  POST /api/scan/bulk     - Bulk scan multiple targets")
    print("  GET  /api/health        - Health check")
    print()
    print("Example:")
    print(f'  curl -X POST http://{args.host}:{args.port}/api/scan \\')
    print('       -H "Content-Type: application/json" \\')
    print('       -d \'{"target": "192.168.1.1"}\'')
    print()
    
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


