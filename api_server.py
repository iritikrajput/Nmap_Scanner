#!/usr/bin/env python3
"""
Security Scanner API Server - Database-First Edition

Architecture:
- Background scanner writes results to database
- API reads from database AND accepts IPs to queue
- Background scanner picks up queued IPs automatically

Endpoints:
- POST /api/scan          - Queue IP(s) for scanning
- GET  /api/result/<ip>   - Get scan results for an IP
- GET  /api/queue         - Get queue status
- GET  /api/stats         - Get database statistics
- GET  /api/health        - Health check
"""

import os
import sys
import re
import uuid
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, jsonify, request
from database import get_database

# ─────────────────────────────────────────────────────────────
# APP
# ─────────────────────────────────────────────────────────────
app = Flask(__name__)


# ─────────────────────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────────────────────
def get_db():
    return get_database()


# ─────────────────────────────────────────────────────────────
# VALIDATION
# ─────────────────────────────────────────────────────────────
def is_valid_ip(ip: str) -> bool:
    """Validate IPv4 address format."""
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if not re.match(pattern, ip):
        return False
    parts = ip.split(".")
    return all(0 <= int(p) <= 255 for p in parts)


# ─────────────────────────────────────────────────────────────
# API ENDPOINTS
# ─────────────────────────────────────────────────────────────
@app.route("/api/health", methods=["GET"])
def health():
    """Health check endpoint."""
    db = get_db()
    stats = db.get_scan_stats()
    queue = db.get_queue_stats()

    return jsonify({
        "status": "ok",
        "mode": "database-first",
        "total_ips_scanned": stats["total_ips"],
        "queue_pending": queue["pending"],
        "last_scan": stats["last_scan"]
    })


@app.route("/api/scan", methods=["POST"])
def queue_scan():
    """
    Queue IP(s) for background scanning.

    The background scanner will pick up these IPs automatically.
    This endpoint returns immediately - it does NOT wait for scan completion.

    Request body:
        {"ip": "192.168.1.1"}
    or:
        {"ips": ["192.168.1.1", "192.168.1.2", ...]}

    Response:
        {
            "status": "queued",
            "job_id": "api_20260112_123456_abc123",
            "queued_ips": 5,
            "message": "IPs added to scan queue"
        }
    """
    data = request.get_json() or {}

    # Parse IPs
    if "ip" in data:
        ips = [data["ip"]]
    elif "ips" in data:
        ips = data["ips"]
    else:
        return jsonify({
            "error": "Missing 'ip' or 'ips' in request body",
            "example": {"ip": "192.168.1.1"}
        }), 400

    # Validate
    if not ips:
        return jsonify({"error": "No IPs provided"}), 400

    if not isinstance(ips, list):
        ips = [ips]

    # Limit to prevent abuse
    MAX_IPS_PER_REQUEST = 1000
    if len(ips) > MAX_IPS_PER_REQUEST:
        return jsonify({
            "error": f"Too many IPs (max {MAX_IPS_PER_REQUEST} per request)",
            "provided": len(ips)
        }), 400

    # Validate each IP
    valid_ips = []
    invalid_ips = []
    for ip in ips:
        ip = str(ip).strip()
        if is_valid_ip(ip):
            valid_ips.append(ip)
        else:
            invalid_ips.append(ip)

    if not valid_ips:
        return jsonify({
            "error": "No valid IPs provided",
            "invalid_ips": invalid_ips[:10]  # Show first 10
        }), 400

    # Create job and queue IPs
    db = get_db()
    job_id = f"api_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"

    db.create_job(job_id, len(valid_ips))
    db.queue_ips(valid_ips, job_id)

    response = {
        "status": "queued",
        "job_id": job_id,
        "queued_ips": len(valid_ips),
        "message": "IPs added to scan queue. Background scanner will process them."
    }

    if invalid_ips:
        response["skipped_invalid"] = len(invalid_ips)
        response["invalid_examples"] = invalid_ips[:5]

    return jsonify(response), 202  # 202 Accepted


@app.route("/api/result/<ip>", methods=["GET"])
def get_result(ip: str):
    """
    Get scan results for an IP address.

    Returns all port scan data from the database.
    This endpoint is READ-ONLY and extremely fast.

    Response:
    {
        "ip": "8.8.8.8",
        "last_scanned": "2026-01-12T00:15:00",
        "ports": [
            {
                "port": 53,
                "protocol": "udp",
                "state": "open",
                "service": "dns",
                "product": "bind",
                "version": "9.16"
            }
        ]
    }
    """
    db = get_db()
    result = db.get_result_by_ip(ip)

    if not result:
        # Check if it's in queue
        queue = db.get_queue_stats()
        return jsonify({
            "error": "No results found",
            "ip": ip,
            "message": "This IP has not been scanned yet. Use POST /api/scan to queue it.",
            "queue_pending": queue["pending"]
        }), 404

    return jsonify(result)


@app.route("/api/queue", methods=["GET"])
def get_queue():
    """
    Get current queue status.

    Returns:
    - pending: IPs waiting to be scanned
    - running: IPs currently being scanned
    - completed: IPs finished scanning
    - failed: IPs that failed to scan
    """
    db = get_db()
    queue = db.get_queue_stats()
    job = db.get_latest_job()

    response = {
        "queue": queue,
        "total_in_queue": queue["pending"] + queue["running"]
    }

    if job:
        response["latest_job"] = {
            "job_id": job["job_id"],
            "status": job["status"],
            "progress": f"{job['completed_ips']}/{job['total_ips']}",
            "started_at": job["started_at"],
            "completed_at": job["completed_at"]
        }

    return jsonify(response)


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """
    Get database statistics.

    Returns:
    - total_ips: Number of unique IPs scanned
    - total_ports: Total port records in database
    - last_scan: Timestamp of most recent scan
    - queue: Current queue status
    """
    db = get_db()
    stats = db.get_scan_stats()
    queue = db.get_queue_stats()
    job = db.get_latest_job()

    response = {
        "database": {
            "total_ips": stats["total_ips"],
            "total_ports": stats["total_ports"],
            "last_scan": stats["last_scan"]
        },
        "queue": queue
    }

    if job:
        response["latest_job"] = {
            "job_id": job["job_id"],
            "status": job["status"],
            "progress": f"{job['completed_ips']}/{job['total_ips']}",
            "started_at": job["started_at"],
            "completed_at": job["completed_at"]
        }

    return jsonify(response)


@app.route("/api/ips", methods=["GET"])
def list_ips():
    """
    List all scanned IPs.

    Returns list of unique IP addresses in the database.
    """
    db = get_db()
    ips = db.get_all_ips()

    return jsonify({
        "total": len(ips),
        "ips": ips
    })


# ─────────────────────────────────────────────────────────────
# ERROR HANDLERS
# ─────────────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error"}), 500


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Security Scanner API")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind")
    parser.add_argument("--port", type=int, default=5000, help="Port to bind")
    parser.add_argument("--debug", action="store_true", help="Debug mode")

    args = parser.parse_args()

    print("\n" + "=" * 60)
    print("Security Scanner API (Database-First)")
    print("=" * 60)
    print("POST /api/scan         - Queue IP(s) for scanning")
    print("GET  /api/result/<ip>  - Get scan results for IP")
    print("GET  /api/queue        - Queue status")
    print("GET  /api/stats        - Database statistics")
    print("GET  /api/ips          - List all scanned IPs")
    print("GET  /api/health       - Health check")
    print("=" * 60)
    print(f"Server: http://{args.host}:{args.port}")
    print("=" * 60 + "\n")

    app.run(host=args.host, port=args.port, debug=args.debug)
