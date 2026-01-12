#!/usr/bin/env python3
"""
Security Scanner - Database Layer
SQLite by default, PostgreSQL supported for production.

Tables:
- scan_results: Port scan data indexed by IP
- scan_jobs: Daily job tracking
"""

import os
import sqlite3
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from contextlib import contextmanager

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────
DB_TYPE = os.environ.get("DB_TYPE", "sqlite")  # sqlite or postgresql
DB_PATH = os.environ.get("DB_PATH", "./scan_results/scanner.db")
DB_URL = os.environ.get("DATABASE_URL", None)  # For PostgreSQL

# ─────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────
@dataclass
class PortResult:
    port: int
    protocol: str
    state: str
    service_name: str
    service_product: str
    service_version: str


@dataclass
class ScanResult:
    ip: str
    ports: List[PortResult]
    scanned_at: str
    scan_id: str


# ─────────────────────────────────────────────
# Schema
# ─────────────────────────────────────────────
SCHEMA_SQLITE = """
-- Scan results: one row per IP+port combination
CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    state TEXT NOT NULL DEFAULT 'open',
    service_name TEXT,
    service_product TEXT,
    service_version TEXT,
    scanned_at TIMESTAMP NOT NULL,
    scan_id TEXT,
    UNIQUE(ip, port, protocol)
);

-- Indexes for fast lookups
CREATE INDEX IF NOT EXISTS idx_scan_results_ip ON scan_results(ip);
CREATE INDEX IF NOT EXISTS idx_scan_results_ip_port ON scan_results(ip, port);
CREATE INDEX IF NOT EXISTS idx_scan_results_scanned_at ON scan_results(scanned_at);

-- Scan jobs: tracks daily scan batches
CREATE TABLE IF NOT EXISTS scan_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT UNIQUE NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    total_ips INTEGER DEFAULT 0,
    completed_ips INTEGER DEFAULT 0,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_created ON scan_jobs(created_at);

-- IP queue: IPs waiting to be scanned
CREATE TABLE IF NOT EXISTS ip_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    job_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    batch_id INTEGER,
    queued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ip_queue_status ON ip_queue(status);
CREATE INDEX IF NOT EXISTS idx_ip_queue_job ON ip_queue(job_id);
CREATE INDEX IF NOT EXISTS idx_ip_queue_batch ON ip_queue(batch_id);
"""


# ─────────────────────────────────────────────
# Database Connection
# ─────────────────────────────────────────────
class Database:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._ensure_dir()
        self._init_schema()

    def _ensure_dir(self):
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)

    @contextmanager
    def connection(self):
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self):
        with self.connection() as conn:
            conn.executescript(SCHEMA_SQLITE)

    # ─────────────────────────────────────────
    # Scan Results
    # ─────────────────────────────────────────
    def upsert_port(
        self,
        ip: str,
        port: int,
        protocol: str,
        state: str,
        service_name: str = "",
        service_product: str = "",
        service_version: str = "",
        scan_id: str = ""
    ):
        """Insert or update a port scan result."""
        with self.connection() as conn:
            conn.execute("""
                INSERT INTO scan_results
                    (ip, port, protocol, state, service_name, service_product, service_version, scanned_at, scan_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip, port, protocol) DO UPDATE SET
                    state = excluded.state,
                    service_name = excluded.service_name,
                    service_product = excluded.service_product,
                    service_version = excluded.service_version,
                    scanned_at = excluded.scanned_at,
                    scan_id = excluded.scan_id
            """, (ip, port, protocol, state, service_name, service_product, service_version,
                  datetime.now().isoformat(), scan_id))

    def upsert_ports_batch(self, ip: str, ports: List[Dict], scan_id: str = ""):
        """Insert or update multiple ports for an IP."""
        with self.connection() as conn:
            now = datetime.now().isoformat()
            for p in ports:
                conn.execute("""
                    INSERT INTO scan_results
                        (ip, port, protocol, state, service_name, service_product, service_version, scanned_at, scan_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(ip, port, protocol) DO UPDATE SET
                        state = excluded.state,
                        service_name = excluded.service_name,
                        service_product = excluded.service_product,
                        service_version = excluded.service_version,
                        scanned_at = excluded.scanned_at,
                        scan_id = excluded.scan_id
                """, (
                    ip,
                    p.get("port", 0),
                    p.get("protocol", "tcp"),
                    p.get("state", "open"),
                    p.get("service", ""),
                    p.get("product", ""),
                    p.get("version", ""),
                    now,
                    scan_id
                ))

    def get_result_by_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get all scan results for an IP."""
        with self.connection() as conn:
            rows = conn.execute("""
                SELECT port, protocol, state, service_name, service_product, service_version, scanned_at
                FROM scan_results
                WHERE ip = ?
                ORDER BY port
            """, (ip,)).fetchall()

            if not rows:
                return None

            # Get the most recent scan time
            last_scanned = max(row["scanned_at"] for row in rows)

            return {
                "ip": ip,
                "last_scanned": last_scanned,
                "ports": [
                    {
                        "port": row["port"],
                        "protocol": row["protocol"],
                        "state": row["state"],
                        "service": row["service_name"],
                        "product": row["service_product"],
                        "version": row["service_version"]
                    }
                    for row in rows
                ]
            }

    def get_all_ips(self) -> List[str]:
        """Get list of all unique IPs in the database."""
        with self.connection() as conn:
            rows = conn.execute("SELECT DISTINCT ip FROM scan_results ORDER BY ip").fetchall()
            return [row["ip"] for row in rows]

    def get_scan_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        with self.connection() as conn:
            total_ips = conn.execute("SELECT COUNT(DISTINCT ip) FROM scan_results").fetchone()[0]
            total_ports = conn.execute("SELECT COUNT(*) FROM scan_results").fetchone()[0]
            last_scan = conn.execute("SELECT MAX(scanned_at) FROM scan_results").fetchone()[0]
            return {
                "total_ips": total_ips,
                "total_ports": total_ports,
                "last_scan": last_scan
            }

    # ─────────────────────────────────────────
    # Scan Jobs
    # ─────────────────────────────────────────
    def create_job(self, job_id: str, total_ips: int) -> str:
        """Create a new scan job."""
        with self.connection() as conn:
            conn.execute("""
                INSERT INTO scan_jobs (job_id, status, total_ips, started_at)
                VALUES (?, 'running', ?, ?)
            """, (job_id, total_ips, datetime.now().isoformat()))
        return job_id

    def update_job_progress(self, job_id: str, completed_ips: int):
        """Update job progress."""
        with self.connection() as conn:
            conn.execute("""
                UPDATE scan_jobs SET completed_ips = ? WHERE job_id = ?
            """, (completed_ips, job_id))

    def complete_job(self, job_id: str, status: str = "completed"):
        """Mark job as completed."""
        with self.connection() as conn:
            conn.execute("""
                UPDATE scan_jobs
                SET status = ?, completed_at = ?
                WHERE job_id = ?
            """, (status, datetime.now().isoformat(), job_id))

    def get_job(self, job_id: str) -> Optional[Dict]:
        """Get job status."""
        with self.connection() as conn:
            row = conn.execute("""
                SELECT * FROM scan_jobs WHERE job_id = ?
            """, (job_id,)).fetchone()
            if row:
                return dict(row)
            return None

    def get_latest_job(self) -> Optional[Dict]:
        """Get most recent job."""
        with self.connection() as conn:
            row = conn.execute("""
                SELECT * FROM scan_jobs ORDER BY created_at DESC LIMIT 1
            """).fetchone()
            if row:
                return dict(row)
            return None

    # ─────────────────────────────────────────
    # IP Queue
    # ─────────────────────────────────────────
    def queue_ips(self, ips: List[str], job_id: str):
        """Add IPs to the scan queue."""
        with self.connection() as conn:
            for ip in ips:
                conn.execute("""
                    INSERT INTO ip_queue (ip, job_id, status)
                    VALUES (?, ?, 'pending')
                """, (ip, job_id))

    def get_pending_ips(self, limit: int = 25) -> List[Dict]:
        """Get pending IPs for scanning."""
        with self.connection() as conn:
            rows = conn.execute("""
                SELECT id, ip, job_id FROM ip_queue
                WHERE status = 'pending'
                ORDER BY id
                LIMIT ?
            """, (limit,)).fetchall()
            return [dict(row) for row in rows]

    def mark_ip_started(self, ip_id: int, batch_id: int):
        """Mark IP as being scanned."""
        with self.connection() as conn:
            conn.execute("""
                UPDATE ip_queue
                SET status = 'running', batch_id = ?, started_at = ?
                WHERE id = ?
            """, (batch_id, datetime.now().isoformat(), ip_id))

    def mark_ip_completed(self, ip_id: int):
        """Mark IP scan as completed."""
        with self.connection() as conn:
            conn.execute("""
                UPDATE ip_queue
                SET status = 'completed', completed_at = ?
                WHERE id = ?
            """, (datetime.now().isoformat(), ip_id))

    def mark_ip_failed(self, ip_id: int):
        """Mark IP scan as failed."""
        with self.connection() as conn:
            conn.execute("""
                UPDATE ip_queue SET status = 'failed' WHERE id = ?
            """, (ip_id,))

    def get_queue_stats(self, job_id: str = None) -> Dict:
        """Get queue statistics."""
        with self.connection() as conn:
            if job_id:
                pending = conn.execute(
                    "SELECT COUNT(*) FROM ip_queue WHERE job_id = ? AND status = 'pending'",
                    (job_id,)
                ).fetchone()[0]
                running = conn.execute(
                    "SELECT COUNT(*) FROM ip_queue WHERE job_id = ? AND status = 'running'",
                    (job_id,)
                ).fetchone()[0]
                completed = conn.execute(
                    "SELECT COUNT(*) FROM ip_queue WHERE job_id = ? AND status = 'completed'",
                    (job_id,)
                ).fetchone()[0]
                failed = conn.execute(
                    "SELECT COUNT(*) FROM ip_queue WHERE job_id = ? AND status = 'failed'",
                    (job_id,)
                ).fetchone()[0]
            else:
                pending = conn.execute("SELECT COUNT(*) FROM ip_queue WHERE status = 'pending'").fetchone()[0]
                running = conn.execute("SELECT COUNT(*) FROM ip_queue WHERE status = 'running'").fetchone()[0]
                completed = conn.execute("SELECT COUNT(*) FROM ip_queue WHERE status = 'completed'").fetchone()[0]
                failed = conn.execute("SELECT COUNT(*) FROM ip_queue WHERE status = 'failed'").fetchone()[0]

            return {
                "pending": pending,
                "running": running,
                "completed": completed,
                "failed": failed,
                "total": pending + running + completed + failed
            }

    def clear_queue(self, job_id: str = None):
        """Clear the IP queue."""
        with self.connection() as conn:
            if job_id:
                conn.execute("DELETE FROM ip_queue WHERE job_id = ?", (job_id,))
            else:
                conn.execute("DELETE FROM ip_queue")


# ─────────────────────────────────────────────
# Singleton Instance
# ─────────────────────────────────────────────
_db_instance = None


def get_database() -> Database:
    global _db_instance
    if _db_instance is None:
        _db_instance = Database()
    return _db_instance


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Database Management")
    parser.add_argument("--init", action="store_true", help="Initialize database")
    parser.add_argument("--stats", action="store_true", help="Show statistics")
    parser.add_argument("--get", type=str, help="Get result for IP")

    args = parser.parse_args()

    db = get_database()

    if args.init:
        print(f"Database initialized: {DB_PATH}")

    if args.stats:
        stats = db.get_scan_stats()
        print(f"Total IPs: {stats['total_ips']}")
        print(f"Total Ports: {stats['total_ports']}")
        print(f"Last Scan: {stats['last_scan']}")

    if args.get:
        result = db.get_result_by_ip(args.get)
        if result:
            import json
            print(json.dumps(result, indent=2))
        else:
            print(f"No results for {args.get}")
