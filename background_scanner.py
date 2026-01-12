#!/usr/bin/env python3
"""
Security Scanner - Background Scanner Service
Continuous batch processor that processes:
1. IPs pushed via API (POST /api/scan)
2. IPs from targets.txt file (daily scheduled scans)

Design:
- Runs continuously in the background
- Processes IPs in batches of 25
- Max 4 parallel batches at a time
- Writes results directly to database
- Handles 1 to 100,000+ IPs safely
"""

import os
import sys
import time
import signal
import logging
import uuid
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import get_database, Database
from scanner_api import SecurityScanner
from config import ScannerConfig

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", 25))
MAX_PARALLEL_BATCHES = int(os.environ.get("MAX_PARALLEL_BATCHES", 4))
SCAN_INTERVAL_HOURS = int(os.environ.get("SCAN_INTERVAL_HOURS", 24))
TARGETS_FILE = os.environ.get("TARGETS_FILE", "targets.txt")
QUEUE_CHECK_INTERVAL = int(os.environ.get("QUEUE_CHECK_INTERVAL", 5))  # seconds

# ─────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("BackgroundScanner")

# ─────────────────────────────────────────────
# Shutdown handling
# ─────────────────────────────────────────────
shutdown_event = threading.Event()


def handle_signal(signum, frame):
    logger.info("Shutdown signal received, finishing current batch...")
    shutdown_event.set()


signal.signal(signal.SIGINT, handle_signal)
signal.signal(signal.SIGTERM, handle_signal)


# ─────────────────────────────────────────────
# IP Loading
# ─────────────────────────────────────────────
def load_targets_from_file(filepath: str) -> List[str]:
    """Load target IPs from a file."""
    if not os.path.exists(filepath):
        logger.warning(f"Targets file not found: {filepath}")
        return []

    targets = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)

    return targets


# ─────────────────────────────────────────────
# Batch Processor
# ─────────────────────────────────────────────
class BatchProcessor:
    def __init__(self, db: Database, config: ScannerConfig):
        self.db = db
        self.config = config
        self.scanner = SecurityScanner(config)

    def scan_single_ip(self, ip: str, scan_id: str) -> dict:
        """Scan a single IP and return results."""
        try:
            result = self.scanner.scan(ip, scan_type="default")

            # Extract port data
            ports_data = []
            for port in result.open_ports:
                ports_data.append({
                    "port": port.port,
                    "protocol": port.protocol,
                    "state": port.state,
                    "service": port.service,
                    "product": getattr(port, "product", ""),
                    "version": getattr(port, "version", "")
                })

            # Write to database
            if ports_data:
                self.db.upsert_ports_batch(ip, ports_data, scan_id)

            return {
                "ip": ip,
                "status": "completed",
                "ports_found": len(ports_data)
            }

        except Exception as e:
            logger.error(f"Scan failed for {ip}: {e}")
            return {
                "ip": ip,
                "status": "failed",
                "error": str(e)
            }

    def process_batch(self, ips: List[str], scan_id: str, batch_id: int) -> List[dict]:
        """Process a batch of IPs."""
        logger.info(f"Batch {batch_id}: Processing {len(ips)} IPs")

        results = []
        for ip in ips:
            if shutdown_event.is_set():
                logger.info(f"Batch {batch_id}: Shutdown requested, stopping")
                break

            result = self.scan_single_ip(ip, scan_id)
            results.append(result)
            logger.debug(f"Batch {batch_id}: {ip} -> {result['status']}")

        completed = sum(1 for r in results if r["status"] == "completed")
        logger.info(f"Batch {batch_id}: Completed {completed}/{len(ips)} IPs")

        return results


# ─────────────────────────────────────────────
# Scan Job Manager
# ─────────────────────────────────────────────
class ScanJobManager:
    def __init__(self):
        self.db = get_database()
        self.config = ScannerConfig.from_env()
        self.processor = BatchProcessor(self.db, self.config)

    def create_job(self, targets: List[str]) -> str:
        """Create a new scan job."""
        job_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        self.db.create_job(job_id, len(targets))
        self.db.queue_ips(targets, job_id)
        logger.info(f"Created job {job_id} with {len(targets)} targets")
        return job_id

    def process_queue(self):
        """Process any pending IPs in the queue (from API or file)."""
        batch_id = 0
        total_completed = 0

        with ThreadPoolExecutor(max_workers=MAX_PARALLEL_BATCHES) as executor:
            while not shutdown_event.is_set():
                # Get pending IPs from queue
                pending = self.db.get_pending_ips(limit=BATCH_SIZE * MAX_PARALLEL_BATCHES)

                if not pending:
                    return total_completed  # No more IPs to process

                # Split into batches
                batches = []
                for i in range(0, len(pending), BATCH_SIZE):
                    batch = pending[i:i + BATCH_SIZE]
                    batches.append(batch)

                # Mark IPs as running
                for batch in batches:
                    for ip_record in batch:
                        self.db.mark_ip_started(ip_record["id"], batch_id)

                # Process batches in parallel
                futures = {}
                for batch in batches:
                    batch_id += 1
                    ips = [r["ip"] for r in batch]
                    job_id = batch[0]["job_id"]  # All IPs in batch have same job_id
                    future = executor.submit(
                        self.processor.process_batch, ips, job_id, batch_id
                    )
                    futures[future] = batch

                # Collect results
                for future in as_completed(futures):
                    batch = futures[future]
                    try:
                        results = future.result()
                        for i, result in enumerate(results):
                            ip_record = batch[i]
                            if result["status"] == "completed":
                                self.db.mark_ip_completed(ip_record["id"])
                                total_completed += 1
                            else:
                                self.db.mark_ip_failed(ip_record["id"])

                            # Update job progress
                            self.db.update_job_progress(ip_record["job_id"], total_completed)
                    except Exception as e:
                        logger.error(f"Batch processing error: {e}")
                        for ip_record in batch:
                            self.db.mark_ip_failed(ip_record["id"])

                # Brief pause between batch rounds
                time.sleep(1)

        return total_completed

    def run_daily_scan(self, targets: List[str]):
        """Run a complete daily scan from file."""
        if not targets:
            logger.warning("No targets to scan")
            return

        job_id = self.create_job(targets)
        completed = self.process_queue()

        # Mark job complete
        status = "completed" if not shutdown_event.is_set() else "interrupted"
        self.db.complete_job(job_id, status)

        logger.info(f"Daily scan complete: {completed} IPs processed")


# ─────────────────────────────────────────────
# Continuous Scheduler
# ─────────────────────────────────────────────
def run_continuous(targets_file: str = TARGETS_FILE):
    """
    Run continuous background scanning.

    Processes:
    1. IPs pushed via API (POST /api/scan) - checked every few seconds
    2. IPs from targets.txt - scheduled daily
    """
    logger.info("=" * 60)
    logger.info("Security Scanner - Background Service Started")
    logger.info("=" * 60)
    logger.info(f"Batch size: {BATCH_SIZE}")
    logger.info(f"Parallel batches: {MAX_PARALLEL_BATCHES}")
    logger.info(f"Daily scan interval: {SCAN_INTERVAL_HOURS} hours")
    logger.info(f"Queue check interval: {QUEUE_CHECK_INTERVAL} seconds")
    logger.info(f"Targets file: {targets_file}")
    logger.info("=" * 60)
    logger.info("Listening for IPs from API (POST /api/scan)...")
    logger.info("=" * 60)

    manager = ScanJobManager()
    last_daily_scan = None

    while not shutdown_event.is_set():
        now = datetime.now()

        # 1. Process any pending IPs in queue (from API)
        queue_stats = manager.db.get_queue_stats()
        if queue_stats["pending"] > 0:
            logger.info(f"Found {queue_stats['pending']} pending IPs in queue")
            completed = manager.process_queue()
            if completed > 0:
                logger.info(f"Processed {completed} IPs from queue")

        # 2. Check if it's time for daily scheduled scan
        should_daily_scan = (
            last_daily_scan is None or
            (now - last_daily_scan) >= timedelta(hours=SCAN_INTERVAL_HOURS)
        )

        if should_daily_scan:
            logger.info("Starting scheduled daily scan...")
            targets = load_targets_from_file(targets_file)
            if targets:
                logger.info(f"Loaded {len(targets)} targets from {targets_file}")
                manager.run_daily_scan(targets)
            else:
                logger.info("No targets in file, skipping daily scan")
            last_daily_scan = datetime.now()

        # Sleep before next queue check
        time.sleep(QUEUE_CHECK_INTERVAL)

    logger.info("Background scanner stopped")


def run_once(targets_file: str = TARGETS_FILE):
    """Run a single scan immediately from file."""
    logger.info("Running single scan...")

    targets = load_targets_from_file(targets_file)
    if not targets:
        logger.error(f"No targets found in {targets_file}")
        return

    logger.info(f"Loaded {len(targets)} targets")

    manager = ScanJobManager()
    manager.run_daily_scan(targets)


def run_queue_processor():
    """Process only the queue (IPs pushed via API), then exit."""
    logger.info("Processing queue...")

    manager = ScanJobManager()
    queue_stats = manager.db.get_queue_stats()

    if queue_stats["pending"] == 0:
        logger.info("Queue is empty, nothing to process")
        return

    logger.info(f"Found {queue_stats['pending']} pending IPs")
    completed = manager.process_queue()
    logger.info(f"Processed {completed} IPs")


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Background Scanner Service",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python background_scanner.py --continuous        # Run as service (API + daily)
  python background_scanner.py --process-queue    # Process API queue only
  python background_scanner.py --once              # Scan targets.txt once
  python background_scanner.py --once -f ips.txt   # Scan from file
  python background_scanner.py --status            # Show queue status
        """
    )

    parser.add_argument("-f", "--file", default=TARGETS_FILE,
                        help="Targets file (default: targets.txt)")
    parser.add_argument("--continuous", action="store_true",
                        help="Run as continuous background service")
    parser.add_argument("--process-queue", action="store_true",
                        help="Process API queue and exit")
    parser.add_argument("--once", action="store_true",
                        help="Run single scan from file and exit")
    parser.add_argument("--status", action="store_true",
                        help="Show current queue status")
    parser.add_argument("--batch-size", type=int, default=BATCH_SIZE,
                        help=f"IPs per batch (default: {BATCH_SIZE})")
    parser.add_argument("--parallel", type=int, default=MAX_PARALLEL_BATCHES,
                        help=f"Parallel batches (default: {MAX_PARALLEL_BATCHES})")

    args = parser.parse_args()

    # Override globals
    BATCH_SIZE = args.batch_size
    MAX_PARALLEL_BATCHES = args.parallel

    if args.status:
        db = get_database()
        stats = db.get_scan_stats()
        queue = db.get_queue_stats()
        job = db.get_latest_job()

        print("\n" + "=" * 50)
        print("Database Statistics")
        print("=" * 50)
        print(f"Total IPs scanned: {stats['total_ips']}")
        print(f"Total port records: {stats['total_ports']}")
        print(f"Last scan: {stats['last_scan']}")

        print("\n" + "=" * 50)
        print("Queue Status")
        print("=" * 50)
        print(f"Pending: {queue['pending']}")
        print(f"Running: {queue['running']}")
        print(f"Completed: {queue['completed']}")
        print(f"Failed: {queue['failed']}")

        if job:
            print("\n" + "=" * 50)
            print("Latest Job")
            print("=" * 50)
            print(f"Job ID: {job['job_id']}")
            print(f"Status: {job['status']}")
            print(f"Progress: {job['completed_ips']}/{job['total_ips']}")

    elif args.continuous:
        run_continuous(args.file)

    elif args.process_queue:
        run_queue_processor()

    elif args.once:
        run_once(args.file)

    else:
        parser.print_help()
