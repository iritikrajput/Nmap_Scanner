#!/usr/bin/env python3
"""
Security Scanner Worker - Redis Queue Consumer

This worker processes scan jobs from the Redis queue.
Run multiple instances for horizontal scaling.

Usage:
  python3 worker.py                     # Start single worker
  python3 worker.py --workers 4         # Start 4 workers
  
Environment Variables:
  REDIS_HOST     - Redis host (default: localhost)
  REDIS_PORT     - Redis port (default: 6379)
  REDIS_DB       - Redis database (default: 0)
  REDIS_PASSWORD - Redis password (optional)

Redis Schema:
  scan:queue        -> List of pending jobs (JSON)
  scan:result:{id}  -> Scan result (JSON)
  scan:status:{id}  -> Scan status (pending/running/completed/failed)
"""

import os
import sys
import json
import time
import signal
import logging
import multiprocessing
from datetime import datetime
from typing import Optional, Dict, Any

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import redis
except ImportError:
    print("ERROR: Redis package not installed. Run: pip install redis")
    sys.exit(1)

from scanner_api import SecurityScanner, SCAN_PROFILES
from config import ScannerConfig

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
REDIS_DB = int(os.environ.get("REDIS_DB", 0))
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD", None)

# Queue settings
QUEUE_NAME = "scan:queue"
RESULT_TTL = 86400  # 24 hours
POLL_TIMEOUT = 5    # seconds

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - Worker[%(process)d] - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Graceful shutdown flag
shutdown_flag = multiprocessing.Event()


def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    logger.info("Shutdown signal received. Finishing current job...")
    shutdown_flag.set()


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


# ═══════════════════════════════════════════════════════════════════════════════
# REDIS CLIENT
# ═══════════════════════════════════════════════════════════════════════════════

def get_redis_client() -> redis.Redis:
    """Create Redis client connection"""
    return redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        db=REDIS_DB,
        password=REDIS_PASSWORD,
        decode_responses=True
    )


def test_redis_connection(client: redis.Redis) -> bool:
    """Test Redis connection"""
    try:
        client.ping()
        return True
    except redis.ConnectionError:
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# WORKER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def process_job(job: Dict[str, Any], redis_client: redis.Redis) -> Dict[str, Any]:
    """
    Process a single scan job
    
    Args:
        job: Job dict with id, target, scan_type, client
        redis_client: Redis connection
        
    Returns:
        Scan result dictionary
    """
    scan_id = job["id"]
    target = job["target"]
    scan_type = job.get("scan_type", "default")
    client = job.get("client", "unknown")
    
    logger.info(f"Processing job {scan_id}: {target} ({scan_type})")
    
    # Update status to running
    redis_client.set(f"scan:status:{scan_id}", "running")
    
    started_at = datetime.now().isoformat()
    
    try:
        # Validate scan type
        if scan_type not in SCAN_PROFILES:
            raise ValueError(f"Invalid scan_type: {scan_type}")
        
        # Create scanner and run scan
        config = ScannerConfig.from_env()
        scanner = SecurityScanner(config)
        result = scanner.scan(target, scan_type=scan_type)
        result_dict = result.to_dict()
        
        scan_result = {
            "id": scan_id,
            "target": target,
            "scan_type": scan_type,
            "client": client,
            "status": "completed",
            "started_at": started_at,
            "completed_at": datetime.now().isoformat(),
            **result_dict
        }
        
        logger.info(f"Job {scan_id} completed successfully")
        
    except PermissionError as e:
        scan_result = {
            "id": scan_id,
            "target": target,
            "scan_type": scan_type,
            "client": client,
            "status": "blocked",
            "started_at": started_at,
            "completed_at": datetime.now().isoformat(),
            "error": str(e)
        }
        logger.warning(f"Job {scan_id} blocked: {e}")
        
    except Exception as e:
        scan_result = {
            "id": scan_id,
            "target": target,
            "scan_type": scan_type,
            "client": client,
            "status": "failed",
            "started_at": started_at,
            "completed_at": datetime.now().isoformat(),
            "error": str(e)
        }
        logger.error(f"Job {scan_id} failed: {e}")
    
    # Store result in Redis
    redis_client.set(
        f"scan:result:{scan_id}",
        json.dumps(scan_result),
        ex=RESULT_TTL
    )
    redis_client.set(
        f"scan:status:{scan_id}",
        scan_result["status"],
        ex=RESULT_TTL
    )
    
    return scan_result


def worker_loop(worker_id: int):
    """
    Main worker loop - continuously process jobs from queue
    
    Args:
        worker_id: Unique worker identifier
    """
    logger.info(f"Worker {worker_id} starting...")
    
    redis_client = get_redis_client()
    
    if not test_redis_connection(redis_client):
        logger.error(f"Worker {worker_id}: Failed to connect to Redis")
        return
    
    logger.info(f"Worker {worker_id}: Connected to Redis at {REDIS_HOST}:{REDIS_PORT}")
    
    jobs_processed = 0
    
    while not shutdown_flag.is_set():
        try:
            # Block and wait for job from queue (BRPOP)
            result = redis_client.brpop(QUEUE_NAME, timeout=POLL_TIMEOUT)
            
            if result is None:
                # Timeout - no job available
                continue
            
            _, job_json = result
            
            try:
                job = json.loads(job_json)
            except json.JSONDecodeError:
                logger.error(f"Invalid job JSON: {job_json}")
                continue
            
            # Process the job
            process_job(job, redis_client)
            jobs_processed += 1
            
        except redis.ConnectionError as e:
            logger.error(f"Redis connection lost: {e}")
            time.sleep(5)
            redis_client = get_redis_client()
            
        except Exception as e:
            logger.error(f"Worker error: {e}")
            time.sleep(1)
    
    logger.info(f"Worker {worker_id} shutting down. Processed {jobs_processed} jobs.")


def start_workers(num_workers: int = 1):
    """
    Start multiple worker processes
    
    Args:
        num_workers: Number of worker processes to spawn
    """
    logger.info(f"Starting {num_workers} worker(s)...")
    
    processes = []
    
    for i in range(num_workers):
        p = multiprocessing.Process(target=worker_loop, args=(i,))
        p.start()
        processes.append(p)
    
    logger.info(f"All {num_workers} workers started. Press Ctrl+C to stop.")
    
    try:
        # Wait for all processes
        for p in processes:
            p.join()
    except KeyboardInterrupt:
        logger.info("Stopping all workers...")
        shutdown_flag.set()
        for p in processes:
            p.join(timeout=30)
            if p.is_alive():
                p.terminate()


# ═══════════════════════════════════════════════════════════════════════════════
# CLI UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

def show_queue_stats():
    """Display current queue statistics"""
    redis_client = get_redis_client()
    
    if not test_redis_connection(redis_client):
        print("ERROR: Cannot connect to Redis")
        return
    
    queue_length = redis_client.llen(QUEUE_NAME)
    
    # Count status types
    pending = 0
    running = 0
    completed = 0
    failed = 0
    
    for key in redis_client.scan_iter("scan:status:*"):
        status = redis_client.get(key)
        if status == "pending":
            pending += 1
        elif status == "running":
            running += 1
        elif status == "completed":
            completed += 1
        elif status == "failed":
            failed += 1
    
    print()
    print("═" * 50)
    print("  Redis Queue Statistics")
    print("═" * 50)
    print(f"  Queue Length:    {queue_length}")
    print(f"  Pending:         {pending}")
    print(f"  Running:         {running}")
    print(f"  Completed:       {completed}")
    print(f"  Failed:          {failed}")
    print("═" * 50)
    print()


def clear_queue():
    """Clear all pending jobs from queue"""
    redis_client = get_redis_client()
    
    if not test_redis_connection(redis_client):
        print("ERROR: Cannot connect to Redis")
        return
    
    queue_length = redis_client.llen(QUEUE_NAME)
    redis_client.delete(QUEUE_NAME)
    print(f"Cleared {queue_length} jobs from queue")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Security Scanner Worker - Redis Queue Consumer"
    )
    parser.add_argument(
        "--workers", "-w",
        type=int,
        default=1,
        help="Number of worker processes (default: 1)"
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Show queue statistics and exit"
    )
    parser.add_argument(
        "--clear",
        action="store_true",
        help="Clear pending jobs from queue and exit"
    )
    
    args = parser.parse_args()
    
    print()
    print("═" * 60)
    print("  Security Scanner Worker - Redis Queue Consumer")
    print("═" * 60)
    print(f"  Redis:    {REDIS_HOST}:{REDIS_PORT} (db: {REDIS_DB})")
    print(f"  Queue:    {QUEUE_NAME}")
    print(f"  Workers:  {args.workers}")
    print("═" * 60)
    print()
    
    if args.stats:
        show_queue_stats()
    elif args.clear:
        clear_queue()
    else:
        start_workers(args.workers)

