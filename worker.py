#!/usr/bin/env python3
"""
Security Scanner Worker - Redis Queue Consumer (FINAL)

Design:
- One scan per worker process
- Horizontal scaling via multiple workers
- No threading inside worker
- Redis-backed status & results
"""

import os
import sys
import json
import time
import signal
import logging
import multiprocessing
from datetime import datetime
from typing import Dict, Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import redis
except ImportError:
    print("ERROR: redis package not installed. Run: pip install redis")
    sys.exit(1)

from scanner_api import SecurityScanner, SCAN_PROFILES
from config import ScannerConfig

# ─────────────────────────────────────────────
# Redis configuration
# ─────────────────────────────────────────────
REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
REDIS_DB = int(os.environ.get("REDIS_DB", 0))
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD")

QUEUE_NAME = "scan:queue"
RESULT_TTL = 86400  # 24 hours
BRPOP_TIMEOUT = 5

# ─────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - Worker[%(process)d] - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("scanner-worker")

# Shutdown flag
shutdown_event = multiprocessing.Event()


def handle_signal(signum, frame):
    logger.info("Shutdown signal received, finishing current job...")
    shutdown_event.set()


signal.signal(signal.SIGINT, handle_signal)
signal.signal(signal.SIGTERM, handle_signal)

# ─────────────────────────────────────────────
# Redis helpers
# ─────────────────────────────────────────────
def get_redis() -> redis.Redis:
    return redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        db=REDIS_DB,
        password=REDIS_PASSWORD,
        decode_responses=True
    )


def redis_ok(r: redis.Redis) -> bool:
    try:
        r.ping()
        return True
    except redis.RedisError:
        return False

# ─────────────────────────────────────────────
# Job processing
# ─────────────────────────────────────────────
def process_job(job: Dict[str, Any], r: redis.Redis):
    scan_id = job["id"]
    target = job["target"]
    scan_type = job.get("scan_type", "default")
    client = job.get("client", "unknown")

    logger.info(f"[{scan_id}] Starting scan: {target} ({scan_type})")

    r.set(f"scan:status:{scan_id}", "running", ex=RESULT_TTL)
    started_at = datetime.now().isoformat()

    try:
        if scan_type not in SCAN_PROFILES:
            raise ValueError(f"Invalid scan_type: {scan_type}")

        config = ScannerConfig.from_env()
        scanner = SecurityScanner(config)

        result = scanner.scan(target, scan_type=scan_type)
        result_dict = result.to_dict()

        payload = {
            "id": scan_id,
            "target": target,
            "scan_type": scan_type,
            "client": client,
            "status": "completed",
            "started_at": started_at,
            "completed_at": datetime.now().isoformat(),
            **result_dict,
        }

        logger.info(f"[{scan_id}] Scan completed")

    except PermissionError as e:
        payload = {
            "id": scan_id,
            "target": target,
            "scan_type": scan_type,
            "client": client,
            "status": "blocked",
            "started_at": started_at,
            "completed_at": datetime.now().isoformat(),
            "error": str(e),
        }
        logger.warning(f"[{scan_id}] Blocked: {e}")

    except Exception as e:
        payload = {
            "id": scan_id,
            "target": target,
            "scan_type": scan_type,
            "client": client,
            "status": "failed",
            "started_at": started_at,
            "completed_at": datetime.now().isoformat(),
            "error": str(e),
        }
        logger.error(f"[{scan_id}] Failed: {e}")

    r.set(f"scan:result:{scan_id}", json.dumps(payload), ex=RESULT_TTL)
    r.set(f"scan:status:{scan_id}", payload["status"], ex=RESULT_TTL)


# ─────────────────────────────────────────────
# Worker loop
# ─────────────────────────────────────────────
def worker_loop(worker_id: int):
    logger.info(f"Worker-{worker_id} starting")

    r = get_redis()
    if not redis_ok(r):
        logger.error("Redis connection failed")
        return

    logger.info(f"Worker-{worker_id} connected to Redis")

    jobs_done = 0

    while not shutdown_event.is_set():
        try:
            item = r.brpop(QUEUE_NAME, timeout=BRPOP_TIMEOUT)
            if not item:
                continue

            _, raw_job = item
            try:
                job = json.loads(raw_job)
            except json.JSONDecodeError:
                logger.error("Invalid job JSON")
                continue

            process_job(job, r)
            jobs_done += 1

        except redis.RedisError as e:
            logger.error(f"Redis error: {e}")
            time.sleep(5)
            r = get_redis()

        except Exception as e:
            logger.error(f"Worker error: {e}")
            time.sleep(1)

    logger.info(f"Worker-{worker_id} exiting (jobs processed: {jobs_done})")

# ─────────────────────────────────────────────
# Worker manager
# ─────────────────────────────────────────────
def start_workers(count: int):
    logger.info(f"Starting {count} worker(s)")
    procs = []

    for i in range(count):
        p = multiprocessing.Process(target=worker_loop, args=(i,))
        p.start()
        procs.append(p)

    try:
        for p in procs:
            p.join()
    except KeyboardInterrupt:
        shutdown_event.set()
        for p in procs:
            p.join(timeout=30)
            if p.is_alive():
                p.terminate()

# ─────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────
def show_stats():
    r = get_redis()
    if not redis_ok(r):
        print("Redis unavailable")
        return

    print("\nRedis Queue Stats")
    print("-" * 40)
    print(f"Queue length: {r.llen(QUEUE_NAME)}")

    counts = {"pending": 0, "running": 0, "completed": 0, "failed": 0, "blocked": 0}
    for k in r.scan_iter("scan:status:*"):
        s = r.get(k)
        if s in counts:
            counts[s] += 1

    for k, v in counts.items():
        print(f"{k.capitalize():10}: {v}")
    print()

def clear_queue():
    r = get_redis()
    if not redis_ok(r):
        print("Redis unavailable")
        return
    n = r.llen(QUEUE_NAME)
    r.delete(QUEUE_NAME)
    print(f"Cleared {n} queued jobs")

# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Security Scanner Redis Worker")
    parser.add_argument("-w", "--workers", type=int, default=1, help="Number of workers")
    parser.add_argument("--stats", action="store_true", help="Show queue stats")
    parser.add_argument("--clear", action="store_true", help="Clear queue")

    args = parser.parse_args()

    print("\nSecurity Scanner Worker")
    print("=" * 50)
    print(f"Redis:   {REDIS_HOST}:{REDIS_PORT} (db {REDIS_DB})")
    print(f"Queue:   {QUEUE_NAME}")
    print("=" * 50)

    if args.stats:
        show_stats()
    elif args.clear:
        clear_queue()
    else:
        start_workers(args.workers)
