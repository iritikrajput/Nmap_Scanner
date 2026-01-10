#!/usr/bin/env python3
"""
Daily Security Scanner Script (Gunicorn / ThreadPool Optimized)

Run via cron to scan all targets safely without nested parallelism.
"""

import argparse
import os
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner_api import SecurityScanner
from config import ScannerConfig


# ─────────────────────────────────────────────
# Thread-local scanner (important)
# ─────────────────────────────────────────────
thread_local = threading.local()


def get_scanner(config: ScannerConfig) -> SecurityScanner:
    if not hasattr(thread_local, "scanner"):
        thread_local.scanner = SecurityScanner(config)
    return thread_local.scanner


def scan_target(target: str, config: ScannerConfig):
    scanner = get_scanner(config)
    try:
        return scanner.scan(target)
    except Exception as e:
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Daily Security Scanner (Optimized, Cron-Safe)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("-f", "--file", required=True, help="Targets file (one per line)")
    parser.add_argument("-o", "--output", default="./scan_results", help="Output directory")
    parser.add_argument("--workers", type=int, default=2, help="Parallel scans (default: 2)")
    parser.add_argument("--json-only", action="store_true", help="Save JSON only")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")

    args = parser.parse_args()

    # Validate target file
    if not os.path.exists(args.file):
        print(f"Error: File not found: {args.file}")
        sys.exit(1)

    # Load configuration
    config = ScannerConfig.from_env()
    config.output_dir = args.output

    if args.json_only:
        config.output_formats = ["json"]

    if args.quiet:
        config.log_level = "WARNING"

    os.makedirs(config.output_dir, exist_ok=True)

    # Load targets
    targets = []
    with open(args.file, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)

    print("=" * 60)
    print(f"  DAILY SECURITY SCAN - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    print(f"  Targets loaded: {len(targets)}")
    print(f"  Output dir:     {config.output_dir}")
    print(f"  Workers:        {args.workers}")
    print("=" * 60)
    print()

    if not targets:
        print("No targets to scan.")
        sys.exit(0)

    # Dependency check (once)
    scanner = SecurityScanner(config)
    nmap_ok, deps = scanner.check_dependencies()
    if not nmap_ok:
        print("Error: Nmap not found. Install with: sudo apt install nmap")
        sys.exit(1)

    # ─────────────────────────────────────────────
    # Run scans (SINGLE LEVEL PARALLELISM)
    # ─────────────────────────────────────────────
    results = []

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_map = {
            executor.submit(scan_target, target, config): target
            for target in targets
        }

        for future in as_completed(future_map):
            result = future.result()
            if result:
                results.append(result)

    # ─────────────────────────────────────────────
    # Summary
    # ─────────────────────────────────────────────
    alive = sum(1 for r in results if r.status == "alive")
    dead = sum(1 for r in results if r.status == "dead")
    failed = sum(1 for r in results if r.status == "failed")

    print()
    print("=" * 60)
    print("  SCAN SUMMARY")
    print("=" * 60)
    print(f"  Total scanned: {len(results)}")
    print(f"  Alive:         {alive}")
    print(f"  Dead:          {dead}")
    print(f"  Failed:        {failed}")
    print()

    high_risk = [r for r in results if r.risk_level in ("HIGH", "CRITICAL")]
    if high_risk:
        print("  HIGH RISK TARGETS:")
        for r in high_risk:
            print(f"    - {r.target}: {r.risk_level} ({r.risk_score}/100)")
        print()

    print("  OUTPUT FILES:")
    for r in results:
        json_file = r.output_files.get("report_json")
        if json_file:
            print(f"    - {os.path.basename(json_file)}")

    print()
    print("=" * 60)
    print(f"  Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)


if __name__ == "__main__":
    main()
