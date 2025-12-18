#!/usr/bin/env python3
"""
Daily Security Scanner Script
Run this script daily via cron to scan all targets

Usage:
  python3 daily_scan.py -f targets.txt
  python3 daily_scan.py -f ips.txt -o /var/scans

Cron Example (run daily at 2 AM):
  0 2 * * * cd /path/to/scanner && python3 daily_scan.py -f targets.txt >> /var/log/scanner.log 2>&1
"""

import argparse
import os
import sys
from datetime import datetime

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner_api import SecurityScanner
from config import ScannerConfig


def main():
    parser = argparse.ArgumentParser(
        description="Daily Security Scanner - Scans targets and appends results to JSON files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 daily_scan.py -f targets.txt
  python3 daily_scan.py -f ips.txt -o /var/scans

Output:
  Results are saved as {target}.json (e.g., 192.168.1.1.json, example.com.json)
  Each scan is appended to the file, preserving scan history.
        """
    )
    parser.add_argument("-f", "--file", required=True, help="File with targets (one per line)")
    parser.add_argument("-o", "--output", default="./scan_results", help="Output directory")
    parser.add_argument("--workers", type=int, default=2, help="Concurrent scans (default: 2)")
    parser.add_argument("--json-only", action="store_true", help="Output JSON only (no TXT/XML)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode (less output)")
    
    args = parser.parse_args()
    
    # Check if targets file exists
    if not os.path.exists(args.file):
        print(f"Error: File not found: {args.file}")
        sys.exit(1)
    
    # Load config
    config = ScannerConfig.from_env()
    config.output_dir = args.output
    
    if args.json_only:
        config.output_formats = ["json"]
    
    if args.quiet:
        config.log_level = "WARNING"
    
    # Create output directory
    os.makedirs(config.output_dir, exist_ok=True)
    
    # Print header
    print("=" * 60)
    print(f"  DAILY SECURITY SCAN - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    print(f"  Targets file: {args.file}")
    print(f"  Output dir:   {config.output_dir}")
    print("=" * 60)
    print()
    
    # Load targets
    targets = []
    with open(args.file, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                targets.append(line)
    
    print(f"Loaded {len(targets)} targets")
    print()
    
    # Initialize scanner
    scanner = SecurityScanner(config)
    
    # Check dependencies
    nmap_ok, deps = scanner.check_dependencies()
    if not nmap_ok:
        print("Error: Nmap not found. Install with: sudo apt install nmap")
        sys.exit(1)
    
    # Run scans
    results = scanner.scan_multiple(targets, max_workers=args.workers)
    
    # Summary
    print()
    print("=" * 60)
    print("  SCAN SUMMARY")
    print("=" * 60)
    
    alive_count = sum(1 for r in results if r.status == "alive")
    dead_count = sum(1 for r in results if r.status == "dead")
    failed_count = sum(1 for r in results if r.status == "failed")
    
    print(f"  Total scanned: {len(results)}")
    print(f"  Alive:         {alive_count}")
    print(f"  Dead:          {dead_count}")
    print(f"  Failed:        {failed_count}")
    print()
    
    # List high risk targets
    high_risk = [r for r in results if r.risk_level in ["HIGH", "CRITICAL"]]
    if high_risk:
        print("  HIGH RISK TARGETS:")
        for r in high_risk:
            print(f"    - {r.target}: {r.risk_level} ({r.risk_score}/100)")
    print()
    
    # List output files
    print("  OUTPUT FILES:")
    for r in results:
        json_file = r.output_files.get("report_json", "")
        if json_file:
            print(f"    - {os.path.basename(json_file)}")
    
    print()
    print("=" * 60)
    print(f"  Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)


if __name__ == "__main__":
    main()
