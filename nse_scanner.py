#!/usr/bin/env python3
"""
NSE Scanner - Nmap Scripting Engine Scanner
Scans targets (domains/IPs) from a file or single target via command line
"""

import subprocess
import argparse
import os
import sys
from datetime import datetime


# Available NSE script categories
NSE_CATEGORIES = [
    "auth",       # Authentication related scripts
    "broadcast",  # Discover hosts by broadcasting
    "brute",      # Brute force attacks
    "default",    # Default scripts (-sC)
    "discovery",  # Discovery scripts
    "dos",        # Denial of Service scripts
    "exploit",    # Exploitation scripts
    "external",   # External service queries
    "fuzzer",     # Fuzzing scripts
    "intrusive",  # Intrusive scripts (may crash targets)
    "malware",    # Malware detection
    "safe",       # Safe scripts
    "version",    # Version detection
    "vuln",       # Vulnerability detection
]


def print_banner():
    """Print the scanner banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                    NSE SCANNER v1.1                           ║
║         Nmap Scripting Engine Scanner                         ║
╠═══════════════════════════════════════════════════════════════╣
║  Scan single IP/domain or multiple targets from a file        ║
╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def check_nmap():
    """Check if nmap is installed"""
    try:
        result = subprocess.run(
            ["nmap", "--version"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            version_line = result.stdout.split('\n')[0]
            print(f"[+] Found: {version_line}")
            return True
    except FileNotFoundError:
        pass
    
    print("[!] Error: Nmap is not installed or not in PATH")
    print("[*] Install nmap: sudo apt install nmap")
    return False


def read_targets(filepath):
    """Read targets from file (one per line)"""
    if not os.path.exists(filepath):
        print(f"[!] Error: Target file '{filepath}' not found")
        sys.exit(1)
    
    targets = []
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            # Skip empty lines and comments
            if line and not line.startswith('#'):
                targets.append(line)
    
    if not targets:
        print("[!] Error: No valid targets found in file")
        sys.exit(1)
    
    return targets


def run_nse_scan(target, scripts, ports, output_dir, extra_args=None):
    """Run NSE scan on a single target"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace('/', '_').replace(':', '_')
    output_base = os.path.join(output_dir, f"{safe_target}_{timestamp}")
    
    # Build nmap command
    cmd = ["nmap"]
    
    # Add script arguments
    if scripts:
        cmd.extend(["--script", scripts])
    else:
        cmd.append("-sC")  # Default scripts
    
    # Add port specification
    if ports:
        cmd.extend(["-p", ports])
    
    # Add extra arguments
    if extra_args:
        cmd.extend(extra_args.split())
    
    # Add output options
    cmd.extend([
        "-oN", f"{output_base}.txt",    # Normal output
        "-oX", f"{output_base}.xml",    # XML output
    ])
    
    # Add target
    cmd.append(target)
    
    print(f"\n{'='*60}")
    print(f"[*] Scanning: {target}")
    print(f"[*] Command: {' '.join(cmd)}")
    print(f"{'='*60}")
    
    try:
        # Run scan
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        # Stream output in real-time
        output_lines = []
        for line in process.stdout:
            print(line, end='')
            output_lines.append(line)
        
        process.wait()
        
        if process.returncode == 0:
            print(f"\n[+] Scan completed for {target}")
            print(f"[+] Results saved to: {output_base}.txt")
        else:
            print(f"\n[!] Scan finished with return code: {process.returncode}")
        
        return True, ''.join(output_lines)
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        process.kill()
        return False, None
    except Exception as e:
        print(f"[!] Error scanning {target}: {str(e)}")
        return False, None


def main():
    parser = argparse.ArgumentParser(
        description="NSE Scanner - Scan targets using Nmap Scripting Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  # Single target scanning
  %(prog)s -t 192.168.1.1                     # Scan single IP
  %(prog)s -t example.com -s vuln             # Vuln scan on domain
  %(prog)s -t 10.0.0.1 -s "http-*" -p 80,443  # HTTP scan on specific ports
  
  # Multiple targets from file
  %(prog)s -f targets.txt                     # Default scan on all targets
  %(prog)s -f targets.txt -s vuln             # Vulnerability scan
  %(prog)s -f targets.txt -s "http-*"         # HTTP scripts only
  %(prog)s -f targets.txt -s default,safe     # Multiple categories
  %(prog)s -f targets.txt -p 80,443           # Specific ports
  %(prog)s -f targets.txt -s vuln -p 1-1000   # Vuln scan on top 1000 ports

Available NSE Categories:
  {', '.join(NSE_CATEGORIES)}

Script Examples:
  vuln                - Vulnerability detection scripts
  http-*              - All HTTP related scripts
  ssl-*               - All SSL/TLS scripts
  ssh-*               - All SSH scripts
  smb-*               - All SMB scripts
  dns-*               - All DNS scripts
        """
    )
    
    # Target options (mutually exclusive group)
    target_group = parser.add_mutually_exclusive_group()
    
    target_group.add_argument(
        "-t", "--target",
        help="Single target IP or domain to scan"
    )
    
    target_group.add_argument(
        "-f", "--file",
        help="File containing targets (one per line)"
    )
    
    parser.add_argument(
        "-s", "--scripts",
        default="default",
        help="NSE scripts/categories to run (default: default)"
    )
    
    parser.add_argument(
        "-p", "--ports",
        help="Ports to scan (e.g., 80,443 or 1-1000 or -)"
    )
    
    parser.add_argument(
        "-o", "--output",
        default="./scan_results",
        help="Output directory for results (default: ./scan_results)"
    )
    
    parser.add_argument(
        "-e", "--extra",
        help="Extra nmap arguments (e.g., '-sV -T4')"
    )
    
    parser.add_argument(
        "--list-scripts",
        action="store_true",
        help="List available NSE scripts and exit"
    )
    
    args = parser.parse_args()
    
    print_banner()
    
    # List scripts if requested
    if args.list_scripts:
        print("[*] Listing available NSE scripts...")
        subprocess.run(["ls", "/usr/share/nmap/scripts/"])
        return
    
    # Validate that either -t or -f is provided
    if not args.target and not args.file:
        parser.error("You must specify either -t/--target or -f/--file")
    
    # Check nmap installation
    if not check_nmap():
        sys.exit(1)
    
    # Get targets (from single target or file)
    if args.target:
        targets = [args.target]
        print(f"\n[+] Single target mode: {args.target}")
    else:
        targets = read_targets(args.file)
        print(f"\n[+] Loaded {len(targets)} target(s) from {args.file}")
        for i, t in enumerate(targets, 1):
            print(f"    {i}. {t}")
    
    # Create output directory
    os.makedirs(args.output, exist_ok=True)
    print(f"\n[+] Output directory: {args.output}")
    
    # Scan summary
    print(f"\n[*] Scan Configuration:")
    print(f"    Scripts: {args.scripts}")
    print(f"    Ports: {args.ports or 'default (top 1000)'}")
    if args.extra:
        print(f"    Extra args: {args.extra}")
    
    # Confirm before scanning
    print(f"\n[?] Ready to scan {len(targets)} target(s). Press Enter to continue or Ctrl+C to abort...")
    try:
        input()
    except KeyboardInterrupt:
        print("\n[!] Scan aborted by user")
        sys.exit(0)
    
    # Run scans
    successful = 0
    failed = 0
    start_time = datetime.now()
    
    for i, target in enumerate(targets, 1):
        print(f"\n[*] Progress: {i}/{len(targets)}")
        success, _ = run_nse_scan(
            target,
            args.scripts,
            args.ports,
            args.output,
            args.extra
        )
        if success:
            successful += 1
        else:
            failed += 1
    
    # Summary
    end_time = datetime.now()
    duration = end_time - start_time
    
    print(f"\n{'='*60}")
    print("[*] SCAN SUMMARY")
    print(f"{'='*60}")
    print(f"    Total targets: {len(targets)}")
    print(f"    Successful: {successful}")
    print(f"    Failed: {failed}")
    print(f"    Duration: {duration}")
    print(f"    Results saved in: {args.output}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()

