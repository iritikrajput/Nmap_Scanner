#!/usr/bin/env python3
"""
NSE Scanner - Nmap Scripting Engine Scanner v2.0
Optimized for security scanning with SSL/TLS and HTTP header checks
"""

import subprocess
import argparse
import os
import sys
import json
from datetime import datetime


# Security-focused NSE scripts
SECURITY_SCRIPTS = {
    # SSL/TLS Certificate Scripts
    "ssl-cert": "Retrieves SSL certificate information",
    "ssl-enum-ciphers": "Enumerates SSL/TLS ciphers and protocols",
    "ssl-known-key": "Checks for known weak SSL keys",
    "ssl-date": "Retrieves target's time from SSL certificate",
    "ssl-heartbleed": "Checks for Heartbleed vulnerability",
    "ssl-poodle": "Checks for POODLE vulnerability",
    "ssl-dh-params": "Checks Diffie-Hellman parameters",
    "ssl-ccs-injection": "Checks for CCS injection vulnerability",
    
    # HTTP Security Header Scripts
    "http-security-headers": "Checks for security headers (HSTS, CSP, X-Frame-Options, etc.)",
    "http-headers": "Retrieves HTTP headers",
    "http-server-header": "Gets server header info",
    "http-cors": "Checks CORS configuration",
    "http-cookie-flags": "Checks cookie security flags",
    "http-csrf": "Checks for CSRF vulnerabilities",
    "http-xssed": "Checks XSSed.com database for XSS vulnerabilities",
}

# Scan profiles
SCAN_PROFILES = {
    "quick": {
        "description": "Quick scan - Top 100 ports, basic scripts",
        "ports": "--top-ports 100",
        "scripts": "default",
        "extra": "-T4"
    },
    "standard": {
        "description": "Standard scan - Top 1000 ports",
        "ports": None,  # Default nmap behavior
        "scripts": "default",
        "extra": "-sV -T4"
    },
    "full": {
        "description": "Full scan - All 65535 ports",
        "ports": "-",
        "scripts": "default,safe",
        "extra": "-sV -T4"
    },
    "security": {
        "description": "Security scan - SSL/TLS + HTTP headers + Vulns",
        "ports": "-",
        "scripts": "ssl-cert,ssl-enum-ciphers,ssl-heartbleed,ssl-poodle,http-security-headers,http-headers,http-cookie-flags,vuln",
        "extra": "-sV -T4"
    },
    "https": {
        "description": "HTTPS Security - SSL/TLS certificates + Security headers",
        "ports": "443,8443,8080,4443",
        "scripts": "ssl-cert,ssl-enum-ciphers,ssl-heartbleed,ssl-poodle,ssl-dh-params,ssl-ccs-injection,http-security-headers,http-headers,http-cookie-flags,http-cors",
        "extra": "-sV"
    },
    "web": {
        "description": "Web scan - HTTP/HTTPS ports with web scripts",
        "ports": "80,443,8080,8443,8000,3000,5000",
        "scripts": "http-*,ssl-cert,ssl-enum-ciphers",
        "extra": "-sV -T4"
    }
}


def print_banner():
    """Print the scanner banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════════╗
║                      NSE SCANNER v2.0                             ║
║            Security-Focused Nmap Scripting Engine                 ║
╠═══════════════════════════════════════════════════════════════════╣
║  ✓ All Ports Scanning (65535)    ✓ SSL/TLS Certificate Check      ║
║  ✓ HTTP Security Headers         ✓ Only Open Ports Displayed      ║
╚═══════════════════════════════════════════════════════════════════╝
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


def format_scan_results(output_file):
    """Parse and display formatted scan results"""
    if not os.path.exists(output_file):
        return
    
    print("\n" + "─" * 70)
    print("📊 SCAN RESULTS SUMMARY")
    print("─" * 70)
    
    with open(output_file, 'r') as f:
        content = f.read()
        
    # Extract key information
    lines = content.split('\n')
    current_section = None
    
    for line in lines:
        # Host info
        if "Nmap scan report for" in line:
            print(f"\n🎯 {line}")
        
        # Open ports
        elif "/tcp" in line and "open" in line:
            parts = line.split()
            if len(parts) >= 3:
                port = parts[0]
                state = parts[1]
                service = ' '.join(parts[2:])
                print(f"   ├─ ✅ {port:<15} {service}")
        
        # SSL Certificate info
        elif "Subject:" in line and "ssl-cert" in content:
            print(f"   │  🔐 {line.strip()}")
        elif "Issuer:" in line:
            print(f"   │  📜 {line.strip()}")
        elif "Not valid after:" in line:
            print(f"   │  ⏰ {line.strip()}")
        
        # Security headers
        elif "Strict-Transport-Security" in line:
            print(f"   │  🛡️  HSTS: {'✅ Present' if 'MISSING' not in line else '❌ MISSING'}")
        elif "Content-Security-Policy" in line:
            print(f"   │  🛡️  CSP: {'✅ Present' if 'MISSING' not in line else '❌ MISSING'}")
        elif "X-Frame-Options" in line:
            print(f"   │  🛡️  X-Frame-Options: {'✅ Present' if 'MISSING' not in line else '❌ MISSING'}")
        elif "X-Content-Type-Options" in line:
            print(f"   │  🛡️  X-Content-Type-Options: {'✅ Present' if 'MISSING' not in line else '❌ MISSING'}")
        
        # Vulnerabilities
        elif "VULNERABLE" in line:
            print(f"   │  ⚠️  {line.strip()}")
        
        # TLS versions
        elif "TLSv1.0" in line or "TLSv1.1" in line:
            print(f"   │  ⚠️  Weak TLS: {line.strip()}")
        elif "TLSv1.2" in line or "TLSv1.3" in line:
            print(f"   │  ✅ {line.strip()}")


def run_nse_scan(target, scripts, ports, output_dir, extra_args=None, show_closed=False):
    """Run NSE scan on a single target"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace('/', '_').replace(':', '_').replace('.', '_')
    output_base = os.path.join(output_dir, f"{safe_target}_{timestamp}")
    
    # Build nmap command
    cmd = ["nmap"]
    
    # Only show open ports (cleaner output)
    if not show_closed:
        cmd.append("--open")
    
    # Add script arguments
    if scripts:
        cmd.extend(["--script", scripts])
    else:
        cmd.append("-sC")  # Default scripts
    
    # Add port specification (default: all ports)
    if ports:
        cmd.extend(["-p", ports])
    else:
        cmd.extend(["-p", "-"])  # All 65535 ports by default
    
    # Add extra arguments
    if extra_args:
        cmd.extend(extra_args.split())
    
    # Add output options
    cmd.extend([
        "-oN", f"{output_base}.txt",    # Normal output
        "-oX", f"{output_base}.xml",    # XML output
        "-oG", f"{output_base}.gnmap",  # Grepable output
    ])
    
    # Add target
    cmd.append(target)
    
    print(f"\n{'═' * 70}")
    print(f"🔍 SCANNING: {target}")
    print(f"{'═' * 70}")
    print(f"📋 Command: {' '.join(cmd)}")
    print(f"📁 Output: {output_base}.*")
    print(f"{'─' * 70}")
    
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
            print(f"\n✅ Scan completed for {target}")
            # Display formatted results
            format_scan_results(f"{output_base}.txt")
        else:
            print(f"\n⚠️  Scan finished with return code: {process.returncode}")
        
        return True, ''.join(output_lines), output_base
        
    except KeyboardInterrupt:
        print("\n❌ Scan interrupted by user")
        process.kill()
        return False, None, None
    except Exception as e:
        print(f"❌ Error scanning {target}: {str(e)}")
        return False, None, None


def list_profiles():
    """List available scan profiles"""
    print("\n📋 AVAILABLE SCAN PROFILES:")
    print("─" * 60)
    for name, profile in SCAN_PROFILES.items():
        print(f"\n  {name}:")
        print(f"    Description: {profile['description']}")
        print(f"    Ports: {profile['ports'] or 'default (top 1000)'}")
        print(f"    Scripts: {profile['scripts']}")
    print()


def list_security_scripts():
    """List security-focused NSE scripts"""
    print("\n🔐 SECURITY-FOCUSED NSE SCRIPTS:")
    print("─" * 60)
    
    print("\n  SSL/TLS Certificate Scripts:")
    for script, desc in SECURITY_SCRIPTS.items():
        if script.startswith("ssl-"):
            print(f"    • {script}: {desc}")
    
    print("\n  HTTP Security Header Scripts:")
    for script, desc in SECURITY_SCRIPTS.items():
        if script.startswith("http-"):
            print(f"    • {script}: {desc}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="NSE Scanner v2.0 - Security-Focused Nmap Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single target with security profile (recommended)
  %(prog)s -t example.com --profile security
  
  # HTTPS security check (SSL + headers)
  %(prog)s -t example.com --profile https
  
  # Full port scan
  %(prog)s -t 192.168.1.1 --profile full
  
  # Custom scan
  %(prog)s -t example.com -s "ssl-cert,http-security-headers" -p 443
  
  # Multiple targets from file
  %(prog)s -f targets.txt --profile security
  
  # Quick scan
  %(prog)s -t example.com --profile quick

Profiles: quick, standard, full, security, https, web
        """
    )
    
    # Target options
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument("-t", "--target", help="Single target IP or domain")
    target_group.add_argument("-f", "--file", help="File containing targets")
    
    # Scan options
    parser.add_argument("-s", "--scripts", help="NSE scripts to run")
    parser.add_argument("-p", "--ports", help="Ports to scan (default: all)")
    parser.add_argument("--profile", choices=SCAN_PROFILES.keys(),
                       help="Use predefined scan profile")
    parser.add_argument("-o", "--output", default="./scan_results",
                       help="Output directory (default: ./scan_results)")
    parser.add_argument("-e", "--extra", help="Extra nmap arguments")
    
    # Display options
    parser.add_argument("--show-closed", action="store_true",
                       help="Show closed ports (default: only open)")
    parser.add_argument("--list-profiles", action="store_true",
                       help="List available scan profiles")
    parser.add_argument("--list-scripts", action="store_true",
                       help="List security-focused NSE scripts")
    
    args = parser.parse_args()
    
    print_banner()
    
    # List options
    if args.list_profiles:
        list_profiles()
        return
    
    if args.list_scripts:
        list_security_scripts()
        return
    
    # Validate target
    if not args.target and not args.file:
        parser.error("You must specify -t/--target or -f/--file (or use --list-profiles)")
    
    # Check nmap
    if not check_nmap():
        sys.exit(1)
    
    # Get scan settings from profile or arguments
    if args.profile:
        profile = SCAN_PROFILES[args.profile]
        scripts = args.scripts or profile["scripts"]
        ports = args.ports or profile["ports"]
        extra = args.extra or profile.get("extra", "")
        print(f"\n📌 Using profile: {args.profile}")
        print(f"   {profile['description']}")
    else:
        scripts = args.scripts or "ssl-cert,ssl-enum-ciphers,http-security-headers,http-headers"
        ports = args.ports  # Will default to all ports in run_nse_scan
        extra = args.extra or "-sV -T4"
    
    # Get targets
    if args.target:
        targets = [args.target]
        print(f"\n🎯 Target: {args.target}")
    else:
        targets = read_targets(args.file)
        print(f"\n🎯 Loaded {len(targets)} target(s) from {args.file}")
        for i, t in enumerate(targets, 1):
            print(f"   {i}. {t}")
    
    # Create output directory
    os.makedirs(args.output, exist_ok=True)
    print(f"\n📁 Output directory: {args.output}")
    
    # Scan configuration
    print(f"\n⚙️  Scan Configuration:")
    print(f"   Scripts: {scripts}")
    print(f"   Ports: {ports or 'ALL (1-65535)'}")
    print(f"   Show closed ports: {'Yes' if args.show_closed else 'No'}")
    if extra:
        print(f"   Extra args: {extra}")
    
    # Confirm
    print(f"\n❓ Ready to scan {len(targets)} target(s). Press Enter to continue or Ctrl+C to abort...")
    try:
        input()
    except KeyboardInterrupt:
        print("\n❌ Scan aborted")
        sys.exit(0)
    
    # Run scans
    successful = 0
    failed = 0
    results = []
    start_time = datetime.now()
    
    for i, target in enumerate(targets, 1):
        print(f"\n📊 Progress: {i}/{len(targets)}")
        success, output, output_base = run_nse_scan(
            target, scripts, ports, args.output, extra, args.show_closed
        )
        if success:
            successful += 1
            results.append({"target": target, "output": output_base})
        else:
            failed += 1
    
    # Summary
    end_time = datetime.now()
    duration = end_time - start_time
    
    print(f"\n{'═' * 70}")
    print("📊 FINAL SCAN SUMMARY")
    print(f"{'═' * 70}")
    print(f"   Total targets: {len(targets)}")
    print(f"   ✅ Successful: {successful}")
    print(f"   ❌ Failed: {failed}")
    print(f"   ⏱️  Duration: {duration}")
    print(f"   📁 Results saved in: {args.output}")
    print(f"\n   Output files per target:")
    for r in results:
        print(f"      • {r['target']}: {r['output']}.*")
    print(f"{'═' * 70}")


if __name__ == "__main__":
    main()
