#!/usr/bin/env python3
"""
VulnSweep - Automated Vulnerability Scanner
Author: https://github.com/N4sh-x
License: MIT
Version: 1.1
GitHub: https://github.com/N4sh-x/VulnSweep

Description:
Automated vulnerability scanner for network and web targets.
Detects active hosts, scans ports, tests web servers, and checks for common vulnerabilities.

Requirements:
    see "REQUIRED_TOOLS"
Usage:
    python3 auto-vulnscanner.py -t <network/IP> -o <output_directory> [--gobuster-wordlist <path>] [--stealth] [--scans web, smb]

Options:
    --gobuster-wordlist <path>   : Path to wordlist for Gobuster (default: /usr/share/wordlists/dirb/common.txt)
    --stealth                    : Enables stealth mode for Masscan & Nmap
    --scans <scan1,scan2,...>    : Select specific scans (web, smb) instead of running all

History:
    12.03.2025; Initial version
"""

import os
import subprocess
import re
import shutil
import argparse
import json
from datetime import datetime

# Required tools
REQUIRED_TOOLS = ["nmap", "masscan", "nikto", "smbclient", "netcat", "gobuster", "enum4linux"]

# ASCII Banner
def print_banner():
    banner = """

  _   __       __       ____                      
 | | / /__ __ / /___   / __/_    __ ___  ___  ___ 
 | |/ // // // // _ \ _\ \ | |/|/ // -_)/ -_)/ _ \
 |___/ \_,_//_//_//_//___/ |__,__/ \__/ \__// .__/
                                           /_/  

  StealthScanX - Automated Vulnerability Scanner
    """
    print(banner)

def check_and_install_tools():
    for tool in REQUIRED_TOOLS:
        if shutil.which(tool) is None:
            print(f"[-] {tool} not found. Please install it.")
            exit(1)

def run_scan(command):
    try:
        return subprocess.getoutput(command)
    except Exception as e:
        print(f"[ERROR] Failed to run command: {command}\n{e}")
        return ""

def save_report(data, output_dir, format="txt"):
    os.makedirs(output_dir, exist_ok=True)
    date = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_file = os.path.join(output_dir, f"scan_report_{date}.{format}")
    
    if format == "json":
        with open(report_file, "w") as f:
            json.dump({"scan_results": data}, f, indent=4)
    else:
        with open(report_file, "w") as f:
            f.write(data)
    
    print(f"[+] Scan completed. Report saved at: {report_file}")

def print_help():
    help_text = """
Auto Vulnerability Scanner - Help Menu

Usage:
    python3 auto-vulnscanner.py -t <network/IP> -o <output_directory> [options]

Options:
    -t, --target <network/IP>     Target network (CIDR) or single IP
    -o, --output <directory>      Directory to save scan report
    --gobuster-wordlist <path>    Path to wordlist for Gobuster (default: /usr/share/wordlists/dirb/common.txt)
    --stealth                     Enables stealth mode for Masscan & Nmap
    --scans <scan1,scan2,...>     Select specific scans (web, smb) instead of running all

Example:
    python3 auto-vulnscanner.py -t 192.168.1.0/24 -o reports --stealth --scans web,smb
"""
    print(help_text)

def main():
    parser = argparse.ArgumentParser(description="Auto Vulnerability Scanner", add_help=False)
    parser.add_argument("-t", "--target", required=True, help="Target network (CIDR) or single IP")
    parser.add_argument("-o", "--output", required=True, help="Directory to save the scan report")
    parser.add_argument("--gobuster-wordlist", default="/usr/share/wordlists/dirb/common.txt", help="Wordlist for Gobuster")
    parser.add_argument("--stealth", action="store_true", help="Enable stealth mode for Masscan & Nmap")
    parser.add_argument("--scans", default="all", help="Comma-separated list of scans (e.g., 'web,smb') or 'all'")
    parser.add_argument("-h", "--help", action="store_true", help="Show help menu")
    args = parser.parse_args()

    if args.help:
        print_help()
        exit(0)

    print_banner()

    target = args.target.strip()
    output_directory = os.path.expanduser(args.output.strip())
    gobuster_wordlist = args.gobuster_wordlist
    stealth_mode = args.stealth
    enabled_scans = args.scans.split(",")
    check_and_install_tools()

    is_network = "/" in target
    print(f"[+] Target: {'Network' if is_network else 'Single IP'}")
    
    if is_network:
        rate = "10" if stealth_mode else "10000"
        max_rate = f"--max-rate={rate}"
        ports = "-p1-1024" if stealth_mode else "-p1-65535"
        masscan_results = run_scan(f"masscan {ports} {max_rate} --wait 10 {target}")
    else:
        masscan_results = run_scan(f"masscan -p22,80,443,3389,445,8080,8443 --max-rate=5 --wait 10 {target}")
    
    open_ports = {}
    for line in masscan_results.split("\n"):
        match = re.search(r"Discovered open port (\d+)/tcp on (\d+\.\d+\.\d+\.\d+)", line)
        if match:
            port, ip = match.groups()
            port = int(port)
            open_ports.setdefault(ip, []).append(port)
    
    if not open_ports:
        print("[-] No open ports found.")
        exit(1)
    
    for ip, ports in open_ports.items():
        port_list = ",".join(map(str, ports))
        print(f"[+] Nmap scan for {ip} on ports: {port_list}")
        scan_flags = "-Pn -sS -sV --version-light -T1 --spoof-mac 00:11:22:33:44:55 --max-retries 2 --scan-delay 500ms --max-rate 5" if stealth_mode else "-Pn -sC -sV"
        report_data = run_scan(f"nmap {scan_flags} -p {port_list} {ip}")
    
    save_report(report_data, output_directory, "txt")

if __name__ == "__main__":
    main()
