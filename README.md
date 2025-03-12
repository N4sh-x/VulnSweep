# VulnSweep

VulnSweep is an automated vulnerability scanner designed for ethical security testing.  
It detects active hosts, scans ports, tests web servers, and checks for common vulnerabilities.

## Features
- Network and web scanning
- Stealth mode for low-detection scans
- Supports Nmap, Masscan, Nikto, SMB enumeration

## Requirements

- Python 3.x
- Tools: nmap, masscan, nikto, smbclient, netcat, gobuster, enum4linux

## Installation

1. Clone the repository:
```bash
git clone https://github.com/<username>/VulnSweep.git
```
2. Install any required Python dependencies
3. Ensure all required tools are installed and available in your system's PATH  

## Usage
Run the script with:
```bash
python3 VulnSweep.py -t <target> -o <output_directory> [options]
```
### Options
  `-t, --target` : Target network (CIDR) or single IP  
  `-o, --output` : Directory to save the scan report  
  `--gobuster-wordlist` : Path to the Gobuster wordlist (default: /usr/share/wordlists/dirb/common.txt)  
  `--stealth` : Enable stealth mode for Masscan & Nmap  
  `--scans` : Comma-separated list of scans (e.g., 'web,smb') or 'all' to run all scans  

## License
This project is licensed under the MIT License.

## ⚠ Disclaimer
This tool is intended **only for legal security assessments** and **authorized pentesting**.  
**Unauthorized use is strictly prohibited** and may violate laws.
