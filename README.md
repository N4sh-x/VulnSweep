# VulnSweep

VulnSweep is an automated vulnerability scanner designed for ethical security testing.  
It detects active hosts, scans ports, tests web servers, and checks for common vulnerabilities.

## ⚠ Disclaimer
This tool is intended **only for legal security assessments** and **authorized pentesting**.  
**Unauthorized use is strictly prohibited** and may violate laws.

## 📌 Features
- Network and web scanning
- Stealth mode for low-detection scans
- Supports Nmap, Masscan, Nikto, SMB enumeration

## 🚀 Usage
Run the script with:
```bash
python3 VulnSweep.py -t <target> -o <output_directory> [options]
