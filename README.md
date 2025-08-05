# Network Security Vulnerability Scanner and Report Generator
**Author:** William Jones
**Course:** Shell Scripting for Technologists
**Repository:**
- [HTTPS Link](https://github.com/WillJ7915/finial-project-scanner.git)
- SSH: `git@github.com:WillJ7915/finial-project-scanner.git`

---

## Description

This Bash script is a comprehensive **network security vulnerability scanning tool** designed for educational use in a UAT Shell Scripting for Technologists course. It takes an IP address or hostname as input and generates a structured security report.

The script performs the following: 
- Validates input
- Scans open ports and services using `nmap`
- Displays simulated details for SSL/TLS, OS detection, firewall tools and vulnerabilities
- Outputs a well-formatted report to `net_scan_rpt.txt`

---

## Features

- **Input Validation**
- **Color-coded terminal output** (ANSI escape codes)
- **ASCII Banner** via `figlet`
- **Nmap Scanning**: 
  - Fast scan (`-sV -F`)
  - Vulnerability detection using `--script vuln`
- **Simulated Details**:
  - OS fingerprinting
  - SSL/TLS configuration checks
  - Firewall & IDS/IPS detection
- **Vulnerability Detection**:
  - Specific version checks for known CVEs
  - Color-coded severity (based on CVSS)
  - CVSS scores and CVE references included
- **Per-Port & Per-Service Breakout**
- **Analyst Recommendations and Notes**
- **Timestamped Output**
- **Final Report** saved as `net_scan_rpt.txt

 ---

 ## Requirements

 - **Operating System:** Linux (Ubuntu recommended)
 - **Packages (must be installed):**
   - `nmap`
   - `figlet`
   - `nikto` *(for web vulnerability scanning)*
  
Install prerequisits using:

```bash
sudo apt update
sudo apt install nmap figlet nikto
