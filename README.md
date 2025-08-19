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

## Usage

- **Basic Usage
  - Run script with the following command: ./will_gen_rpt.sh <target ip or hostname>

---

## Features

- **Input Validation**
- **Color-coded terminal output** (ANSI escape codes)
- **ASCII Banner** via `figlet`
- **Nmap Scanning**: 
  - Fast scan (`-sV -F`)
  - Vulnerability detection using `--script vuln`
- **Details Collected**:
  - OS fingerprinting
  - SSL/TLS configuration checks
  - Firewall & IDS/IPS detection
- **Vulnerability Detection**:
  - Live **NVD CVE lookups** via `curl` + `jq`
  - Color-coded severity (based on CVSS)
  - CVSS scores and CVE references included
- **Per-Port & Per-Service Breakout**
- **Analyst Recommendations and Notes**
- **Timestamped Output**
- **Final Report** saved as `net_scan_rpt_YYYYMMDD_HHMM.txt
- **Supplemental Reports**
  - nmap_scan.txt
  - nmap_vuln_scan.txt

 ---

## Requirements

 - **Operating System:** Linux (Ubuntu recommended)
 - **Packages (must be installed):**
   - `nmap`
   - `figlet`
   - `nikto` *(for web vulnerability scanning)*
   - `curl` *(for NVD API queries)*
   - `jq` *(for JSON parsing)*
   - Core text utilities: `grep`, `awk`, `sed`, `tee`, `timeout`
  
Install prerequisits using:

```bash
sudo apt update
sudo apt install nmap figlet nikto curl jq coreutils

---

## Configuration

- **FINAL_REPORT** 
  - report filename prefix (default: net_scan_rpt_YYYYMMDD_HHMM.txt)
- **FIG_FONT**
  - figlet font (smblock, falls back to slant)
- **Nikto timeout** 
  - default 200s
- **NVD CVE Query**
  - defaults to 3 results per detected service

---

## Limitations

- Requires internet access for NVD CVE lookups.
- Some nmap options (e.g., OS detection -O) may require sudo.
- Nikto scans are noisy and may trigger firewalls/IDS alerts.
- Designed for educational purposes only — not a substitute for enterprise-grade vulnerability scanners.

---

## Contributing

- **Pull requests and suggestions are welcome. Ideas for improvement:**
  - Support scanning multiple targets in one run
  - Add HTML/JSON/CSV output formats
  - Integrate additional Nmap script families (http-*, dns-*, etc.)
  - Expand analyst recommendations by service type
  - Dockerize for easier setup

---

## Future Enhancements

- Parallel scanning of multiple hosts
- Exporting vulnerabilities to CSV/JSON for further analysis
- Integration with Shodan API for external recon
- Improved report formatting (markdown/HTML templates)
