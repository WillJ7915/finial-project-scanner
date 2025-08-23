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
- **Target Flexibility**
  - Scan a sigle target (IP or Hostname)
  - Supply a file of multiple targets for batch scanning
- **Network Mapping & Service Discovery** 
  - Host discovery and port scanning with nmap
  - Service/version detection
  - Deep Scan for comprehensive TCP/UDP analysis
  - Vulnerability detection using `--script vuln`
- **Details Collected**:
  - OS fingerprinting (requires root)
  - SSL/TLS configuration checks
  - Firewall & IDS/IPS detection
  - Traceroute performed via both nmap --traceroute and traceroute
  - Results logged and appended to the final report
- **Geolocation and ASN Lookup**
  - IP enrichment using ipinfo.io API
- **Vulnerability Detection**
  - CVE lookups from NVD REST API
  - Color-coded severity (based on CVSS)
  - CVSS scores and CVE references included
  - Dynamic mitigation notes for high-profile threats
- **Per-Port & Per-Service Breakout**
- **Analyst Recommendations and Notes**
  - Final REport includes:
    - Table of Contents
    - Scan Summary
    - Vulnerability Analysis (with remediation)
    - Recommendations
    - Appendices with raw scan outputs
- **Timestamped Output**
- **Supplemental Reports**
  - nmap_scan.txt
  - nmap_vuln_scan.txt
  - traceroute_TIMESTAMP.txt (merged into final report)

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
 - **Privileges**
   - Some features (-sS, -O, --traceroute) require root
   - Run with sudo for full feature set
  
Install prerequisits using:

```bash
sudo apt update
sudo apt install nmap figlet nikto curl jq coreutils

---

## Configuration

- **FINAL_REPORT** 
  - report filename prefix (default: net_scan_rpt_YYYYMMDD_HHMM.txt)
- **Supplemental Reports (detailed logs)
  - scan_results_<timestamp>.txt – basic results
  - nmap_scan_<timestamp>.txt – main nmap scan output
  - nmap_vuln_scan_<timestamp>.txt – vulnerability scripts
  - nmap_traceroute_<timestamp>.txt – nmap traceroute results
  - traceroute_<timestamp>.txt – standalone traceroute results
  - scan_log_<timestamp>.txt – script execution log
- **Deep_Scan**
  - DEEP_SCAN=true
    - If true, performs full TCP/UDP scanning with service versioning
    - If false, runs a faster, lightweight scan
- **Rate Limiting for NVD API
  - Built-in sleep 1 between queries prevents API throttling
- **FIG_FONT**
  - figlet font (smblock, falls back to slant)
- **Nikto timeout** 
  - default 200s
- **NVD CVE Query**
  - defaults to 3 results per detected service
- **Rate Limiting**
  - sleep 1 introduced in query_nvd() to avoid API throttling

---

## Limitations

- Requires internet access for NVD CVE lookups.
- Root privileges required for SYN scans, OS detection, and traceroute.
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
- Dynamic remediation mapping in recommendations section

---

## Disclaimer

- This tool is intended for authorized penetration testing, research, and cybersecurity education.
- Unauthorized use against systems you do not own or have explicit permission to test is prohibited. 
