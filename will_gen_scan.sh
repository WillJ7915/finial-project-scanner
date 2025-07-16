#!/bin/bash

# GitHub Repository Added
# HTTPS: https://github.com/WillJ7915/finial-project-scanner.git
# SSH: git@github.com:WillJ7915/finial-project-scanner.git

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'
# No Color / Reset


# Print Usage and Exit if Arguments are Invalid
validate_input() {
  if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <target_ip_or_hostname>" >&2
    exit 1
  fi
}

# Header
write_header() {
  local target="$1"
  echo -e "${RED}*****${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}*****${NC}"
  figlet -f smblock "Network Security Scan Report"
  echo -e "${RED}*****${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}*****${NC}"
  echo ""
  echo "Target IP/Hostname: $target"
  echo ""
}

# Operating System Detection
write_os_section() {
  echo -e "${BLUE}---------------------------"
  echo "Operating System Detection:"
  echo -e "---------------------------${NC}"
  echo "Detected OS: Linux (Kernel 5.x)"
  echo "Accuracy: 90%"
  echo ""
}

# Open Ports and Services Section
write_ports_section() {
  local target="$1"
  echo -e "${GREEN}---------------------------------"
  echo "Open Ports and Detected Services:"
  echo -e "---------------------------------${NC}"
# Run Nmap Scan and Append Open Ports/Services
  nmap -sV "$target" | grep "open" | while read -r line; do
    echo -e "${GREEN}$line${NC}"
  done
  echo ""
}

# SSL/TLS Configuration
write_ssl_section() {
  echo -e "${YELLOW}----------------------"
  echo "SSL/TLS Configuration:"
  echo -e "----------------------${NC}"
  echo "Port 443: TLS 1.2 Enabled, TLS 1.0/1.1 Disabled"
  echo "Self-Signed Certificate Detected"
  echo "Certificate Expiry: 30 days remaining"
  echo ""
}

# Firewall and Security Tools Detection
write_firewall_section() {
  echo -e "${MAGENTA}-------------------------------------"
  echo "Firewall and Security Tools Detected:"
  echo -e "-------------------------------------${NC}"
  echo "UFW Firewall - Active"
  echo "Fail2Ban Service - Running"
  echo "SNORT IDS - Not Detected"
  echo ""
}

# Vulnerabilities Section
write_vulns_section() {
  echo -e "${RED}-------------------------------------"
  echo "Potential Vulnerabilities Identified:"
  echo -e "-------------------------------------${NC}"
  echo "CVE-2023-XXXX - Outdated Web Server"
  echo "Default Credentials - FTP Server"
  echo "Weak SSH Key - Possible brute-force vulnerability"
  echo ""
}

# Detected Services Version Information
write_versions_section() {
  echo -e "${CYAN}--------------------------------------"
  echo "Detected Services Version Information:"
  echo -e "--------------------------------------${NC}"
  echo "Apache HTTP Server 2.4.29"
  echo "OpenSSH 7.6p1 Ubuntu"
  echo "MySQL Server 5.7.33"
  echo ""
}

# Recommendations Section
write_recs_section() {
  echo -e "${NC}--------------------------------"
  echo "Recommendations for Remediation:"
  echo -e "--------------------------------"
  echo "1. Update all software to the latest versions."
  echo "2. Change default credentials immediately."
  echo "3. Implement a firewall."
  echo ""
}

# Notes and Analyst Comments
write_notes_section() {
  echo "---------------------------"
  echo "Notes and Analyst Comments:"
  echo "---------------------------"
  echo ""
}

# Footer
write_footer() {
  echo -e "${RED}***${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}****${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}***${NC}"
  echo "End of Report - Generated on: $(date)"
  echo -e "${RED}***${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}****${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}***${NC}"
}

# Main Function
main() {
  validate_input "$@"

  local target="$1"
  local REPORT_FILE="net_scan_rpt.txt"

  write_header "$target" > "$REPORT_FILE"
  write_os_section >> "$REPORT_FILE"
  write_ports_section "$target" >> "$REPORT_FILE"
  write_ssl_section >> "$REPORT_FILE"
  write_firewall_section >> "$REPORT_FILE"
  write_vulns_section >> "$REPORT_FILE"
  write_versions_section >> "$REPORT_FILE"
  write_recs_section >> "$REPORT_FILE"
  write_notes_section >> "$REPORT_FILE"
  write_footer >> "$REPORT_FILE"
}

# Execute Script
main "$@"
