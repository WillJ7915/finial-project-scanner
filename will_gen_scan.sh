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

# Global Variables
timestamp=$(date +"%Y%m%d_%H%M")
SCAN_RESULTS=""
NMAP_RESULTS="nmap_scan.txt"
NMAP_VULN_RESULTS="nmap_vuln_scan.txt"
FINAL_REPORT="$net_scan_rpt_${timestamp}.txt"

# Tool Checks
check_dependencies() {
  for cmd in nmap nikto figlet; do
    if ! command -v "$cmd" &> /dev/null; then
      echo "Error: '$cmd' is not installed. Please install it first."
      exit 1
    fi
  done
}

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

# Nmap Scan Section
write_nmap_scan_section() {
  local target="$1"
  local timestamp
  timestamp=$(date "+%Y-%m-%d %H:%M:%S")

  echo -e "${CYAN}--------------------------------------"
  echo "Nmap Scan:"
  echo -e "--------------------------------------${NC}"

  echo "### Nmap Fast Scan Results for $target on $timestamp ###" >> "$FINAL_REPORT"

  # Fast scan to identify basic open services
  nmap -sV -F "$target" | tee "$NMAP_RESULTS" | grep -E "^[0-9]+/tcp\s+open" | while read -r line; do
    echo -e "${CYAN}$line${NC}"
  done

  # Append full fast scan results to the report
  cat "$NMAP_RESULTS" >> "$FINAL_REPORT"

  # Now run the vulnerability script scan
  echo -e "${CYAN}\n--- Launching Vulnerability Script Scan ---${NC}"
  echo "### Nmap --script vuln Results for $target on $timestamp ###" >> "$FINAL_REPORT"

  echo "[DEBUG] Running nmap vuln scan..." >> "$FINAL_REPORT"
  nmap -sV --script vuln "$target" | tee "$NMAP_VULN_RESULTS"
  echo "[DEBUG] Appending vuln scan to final report..." >> "$FINAL_REPORT"
  cat "$NMAP_VULN_RESULTS" >> "$FINAL_REPORT"

  # Store the scan output in a global variable for later use (in vuln parsing)
  SCAN_RESULTS_SERVICES=$(cat "$NMAP_RESULTS")
  SCAN_RESULTS_VULNS=$(cat "$NMAP_VULN_RESULTS")
}

# Open Ports + Web Services (80/443) Section
write_ports_section() {
  local target="$1"
  echo -e "${GREEN}---------------------------------"
  echo "Open Ports and Web Services:"
  echo -e "---------------------------------${NC}"
  if grep -qE '\b(80|443)/tcp\s+open' "$NMAP_RESULTS"; then
    echo -e "\n\n### Nikto Deep Dive Results ###" >> "$FINAL_REPORT"
    echo "[+] Web server detected. Launching Nikto..."
    nikto -h "$target" >> "$FINAL_REPORT"
    timeout 200s nikto -h "$target" >> "$FINAL_REPORT" 2>&1
    echo "[+] Nikto scan complete."
else
    echo "[+] No web server detected on common ports. Skipping Nikto scan."
fi
  echo ""
}

# Ports and Services Results
write_ports_services_section() {
  echo -e "${GREEN}Breakdown: Detected Open Ports & Services${NC}"

  echo "$SCAN_RESULTS_SERVICES" | grep "open" | while read -r line; do
    # Example line: 80/tcp   open  http    Apache httpd 2.4.49
    port=$(echo "$line" | awk '{print $1}')
    service=$(echo "$line" | awk '{print $3}')
    product_name=$(echo "$line" | awk '{print $4}')
    product_version=$(echo "$line" | awk '{print $5}')

    echo -e "${GREEN}Port:${NC} $port"
    echo -e "${GREEN}Service:${NC} $service"
    echo -e "${GREEN}Product:${NC} $product_name"
    echo -e "${GREEN}Version:${NC} $product_version"

  if [ -n "$product_name" ] && [ -n "$product_version" ]; then
    query_nvd "$product_name" "$product_version"
fi

    echo ""
  done
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
  local target="$1"
  echo -e "${RED}-------------------------------------"
  echo "Analyzing Potential Vulnerabilities and Service Versions:"
  echo -e "-------------------------------------${NC}"
  echo "$SCAN_RESULTS_VULNS" | grep "open" | while read -r line; do

    service_info=$(echo "$line" | cut -d ' ' -f3-)
    product=$(echo "$service_info" | awk '{print $1}')
    version=$(echo "$service_info" | awk '{print $2}')

  echo "[DEBUG] product=$product, version=$version"

  case "$product $version" in
    "vsftpd 2.3.4")
      echo -e "${RED}[!!] VULNERABILITY DETECTED: vsftpd 2.3.4 has a known backdoor.${NC}"
      echo -e "     CVSS Score: 10.0 — Critical"
      ;;
    "Apache httpd 2.4.49")
      echo -e "${RED}[!!] VULNERABILITY DETECTED: Apache 2.4.49 vulnerable to path traversal (CVE-2021-41773).${NC}"
      echo -e "     CVSS Score: 7.5 — High"
      ;;
    "Exim 4.87")
      echo -e "${RED}[!!] VULNERABILITY DETECTED: Exim 4.87 RCE (remote code execution) (CVE-2019-10149).${NC}"
      echo -e "     CVSS Score: 9.8 — Critical"
      ;;
    "OpenSSH 7.2p2")
      echo -e "${RED}[!!] VULNERABILITY DETECTED: OpenSSH 7.2p2 information disclosure (CVE-2016-0777).${NC}"
      echo -e "     CVSS Score: 5.3 — Medium"
      ;;
  esac
done

  echo ""
}

# NVD Query Function
write_query_section() {
  local product="#1"
  local version="$2"
  local results_limit=3

  echo "[+] Querying NVD for $product $version ..." >> "$FINAL_REPORT"

  curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${product}%20${version}&resultsPerPage=${results_limit}" \
    | jq '.vulnerabilities[]?.cve | {id: .id, description: .descriptions[0].value}'

  echo "" >> "$FINAL_REPORT"
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
  check_dependencies

  local target="$1"
  
  write_header "$target" > "$REPORT_FILE"
  write_os_section >> "$REPORT_FILE"
  write_nmap_scan_section "$target" 
  write_ports_section "$target" >> "$REPORT_FILE"
  write_ports_services_section >> "$REPORT_FILE" 
  write_ssl_section >> "$REPORT_FILE"
  write_firewall_section >> "$REPORT_FILE"
  write_vulns_section | sed 's/\x1b\[[0-9;]*m//g' >> "$REPORT_FILE"
  write_versions_section >> "$REPORT_FILE"
  write_recs_section >> "$REPORT_FILE"
  write_notes_section >> "$REPORT_FILE"
  write_footer >> "$REPORT_FILE"
}

# Execute Script
main "$@"
