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

# Helpers for clean reporting
strip_ansi() { sed -r 's/\x1B\[[0-9;]*[mK]//g'; }

section() { log_both "### $1 ###"; }

append_report() { strip_ansi >> "$FINAL_REPORT"; }

log_both() {
  # Print colored to console; plain to file
  local msg="$1"
  echo -e "$msg"
  echo -e "$msg" | append_report
}

record_severity() {
  case "$1" in
    Critical) ((CRITICAL_COUNT++)) ;;
    High)     ((HIGH_COUNT++)) ;;
    Medium)   ((MEDIUM_COUNT++)) ;;
    Low)      ((LOW_COUNT++)) ;;
  esac
}

# Global Variables
timestamp=$(date +"%Y%m%d_%H%M")
SCAN_RESULTS=""
NMAP_RESULTS="nmap_scan.txt"
NMAP_VULN_RESULTS="nmap_vuln_scan.txt"
FINAL_REPORT="net_scan_rpt_${timestamp}.txt"
CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0

# Tool Checks
check_dependencies() {
  local -a cmds=(nmap nikto figlet curl jq timeout grep awk sed tee)
  local missing=0
  for cmd in "${cmds[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "Error: '$cmd' is not installed. Please install it first."
      missing=1
    fi
  done
  [ "$missing" -eq 1 ] && exit 1
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


  local FIG_FONT="smblock"
  if ! figlet -f "$FIG_FONT" "X" >/dev/null 2>&1; then
    FIG_FONT="slant"
  fi


  echo -e "${RED}*****${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}*****${NC}"
  figlet -f "$FIG_FONT" "Network Security Scan Report"
  echo -e "${RED}*****${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${RED}*****${NC}"


  log_both "Target IP/Hostname: $target"
  log_both "Generated: $(date '+%Y-%m-%d %H:%M')"


  # TOC (printed to both, stored plain in file)
  log_both ""
  log_both "## Table of Contents"
  log_both "1. Operating System Detection"
  log_both "2. Nmap Scan"
  log_both "3. Open Ports & Web Services"
  log_both "4. Detected Open Ports & Services"
  log_both "5. SSL/TLS Configuration"
  log_both "6. Firewall Indicators"
  log_both "7. Vulnerability Findings"
  log_both "8. Detected Services Version Information"
  log_both "9. Recommendations for Remediation"
  log_both "10. Notes and Analyst Comments"
  log_both ""
}

write_summary_section() {
  section "Criticality Summary"


  log_both "Critical Findings: $CRITICAL_COUNT"
  log_both "High Findings:     $HIGH_COUNT"
  log_both "Medium Findings:   $MEDIUM_COUNT"
  log_both "Low Findings:      $LOW_COUNT"
  log_both ""
}

# Operating System Detection
write_os_section() {
  section "Operating System Detection"
  # OS detection may require sudo
  if command -v nmap >/dev/null 2>&1; then
    # Light OS guess using service fingerprints
    grep -E "Service Info: OS:" "$NMAP_RESULTS" | append_report

    # Deeper check (without sudo)
    echo -e "\n--- nmap -O (if permitted) ---" | append_report
    nmap -O "$1" 2>/dev/null | grep -E "OS details|Running|CPE:" | append_report
  else
    log_both "nmap not available for OS detection."
  fi
}

# Nmap Scan Section
write_nmap_scan_section() {
  local target="$1"
  local timestamp
  timestamp=$(date "+%Y-%m-%d %H:%M")

  section "Nmap Scan"
  log_both "Fast scan (-sV -F) for ${target} ad ${ts}"


  # Fast scan to identify basic open services
  nmap -sV -F "$target" | tee "$NMAP_RESULTS" | grep -E "^[0-9]+/tcp\s+open" | while read -r line; do
    echo -e "${CYAN}$line${NC}"
  done | append_report


  # Also dump full fast-scan into the report
  echo -e "\n--- Full Fast Scan Output ---" | append_report
  cat "$NMAP_RESULTS" | append_report

  log_both "\n--- Launching Vulnerability Script Scan ---"
  nmap -sV --script vuln "$target" | tee "$NMAP_VULN_RESULTS" >/dev/null
  echo -e "\n--- nmap --script vuln Output ---" | append_report
  cat "$NMAP_VULN_RESULTS" | append_report

  # Store the scan output in a global variable for later use (in vuln parsing)
  SCAN_RESULTS_SERVICES=$(cat "$NMAP_RESULTS")
  SCAN_RESULTS_VULNS=$(cat "$NMAP_VULN_RESULTS")
}

# Open Ports + Web Services (80/443) Section
write_ports_section() {
  section "Open Ports & Web Services"
  if grep -qE '\b(80|443)/tcp\s+open' "$NMAP_RESULTS"; then
    log_both "[+] Web Server detected. Launching Nikto (200s timeout)..."
    echo -e "\n--- Nikto Output ---" | append_report
    timeout 200s nikto -h "$1" 2>&1 | append_report
    log_both "[+] Nikto Scan Complete."
  else
    log_both "[+] No Web Server detected on common ports. Skipping Nikto scan."
  fi
}

# Ports and Services Results
write_ports_services_section() {
  section "Detected Open Ports & Services"

  echo "$SCAN_RESULTS_SERVICES" | grep "open" | while read -r line; do
    # Example line: 80/tcp   open  http    Apache httpd 2.4.49
    port=$(echo "$line" | awk '{print $1}')
    service=$(echo "$line" | awk '{print $3}')


    product_and_version=$(echo "$line" | cut -d ' ' -f4-)
    product_name=$(echo "$product_and_version" | awk '{NF--; print}')
    product_version=$(echo "$product_and_version" | awk '{print $NF}')

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
  section "SSL/TLS Configuration"
  if grep -qE '\b443/tcp\s+open' "$NMAP_RESULTS"; then
    log_both "Port 443 detected open. Summarizing TLS via nmap ssl-enum-ciphers..."
    echo -e "\n--- nmap --script ssl-enum-ciphers -p 443 ---" | append_report
    nmap --script ssl-enum-ciphers -p 443 "$1" 2>/dev/null \
      | grep -E "TLSv|cipher|ciphers" | append_report
  else
    log_both "No HTTPS service (443) detect in fast scan. Skipping TLS details."
  fi
}

# Firewall and Security Tools Detection
write_firewall_section() {
  section "Firewall Indicators"
  if grep -q "filtered" "$NMAP_RESULTS"; then
    log_both "Some ports appear filtered. A firewall or packet filter is likely present."
  else
    log_both "No clear indicators of packet filtering in fast scan."
  fi
}

# Vulnerabilities Section
write_vulns_section() {
  section "Vulnerability Findings"


  # Summarize CVEs that nmap scripts printed
  if grep -qE 'CVE-' "$NMAP_VULN_RESULTS"; then
    log_both "CVE references detected by nmap scripts:"
    grep -E 'CVE-' "$NMAP_VULN_RESULTS" \
      | sed 's/^[[:space:]]\+//; s/[[:space:]]\+$//' \
      | sort -u \
      | while read -r cve; do
          # Attempt detection of severity keywords in line
          if echo "$cve" | grep -qi "CVSS.*10\|Critical"; then
            record_severity Critical
          elif echo "$cve" | grep -qi "CVSS.*[7-9]\|High"; then
            record_severity High
          elif echo "$cve" | grep -qi "CVSS.*[4-6]\|Medium"; then
            record_severity Medium
          else
            record_severity Low
          fi
          echo "$cve" | append_report
       done
  else
    log_both "No CVE references found by nmap --script vuln."
  fi


  # Include the full vuln script output in the report
  echo -e "\n--- Full nmap --script vuln Output ---" | append_report
  cat "$NMAP_VULN_RESULTS" | append_report
}

# NVD Query Function
query_nvd() {
  local product="$1"
  local version="$2"
  local results_limit=3

  # Avoid empty queries
  [ -z "$product" ] && return
  [ -z "$version" ] && return

  # URL-encode spaces minimally
  local q
  q=$(printf "%s %s" "$product" "$version" | sed 's/ \+/%20/g')

  # Header in both console (color) and report (plain)
  log_both "\n### NVD Matches: ${product} ${version} ###"

  curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${q}&resultsPerPage=${results_limit}" \
  | jq -r '
     .vulnerabilities[]?.cve
     | {
         id: .id,
         desc: (.descriptions[]? | select(.lang=="en") | .value) // "No English description",
         score: (
           .metrics.cvssMetricV31[0]?.cvssData.baseScore //
           .metrics.cvssMetricV30[0]?.cvssData.baseScore //
           .metrics.cvssMetricV2[0]?.cvssData.baseScore // "N/A"
         )
       }
     | "- \(.id) - CVSS: \(.score)\n  \(.desc)"
   ' \
  | append_report # to file only keeping console clean
}

# Detected Services Version Information
write_versions_section() {
  section "Detected Services Version Information"


  if [ -n "$SCAN_RESULTS_SERVICES" ]; then
    echo "$SCAN_RESULTS_SERVICES" \
    | grep "open" \
    | awk '{printf "- Port %s: %s %s %s\n", $1, $3, $4, $5}' \
    | append_report
  else
    log_both "No Version Information available (did scan run?)."
  fi


  log_both ""
}

# Recommendations Section
write_recs_section() {
  section "Recommendations for Remediation"


  log_both "General Best Practices:"
  log_both "1. Keep all software updated to the latest stable versions."
  log_both "2. Change or disable default credentials immediately."
  log_both "3. Enforce strong password and SSH key policies."
  log_both "4. Implement a Firewall and restrict unnecessary open ports."
  log_both "5. Regularly back up configurations and critical data."

  # Conditional service-based recommendations
  if echo "$SCAN_RESULTS_SERVICES" | grep -qi "apache"; then
    log_both "6. Harden Apache: disable directory listing, apply security modules (mod_security)."
  fi
  if echo "$SCAN_RESULTS_SERVICES" | grep -qi "mysql"; then
    log_both "7. Secure MySQL: restrict root access, enforce SSL/TLS, and use least privilege accounts."
  fi
  if echo "$SCAN_RESULTS_SERVICES" | grep -qi "ssh"; then
    log_both "8. Secure SSH: disable root login, enforce key-based authentication, change default port if possible."
  fi


  log_both ""
}

# Notes and Analyst Comments
write_notes_section() {
  section "Notes & Analyst Comments"


  log_both "This section is reserved for analyst observations."
  log_both "Consider including:"
  log_both "- Business impact of identified vulnerabilities"
  log_both "- Potential false positives from automated scans"
  log_both "- Recommendations for further manual testing"
  log_both "- Any unusual network behavior noticed during scans"


  log_both "\n[Analyst Notes Placeholder]\n"

  # Manual notes to be viewed
  if [ -f "analyst_notes.txt" ]; then
    cat analyst_notes.txt | append_report
  fi
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
: > "$FINAL_REPORT"   # truncate/create fresh report

  write_header "$target"
  write_summary_section
  write_os_section "target"
  write_nmap_scan_section "$target"
  write_ports_section "$target"
  write_ports_services_section
  write_ssl_section "target"
  write_firewall_section
  write_vulns_section
  write_versions_section
  write_recs_section
  write_notes_section
  write_footer
}

# Execute Script
main "$@"
