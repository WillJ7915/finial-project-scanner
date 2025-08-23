#!/usr/bin/env bash

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

# Helpers for clean reporting
strip_ansi() { sed -r 's/\x1B\[[0-9;]*[mK]//g'; }
section() { log_both "### $1 ###"; }
append_report() { strip_ansi >> "$FINAL_REPORT"; }
log_both() {
  # Print colored to console; plain to file
  local msg="$1"
  # To Console with color
  echo -e "$msg"
  # To File (clean)
  echo -e "$msg" | strip_ansi >> "$FINAL_REPORT"
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
target="$1"
timestamp=$(date +"%Y%m%d_%H%M")
SCAN_RESULTS="scan_results_${timestamp}.txt"
NMAP_RESULTS="nmap_scan_${timestamp}.txt"
NMAP_VULN_RESULTS="nmap_vuln_scan_${timestamp}.txt"
FINAL_REPORT="net_scan_rpt_${timestamp}.txt"
LOG_FILE="scan_log_${timestamp}.txt"
CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0
DEEP_SCAN=true # Full TCP/UDP/Service sweeps (enabled with 'true'; disabled with 'false')

# Dependency Check
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

# Header
write_header() {
    local target="$1"
    local FIG_FONT="smblock"
    if ! figlet -f "$FIG_FONT" "X" >/dev/null 2>&1; then FIG_FONT="slant"; fi
    echo -e "${RED}*****${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${NC}"
    figlet -f "$FIG_FONT" "Network Security Scan Report"
    echo -e "${RED}*****${WHITE}***${BLUE}***${RED}***${WHITE}***${BLUE}***${NC}"
    log_both "Target IP/Hostname: $target"
    log_both "Generated: $(date '+%Y-%m-%d %H:%M')"
    log_both ""
    log_both "## Table of Contents"
    log_both "1. Operating System Detection"
    log_both "2. Nmap Scan"
    log_both "3. Open Ports & Web Services"
    log_both "4. Detected Services & Versions"
    log_both "5. SSL/TLS Configuration"
    log_both "6. Firewall Indicators"
    log_both "7. Vulnerability Findings & NVD"
    log_both "8. Recommendations"
    log_both "9. Analyst Notes"
    log_both "10. Criticality Summary"
    log_both ""
}

# Perform Nmap Scan
nmap_scan() {
    echo -e "${GREEN}[*] Running initial nmap scan on $target...${NC}" | tee -a "$LOG_FILE"
    nmap -sS -sV -F -O --script=vuln --script-args=unsafe=1 "$target" -oN "$SCAN_RESULTS"
    nmap -sV -F "$target" -oN "$NMAP_RESULTS"
    if [[ "$DEEP_SCAN" == "true" ]]; then
        echo "[*] Running deep TCP/UDP scan..." | tee -a "$LOG_FILE"
        nmap -sS -sV -p- --open --reason --script vuln,http-vuln*,dns*,smtp* "$target" >> "$SCAN_RESULTS"
        nmap -sU --top-ports 50 --open --reason "$target" >> "$SCAN_RESULTS"
        nmap --script ftp*,mysql*,smb*,http* "$target" >> "$SCAN_RESULTS"
    fi
    # Run vulnerability NSE scripts
    nmap -sV --script vuln,ftp-anon,ssh2-enum-algos,http-config-backup,mysql-info,smb-enum-shares "$target" | tee "$NMAP_VULN_RESULTS" >/dev/null
}

# Run Nikto scan for web ports detected
run_nikto_scan() {
    #Check if port 80 or 443 is/are open
    if grep -qE '\b(80|443)/tcp\s+open' "$NMAP_RESULTS"; then
        log_both "[+] Web server detected. Launching Nikto scan (200s timeout)..."
        if ! timeout 200s nikto -h "$target" 2>&1 | append_report; then
            log_both "[!] Nikto scan failed for $target (possible timeout or connectivity issue)."
            return 1
        fi
        log_both "[+] Nikto scan complete."
    else
        log_both "[+] No web server detected on common ports. Skipping Nikto scan."
    fi
}

# Network Infrastructure Mapping
network_infra() {
    echo "[*] Mapping network infrastructure..." | tee -a "$LOG_FILE"
    nmap --traceroute "$target" -oN "nmap_traceroute_${timestamp}.txt"
    traceroute -n "$target" > "traceroute_${timestamp}.txt"
    cat "traceroute_${timestamp}.txt" >> "$FINAL_REPORT"
    if command -v curl >/dev/null 2>&1; then
        echo -e "\n[*] Enriching with IP/ASN details..." | tee -a "$LOG_FILE"
        curl -s ipinfo.io/$target >> "$SCAN_RESULTS"
    fi
}

# Operating System Detection
write_os_section() {
    section "Operating System Detection"
    if [ -f "$NMAP_RESULTS" ]; then
        grep -E "Service Info: OS:" "$NMAP_RESULTS" | while IFS= read -r line; do
            log_both "$line"
        done
    fi
}

# Ports & services
write_ports_services_section() {
    section "Detected Open Ports & Services"
    local scan="$NMAP_RESULTS"
    cat "$scan" | grep "open" | while read -r line; do
        port=$(echo "$line" | awk '{print $1}')
        service=$(echo "$line" | awk '{print $3}')
        product_and_version=$(echo "$line" | cut -d ' ' -f4-)
        log_both "- Port $port: Service=$service, Info=$product_and_version"
        if [ -n "$product_and_version" ]; then
            product_name=$(echo "$product_and_version" | awk '{NF--; print}')
            product_version=$(echo "$product_and_version" | awk '{print $NF}')
            query_nvd "$product_name" "$product_version"
        fi
    done
}

# SSL/TLS
write_ssl_section() {
    section "SSL/TLS Configuration"
    if grep -qE '\b443/tcp\s+open' "$NMAP_RESULTS"; then
        log_both "Port 443 detected open. Summarizing TLS..."
        nmap --script ssl-enum-ciphers -p 443 "$target" 2>/dev/null | append_report
    else
        log_both "No HTTPS service detected. Skipping TLS."
    fi
}

# Firewall detection
write_firewall_section() {
    section "Firewall Indicators"
    if grep -q "filtered" "$NMAP_RESULTS"; then
        log_both "Some ports appear filtered. Firewall likely present."
    else
        log_both "No clear firewall indicators detected."
    fi
}

# Vulnerabilities Section
write_vulns_section() {
    section "Vulnerability Findings"
    if grep -qE 'CVE-' "$NMAP_VULN_RESULTS"; then
        log_both "CVE references detected:"
        grep -E 'CVE-' "$NMAP_VULN_RESULTS" | sort -u | while read -r cve; do
            log_both "$cve"
            # Lookup recommended mitigation dynamically
            case "$cve" in
                *CVE-2021-44228*) log_both "Recommendation: Patch log4j to 2.17.1 or later." ;;
                *CVE-2022-22965*) log_both "Recommendation: Apply Spring4Shell patch." ;;
            esac
        done
    else
        log_both "No CVEs found by nmap scripts."
    fi
    echo -e "\n--- Full nmap vuln output ---" | append_report
    cat "$NMAP_VULN_RESULTS" | append_report
}

# NVD Query
query_nvd() {
    local product="$1"
    local version="$2"
    [ -z "$product" ] && return
    [ -z "$version" ] && return
    log_both "Querying NVD for $product $version..."
    local search_query
    search_query=$(printf "%s %s" "$product" "$version" | sed 's/ \+/%20/g')
    local json
    json=$(curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${search_query}&resultsPerPage=3")
    if [[ -z "$json" ]] || echo "$json" | jq -e '.message' >/dev/null; then
        log_both "[!] NVD API error or no results."
        return
    fi
    echo "$json" | jq -r '.vulnerabilities[] | "  CVE ID: \(.cve.id)\n  Description: \((.cve.descriptions[] | select(.lang=="en")).value)\n  Severity: \(
        if .cve.metrics.cvssMetricV31 then .cve.metrics.cvssMetricV31[0].cvssData.baseSeverity
        elif .cve.metrics.cvssMetricV2 then .cve.metrics.cvssMetricV2[0].cvssData.baseSeverity
        else "Unknown" end)"' | while read -r line; do
        log_both "$line"
        if [[ "$line" =~ ^Severity:\ (.*) ]]; then
            record_severity "${BASH_REMATCH[1]}"
        fi
    done
    # Prevent hitting API rate limits
    sleep 1
}

# Recommendations
write_recs_section() {
    section "Recommendations"
    log_both "General Best Practices:"
    log_both "1. Keep software updated."
    log_both "2. Change default credentials."
    log_both "3. Enforce strong passwords and SSH keys."
    log_both "4. Restrict unnecessary ports via firewall."
    log_both "5. Regular backups."

    # Dynamic remediation notes from CVE scan
    if grep -q "CVE-" "$NMAP_VULN_RESULTS"; then
        log_both "Mitigation notes for detected CVEs:"
        grep -E 'CVE-' "$NMAP_VULN_RESULTS" | sort -u | while read -r cve; do
            case "$cve" in
                *CVE-2021-44228*) log_both "  $cve → Patch log4j to 2.17.1+" ;;
                *CVE-2022-22965*) log_both "  $cve → Apply Spring4Shell patch." ;;
                *) log_both "  $cve → Check vendor advisory for mitigation." ;;
            esac
        done
    fi
}

# Notes & Analyst Comments
write_notes_section() {
    section "Analyst Notes"
    log_both "Consider business impact, false positives, further testing, unusual network behavior."
    [ -f "analyst_notes.txt" ] && cat analyst_notes.txt | append_report
}

# Summary
write_summary_section() {
    section "Criticality Summary"
    log_both "Critical Findings: $CRITICAL_COUNT"
    log_both "High Findings:     $HIGH_COUNT"
    log_both "Medium Findings:   $MEDIUM_COUNT"
    log_both "Low Findings:      $LOW_COUNT"
    log_both "See detailed logs in:"
    log_both "- $SCAN_RESULTS"
    log_both "- $NMAP_RESULTS"
    log_both "- $NMAP_VULN_RESULTS"
}

# Input validation
validate_input() {
    if [ "$#" -ne 1 ]; then
        echo "Usage: $0 <target_ip_or_hostname>" >&2
        exit 1
    fi
    local input="$1"
    if ! [[ "$input" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ || "$input" =~ ^[a-zA-Z0-9.-]+$ ]]; then
        echo "Error: Invalid IP or hostname."
        exit 1
    fi
}

# Footer
write_footer() {
    section "Ethical Considerations"
    log_both "- Authorized use only. Do not scan without permission."
    log_both "- Follow legal and ethical guidelines."
    log_both ""
    echo -e "${RED}***${WHITE}***${BLUE}***${NC}"
    echo "End of Report - Generated on: $(date)"
    echo -e "${RED}***${WHITE}***${BLUE}***${NC}"
}

# Main
main() {
    validate_input "$@"
    check_dependencies
    target="$1"
    : > "$FINAL_REPORT"
  if [[ -f "$1" ]]; then
    # Input is a file containing multiple targets
    while read -r target; do
    [[ -z "$target" ]] && continue 
    write_header "$target"
    nmap_scan "$target"
    run_nikto_scan "$target"
    network_infra "$target"
    write_os_section "$target"
    write_ports_services_section "$target"
    write_ssl_section "$target"
    write_firewall_section "$target"
    write_vulns_section "$target"
    write_recs_section
    write_notes_section
    write_summary_section
    write_footer
    done < "$1"
  else
    # Single host
    target="$1"
    write_header "$target"
    nmap_scan "$target"
    run_nikto_scan "$target"
    network_infra "$target"
    write_os_section "$target"
    write_ports_services_section "$target"
    write_ssl_section "$target"
    write_firewall_section "$target"
    write_vulns_section "$target"
    write_recs_section
    write_notes_section
    write_summary_section
    write_footer
  fi
}

main "$@"
