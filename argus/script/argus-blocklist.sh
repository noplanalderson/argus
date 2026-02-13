#!/bin/bash

#################################################################
# ARGUS Multi-Blocklist Automation Script
# Copyright (C) 2025 M. Ridwan Na'im
#
# Download multiple blocklists and convert to CDB format
# Optimization & Maintenance: ridwannaim@tangerangkota.go.id
# Cron: 0 */6 * * * /var/www/html/script/argus-blocklist.sh
#################################################################

umask 007

# Configuration variables
BASE_DIR="/var/www/html/"
LOG_FILE="/var/log/ip-blocklist.log"
LOCK_FILE="/var/run/lock/ip-blocklist.lock"
LISTS_DIR="${BASE_DIR}/blocklist"
ARGUS_IPSET="${LISTS_DIR}/argus-ipsets.ipset"
ARGUS_CDB="${LISTS_DIR}/argus-ipsets.cdb"
CONVERTER_SCRIPT="${BASE_DIR}/script/argusip-converter.php"
PHP_PATH="/usr/local/bin/php"
MAX_LOG_SIZE=512000
FIREHOL_REPO="https://raw.githubusercontent.com/firehol/blocklist-ipsets/master"

# Logging function
log() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') $1" | tee -a "$LOG_FILE"
}

error_exit() {
    log "ERROR: $1"
    [[ -f "$LOCK_FILE" ]] && rm -f "$LOCK_FILE"
    exit 1
}

# Log rotate configuration
if [[ -f "$LOG_FILE" ]] && [[ $(stat -c%s "$LOG_FILE") -gt $MAX_LOG_SIZE ]]; then
    mv "$LOG_FILE" "${LOG_FILE}.old"
    touch "$LOG_FILE"
fi

log "=========================================================="
log "🚀 START PARSING ARGUS IPSET"
log "=========================================================="

# Basic validation
[[ $EUID -ne 0 ]] && error_exit "The script must be run as root."
[[ ! -d "$LISTS_DIR" ]] && mkdir -p "$LISTS_DIR"
[[ ! -x "$PHP_PATH" ]] && error_exit "PHP not found: $PHP_PATH"

# Lock PID
if [[ -f "$LOCK_FILE" ]]; then
    pid=$(cat "$LOCK_FILE")
    if [[ -n "$pid" && $(ps -p "$pid" -o comm=) ]]; then
        error_exit "Script is already running with PID $pid."
    fi
    rm -f "$LOCK_FILE"
fi

echo $$ > "$LOCK_FILE"
trap 'rm -f "$LOCK_FILE"' EXIT

# Check wget
command -v wget &>/dev/null || {
    log "Installing wget..."
    if command -v apt-get &>/dev/null; then
        apt-get update && apt-get install -y wget
    elif command -v yum &>/dev/null; then
        yum install -y wget
    elif command -v dnf &>/dev/null; then
        dnf install -y wget
    else
        error_exit "Install wget manually"
    fi
}

# Download all .ipset lists from FireHOL GitHub repository
log "INFO: Retrieve .ipset lists from FireHOL GitHub repository..."
IPSET_LIST=$(wget -q -O - https://api.github.com/repos/firehol/blocklist-ipsets/contents | grep '"name": ".*.ipset"' | cut -d '"' -f4)

if [[ -z "$IPSET_LIST" ]]; then
    error_exit "Failed fetching .ipset lists from FireHOL GitHub repository."
fi

# Remove old ARGUS IPSET
> "$ARGUS_IPSET"

TOTAL_IPS=0
TOTAL_FILES=0

# Loop and process each .ipset
for ipset in $IPSET_LIST; do
    log "INFO: Processing $ipset..."
    temp_file="${LISTS_DIR}/$ipset"

    if ! wget -q --timeout=60 --tries=3 "$FIREHOL_REPO/$ipset" -O "$temp_file"; then
        log "  ERROR: Failed to download $ipset"
        continue
    fi

    valid_ips=$(grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' "$temp_file" | grep -Ev '(^127\.|^0\.|^255\.)')
    count=$(echo "$valid_ips" | wc -l)

    if [[ $count -eq 0 ]]; then
        log "  WARNING: $ipset not contains valid IP"
        rm -f "$temp_file"
        continue
    fi

    echo "$valid_ips" >> "$ARGUS_IPSET"
    log "SUCCESS: $count valid IPs added from $ipset"

    TOTAL_IPS=$((TOTAL_IPS + count))
    TOTAL_FILES=$((TOTAL_FILES + 1))
    rm -f "$temp_file"
    sleep 0.1
done

# Remove duplicate IP dan save
sort -u "$ARGUS_IPSET" -o "$ARGUS_IPSET"
chmod 660 "$ARGUS_IPSET"

# === CONVERT TO CDB FORMAT ===
echo "INFO: Converting to CDB..."
if command -v $PHP_PATH &>/dev/null; then
    if [[ ! -f "$CONVERTER_SCRIPT" ]]; then
        log "ERROR: Converter script not found at $CONVERTER_SCRIPT. Skipping CDB conversion."
        exit 1
    fi
    $PHP_PATH $CONVERTER_SCRIPT "$ARGUS_IPSET" "$ARGUS_CDB"
    chmod 660 "$ARGUS_CDB"
    log "SUCCESS: Converted $ARGUS_IPSET to CDB format."
else
    log "ERROR: PHP not installed. Skipping CDB conversion."
fi


log "=========================================================="
log "✅ FINISH PARSING ARGUS IPSET"
log "Number of files processed : $TOTAL_FILES"
log "Number of unique IPs      : $(wc -l < "$ARGUS_IPSET")"
log "File saved                : $ARGUS_IPSET"
log "CDB File                  : $ARGUS_CDB"
log "=========================================================="

log "INFO: Process completed."
exit 0
