#!/bin/bash
#
# host_scan.sh
# Host integrity scanner for our IT 360 project.
# Compares the current system state to the saved baseline
# and writes a timestamped report under logs/.

# Figure out where this script lives and build paths from that
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASELINE_DIR="$BASE_DIR/baselines"
LOG_DIR="$BASE_DIR/logs"
TIMESTAMP="$(date '+%Y-%m-%d_%H-%M-%S')"
REPORT="$LOG_DIR/host_scan_$TIMESTAMP.txt"

# Make sure the logs directory exists so we can write the report
mkdir -p "$LOG_DIR"

#  Helper: check baseline exists 

check_baselines() {
    local missing=0

    for f in suid_files.txt listeners.txt processes.txt passwd.txt group.txt; do
        if [[ ! -f "$BASELINE_DIR/$f" ]]; then
            echo "[!] Missing baseline file: $BASELINE_DIR/$f"
            missing=1
        fi
    done

    if [[ $missing -ne 0 ]]; then
        echo "[!] Baseline is incomplete. Run baseline.sh first."
        exit 1
    fi
}

# Helper: write a section header 

section() {
    echo "==================================================" >> "$REPORT"
    echo "$1" >> "$REPORT"
    echo "==================================================" >> "$REPORT"
}

# Make sure we have a valid baseline before doing anything
check_baselines

echo "[*] Running host integrity scan..."
echo "[*] Baseline dir: $BASELINE_DIR"
echo "[*] Report will be saved to: $REPORT"

echo "[+] Host integrity scan started at: $(date)" >> "$REPORT"
echo >> "$REPORT"

# Use a temporary directory for all the comparison files
TMP_DIR="$(mktemp -d)"

#  SUID / SGID files 

section "SUID/SGID FILES"

echo "[*] Collecting current SUID/SGID files..."
find / -perm -4000 -o -perm -2000 2>/dev/null | sort > "$TMP_DIR/suid_current.txt"
sort "$BASELINE_DIR/suid_files.txt" > "$TMP_DIR/suid_baseline.txt"

echo "New SUID/SGID files (not in baseline):" >> "$REPORT"
comm -13 "$TMP_DIR/suid_baseline.txt" "$TMP_DIR/suid_current.txt" >> "$REPORT"
echo >> "$REPORT"

echo "Removed SUID/SGID files (in baseline, missing now):" >> "$REPORT"
comm -23 "$TMP_DIR/suid_baseline.txt" "$TMP_DIR/suid_current.txt" >> "$REPORT"
echo >> "$REPORT"

# Listening ports 

section "LISTENING PORTS"

echo "[*] Collecting current listening ports..."

if command -v ss >/dev/null 2>&1; then
    ss -tuln | sort > "$TMP_DIR/listeners_current.txt"
else
    echo "[!] ss command not found, skipping port comparison." >> "$REPORT"
    echo "[!] ss command not found, skipping port comparison."
    > "$TMP_DIR/listeners_current.txt"
fi

sort "$BASELINE_DIR/listeners.txt" > "$TMP_DIR/listeners_baseline.txt"

echo "New listening ports:" >> "$REPORT"
comm -13 "$TMP_DIR/listeners_baseline.txt" "$TMP_DIR/listeners_current.txt" >> "$REPORT"
echo >> "$REPORT"

echo "Ports no longer listening:" >> "$REPORT"
comm -23 "$TMP_DIR/listeners_baseline.txt" "$TMP_DIR/listeners_current.txt" >> "$REPORT"
echo >> "$REPORT"

# Processes

section "PROCESSES"

echo "[*] Collecting current process list..."
ps aux | sort > "$TMP_DIR/processes_current.txt"
sort "$BASELINE_DIR/processes.txt" > "$TMP_DIR/processes_baseline.txt"

echo "New processes (not present in baseline):" >> "$REPORT"
comm -13 "$TMP_DIR/processes_baseline.txt" "$TMP_DIR/processes_current.txt" | head -n 200 >> "$REPORT"
echo >> "$REPORT"
echo "(Showing up to 200 lines for readability.)" >> "$REPORT"
echo >> "$REPORT"

# Users

section "USERS"

echo "[*] Comparing users..."
cut -d: -f1 "$BASELINE_DIR/passwd.txt" | sort > "$TMP_DIR/users_baseline.txt"
cut -d: -f1 /etc/passwd | sort > "$TMP_DIR/users_current.txt"

echo "New user accounts:" >> "$REPORT"
comm -13 "$TMP_DIR/users_baseline.txt" "$TMP_DIR/users_current.txt" >> "$REPORT"
echo >> "$REPORT"

echo "Removed user accounts:" >> "$REPORT"
comm -23 "$TMP_DIR/users_baseline.txt" "$TMP_DIR/users_current.txt" >> "$REPORT"
echo >> "$REPORT"

# Groups

section "GROUPS"

echo "[*] Comparing groups..."
cut -d: -f1 "$BASELINE_DIR/group.txt" | sort > "$TMP_DIR/groups_baseline.txt"
cut -d: -f1 /etc/group | sort > "$TMP_DIR/groups_current.txt"

echo "New groups:" >> "$REPORT"
comm -13 "$TMP_DIR/groups_baseline.txt" "$TMP_DIR/groups_current.txt" >> "$REPORT"
echo >> "$REPORT"

echo "Removed groups:" >> "$REPORT"
comm -23 "$TMP_DIR/groups_baseline.txt" "$TMP_DIR/groups_current.txt" >> "$REPORT"
echo >> "$REPORT"

# Done 

echo "[+] Host integrity scan complete at: $(date)" >> "$REPORT"
echo "[*] Scan finished."
echo "[*] Report saved to: $REPORT"

rm -rf "$TMP_DIR"



