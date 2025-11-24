#!/bin/bash
#
# security_suite.sh
# Master controller for:
#   - group_firewall.py  (network IDS + auto-block)
#   - host_scan.sh       (host integrity scan)
#   - auto_alert.py      (summary report)

FIREWALL_SCRIPT="$HOME/group_firewall.py"
PYTHON_BIN="$HOME/venv/bin/python3"
HOST_SCAN_SCRIPT="$HOME/host_scan.sh"
AUTO_ALERT_SCRIPT="$HOME/auto_alert.py"
PID_FILE="$HOME/group_firewall.pid"

# Helper: ensure required files exist

check_file() {
    if [ ! -f "$1" ]; then
        echo "[!] Missing required file: $1"
        return 1
    fi
    return 0
}

check_python() {
    if [ ! -x "$PYTHON_BIN" ]; then
        echo "[!] Python virtual environment not found at: $PYTHON_BIN"
        echo "    Run: python3 -m venv venv && source venv/bin/activate"
        return 1
    fi
    return 0
}

# Start Firewall IDS

start_firewall() {

    check_file "$FIREWALL_SCRIPT" || return
    check_python || return

    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo "[!] Firewall already running (PID $(cat "$PID_FILE"))."
        return
    fi

    echo "[*] Starting firewall IDS..."
    sudo "$PYTHON_BIN" "$FIREWALL_SCRIPT" &

    echo $! > "$PID_FILE"
    echo "[+] Firewall started with PID $(cat "$PID_FILE")."
}

# Stop Firewall IDS

stop_firewall() {

    if [ ! -f "$PID_FILE" ]; then
        echo "[!] Firewall does not appear to be running."
        return
    fi

    PID=$(cat "$PID_FILE")

    if [[ ! "$PID" =~ ^[0-9]+$ ]]; then
        echo "[!] PID file corrupted. Removing."
        rm -f "$PID_FILE"
        return
    fi

    if kill -0 "$PID" 2>/dev/null; then
        echo "[*] Stopping firewall (PID $PID)..."
        sudo kill "$PID"
        rm -f "$PID_FILE"
        echo "[+] Firewall stopped."
    else
        echo "[!] Firewall process not running. Cleaning up PID file."
        rm -f "$PID_FILE"
    fi
}

# Host Integrity Scan

run_host_scan() {
    check_file "$HOST_SCAN_SCRIPT" || return
    echo "[*] Running host integrity scan..."
    sudo "$HOST_SCAN_SCRIPT"
}

# Auto Alert Summary

run_auto_alert() {
    check_file "$AUTO_ALERT_SCRIPT" || return
    echo "[*] Running auto-alert summary..."
    "$AUTO_ALERT_SCRIPT"
}

# Full Cycle

run_full_cycle() {
    echo "============================================================"
    echo "[*] Running full cycle (host scan + auto-alert)..."
    echo "============================================================"
    run_host_scan
    echo
    run_auto_alert
}

# Main Menu

show_menu() {
    echo "============================================================"
    echo "            IT 360 Security Suite Controller"
    echo "============================================================"
    echo "1) Start firewall IDS"
    echo "2) Stop firewall IDS"
    echo "3) Run host integrity scan"
    echo "4) Run auto alert summary"
    echo "5) Run full cycle (scan + alert)"
    echo "6) Quit"
    echo

    read -rp "Select an option [1-6]: " choice
    echo

    case "$choice" in
        1) start_firewall ;;
        2) stop_firewall ;;
        3) run_host_scan ;;
        4) run_auto_alert ;;
        5) run_full_cycle ;;
        6) echo "Goodbye."; exit 0 ;;
        *) echo "[!] Invalid selection." ;;
    esac

    echo
}

# Loop forever

while true; do
    show_menu
done



