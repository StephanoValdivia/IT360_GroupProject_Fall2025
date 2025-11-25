#!/usr/bin/env python3

import os
import re
from datetime import datetime

# Auto Alert Summary Script
# Reads:
#   - group_firewall.log (network IDS events)
#   - latest host_scan_*.txt (host integrity report)
# and prints a short, combined summary to the terminal.

BASE_DIR = os.path.dirname(os.path.abspath(_file_))
LOG_DIR = os.path.join(BASE_DIR, "logs")
FIREWALL_LOG = os.path.join(LOG_DIR, "group_firewall.log")
HOST_SCAN_PREFIX = "host_scan_"
HOST_SCAN_SUFFIX = ".txt"


# Helper functions

def find_latest_host_scan(log_dir):
    """
    Return full path to the newest host_scan_*.txt file in log_dir,
    or None if no reports are found.
    """
    if not os.path.isdir(log_dir):
        return None

    candidates = []
    for name in os.listdir(log_dir):
        if name.startswith(HOST_SCAN_PREFIX) and name.endswith(HOST_SCAN_SUFFIX):
            full_path = os.path.join(log_dir, name)
            candidates.append(full_path)

    if not candidates:
        return None

    # Pick the one with the most recent modification time
    return max(candidates, key=os.path.getmtime)


def summarize_firewall_log(path):
    """
    Parse group_firewall.log and count total scan events
    and how many times each IP was blocked.
    """
    summary = {
        "blocked_ips": {},   # ip -> count
        "scan_events": 0,
    }

    if not os.path.isfile(path):
        return summary

    block_re = re.compile(r"Blocking IP:\s+(\d+\.\d+\.\d+\.\d+)")

    with open(path, "r") as f:
        for line in f:
            if "Scan detected on port" in line:
                summary["scan_events"] += 1

            m = block_re.search(line)
            if m:
                ip = m.group(1)
                summary["blocked_ips"][ip] = summary["blocked_ips"].get(ip, 0) + 1

    return summary


def extract_section(text, header):
    """
    Given the full host_scan report text and a header string like
    'New SUID/SGID files (not in baseline):'
    return the lines under that header until a blank line or ====== line.
    """
    lines = text.splitlines()
    results = []
    capture = False

    for line in lines:
        if header in line:
            capture = True
            # skip the header line itself
            continue

        if capture:
            # End of section: blank line or separator
            if line.strip() == "" or set(line.strip()) == {"="}:
                break
            results.append(line)

    # Strip trailing empty lines if any
    while results and results[-1].strip() == "":
        results.pop()

    return results


def summarize_host_scan(path):
    """
    Return a dict of interesting sections from the latest host_scan report,
    or None if the file doesn't exist.
    """
    if path is None or not os.path.isfile(path):
        return None

    with open(path, "r") as f:
        text = f.read()

    return {
        "path": path,
        "new_suid": extract_section(text, "New SUID/SGID files (not in baseline):"),
        "new_ports": extract_section(text, "New listening ports:"),
        "new_procs": extract_section(text, "New processes (not present in baseline):"),
        "new_users": extract_section(text, "New user accounts:"),
        "new_groups": extract_section(text, "New groups:"),
    }


# Main logic

def main():
    print("=" * 70)
    print(f"[+] Auto Alert Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    print(f"Log directory: {LOG_DIR}")
    print()

    #  Network / firewall summary 
    print("=== Network Alerts (group_firewall.log) ===")
    fw_summary = summarize_firewall_log(FIREWALL_LOG)

    if not os.path.isfile(FIREWALL_LOG):
        print("[-] Firewall log not found.")
    else:
        print(f"Total scan events detected: {fw_summary['scan_events']}")
        if fw_summary["blocked_ips"]:
            print("Blocked IPs:")
            # Sort for consistent output
            for ip in sorted(fw_summary["blocked_ips"].keys()):
                count = fw_summary["blocked_ips"][ip]
                print(f"  - {ip} (blocked {count} time(s))")
        else:
            print("No IPs have been blocked yet.")
    print()

    #  Host integrity summary 
    print("=== Host Integrity Alerts (latest host_scan report) ===")
    latest_path = find_latest_host_scan(LOG_DIR)
    host_summary = summarize_host_scan(latest_path)

    if host_summary is None:
        print("[-] No host_scan_*.txt reports found.")
        print("[+] Auto alert summary complete.")
        return

    print(f"Using report: {os.path.basename(host_summary['path'])}")
    print()

    def show_section(title, lines):
        print(title)
        if not lines:
            print("  (none)")
        else:
            for line in lines:
                print("  " + line.rstrip())
        print()

    show_section("New SUID/SGID files:", host_summary["new_suid"])
    show_section("New listening ports:", host_summary["new_ports"])
    show_section("New processes:", host_summary["new_procs"])
    show_section("New user accounts:", host_summary["new_users"])
    show_section("New groups:", host_summary["new_groups"])

    print("[+] Auto alert summary complete.")


if __name__ == "__main__":
    main()



