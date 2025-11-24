#!/bin/bash
#
# baseline.sh
# Creates the initial baseline snapshot used by the host integrity scanner.

# Determine script directory and baseline output folder
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$BASE_DIR/baselines"

mkdir -p "$OUT_DIR"

echo "==========================================================="
echo "[*] Building system baseline..."
echo "     Output directory: $OUT_DIR"
echo "==========================================================="

# 1) SUID / SGID FILES

echo "[*] Collecting SUID/SGID files..."
find / -perm -4000 -o -perm -2000 2>/dev/null | sort > "$OUT_DIR/suid_files.txt"

# 2) LISTENING PORTS

echo "[*] Capturing listening ports..."
ss -tuln | sort > "$OUT_DIR/listeners.txt"

# 3) PROCESS SNAPSHOT

echo "[*] Saving current process list..."
ps aux | sort > "$OUT_DIR/processes.txt"

# 4) USER & GROUP INFORMATION

echo "[*] Saving /etc/passwd and /etc/group..."
cut -d: -f1,3,4,7 /etc/passwd > "$OUT_DIR/passwd.txt"
cut -d: -f1,3 /etc/group > "$OUT_DIR/group.txt"

# DONE

echo "[+] Baseline created successfully."
echo "[+] Files saved under: $OUT_DIR"
echo "==========================================================="



