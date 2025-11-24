#!/usr/bin/env python3

"""
group_firewall.py
Simple firewall-style IDS that watches TCP traffic, logs scan activity,
and automatically blocks IPs that cross a port-scan threshold.
"""

import os
import time
import subprocess
from collections import defaultdict
from datetime import datetime, timedelta

from scapy.all import IP, TCP, sniff, send


# Configuration

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

LOG_FILE = os.path.join(LOG_DIR, "group_firewall.log")

SCAN_THRESHOLD = 5         # number of ports before we block an IP
BLOCK_MINUTES = 10         # how long an IP stays blocked
BLOCK_DURATION = timedelta(minutes=BLOCK_MINUTES)


class FirewallIDS:
    """Firewall-style IDS that tracks scan attempts and manages iptables blocks."""

    def __init__(self) -> None:
        # per-IP scan tracking
        self.scan_stats = defaultdict(lambda: {"count": 0, "last_seen": None})
        # list of {"ip": str, "unblock_time": datetime}
        self.unblock_queue = []

    # Logging helper

    def log(self, msg: str) -> None:
        """Print to stdout and append to the main log file."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{timestamp}] {msg}"
        print(line)
        try:
            with open(LOG_FILE, "a") as f:
                f.write(line + "\n")
        except Exception as exc:
            print(f"[!] Failed to write to log file: {exc}")

    # iptables helpers

    def ip_is_already_blocked(self, ip: str) -> bool:
        """Return True if the IP already has a DROP rule in iptables."""
        try:
            result = subprocess.run(
                ["sudo", "iptables", "-L", "-n"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                check=False,
            )
        except Exception as exc:
            self.log(f"[!] Error checking iptables for {ip}: {exc}")
            return False

        return ip in result.stdout

    def block_ip(self, ip: str) -> None:
        """Add a DROP rule for the given IP."""
        if self.ip_is_already_blocked(ip):
            self.log(f"IP {ip} is already blocked. Skipping...")
            return

        self.log(f"Blocking IP: {ip}")
        try:
            subprocess.run(
                ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
            )
        except subprocess.CalledProcessError as exc:
            self.log(f"Error blocking IP {ip}: {exc}")

    def unblock_ip(self, ip: str) -> None:
        """Remove the DROP rule for the given IP."""
        self.log(f"Unblocking IP: {ip}")
        try:
            subprocess.run(
                ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
            )
        except subprocess.CalledProcessError as exc:
            self.log(f"Error unblocking IP {ip}: {exc}")

    # Packet handling

    def handle_packet(self, packet) -> None:
        """
        Callback used by scapy.sniff.
        We only care about TCP SYN packets, which we treat as scan attempts.
        """
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return

        tcp_layer = packet[TCP]
        ip_layer = packet[IP]

        # Only look at initial SYN packets (basic scan detection)
        if tcp_layer.flags != "S":
            return

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        dst_port = tcp_layer.dport
        src_port = tcp_layer.sport

        self.log(f"Scan detected on port {dst_port} from {src_ip}")

        now = datetime.now()
        stat = self.scan_stats[src_ip]

        # If this IP hasn't been seen in a while, reset its counter
        if stat["last_seen"] and now - stat["last_seen"] > BLOCK_DURATION:
            stat["count"] = 0

        stat["count"] += 1
        stat["last_seen"] = now

        # If the IP crosses the threshold, block it and schedule an unblock
        if stat["count"] > SCAN_THRESHOLD:
            self.log(
                f"IP {src_ip} exceeded scan limit ({SCAN_THRESHOLD}), "
                f"blocking for {BLOCK_MINUTES} minutes..."
            )
            self.block_ip(src_ip)
            unblock_time = now + BLOCK_DURATION
            self.log(
                f"IP {src_ip} will be unblocked at "
                f"{unblock_time.strftime('%Y-%m-%d %H:%M:%S')}"
            )
            self.unblock_queue.append(
                {"ip": src_ip, "unblock_time": unblock_time}
            )
            return

        # Optional: send a SYN-ACK back (harmless decoy response)
        syn_ack = (
            IP(dst=src_ip, src=dst_ip)
            / TCP(
                sport=dst_port,
                dport=src_port,
                flags="SA",
                seq=100,
                ack=tcp_layer.seq + 1,
            )
        )
        send(syn_ack, verbose=0)
        self.log(f"Sent SYN-ACK to {src_ip} on port {dst_port}")

    # Unblock queue processing

    def process_unblock_queue(self) -> None:
        """Unblock any IPs whose timers have expired."""
        now = datetime.now()
        for task in list(self.unblock_queue):
            if now >= task["unblock_time"]:
                self.unblock_ip(task["ip"])
                self.unblock_queue.remove(task)

    # Main entry point

    def start(self) -> None:
        """Start sniffing in a background thread and manage unblock timing."""
        import threading

        def sniff_loop():
            self.log("Starting packet sniffing (tcp)...")
            sniff(filter="tcp", prn=self.handle_packet, store=False)

        t = threading.Thread(target=sniff_loop, daemon=True)
        t.start()

        self.log("Firewall IDS active and monitoring traffic.")

        try:
            while True:
                self.process_unblock_queue()
                time.sleep(5)
        except KeyboardInterrupt:
            self.log("Stopping firewall IDS...")

if __name__ == "__main__":
    firewall = FirewallIDS()
    firewall.start()



