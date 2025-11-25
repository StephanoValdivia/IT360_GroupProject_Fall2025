# IT360\_GroupProject\_Fall2025

*Project Overview 

The IT360 Security Suite is a lightweight security monitoring tool that combines three components: a network intrusion detection system, a host integrity scanner, and an automated alert generator. All three modules are controlled through a single menu-driven interface.
This project was developed to meet the IT 360 Final Project requirement, which instructs students to create a functioning digital forensics tool and document the full lifecycle from setup through demonstration.

*Purpose

This tool addresses a common digital forensics need: monitoring a system for suspicious activity in real time while also preserving system state for comparison. It provides:

- A Python-based firewall IDS that detects network scans and blocks hostile IPs.

- A host integrity scanner that identifies changes to critical system attributes.

- An automated alert generator that summarizes recent network and host activity.

*Core Features

1 Network Firewall IDS (Python)

- Detects TCP SYN scan attempts

- Tracks per-IP activity

- Automatically blocks malicious IPs using iptables

- Logs all events for later review


2 Host Integrity Scanner (Bash)

- Compares system state to a recorded baseline

- Detects new SUID/SGID files

- Detects new listening ports

- Detects new or unexpected processes

- Detects new or removed users and groups

- Saves timestamped forensic reports


3 Auto-Alert Summary Tool (Python)

- Reads the latest firewall IDS log

- Reads the latest host integrity scan report

- Produces a combined summary of anomalies


4 Security Suite Controller (Bash)

- Simple menu for running all components

- Start/stop IDS, run scans, generate alerts

- Centralized workflow for ease of use

*Why This Matters

In digital forensics, investigators must be able to quickly identify hostile network behavior, track system changes over time, and preserve data in readable forensic reports. This tool provides all of these functions in one accessible package.

===========================================================================
*Setup Instructions

These steps assume a fresh Ubuntu VM with internet access and a user account that has sudo privileges.

1	Update the system and install required packages

-	sudo apt update

-	sudo apt upgrade

-	sudo apt install -y git python3 python3-venv python3-pip iproute2

2	Clone this repository

-	cd ~

-	git clone https://github.com/StephanoValdivia/IT360_GroupProject_Fall2025.git

-	cd IT360_GroupProject_Fall2025/src

3	Create and activate the Python virtual environment

-	python3 -m venv venv

-	source venv/bin/activate

4	Install Python dependencies inside the virtual environment

-	pip install scapy

5	Make the Bash scripts executable

-	chmod +x baseline.sh host_scan.sh security_suite.sh

6	Create the initial system baseline (run once on a “clean” system)

-	sudo ./baseline.sh

This captures SUID/SGID files, listening ports, processes, users, and groups into the baselines folder for later comparison.

7	Start the IT 360 Security Suite controller

-	./security_suite.sh

This opens a simple menu that lets you:

1.	Start the firewall IDS

2.	Stop the firewall IDS

3.	Run a host integrity scan

4.	Run the auto-alert summary

5.	Run a full cycle (scan + alert)

6.	Quit

8.	Future runs

After the first setup, to run the tool again you only need to:

-	cd ~/IT360_GroupProject_Fall2025/src

-	source venv/bin/activate

-	./security_suite.sh

(Run sudo ./baseline.sh again only if you intentionally want to rebuild the baseline.)

