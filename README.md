# Honeypot-Based Intrusion Monitoring System

## Overview
This project implements a Cowrie SSH honeypot to detect and analyze attacker behavior.

## Features
- Fake SSH server (Cowrie)
- Attacker simulation
- Real-time logging
- Alert system
- Dashboard (Flask UI)

## How to Run

### Start Cowrie
PYTHONPATH=src twistd -n cowrie

### Run Dashboard
python3 app.py

## Network Setup
- Honeypot: 192.168.100.10
- Attacker: 192.168.100.20

## UI Dashboard in Kali
http://127.0.0.1:5000/