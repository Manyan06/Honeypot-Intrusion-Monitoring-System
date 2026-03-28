# Honeypot-Based Intrusion Monitoring System (Cowrie SSH + Flask Dashboard)

A **honeypot-based intrusion monitoring lab** built using the **Cowrie SSH honeypot** deployed inside a **Kali Linux VM**. The honeypot simulates a vulnerable SSH service to **attract attackers**, **record their behavior**, and **generate alerts**—all without exposing any real production system.

> This environment is intended for **education, security research, and controlled lab use** only.

---

## Project Summary

With the increasing number of cyber-attacks targeting network services, organizations need mechanisms to **detect and analyze malicious activity** without risking real systems.

This project uses **Cowrie**, an SSH honeypot that provides a **fake Linux shell** to attackers. It captures:
- SSH login attempts (usernames/passwords)
- Commands executed by the attacker
- Session timing and metadata
- Structured logs for analysis (e.g., JSON logs)

A lightweight **alert script** monitors login activity and generates alerts when suspicious SSH events occur. A **Flask-based dashboard** provides a simple UI view for monitoring.

---

## Key Features
- **Cowrie SSH Honeypot** (decoy SSH server)
- **Fake Linux shell** session for attackers (isolated/emulated environment)
- **Structured logging** of attacker actions
- **Alerting** via `alert.sh` for login events
- **Dashboard UI** (Flask app)

---

## Lab Architecture

```text
                 ┌──────────────────────────────┐
                 │        Attacker VM           │
                 │        Kali Linux            │
                 │   IP: 192.168.100.20         │
                 │                              │
                 │  SSH Client / Attack Tools   │
                 └───────────────┬──────────────┘
                                 │
                                 │ SSH Connection
                                 │ Port 2222
                                 ▼
        ─────────────────────────────────────────────────
              Isolated Internal Network (honeynet)
        ─────────────────────────────────────────────────
                                 │
                                 ▼
                 ┌──────────────────────────────┐
                 │        Honeypot VM           │
                 │        Kali Linux            │
                 │   IP: 192.168.100.10         │
                 │                              │
                 │       Cowrie SSH Honeypot    │
                 └───────────────┬──────────────┘
                                 │
                                 │ Fake Shell Session
                                 ▼
                 ┌──────────────────────────────┐
                 │     Emulated Linux Shell     │
                 │        (Fake Environment)    │
                 │                              │
                 │   Attacker executes commands │
                 │   id, uname, wget, etc.      │
                 └───────────────┬──────────────┘
                                 │
                                 │ Logs attacker activity
                                 ▼
                 ┌──────────────────────────────┐
                 │        Intrusion Logs        │
                 │                              │
                 │ cowrie.json                  │
                 │ cowrie.log                   │
                 │ session TTY recordings       │
                 └───────────────┬──────────────┘
                                 │
                                 │ monitored / parsed
                                 ▼
                 ┌──────────────────────────────┐
                 │        Alert System          │
                 │        alert.sh script       │
                 │                              │
                 │ Detects login attempts       │
                 │ Generates intrusion alerts   │
                 └──────────────────────────────┘
```

---

## Network Configuration

This project uses **two VMs** connected via an **isolated internal network**:

| Machine | OS | Interface | IP Address |
|--------|----|-----------|------------|
| Honeypot VM | Kali Linux | `eth1` | `192.168.100.10/24` |
| Attacker VM | Kali Linux | `eth0` | `192.168.100.20/24` |

Cowrie listens on SSH port **2222** (honeypot port), so the attacker connects using:
```bash
ssh root@192.168.100.10 -p 2222
```
---

## Requirements
- 2× Virtual Machines (recommended)
  - **Honeypot VM:** Kali Linux + Cowrie
  - **Attacker VM:** Kali Linux (or any SSH client machine)
- Internal/host-only network configured between VMs
- Python3 and Flask installed
- Cowrie installed and configured under `~/cowrie`

---

## Setup & Run

### 1) Configure Network Interfaces

**On Honeypot VM**
```bash
sudo ip addr add 192.168.100.10/24 dev eth1
sudo ip link set eth1 up
```

**On Attacker VM**
```bash
sudo ip addr add 192.168.100.20/24 dev eth0
sudo ip link set eth0 up
```

(Optional) Verify connectivity (from attacker to honeypot):
```bash
ping -c 3 192.168.100.10
```

---

### 2) Run Cowrie Honeypot

On the **Honeypot VM**, open **Terminal 1**:

```bash
cd ~/cowrie
source cowrie-env/bin/activate
PYTHONPATH=src twistd -n cowrie
```

Keep this terminal running.

---

### 3) Run Alert Script

On the **Honeypot VM**, open **Terminal 2**:

```bash
cd ~/cowrie
./alert.sh
```

---

### 4) Run Dashboard (Flask UI)

On the **Honeypot VM**, open another terminal (or reuse one):

```bash
python3 app.py
```

Open the dashboard in the Honeypot VM browser:

```text
http://127.0.0.1:5000/
```

---

### 5) Simulate an Attacker (SSH into the Honeypot)

On the **Attacker VM**:

```bash
ssh root@192.168.100.10 -p 2222
```

Once connected, try typical attacker-style discovery commands (in a controlled lab):
```bash
id
uname -a
whoami
pwd
ls -la
cat /etc/passwd
```

---

## Logs & Evidence

Cowrie records activity such as:
- authentication attempts
- commands entered
- session info
- (optionally) file download attempts and TTY recordings depending on Cowrie configuration

Common Cowrie log locations (may vary by config):
- JSON event logs: `~/cowrie/var/log/cowrie/cowrie.json`
- Text logs: `~/cowrie/var/log/cowrie/cowrie.log`
- Session recordings: `~/cowrie/var/lib/cowrie/tty/`

> If your dashboard/alert script reads from specific paths, ensure those match your Cowrie configuration.

---

## Demo Commands Captured
During testing, the attacker VM executed reconnaissance and post-compromise style commands including:
- system information enumeration (`uname`, `id`, etc.)
- basic credential and user enumeration
- simulated payload download attempts (e.g., `wget`, `curl`)

Cowrie successfully captured these actions for forensic analysis.

---

## Screenshots
Screenshots are available in [`screenshots/`](./screenshots):
- `01_honeypot_running.png`
- `02_attacker_ssh_login.png`
- `03_fake_shell_commands.png`
- `04_intrusion_logs.png`
- `05_Alert_detected.png`
- `06_Dashboard.png`

---

## Troubleshooting

### SSH connection fails
- Confirm both VMs are on the same internal network.
- Confirm `eth1` is up and IPs are correct.
- Confirm Cowrie is running and listening on port `2222`:
  ```bash
  sudo ss -lntp | grep 2222
  ```

### Dashboard not loading
- Confirm Flask is running:
  ```bash
  python3 app.py
  ```
- Confirm you are opening:
  ```text
  http://127.0.0.1:5000/
  ```

### Alert script not triggering
- Confirm `alert.sh` has execute permission:
  ```bash
  chmod +x alert.sh
  ```
- Confirm it’s watching the correct log file path.

---

## Disclaimer
This project is for **authorized, controlled environments** only. Do not deploy honeypots on networks you do not own or without explicit permission. The author is not responsible for misuse.
