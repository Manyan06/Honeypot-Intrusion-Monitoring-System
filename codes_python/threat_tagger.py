# threat_tagger.py  —  UPGRADE 3: Threat Intent Tagging

THREAT_RULES = [
    {
        "tag":         "💣 Malware Dropper Detected",
        "severity":    "CRITICAL",
        "color":       "danger",
        "requires_all": ["wget"],
        "requires_any": [".sh", ".py", ".elf", ".bin", "http://", "https://"]
    },
    {
        "tag":         "🔑 Credential Harvesting Attempt",
        "severity":    "HIGH",
        "color":       "danger",
        "requires_all": [],
        "requires_any": ["cat /etc/shadow", "cat /etc/passwd", "history", ".ssh", "authorized_keys"]
    },
    {
        "tag":         "🔒 Persistence Mechanism Planted",
        "severity":    "HIGH",
        "color":       "warning",
        "requires_all": [],
        "requires_any": ["crontab", "authorized_keys", "useradd", "adduser", "rc.local", "systemctl enable"]
    },
    {
        "tag":         "🛡️ Defense Evasion Attempt",
        "severity":    "HIGH",
        "color":       "warning",
        "requires_all": [],
        "requires_any": ["iptables", "unset history", "export histsize=0", "shred", "chattr"]
    },
    {
        "tag":         "⚡ Privilege Escalation Attempt",
        "severity":    "HIGH",
        "color":       "warning",
        "requires_all": [],
        "requires_any": ["sudo", "su -", "chmod +s", "find / -perm -4000"]
    },
    {
        "tag":         "📡 C2 Communication Attempt",
        "severity":    "MEDIUM",
        "color":       "warning",
        "requires_all": [],
        "requires_any": ["wget", "curl", "tftp", "nc ", "netcat", "ncat"]
    },
    {
        "tag":         "🔍 System Reconnaissance",
        "severity":    "LOW",
        "color":       "info",
        "requires_all": [],
        "requires_any": ["whoami", "id", "uname", "hostname", "ps aux", "netstat", "ifconfig", "ip addr"]
    },
    {
        "tag":         "📁 File System Enumeration",
        "severity":    "LOW",
        "color":       "info",
        "requires_all": [],
        "requires_any": ["ls -la", "ls -al", "find /", "ls /etc", "ls /var", "ls /home", "ls /root"]
    },
]

def generate_tags(commands):
    if not commands:
        return []

    cmd_str = " ".join(commands).lower()
    matched_tags = []

    for rule in THREAT_RULES:
        # Check all required keywords present
        all_ok = all(kw in cmd_str for kw in rule["requires_all"])
        # Check at least one optional keyword present
        any_ok = any(kw in cmd_str for kw in rule["requires_any"]) if rule["requires_any"] else True

        if all_ok and any_ok:
            matched_tags.append({
                "tag":      rule["tag"],
                "severity": rule["severity"],
                "color":    rule["color"]
            })

    return matched_tags