# profiler.py

BOT_COMMANDS      = ["enable", "busybox", "linuxshell", "/bin/sh", "shell", "system", "assword"]
TARGETED_COMMANDS = ["cat /etc/shadow", ".ssh", "authorized_keys", "history",
                     "crontab", "iptables", "find / -perm", "useradd", "adduser", "passwd"]
SCRIPT_COMMANDS   = ["id", "whoami", "uname", "pwd", "ls", "cat /etc/passwd",
                     "wget", "curl", "ps", "netstat", "ifconfig", "hostname"]

def classify_attacker(commands):
    if not commands:
        return {
            "type":        "No Commands",
            "confidence":  "N/A",
            "description": "Attacker connected but executed no commands",
            "badge":       "secondary"
        }

    commands_str = " ".join(commands).lower()

    bot_score      = sum(1 for c in BOT_COMMANDS      if c in commands_str)
    targeted_score = sum(1 for c in TARGETED_COMMANDS if c in commands_str)
    script_score   = sum(1 for c in SCRIPT_COMMANDS   if c in commands_str)

    if bot_score >= 1:
        return {
            "type":        "Automated Bot",
            "confidence":  "High",
            "description": "Scripted/botnet behavior — automated tooling detected",
            "badge":       "danger"
        }
    elif targeted_score >= 2:
        return {
            "type":        "Targeted Attacker",
            "confidence":  "High",
            "description": "Actively hunting credentials and persistence mechanisms",
            "badge":       "warning"
        }
    elif script_score >= 2:
        return {
            "type":        "Script Kiddie",
            "confidence":  "Medium",
            "description": "Basic recon commands, likely using pre-built scripts",
            "badge":       "info"
        }
    else:
        return {
            "type":        "Curious User",
            "confidence":  "Low",
            "description": "Minimal activity, unclear intent",
            "badge":       "success"
        }