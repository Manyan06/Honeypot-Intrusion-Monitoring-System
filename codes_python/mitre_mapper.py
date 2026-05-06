# mitre_mapper.py

MITRE_MAPPING = {
    "whoami":             {"id": "T1033", "name": "System Owner/User Discovery",           "tactic": "Discovery"},
    "id":                 {"id": "T1033", "name": "System Owner/User Discovery",           "tactic": "Discovery"},
    "uname":              {"id": "T1082", "name": "System Information Discovery",          "tactic": "Discovery"},
    "hostname":           {"id": "T1082", "name": "System Information Discovery",          "tactic": "Discovery"},
    "cat /etc/passwd":    {"id": "T1087", "name": "Account Discovery",                    "tactic": "Discovery"},
    "cat /etc/shadow":    {"id": "T1003", "name": "OS Credential Dumping",                "tactic": "Credential Access"},
    "ls":                 {"id": "T1083", "name": "File and Directory Discovery",          "tactic": "Discovery"},
    "find":               {"id": "T1083", "name": "File and Directory Discovery",          "tactic": "Discovery"},
    "pwd":                {"id": "T1083", "name": "File and Directory Discovery",          "tactic": "Discovery"},
    "ps":                 {"id": "T1057", "name": "Process Discovery",                     "tactic": "Discovery"},
    "netstat":            {"id": "T1049", "name": "System Network Connections Discovery",  "tactic": "Discovery"},
    "ifconfig":           {"id": "T1016", "name": "System Network Configuration Discovery","tactic": "Discovery"},
    "ip addr":            {"id": "T1016", "name": "System Network Configuration Discovery","tactic": "Discovery"},
    "wget":               {"id": "T1105", "name": "Ingress Tool Transfer",                 "tactic": "Command and Control"},
    "curl":               {"id": "T1105", "name": "Ingress Tool Transfer",                 "tactic": "Command and Control"},
    "chmod":              {"id": "T1222", "name": "File Permission Modification",          "tactic": "Defense Evasion"},
    "sudo":               {"id": "T1548", "name": "Abuse Elevation Control Mechanism",    "tactic": "Privilege Escalation"},
    "passwd":             {"id": "T1098", "name": "Account Manipulation",                  "tactic": "Persistence"},
    "crontab":            {"id": "T1053", "name": "Scheduled Task/Job",                    "tactic": "Persistence"},
    "bash":               {"id": "T1059", "name": "Command and Scripting Interpreter",     "tactic": "Execution"},
    "sh":                 {"id": "T1059", "name": "Command and Scripting Interpreter",     "tactic": "Execution"},
    "python":             {"id": "T1059", "name": "Command and Scripting Interpreter",     "tactic": "Execution"},
    "echo":               {"id": "T1059", "name": "Command and Scripting Interpreter",     "tactic": "Execution"},
    "ssh":                {"id": "T1021", "name": "Remote Services",                       "tactic": "Lateral Movement"},
    "history":            {"id": "T1552", "name": "Unsecured Credentials",                 "tactic": "Credential Access"},
    "authorized_keys":    {"id": "T1098", "name": "Account Manipulation",                  "tactic": "Persistence"},
    ".ssh":               {"id": "T1552", "name": "Unsecured Credentials",                 "tactic": "Credential Access"},
    "iptables":           {"id": "T1562", "name": "Impair Defenses",                       "tactic": "Defense Evasion"},
    "useradd":            {"id": "T1136", "name": "Create Account",                        "tactic": "Persistence"},
    "adduser":            {"id": "T1136", "name": "Create Account",                        "tactic": "Persistence"},
    "env":                {"id": "T1082", "name": "System Information Discovery",          "tactic": "Discovery"},
    "cat /proc":          {"id": "T1082", "name": "System Information Discovery",          "tactic": "Discovery"},
    "df":                 {"id": "T1082", "name": "System Information Discovery",          "tactic": "Discovery"},
    "mount":              {"id": "T1082", "name": "System Information Discovery",          "tactic": "Discovery"},
    "last":               {"id": "T1087", "name": "Account Discovery",                    "tactic": "Discovery"},
    "who":                {"id": "T1087", "name": "Account Discovery",                    "tactic": "Discovery"},
    "w ":                 {"id": "T1087", "name": "Account Discovery",                    "tactic": "Discovery"},
}

TACTIC_CATEGORY = {
    "Discovery":          "Discovery",
    "Credential Access":  "Credential Access",
    "Execution":          "Execution",
    "Persistence":        "Persistence",
    "Privilege Escalation":"Privilege Escalation",
    "Defense Evasion":    "Defense Evasion",
    "Command and Control":"Command and Control",
    "Lateral Movement":   "Lateral Movement",
}

def map_command_to_mitre(command):
    command_lower = command.strip().lower()
    results = []
    seen_ids = set()
    for keyword, technique in MITRE_MAPPING.items():
        if keyword in command_lower:
            if technique["id"] not in seen_ids:
                results.append(technique)
                seen_ids.add(technique["id"])
    if not results:
        results.append({
            "id": "T1059",
            "name": "Command and Scripting Interpreter",
            "tactic": "Execution"
        })
    return results

def get_tactic_sequence(commands):
    """Returns ordered list of tactics for a session's commands."""
    sequence = []
    for cmd in commands:
        techniques = map_command_to_mitre(cmd)
        for t in techniques:
            tactic = t["tactic"]
            if not sequence or sequence[-1] != tactic:
                sequence.append(tactic)
    return sequence