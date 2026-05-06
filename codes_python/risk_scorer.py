# risk_scorer.py  —  UPGRADE 1: Risk Scoring

CREDENTIAL_KEYWORDS  = ["shadow", "passwd", "history", ".ssh", "authorized_keys", "password", "credential"]
PERSISTENCE_KEYWORDS = ["crontab", "useradd", "adduser", "authorized_keys", "rc.local", "systemctl", "passwd"]
DOWNLOAD_KEYWORDS    = ["wget", "curl", "tftp", "ftp", "scp"]
EVASION_KEYWORDS     = ["iptables", "chmod", "chattr", "unset history", "export histsize=0", "shred"]
EXECUTION_KEYWORDS   = ["bash", "sh", "python", "perl", "ruby", "php", ".sh", "exec", "eval"]

def calculate_risk(session):
    score    = 0
    reasons  = []
    commands = [c.lower() for c in session.get("commands", [])]
    cmd_str  = " ".join(commands)

    # Login success = very high risk
    if session.get("login_success"):
        score += 10
        reasons.append("Successful login (+10)")

    # Many login attempts = brute force
    attempts = session.get("login_attempts", 0)
    if attempts >= 10:
        score += 5
        reasons.append(f"High brute force attempts: {attempts} (+5)")
    elif attempts >= 3:
        score += 2
        reasons.append(f"Multiple login attempts: {attempts} (+2)")

    # Credential access commands
    cred_hits = [k for k in CREDENTIAL_KEYWORDS if k in cmd_str]
    if cred_hits:
        score += len(cred_hits) * 4
        reasons.append(f"Credential access commands: {', '.join(cred_hits)} (+{len(cred_hits)*4})")

    # Persistence commands
    pers_hits = [k for k in PERSISTENCE_KEYWORDS if k in cmd_str]
    if pers_hits:
        score += len(pers_hits) * 5
        reasons.append(f"Persistence attempt: {', '.join(pers_hits)} (+{len(pers_hits)*5})")

    # Download/C2 commands
    dl_hits = [k for k in DOWNLOAD_KEYWORDS if k in cmd_str]
    if dl_hits:
        score += len(dl_hits) * 3
        reasons.append(f"Tool/payload download: {', '.join(dl_hits)} (+{len(dl_hits)*3})")

    # Defense evasion
    eva_hits = [k for k in EVASION_KEYWORDS if k in cmd_str]
    if eva_hits:
        score += len(eva_hits) * 4
        reasons.append(f"Defense evasion: {', '.join(eva_hits)} (+{len(eva_hits)*4})")

    # Execution
    exec_hits = [k for k in EXECUTION_KEYWORDS if k in cmd_str]
    if exec_hits:
        score += len(exec_hits) * 2
        reasons.append(f"Execution attempt: {', '.join(exec_hits)} (+{len(exec_hits)*2})")

    # Raw command volume
    cmd_count = len(commands)
    if cmd_count > 10:
        score += 3
        reasons.append(f"High command volume: {cmd_count} (+3)")
    elif cmd_count > 4:
        score += 1
        reasons.append(f"Moderate command volume: {cmd_count} (+1)")

    # Determine level
    if score >= 15:
        level = "CRITICAL"
        color = "danger"
        icon  = "🔴"
    elif score >= 8:
        level = "HIGH"
        color = "warning"
        icon  = "🟠"
    elif score >= 4:
        level = "MEDIUM"
        color = "info"
        icon  = "🟡"
    else:
        level = "LOW"
        color = "success"
        icon  = "🟢"

    return {
        "score":   score,
        "level":   level,
        "color":   color,
        "icon":    icon,
        "reasons": reasons
    }