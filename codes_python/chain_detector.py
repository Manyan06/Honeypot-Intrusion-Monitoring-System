# chain_detector.py  —  UPGRADE 2: Attack Chain Detection

from mitre_mapper import get_tactic_sequence

# Known attack chain patterns: (ordered subset of tactics → chain name)
KNOWN_CHAINS = [
    {
        "name":        "Full Compromise Chain",
        "severity":    "CRITICAL",
        "sequence":    ["Discovery", "Credential Access", "Persistence"],
        "description": "Attacker performed recon, stole credentials, and established persistence",
        "color":       "danger"
    },
    {
        "name":        "Malware Deployment Chain",
        "severity":    "CRITICAL",
        "sequence":    ["Discovery", "Command and Control", "Execution"],
        "description": "Attacker enumerated system, downloaded tools, and executed payload",
        "color":       "danger"
    },
    {
        "name":        "Credential Harvesting Chain",
        "severity":    "HIGH",
        "sequence":    ["Discovery", "Credential Access"],
        "description": "Attacker performed recon followed by credential theft attempt",
        "color":       "warning"
    },
    {
        "name":        "Privilege Escalation Chain",
        "severity":    "HIGH",
        "sequence":    ["Discovery", "Privilege Escalation"],
        "description": "Attacker enumerated system and attempted to escalate privileges",
        "color":       "warning"
    },
    {
        "name":        "Persistence Chain",
        "severity":    "HIGH",
        "sequence":    ["Discovery", "Persistence"],
        "description": "Attacker surveyed the system and planted a backdoor",
        "color":       "warning"
    },
    {
        "name":        "Defense Evasion Chain",
        "severity":    "MEDIUM",
        "sequence":    ["Discovery", "Defense Evasion"],
        "description": "Attacker explored system and attempted to hide activity",
        "color":       "info"
    },
    {
        "name":        "Reconnaissance Only",
        "severity":    "LOW",
        "sequence":    ["Discovery"],
        "description": "Attacker only performed basic system enumeration",
        "color":       "success"
    },
]

def _is_subsequence(pattern, sequence):
    """Check if pattern is an ordered subsequence of sequence."""
    it = iter(sequence)
    return all(tactic in it for tactic in pattern)

def detect_chain(commands):
    if not commands:
        return {
            "name":        "No Activity",
            "severity":    "NONE",
            "sequence":    [],
            "description": "No commands executed in this session",
            "color":       "secondary",
            "tactic_flow": []
        }

    tactic_sequence = get_tactic_sequence(commands)

    # Try matching known chains (most severe first)
    for chain in KNOWN_CHAINS:
        if _is_subsequence(chain["sequence"], tactic_sequence):
            return {
                "name":        chain["name"],
                "severity":    chain["severity"],
                "sequence":    chain["sequence"],
                "description": chain["description"],
                "color":       chain["color"],
                "tactic_flow": tactic_sequence
            }

    # Fallback: unknown pattern
    return {
        "name":        "Unknown Pattern",
        "severity":    "MEDIUM",
        "sequence":    list(set(tactic_sequence)),
        "description": "Unusual command sequence not matching known attack chains",
        "color":       "info",
        "tactic_flow": tactic_sequence
    }