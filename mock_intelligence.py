import random

def get_mock_security_report(data_summary: str):
    """
    Returns a realistic mock security report based on input keywords.
    """
    stacks = ["React", "Node.js", "Python", "Django", "PostgreSQL", "JavaScript", "AWS", "Firebase"]
    detected_stack = [s for s in stacks if s.lower() in data_summary.lower()]
    if not detected_stack:
        detected_stack = ["Generic Web App"]

    risk_score = random.randint(45, 88)
    
    mock_data = {
        "risk_score": risk_score,
        "attack_path": "Adversary identifies exposed .env file in public directory, extracts master database credentials, and initiates a full data exfiltration through the admin portal.",
        "breach_points": [
            { "area": "Public Directory", "reason": "Exposed configuration files (.env, .git) found during directory traversal." },
            { "area": "Authentication Module", "reason": "Weak password policy and lack of MFA on administrator accounts." }
        ],
        "components": [
            { "name": "Frontend", "risk": 40 },
            { "name": "Database", "risk": 85 },
            { "name": "Auth Server", "risk": 90 }
        ],
        "failed_tests": [
            { "name": "Directory Traversal", "risk": 95 },
            { "name": "Broken Access Control", "risk": 80 },
            { "name": "Insecure JWT Storage", "risk": 70 }
        ],
        "defense_plan": [
            "Secure sensitive configuration files immediately.",
            "Enforce Multi-Factor Authentication (MFA) across all administrative endpoints.",
            "Implement a strict Content Security Policy (CSP) to mitigate script injection."
        ],
        "attacker_vision": [
            {
                "step": "Reconnaissance",
                "method": "Brute-forcing directory endpoints using common wordlists.",
                "leverage": "Discovers misconfigured permissions on the upload folder."
            },
            {
                "step": "Weaponization",
                "method": "Uploading a reverse-shell script disguised as an image file.",
                "leverage": "Gains initial foothold on the application server."
            }
        ],
        "defender_fixes": [
            {
                "target": "File System",
                "action": "Ensure all configuration files are outside the web-root.",
                "why": "Prevents attackers from downloading your private keys and passwords directly from the browser."
            },
            {
                "target": "Access Control",
                "action": "Require a second code from an app when logging in.",
                "why": "Even if a hacker steals your password, they can't get into your account without that secret code."
            }
        ],
        "mermaid_graph": "graph TD\nA[Attacker] -->|Exploit Directory| B[.env File]\nB -->|Credential Theft| C[Database]\nC -->|Data Exfiltration| D[Dark Web]\nB -->|Full Access| E[Admin Portal]",
        "is_mock": True
    }
    
    return mock_data
