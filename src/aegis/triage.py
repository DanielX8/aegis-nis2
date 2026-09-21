"""
Aegis NIS2 - Triage Engine.

Maps normalized alerts to MITRE ATT&CK techniques and assigns NIS2-aware severity levels.
Produces Incident objects ready for persistence, quarantine, and regulatory notification.
"""
from __future__ import annotations
from datetime import datetime, timezone
import json
import re
from typing import List, Optional

from aegis.models import Alert, Incident, Severity

MITRE_RULES = [
    # Check specific high-impact techniques first
    (r"shadow\s*copy|vssadmin|resize\s*shadowstorage|bcedit", "T1490", "Inhibit System Recovery", Severity.CRITICAL),
    (r"ransomware|encrypted\s*files|ransom\s*note|\.locked|\.crypted", "T1486", "Data Encrypted for Impact", Severity.CRITICAL),
    (r"mimikatz|lsass|sekurlsa|kerberoast|credential\s*dump", "T1003", "OS Credential Dumping", Severity.HIGH),
    (r"ssh.*failed|failed\s*password|authentication\s*failure|brute\s*force|invalid\s*user", "T1110", "Brute Force", Severity.HIGH),
    (r"powershell.*downloadstring|powershell.*-enc|certutil.*-urlcache", "T1059.001", "Command and Scripting Interpreter: PowerShell", Severity.HIGH),
    (r"exfiltration|data\s*leak|upload.*mega\.nz|s3\s*bucket\s*sync", "T1048", "Exfiltration Over Alternative Protocol", Severity.CRITICAL),
    (r"nmap|port\s*scan|masscan|syn\s*scan", "T1046", "Network Service Discovery", Severity.LOW),
]

def triage_alert(alert: Alert) -> Incident:
    alert_desc = alert.description or ""
    raw_str = json.dumps(alert.raw) if isinstance(alert.raw, dict) else str(alert.raw or "")
    combined = f"{alert_desc} {raw_str}".lower()

    matched_technique = None
    matched_tactic = None
    assigned_severity = Severity.LOW

    for pattern, tech_id, tactic, sev in MITRE_RULES:
        if re.search(pattern, combined):
            matched_technique = tech_id
            matched_tactic = tactic
            assigned_severity = sev
            break
    else:
        # Fallback based on rule level
        lvl = alert.rule_level or 0
        if lvl >= 12:
            assigned_severity = Severity.CRITICAL
        elif lvl >= 8:
            assigned_severity = Severity.HIGH
        elif lvl >= 4:
            assigned_severity = Severity.MEDIUM
        else:
            assigned_severity = Severity.LOW

    desc_final = alert.description or f"Alert {alert.rule_id or alert.id}"

    return Incident(
        severity=assigned_severity,
        mitre_technique_id=matched_technique,
        mitre_technique_name=matched_tactic,
        affected_hosts=[alert.hostname] if alert.hostname else [],
        source_ips=[alert.source_ip] if alert.source_ip else [],
        description=desc_final,
        raw_alert_ids=[alert.id],
    )

def triage_batch(alerts: List[Alert]) -> List[Incident]:
    return [triage_alert(a) for a in alerts]

def max_severity(*sevs: Severity) -> Severity:
    order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    if not sevs:
        return Severity.LOW
    highest = sevs[0]
    for s in sevs[1:]:
        if order.index(s) > order.index(highest):
            highest = s
    return highest
