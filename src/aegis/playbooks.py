"""
Aegis NIS2 - Playbook Execution Engine.

Executes structured YAML-based response playbooks mapped to MITRE ATT&CK techniques.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
import pathlib
from typing import Any, Dict, List, Optional
import yaml

from aegis.models import Incident, IncidentStatus, Severity
from aegis.quarantine import QuarantineManager

@dataclass
class PlaybookStepResult:
    step_name: str
    action: str
    status: str
    details: Dict[str, Any] = field(default_factory=dict)
    executed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

@dataclass
class PlaybookResult:
    playbook_id: str
    incident_id: str
    status: str
    steps: List[PlaybookStepResult] = field(default_factory=list)
    completed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

class PlaybookRunner:
    def __init__(self, playbooks_dir: Optional[pathlib.Path] = None, quarantine_mgr: Optional[QuarantineManager] = None):
        self.playbooks_dir = playbooks_dir or pathlib.Path(__file__).parent.parent.parent / "playbooks"
        self.quarantine_mgr = quarantine_mgr or QuarantineManager(dry_run=True)
        self.playbooks: Dict[str, Dict[str, Any]] = {}
        self.load_playbooks()

    def load_playbooks(self):
        if not self.playbooks_dir.exists():
            return
        for file in self.playbooks_dir.glob("*.yml"):
            try:
                data = yaml.safe_load(file.read_text(encoding="utf-8"))
                if data and "id" in data:
                    self.playbooks[data["id"]] = data
            except Exception:
                pass

    def run_for_incident(self, incident: Incident) -> PlaybookResult:
        pb_id = "default"
        if incident.mitre_technique_id in ("T1486", "T1490"):
            pb_id = "ransomware-response"
        elif incident.mitre_technique_id == "T1110":
            pb_id = "brute-force-response"

        pb_config = self.playbooks.get(pb_id, {
            "id": pb_id,
            "name": f"Automated Response for {incident.mitre_technique_id or 'General Incident'}",
            "steps": [
                {"name": "Isolate Affected Hosts", "action": "isolate_host"},
                {"name": "Block Ingress IP", "action": "block_source_ip"},
            ]
        })

        step_results = []
        for step in pb_config.get("steps", []):
            name = step.get("name", "Step")
            action = step.get("action", "")
            status = "completed"
            details = {}

            if action == "isolate_host":
                for host in incident.affected_hosts:
                    q = self.quarantine_mgr.isolate_host(host, reason=f"Incident {incident.id}")
                    details[host] = q.status
            elif action == "block_source_ip":
                for ip in incident.source_ips:
                    q = self.quarantine_mgr.block_ip(ip, reason=f"Incident {incident.id}")
                    details[ip] = q.status

            step_results.append(PlaybookStepResult(step_name=name, action=action, status=status, details=details))

        incident.status = IncidentStatus.CONTAINED
        incident.quarantine_applied = True
        incident.playbook_executed = pb_id
        return PlaybookResult(
            playbook_id=pb_id,
            incident_id=incident.id,
            status="completed",
            steps=step_results,
        )
