import pytest
from aegis.models import Incident, Severity, IncidentStatus
from aegis.playbooks import PlaybookRunner

def test_playbook_execution_ransomware():
    runner = PlaybookRunner()
    incident = Incident(
        description="Ransomware detected: encrypted files",
        severity=Severity.CRITICAL,
        mitre_technique_id="T1486",
        source_ips=["198.51.100.77"],
        affected_hosts=["ws-financial-01"],
    )
    result = runner.run_for_incident(incident)
    assert result.status == "completed"
    assert incident.status == IncidentStatus.CONTAINED
    assert len(result.steps) > 0
