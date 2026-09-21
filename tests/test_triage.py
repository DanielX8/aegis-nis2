"""Tests for the triage engine."""
import pytest
from aegis.triage import triage_alert, triage_batch, max_severity
from aegis.normalizer import normalize_wazuh
from aegis.models import Severity, IncidentStatus


def test_triage_ssh_brute_force(sample_wazuh_alert):
    """SSH brute force (level 10 + 'authentication failure') -> HIGH via technique override."""
    alert = normalize_wazuh(sample_wazuh_alert)
    incident = triage_alert(alert)
    assert incident.mitre_technique_id == "T1110"
    assert incident.mitre_technique_name == "Brute Force"
    assert incident.severity in (Severity.HIGH, Severity.CRITICAL)


def test_triage_ransomware_is_critical():
    raw = {"rule": {"id": "554", "level": 15, "description": "File added to the system: possible ransomware encryption activity."}, "agent": {"name": "ws-01"}, "data": {}}
    alert = normalize_wazuh(raw)
    incident = triage_alert(alert)
    assert incident.severity == Severity.CRITICAL
    assert incident.mitre_technique_id == "T1486"


def test_triage_shadow_copy_deletion_is_critical():
    raw = {"rule": {"id": "92201", "level": 15, "description": "Shadow copy deletion detected: ransomware inhibiting system recovery."}, "agent": {"name": "ws-02"}, "data": {}}
    alert = normalize_wazuh(raw)
    incident = triage_alert(alert)
    assert incident.severity == Severity.CRITICAL
    assert incident.mitre_technique_id == "T1490"


def test_triage_low_level_is_low():
    raw = {"rule": {"id": "100", "level": 3, "description": "Normal user login."}, "agent": {"name": "ws-01"}, "data": {}}
    alert = normalize_wazuh(raw)
    incident = triage_alert(alert)
    assert incident.severity == Severity.LOW


def test_triage_incident_has_nis2_deadlines(sample_incident):
    from datetime import timedelta
    assert sample_incident.early_warning_deadline == sample_incident.detected_at + timedelta(hours=24)
    assert sample_incident.notification_deadline == sample_incident.detected_at + timedelta(hours=72)
    assert sample_incident.final_report_deadline == sample_incident.detected_at + timedelta(days=30)


def test_triage_high_and_critical_are_reportable(sample_incident):
    assert sample_incident.is_nis2_reportable is True


def test_triage_low_is_not_reportable():
    raw = {"rule": {"id": "1", "level": 2, "description": "routine event"}, "agent": {"name": "h"}, "data": {}}
    from aegis.normalizer import normalize_wazuh as nw
    incident = triage_alert(nw(raw))
    assert incident.is_nis2_reportable is False


def test_triage_batch_produces_one_per_alert():
    raws = [
        {"rule": {"id": "1", "level": 10, "description": "failed password"}, "agent": {"name": "h1"}, "data": {"srcip": "1.1.1.1"}},
        {"rule": {"id": "2", "level": 15, "description": "ransomware detected"}, "agent": {"name": "h2"}, "data": {}},
    ]
    from aegis.normalizer import normalize_batch
    alerts = normalize_batch(raws)
    incidents = triage_batch(alerts)
    assert len(incidents) == 2


def test_max_severity():
    assert max_severity(Severity.LOW, Severity.HIGH) == Severity.HIGH
    assert max_severity(Severity.CRITICAL, Severity.HIGH) == Severity.CRITICAL
    assert max_severity(Severity.MEDIUM, Severity.MEDIUM) == Severity.MEDIUM
