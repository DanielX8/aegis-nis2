import pytest
from aegis.models import Incident, Severity, ReportStage
from aegis.reporter import NIS2Reporter

def test_reporter_early_warning():
    reporter = NIS2Reporter()
    incident = Incident(
        description="Active Shadow Copy Deletion",
        severity=Severity.CRITICAL,
        mitre_technique_id="T1490",
        mitre_technique_name="Inhibit System Recovery",
        affected_hosts=["srv-prod-db"],
    )
    doc = reporter.generate_early_warning(incident)
    assert "NIS2 Article 23(4)(a)" in doc
    assert "CRITICAL" in doc
    assert "T1490" in doc

def test_reporter_create_record():
    reporter = NIS2Reporter()
    incident = Incident(
        description="Active Shadow Copy Deletion",
        severity=Severity.CRITICAL,
        mitre_technique_id="T1490",
    )
    record = reporter.create_report_record(incident, ReportStage.EARLY_WARNING)
    assert record.incident_id == incident.id
    assert record.stage == ReportStage.EARLY_WARNING
    assert record.deadline == incident.early_warning_deadline
