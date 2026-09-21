import pytest
from aegis.models import Incident, Severity
from aegis.threat_intel import ThreatIntelExporter

def test_threat_intel_stix_bundle():
    incident = Incident(
        description="SSH Brute Force on Bastion",
        severity=Severity.HIGH,
        mitre_technique_id="T1110",
        mitre_technique_name="Brute Force",
        source_ips=["203.0.113.5"],
    )
    bundle = ThreatIntelExporter.to_stix_bundle(incident)
    assert bundle["type"] == "bundle"
    assert len(bundle["objects"]) >= 3
    types = [obj["type"] for obj in bundle["objects"]]
    assert "indicator" in types
    assert "attack-pattern" in types
