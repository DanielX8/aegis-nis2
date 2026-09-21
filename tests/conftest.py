"""Shared pytest fixtures for Aegis NIS2 tests."""
import pytest
from datetime import datetime, timezone


@pytest.fixture
def sample_wazuh_alert():
    return {
        "id": "1695000001.12345",
        "timestamp": "2024-09-18T08:00:00.000Z",
        "rule": {"id": "5763", "level": 10, "description": "Multiple authentication failures."},
        "agent": {"id": "001", "name": "linux-srv-01", "ip": "10.0.1.15"},
        "data": {
            "srcip": "185.220.101.5",
            "dstip": "10.0.1.15",
            "dstport": "22",
            "protocol": "tcp",
        },
        "full_log": "sshd[1234]: Failed password for root from 185.220.101.5 port 51204 ssh2",
    }


@pytest.fixture
def sample_incident():
    from aegis.models import Incident, Severity
    return Incident(
        id="INC-2024-0001",
        detected_at=datetime(2024, 9, 18, 8, 0, 0, tzinfo=timezone.utc),
        severity=Severity.HIGH,
        mitre_technique_id="T1110",
        mitre_technique_name="Brute Force",
        affected_hosts=["10.0.1.15"],
        source_ips=["185.220.101.5"],
        description="Multiple SSH authentication failures from external IP",
        raw_alert_ids=["1695000001.12345"],
    )
