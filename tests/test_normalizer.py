"""Tests for the alert normalizer."""
import pytest
from datetime import timezone
from aegis.normalizer import normalize_wazuh, normalize_syslog, normalize_batch
from aegis.models import AlertSource


def test_wazuh_normalizer_extracts_basic_fields(sample_wazuh_alert):
    alert = normalize_wazuh(sample_wazuh_alert)
    assert alert.source == AlertSource.WAZUH
    assert alert.hostname == "linux-srv-01"
    assert alert.source_ip == "185.220.101.5"
    assert alert.dest_ip == "10.0.1.15"
    assert alert.dest_port == 22
    assert alert.rule_id == "5763"
    assert alert.rule_level == 10
    assert "authentication" in alert.description.lower()


def test_wazuh_normalizer_timestamp_parsed(sample_wazuh_alert):
    alert = normalize_wazuh(sample_wazuh_alert)
    assert alert.timestamp is not None
    assert alert.timestamp.tzinfo is not None


def test_wazuh_normalizer_missing_fields():
    minimal = {"rule": {"id": "999", "level": 5, "description": "test"}, "agent": {"name": "host1"}, "data": {}}
    alert = normalize_wazuh(minimal)
    assert alert.hostname == "host1"
    assert alert.source_ip is None
    assert alert.rule_level == 5


def test_syslog_normalizer_extracts_ips():
    line = "Sep 18 08:00:01 webserver sshd[1234]: Failed password for root from 203.0.113.5 port 41200 ssh2"
    alert = normalize_syslog(line)
    assert alert.source == AlertSource.SYSLOG
    assert alert.source_ip == "203.0.113.5"
    assert alert.hostname == "webserver"


def test_syslog_normalizer_no_crash_on_malformed():
    alert = normalize_syslog("this is not a valid syslog line at all!!!")
    assert alert is not None
    assert alert.source == AlertSource.SYSLOG


def test_batch_normalizer_handles_mixed():
    items = [
        {"rule": {"id": "1", "level": 10, "description": "ssh brute force"}, "agent": {"name": "h1"}, "data": {"srcip": "1.2.3.4"}},
        "Sep 18 09:00:00 host1 sshd[111]: Failed password from 5.6.7.8",
    ]
    alerts = normalize_batch(items)
    assert len(alerts) == 2


def test_batch_normalizer_does_not_drop_on_partial_error():
    items = [None, {"rule": {"id": "1", "level": 5, "description": "test"}, "agent": {"name": "h"}, "data": {}}]
    alerts = normalize_batch(items)
    assert len(alerts) == 2
    assert "PARSE ERROR" in alerts[0].description
