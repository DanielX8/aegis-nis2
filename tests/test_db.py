"""Tests for the SQLite incident store."""
import pytest
import tempfile
from pathlib import Path
from aegis.db import IncidentDB
from aegis.models import Severity, IncidentStatus


@pytest.fixture
def db(tmp_path):
    return IncidentDB(tmp_path / "test.db")


def test_save_and_retrieve(db, sample_incident):
    db.save(sample_incident)
    fetched = db.get(sample_incident.id)
    assert fetched is not None
    assert fetched.id == sample_incident.id
    assert fetched.severity == sample_incident.severity
    assert fetched.mitre_technique_id == sample_incident.mitre_technique_id


def test_list_all_empty(db):
    assert db.list_all() == []


def test_list_all_with_filter(db, sample_incident):
    db.save(sample_incident)
    results = db.list_all(severity=Severity.HIGH)
    assert len(results) == 1
    results_critical = db.list_all(severity=Severity.CRITICAL)
    assert len(results_critical) == 0


def test_update_status(db, sample_incident):
    db.save(sample_incident)
    db.update_status(sample_incident.id, IncidentStatus.CONTAINED)
    fetched = db.get(sample_incident.id)
    assert fetched.status == IncidentStatus.CONTAINED


def test_nis2_reportable_only_returns_high_critical(db, sample_incident):
    db.save(sample_incident)
    reportable = db.list_nis2_reportable()
    assert len(reportable) == 1
    assert all(i.severity in (Severity.HIGH, Severity.CRITICAL) for i in reportable)
