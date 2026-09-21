import pytest
from aegis.quarantine import QuarantineManager

def test_quarantine_isolate_host():
    qm = QuarantineManager(dry_run=True)
    action = qm.isolate_host("workstation-99", reason="Ransomware lateral spread")
    assert action.status == "active"
    assert action.target == "workstation-99"
    assert len(qm.list_active()) == 1

def test_quarantine_block_critical_asset_protection():
    qm = QuarantineManager(dry_run=True)
    action = qm.isolate_host("127.0.0.1")
    assert action.status == "failed"
    assert "Safety guard" in action.reason

def test_quarantine_rollback():
    qm = QuarantineManager(dry_run=True)
    action = qm.block_ip("198.51.100.23")
    assert action.status == "active"
    success = qm.rollback(action.action_id)
    assert success is True
    assert len(qm.list_active()) == 0
