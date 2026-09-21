"""
Aegis NIS2 — Core data models.

Defines the canonical types used across the entire pipeline:
  Alert      → raw incoming event from Wazuh / syslog
  Incident   → classified, enriched security incident
  NIS2Report → regulatory report (Art. 23 Early Warning / Notification / Final)
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, model_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AlertSource(str, Enum):
    WAZUH = "wazuh"
    SYSLOG = "syslog"
    CEF = "cef"
    MANUAL = "manual"


class ReportStage(str, Enum):
    """NIS2 Article 23 mandatory reporting stages."""
    EARLY_WARNING = "early_warning"        # T+24h
    INCIDENT_NOTIFICATION = "incident_notification"  # T+72h
    FINAL_REPORT = "final_report"          # T+30d


class ReportStatus(str, Enum):
    PENDING = "pending"
    DRAFT = "draft"
    SUBMITTED = "submitted"
    ACKNOWLEDGED = "acknowledged"
    OVERDUE = "overdue"


class IncidentStatus(str, Enum):
    OPEN = "open"
    TRIAGED = "triaged"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


# ---------------------------------------------------------------------------
# Alert — raw incoming event
# ---------------------------------------------------------------------------

class Alert(BaseModel):
    """Raw security event as received from a SIEM or log source."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source: AlertSource = AlertSource.WAZUH
    raw: dict = Field(description="Verbatim event payload")
    received_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Extracted fields (populated by normalizer)
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    hostname: Optional[str] = None
    rule_id: Optional[str] = None
    rule_level: Optional[int] = None
    description: Optional[str] = None
    timestamp: Optional[datetime] = None

    model_config = {"extra": "allow"}


# ---------------------------------------------------------------------------
# Incident — classified security incident
# ---------------------------------------------------------------------------

class Incident(BaseModel):
    """
    A classified security incident derived from one or more alerts.

    Maps to NIS2 Article 21(2)(b) incident handling requirements.
    """
    id: str = Field(default_factory=lambda: f"INC-{datetime.now(timezone.utc).strftime('%Y-%m')}-{str(uuid.uuid4())[:8].upper()}")
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    severity: Severity
    status: IncidentStatus = IncidentStatus.OPEN

    # MITRE ATT&CK enrichment
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    mitre_tactic: Optional[str] = None

    # Scope
    affected_hosts: list[str] = Field(default_factory=list)
    source_ips: list[str] = Field(default_factory=list)
    affected_sector: str = "General"

    # Narrative
    description: str
    suspected_cause: Optional[str] = None
    cross_border_impact: bool = False

    # Traceability
    raw_alert_ids: list[str] = Field(default_factory=list)
    quarantine_applied: bool = False
    playbook_executed: Optional[str] = None

    # NIS2 reporting state
    nis2_early_warning_sent: bool = False
    nis2_notification_sent: bool = False
    nis2_final_report_sent: bool = False

    @property
    def early_warning_deadline(self) -> datetime:
        """NIS2 Art. 23(3)(a): Early warning within 24 hours of awareness."""
        return self.detected_at + timedelta(hours=24)

    @property
    def notification_deadline(self) -> datetime:
        """NIS2 Art. 23(3)(b): Incident notification within 72 hours."""
        return self.detected_at + timedelta(hours=72)

    @property
    def final_report_deadline(self) -> datetime:
        """NIS2 Art. 23(3)(c): Final report within one month."""
        return self.detected_at + timedelta(days=30)

    @property
    def is_nis2_reportable(self) -> bool:
        """An incident is NIS2-reportable if it is High or Critical severity."""
        return self.severity in (Severity.CRITICAL, Severity.HIGH)

    model_config = {"extra": "allow"}


# ---------------------------------------------------------------------------
# NIS2Report — Article 23 regulatory report
# ---------------------------------------------------------------------------

class NIS2Report(BaseModel):
    """
    A single NIS2 Article 23 regulatory report submission.

    Three instances are generated per reportable incident:
      1. Early Warning     (T+24h)
      2. Incident Notification (T+72h)
      3. Final Report      (T+30d)
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str
    stage: ReportStage
    status: ReportStatus = ReportStatus.DRAFT

    # Deadlines
    deadline: datetime
    submitted_at: Optional[datetime] = None

    # Common fields (all three reports)
    incident_type: str
    suspected_cause: Optional[str] = None
    affected_sector: str = "General"
    cross_border_impact: bool = False
    affected_member_states: list[str] = Field(default_factory=list)

    # Incident Notification + Final Report fields
    severity: Optional[str] = None
    iocs: list[str] = Field(default_factory=list)
    mitre_technique: Optional[str] = None
    affected_systems_count: Optional[int] = None
    containment_actions: list[str] = Field(default_factory=list)

    # Final Report only
    root_cause: Optional[str] = None
    remediation_steps: list[str] = Field(default_factory=list)
    lessons_learned: Optional[str] = None
    nis2_control_gaps: list[str] = Field(default_factory=list)

    @property
    def is_overdue(self) -> bool:
        now = datetime.now(timezone.utc)
        return self.status not in (ReportStatus.SUBMITTED, ReportStatus.ACKNOWLEDGED) and now > self.deadline

    @property
    def hours_until_deadline(self) -> float:
        delta = self.deadline - datetime.now(timezone.utc)
        return delta.total_seconds() / 3600

    model_config = {"extra": "allow"}
