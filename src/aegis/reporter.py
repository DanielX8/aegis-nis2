"""
Aegis NIS2 - Regulatory Report Generator.

Produces Article 23 compliant reports (24h early warning, 72h notification, final report).
"""
from __future__ import annotations
from datetime import datetime, timezone
import pathlib
from typing import Optional
from jinja2 import Environment, FileSystemLoader

from aegis.models import Incident, NIS2Report, ReportStage, ReportStatus

class NIS2Reporter:
    def __init__(self, templates_dir: Optional[pathlib.Path] = None):
        self.templates_dir = templates_dir or pathlib.Path(__file__).parent.parent.parent / "templates"
        self.env = Environment(
            loader=FileSystemLoader(str(self.templates_dir)),
            autoescape=False,
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def generate_early_warning(self, incident: Incident, nca_reference: str = "NCA-NIS2-EU") -> str:
        template = self.env.get_template("early_warning.md.j2")
        return template.render(
            incident=incident,
            nca_reference=nca_reference,
            generated_at=datetime.now(timezone.utc),
        )

    def generate_incident_notification(self, incident: Incident) -> str:
        template = self.env.get_template("incident_notification.md.j2")
        return template.render(
            incident=incident,
            generated_at=datetime.now(timezone.utc),
        )

    def create_report_record(self, incident: Incident, stage: ReportStage) -> NIS2Report:
        if stage == ReportStage.EARLY_WARNING:
            deadline = incident.early_warning_deadline
        elif stage == ReportStage.INCIDENT_NOTIFICATION:
            deadline = incident.notification_deadline
        else:
            deadline = incident.final_report_deadline

        return NIS2Report(
            incident_id=incident.id,
            stage=stage,
            status=ReportStatus.DRAFT,
            deadline=deadline,
            incident_type=incident.mitre_technique_name or incident.description,
            severity=incident.severity.value,
            mitre_technique=incident.mitre_technique_id,
            iocs=incident.source_ips,
            affected_sector=incident.affected_sector,
            cross_border_impact=incident.cross_border_impact,
        )
