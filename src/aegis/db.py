"""
Aegis NIS2 -- SQLite Incident Store.
NIS2 Article 21(2)(b): Persistent, auditable incident records support regulatory reporting.
"""
from __future__ import annotations
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from aegis.models import Incident, IncidentStatus, Severity

DEFAULT_DB = Path("aegis.db")


class IncidentDB:
    """Lightweight SQLite wrapper for incident persistence."""

    def __init__(self, db_path: Path | str = DEFAULT_DB) -> None:
        self.db_path = Path(db_path)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,
                    detected_at TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open',
                    mitre_technique_id TEXT,
                    mitre_technique_name TEXT,
                    mitre_tactic TEXT,
                    affected_hosts TEXT NOT NULL DEFAULT '[]',
                    source_ips TEXT NOT NULL DEFAULT '[]',
                    affected_sector TEXT NOT NULL DEFAULT 'General',
                    description TEXT NOT NULL,
                    suspected_cause TEXT,
                    cross_border_impact INTEGER NOT NULL DEFAULT 0,
                    quarantine_applied INTEGER NOT NULL DEFAULT 0,
                    playbook_executed TEXT,
                    nis2_early_warning_sent INTEGER NOT NULL DEFAULT 0,
                    nis2_notification_sent INTEGER NOT NULL DEFAULT 0,
                    nis2_final_report_sent INTEGER NOT NULL DEFAULT 0,
                    raw_alert_ids TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL
                )
            """)

    def save(self, incident: Incident) -> None:
        """Insert or replace an incident record."""
        with self._connect() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO incidents (
                    id, detected_at, severity, status,
                    mitre_technique_id, mitre_technique_name, mitre_tactic,
                    affected_hosts, source_ips, affected_sector,
                    description, suspected_cause, cross_border_impact,
                    quarantine_applied, playbook_executed,
                    nis2_early_warning_sent, nis2_notification_sent, nis2_final_report_sent,
                    raw_alert_ids, created_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                incident.id, incident.detected_at.isoformat(), incident.severity.value,
                incident.status.value, incident.mitre_technique_id, incident.mitre_technique_name,
                incident.mitre_tactic, json.dumps(incident.affected_hosts),
                json.dumps(incident.source_ips), incident.affected_sector,
                incident.description, incident.suspected_cause,
                int(incident.cross_border_impact), int(incident.quarantine_applied),
                incident.playbook_executed,
                int(incident.nis2_early_warning_sent), int(incident.nis2_notification_sent),
                int(incident.nis2_final_report_sent),
                json.dumps(incident.raw_alert_ids),
                datetime.now(timezone.utc).isoformat(),
            ))

    def get(self, incident_id: str) -> Optional[Incident]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        return self._row_to_incident(row) if row else None

    def list_all(self, severity: Optional[Severity] = None, status: Optional[IncidentStatus] = None) -> list[Incident]:
        query = "SELECT * FROM incidents WHERE 1=1"
        params: list = []
        if severity:
            query += " AND severity = ?"
            params.append(severity.value)
        if status:
            query += " AND status = ?"
            params.append(status.value)
        query += " ORDER BY detected_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_incident(r) for r in rows]

    def list_nis2_reportable(self) -> list[Incident]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM incidents WHERE severity IN ('critical','high') ORDER BY detected_at DESC"
            ).fetchall()
        return [self._row_to_incident(r) for r in rows]

    def update_status(self, incident_id: str, status: IncidentStatus) -> None:
        with self._connect() as conn:
            conn.execute("UPDATE incidents SET status = ? WHERE id = ?", (status.value, incident_id))

    def _row_to_incident(self, row: sqlite3.Row) -> Incident:
        return Incident(
            id=row["id"],
            detected_at=datetime.fromisoformat(row["detected_at"]),
            severity=Severity(row["severity"]),
            status=IncidentStatus(row["status"]),
            mitre_technique_id=row["mitre_technique_id"],
            mitre_technique_name=row["mitre_technique_name"],
            mitre_tactic=row["mitre_tactic"],
            affected_hosts=json.loads(row["affected_hosts"]),
            source_ips=json.loads(row["source_ips"]),
            affected_sector=row["affected_sector"],
            description=row["description"],
            suspected_cause=row["suspected_cause"],
            cross_border_impact=bool(row["cross_border_impact"]),
            quarantine_applied=bool(row["quarantine_applied"]),
            playbook_executed=row["playbook_executed"],
            nis2_early_warning_sent=bool(row["nis2_early_warning_sent"]),
            nis2_notification_sent=bool(row["nis2_notification_sent"]),
            nis2_final_report_sent=bool(row["nis2_final_report_sent"]),
            raw_alert_ids=json.loads(row["raw_alert_ids"]),
        )
