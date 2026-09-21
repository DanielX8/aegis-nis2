"""
Aegis NIS2 - STIX 2.1 Threat Intelligence Bundle Generator.
"""
from __future__ import annotations
from datetime import datetime, timezone
import json
from typing import Any, Dict, List
import uuid

from aegis.models import Incident

class ThreatIntelExporter:
    @staticmethod
    def to_stix_bundle(incident: Incident) -> Dict[str, Any]:
        bundle_id = f"bundle--{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        objects: List[Dict[str, Any]] = [
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": f"identity--{uuid.uuid4()}",
                "name": "Aegis NIS2 CIRT",
                "identity_class": "organization",
                "created": now_iso,
                "modified": now_iso,
            },
            {
                "type": "incident",
                "spec_version": "2.1",
                "id": f"incident--{uuid.uuid4()}",
                "name": incident.description,
                "description": incident.description,
                "created": now_iso,
                "modified": now_iso,
                "labels": ["nis2-reportable" if incident.is_nis2_reportable else "nis2-internal", incident.severity.value.lower()],
            }
        ]

        for ip in incident.source_ips:
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "name": f"Malicious IP {ip}",
                "pattern": f"[ipv4-addr:value = '{ip}']",
                "pattern_type": "stix",
                "valid_from": now_iso,
                "created": now_iso,
                "modified": now_iso,
            })

        if incident.mitre_technique_id:
            objects.append({
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": f"attack-pattern--{uuid.uuid4()}",
                "name": incident.mitre_technique_name or incident.mitre_technique_id,
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": incident.mitre_technique_id,
                    }
                ],
                "created": now_iso,
                "modified": now_iso,
            })

        return {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects,
        }
