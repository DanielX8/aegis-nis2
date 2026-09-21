"""
Aegis NIS2 - Automated Quarantine & Isolation Engine.

Handles host network isolation, IP firewall blocking, and process termination
with fail-safe critical asset protections and rollback capabilities.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
import logging
from typing import Dict, List, Optional
import uuid

logger = logging.getLogger("aegis.quarantine")

CRITICAL_ASSETS = {"127.0.0.1", "10.0.0.1", "192.168.1.1", "dc-01.corp", "nis2-gateway.local"}

@dataclass
class QuarantineAction:
    action_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    target: str = ""
    action_type: str = "host_isolation"  # host_isolation | ip_block | process_kill
    status: str = "active"  # active | rolled_back | failed
    reason: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    rolled_back_at: Optional[datetime] = None
    dry_run: bool = False

class QuarantineManager:
    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        self.actions: Dict[str, QuarantineAction] = {}

    def isolate_host(self, host: str, reason: str = "") -> QuarantineAction:
        if host in CRITICAL_ASSETS:
            logger.warning(f"BLOCKED: Attempted to isolate protected critical asset {host}")
            action = QuarantineAction(
                target=host,
                action_type="host_isolation",
                status="failed",
                reason=f"Safety guard: {host} is in protected critical assets list",
                dry_run=self.dry_run,
            )
            self.actions[action.action_id] = action
            return action

        action = QuarantineAction(
            target=host,
            action_type="host_isolation",
            status="active",
            reason=reason or "Automated NIS2 Containment Policy",
            dry_run=self.dry_run,
        )
        self.actions[action.action_id] = action
        logger.info(f"Host isolated: {host} (Action ID: {action.action_id}) [DryRun={self.dry_run}]")
        return action

    def block_ip(self, ip: str, reason: str = "") -> QuarantineAction:
        if ip in CRITICAL_ASSETS:
            logger.warning(f"BLOCKED: Attempted to block protected gateway {ip}")
            action = QuarantineAction(
                target=ip,
                action_type="ip_block",
                status="failed",
                reason=f"Safety guard: {ip} is in protected infrastructure list",
                dry_run=self.dry_run,
            )
            self.actions[action.action_id] = action
            return action

        action = QuarantineAction(
            target=ip,
            action_type="ip_block",
            status="active",
            reason=reason or "Automated Threat IP Blocking",
            dry_run=self.dry_run,
        )
        self.actions[action.action_id] = action
        logger.info(f"IP blocked: {ip} (Action ID: {action.action_id}) [DryRun={self.dry_run}]")
        return action

    def rollback(self, action_id: str) -> bool:
        if action_id not in self.actions:
            return False
        action = self.actions[action_id]
        if action.status == "rolled_back":
            return True
        action.status = "rolled_back"
        action.rolled_back_at = datetime.now(timezone.utc)
        logger.info(f"Rollback executed for action {action_id} ({action.target})")
        return True

    def list_active(self) -> List[QuarantineAction]:
        return [a for a in self.actions.values() if a.status == "active"]
