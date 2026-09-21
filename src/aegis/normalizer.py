"""
Aegis NIS2 — Event Normalizer.

Transforms raw security alerts from Wazuh JSON or syslog CEF format into
structured Alert objects with extracted fields.

NIS2 Article 21(2)(a): Supports risk analysis by ensuring all telemetry
is in a consistent, queryable format.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from aegis.models import Alert, AlertSource


# ---------------------------------------------------------------------------
# Wazuh JSON normalizer
# ---------------------------------------------------------------------------

def normalize_wazuh(raw: dict[str, Any]) -> Alert:
    """
    Parse a Wazuh JSON alert and return a normalized Alert object.

    Expected Wazuh fields:
      id, timestamp, rule.{id,level,description}, agent.{name,ip}, data.{srcip,dstip,dstport}
    """
    alert = Alert(source=AlertSource.WAZUH, raw=raw)

    # Timestamp
    ts_str = raw.get("timestamp", "")
    if ts_str:
        try:
            alert.timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except ValueError:
            alert.timestamp = datetime.now(timezone.utc)
    else:
        alert.timestamp = datetime.now(timezone.utc)

    # Rule metadata
    rule = raw.get("rule", {})
    alert.rule_id = str(rule.get("id", ""))
    alert.rule_level = int(rule.get("level", 0))
    alert.description = rule.get("description", "Unknown event")

    # Agent / host info
    agent = raw.get("agent", {})
    alert.hostname = agent.get("name", agent.get("ip", "unknown"))

    # Network fields — Wazuh puts them in data or syscheck
    data = raw.get("data", {})
    alert.source_ip = data.get("srcip") or raw.get("srcip")
    alert.dest_ip = data.get("dstip") or raw.get("dstip") or agent.get("ip")

    dst_port = data.get("dstport") or data.get("dst_port")
    if dst_port:
        try:
            alert.dest_port = int(str(dst_port).split("/")[0])
        except (ValueError, IndexError):
            pass

    return alert


# ---------------------------------------------------------------------------
# Syslog/CEF normalizer
# ---------------------------------------------------------------------------

# Common syslog pattern: <priority>timestamp hostname process[pid]: message
_SYSLOG_RE = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+(?P<host>\S+)\s+(?P<proc>\S+?)(?:\[(?P<pid>\d+)\])?\s*:\s+(?P<msg>.+)"
)

# Basic IP extraction
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Port after "port "
_PORT_RE = re.compile(r"\bport\s+(\d+)\b", re.IGNORECASE)


def normalize_syslog(line: str) -> Alert:
    """Parse a syslog line and return a normalized Alert object."""
    raw = {"raw_line": line}
    alert = Alert(source=AlertSource.SYSLOG, raw=raw)
    alert.timestamp = datetime.now(timezone.utc)

    m = _SYSLOG_RE.match(line.strip())
    if m:
        alert.hostname = m.group("host")
        alert.description = m.group("msg")[:200]
        raw["process"] = m.group("proc")

    # Extract IPs from the message
    ips = _IP_RE.findall(line)
    if len(ips) >= 2:
        alert.source_ip = ips[0]
        alert.dest_ip = ips[1]
    elif len(ips) == 1:
        alert.source_ip = ips[0]

    # Extract port
    port_m = _PORT_RE.search(line)
    if port_m:
        try:
            alert.dest_port = int(port_m.group(1))
        except ValueError:
            pass

    return alert


# ---------------------------------------------------------------------------
# Unified dispatcher
# ---------------------------------------------------------------------------

def normalize(raw: dict[str, Any] | str, source: AlertSource = AlertSource.WAZUH) -> Alert:
    """
    Normalize a raw alert to an Alert object.

    Args:
        raw: Either a dict (Wazuh JSON) or a string (syslog line).
        source: Override the detected source type.
    """
    if isinstance(raw, str):
        return normalize_syslog(raw)
    return normalize_wazuh(raw)


def normalize_batch(alerts: list[dict | str]) -> list[Alert]:
    """Normalize a list of raw alerts, skipping any that fail."""
    results = []
    for item in alerts:
        try:
            results.append(normalize(item))
        except Exception as exc:
            # Emit a minimal alert so nothing is silently dropped
            results.append(Alert(
                source=AlertSource.WAZUH if isinstance(item, dict) else AlertSource.SYSLOG,
                raw={"raw": item, "parse_error": str(exc)},
                description=f"[PARSE ERROR] {exc}",
            ))
    return results
