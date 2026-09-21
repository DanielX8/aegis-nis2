# Aegis NIS2 (SOAR & Compliance Engine)

> **Autonomous Incident Triage, Automated Containment & Article 23 Regulatory Compliance**

A lightweight, enterprise-grade Python SOAR and Incident Response framework purpose-built for the **EU NIS2 Directive (Directive 2022/2555)** and modern Security Operations Centers (SOC).

---

## Key Capabilities

1. **Autonomous Log Ingestion & Normalization**:
   - Parses SIEM/EDR formats (Wazuh, Syslog, Suricata/Zeek).
   - Maps alerts directly to **MITRE ATT&CK®** techniques.

2. **NIS2 Article 23 Compliance Radar**:
   - Autonomously calculates mandatory reporting clocks:
     - **24-Hour Early Warning** (Article 23(4)(a))
     - **72-Hour Incident Notification** (Article 23(4)(b))
     - **1-Month Final Incident Report** (Article 23(4)(c))
   - Auto-generates regulator-ready Markdown notifications.

3. **Automated Containment & Quarantine**:
   - YAML-defined playbooks for ransomware containment (`T1486`), shadow copy protection (`T1490`), and credential dumping (`T1003`).
   - Built-in fail-safe protection for critical assets and 1-click rollbacks.

4. **Threat Intelligence & STIX 2.1**:
   - Generates compliant STIX 2.1 bundles for sharing with CSIRTs / national authorities.

5. **Operations Dashboard & Rich CLI**:
   - Interactive terminal UI powered by `Rich` and `Click`.
   - Real-time Flask & Tailwind dark-mode monitoring dashboard.

---

## Quickstart

```bash
# Clone and install
git clone https://github.com/DanielX8/aegis-nis2.git
cd aegis-nis2
pip install -e .

# Triage incoming alert batch
aegis triage --file samples/wazuh-alerts.json

# Execute containment playbooks
aegis respond <INCIDENT_ID>

# Generate 24h early warning regulatory notification
aegis report <INCIDENT_ID> --type 24h

# Export STIX 2.1 bundle for CSIRT sharing
aegis export-stix <INCIDENT_ID>
```

---

## Architecture Diagram

See [aegis-nis2-architecture.html](file:///C:/Users/DLEIN/.gemini/antigravity-ide/brain/733bb6fb-f6f9-48c1-b559-9f8b135103a0/aegis-nis2-architecture.html) for the full Archify-rendered system topology.

---

## License

MIT License. Designed and engineered by Daniel Odhiambo.
