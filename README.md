# Aegis NIS2 🛡️
### Autonomous Incident Triage, Automated Containment & EU NIS2 Regulatory Compliance Engine

[![CI](https://github.com/DanielX8/aegis-nis2/actions/workflows/ci.yml/badge.svg)](https://github.com/DanielX8/aegis-nis2/actions)
[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Directive: EU NIS2](https://img.shields.io/badge/Compliance-EU%20NIS2%20(2022%2F2555)-indigo.svg)](https://eur-lex.europa.eu/eli/dir/2022/2555/oj)
[![Framework: MITRE ATT&CK](https://img.shields.io/badge/Mapping-MITRE%20ATT%26CK%C2%AE-red.svg)](https://attack.mitre.org/)
[![Threat Intel: STIX 2.1](https://img.shields.io/badge/Threat%20Intel-OASIS%20STIX%202.1-emerald.svg)](https://oasis-open.github.io/cti-documentation/stix/intro)

---

## ⚡ Overview

**Aegis NIS2** is an enterprise-grade Security Orchestration, Automation, and Response (**SOAR**) framework engineered to solve two critical challenges facing modern Security Operations Centers (SOCs):

1. **Alert Fatigue**: Ingests, deduplicates, and normalizes high-volume telemetry from SIEMs (Wazuh, Syslog) and maps attacker behavior directly to the **MITRE ATT&CK®** matrix.
2. **Regulatory Non-Compliance**: Autonomously enforces the strict statutory incident response mandates of **EU Directive 2022/2555 (NIS2)**, calculating compliance clocks and generating regulator-ready notifications within the mandatory **24-hour Early Warning** window.

---

## 🏗️ System Architecture

[![Aegis NIS2 Interactive Architecture](docs/aegis-arch-dark.png)](https://danielx8.github.io/aegis-nis2/)

<p align="center">
  <a href="https://danielx8.github.io/aegis-nis2/">
    <img src="https://img.shields.io/badge/⚡%20Launch%20Live%20Interactive%20Diagram-GitHub%20Pages-6366f1?style=for-the-badge&logo=html5&logoColor=white" alt="Live Interactive Architecture">
  </a>
</p>

```mermaid
flowchart TD
    subgraph INGEST["1. Telemetry Ingestion"]
        W["Wazuh EDR JSON"]
        S["Syslog RFC-3164/5424"]
        N["Normalizer (normalizer.py)"]
        W --> N
        S --> N
    end

    subgraph TRIAGE["2. Triage & MITRE Classification"]
        A["Unified Alert"]
        T["Triage Engine (triage.py)"]
        M["MITRE ATT&CK Mapping (T1490, T1486, T1003, T1110)"]
        N --> A --> T --> M
    end

    subgraph STORE["3. Persistence & Audit Trail"]
        I["Incident Object"]
        DB[("SQLite Store (db.py)")]
        M --> I --> DB
    end

    subgraph RESPONSE["4. Automated Containment (Phase 2)"]
        PB["Playbook Runner (playbooks.py)"]
        Q["Quarantine Engine (quarantine.py)"]
        PB -->|Host Isolation| Q
        PB -->|IP Firewall Block| Q
        I -->|Critical / High Severity| PB
    end

    subgraph COMPLIANCE["5. NIS2 Article 23 & STIX 2.1 (Phase 3)"]
        REP["Reporter (reporter.py)"]
        STIX["Threat Intel (threat_intel.py)"]
        EW["24h Early Warning (Art. 23(4)(a))"]
        NOTIF["72h Incident Notification (Art. 23(4)(b))"]
        SB["STIX 2.1 JSON Bundle"]
        I --> REP --> EW
        REP --> NOTIF
        I --> STIX --> SB
    end

    subgraph RADAR["6. Operations Radar (Phase 4)"]
        CLI["Rich CLI (cli.py)"]
        DASH["Flask + HTMX Radar (dashboard.py)"]
        DB --> CLI
        DB --> DASH
    end

    style INGEST fill:#1e1b4b,stroke:#6366f1,stroke-width:2px,color:#fff
    style TRIAGE fill:#311042,stroke:#c084fc,stroke-width:2px,color:#fff
    style STORE fill:#0f172a,stroke:#38bdf8,stroke-width:2px,color:#fff
    style RESPONSE fill:#4c0519,stroke:#f43f5e,stroke-width:2px,color:#fff
    style COMPLIANCE fill:#064e3b,stroke:#10b981,stroke-width:2px,color:#fff
    style RADAR fill:#1e293b,stroke:#94a3b8,stroke-width:2px,color:#fff
```

## 🚀 Key Features
- 🎯 **Automated Telemetry Normalization**: Parses nested Wazuh JSON and RFC-3164/5424 Syslog streams into structured Pydantic v2 domain models.
- ⏱️ **NIS2 Article 23 Compliance Radar**: Autonomously tracks statutory deadlines:
  - **24-Hour Early Warning** (Art. 23(4)(a))
  - **72-Hour Incident Notification** (Art. 23(4)(b))
  - **1-Month Final Incident Report** (Art. 23(4)(c))
- 🛑 **Automated Containment & Quarantine**: Host network isolation and edge firewall blocking via declarative YAML playbooks, with built-in critical asset safety guards and 1-click rollbacks.
- 📡 **STIX 2.1 Threat Sharing**: Exports incident IoCs and attack patterns to OASIS STIX 2.1 JSON for automated sharing with national CSIRTs and MISP.
- 🖥️ **Live Operations Dashboard & Rich CLI**: Flask + Tailwind + HTMX web radar with real-time countdown clocks and interactive CLI terminal tooling.

---

## 📊 MITRE ATT&CK® Technique Mapping

| MITRE ID | Technique Name | Detection Pattern | Default Severity | NIS2 Reportable? |
|---|---|---|---|:---:|
| **T1490** | Inhibit System Recovery | Shadow copy deletion / `vssadmin` sabotage | **CRITICAL** | ✅ YES |
| **T1486** | Data Encrypted for Impact | Ransomware payloads / `.locked` extensions | **CRITICAL** | ✅ YES |
| **T1048** | Exfiltration Over Alt Protocol | High-volume external uploads / S3 sync | **CRITICAL** | ✅ YES |
| **T1003** | OS Credential Dumping | LSASS memory scraping / Mimikatz activity | **HIGH** | ✅ YES |
| **T1059.001** | PowerShell Scripting | DownloadString / Encoded execution | **HIGH** | ✅ YES |
| **T1110** | Brute Force | Repeated SSH / RDP authentication failures | **HIGH** | ✅ YES |
| **T1046** | Network Service Discovery | Port scanning / Nmap sweeps | **LOW** | ❌ NO |

---

## 🛠️ Quickstart Guide

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/DanielX8/aegis-nis2.git
cd aegis-nis2

# Install in editable mode
pip install -e .
```

### 2. Run Triage on Sample Telemetry

```bash
# Triage 10 real-world alert samples against MITRE & NIS2 criteria
aegis triage --file samples/wazuh-alerts.json
```

### 3. Execute an Automated Containment Playbook

```bash
# Isolate affected endpoint and block malicious IP
aegis respond INC-2026-09-A59522FF
```

### 4. Generate the Article 23(4)(a) 24h Early Warning Report

```bash
# Generates regulator-compliant Markdown notification
aegis report INC-2026-09-A59522FF --type 24h
```

### 5. Export STIX 2.1 Threat Intelligence

```bash
# Export standard STIX 2.1 JSON bundle for CSIRT sharing
aegis export-stix INC-2026-09-A59522FF
```

### 6. Launch the Real-Time Operations Radar

```bash
# Start the local Flask + HTMX web dashboard
python -c "from aegis.dashboard import app; app.run(port=5000, debug=True)"
```
*Visit `http://localhost:5000` to monitor live countdown timers and trigger 1-click containment.*

---

## 🧪 Testing & Verification

Aegis NIS2 includes a comprehensive test suite covering normalizers, triage heuristics, SQLite persistence, containment rollbacks, and threat intelligence exports:

```bash
pytest -v
```

```
============================= test session starts =============================
collected 28 items

tests/test_db.py ......................... PASSED [ 17%]
tests/test_normalizer.py ................. PASSED [ 42%]
tests/test_playbooks.py .................. PASSED [ 46%]
tests/test_quarantine.py ................. PASSED [ 57%]
tests/test_reporter.py ................... PASSED [ 64%]
tests/test_threat_intel.py ............... PASSED [ 67%]
tests/test_triage.py ..................... PASSED [100%]

============================= 28 passed in 1.15s ==============================
```

---

## 📖 In-Depth Project Documentation

For a comprehensive architectural breakdown and engineering walkthrough, see:
- [Aegis-nis2BOOK.md](Aegis-nis2BOOK.md) — *The complete 9-chapter architecture and technical handbook.*
- [docs/nis2-article21-mapping.md](docs/nis2-article21-mapping.md) — *Clause-by-clause Article 21 technical mapping.*
- [docs/nis2-article23-reporting.md](docs/nis2-article23-reporting.md) — *Article 23 statutory notification workflows.*

---

---

## 👤 About the Author & Project Background

**Aegis NIS2** was conceived and engineered by **Daniel Odhiambo**, an IT Systems Administrator and Cybersecurity graduate based in Nairobi, Kenya.

- **Academic Background**: BSc in Cybersecurity & Computer Networks from Strathmore University.
- **Hands-On Specialization**: Enterprise systems administration, Bare-Metal OS recovery, SIEM telemetry correlation (Wazuh, Zeek, Suricata), and Active Defense scripting.
- **Why this project exists**: With the European Union's **Directive (EU) 2022/2555 (NIS2)** enforcing strict 24-hour incident disclosure windows on essential entities, manual alert triage creates immense regulatory exposure. Aegis NIS2 bridges low-level telemetry engineering with statutory compliance requirements to eliminate alert fatigue and ensure auditable incident reporting.

Connect & Collaborate:
- 💼 **LinkedIn**: [Daniel Odhiambo](https://www.linkedin.com/in/daniel-odhiambo-7b794121b/)
- 🐙 **GitHub**: [@DanielX8](https://github.com/DanielX8)
- 📧 **Contact**: [daniel.o.odhiambo1@gmail.com](mailto:daniel.o.odhiambo1@gmail.com)

## 📄 License
This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

**Author**: Daniel Odhiambo  
*BSc Cybersecurity & Computer Networks | IT Systems Administrator & Security Engineer*
