# Aegis NIS2: The Definitive Architecture & Engineering Handbook

> **An End-to-End Guide to Autonomous Incident Triage, Automated Containment, and EU NIS2 Regulatory Compliance**  
> *Author: Daniel Odhiambo*  
> *Version: 1.0.0 — Production Reference*

---

# Table of Contents
1. [Executive Summary & The Problem](#1-executive-summary--the-problem)
2. [The Legal Framework: Directive (EU) 2022/2555 (NIS2)](#2-the-legal-framework-directive-eu-20222555-nis2)
   - 2.1 [Article 21: Cybersecurity Risk-Management Measures](#21-article-21-cybersecurity-risk-management-measures)
   - 2.2 [Article 23: The Mandatory 3-Stage Reporting Clock](#22-article-23-the-mandatory-3-stage-reporting-clock)
   - 2.3 [What Constitutes a "Significant Incident"?](#23-what-constitutes-a-significant-incident)
3. [System Architecture & Data Flow](#3-system-architecture--data-flow)
4. [Phase 1: Ingestion, Normalization & Triage Engine](#4-phase-1-ingestion-normalization--triage-engine)
   - 4.1 [Core Data Models (`src/aegis/models.py`)](#41-core-data-models-srcaegismodelspy)
   - 4.2 [Alert Normalization (`src/aegis/normalizer.py`)](#42-alert-normalization-srcaegisnormalizerpy)
   - 4.3 [Triage & MITRE ATT&CK Mapping (`src/aegis/triage.py`)](#43-triage--mitre-attck-mapping-srcaegistriagepy)
   - 4.4 [Incident Persistence Store (`src/aegis/db.py`)](#44-incident-persistence-store-srcaegisdbpy)
   - 4.5 [Sample Telemetry & Verification (`samples/wazuh-alerts.json`)](#45-sample-telemetry--verification)
5. [Phase 2: Quarantine & Automated Playbook Engine](#5-phase-2-quarantine--automated-playbook-engine)
   - 5.1 [Quarantine & Network Isolation (`src/aegis/quarantine.py`)](#51-quarantine--network-isolation-srcaegisquarantinepy)
   - 5.2 [YAML Playbook Engine (`src/aegis/playbooks.py`)](#52-yaml-playbook-engine-srcaegisplaybookspy)
   - 5.3 [Built-in Playbook Definitions (`playbooks/`)](#53-built-in-playbook-definitions-playbooks)
6. [Phase 3: Regulatory Reporting & Threat Intelligence](#6-phase-3-regulatory-reporting--threat-intelligence)
   - 6.1 [Article 23 Notification Generator (`src/aegis/reporter.py`)](#61-article-23-notification-generator-srcaegisreporterpy)
   - 6.2 [STIX 2.1 Threat Intelligence Exporter (`src/aegis/threat_intel.py`)](#62-stix-21-threat-intelligence-exporter-srcaegisthreat_intelpy)
   - 6.3 [Interactive Command Line Interface (`src/aegis/cli.py`)](#63-interactive-command-line-interface-srcaegisclipy)
7. [Phase 4: Operations Radar Dashboard & CI/CD](#7-phase-4-operations-radar-dashboard--cicd)
   - 7.1 [Live Web Dashboard (`src/aegis/dashboard.py`)](#71-live-web-dashboard-srcaegisdashboardpy)
   - 7.2 [Archify System Topology (`docs/architecture.html`)](#72-archify-system-topology-docsarchitecturehtml)
   - 7.3 [Continuous Integration Pipeline (`.github/workflows/ci.yml`)](#73-continuous-integration-pipeline-githubworkflowsciyml)
8. [Step-by-Step Hands-On Tutorial](#8-step-by-step-hands-on-tutorial)
9. [Cybersecurity & Regulatory Glossary](#9-cybersecurity--regulatory-glossary)

---

# 1. Executive Summary & The Problem

Modern Security Operations Centers (SOCs) face two immense challenges:
1. **Extreme Alert Fatigue**: An enterprise network generates hundreds of thousands of raw alerts daily from firewalls, endpoints, and EDR agents. Most are low-level noise.
2. **Aggressive Regulatory Penalties**: Under the European Union’s **NIS2 Directive**, organizations in critical and essential sectors face fines of up to **€10 million or 2% of global annual turnover** if they fail to notify national authorities of significant cyber incidents within **24 hours**.

### What Aegis NIS2 Does
**Aegis NIS2** is a lightweight, Python-based Security Orchestration, Automation, and Response (SOAR) framework. It:
- Ingests raw telemetry from SIEM tools (e.g., Wazuh, Syslog).
- Correlates isolated alerts into unified **Incidents**.
- Automatically maps adversary behavior to the **MITRE ATT&CK®** framework.
- Calculates statutory **24-hour, 72-hour, and 30-day compliance clocks**.
- Executes **automated containment playbooks** (host isolation, IP blocking).
- Generates **regulator-ready Markdown notifications** and **STIX 2.1 threat intelligence bundles**.
- Displays everything on an **interactive dark-mode operations dashboard**.

---

# 2. The Legal Framework: Directive (EU) 2022/2555 (NIS2)

The NIS2 Directive was established by the European Union to strengthen cybersecurity across critical infrastructure. It applies to **Essential Entities** (Energy, Healthcare, Banking, Transport, Digital Infrastructure) and **Important Entities** (Postal, Manufacturing, Food, E-Commerce).

### 2.1 Article 21: Cybersecurity Risk-Management Measures
Article 21 mandates that covered entities implement technical and operational measures to manage risk.
- **Article 21(2)(b) — Incident Handling**: Mandates systematic processes for the prevention, detection, and response to cyber incidents.
- *How Aegis satisfies this*: aegis provides continuous log ingestion, automated triage, immutable SQLite audit trails, and YAML-driven containment playbooks.

### 2.2 Article 23: The Mandatory 3-Stage Reporting Clock
When an incident is classified as "Significant", Article 23 enforces a strict statutory countdown:

```
[Awareness of Incident (T=0)]
       │
       ▼ (Within 24 Hours)
[Stage 1: Early Warning Notification — Art. 23(4)(a)]
  - Discloses suspected cause (malicious / cross-border potential).
  - Generated via `aegis report <ID> --type 24h`.
       │
       ▼ (Within 72 Hours)
[Stage 2: Incident Notification — Art. 23(4)(b)]
  - Initial assessment of severity, technical impact, and Indicators of Compromise (IoCs).
  - Generated via `aegis report <ID> --type 72h`.
       │
       ▼ (Within 1 Month)
[Stage 3: Final Incident Report — Art. 23(4)(c)]
  - Comprehensive root-cause analysis, mitigation actions, and lessons learned.
```

### 2.3 What Constitutes a "Significant Incident"?
Under NIS2 Article 23(3), an incident is legally significant if:
1. It causes or can cause **severe operational disruption** or substantial financial loss.
2. It causes or can cause **considerable material or non-material damage** to other persons or organizations (supply chain contagion).

In Aegis, any incident triaged as **`CRITICAL`** or **`HIGH`** automatically sets `is_nis2_reportable = True` and starts the 24-hour early warning clock.

---

# 3. System Architecture & Data Flow

```
┌───────────────────────────┐      ┌───────────────────────────┐
│   Raw Telemetry Sources   │      │    SIEM / EDR Ingest      │
│  (Wazuh JSON, Syslog, CEF)│ ───▶ │  src/aegis/normalizer.py  │
└───────────────────────────┘      └─────────────┬─────────────┘
                                                 │
                                       Produces `Alert`
                                                 │
                                                 ▼
                                   ┌───────────────────────────┐
                                   │     Triage Engine         │
                                   │   src/aegis/triage.py     │
                                   │  - MITRE ATT&CK Mapping   │
                                   │  - NIS2 24h Clock Init    │
                                   └─────────────┬─────────────┘
                                                 │
                                     Produces `Incident`
                                                 │
                                                 ▼
                                   ┌───────────────────────────┐
                                   │   SQLite Incident Store   │
                                   │     src/aegis/db.py       │
                                   └──────┬─────────────┬──────┘
                                          │             │
                    ┌─────────────────────┘             └─────────────────────┐
                    ▼                                                         ▼
     ┌─────────────────────────────┐                           ┌─────────────────────────────┐
     │  Containment Playbooks      │                           │  Article 23 & STIX Exporter │
     │  src/aegis/quarantine.py    │                           │  src/aegis/reporter.py      │
     │  src/aegis/playbooks.py     │                           │  src/aegis/threat_intel.py  │
     │  - Host Isolation           │                           │  - 24h Early Warning (Jinja)│
     │  - IP Perimeter Firewall    │                           │  - STIX 2.1 Threat Bundles  │
     └──────────────┬──────────────┘                           └──────────────┬──────────────┘
                    │                                                         │
                    └─────────────────────┬───────────────────────────────────┘
                                          ▼
                           ┌─────────────────────────────┐
                           │    Operations Radar & CLI   │
                           │     src/aegis/cli.py        │
                           │     src/aegis/dashboard.py  │
                           └─────────────────────────────┘
```

---

# 4. Phase 1: Ingestion, Normalization & Triage Engine

### 4.1 Core Data Models (`src/aegis/models.py`)
Built with **Pydantic v2**, the domain models enforce strict typing and UTC timestamps:

1. **`Alert`**: The raw log entity containing verbatim payloads and normalized fields (`source_ip`, `dest_ip`, `hostname`, `rule_level`, `timestamp`).
2. **`Incident`**: The enriched security case. Key properties:
   - `early_warning_deadline`: Computed as `detected_at + timedelta(hours=24)`.
   - `notification_deadline`: Computed as `detected_at + timedelta(hours=72)`.
   - `final_report_deadline`: Computed as `detected_at + timedelta(days=30)`.
   - `is_nis2_reportable`: Evaluates `True` when severity is `CRITICAL` or `HIGH`.
3. **`NIS2Report`**: Tracks draft, submission, and overdue states for regulatory filings.

### 4.2 Alert Normalization (`src/aegis/normalizer.py`)
Parses heterogeneous formats into a standardized `Alert`:
- `normalize_wazuh(dict)`: Unpacks nested Wazuh alerts (`rule.id`, `rule.level`, `rule.description`, `agent.name`, `data.srcip`).
- `normalize_syslog(str)`: Uses regular expressions to extract IP addresses, hostnames, and message bodies from RFC-3164/5424 syslog streams.
- `normalize_batch(list)`: Ingests batches safely without crashing on partial format errors.

### 4.3 Triage & MITRE ATT&CK Mapping (`src/aegis/triage.py`)
Implements a two-tier decision hierarchy:
1. **Tier 1 — MITRE Regex Heuristics**:
   - `T1490 (Inhibit System Recovery)`: Shadow copy deletion (`vssadmin delete shadows`) $\rightarrow$ **`CRITICAL`**
   - `T1486 (Data Encrypted for Impact)`: Ransomware file extensions (`.locked`, `.crypted`) $\rightarrow$ **`CRITICAL`**
   - `T1048 (Exfiltration Over Alternative Protocol)`: Mega.nz uploads / S3 sync $\rightarrow$ **`CRITICAL`**
   - `T1003 (OS Credential Dumping)`: Mimikatz, LSASS memory scraping $\rightarrow$ **`HIGH`**
   - `T1059.001 (PowerShell)`: DownloadString, encoded commands $\rightarrow$ **`HIGH`**
   - `T1110 (Brute Force)`: Repeated authentication failures $\rightarrow$ **`HIGH`**
   - `T1046 (Network Service Discovery)`: Nmap, port scans $\rightarrow$ **`LOW`**
2. **Tier 2 — Rule-Level Fallback**:
   - Evaluates numeric SIEM rule levels (Level $\ge 12 \rightarrow$ `CRITICAL`, Level $\ge 8 \rightarrow$ `HIGH`, Level $\ge 4 \rightarrow$ `MEDIUM`, else `LOW`).

### 4.4 Incident Persistence Store (`src/aegis/db.py`)
A lightweight SQLite database (`aegis.db`) that records every incident, containment action, and regulatory status. Includes query filters (`list_nis2_reportable()`, `update_status()`).

---

# 5. Phase 2: Quarantine & Automated Playbook Engine

### 5.1 Quarantine & Network Isolation (`src/aegis/quarantine.py`)
Handles immediate containment of compromised assets:
- **Host Isolation**: Disconnects infected endpoints from the corporate LAN.
- **IP Perimeter Block**: Drops ingress/egress connections at the firewall.
- **Critical Asset Protection**: Built-in safety guard prevents isolating domain controllers, default gateways, or internal triage engines (`127.0.0.1`, `10.0.0.1`, `dc-01.corp`).
- **1-Click Rollback**: Any quarantine action can be instantly reverted via `rollback(action_id)`.

### 5.2 YAML Playbook Engine (`src/aegis/playbooks.py`)
Dynamically parses declarative YAML files to execute automated responses mapped to MITRE techniques:
- [playbooks/ransomware.yml](file:///C:/Users/DLEIN/Documents/PERS%20PROJECTS/aegis-nis2/playbooks/ransomware.yml): Isolates affected hosts, blocks external C2 IPs, and starts the NIS2 24h clock.
- [playbooks/data-exfiltration.yml](file:///C:/Users/DLEIN/Documents/PERS%20PROJECTS/aegis-nis2/playbooks/data-exfiltration.yml): Terminates exfiltration sockets and quarantines data-dumping endpoints.
- [playbooks/brute-force-response.yml](file:///C:/Users/DLEIN/Documents/PERS%20PROJECTS/aegis-nis2/playbooks/brute-force-response.yml): Blocks attacking IPs on ingress tables.

---

# 6. Phase 3: Regulatory Reporting & Threat Intelligence

### 6.1 Article 23 Notification Generator (`src/aegis/reporter.py`)
Uses Jinja2 templates to compile formal Markdown reports ready for submission to national CSIRTs:
- `generate_early_warning(incident)`: Produces the **24-hour Early Warning Notification** (Art. 23(4)(a)).
- `generate_incident_notification(incident)`: Produces the **72-hour Incident Notification** (Art. 23(4)(b)).

### 6.2 STIX 2.1 Threat Intelligence Exporter (`src/aegis/threat_intel.py`)
Converts triaged incidents into OASIS STIX 2.1 JSON bundles:
- Generates `identity`, `incident`, `indicator` (for malicious IPs), and `attack-pattern` (for MITRE techniques) objects.
- Enables direct sharing with MISP, OpenCTI, and national CSIRT threat intelligence platforms.

### 6.3 Interactive CLI (`src/aegis/cli.py`)
Terminal interface powered by `Click` and `Rich`:
- `aegis triage --file <alerts.json>`: Batch normalize and triage alerts.
- `aegis respond <INCIDENT_ID>`: Trigger automated containment playbooks.
- `aegis report <INCIDENT_ID> --type 24h`: Generate Article 23 early warning notification.
- `aegis export-stix <INCIDENT_ID>`: Export STIX 2.1 JSON bundle.

---

# 7. Phase 4: Operations Radar Dashboard & CI/CD

### 7.1 Live Web Dashboard (`src/aegis/dashboard.py`)
A real-time Flask web application styled with Tailwind CSS and HTMX:
- Displays live KPI cards: **Total Ingested**, **NIS2 Reportable**, **Contained**, and **Open Triage**.
- Features an **Incident Radar Table** with live countdown timers for 24h early warning deadlines.
- Interactive **"Contain Now"** button that executes containment playbooks and updates status badges in real time without full page reloads.

### 7.2 Archify System Topology (`docs/architecture.html`)
Standalone, interactive SVG system architecture generated via the Archify skill, detailing the entire pipeline from telemetry ingestion to regulatory notification.

### 7.3 Continuous Integration Pipeline (`.github/workflows/ci.yml`)
Automated GitHub Actions workflow testing the codebase on Python 3.10, 3.11, and 3.12 with `pytest` and coverage reporting.

---

# 8. Step-by-Step Hands-On Tutorial

Follow these steps in your terminal to test the full Aegis pipeline:

### Step 1: Ingest and Triage Alerts
```powershell
cd "C:\Users\DLEIN\Documents\PERS PROJECTS\aegis-nis2"
$env:PYTHONPATH = "src"
python -m aegis.cli triage --file "samples/wazuh-alerts.json"
```
*Output*: Displays the color-coded NIS2 Triage Table and saves 10 incidents to SQLite.

### Step 2: Execute an Automated Response Playbook
```powershell
# Pick any incident ID from the triage table
python -m aegis.cli respond INC-2026-09-A59522FF
```
*Output*: Executes the containment playbook, quarantines the host, blocks the offending IP, and marks the incident as `contained`.

### Step 3: Generate the 24-Hour NIS2 Early Warning Report
```powershell
python -m aegis.cli report INC-2026-09-A59522FF --type 24h
```
*Output*: Generates the complete, regulator-compliant Article 23(4)(a) Markdown notification.

### Step 4: Export to STIX 2.1 Threat Intel
```powershell
python -m aegis.cli export-stix INC-2026-09-A59522FF
```
*Output*: Prints standard STIX 2.1 JSON with embedded indicators and MITRE attack patterns.

### Step 5: Launch the Operations Dashboard
```powershell
python -c "from aegis.dashboard import app; app.run(port=5000, debug=True)"
```
*Open in Browser*: Navigate to `http://127.0.0.1:5000` to interact with the real-time compliance radar.

---

# 9. Cybersecurity & Regulatory Glossary

- **NIS2 (Directive 2022/2555)**: European Union cybersecurity directive mandating strict incident handling and statutory reporting deadlines for critical infrastructure.
- **CSIRT**: Computer Security Incident Response Team (the national body that receives NIS2 incident reports).
- **NCA**: National Competent Authority responsible for NIS2 enforcement.
- **SOAR**: Security Orchestration, Automation, and Response (systems that automate repetitive incident response tasks).
- **MITRE ATT&CK®**: Globally accessible knowledge base of adversary tactics and techniques based on real-world observations.
- **STIX 2.1**: Structured Threat Information Expression — an open XML/JSON standard for sharing cyber threat intelligence.
- **IoC**: Indicator of Compromise (e.g., malicious IP, domain, file hash).
- **Wazuh**: Open-source unified XDR and SIEM platform.
- **Early Warning**: Mandatory initial notification sent to authorities within 24 hours of incident awareness under NIS2 Article 23(4)(a).
