# NIS2 Article 21 Cybersecurity Risk-Management Measures Mapping

Directive (EU) 2022/2555 (NIS2) mandates that essential and important entities take appropriate technical, operational, and organizational measures.

## Article 21(2) Technical Measure Alignment

| NIS2 Clause | Requirement | Aegis Implementation Component |
|---|---|---|
| **Art. 21(2)(a)** | Policies on risk analysis and information system security | Continuous alert ingestion (`aegis.normalizer`) and automated MITRE classification. |
| **Art. 21(2)(b)** | **Incident handling** (prevention, detection, and response) | Autonomous triage engine (`aegis.triage`) and execution of automated containment playbooks (`aegis.playbooks`). |
| **Art. 21(2)(c)** | Business continuity, backup management, disaster recovery, crisis management | Automated shadow copy protection (`T1490`) and critical infrastructure asset safeguarding. |
| **Art. 21(2)(d)** | Supply chain security and network vulnerability assessments | Telemetry correlation from EDR/SIEM across edge devices and cloud endpoints. |
| **Art. 21(2)(g)** | Basic computer hygiene practices and cybersecurity training | Automated detection of brute force attacks (`T1110`) and credential harvesting (`T1003`). |
| **Art. 21(2)(j)** | Multi-factor authentication or continuous authentication | Immediate IP quarantine (`aegis.quarantine`) on credential stuffing detections. |
