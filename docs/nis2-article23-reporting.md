# NIS2 Article 23 Reporting Obligations & Timelines

Under Article 23 of Directive (EU) 2022/2555, entities must notify their CSIRT or competent national authority (NCA) of any significant incident according to strict statutory deadlines.

## Statutory Notification Workflow

```
[Incident Awareness (T=0)]
       │
       ▼  (Within 24 Hours)
[1. Early Warning Notification — Art. 23(4)(a)]
  - Indicates suspected cause (malicious / cross-border)
  - Generated via `aegis report <ID> --type 24h`
       │
       ▼  (Within 72 Hours)
[2. Incident Notification — Art. 23(4)(b)]
  - Updated severity assessment, initial IoCs, impact indicators
  - Generated via `aegis report <ID> --type 72h`
       │
       ▼  (Within 1 Month)
[3. Final Incident Report — Art. 23(4)(c)]
  - Root cause analysis, remediation actions, control gap evaluations
```

## STIX 2.1 Threat Sharing
Aegis automatically exports incident IoCs to structured STIX 2.1 JSON bundles via `aegis export-stix <ID>` for direct ingestion into MISP and national CSIRT intelligence platforms.
