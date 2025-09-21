# RTOps — Red Team Operations Platform

**RTOps** is a single-file, local-first Red Team operations platform that helps you plan, execute, and report on Red Team exercises. It includes RoE, Emulation Plans, Exercises, Findings, IoCs, Threat Intel notes, a Kill Chain builder, MITRE ATT&CK mapping (grouped by **tactics**), dashboards, and PDF reporting — all backed by a local SQLite database.

- **Local & Offline**: Everything runs on your machine; data stays in a local SQLite file.
- **Minimal footprint**: Single Python file (`rto_platform.py`) + 3 common dependencies.
- **ATT&CK aware**: Import STIX/Navigator layers and enrich names/descriptions from ATT&CK Excel.
- **Stakeholders**: Maintain **People** and **Assignments** (duties) per exercise.
- **Reporting**: Generate polished PDF reports per exercise.

---

## Quickstart

### 1) Requirements

- Python 3.9+ (tested on 3.11)
- Packages (pinned in `requirements.txt`):
  - `Flask`
  - `reportlab`
  - `openpyxl`

```bash
# Windows / macOS / Linux
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate

pip install -r requirements.txt
python rto_platform.py
```

### 2) Features

Rules of Engagement (RoE): scope, legal constraints, contacts, approvals.

Emulation Plans: choose ATT&CK TTPs by tactic, link to threat actors/campaigns.

Exercises: objectives, timeline, environment, linked RoE & Plan, stakeholders.

People & Assignments: register key people; assign duties per exercise (e.g., “Approver”, “Blue POC”, “Comms”).

Findings: severity, status, remediation, evidence, owner, asset.

IoCs: IP/Domain/URL/Hash/etc, linked to technique IDs (optional).

Threat Intel: notes with sources and tags.

MITRE Map: techniques grouped by tactics (Initial Access, Execution, …) with search.

Cyber Kill Chain: map selected TTPs to each stage and save versions.

Dashboards: KPIs, Findings by Severity (bar), Status over Time (line).

PDF Report: per exercise — includes objectives, linked RoE & Plan, TTPs, stakeholders, findings, and IoCs snapshot.

<img width="1906" height="836" alt="image" src="https://github.com/user-attachments/assets/5b450904-7b88-4c18-aa43-68b524fc1899" />
