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
