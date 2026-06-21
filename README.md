# Cloud Misconfiguration Detector

A defensive, offline-first security tool that scans Infrastructure-as-Code (Terraform) for common cloud misconfigurations, scores findings by risk, and produces both machine-readable and human-readable reports.

**Author:** Israel Mbiyavanga David

---

## Table of Contents

- [Overview](#overview)
- [Architecture & Features](#architecture--features)
- [Supported Inputs & Engine Rules](#supported-inputs--engine-rules)
- [Risk Scoring & Prioritization Logic](#risk-scoring--prioritization-logic)
- [Getting Started & Installation](#getting-started--installation)
- [Usage](#usage)
- [Streamlit Dashboard](#streamlit-dashboard)
- [Automated Testing](#automated-testing)
- [Sample Report Output](#sample-report-output)
- [Extensibility & Roadmap](#extensibility--roadmap)
- [Limitations](#limitations)

---

## Overview

Infrastructure-as-Code (IaC) tools like Terraform let teams provision entire cloud environments in minutes — but a single misconfigured line can expose sensitive assets to the public internet.

The **Cloud Misconfiguration Detector** is a defensive security tool designed to "shift left." It parses Terraform configuration files (`.tf`), runs them through a static analysis rule engine, calculates a contextual risk priority score, and flags vulnerabilities before they're ever deployed to production — with no network calls or cloud credentials required.

---

## Architecture & Features

```
[IaC Source (*.tf)] ──> [HCL2 Parser + Sanitizer] ──> [Rule Engine] ──> [Risk Scoring] ──> [JSON / Markdown Reports]
                                                                                                  │
                                                                                                  ├──> [FastAPI Server]
                                                                                                  └──> [Streamlit Dashboard]
```

- **Parsing & sanitization** — Uses `python-hcl2` to convert HCL into Python dictionaries, then recursively unwraps single-element list wrappers and strips stray literal quote characters so rule logic always receives clean, predictable types (`bool`, `str`, `list`).
- **Rule engine** — Pure-Python static analysis checks targeting high-impact misconfigurations.
- **Risk prioritization** — A tiered base score adjusted by contextual category boosts, so the highest-impact findings always surface first.
- **Dual reporting** — JSON for CI/CD and SOAR ingestion, Markdown for human review.
- **REST API** — A lightweight FastAPI service for serving the latest scan results.
- **Interactive dashboard** — A Streamlit app for visual triage with severity badges, risk meters, and a computed security posture grade.
- **Unit tested** — A `pytest` suite validates that each rule correctly flags true positives and ignores secure configurations.

---

## Supported Inputs & Engine Rules

The parser scans any directory of `.tf` files (default: `data/raw/terraform/`). Current rules:

| Rule ID | Title | Target Resource | Default Severity |
|---|---|---|---|
| `AWS-SG-OPEN-*` | Admin port exposed to the internet | `aws_security_group_rule` | High |
| `AWS-S3-PUBLIC-*` | S3 public access block disabled or partially disabled | `aws_s3_bucket_public_access_block` | Critical |
| `AWS-RDS-ENC-*` | RDS storage encryption disabled | `aws_db_instance` | High |

Each finding includes the resource location (file, type, name), structured evidence, and a concrete remediation action.

---

## Risk Scoring & Prioritization Logic

Severity maps to a numeric base score:

| Severity | Base Score |
|---|---|
| Critical | 100 |
| High | 80 |
| Medium | 50 |
| Low | 20 |
| Info | 5 |

**Contextual boosts** (applied on top of the base score, capped at 100):

- `+10` if the finding category contains "public" (e.g., Public Data Exposure)
- `+5` if the finding category contains "data" (e.g., Data Protection)

```
risk_score = min(100, base_severity_score + context_boosts)
```

Findings are sorted descending by `risk_score`, so the report always leads with the most urgent issue.

---

## Getting Started & Installation

### Prerequisites

- Python 3.10+
- Git

### Installation

```bash
# Clone and enter the repository
git clone https://github.com/<your-username>/cloud-misconfig-detector.git
cd cloud-misconfig-detector

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -U pip
pip install -r requirements.txt
```

`requirements.txt` should include: `pydantic`, `python-dotenv`, `pandas`, `numpy`, `Jinja2`, `fastapi`, `uvicorn`, `python-hcl2`, `streamlit`, `pytest`.

---

## Usage

### 1. Run the scan pipeline

```bash
python -m src.utils.run
```

> Run with `python -m src.utils.run` (module mode), not `python src/utils/run.py`. Module mode ensures the `src` package resolves correctly. The runner logs each pipeline stage (resources parsed, findings detected, files written) so failures are visible immediately instead of silently producing a stale report.

This writes:

- `data/processed/report.json` — full structured report
- `docs/examples/report.md` — human-readable Markdown report

### 2. Serve results via API

```bash
uvicorn src.api.app:app --reload --port 8000
```

```bash
curl http://127.0.0.1:8000/report
```

If no report has been generated yet, the endpoint returns a `404` with a message pointing you back to the pipeline command, rather than a misleading `200 OK`.

---

## Streamlit Dashboard

For visual triage, launch the interactive dashboard:

```bash
streamlit run src/frontend/dashboard.py
```

This opens `http://localhost:8501` and displays:

- **Summary metrics** — total resources scanned, number of findings, and an overall security posture grade (A+ through F, derived from severity and finding count)
- **Expandable finding cards** — color-coded severity badges (🔴 critical, 🟠 high, 🟡 medium, 🔵 low, ⚪ info), remediation guidance, source file, a risk-score progress bar, and the raw evidence payload as JSON

The dashboard reads directly from `data/processed/report.json`, so re-run the pipeline and refresh the page to see updated results.

---

## Automated Testing

The rule engine is covered by a `pytest` suite in `tests/test_aws_rules.py`, using mock resource dictionaries (no `.tf` files or disk I/O required) to verify:

- Open admin ports (`22`/`3389`) on `0.0.0.0/0` are flagged; restricted CIDRs and non-admin ports are not
- A disabled S3 public access block setting is flagged as critical
- `storage_encrypted = false` on an RDS instance is flagged; `true` is not

Run the suite:

```bash
python -m pytest
```

> If you'd rather run bare `pytest`, add a `pytest.ini` at the project root with:
> ```ini
> [pytest]
> pythonpath = .
> ```

Expected output:

```
============================= test session starts ==============================
collected 5 items

tests/test_aws_rules.py .....                                            [100%]

============================== 5 passed in 0.08s ===============================
```

---

## Sample Report Output

Excerpt from `docs/examples/report.md`:

```markdown
# Cloud Misconfiguration Report (IaC)

Total findings: 3

## Top Findings

### 1. S3 public access block disabled or partially disabled (CRITICAL) | Risk 100
Category: Public Data Exposure
Resource: aws_s3_bucket_public_access_block.public_block
File: data/raw/terraform/s3_public.tf

Remediation:
Enable all S3 public access block settings and verify bucket policies and ACLs.

### 2. Admin port exposed to the internet (HIGH) | Risk 90
Category: Network Exposure
Resource: aws_security_group_rule.ssh_open
File: data/raw/terraform/sg_open.tf

Remediation:
Restrict ingress to trusted IP ranges, use VPN/bastion, and enforce MFA for admin access.
```

---

## Extensibility & Roadmap

- **Multi-cloud rules** — Add `azure_rules.py` / `gcp_rules.py` under `src/rules/` following the same `(resources) -> List[Finding]` pattern.
- **Cloud export ingestion** — Add a parser under `src/ingest/` capable of consuming exports such as `aws ec2 describe-security-groups` or `az network nsg list` JSON, alongside static `.tf` analysis.
- **Additional rules** — Unencrypted EBS volumes, public-facing load balancers, IAM wildcard policies, disabled CloudTrail/VPC Flow Logs.
- **ML-assisted triage** — A classifier trained on analyst true-positive/false-positive labels to re-rank findings over time, layered on top of (not replacing) the deterministic rule engine.

---

## Limitations

- **Static analysis only** — The tool evaluates HCL as written; it cannot resolve values only known at `terraform apply` time (data sources, computed attributes, remote state).
- **Context-independent scoring** — Each resource is scored in isolation. Real-world blast radius (e.g., how a security group attaches to specific instances, or how IAM roles chain together) requires a graph-based relational model the current engine does not build.
- **Human review required** — Findings and remediation text are guidance, not an authoritative compliance verdict. Always validate against your environment before acting.
