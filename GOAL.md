# Goal: Build A Practice-Ready Policy-To-Evidence Graph

Status: Proposed
Date created: 2026-05-12
Target repo: `itsnmills/policy-to-evidence-graph`
Suggested visibility: Public
Strategic priority: Very high
Primary resume signal: GRC automation, control mapping, evidence management, healthcare compliance readiness, security reporting
Slash-goal source file: `../Goal - Security Operations Triage Ticketing Pipeline.md`

## Executive Summary

Build a local-first Policy-to-Evidence Graph that maps healthcare security controls, policies, procedures, practice systems, risks, and evidence references into a clear readiness graph. The tool should ingest existing artifacts from the Small-Practice Security Kit, ePHI Data Flow Mapper, HIPAA Evidence Binder, Vendor Risk Manager, and Security Operations Triage Pipeline, then generate a control-to-evidence matrix, missing-evidence gaps, and readiness trends over time.

The strongest wedge is:

> Help small healthcare practices and the people supporting them understand which policies and controls have current evidence, which are missing proof, which owners need to act, and how readiness changes across review cycles.

This should feel like a lightweight local GRC evidence engine for small practices, not an enterprise GRC clone.

## Product Positioning

Working name:

Small Practice Policy-to-Evidence Graph

One-line description:

A local-first evidence graph that maps healthcare security policies and controls to proof, owners, review cadence, gaps, and readiness trends.

What it is:

- A control-to-evidence graph builder.
- A policy/evidence crosswalk generator.
- A missing-evidence gap analyzer.
- A review cadence and staleness tracker.
- A readiness trend reporter.
- A local dashboard for practice owners, MSPs, and consultants.
- A bridge between security operations work and compliance/GRC evidence.

What it is not:

- Not a legal opinion.
- Not HIPAA certification.
- Not a substitute for a complete Security Risk Analysis.
- Not an enterprise GRC platform.
- Not a storage system for PHI, patient records, credentials, or raw sensitive screenshots.

## Intended Users

Primary users:

- Small healthcare practice administrators.
- MSPs supporting healthcare clients.
- Healthcare security consultants.
- Entry-level GRC analysts.
- Security analysts who need to connect remediation to evidence.

Secondary users:

- Practice owners preparing for insurance, auditor, or vendor questionnaire requests.
- Students building a credible healthcare cybersecurity portfolio.
- Small healthcare vendors organizing security evidence.

## Core User Story

As a small practice or consultant, I can load a control library, policy register, system inventory, risk register, vendor register, incident/backup records, and evidence reference log. The tool builds a graph that shows which controls are supported by current evidence, which controls are stale or missing proof, who owns the next action, and how readiness has changed since the previous review.

## Design Principles

- Local-first by default.
- Evidence references over raw sensitive evidence.
- No PHI or credentials required.
- Source-grounded and transparent.
- Simple enough for a practice manager.
- Structured enough for an MSP, vCISO, or GRC analyst.
- Trends over time, not one-time checklist theater.
- Honest language: "readiness support" and "evidence mapping," not "guaranteed compliance."
- Integrates naturally with the existing open-source healthcare security portfolio.

## Repository Structure

Expected final structure:

```text
policy-to-evidence-graph/
├── README.md
├── LICENSE
├── DISCLAIMER.md
├── SECURITY.md
├── pyproject.toml
├── requirements-dev.txt
├── .github/
│   └── workflows/
│       └── ci.yml
├── docs/
│   ├── architecture.md
│   ├── data-model.md
│   ├── graph-model.md
│   ├── control-library.md
│   ├── evidence-rules.md
│   ├── readiness-trends.md
│   ├── privacy-and-storage-boundary.md
│   ├── sample-practice-walkthrough.md
│   └── import-plans-existing-repos.md
├── schemas/
│   ├── control.schema.json
│   ├── policy.schema.json
│   ├── evidence.schema.json
│   ├── system.schema.json
│   ├── vendor.schema.json
│   ├── risk.schema.json
│   ├── review_snapshot.schema.json
│   └── project.schema.json
├── src/
│   └── evidence_graph/
│       ├── __init__.py
│       ├── cli.py
│       ├── ingest.py
│       ├── normalize.py
│       ├── graph.py
│       ├── controls.py
│       ├── evidence.py
│       ├── gaps.py
│       ├── trends.py
│       ├── reports.py
│       ├── validators.py
│       └── dashboard.py
├── web/
│   ├── index.html
│   ├── app.js
│   └── styles.css
├── control_libraries/
│   ├── small_practice_security_baseline.yaml
│   ├── hipaa_security_rule_practical.yaml
│   ├── hph_cpg_essential.yaml
│   ├── nist_csf_practical.yaml
│   └── cisa_cpg_practical.yaml
├── templates/
│   ├── policy_register.csv
│   ├── evidence_reference_log.csv
│   ├── system_inventory.csv
│   ├── vendor_register.csv
│   ├── risk_register.csv
│   ├── incident_readiness_register.csv
│   ├── backup_restore_register.csv
│   └── review_snapshot.yaml
├── examples/
│   ├── family-medicine/
│   ├── dental/
│   ├── behavioral-health/
│   └── consultant-client-review/
├── tests/
│   ├── test_ingest.py
│   ├── test_graph.py
│   ├── test_controls.py
│   ├── test_evidence.py
│   ├── test_gaps.py
│   ├── test_trends.py
│   ├── test_reports.py
│   ├── test_cli.py
│   └── snapshots/
└── dist/
    └── .gitkeep
```

## Core Concepts

### Graph Nodes

Required node types:

```text
control
policy
procedure
system
vendor
risk
evidence
ticket
incident_readiness_item
backup_restore_item
owner
review
```

### Graph Edges

Required edge types:

```text
supports
implements
requires_evidence
has_evidence
owned_by
depends_on
affects
mitigates
needs_review
is_stale
generated_from
```

### Readiness States

Use these states:

```text
ready
partial
missing
stale
not_applicable
needs_review
unknown
```

### Evidence Types

Supported evidence types:

```text
policy_document
procedure_document
system_inventory
vendor_baa
access_review
backup_restore_test
downtime_drill
incident_log
risk_analysis_note
security_training_record
log_review
configuration_export
patch_ticket
vulnerability_report
ai_workflow_review
email_security_review
encryption_review
signoff
```

## Required Inputs

### Control Library

YAML format.

Minimum fields:

```yaml
control_id: SPB-001
title: Maintain system inventory
domain: Asset Management
description: Maintain a current inventory of systems and services that may store, process, transmit, or support ePHI workflows.
source_mappings:
  hipaa:
    - Security Rule risk analysis scope concept
  hph_cpg:
    - Asset inventory
  nist_csf:
    - ID.AM
expected_evidence:
  - system_inventory
  - review_signoff
owner_role: IT Owner
cadence_days: 90
criticality: high
practice_notes: Keep patient names and record-level PHI out of inventory.
```

Required baseline controls:

- System inventory.
- ePHI data flow documentation.
- Vendor/BAA tracking.
- Access review.
- MFA/access controls.
- Backup and restore testing.
- Downtime procedure.
- Incident response contact tree.
- Security awareness training.
- Log review.
- Vulnerability/patch review.
- Email security review.
- Endpoint security review.
- Risk analysis update.
- Policy review and signoff.
- AI workflow/data-use review.

### Policy Register

Supported format:

- CSV and JSON.

Minimum fields:

```text
policy_id
policy_name
policy_type
owner
last_reviewed
next_review_due
status
evidence_reference
mapped_controls
```

### Evidence Reference Log

Supported format:

- CSV and JSON.

Minimum fields:

```text
evidence_id
evidence_type
title
description
owner
date_collected
review_date
storage_location_reference
contains_phi
contains_secrets
source_system
mapped_controls
notes
```

Rules:

- Evidence entries with `contains_phi=true` must produce a warning.
- Evidence entries with `contains_secrets=true` must produce a warning.
- The tool should encourage references to secure storage locations, not raw evidence upload.

### System Inventory

Minimum fields:

```text
system_id
system_name
system_type
owner
vendor
ephi_relevance
criticality
internet_exposed
review_date
evidence_reference
```

### Vendor Register

Minimum fields:

```text
vendor_id
vendor_name
service_type
touches_ephi
baa_status
last_reviewed
next_review_due
evidence_reference
owner
```

### Risk Register

Minimum fields:

```text
risk_id
title
description
affected_systems
owner
risk_level
status
mitigating_controls
evidence_reference
review_date
```

### Review Snapshots

Store review snapshots so the tool can show trend over time.

Minimum fields:

```text
snapshot_id
review_date
practice_name
controls_ready
controls_partial
controls_missing
controls_stale
high_priority_gaps
generated_from
reviewer
signoff_status
```

## Required Outputs

### Control-To-Evidence Matrix

Generate:

- `out/control_to_evidence_matrix.csv`
- `out/control_to_evidence_matrix.json`
- `out/control_to_evidence_matrix.md`
- `out/control_to_evidence_matrix.html`

Required fields:

```text
control_id
control_title
domain
owner_role
readiness_state
expected_evidence
current_evidence
missing_evidence
stale_evidence
next_action
source_mappings
review_due
```

### Missing Evidence Gap Report

Generate:

- `out/missing_evidence_gaps.md`
- `out/missing_evidence_gaps.csv`
- `out/missing_evidence_gaps.json`

Report sections:

- Critical missing evidence.
- Stale evidence.
- Controls with no owner.
- Controls with no mapped policy.
- Systems with no evidence reference.
- Vendors touching ePHI with missing/unknown BAA status.
- Risks without mitigating evidence.
- AI workflows without review evidence.
- Next actions by owner.

### Readiness Trend Report

Generate:

- `out/readiness_trends.md`
- `out/readiness_trends.json`
- `out/readiness_trends.csv`

Trend metrics:

```text
ready_count
partial_count
missing_count
stale_count
not_applicable_count
needs_review_count
unknown_count
ready_percent
critical_gap_count
evidence_staleness_average_days
owner_action_count
```

Trend report must compare current run to prior snapshots when available.

Example trend language:

```text
Readiness improved from 42% to 58% since the last review. The largest gains came from vendor BAA evidence and backup restore test documentation. The largest remaining gaps are access review evidence, AI workflow review, and log review cadence.
```

### Evidence Graph JSON

Generate:

- `out/evidence_graph.json`

Shape:

```json
{
  "nodes": [],
  "edges": [],
  "metadata": {
    "generated_at": "",
    "practice_name": "",
    "source_files": []
  }
}
```

This file powers the dashboard and allows future integrations.

### Review Packet

Generate:

- `out/policy-evidence-review-packet.md`
- `out/policy-evidence-review-packet.html`
- `out/policy-evidence-review-packet.pdf`

Packet sections:

- Executive summary.
- Readiness score by domain.
- Top missing evidence.
- Top stale evidence.
- Owner action list.
- Vendor/BAA evidence gaps.
- AI workflow evidence gaps.
- Backup/downtime/incident evidence status.
- Vulnerability and patch evidence status.
- Control-to-evidence matrix summary.
- Trend since prior review.
- Source mappings.
- Signoff page.
- Appendix with control library and evidence rules.

### Owner Action Packets

Generate owner-specific Markdown packets:

- Practice Manager.
- IT Owner.
- Security Reviewer.
- Vendor Owner.
- Clinical Systems Owner.

Each owner packet must include:

- Assigned controls.
- Missing evidence.
- Stale evidence.
- Due dates.
- Plain-English next action.
- Evidence to collect.
- How to record completion.

### Dashboard

Build a local HTML dashboard.

Required views:

- Readiness overview.
- Control-to-evidence matrix.
- Evidence graph.
- Gaps by owner.
- Gaps by domain.
- Vendor/BAA evidence.
- AI workflow evidence.
- Trend over time.
- Review packet preview.

Dashboard requirements:

- Runs locally.
- Loads `out/evidence_graph.json` and generated reports.
- No internet required.
- No external telemetry.
- Search/filter by control, owner, readiness state, evidence type, domain, and source mapping.
- Clear visual distinction between missing, stale, partial, ready, and needs-review states.
- Suitable for a practice manager and a consultant sitting together during a review.

## CLI Requirements

Provide these commands:

```bash
evidence-graph init my-practice
evidence-graph validate my-practice
evidence-graph build my-practice
evidence-graph dashboard my-practice
evidence-graph snapshot my-practice
evidence-graph export my-practice --format markdown
evidence-graph export my-practice --format html
evidence-graph export my-practice --format pdf
evidence-graph sample --practice family-medicine
```

CLI behavior:

- Offline by default.
- Clear warnings for PHI/secrets flags.
- Non-zero exit code for invalid required data in strict mode.
- `--strict` mode for CI.
- `--no-pdf` fallback if PDF generation dependency is missing.
- Friendly console summary with counts and top gaps.

## Readiness Logic

### Control State Assignment

Assign each control one readiness state:

`ready`

All required evidence types are present, current, mapped, and reviewed within cadence.

`partial`

Some evidence exists, but required evidence is incomplete.

`missing`

No acceptable evidence exists for required evidence types.

`stale`

Evidence exists but is older than cadence or review due date.

`not_applicable`

Control is explicitly marked not applicable with rationale and approval.

`needs_review`

Evidence exists but has warnings, unclear mapping, PHI/secrets flag, or missing signoff.

`unknown`

Insufficient data to assign a meaningful status.

### Evidence Freshness

Each control library entry defines `cadence_days`.

Freshness states:

```text
current
due_soon
stale
missing_date
```

Recommended thresholds:

- `current`: within cadence.
- `due_soon`: due within 14 days.
- `stale`: beyond cadence.
- `missing_date`: date missing.

### Gap Priority

Gap priority should consider:

- Control criticality.
- Missing vs stale.
- ePHI relevance.
- Patient-care relevance.
- Vendor/BAA impact.
- Incident/downtime impact.
- Prior review recurrence.
- Owner missing.

Priority bands:

```text
critical
high
medium
low
informational
```

## Source Mapping Requirements

The tool must include practical source mappings without overclaiming legal conclusions.

Baseline mapping sources:

- HIPAA Security Rule concepts.
- NIST SP 800-66 Rev. 2 practical guidance.
- HHS HPH Cybersecurity Performance Goals.
- CISA Cybersecurity Performance Goals.
- NIST Cybersecurity Framework categories.
- 405(d) HICP practice areas where appropriate.

Source mapping output must state:

- Source family.
- Source concept.
- Practical evidence expectation.
- Internal control ID.

Do not claim:

- "This proves compliance."
- "This satisfies HIPAA."
- "This replaces legal/security assessment."

Use language:

- "Supports evidence for..."
- "Maps to practical readiness concept..."
- "Helps prepare documentation for..."

## Existing Repo Integration Plan

### Small-Practice Security Kit

Repo:

`https://github.com/itsnmills/small-practice-security-kit`

Integration:

- Import practice profile.
- Import systems.
- Import vendors.
- Import ePHI flows.
- Import evidence references.
- Export readiness gaps back into packet.

### ePHI Data Flow Mapper

Repo:

`https://github.com/itsnmills/ephi-data-flow-mapper`

Integration:

- Import flow register.
- Map ePHI flow documentation to controls for system inventory, transmission, vendor review, and risk analysis support.
- Highlight flows lacking evidence or owner.

### HIPAA Evidence Binder Template

Repo:

`https://github.com/itsnmills/hipaa-evidence-binder-template`

Integration:

- Import binder manifest and evidence index.
- Export updated evidence matrix and review packet into binder-compatible folders.

### Vendor Risk Manager

Repo:

`https://github.com/itsnmills/vendor-risk-manager`

Integration:

- Import vendor register, BAA status, annual verification evidence, and vendor action items.
- Map vendor evidence to BAA/vendor control expectations.

### Security Operations Triage Pipeline

Future repo:

`https://github.com/itsnmills/security-operations-triage-pipeline`

Integration:

- Import tickets, critical findings, accepted risks, false positives, and remediation evidence.
- Map remediation tickets to vulnerability management, incident readiness, asset inventory, and patch evidence controls.

### HealthAI Audit

Repo:

`https://github.com/itsnmills/health-ai-governance-auditor`

Integration:

- Import AI tool/workflow reviews.
- Map AI workflow evidence to policy, vendor, PHI handling, and human review controls.

## Example Scenario

Fictional practice:

Riverside Family Medicine

Inputs:

- 26 baseline controls.
- 17 policies/procedures.
- 31 evidence references.
- 19 systems.
- 12 vendors.
- 9 risks.
- 2 prior review snapshots.

Expected outputs:

- Control matrix with 26 rows.
- Evidence graph with control, policy, evidence, system, vendor, risk, and owner nodes.
- Missing evidence report with owner action list.
- Trend report showing readiness movement since prior review.
- Review packet for quarterly management review.
- Dashboard for local review.

## Build Phases

### Phase 1: Repo Foundation

Tasks:

- Create repo skeleton.
- Add README, LICENSE, DISCLAIMER, SECURITY.
- Add Python package and CLI entrypoint.
- Add JSON schemas.
- Add baseline control libraries.
- Add CI workflow.

Acceptance criteria:

- `evidence-graph --help` works.
- Sample project can be initialized.
- CI runs tests.
- README has a 5-minute quickstart.

### Phase 2: Input Models And Validation

Tasks:

- Implement CSV/JSON/YAML ingestion.
- Validate control library, policy register, evidence log, system inventory, vendor register, risk register, and snapshots.
- Preserve unknown fields for future compatibility.
- Add PHI/secrets warnings.

Acceptance criteria:

- Invalid files produce useful validation output.
- Strict mode fails on missing required fields.
- Tests cover malformed inputs, duplicates, stale dates, and missing owners.

### Phase 3: Graph Builder

Tasks:

- Build graph nodes and edges.
- Link controls to expected evidence.
- Link evidence to controls.
- Link systems, vendors, risks, policies, owners, and tickets.
- Export `evidence_graph.json`.

Acceptance criteria:

- Every control produces a node.
- Every evidence reference produces a node.
- Required edges are created.
- Graph output is deterministic and snapshot-tested.

### Phase 4: Gap And Readiness Engine

Tasks:

- Implement readiness state logic.
- Implement evidence freshness.
- Implement missing evidence detection.
- Implement stale evidence detection.
- Implement owner action generation.
- Implement gap priority.

Acceptance criteria:

- Every control has a readiness state and explanation.
- Missing/stale evidence reports are complete.
- Owner action packets are generated.
- Tests cover each state transition.

### Phase 5: Trend Engine

Tasks:

- Implement review snapshot creation.
- Compare current state to prior snapshot.
- Generate trend metrics.
- Generate plain-English trend summary.

Acceptance criteria:

- Current run can create a snapshot.
- Trend report works with zero, one, or multiple prior snapshots.
- Regression and improvement are both detected.

### Phase 6: Reports And Dashboard

Tasks:

- Generate matrix CSV/JSON/Markdown/HTML.
- Generate gap reports.
- Generate readiness trend reports.
- Generate review packet Markdown/HTML/PDF.
- Build local dashboard.

Acceptance criteria:

- A non-developer can open dashboard and understand readiness, gaps, owners, and trends.
- Review packet is suitable for a quarterly review.
- PDF generation works or provides a clear fallback.

### Phase 7: Practice-Ready Examples And Docs

Tasks:

- Add family medicine, dental, behavioral health, and consultant-client examples.
- Add source mapping docs.
- Add privacy model docs.
- Add import plans for existing repos.
- Add screenshots and sample outputs.

Acceptance criteria:

- Sample walkthrough is complete.
- Outputs use fictional data only.
- Docs explain how this fits with other repos.
- README is portfolio-grade and practitioner-useful.

## Testing Requirements

Unit tests:

- Control library parsing.
- Policy register parsing.
- Evidence log parsing.
- System/vendor/risk parsing.
- Graph node creation.
- Graph edge creation.
- Readiness state logic.
- Evidence freshness.
- Gap priority.
- Trend calculation.
- Report generation.

Integration tests:

- Full sample build for family medicine.
- Full sample build for dental.
- Full sample build for behavioral health.
- Strict validation failure project.
- Snapshot comparison over three review cycles.

Snapshot tests:

- Control-to-evidence matrix Markdown.
- Missing evidence gap report.
- Readiness trend report.
- Review packet.
- Evidence graph JSON.

Security/privacy tests:

- Sample PHI scanner.
- Secret scanner.
- No outbound network test for default path.
- Evidence references warn on sensitive flags.

Manual E2E:

```bash
evidence-graph sample --practice family-medicine
evidence-graph validate examples/family-medicine
evidence-graph build examples/family-medicine
evidence-graph snapshot examples/family-medicine
evidence-graph dashboard examples/family-medicine
```

Expected artifacts:

```text
out/control_to_evidence_matrix.csv
out/control_to_evidence_matrix.json
out/control_to_evidence_matrix.md
out/missing_evidence_gaps.md
out/readiness_trends.md
out/evidence_graph.json
out/policy-evidence-review-packet.md
out/policy-evidence-review-packet.html
out/policy-evidence-review-packet.pdf
out/owner_actions/*.md
```

## README Requirements

README must include:

- Clear product statement.
- Who it is for.
- What it does not do.
- 5-minute quickstart.
- Example dashboard screenshots or output snippets.
- Data model overview.
- Graph model overview.
- Readiness state explanation.
- Control library explanation.
- Evidence reference safety guidance.
- Trend/report examples.
- Integration plan with existing repos.
- Resume bullet suggestions.
- Disclaimer.

## Documentation Requirements

Required docs:

- `docs/architecture.md`: package architecture and data flow.
- `docs/data-model.md`: all inputs and outputs.
- `docs/graph-model.md`: node and edge definitions.
- `docs/control-library.md`: how controls are defined and mapped.
- `docs/evidence-rules.md`: readiness and gap logic.
- `docs/readiness-trends.md`: snapshot and trend methodology.
- `docs/privacy-and-storage-boundary.md`: how to avoid PHI/secrets.
- `docs/sample-practice-walkthrough.md`: end-to-end use case.
- `docs/import-plans-existing-repos.md`: concrete import/export plans.

## Resume Bullets After Completion

Use after the project is built:

- Built a local-first Policy-to-Evidence Graph that maps healthcare security controls, policies, systems, vendors, risks, tickets, and evidence references into a control-to-evidence matrix and readiness graph.
- Implemented missing-evidence detection, stale-evidence checks, owner action packets, review snapshots, and readiness trend reporting across synthetic small-practice examples.
- Added source mappings to HIPAA Security Rule concepts, NIST SP 800-66, HPH CPG, CISA CPG, and NIST CSF without storing PHI or claiming compliance certification.

## Definition Of Done

This goal is complete when:

- Repo exists and is public-ready.
- CLI can initialize, validate, build, snapshot, export, and launch dashboard.
- Baseline control libraries are present.
- Sample data exists for at least three practice types.
- Control-to-evidence matrix, gap report, trend report, graph JSON, owner action packets, and review packet are generated.
- Local dashboard works from generated artifacts.
- Tests pass locally and in GitHub Actions.
- README and docs are practitioner-useful and recruiter-readable.
- Sample data is synthetic and PHI/secret scanned.
- Existing repo import/export plans are explicit.
- The final demo feels like a tool a small healthcare practice, MSP, or consultant could use tomorrow.
