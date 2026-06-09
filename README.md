# Policy-to-Evidence Graph

A local-first evidence graph for small healthcare practices, MSPs, and consultants.

You can load control libraries, policy/evidence registers, system inventories, vendor records, and risk snapshots.
The tool builds a control-to-evidence graph, flags stale or missing evidence, tracks readiness trends, and exports a practical review packet.

## Velari Suite Navigation

These repos are the public navigation layer for the Velari Small Practice Security Suite. They are local-first, PHI-avoidant evidence tools for small healthcare practices and MSPs; each repo has its own scope and safety boundaries.

| Repo | Role |
|---|---|
| [Small Practice Security Kit](https://github.com/itsnmills/small-practice-security-kit) | Flagship no-PHI readiness packet and owner/MSP handoff. |
| [Cloud/IAM Access Review Analyzer](https://github.com/itsnmills/cloud-iam-access-review-analyzer) | Google Workspace, Microsoft 365, and AWS IAM export review packets. |
| [HealthAI Governance Auditor](https://github.com/itsnmills/health-ai-governance-auditor) | AI tool inventory, vendor questions, and PHI-handling review prompts. |
| [Strands PHI Guardrails Demo](https://github.com/itsnmills/Strands-PHI-Guardrails-Demo) | Deterministic RBAC, purpose-of-use, BAA-status, and PHI-pattern guardrail examples. |
| [Security Operations Triage Pipeline](https://github.com/itsnmills/security-operations-triage-pipeline) | Scanner/alert exports into owner-ready tickets and handoff packets. |
| [Policy-to-Evidence Graph](https://github.com/itsnmills/policy-to-evidence-graph) | Local control-to-evidence map, freshness checks, and review packet exports. |

Use these for evidence organization and review preparation. They do not provide legal advice, certify compliance, complete a formal Security Risk Analysis, or make breach-notification decisions.

## Quick start (60 seconds)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
evidence-graph init
evidence-graph build
python -m http.server 8000 --directory web
```

Or from installed entrypoint:

```bash
evidence-graph sample
python -m evidence_graph.cli build --project .
evidence-graph dashboard --project .
evidence-graph export --project .
```

## Security-first and encryption workflow

This project keeps data local, and you can keep generated outputs encrypted on disk.

### Setup for encrypted mode

```bash
export PTEG_ENCRYPTION_KEY='choose-a-long-random-passphrase'

# Or generate and store a project-local passphrase file:
evidence-graph generate-passphrase --project . --output .evidence_graph/secrets/passphrase.txt
evidence-graph init
```

If you prefer environment-only secrets, keep it long and random:

```bash
export PTEG_ENCRYPTION_KEY='choose-a-long-random-passphrase'
```

### Build encrypted review packet

```bash
evidence-graph init
evidence-graph sample --project .
evidence-graph build --project . --encrypt
```

Outputs include:

- `.enc` files next to each generated artifact
- `out/security_bundle.json` (includes encryption metadata and manifest hashes)
- `out/integrity_manifest.json` (SHA-256 file integrity snapshot)

Use `--delete-plaintext` only if you want encrypted-only output storage:

```bash
evidence-graph build --project . --encrypt --delete-plaintext
```

Protect or decrypt an individual file:

```bash
evidence-graph protect --project . --input out/review_packet.md
evidence-graph unprotect --project . --input out/review_packet.md.enc --output out/review_packet.md
```

Best-practice hardened workflow for clinics and consultants:

- Keep `project.yaml`, `.evidence_graph/` and `out/` private (`chmod 700/600` behavior is enforced on supported systems).
- Use `.enc` handoff artifacts for clients and retain plaintext only on trusted admin hosts.
- Validate every build with:
  - `evidence-graph security-audit --strict --project .`
  - `evidence-graph verify --project .`
- Store the generated `out/security_audit_report.json` and `out/security_bundle.json` with your delivery packet.

### Security posture preflight for clinics

```bash
evidence-graph build --project . --strict --encrypt --delete-plaintext
evidence-graph export --project . --format all --strict --encrypt
```

## Commands

- `init` creates local project state and default folders.
- `validate` validates all supported files against schemas.
- `build` ingests inputs and produces matrix/gaps/readiness artifacts.
- `snapshot` records review snapshots for trend tracking.
- `dashboard` builds static dashboard assets from latest run.
- `export` emits Markdown/HTML/JSON/PDF review packet artifacts.
- `sample` creates realistic synthetic data for local testing.
- `security-audit` runs a posture scan for permissions, passphrase hygiene, PHI-like content, and integrity/snapshot checks.
- `generate-passphrase` creates a strong local passphrase for local encryption.

## Data flow

1. Intake controls, policies, evidence, systems, vendors, and risks.
2. Build graph and compute readiness by control.
3. Produce:
   - `out/control_to_evidence_matrix.csv`
   - `out/missing_evidence_gaps.csv`
   - `out/readiness_summary.json`
   - `out/review_packet.md/html/json`
4. Save a snapshot with `snapshot` and compare over time.
5. Run `security-audit --strict` before sharing outputs.

## Output philosophy

This is not enterprise GRC software. It is a practical evidence support tool.

- Readiness signal, not legal opinion
- Local and inspectable by default
- Evidence-first, PHI-light
- Designed for one-day setup for small practices

## Import mapping (from existing repos)

See [docs/import-plans-existing-repos.md](docs/import-plans-existing-repos.md)

## File formats

- CSV templates are in `templates/`
- Default control libraries are in `control_libraries/`
- Example datasets in `examples/`

## Notes on trust and staleness

Evidence freshness uses review dates and configured thresholds.
Missing or stale controls are highlighted by priority.

## Contributing

1. Run `ruff check src tests`
2. Run tests: `pytest`
3. Open PR with a summary and sample output files in `/out`
