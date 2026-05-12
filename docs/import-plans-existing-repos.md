# Import Plans for Existing Repos

## Small Practice Security Kit
- policy register: map security kit policy list to `policy_register.csv`
- readiness milestones: map checklist completion to `evidence_reference_log.csv`
- local path examples:
  - `../small-practice-security-kit` for practice-level playbooks and readiness milestones
- repo mapping:
  - map security-kits policy IDs -> `policy_id`
  - map `control_id` tags to `control_ids`

## ephi-data-flow-mapper
- system inventory: map `systems` + `touches_phi` to `system_inventory.csv`
- local path example: `../ephi-data-flow-mapper`

## vendor-risk-manager
- export vendor inventory to `vendor_register.csv`
- map `baa_status`, `review_date`, and policy-impacting controls to `controls`
- local path example: `../vendor-risk-manager` (if present in workspace)

## hipaa-evidence-binder-template
- map evidence artifacts to `evidence_reference_log.csv` with evidence_type + collected_at
- local path example: `../hipaa-evidence-binder-template`

## health-ai-governance-auditor / ai-governance-auditor
- map AI workflow approvals to control `CPR-005` and policy `POL-05`
- local path examples:
  - `../health-ai-governance-auditor`
  - `../ai-governance-auditor`

## healthcare-ai-security-lab
- map KEV findings to `risk_register.csv` and attach remediation severity to `risks` controls

## Security Operations Triage Pipeline
- map triage ticket artifacts -> `missing_evidence_gaps.csv` and export packet references
- local path example: `../security-operations-triage-pipeline`

## GitHub references
- [ephi-data-flow-mapper](https://github.com/itsnmills/ephi-data-flow-mapper)
- [vendor-risk-manager](https://github.com/itsnmills/vendor-risk-manager)
- [hipaa-evidence-binder-template](https://github.com/itsnmills/hipaa-evidence-binder-template)
- [health-ai-governance-auditor](https://github.com/itsnmills/health-ai-governance-auditor)
- [security-operations-triage-pipeline](https://github.com/itsnmills/security-operations-triage-pipeline)
