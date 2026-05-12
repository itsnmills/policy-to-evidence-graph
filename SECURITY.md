# Security and Privacy Policy

This repository is designed for **local-first operation** and assumes the user stores only references to evidence, not PHI.

## Threat model

- No production credentials should be placed in input files.
- No patient-level records are accepted.
- Evidence should be linked by document names, ticket IDs, or internal references.

## Safe usage requirements

- Keep `project.yaml` and evidence references inside a directory you already protect.
- Run on isolated client systems with local encryption if policy requires.
- Do not place PHI or raw access logs in inputs.
- Use a strong passphrase in `PTEG_ENCRYPTION_KEY` or `project.yaml`-configured passphrase file before running encrypted builds.
- Use `evidence-graph build --encrypt` or `evidence-graph protect` for sensitive outputs.
- Never pass secrets on command lines. Use `--passphrase-file` or a secure environment variable.

Recommended clinic workflow:

- Run `evidence-graph init` on a locked-down admin workstation.
- Optionally create a local passphrase file with:
  - `evidence-graph generate-passphrase --project . --output .evidence_graph/secrets/passphrase.txt`
- Set `security.encrypt_outputs: true` in `project.yaml` when packet handoff is expected.
- Set `security.delete_plaintext: true` if you want output files removed automatically after encryption.
- Use `security.strict_mode: true` for clinic-style preflight blocking on PHI-like patterns and posture issues.

## Security posture command

Run `evidence-graph security-audit --strict --project .` before sharing with clients.
This writes:

- `out/security_audit_report.json`
- `out/security_audit_report.md`

It validates required inputs, PHI-like findings, path permissions, passphrase source, integrity manifest, and snapshot chain health.

## Integrity protections

- Build and export create `out/integrity_manifest.json` with SHA-256 hashes for generated artifacts.
- Snapshots now include `integrity.snapshot_signature` for tamper-evident trailing.
- Encrypted artifacts are tracked in `out/security_bundle.json` with owner-owned passphrase references.

## Reporting security issues

If you find a security issue in this repository, open a GitHub issue with:

- Expected behavior
- Reproduction steps
- Example input sample (redacted)
- Environment details

Please do not include secrets in tickets.
