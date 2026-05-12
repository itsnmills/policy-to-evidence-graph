# Privacy and Storage Boundary

No patient records are required.

Keep evidence references only, like:

- file names
- ticket IDs
- meeting records
- control IDs
- review timestamps

Do not place PHI, secrets, or patient notes into project files.

Recommended default for clinics:

- Enable encrypted outputs:
  - `PTEG_ENCRYPTION_KEY` environment variable
  - `evidence-graph build --project . --encrypt`
- Keep `.evidence_graph` and `out` permissions restricted on shared machines.
- Distribute only `.enc` artifacts; retain plaintext only on trusted admin endpoints.
- For passphrases, prefer `evidence-graph generate-passphrase --project . --output .evidence_graph/secrets/passphrase.txt` and keep file permissions private.
- Run `security-audit --strict --project .` before sharing packet artifacts.
