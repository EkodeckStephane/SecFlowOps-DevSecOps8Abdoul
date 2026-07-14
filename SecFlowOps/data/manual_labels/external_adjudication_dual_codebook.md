# Dual External Adjudication Codebook

Each external finding must be reviewed independently by two reviewers before consensus.

## Review status

- `confirmed`: repository evidence supports the finding under the scanner rule semantics.
- `rejected`: repository evidence contradicts the finding.
- `uncertain`: evidence is insufficient without additional runtime, advisory, or maintainer context.

## True positive

- `true`: the finding is valid under the documented evidence type.
- `false`: the finding is invalid under the documented evidence type.
- `unknown`: the reviewer cannot decide from the provided artifact.

## Evidence type

- `static_code`: source/configuration evidence only.
- `dependency_manifest`: manifest or lockfile evidence.
- `advisory_database`: CVE/GHSA/npm advisory evidence.
- `dynamic_runtime`: executable exploit or runtime observation.
- `secret_material`: committed credential/key/token evidence.

## Consensus rule

Consensus is accepted when both reviewers agree on `true_positive` and compatible severity.
Disagreements require a consensus row with a written reason; do not overwrite reviewer files.
