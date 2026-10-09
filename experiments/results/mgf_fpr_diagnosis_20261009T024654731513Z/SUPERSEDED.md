# Superseded diagnostic grouping

Recovery, raw Y, selection, threshold and history replay completed without
mismatches. An artifact test then found that component summaries lacked a
trajectory tag: projection and full-vector CLOSED loops have different updates,
so `(context, round, client, component-region)` was not a unique identifier.

Preserved without overwriting its original files. The fresh diagnosis adds
`trajectory_scope` to per-client components/coordinate diagnostics and does not
pool the two closed-loop update sets. Runtime and parameters remain unchanged.
Use the fresh artifact named in `docs/reproduction/mgf-fpr-diagnosis-2026-10-09.md`.
