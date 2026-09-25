# Supply-chain fixture

A checkout written to exercise the supply-chain engines, each defect labelled
with the rule that must report it. Kept separate from `vulnerable/` so that
repo's pinned seeded-flaw table stays about SAST, secrets and IaC.

| Seeded | Rule |
|---|---|
| `infra/Dockerfile` pins `python:3.8` (EOL 2024-10-07) | `AEGIS-SUPPLY-010` |
| `.python-version` pins `3.10` (EOL 2026-10-31, within a year) | `AEGIS-SUPPLY-011` |
| `infra/Dockerfile.legacy` pins `crystal:1.9`, unknown runtime | `AEGIS-SUPPLY-019` |
| `requirements.txt` names an AGPL package | `AEGIS-SUPPLY-020` |
| `src/package.json` depends on `1odash` and `exprses` | `AEGIS-SUPPLY-030` |
| `src/package.json` has an unpinned `*` dependency | `AEGIS-SUPPLY-031` |
| `src/package.json` has a `postinstall` script | `AEGIS-SUPPLY-032` |

Nothing here is executed. The npm names are deliberately not real packages, so
a reader who installs this by accident gets a resolution failure rather than
someone else's code.
