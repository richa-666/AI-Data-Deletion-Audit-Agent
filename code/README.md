# Deletion Audit Agent

This package builds a deterministic, evidence-driven deletion audit from the
participant-facing files in `dataset/`. It does not call an external model or
require network access at runtime.

## Setup and execution

From the repository root, install the Python dependency and run the full audit:

```powershell
python -m pip install -r code\requirements.txt
python code\main.py
```

The command reads `dataset/` relative to the repository root and writes
`output.csv` in that root only when every authorized case has enough evidence
to construct a valid audit. If any case is unresolved, it lists the case and
evidence gap in `code/evaluation/unresolved_cases.csv` and exits without
replacing an existing `output.csv`. A successful output has the columns
`case_id,deletion_status,steps_json`, one sorted row for each of the 518
requests.

Run sample evaluation and the independent custom scenarios:

```powershell
python code\evaluation\main.py
```

Run the unit tests:

```powershell
python -m unittest discover -s code\tests -v
```

## Architecture

- `audit_agent/identity.py` loads current identities and identity audit history,
  resolves request emails across historical aliases, and returns identifiers
  valid at the request's `audit_at`.
- `audit_agent/evidence.py` ingests manifest-listed JSON, SQLite-compatible SQL,
  logs, text, and PDFs. SQL data snapshots are parsed locally, including nested
  JSON records. On Windows, screenshot OCR uses the built-in Windows Runtime
  OCR API through `windows_ocr.ps1`; on other systems it uses Pillow,
  pytesseract, and a working Tesseract executable when available.
- `audit_agent/engine.py` classifies deletion intent, applies the supplied
  category rules to evidence at or before `audit_at`, generates findings and
  remediation/verification steps, sorts them deterministically, and validates
  the output structure.
- `evaluation/main.py` compares predictions with the public sample and runs
  three synthetic scenarios for non-deletion intent, an incomplete deletion
  with an active flow and remaining copy, and a compliant policy-retained
  security record.

Evidence matches are expanded to related events for the same system/resource
so that a lookup start can be joined to its result without treating unrelated
resources as evidence for the subject. Workflow status and reported activity
results are not used as deletion proof.

## Limitations

The agent uses deterministic rules rather than a model. Consequently, request
classification is not a substitute for human review of ambiguous language.
An authorized request is not considered complete without supported
verification steps, including evidence that the account profile is absent.
Evidence gaps are reported by case and stop generation before the output file
is replaced. The previous `output.csv`, if present, is left untouched and must
not be treated as the result of a failed run. Some evidence resources do not
contain a direct identifier link to the subject; no unsupported cross-resource
association is invented. The public-sample evaluation report documents
measured accuracy and residual mismatches, and predictions are not a claim of
perfect case-level or sequence-level accuracy.

## Output and packaging

The final submission output is the repository-root `output.csv`. For the
submission archive, include the repository `README.md` and this `code/`
directory, and exclude `dataset/`, caches, virtual environments, and nested
archives. The evaluation reports are stored under `code/evaluation/`.
