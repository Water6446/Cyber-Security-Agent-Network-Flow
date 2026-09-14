# Security Policy

## First, the important scoping note

**This project is not a production security control, and should not be deployed
as one.** It is a research and teaching artifact that explains and triages
findings *downstream* of detection. It is not tuned for a real SOC, not
benchmarked for detection accuracy, and not safe to point at a live network as a
gatekeeper. Deploying it as a detector is a misuse, not a vulnerability.

## What counts as a vulnerability here

Reports that are in scope:

- A way to make an agent emit an unverified claim that the grounding checks
  report as verified — the grounding and quarantine boundaries are the security
  properties this project actually asserts.
- A path by which ground truth (the `Label` column, the answer key, or the phase
  crosswalk in `src/eval_sidecar.py`) reaches an agent's context. See
  `tests/test_quarantine.py` for the boundary this is meant to enforce.
- Prompt injection through dataset contents or tool results that escapes the
  capped, narrow tool surface — for example, causing arbitrary code execution,
  file access outside the repository, or network calls the tools do not make.
- Leakage of an API key through logs, run manifests, or `outputs/`.
- Anything in the dependency chain that executes on `pip install` or on import.

Out of scope: the model being wrong, missing an attack, or writing a poor
report. That is model quality, measured by the eval sidecar, not a
vulnerability.

## Reporting

Report privately — **please do not open a public issue for a vulnerability.**

Use GitHub's private vulnerability reporting on this repository:
**Security → Report a vulnerability**. That opens a channel visible only to the
maintainer.

Please include what you were running (provider, model, command line), what you
expected, what happened, and the smallest reproduction you can manage.

This is a personal project maintained by one person alongside other work. There
is no SLA; expect a first response within a couple of weeks, and be aware that
fixes land on a best-effort basis.

## Handling secrets in reports

Never include a real API key, a real capture from a network you do not own, or
personal data in a report. Redact it and describe the shape of the problem
instead.
