# `environment/` — environment context profiles (Week 4, M1)

A profile tells the agents **what network they are looking at**. The same
flows mean different things on a corporate DMZ than on a home laptop, so a
profile lets an agent judge what is normal and what matters — *without* being
told which flows are attacks (constraint #2, ground-truth quarantine).

## Layout

- `profiles/*.yaml` — one file per environment. Two ship: `enterprise_dmz`,
  `personal_laptop`. Section A is **facts** (objective, reviewable); Section B
  is `analyst_policy` — **judgment**, fenced and rendered separately so a
  reviewer sees opinion as opinion.
- `validator.py` — the load-time gate. Four hard-reject rules (label-vocabulary
  collision, maliciousness assertion, phase/technique pinning, verdict
  language) and three warnings. It is **dataset-aware**: reject rule 1 takes
  the loaded dataset's label vocabulary. Rejection raises loudly and refuses to
  run; the verdict is written to the run manifest.
- `__init__.py` — the per-agent **injection matrix** (`ENVIRONMENT_INJECTION`),
  the deterministic prose **renderer**, and `inject()`, which returns the
  modified prompt plus a manifest entry proving exactly what each agent saw.

## The one thing not to change

`ENVIRONMENT_INJECTION["threat_intel"] == []` on purpose. ATT&CK mapping must
be environment-invariant, so Threat Intel receives no context and its prompt is
byte-identical across profiles — the testable prediction the M7 experiment
checks. It is an explicit empty allowlist, not an omission.

## Use

```bash
python src/workflow.py --csv <day>.csv --environment enterprise_dmz
python src/workflow.py --csv <day>.csv            # no context (logged in manifest)
```
