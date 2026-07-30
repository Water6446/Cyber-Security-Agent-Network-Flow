# `datasets/` — dataset adapter layer (Week 4–5, M4/M5)

Generalises loading so a second dataset lands on the same pipeline. Everything
downstream reads **canonical** fields; `extra` carries dataset-specific
columns.

## Layout

- `canonical.py` — `CanonicalFlow`, the internal schema every loader normalises
  to (`flow_id, src_ip, src_port, dst_ip, dst_port, protocol,
  timestamp_start/end, duration, fwd/bwd packets/bytes, flags_summary, extra`).
- `base.py` — the `Loader` interface: `load_slice`, `label_vocabulary`,
  `ground_truth`, `phase_ground_truth`.
- `registry.py` — `DATASETS = {dataset_id: LoaderClass}`; `get_loader(id)`.
- `cic_ids2017.py` — refactored CIC loader with **mandatory schema probing**
  (raises `SchemaError` on an unrecognised CICFlowMeter header instead of
  producing null columns). `phase_ground_truth` is `None` — CIC labels attack
  *types*, not phases.
- `dapt2020.py` — DAPT 2020 (CICFlowMeter output with `activity` + `stage`
  labels). `phase_ground_truth` returns the APT stage. **Not committed** — the
  dataset is large/separately licensed; pass `root=...` or a slice path.

## Quarantine (enforced, not just intended)

`ground_truth()` and `phase_ground_truth()` return **labels** and may be called
**only from `eval_sidecar.py`**. `tests/test_quarantine.py` greps the agent
modules and fails if either symbol appears in them.

## The DAPT taxonomy gap

DAPT's four APT stages do not map cleanly onto the six Lockheed phases (Lockheed
has no lateral-movement phase). The crosswalk lives in `eval_sidecar.py` with
**primary + acceptable-alternate** mappings, and scoring reports **three
buckets** (primary / alternate / disagreement) — never one blended number.
