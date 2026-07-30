"""
DAPT 2020 loader (M5)
=====================
DAPT 2020 represents an enterprise falling to an APT campaign. Its network
flows are CICFlowMeter output (so the adapter work is small — the flow-field
probe is shared with the CIC loader), grouped per day, and — crucially — its
flow labels carry BOTH an 'activity' field (the specific attack) AND a 'stage'
field (the APT stage). The stage field is the only readily available per-flow
kill-chain-phase-like ground truth, which is why this dataset is here.

The five days:
    day 1  Benign baseline
    day 2  Reconnaissance (scanning)
    day 3  Foothold Establishment (SQLi, XSS, auth bypass)
    day 4  Lateral Movement (insider scan, auth bypass, SQLi)
    day 5  Data Exfiltration (exfil to a C&C server)

QUARANTINE: 'activity' and 'stage' are LABELS. They are cached for the sidecar
and returned only via ground_truth()/phase_ground_truth(). They are NEVER put
into CanonicalFlow.extra (which agents can read).

NOTE: the DAPT dataset is not committed (it is large and separately licensed).
Point the loader at the download with --dapt-root / root=..., or a slice path.
The stage→phase crosswalk and scoring live in eval_sidecar.py (M5).
"""

from __future__ import annotations

import os
from typing import Iterable, Optional

from .base import Loader
from .canonical import CanonicalFlow
from .cic_ids2017 import probe_schema, _read_csv, _norm

# DAPT's activity + stage vocabulary (feeds the environment validator).
LABEL_VOCABULARY = [
    "Benign", "Reconnaissance", "Foothold Establishment",
    "Lateral Movement", "Data Exfiltration",
    "Scanning", "Directory Bruteforce", "Account Bruteforce",
    "SQL Injection", "XSS", "CSRF", "Command Injection",
    "Authentication Bypass", "Malware Download", "Backdoor",
]

_STAGE_NORMS = {"stage", "apstage", "attackstage"}
_ACTIVITY_NORMS = {"activity", "subactivity", "attack"}


class Dapt2020Loader(Loader):
    dataset_id = "dapt2020"

    def __init__(self, root: str = None):
        self.root = root or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "DAPT2020")
        self._stage_cache = {}      # flow_id -> APT stage  (phase ground truth)
        self._activity_cache = {}   # flow_id -> activity    (label ground truth)

    def _resolve_path(self, slice_spec) -> tuple:
        limit = None
        if isinstance(slice_spec, dict):
            limit = slice_spec.get("limit")
            slice_spec = slice_spec.get("path") or slice_spec.get("day")
        if slice_spec and os.path.exists(str(slice_spec)):
            return str(slice_spec), limit
        if os.path.isdir(self.root):
            for fn in sorted(os.listdir(self.root)):
                if fn.endswith(".csv") and str(slice_spec).lower() in fn.lower():
                    return os.path.join(self.root, fn), limit
        raise FileNotFoundError(
            f"no DAPT 2020 file matching {slice_spec!r} in {self.root} — the "
            "DAPT dataset is not committed; download it and pass root=... or a "
            "full slice path.")

    def load_slice(self, slice_spec) -> Iterable[CanonicalFlow]:
        path, limit = self._resolve_path(slice_spec)
        raw = _read_csv(path, nrows=limit)
        m = probe_schema(raw.columns)               # shared CICFlowMeter probe
        by_norm = {_norm(c): c for c in raw.columns}
        stage_col = next((by_norm[n] for n in _STAGE_NORMS if n in by_norm), None)
        activity_col = next((by_norm[n] for n in _ACTIVITY_NORMS if n in by_norm), None)
        self._stage_cache, self._activity_cache = {}, {}
        for i, row in raw.iterrows():
            fid = str(row[m["flow_id"]]) if "flow_id" in m else f"{os.path.basename(path)}:{i}"
            if stage_col:
                self._stage_cache[fid] = str(row[stage_col])
            if activity_col:
                self._activity_cache[fid] = str(row[activity_col])
            yield CanonicalFlow(
                flow_id=fid,
                src_ip=row.get(m["src_ip"]),
                src_port=row.get(m["src_port"]),
                dst_ip=row.get(m["dst_ip"]),
                dst_port=row.get(m["dst_port"]),
                protocol=row.get(m["protocol"]),
                timestamp_start=row.get(m["timestamp_start"]),
                timestamp_end=None,
                duration=row.get(m["duration"]),
                fwd_packets=row.get(m["fwd_packets"]),
                bwd_packets=row.get(m["bwd_packets"]),
                fwd_bytes=row.get(m["fwd_bytes"]) if "fwd_bytes" in m else None,
                bwd_bytes=row.get(m["bwd_bytes"]) if "bwd_bytes" in m else None,
                flags_summary="",
                extra={})       # NB: stage/activity are labels — never in extra

    def label_vocabulary(self) -> list:
        return list(LABEL_VOCABULARY)

    # -- SIDECAR ONLY ---------------------------------------------------------
    def ground_truth(self, flow_id) -> Optional[str]:
        return self._activity_cache.get(str(flow_id))

    def phase_ground_truth(self, flow_id) -> Optional[str]:
        return self._stage_cache.get(str(flow_id))
