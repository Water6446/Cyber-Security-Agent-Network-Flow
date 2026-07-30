"""
CIC-IDS2017 loader (M4)
=======================
Refactor of the Week 2/3 loading logic into the adapter layer, with MANDATORY
schema probing. CICFlowMeter column names vary between versions (leading
spaces, capitalisation, `Flow ID` vs `FlowID`, `Destination Port` vs
`Dst Port`), so the loader probes the header and maps every canonical field
explicitly, raising a clear SchemaError on an unrecognised header rather than
silently producing null columns.

CIC-IDS2017 labels ATTACK TYPES, not kill-chain phases, so phase_ground_truth
returns None (see DAPT 2020 for the phase-labelled dataset).
"""

from __future__ import annotations

import os
import re
from typing import Iterable, Optional

import pandas as pd

from .base import Loader
from .canonical import CanonicalFlow


class SchemaError(ValueError):
    """Raised when a file's header cannot be mapped to the canonical schema."""


# The CIC-IDS2017 ATTACK families (as they appear in the Label column, modulo
# the dataset's mangled dash encodings). Feeds the environment validator, whose
# label-collision rule rejects profiles that name an attack class. BENIGN is
# deliberately EXCLUDED: it is the baseline label, not an attack class, and
# "benign" is a legitimate word in a profile's baseline_behavior description —
# treating it as a collision label would reject valid profiles. This keeps the
# loader's vocabulary consistent with validator.CIC_IDS2017_LABELS.
LABEL_VOCABULARY = [
    "DDoS", "PortScan", "Bot", "Infiltration", "Heartbleed",
    "Web Attack", "Brute Force", "XSS", "Sql Injection",
    "DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest",
    "FTP-Patator", "SSH-Patator",
]


def _norm(col: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(col).lower())


# canonical field -> set of normalised acceptable source-header spellings
_ALIASES = {
    "flow_id":         {"flowid"},
    "src_ip":          {"sourceip", "srcip"},
    "src_port":        {"sourceport", "srcport"},
    "dst_ip":          {"destinationip", "dstip", "destip"},
    "dst_port":        {"destinationport", "dstport", "destport"},
    "protocol":        {"protocol"},
    "timestamp_start": {"timestamp"},
    "duration":        {"flowduration", "duration"},
    "fwd_packets":     {"totalfwdpackets", "totfwdpkts", "totalforwardpackets"},
    "bwd_packets":     {"totalbackwardpackets", "totbwdpkts"},
    "fwd_bytes":       {"totallengthoffwdpackets", "totlenfwdpkts"},
    "bwd_bytes":       {"totallengthofbwdpackets", "totlenbwdpkts"},
    "label":           {"label"},
}

# fields that MUST map or the file is not usable CIC flow data
_REQUIRED = ["src_ip", "src_port", "dst_ip", "dst_port", "protocol",
             "timestamp_start", "duration", "fwd_packets", "bwd_packets"]


def probe_schema(columns) -> dict:
    """Map canonical fields to actual column names. Raises SchemaError if a
    required field cannot be found, naming what was expected and what was seen
    — never returns a partial map that would yield null columns downstream."""
    stripped = [str(c).strip() for c in columns]
    by_norm = {}
    for c in stripped:
        by_norm.setdefault(_norm(c), c)      # first spelling wins
    mapping, missing = {}, []
    for field, aliases in _ALIASES.items():
        hit = next((by_norm[a] for a in aliases if a in by_norm), None)
        if hit is not None:
            mapping[field] = hit
        elif field in _REQUIRED:
            missing.append(field)
    if missing:
        raise SchemaError(
            "unrecognised CIC-IDS2017 schema: could not map required field(s) "
            f"{missing}. Saw columns {stripped[:12]}"
            f"{'…' if len(stripped) > 12 else ''}. "
            "This loader expects CICFlowMeter GeneratedLabelledFlows headers "
            "(e.g. 'Source IP', 'Destination Port', 'Flow Duration').")
    return mapping


def _read_csv(path: str, nrows: int = None) -> pd.DataFrame:
    try:
        raw = pd.read_csv(path, low_memory=False, nrows=nrows)
    except UnicodeDecodeError:                      # Thursday/Friday files
        raw = pd.read_csv(path, low_memory=False, nrows=nrows, encoding="latin-1")
    raw.columns = raw.columns.str.strip()
    return raw


def load_dataframe(path: str, nrows: int = None):
    """Load a CIC CSV as (df_without_label, labels_or_None), schema-probed.
    This is what the Network Analyst's load_data delegates to, so the agent
    inherits the clear-error-on-bad-schema behaviour. Native column names are
    preserved for the existing NA tools; the canonical view is load_slice()."""
    raw = _read_csv(path, nrows=nrows)
    probe_schema(raw.columns)                       # raises on a bad header
    raw = raw.replace([float("inf"), -float("inf")], pd.NA)
    labels = None
    if "Label" in raw.columns:
        labels = raw["Label"]
        raw = raw.drop(columns=["Label"])
    return raw, labels


class CicIds2017Loader(Loader):
    dataset_id = "cic_ids2017"

    def __init__(self, root: str = None):
        # default to the repo's committed dataset location
        self.root = root or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "GeneratedLabelledFlows", "TrafficLabelling")
        self._labels_cache = {}     # flow_id -> label, populated by load_slice

    # -- slice spec resolution ------------------------------------------------
    def _resolve_path(self, slice_spec) -> tuple:
        """slice_spec may be a full path, a filename, a day key, or a dict
        {"path"/"day":..., "limit": N}. Returns (path, limit)."""
        limit = None
        if isinstance(slice_spec, dict):
            limit = slice_spec.get("limit")
            slice_spec = slice_spec.get("path") or slice_spec.get("day")
        if slice_spec and os.path.isabs(str(slice_spec)) and os.path.exists(slice_spec):
            return slice_spec, limit
        # match a file in root by case-insensitive substring (e.g. "Monday")
        if os.path.isdir(self.root):
            for fn in sorted(os.listdir(self.root)):
                if str(slice_spec).lower() in fn.lower():
                    return os.path.join(self.root, fn), limit
        if slice_spec and os.path.exists(str(slice_spec)):
            return str(slice_spec), limit
        raise FileNotFoundError(f"no CIC-IDS2017 file matching {slice_spec!r} "
                                f"in {self.root}")

    def load_slice(self, slice_spec) -> Iterable[CanonicalFlow]:
        path, limit = self._resolve_path(slice_spec)
        raw = _read_csv(path, nrows=limit)
        m = probe_schema(raw.columns)
        has_label = "label" in m
        self._labels_cache = {}
        for i, row in raw.iterrows():
            fid = str(row[m["flow_id"]]) if "flow_id" in m else f"{os.path.basename(path)}:{i}"
            if has_label:
                self._labels_cache[fid] = str(row[m["label"]])
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
                extra={})

    def label_vocabulary(self) -> list:
        return list(LABEL_VOCABULARY)

    # -- SIDECAR ONLY ---------------------------------------------------------
    def ground_truth(self, flow_id) -> Optional[str]:
        return self._labels_cache.get(str(flow_id))

    def phase_ground_truth(self, flow_id) -> Optional[str]:
        return None      # CIC-IDS2017 labels attack types, not phases
