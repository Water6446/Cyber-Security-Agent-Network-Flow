"""
Canonical flow schema (M4)
==========================
The internal flow shape EVERY loader normalises to. Everything downstream is
meant to read canonical fields; `extra` carries dataset-specific columns for
tools that want them, so no downstream code needs to know which dataset it is
looking at.

Keeping this schema tiny and explicit is deliberate: a new dataset only has to
answer "which of your columns is src_ip?" rather than reshape the pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict


# The canonical fields, in order. A loader that cannot fill a NON-optional one
# from its source schema must raise (see datasets.cic_ids2017.SchemaError),
# rather than silently produce nulls.
CANONICAL_FIELDS = [
    "flow_id", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
    "timestamp_start", "timestamp_end", "duration",
    "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes",
    "flags_summary", "extra",
]

# Fields a loader MUST be able to populate for the pipeline to make sense.
# timestamp_end and flags_summary are allowed to be None/"" (not every dataset
# has them); extra defaults to {}.
REQUIRED_FIELDS = [
    "flow_id", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
    "timestamp_start", "duration", "fwd_packets", "bwd_packets",
]


@dataclass
class CanonicalFlow:
    flow_id: str
    src_ip: str
    src_port: object
    dst_ip: str
    dst_port: object
    protocol: object
    timestamp_start: object
    timestamp_end: object = None
    duration: object = None
    fwd_packets: object = None
    bwd_packets: object = None
    fwd_bytes: object = None
    bwd_bytes: object = None
    flags_summary: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)
