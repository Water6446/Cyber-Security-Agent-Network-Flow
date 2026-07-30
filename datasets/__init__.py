"""Dataset adapter layer (M4).

Downstream code reads canonical fields only; loaders normalise each dataset to
CanonicalFlow. ground_truth()/phase_ground_truth() are quarantined to the eval
sidecar (enforced by tests/test_quarantine.py).
"""

from .canonical import CanonicalFlow, CANONICAL_FIELDS, REQUIRED_FIELDS
from .registry import DATASETS, get_loader

__all__ = ["CanonicalFlow", "CANONICAL_FIELDS", "REQUIRED_FIELDS",
           "DATASETS", "get_loader"]
