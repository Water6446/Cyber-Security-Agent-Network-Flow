"""
Loader interface (M4)
=====================
Every dataset loader exposes the same four methods. Two of them —
ground_truth() and phase_ground_truth() — return LABELS and are therefore
QUARANTINED: they may be imported and called ONLY from eval_sidecar.py. A test
(tests/test_quarantine.py) greps the agent modules and fails if either symbol
appears there, so the quarantine is enforced mechanically, not just intended.
"""

from __future__ import annotations

from typing import Iterable, Optional


class Loader:
    dataset_id: str = "base"

    # -- agent-facing ---------------------------------------------------------
    def load_slice(self, slice_spec) -> Iterable:
        """Yield CanonicalFlow objects for the requested slice. slice_spec is
        loader-defined (a path, a day key, or a dict with a row limit)."""
        raise NotImplementedError

    def label_vocabulary(self) -> list:
        """The dataset's label values — feeds the environment validator so it
        can reject a profile that names an attack class (dataset-aware
        rejection). This is metadata ABOUT the labels, not the labels of any
        specific flow, so it is safe for the validator to hold."""
        raise NotImplementedError

    # -- sidecar-only (QUARANTINED) ------------------------------------------
    def ground_truth(self, flow_id) -> Optional[str]:
        """The true label for one flow. SIDECAR ONLY — never call from an
        agent module."""
        raise NotImplementedError

    def phase_ground_truth(self, flow_id) -> Optional[str]:
        """The true kill-chain/APT stage for one flow, or None if the dataset
        has no phase labels. SIDECAR ONLY."""
        raise NotImplementedError
