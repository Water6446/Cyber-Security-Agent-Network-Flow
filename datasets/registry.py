"""
Dataset registry (M4)
=====================
DATASETS maps a dataset_id to its Loader class. Adding a dataset is a one-line
registration here plus a loader module — the adapter layer's whole purpose.
"""

from __future__ import annotations

from .cic_ids2017 import CicIds2017Loader

DATASETS = {CicIds2017Loader.dataset_id: CicIds2017Loader}

# DAPT 2020 is registered lazily so importing the registry never requires the
# DAPT module to import cleanly before it is finished (M5).
try:
    from .dapt2020 import Dapt2020Loader
    DATASETS[Dapt2020Loader.dataset_id] = Dapt2020Loader
except Exception:                                   # pragma: no cover
    pass


def get_loader(dataset_id: str, **kwargs):
    if dataset_id not in DATASETS:
        raise KeyError(f"unknown dataset {dataset_id!r}; known: {sorted(DATASETS)}")
    return DATASETS[dataset_id](**kwargs)
