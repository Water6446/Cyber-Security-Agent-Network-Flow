"""
M4 tests — dataset adapter layer: canonical normalisation, mandatory schema
probing, registry, and the sidecar-only ground-truth methods.
"""
import os

import pytest

import datasets
from datasets import canonical
from datasets.cic_ids2017 import (CicIds2017Loader, SchemaError, probe_schema,
                                  load_dataframe, LABEL_VOCABULARY)
from environment import validator as V

CIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "GeneratedLabelledFlows", "TrafficLabelling")
CIC_FILES = ([os.path.join(CIC_DIR, f) for f in sorted(os.listdir(CIC_DIR))
              if f.endswith(".csv")] if os.path.isdir(CIC_DIR) else [])


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
def test_registry_has_cic_and_dapt():
    assert "cic_ids2017" in datasets.DATASETS
    assert "dapt2020" in datasets.DATASETS            # registered lazily (M5)


def test_get_loader_unknown_raises():
    with pytest.raises(KeyError):
        datasets.get_loader("nope")


# ---------------------------------------------------------------------------
# Canonical normalisation — every committed CIC day maps and populates fields
# ---------------------------------------------------------------------------
@pytest.mark.skipif(not CIC_FILES, reason="CIC dataset not present")
@pytest.mark.parametrize("path", CIC_FILES, ids=lambda p: os.path.basename(p)[:16])
def test_every_cic_file_loads_into_canonical(path):
    loader = CicIds2017Loader()
    flows = list(loader.load_slice({"path": path, "limit": 25}))
    assert flows, f"no flows from {path}"
    f0 = flows[0]
    assert isinstance(f0, canonical.CanonicalFlow)
    for field in canonical.REQUIRED_FIELDS:
        assert getattr(f0, field) is not None, f"{field} null in {os.path.basename(path)}"


@pytest.mark.skipif(not CIC_FILES, reason="CIC dataset not present")
def test_phase_ground_truth_none_for_cic():
    loader = CicIds2017Loader()
    list(loader.load_slice({"path": CIC_FILES[0], "limit": 5}))
    # CIC labels attack types, not phases
    assert loader.phase_ground_truth("anything") is None


@pytest.mark.skipif(not CIC_FILES, reason="CIC dataset not present")
def test_ground_truth_is_available_via_loader():
    loader = CicIds2017Loader()
    flows = list(loader.load_slice({"path": CIC_FILES[0], "limit": 25}))
    label = loader.ground_truth(flows[0].flow_id)
    assert isinstance(label, str) and label


# ---------------------------------------------------------------------------
# Schema probing — clear error on a mangled header, not silent nulls
# ---------------------------------------------------------------------------
def test_probe_raises_on_mangled_header():
    with pytest.raises(SchemaError) as ei:
        probe_schema(["foo", "bar", "baz"])
    assert "unrecognised" in str(ei.value).lower()


def test_probe_handles_spelling_variants():
    m = probe_schema([" Source IP", "Dst Port", "FlowID", "Protocol",
                      "Source Port", "Destination IP", "Timestamp",
                      "Flow Duration", "Total Fwd Packets", "Total Backward Packets"])
    assert m["dst_port"] == "Dst Port" and m["flow_id"] == "FlowID"


def test_load_dataframe_raises_on_mangled_csv(tmp_path):
    p = tmp_path / "bad.csv"
    p.write_text("foo,bar,baz\n1,2,3\n")
    with pytest.raises(SchemaError):
        load_dataframe(str(p))


def test_network_analyst_load_data_raises_on_bad_schema(tmp_path):
    import network_analyst as na
    p = tmp_path / "bad.csv"
    p.write_text("foo,bar,baz\n1,2,3\n")
    with pytest.raises(SchemaError):
        na.load_data(str(p))


# ---------------------------------------------------------------------------
# Label vocabulary feeds the validator and stays consistent with it
# ---------------------------------------------------------------------------
def test_label_vocabulary_matches_validator_constant():
    # every attack family the validator hardcodes must be in the loader's vocab
    loader_vocab = set(CicIds2017Loader().label_vocabulary())
    for lbl in V.CIC_IDS2017_LABELS:
        assert lbl in loader_vocab, lbl
