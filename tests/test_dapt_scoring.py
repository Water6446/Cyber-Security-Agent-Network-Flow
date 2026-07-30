"""
M5 tests — DAPT 2020 loader + kill-chain phase scoring.

The real DAPT dataset is not committed, so the loader is exercised against a
synthetic CICFlowMeter-v4 file (the schema the adapter must accept). Scoring is
pure and fully tested. Coherence / impossible-jump checks are verified to run
with NO phase ground truth (they must generalise to unlabelled data).
"""
import datasets
import eval_sidecar as ev
from datasets.dapt2020 import Dapt2020Loader
from environment import validator as V


DAPT_HEADER = ("Flow ID,Src IP,Src Port,Dst IP,Dst Port,Protocol,Timestamp,"
               "Flow Duration,Tot Fwd Pkts,Tot Bwd Pkts,TotLen Fwd Pkts,"
               "TotLen Bwd Pkts,Activity,Stage")


def _write_dapt(tmp_path):
    p = tmp_path / "dapt_day2.csv"
    p.write_text(
        DAPT_HEADER + "\n"
        "f1,10.0.0.9,4444,10.0.0.5,80,6,26/8/2019 10:00,120,5,2,300,100,Scanning,Reconnaissance\n"
        "f2,10.0.0.9,5555,8.8.8.8,443,6,26/8/2019 11:00,900,20,30,5000,9000,Exfil,Data Exfiltration\n"
        "f3,10.0.0.2,0,10.0.0.5,0,6,26/8/2019 09:00,50,1,1,60,60,Normal,Benign\n")
    return str(p)


# ---------------------------------------------------------------------------
# DAPT loader
# ---------------------------------------------------------------------------
def test_dapt_registered_in_registry():
    assert "dapt2020" in datasets.DATASETS


def test_dapt_loads_cicflowmeter_v4_into_canonical(tmp_path):
    loader = Dapt2020Loader(root=str(tmp_path))
    flows = list(loader.load_slice({"path": _write_dapt(tmp_path)}))
    assert len(flows) == 3
    assert flows[0].src_ip == "10.0.0.9" and int(flows[0].dst_port) == 80
    # labels must NOT leak into the agent-facing canonical flow
    assert "stage" not in flows[0].extra and "activity" not in flows[0].extra


def test_dapt_phase_and_activity_ground_truth_sidecar(tmp_path):
    loader = Dapt2020Loader(root=str(tmp_path))
    flows = list(loader.load_slice({"path": _write_dapt(tmp_path)}))
    assert loader.phase_ground_truth(flows[0].flow_id) == "Reconnaissance"
    assert loader.phase_ground_truth(flows[1].flow_id) == "Data Exfiltration"
    assert loader.ground_truth(flows[0].flow_id) == "Scanning"


def test_dapt_label_vocabulary_matches_validator():
    vocab = set(Dapt2020Loader().label_vocabulary())
    for lbl in ["Reconnaissance", "Foothold Establishment", "Lateral Movement",
                "Data Exfiltration"]:
        assert lbl in vocab and lbl in set(V.DAPT2020_LABELS)


# ---------------------------------------------------------------------------
# Crosswalk + three-bucket scoring
# ---------------------------------------------------------------------------
def test_stage_to_phase_primary_and_alternates():
    assert ev.stage_to_phase("Reconnaissance") == ("Reconnaissance", set())
    p, alt = ev.stage_to_phase("Foothold Establishment")
    assert p == "Exploitation" and alt == {"Delivery", "Installation"}
    assert ev.stage_to_phase("Benign") == (None, set())


def test_three_bucket_scoring():
    pairs = [
        ("Reconnaissance", "Reconnaissance"),          # primary
        ("Exploitation", "Foothold Establishment"),    # primary
        ("Delivery", "Foothold Establishment"),        # alternate
        ("Command and Control", "Foothold Establishment"),  # disagreement
        ("Actions on Objectives", "Data Exfiltration"),     # primary
        ("Reconnaissance", "Benign"),                  # benign/unmapped
    ]
    b = ev.score_phases(pairs)["buckets"]
    assert b == {"primary": 3, "alternate": 1, "disagreement": 1,
                 "benign_or_unmapped": 1}


def test_confusion_matrix_renders():
    scored = ev.score_phases([("Delivery", "Foothold Establishment")])
    txt = ev.confusion_matrix_text(scored["confusion"])
    assert "true\\pred" in txt


def test_never_reports_single_blended_number():
    # the scorer exposes buckets, not one accuracy figure
    result = ev.score_phases([("Reconnaissance", "Reconnaissance")])
    assert "buckets" in result and "accuracy" not in result


# ---------------------------------------------------------------------------
# Code-only checks — must run with NO phase ground truth
# ---------------------------------------------------------------------------
def test_impossible_jump_detected():
    assert ev.impossible_jumps(["Actions on Objectives", "Reconnaissance"])
    assert not ev.impossible_jumps(["Exploitation", "Actions on Objectives"])


def test_ordering_coherence():
    assert ev.ordering_coherence(["Reconnaissance", "Exploitation",
                                  "Actions on Objectives"])["coherent"]
    bad = ev.ordering_coherence(["Exploitation", "Reconnaissance"])
    assert not bad["coherent"] and bad["inversions"]


def test_evaluate_phases_runs_without_ground_truth():
    kill_chain = {"phase_assignments": [
        {"phase": "Reconnaissance", "finding_ids": ["F1"]},
        {"phase": "Actions on Objectives", "finding_ids": ["F2"]}],
        "phase_divergence": {"model_only": ["Delivery"], "crosswalk_only": []}}
    findings = {"findings": [
        {"title": "scan", "first_seen": "7/7/2017 9:00"},
        {"title": "exfil", "first_seen": "7/7/2017 10:00"}]}
    # df/phase_labels None => phase_ground_truth is effectively None
    result = ev.evaluate_phases(kill_chain, findings)
    assert "coherence" in result and "impossible_jumps" in result
    assert "divergence" in result
    assert "phase_agreement" not in result           # no labels -> skipped
    # F1 Recon then F2 Actions on Objectives is temporally coherent
    assert result["coherence"]["coherent"]
    # Actions on Objectives with no Delivery/Exploitation -> impossible jump
    assert result["impossible_jumps"]


def test_evaluate_phases_with_stage_labels_scores():
    kill_chain = {"phase_assignments": [
        {"phase": "Reconnaissance", "finding_ids": ["F1"]},
        {"phase": "Actions on Objectives", "finding_ids": ["F2"]}]}
    findings = {"findings": [{"title": "scan"}, {"title": "exfil"}]}
    result = ev.evaluate_phases(kill_chain, findings,
                                true_stages={"F1": "Reconnaissance",
                                             "F2": "Data Exfiltration"})
    assert result["phase_agreement"]["buckets"]["primary"] == 2
