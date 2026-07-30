"""
M2 tests — Kill Chain agent: crosswalk, divergence, grounding, temporal
ordering, retry evaluation, and the one-re-prompt-then-hard-error vocab rule.

The model-driven paths are exercised with a scripted fake client so no LLM is
needed.
"""
import json

import pytest

import agent_core
import kill_chain as kc
import threat_intel as ti
from environment import validator as V


# ---------------------------------------------------------------------------
# Scripted fake client (mimics the OpenAI chat-completions surface _chat uses)
# ---------------------------------------------------------------------------
class _Msg:
    def __init__(self, content, tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls or []


class _Usage:
    completion_tokens = 0


class _Resp:
    def __init__(self, content):
        self.choices = [type("C", (), {"message": _Msg(content)})()]
        self.usage = _Usage()


class FakeClient:
    """Returns scripted assistant contents in order, never any tool calls."""
    def __init__(self, scripted):
        self.scripted, self.n = list(scripted), 0
        outer = self

        class Completions:
            def create(self, **kw):
                content = outer.scripted[outer.n]
                outer.n += 1
                return _Resp(content)

        self.chat = type("Chat", (), {"completions": Completions()})()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
FINDINGS = {"findings": [
    {"title": "SYN scan", "severity": "High", "source_ips": ["172.16.0.1"],
     "ports": [22, 80], "first_seen": "7/7/2017 9:00", "flow_count": 5000},
    {"title": "SSH brute force", "severity": "High", "source_ips": ["172.16.0.1"],
     "ports": [22], "first_seen": "7/7/2017 9:20", "flow_count": 2000},
    {"title": "Beacon", "severity": "Medium", "source_ips": ["10.0.0.9"],
     "ports": [443], "first_seen": "7/7/2017 10:00", "flow_count": 40},
]}
MAPPINGS = {"mappings": [
    {"finding_id": "F1", "technique_id": "T1046", "technique_name": "Network Service Discovery",
     "tactic": "Discovery", "confidence": "high"},
    {"finding_id": "F2", "technique_id": "T1110", "technique_name": "Brute Force",
     "tactic": "Credential Access", "confidence": "high"},
    {"finding_id": "F3", "technique_id": "T1071", "technique_name": "Application Layer Protocol",
     "tactic": "Command and Control", "confidence": "medium"},
]}


def _valid_model_output():
    return {"phase_assignments": [
        {"phase": "Reconnaissance", "finding_ids": ["F1"], "technique_ids": ["T1046"],
         "justification": "scan", "confidence": "high"},
        {"phase": "Actions on Objectives", "finding_ids": ["F2"], "technique_ids": ["T1110"],
         "justification": "creds", "confidence": "high"}],
        "narrative": "recon then creds",
        "gaps": [], "unassigned_finding_ids": []}


def _report(structured):
    return "## Kill chain\nprose here\n\n```json\n" + json.dumps(structured) + "\n```\n"


@pytest.fixture(autouse=True)
def _ctx():
    ti.load_attack_data()
    kc._load_run_context(MAPPINGS, FINDINGS)


# ---------------------------------------------------------------------------
# Crosswalk
# ---------------------------------------------------------------------------
def test_crosswalk_covers_every_live_tactic():
    """Guard against a future ATT&CK version adding a tactic the crosswalk
    doesn't know — which would silently drop it from derivation."""
    for t in ti.TACTICS:
        assert t["name"] in kc.TACTIC_TO_PHASE, f"tactic {t['name']} missing from crosswalk"


def test_defense_evasion_successors_excluded():
    assert kc.TACTIC_TO_PHASE["Stealth"] is None
    assert kc.TACTIC_TO_PHASE["Defense Impairment"] is None


def test_derive_expected_phases_from_stix():
    # technique->tactic comes from STIX, tactic->phase from the crosswalk
    assert kc.derive_expected_phases(MAPPINGS) == {
        "Reconnaissance", "Actions on Objectives", "Command and Control"}


def test_technique_to_tactic_not_hardcoded():
    assert kc.tactics_for_technique("T1046") == ["Discovery"]


# ---------------------------------------------------------------------------
# Divergence
# ---------------------------------------------------------------------------
def test_phase_divergence_flags_both_directions():
    model_out = {"phase_assignments": [
        {"phase": "Reconnaissance", "finding_ids": ["F1"], "technique_ids": ["T1046"]},
        {"phase": "Delivery", "finding_ids": ["F3"], "technique_ids": ["T1071"]}]}
    d = kc.compute_phase_divergence(model_out, MAPPINGS)
    assert "Delivery" in d["model_only"]            # model asserted, crosswalk didn't
    assert "Command and Control" in d["crosswalk_only"]  # crosswalk implied, model didn't


# ---------------------------------------------------------------------------
# Grounding
# ---------------------------------------------------------------------------
def test_grounding_flags_fake_technique():
    out = _valid_model_output()
    out["phase_assignments"][0]["technique_ids"].append("T9999")
    g = kc.verify_kill_chain_grounding(out, MAPPINGS, FINDINGS)
    assert "T9999" in g["ungrounded_technique_ids"]


def test_grounding_flags_unknown_finding_id():
    out = _valid_model_output()
    out["unassigned_finding_ids"] = ["F99"]
    g = kc.verify_kill_chain_grounding(out, MAPPINGS, FINDINGS)
    assert "F99" in g["unknown_finding_ids"]


def test_grounding_clean_output_has_no_violations():
    g = kc.verify_kill_chain_grounding(_valid_model_output(), MAPPINGS, FINDINGS)
    assert g == {"ungrounded_technique_ids": [], "unknown_finding_ids": []}


# ---------------------------------------------------------------------------
# Temporal ordering (code, not model)
# ---------------------------------------------------------------------------
def test_temporal_ordering_orders_and_gaps():
    out = json.loads(kc.get_temporal_ordering(["F3", "F1", "F2"]))
    seq = [r["finding_id"] for r in out["ordering"]]
    assert seq == ["F1", "F2", "F3"]               # sorted by first_seen
    assert out["ordering"][0]["gap_seconds_from_previous"] is None
    assert out["ordering"][1]["gap_seconds_from_previous"] == 1200.0


def test_temporal_ordering_reports_undetermined():
    kc._load_run_context(MAPPINGS, {"findings": [{"title": "no ts", "severity": "Low"}]})
    out = json.loads(kc.get_temporal_ordering(["F1"]))
    assert out["ordering"] == []
    assert out["undetermined"][0]["finding_id"] == "F1"
    kc._load_run_context(MAPPINGS, FINDINGS)       # restore


def test_get_finding_detail_withholds_timestamps():
    detail = json.loads(kc.get_finding_detail("F1"))
    assert "first_seen" not in detail and "timestamp" not in detail
    assert detail["finding_id"] == "F1"


# ---------------------------------------------------------------------------
# Retry evaluation (code-decided)
# ---------------------------------------------------------------------------
def test_retry_fires_on_mid_campaign_gap():
    out = _valid_model_output()
    out["gaps"] = [{"missing_phase": "Exploitation", "reasoning": "none seen"}]
    # Recon assigned (before) + Actions on Objectives assigned (after) => mid-chain
    dec = kc.evaluate_retry(out, FINDINGS, {"ungrounded_technique_ids": []})
    assert dec["retry"] and dec["reason"] == "phase_gap"


def test_gap_bookend_does_not_fire():
    out = {"phase_assignments": [
        {"phase": "Exploitation", "finding_ids": ["F1"]},
        {"phase": "Actions on Objectives", "finding_ids": ["F2"]}],
        "gaps": [{"missing_phase": "Reconnaissance", "reasoning": "before capture"}],
        "unassigned_finding_ids": []}
    dec = kc.evaluate_retry(out, FINDINGS, {"ungrounded_technique_ids": []})
    assert dec["conditions"]["phase_gap"] is False


def test_retry_fires_on_unassigned_high_severity():
    out = _valid_model_output()
    out["unassigned_finding_ids"] = ["F1"]         # F1 is High severity
    dec = kc.evaluate_retry(out, FINDINGS, {"ungrounded_technique_ids": []})
    assert dec["retry"] and dec["reason"] == "unassigned_high_severity"
    assert "F1" in dec["target_finding_ids"]


def test_retry_fires_on_ungrounded_technique():
    dec = kc.evaluate_retry(_valid_model_output(), FINDINGS,
                            {"ungrounded_technique_ids": ["T9999"]})
    assert dec["retry"] and dec["reason"] == "ungrounded_technique"


def test_no_retry_records_negative_conditions():
    dec = kc.evaluate_retry(_valid_model_output(), FINDINGS,
                            {"ungrounded_technique_ids": []})
    assert dec["retry"] is False
    assert dec["conditions"] == {"phase_gap": False,
                                 "unassigned_high_severity": False,
                                 "ungrounded_technique": False}


# ---------------------------------------------------------------------------
# Phase-vocabulary enforcement — exactly one re-prompt, then hard error
# ---------------------------------------------------------------------------
def test_vocab_ok_no_reprompt():
    client = FakeClient([])                          # must not be called
    out = kc.enforce_phase_vocabulary(client, "m", _valid_model_output())
    assert kc.invalid_phases(out) == []
    assert client.n == 0


def test_vocab_one_reprompt_then_ok():
    bad = _valid_model_output()
    bad["phase_assignments"][0]["phase"] = "Recon"   # out of vocabulary
    fixed = _valid_model_output()
    client = FakeClient([json.dumps(fixed)])          # the single correction call
    out = kc.enforce_phase_vocabulary(client, "m", bad)
    assert kc.invalid_phases(out) == []
    assert client.n == 1                              # exactly one re-prompt


def test_vocab_still_bad_after_one_reprompt_raises():
    bad = _valid_model_output()
    bad["phase_assignments"][0]["phase"] = "Recon"
    still_bad = _valid_model_output()
    still_bad["phase_assignments"][0]["phase"] = "ReconStage"
    client = FakeClient([json.dumps(still_bad)])
    with pytest.raises(kc.KillChainError):
        kc.enforce_phase_vocabulary(client, "m", bad)
    assert client.n == 1                              # only one re-prompt attempted


# ---------------------------------------------------------------------------
# analyze() end-to-end against a fixture Threat Intel JSON (no LLM)
# ---------------------------------------------------------------------------
def test_analyze_runs_standalone_on_fixture():
    client = FakeClient([_report(_valid_model_output())])
    md, structured, extras = kc.analyze(client, "m", MAPPINGS, FINDINGS)
    assert structured is not None
    assert "phase_divergence" in structured and "grounding" in structured
    assert extras["grounding"]["ungrounded_technique_ids"] == []
    # divergence surfaces the crosswalk-only C2 the model didn't assign
    assert "Command and Control" in structured["phase_divergence"]["crosswalk_only"]


def test_analyze_injects_environment_when_profile_given():
    import environment as env
    client = FakeClient([_report(_valid_model_output())])
    prof = env.load_profile("enterprise_dmz")
    md, structured, extras = kc.analyze(client, "m", MAPPINGS, FINDINGS, profile=prof)
    assert extras["injection"] is not None
    assert "crown_jewels" in extras["injection"]["injected_sections"]


# ---------------------------------------------------------------------------
# Vocabulary is shared with the validator (no silent drift)
# ---------------------------------------------------------------------------
def test_phase_vocab_matches_validator():
    assert kc.PHASES == V.KILL_CHAIN_PHASES
