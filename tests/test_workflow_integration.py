"""
M3 integration — a full four-agent run completes offline.

Drives the COMPILED graph with a scripted fake client (no LLM) and a tiny CSV,
proving state threads NA -> TI -> KC -> Report Writer, the manifest records the
node visits / retry decision / per-agent injection, and the happy path takes
exactly four agent nodes.
"""
import json

import pytest

import threat_intel as ti
import workflow as wf
from run_manifest import RunManifest


class _Msg:
    def __init__(self, content):
        self.content, self.tool_calls = content, []


class _Resp:
    def __init__(self, content):
        self.choices = [type("C", (), {"message": _Msg(content)})()]
        self.usage = type("U", (), {"completion_tokens": 0})()


class FakeClient:
    def __init__(self, scripted):
        self.scripted, self.n = list(scripted), 0
        outer = self

        class Completions:
            def create(self, **kw):
                content = outer.scripted[outer.n]
                outer.n += 1
                return _Resp(content)

        self.chat = type("Chat", (), {"completions": Completions()})()


def _fenced(obj):
    return "## report\nprose\n\n```json\n" + json.dumps(obj) + "\n```\n"


NA = _fenced({"findings": [
    {"title": "SYN scan", "severity": "High", "source_ips": ["172.16.0.1"],
     "destination_ips": ["10.0.0.5"], "ports": [22, 80], "flow_count": 100,
     "first_seen": "7/7/2017 9:00", "last_seen": "7/7/2017 9:05",
     "evidence_summary": "many ports from one host"}]})
TI = _fenced({"mappings": [
    {"finding_id": "F1", "technique_id": "T1046",
     "technique_name": "Network Service Discovery", "tactic": "Discovery",
     "confidence": "high", "reasoning": "port scan"}],
    "evidence_requests": []})
KC = _fenced({"phase_assignments": [
    {"phase": "Reconnaissance", "finding_ids": ["F1"], "technique_ids": ["T1046"],
     "justification": "scan across ports", "confidence": "high"}],
    "narrative": "reconnaissance only", "gaps": [], "unassigned_finding_ids": []})
RW = "## Incident report\nA reconnaissance scan (T1046) was observed.\n"


@pytest.fixture
def tiny_csv(tmp_path):
    # full enough to satisfy the M4 schema probe that NA.load_data now runs
    p = tmp_path / "tiny.csv"
    p.write_text("Source IP,Source Port,Destination IP,Destination Port,Protocol,"
                 "Timestamp,Flow Duration,Total Fwd Packets,Total Backward Packets,"
                 "Label\n"
                 "172.16.0.1,44,10.0.0.5,22,6,7/7/2017 9:00,100,5,2,BENIGN\n"
                 "172.16.0.1,55,10.0.0.5,80,6,7/7/2017 9:01,200,6,1,PortScan\n")
    return str(p)


def test_full_four_agent_run_completes(tiny_csv):
    ti.load_attack_data()
    client = FakeClient([NA, TI, KC, RW])
    manifest = RunManifest(provider="fake", model="fake-model")
    manifest.set_dataset("cic_ids2017", "tiny")
    graph = wf.build_graph(client, "fake-model", manifest=manifest)

    state = graph.invoke({
        "csv_path": tiny_csv,
        "findings_md": None, "findings": None, "mappings": None, "mappings_md": None,
        "evidence_requests": [], "followup_count": 0,
        "kill_chain": None, "kill_chain_md": None,
        "kill_chain_retry_count": 0, "kill_chain_retry_decision": None,
        "report": None, "node_visits": 0,
    }, config={"recursion_limit": wf.NODE_VISIT_CEILING + 3})

    # all four agents produced output
    assert state["findings"]["findings"][0]["title"] == "SYN scan"
    assert state["mappings"]["mappings"][0]["technique_id"] == "T1046"
    assert state["kill_chain"]["phase_assignments"][0]["phase"] == "Reconnaissance"
    assert "T1046" in state["report"]

    # happy path visited exactly the four agent nodes, in order
    assert manifest.data["node_visits"] == [
        "network_analyst", "threat_intel", "kill_chain", "report_writer"]
    assert client.n == 4                      # one model call per agent

    # the retry branch was considered and declined (logged, incl. negative)
    decisions = manifest.data["retry_decisions"]
    assert len(decisions) == 1 and decisions[0]["retry"] is False
    assert state["kill_chain_retry_count"] == 0

    # divergence was computed in code and attached
    assert "phase_divergence" in state["kill_chain"]


def test_run_records_per_agent_injection_with_profile(tiny_csv):
    import environment as env
    ti.load_attack_data()
    client = FakeClient([NA, TI, KC, RW])
    manifest = RunManifest(provider="fake", model="fake-model")
    profile = env.load_profile("enterprise_dmz")
    graph = wf.build_graph(client, "fake-model", profile=profile, manifest=manifest)
    graph.invoke({
        "csv_path": tiny_csv,
        "findings_md": None, "findings": None, "mappings": None, "mappings_md": None,
        "evidence_requests": [], "followup_count": 0,
        "kill_chain": None, "kill_chain_md": None,
        "kill_chain_retry_count": 0, "kill_chain_retry_decision": None,
        "report": None, "node_visits": 0,
    }, config={"recursion_limit": wf.NODE_VISIT_CEILING + 3})

    injections = {e["agent"]: e for e in manifest.data["agent_injection"]}
    assert set(injections) == {"network_analyst", "threat_intel", "kill_chain",
                               "report_writer"}
    # Threat Intel invariance: empty allowlist -> empty rendered text
    assert injections["threat_intel"]["injected_sections"] == []
    assert injections["threat_intel"]["rendered_chars"] == 0
    # Kill Chain got crown_jewels
    assert "crown_jewels" in injections["kill_chain"]["injected_sections"]


# adversarial: Kill Chain references an ungrounded technique on pass 1, forcing
# the KC->TI retry. It must fire EXACTLY once, then the cap forces exit.
KC_BAD = _fenced({"phase_assignments": [
    {"phase": "Reconnaissance", "finding_ids": ["F1"],
     "technique_ids": ["T1046", "T9999"], "justification": "scan",
     "confidence": "high"}],
    "narrative": "recon", "gaps": [], "unassigned_finding_ids": []})
TI_FOLLOWUP = _fenced({"mappings": [
    {"finding_id": "F1", "technique_id": "T1046",
     "technique_name": "Network Service Discovery", "tactic": "Discovery",
     "confidence": "high", "reasoning": "no further mapping — declining"}],
    "evidence_requests": []})


def test_kill_chain_retry_fires_exactly_once(tiny_csv):
    ti.load_attack_data()
    client = FakeClient([NA, TI, KC_BAD, TI_FOLLOWUP, KC, RW])
    manifest = RunManifest(provider="fake", model="fake-model")
    graph = wf.build_graph(client, "fake-model", manifest=manifest)
    state = graph.invoke({
        "csv_path": tiny_csv,
        "findings_md": None, "findings": None, "mappings": None, "mappings_md": None,
        "evidence_requests": [], "followup_count": 0,
        "kill_chain": None, "kill_chain_md": None,
        "kill_chain_retry_count": 0, "kill_chain_retry_decision": None,
        "report": None, "node_visits": 0,
    }, config={"recursion_limit": wf.NODE_VISIT_CEILING + 3})

    visits = manifest.data["node_visits"]
    assert visits == ["network_analyst", "threat_intel", "kill_chain",
                      "threat_intel_kc_followup", "kill_chain", "report_writer"]
    assert visits.count("threat_intel_kc_followup") == 1     # fired exactly once
    assert state["kill_chain_retry_count"] == 1              # cap respected
    # first decision retried (ungrounded), the run still finished at the writer
    assert manifest.data["retry_decisions"][0]["retry"] is True
    assert manifest.data["retry_decisions"][0]["reason"] == "ungrounded_technique"
    assert "T1046" in state["report"]
