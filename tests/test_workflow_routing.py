"""
M3 tests — the two feedback edges are pure, code-decided, and capped at one.

Routers are module-level pure functions of state, so the retry/cap logic is
testable with no model and no compiled graph. An adversarial state (retry
always wanted) proves the cap holds.
"""
import workflow as wf


# ---------------------------------------------------------------------------
# NA <-> TI edge (Week 3, now routing forward to kill_chain instead of END)
# ---------------------------------------------------------------------------
def test_ti_routes_to_na_followup_when_evidence_pending():
    state = {"evidence_requests": [{"finding_id": "F1"}], "followup_count": 0,
             "node_visits": 2}
    assert wf.route_after_threat_intel(state) == "network_analyst_followup"


def test_ti_routes_to_kill_chain_when_no_evidence():
    state = {"evidence_requests": [], "followup_count": 0, "node_visits": 2}
    assert wf.route_after_threat_intel(state) == "kill_chain"


def test_ti_na_followup_capped_at_one():
    # evidence still pending but a follow-up already happened -> forward, not loop
    state = {"evidence_requests": [{"finding_id": "F1"}], "followup_count": 1,
             "node_visits": 4}
    assert wf.route_after_threat_intel(state) == "kill_chain"


# ---------------------------------------------------------------------------
# KC <-> TI edge (Week 4)
# ---------------------------------------------------------------------------
def _retry(reason="phase_gap"):
    return {"retry": True, "reason": reason,
            "conditions": {"phase_gap": reason == "phase_gap",
                           "unassigned_high_severity": reason == "unassigned_high_severity",
                           "ungrounded_technique": reason == "ungrounded_technique"}}


def test_kc_routes_to_ti_followup_on_retry():
    state = {"kill_chain_retry_decision": _retry(), "kill_chain_retry_count": 0,
             "node_visits": 5}
    assert wf.route_after_kill_chain(state) == "threat_intel_kc_followup"


def test_kc_routes_to_report_when_no_retry():
    state = {"kill_chain_retry_decision": {"retry": False}, "kill_chain_retry_count": 0,
             "node_visits": 5}
    assert wf.route_after_kill_chain(state) == "report_writer"


def test_kc_retry_capped_at_one_even_if_still_wanted():
    # ADVERSARIAL: the model would loop forever; the cap forces exit.
    state = {"kill_chain_retry_decision": _retry(), "kill_chain_retry_count": 1,
             "node_visits": 7}
    assert wf.route_after_kill_chain(state) == "report_writer"


def test_each_trigger_reason_routes_to_followup_once():
    for reason in ("phase_gap", "unassigned_high_severity", "ungrounded_technique"):
        state = {"kill_chain_retry_decision": _retry(reason),
                 "kill_chain_retry_count": 0, "node_visits": 5}
        assert wf.route_after_kill_chain(state) == "threat_intel_kc_followup", reason
        # second pass: cap holds regardless of reason
        state["kill_chain_retry_count"] = 1
        assert wf.route_after_kill_chain(state) == "report_writer", reason


# ---------------------------------------------------------------------------
# Node-visit ceiling safety net
# ---------------------------------------------------------------------------
def test_ceiling_forces_forward_from_kill_chain():
    state = {"kill_chain_retry_decision": _retry(), "kill_chain_retry_count": 0,
             "node_visits": wf.NODE_VISIT_CEILING}
    assert wf.route_after_kill_chain(state) == "report_writer"


def test_ceiling_forces_forward_from_threat_intel():
    state = {"evidence_requests": [{"finding_id": "F1"}], "followup_count": 0,
             "node_visits": wf.NODE_VISIT_CEILING}
    assert wf.route_after_threat_intel(state) == "kill_chain"


# ---------------------------------------------------------------------------
# Graph compiles (smoke) and exposes both loops
# ---------------------------------------------------------------------------
def test_graph_compiles_and_has_both_loops():
    graph = wf.build_graph(client=None, model=None)
    mmd = graph.get_graph().draw_mermaid()
    assert "threat_intel_kc_followup" in mmd
    assert "network_analyst_followup" in mmd
    assert "report_writer" in mmd
    # forward edges into the two capped nodes exist
    assert "kill_chain" in mmd and "report_writer --> __end__" in mmd
