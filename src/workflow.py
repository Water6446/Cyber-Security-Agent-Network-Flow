"""
LangGraph orchestration — Week 4 (M3)
=====================================
Deterministic workflow BETWEEN agents, agentic tool-calling loops WITHIN
agents. The agent order never varies, so there is no supervisor LLM — routing
is code. The dynamic elements are TWO capped feedback edges, each firing at
most once:

    Network Analyst  ⇄  Threat Intelligence  ⇄  Kill Chain  →  Report Writer
          (≤1 retry)              (≤1 retry)

  - Threat Intel → Network Analyst : if TI needs more evidence (Week 3).
  - Kill Chain  → Threat Intelligence : if the kill-chain view has a
    mid-campaign gap, an unassigned high-severity finding, or an ungrounded
    technique (Week 4). The trigger is evaluated in CODE (kill_chain.evaluate_
    retry), never by asking the model whether it wants a retry.

Every routing decision — including the "no retry needed" case — is logged, and
recorded in the run manifest, so the transcript shows the branch was
considered (constraint #6, auditability). An absolute node-visit ceiling backs
the per-loop caps as a safety net.

    python src/workflow.py --csv <day>.csv [--environment enterprise_dmz] \\
        [--provider claude] [--plan]
    python src/workflow.py --diagram-only      # no CSV / API key needed
"""

import argparse
import contextlib
import io
import os
import sys
from typing import Optional, TypedDict

from langgraph.graph import StateGraph, START, END

import agent_core
import eval_sidecar
import kill_chain as kc
import network_analyst as na
import report_writer as rw
import threat_intel as ti
from run_manifest import RunManifest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    import environment as env
except Exception:                       # pragma: no cover
    env = None


class InvestigationState(TypedDict):
    csv_path: str
    findings_md: Optional[str]
    findings: Optional[dict]
    mappings: Optional[dict]
    mappings_md: Optional[str]
    evidence_requests: list             # TI -> NA feedback payload
    followup_count: int                 # NA<->TI cap (max 1)
    kill_chain: Optional[dict]
    kill_chain_md: Optional[str]
    kill_chain_retry_count: int         # KC<->TI cap (max 1)
    kill_chain_retry_decision: Optional[dict]
    report: Optional[str]
    node_visits: int                    # safety-net ceiling counter


FOLLOWUP_MAX_TURNS = 4
# Worst legitimate path is 8 super-steps (NA, TI, NA-followup, TI, KC, TI-kc-
# followup, KC, RW). The ceiling is the safety net the handoff asks for; the
# per-loop counters are the real guarantee.
NODE_VISIT_CEILING = 12


# ---------------------------------------------------------------------------
# Routers — module-level and PURE (functions of state only), so the retry /
# cap logic is unit-testable without a model or a compiled graph.
# ---------------------------------------------------------------------------
def route_after_threat_intel(state: InvestigationState):
    if state.get("node_visits", 0) >= NODE_VISIT_CEILING:
        print("[graph] node-visit ceiling hit -> forcing kill_chain")
        return "kill_chain"
    if state.get("evidence_requests") and state.get("followup_count", 0) == 0:
        print("[graph] evidence requests pending -> one NA follow-up pass")
        return "network_analyst_followup"
    print("[graph] no NA follow-up (or cap reached) -> kill_chain")
    return "kill_chain"


def route_after_kill_chain(state: InvestigationState):
    if state.get("node_visits", 0) >= NODE_VISIT_CEILING:
        print("[graph] node-visit ceiling hit -> forcing report_writer")
        return "report_writer"
    dec = state.get("kill_chain_retry_decision") or {}
    if dec.get("retry") and state.get("kill_chain_retry_count", 0) == 0:
        print(f"[graph] kill-chain retry ({dec.get('reason')}) -> one TI follow-up pass")
        return "threat_intel_kc_followup"
    print("[graph] no kill-chain retry (or cap reached) -> report_writer")
    return "report_writer"


def build_graph(client, model, force_evidence_request: bool = False,
                plan_mode: bool = False, tool_feedback: bool = False,
                profile: dict = None, manifest: RunManifest = None):
    """Compile the four-agent investigation graph. Nodes close over the LLM
    client (so the exported diagram stays a pure function of the code), over
    the optional environment `profile` (per-agent injection, M1), and over the
    optional `manifest` (recording, constraint #5)."""

    def _inject(agent_name, base_prompt):
        if profile is None or env is None:
            return base_prompt, None
        return env.inject(base_prompt, profile, agent_name)

    na_prompt, na_inj = _inject("network_analyst", na.SYSTEM_PROMPT)
    ti_prompt, ti_inj = _inject("threat_intel", ti.SYSTEM_PROMPT)
    # Kill Chain and Report Writer inject internally (they take `profile`); we
    # compute their entries here only to record them in the manifest.
    if manifest and profile is not None and env is not None:
        for entry in (na_inj, ti_inj):
            manifest.record_agent_injection(entry)
        for agent_name, base in (("kill_chain", kc.SYSTEM_PROMPT),
                                 ("report_writer", rw.SYSTEM_PROMPT)):
            _, e = env.inject(base, profile, agent_name)
            manifest.record_agent_injection(e)

    def _visit(state, name):
        if manifest:
            manifest.record_node_visit(name)
        return state.get("node_visits", 0) + 1

    # -- nodes ---------------------------------------------------------------
    def node_network_analyst(state):
        print("\n[graph] entering network_analyst")
        visits = _visit(state, "network_analyst")
        na.load_data(state["csv_path"])
        raw = na.analyze(client, model, plan_mode=plan_mode,
                         tool_feedback=tool_feedback, system_prompt=na_prompt)
        findings, md = agent_core.extract_json_block(raw)
        if findings is None:
            print("[graph] WARNING: network analyst emitted no parseable JSON block")
            findings = {"findings": []}
        return {"findings": findings, "findings_md": md, "node_visits": visits}

    def node_threat_intel(state):
        print("\n[graph] entering threat_intel")
        visits = _visit(state, "threat_intel")
        md, mappings = ti.analyze(client, model, state["findings"],
                                  plan_mode=plan_mode, tool_feedback=tool_feedback,
                                  system_prompt=ti_prompt)
        if mappings is None:
            print("[graph] WARNING: threat intel emitted no parseable JSON block")
            mappings = {"mappings": [], "evidence_requests": []}
        requests = mappings.get("evidence_requests", []) or []
        if force_evidence_request and not requests and state["followup_count"] == 0:
            print("[graph] --force-evidence-request: injecting a synthetic request")
            requests = [{
                "finding_id": "F1",
                "question": "For each source IP named in the findings, how many "
                            "distinct destination ports did it contact, and which "
                            "single destination port received the most flows?",
                "suggested_tool_query": "count_by(filter_expr=\"`Source IP` == '<ip>'\", "
                                        "column='Destination Port')",
            }]
        return {"mappings": mappings, "mappings_md": md,
                "evidence_requests": requests, "node_visits": visits}

    def node_network_analyst_followup(state):
        print("\n[graph] entering network_analyst_followup")
        visits = _visit(state, "network_analyst_followup")
        questions = "\n".join(
            f"- ({r.get('finding_id', '?')}) {r.get('question', '')}"
            + (f"\n  suggested query: {r['suggested_tool_query']}"
               if r.get("suggested_tool_query") else "")
            for r in state["evidence_requests"])
        task = ("A threat-intelligence analyst needs more evidence about your "
                "earlier findings. Answer ONLY the following questions using "
                "your tools — no full findings report, no JSON block, just a "
                "short markdown answer per question with the numbers you "
                f"measured:\n{questions}")
        answers = na.analyze(client, model, task, max_turns=FOLLOWUP_MAX_TURNS,
                             plan_mode=plan_mode, system_prompt=na_prompt)
        findings = dict(state["findings"])
        findings["followup_answers"] = answers
        return {"findings": findings,
                "followup_count": state["followup_count"] + 1,
                "node_visits": visits}

    def node_kill_chain(state):
        print("\n[graph] entering kill_chain")
        visits = _visit(state, "kill_chain")
        md, structured, extras = kc.analyze(
            client, model, state["mappings"], state["findings"], profile=profile,
            plan_mode=plan_mode, tool_feedback=tool_feedback)
        if structured is None:
            structured = {"phase_assignments": [], "gaps": [],
                          "unassigned_finding_ids": [], "narrative": ""}
        grounding = extras.get("grounding", {}) or {}
        if manifest:
            manifest.record_grounding_violations(
                "kill_chain",
                grounding.get("ungrounded_technique_ids", [])
                + [f"finding:{f}" for f in grounding.get("unknown_finding_ids", [])])
        decision = kc.evaluate_retry(structured, state["findings"], grounding)
        decision_record = dict(decision)
        decision_record["pass"] = state.get("kill_chain_retry_count", 0)
        if manifest:
            manifest.record_retry_decision(decision_record)
        return {"kill_chain": structured, "kill_chain_md": md,
                "kill_chain_retry_decision": decision, "node_visits": visits}

    def node_threat_intel_kc_followup(state):
        print("\n[graph] entering threat_intel_kc_followup")
        visits = _visit(state, "threat_intel_kc_followup")
        dec = state.get("kill_chain_retry_decision") or {}
        md, new_mappings = ti.analyze(client, model, state["findings"],
                                      plan_mode=plan_mode, system_prompt=ti_prompt,
                                      kill_chain_request=dec)
        # The retry is ADDITIVE. TI re-derives from findings alone (it never
        # sees its prior mappings), so merge the new pass ONTO the prior set
        # rather than replacing it — a retry that returns fewer mappings must
        # never drop previously-grounded techniques. Union by (finding, tech).
        prior_list = state["mappings"].get("mappings", []) or []
        prior = len(prior_list)
        mappings = dict(state["mappings"])
        if new_mappings is not None:
            seen = {(str(m.get("finding_id")), str(m.get("technique_id")))
                    for m in prior_list}
            merged = list(prior_list)
            for m in new_mappings.get("mappings", []) or []:
                key = (str(m.get("finding_id")), str(m.get("technique_id")))
                if key not in seen:
                    seen.add(key)
                    merged.append(m)
            mappings["mappings"] = merged
            md = md or state.get("mappings_md")
        else:
            md = state.get("mappings_md")
        now = len(mappings.get("mappings", []))
        mappings["_kill_chain_followup"] = True
        outcome = "added_mappings" if now > prior else "declined_or_none"
        print(f"[graph] TI kill-chain follow-up: mappings {prior} -> {now} ({outcome})")
        if manifest:
            manifest.note(f"kill_chain retry outcome: {outcome} "
                          f"(mappings {prior}->{now})")
        return {"mappings": mappings, "mappings_md": md,
                "kill_chain_retry_count": state.get("kill_chain_retry_count", 0) + 1,
                "node_visits": visits}

    def node_report_writer(state):
        print("\n[graph] entering report_writer")
        visits = _visit(state, "report_writer")
        report, extras = rw.analyze(
            client, model, state["findings"], state["mappings"],
            state.get("kill_chain") or {}, profile=profile,
            plan_mode=plan_mode, tool_feedback=tool_feedback)
        if manifest:
            manifest.record_grounding_violations(
                "report_writer",
                extras.get("grounding", {}).get("ungrounded_technique_ids", []))
        return {"report": report, "node_visits": visits}

    g = StateGraph(InvestigationState)
    g.add_node("network_analyst", node_network_analyst)
    g.add_node("threat_intel", node_threat_intel)
    g.add_node("network_analyst_followup", node_network_analyst_followup)
    g.add_node("kill_chain", node_kill_chain)
    g.add_node("threat_intel_kc_followup", node_threat_intel_kc_followup)
    g.add_node("report_writer", node_report_writer)

    g.add_edge(START, "network_analyst")
    g.add_edge("network_analyst", "threat_intel")
    g.add_conditional_edges("threat_intel", route_after_threat_intel,
                            ["network_analyst_followup", "kill_chain"])
    g.add_edge("network_analyst_followup", "threat_intel")
    g.add_conditional_edges("kill_chain", route_after_kill_chain,
                            ["threat_intel_kc_followup", "report_writer"])
    g.add_edge("threat_intel_kc_followup", "kill_chain")
    g.add_edge("report_writer", END)
    return g.compile()


def export_diagram(graph, mmd_path: str = None):
    """The communication diagram is generated FROM the compiled graph, not
    drawn by hand — the architecture document cannot drift from the code."""
    if mmd_path is None:
        os.makedirs(agent_core.OUTPUT_DIR, exist_ok=True)
        mmd_path = os.path.join(agent_core.OUTPUT_DIR, "workflow_diagram.mmd")
    mermaid = graph.get_graph().draw_mermaid()
    with open(mmd_path, "w", encoding="utf-8") as f:
        f.write(mermaid)
    print(f"[out] workflow diagram (Mermaid source) saved to {mmd_path}")

    png_path = mmd_path.replace(".mmd", ".png")
    import shutil
    import subprocess
    if shutil.which("mmdc"):
        r = subprocess.run(["mmdc", "-i", mmd_path, "-o", png_path],
                           capture_output=True, text=True)
        if r.returncode == 0:
            print(f"[out] rendered {png_path} via mmdc")
            return
    try:
        png = graph.get_graph().draw_mermaid_png()
        with open(png_path, "wb") as f:
            f.write(png)
        print(f"[out] rendered {png_path} via mermaid.ink")
    except Exception as e:
        print(f"[out] could not render PNG ({e}); Mermaid source saved — "
              f"paste it into mermaid.live to render")


def _slice_id(csv_path: str) -> str:
    return os.path.basename(csv_path).replace(".pcap_ISCX.csv", "").replace(".csv", "")


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", help="path to a CIC-IDS2017 CSV")
    ap.add_argument("--provider", choices=sorted(agent_core.PROVIDERS), default="ollama")
    ap.add_argument("--model", default=None)
    ap.add_argument("--environment", default=None,
                    help="environment profile id (e.g. enterprise_dmz). Omit to "
                         "run with NO environment context (logged in the manifest).")
    ap.add_argument("--force-evidence-request", action="store_true",
                    help="inject a synthetic evidence request if the TI agent "
                         "makes none — demonstrates the NA feedback edge")
    ap.add_argument("--diagram-only", action="store_true",
                    help="export the workflow diagram without running agents")
    ap.add_argument("--plan", action="store_true",
                    help="agents narrate their plan and per-turn reasoning")
    ap.add_argument("--tool-feedback", action="store_true",
                    help="each agent critiques its tool set (advisory)")
    args = ap.parse_args()

    if args.diagram_only:
        export_diagram(build_graph(client=None, model=None))
        raise SystemExit(0)
    if not args.csv:
        ap.error("--csv is required (unless --diagram-only)")

    client, model = agent_core.setup_client(args.provider, args.model)

    # --- environment profile: load, validate, record (M1) -------------------
    profile = None
    manifest = RunManifest(provider=args.provider, model=model)
    manifest.set_dataset("cic_ids2017", _slice_id(args.csv))
    if args.environment:
        if env is None:
            raise SystemExit("[config] environment package not importable")
        from environment.validator import validate_or_raise, CIC_IDS2017_LABELS
        profile = env.load_profile(args.environment)
        verdict = validate_or_raise(profile, CIC_IDS2017_LABELS)
        manifest.record_environment(args.environment, env.profile_hash(profile),
                                    verdict.to_manifest())
    else:
        print("[config] no --environment given; running with NO environment context")
        manifest.record_no_environment()

    graph = build_graph(client, model, args.force_evidence_request,
                        plan_mode=args.plan, tool_feedback=args.tool_feedback,
                        profile=profile, manifest=manifest)
    export_diagram(graph)

    state = graph.invoke({
        "csv_path": args.csv,
        "findings_md": None, "findings": None,
        "mappings": None, "mappings_md": None,
        "evidence_requests": [], "followup_count": 0,
        "kill_chain": None, "kill_chain_md": None,
        "kill_chain_retry_count": 0, "kill_chain_retry_decision": None,
        "report": None, "node_visits": 0,
    }, config={"recursion_limit": NODE_VISIT_CEILING + 3})

    print("\n" + "=" * 70 + "\nWORKFLOW COMPLETE\n" + "=" * 70)
    agent_core.save_report("findings", model, state["findings_md"], state["findings"])
    agent_core.save_report("mappings", model, state["mappings_md"], state["mappings"])
    agent_core.save_report("kill_chain", model, state.get("kill_chain_md"),
                           state.get("kill_chain"))
    if state.get("report"):
        agent_core.save_report("report", model, state["report"])
    if state["followup_count"]:
        print(f"[graph] NA feedback edge fired {state['followup_count']} time(s)")
    if state.get("kill_chain_retry_count"):
        print(f"[graph] kill-chain feedback edge fired "
              f"{state['kill_chain_retry_count']} time(s)")

    manifest.write(model)

    # Evaluation sidecar — outside the graph, sees ground truth agents never do.
    class _Tee(io.TextIOBase):
        def __init__(self, *streams): self.streams = streams
        def write(self, s):
            for st in self.streams:
                st.write(s)
            return len(s)
        def flush(self):
            for st in self.streams:
                st.flush()

    buf = io.StringIO()
    with contextlib.redirect_stdout(_Tee(sys.stdout, buf)):
        eval_sidecar.evaluate_findings(state["findings_md"] or "", na.df, na.labels)
        eval_sidecar.evaluate_mappings(state["mappings"] or {},
                                       state["findings"] or {}, na.df, na.labels)
        # CIC-IDS2017 has no phase labels, so only the code-only phase checks
        # (ordering coherence, impossible jumps, model/crosswalk divergence)
        # run here — exactly the ones that generalise to unlabelled data.
        eval_sidecar.evaluate_phases(state.get("kill_chain") or {},
                                     state["findings"] or {})
    eval_path = os.path.join(agent_core.run_dir(model), "eval.txt")
    with open(eval_path, "w", encoding="utf-8") as f:
        f.write(buf.getvalue())
    print(f"[out] evaluation saved to {eval_path}")
