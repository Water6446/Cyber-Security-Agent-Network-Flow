"""
LangGraph orchestration — Week 3
================================
Deterministic workflow BETWEEN agents, agentic tool-calling loops WITHIN
agents. The agent order (Network Analyst -> Threat Intel -> [Kill Chain ->
Report, Weeks 4-5]) never varies, so there is no supervisor/orchestrator LLM
— an LLM choosing the route would add nondeterminism and a failure mode
without adding capability. The one dynamic element is a single, capped
feedback edge: if the Threat Intel agent asks for more evidence, the Network
Analyst gets exactly one targeted follow-up pass.

    START -> network_analyst -> threat_intel
               ^                    |
               |  (evidence_requests nonempty AND followup_count == 0)
               +-- network_analyst_followup <- yes
                                    |
                                    no -> END   # Week 4: END becomes kill_chain

The state schema IS the answer to "what should agents share": distilled
structured findings with cited evidence — never raw flows, never full
transcripts. Each agent works at its own level of abstraction.

    python src/workflow.py --csv data/TrafficLabelling/<day>.csv [--provider claude] [--model ...]
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
import network_analyst as na
import threat_intel as ti


class InvestigationState(TypedDict):
    csv_path: str
    findings_md: Optional[str]        # human-readable NA report
    findings: Optional[dict]          # NA structured JSON  -> TI input
    mappings: Optional[dict]          # TI structured JSON  -> Week 4 input
    mappings_md: Optional[str]
    evidence_requests: list           # TI -> NA feedback payload
    followup_count: int               # feedback-loop cap (max 1)
    # week 4/5 seams:
    kill_chain: Optional[dict]
    report: Optional[str]


FOLLOWUP_MAX_TURNS = 4   # the follow-up answers targeted questions, not a full sweep


def build_graph(client, model, force_evidence_request: bool = False):
    """Compile the investigation graph. The agent nodes close over the LLM
    client so the graph structure stays a pure function of the code — which
    is what makes the exported diagram trustworthy.

    force_evidence_request injects a synthetic request if the TI agent makes
    none, so the feedback edge can be demonstrated on demand (acceptance
    criterion 5) without editing code."""

    def node_network_analyst(state: InvestigationState):
        print("\n[graph] entering network_analyst")
        na.load_data(state["csv_path"])
        raw = na.analyze(client, model)
        findings, md = agent_core.extract_json_block(raw)
        if findings is None:
            print("[graph] WARNING: network analyst emitted no parseable JSON block")
            findings = {"findings": []}
        return {"findings": findings, "findings_md": md}

    def node_threat_intel(state: InvestigationState):
        print("\n[graph] entering threat_intel")
        md, mappings = ti.analyze(client, model, state["findings"])
        if mappings is None:
            print("[graph] WARNING: threat intel emitted no parseable JSON block")
            mappings = {"mappings": [], "evidence_requests": []}
        requests = mappings.get("evidence_requests", []) or []
        if force_evidence_request and not requests and state["followup_count"] == 0:
            print("[graph] --force-evidence-request: injecting a synthetic request "
                  "to exercise the feedback edge")
            requests = [{
                "finding_id": "F1",
                "question": "For each source IP named in the findings, how many "
                            "distinct destination ports did it contact, and which "
                            "single destination port received the most flows from it?",
                "suggested_tool_query": "count_by(filter_expr=\"`Source IP` == '<ip>'\", "
                                        "column='Destination Port')",
            }]
        return {"mappings": mappings, "mappings_md": md,
                "evidence_requests": requests}

    def node_network_analyst_followup(state: InvestigationState):
        print("\n[graph] entering network_analyst_followup")
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
        answers = na.analyze(client, model, task, max_turns=FOLLOWUP_MAX_TURNS)
        findings = dict(state["findings"])
        findings["followup_answers"] = answers
        return {"findings": findings,
                "followup_count": state["followup_count"] + 1}

    def route_after_threat_intel(state: InvestigationState):
        # Hard cap: the feedback edge fires at most once — same spirit as MAX_TURNS.
        if state["evidence_requests"] and state["followup_count"] == 0:
            print("[graph] evidence requests pending -> one follow-up pass")
            return "network_analyst_followup"
        print("[graph] no follow-up needed (or cap reached) -> done")
        return END   # Week 4: replace END with kill_chain

    g = StateGraph(InvestigationState)
    g.add_node("network_analyst", node_network_analyst)
    g.add_node("threat_intel", node_threat_intel)
    g.add_node("network_analyst_followup", node_network_analyst_followup)
    g.add_edge(START, "network_analyst")
    g.add_edge("network_analyst", "threat_intel")
    g.add_conditional_edges("threat_intel", route_after_threat_intel,
                            ["network_analyst_followup", END])
    g.add_edge("network_analyst_followup", "threat_intel")
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
    if shutil.which("mmdc"):                      # local mermaid-cli if present
        r = subprocess.run(["mmdc", "-i", mmd_path, "-o", png_path],
                           capture_output=True, text=True)
        if r.returncode == 0:
            print(f"[out] rendered {png_path} via mmdc")
            return
    try:                                          # else langgraph's remote renderer
        png = graph.get_graph().draw_mermaid_png()
        with open(png_path, "wb") as f:
            f.write(png)
        print(f"[out] rendered {png_path} via mermaid.ink")
    except Exception as e:
        print(f"[out] could not render PNG ({e}); Mermaid source saved — "
              f"paste it into mermaid.live to render")


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", help="path to a CIC-IDS2017 CSV")
    ap.add_argument("--provider", choices=sorted(agent_core.PROVIDERS),
                    default="ollama")
    ap.add_argument("--model", default=None)
    ap.add_argument("--force-evidence-request", action="store_true",
                    help="inject a synthetic evidence request if the TI agent "
                         "makes none — demonstrates the feedback edge")
    ap.add_argument("--diagram-only", action="store_true",
                    help="export the workflow diagram without running agents "
                         "(no CSV or API key needed)")
    args = ap.parse_args()

    if args.diagram_only:
        export_diagram(build_graph(client=None, model=None))
        raise SystemExit(0)
    if not args.csv:
        ap.error("--csv is required (unless --diagram-only)")

    client, model = agent_core.setup_client(args.provider, args.model)
    graph = build_graph(client, model, args.force_evidence_request)
    export_diagram(graph)

    state = graph.invoke({
        "csv_path": args.csv,
        "findings_md": None, "findings": None,
        "mappings": None, "mappings_md": None,
        "evidence_requests": [], "followup_count": 0,
        "kill_chain": None, "report": None,
    })

    print("\n" + "=" * 70 + "\nWORKFLOW COMPLETE\n" + "=" * 70)
    agent_core.save_report("findings", model, state["findings_md"],
                           state["findings"])
    agent_core.save_report("mappings", model, state["mappings_md"],
                           state["mappings"])
    if state["followup_count"]:
        print(f"[graph] feedback edge fired {state['followup_count']} time(s)")

    # Evaluation sidecar — outside the graph, sees ground truth agents never do.
    # The scorers print their report; tee stdout so the same text also lands
    # in the run folder as eval.txt (5th file alongside findings/mappings).
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
    eval_path = os.path.join(agent_core.run_dir(model), "eval.txt")
    with open(eval_path, "w", encoding="utf-8") as f:
        f.write(buf.getvalue())
    print(f"[out] evaluation saved to {eval_path}")
