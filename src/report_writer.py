"""
Report Writer Agent — Week 4 (M3)
=================================
The fourth agent (constraint #4: four agents stay four agents). It SYNTHESISES
the final incident report from the three upstream structured outputs — the
Network Analyst findings, the Threat Intel ATT&CK mappings, and the Kill Chain
phase narrative — for a specific reporting audience (from the environment
profile). It computes nothing new: numbers and technique IDs must already
exist upstream. This is the model transcribing, not deriving (constraint #1).

Grounding still applies: the report may cite ONLY technique IDs that Threat
Intel returned. A light post-check flags any it invents.

    python src/report_writer.py --findings f.json --mappings m.json \\
        --kill-chain kc.json --provider claude
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import textwrap

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import agent_core
import kill_chain as kc          # reuse its read-only STIX lookup tools

try:
    import environment as env
except Exception:                # pragma: no cover
    env = None

RW_MAX_TURNS = 4
TECH_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Report Writer reasons over structured input; it only needs read-only lookups.
TOOLS_IMPL = {
    "get_technique_context": kc.get_technique_context,
    "list_phase_definitions": kc.list_phase_definitions,
}
TOOL_DEFS = [d for d in kc.TOOL_DEFS
             if d["function"]["name"] in TOOLS_IMPL]

SYSTEM_PROMPT = textwrap.dedent("""\
    You are a security report writer. You are given the finished analysis of an
    incident — network-analyst findings, ATT&CK technique mappings, and a
    kill-chain phase narrative — and you write the final incident report for
    the stated audience. Respond in English only.

    You do NOT re-investigate and you do NOT compute new numbers. Every figure,
    IP, port, and technique ID must already appear in the material you were
    given. Cite ONLY technique IDs present in the mappings; never introduce a
    new one. If something is unknown or was flagged as a gap, say so plainly.

    Structure the report as markdown:
    - **Executive summary** (2-4 sentences, plain language)
    - **What happened** — the ordered kill-chain narrative
    - **Findings and ATT&CK mapping** — per finding: what, evidence, technique
    - **Gaps and uncertainty** — missing phases, unassigned findings, low
      confidence, divergences between the model and the mechanical crosswalk
    - **Recommended actions** — concrete and prioritised for the audience

    Match the tone to the audience you are told to write for. Use get_technique_
    context if you need a technique's plain-language description.
    """)


def build_task(findings: dict, mappings: dict, kill_chain: dict) -> str:
    fmap = kc.finding_id_map(findings)
    lines = ["Write the final incident report from the material below.", "",
             "NETWORK ANALYST FINDINGS:"]
    for fid, f in fmap.items():
        lines.append(f"\n[{fid}] {f.get('title', 'untitled')} "
                     f"(severity={f.get('severity')}, confidence={f.get('confidence')})")
        for key in ("source_ips", "destination_ips", "ports", "flow_count",
                    "first_seen", "last_seen", "evidence_summary"):
            if f.get(key) not in (None, [], ""):
                lines.append(f"  {key}: {f[key]}")
    lines += ["", "ATT&CK MAPPINGS:"]
    for m in mappings.get("mappings", []):
        lines.append(f"- {m.get('finding_id')}: {m.get('technique_id')} "
                     f"({m.get('technique_name')}), tactic={m.get('tactic')}, "
                     f"confidence={m.get('confidence')}, "
                     f"verified={m.get('verified')}")
    lines += ["", "KILL-CHAIN ANALYSIS:"]
    lines.append("Narrative: " + str(kill_chain.get("narrative", "")))
    for a in kill_chain.get("phase_assignments", []):
        lines.append(f"- {a.get('phase')}: findings {a.get('finding_ids')} "
                     f"techniques {a.get('technique_ids')} "
                     f"({a.get('confidence')}) — {a.get('justification')}")
    if kill_chain.get("gaps"):
        lines.append("Gaps: " + json.dumps(kill_chain["gaps"]))
    if kill_chain.get("unassigned_finding_ids"):
        lines.append("Unassigned findings: "
                     + json.dumps(kill_chain["unassigned_finding_ids"]))
    div = kill_chain.get("phase_divergence")
    if div and (div.get("model_only") or div.get("crosswalk_only")):
        lines.append("Model/crosswalk divergence: " + json.dumps(div))
    return "\n".join(lines)


def verify_report_grounding(report: str, mappings: dict):
    """Flag technique IDs in the report that Threat Intel never returned."""
    ti_ids = {str(m.get("technique_id", "")).strip().upper()
              for m in mappings.get("mappings", []) if m.get("technique_id")}
    cited = set(TECH_ID_RE.findall(report or ""))
    ungrounded = sorted(cited - ti_ids)
    for tid in ungrounded:
        print(f"[rw-grounding] WARNING: report cites {tid}, not in Threat Intel "
              f"mappings this run")
    return {"cited_technique_ids": sorted(cited), "ungrounded_technique_ids": ungrounded}


def analyze(client, model, findings: dict, mappings: dict, kill_chain: dict,
            profile: dict = None, plan_mode: bool = False, tool_feedback: bool = False):
    """Run the Report Writer. Returns (report_markdown, extras) where extras =
    {"injection": entry_or_None, "grounding": {...}}."""
    kc._load_run_context(mappings, findings)     # so its lookup tools work
    system_prompt = SYSTEM_PROMPT
    injection_entry = None
    if profile is not None and env is not None:
        system_prompt, injection_entry = env.inject(system_prompt, profile, "report_writer")
    report = agent_core.run_agent(
        client, model, build_task(findings, mappings, kill_chain), system_prompt,
        TOOL_DEFS, TOOLS_IMPL, max_turns=RW_MAX_TURNS, label="report_writer",
        plan_mode=plan_mode, tool_feedback=tool_feedback)
    grounding = verify_report_grounding(report, mappings)
    return report, {"injection": injection_entry, "grounding": grounding}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings", required=True)
    ap.add_argument("--mappings", required=True)
    ap.add_argument("--kill-chain", required=True, dest="kill_chain")
    ap.add_argument("--environment")
    ap.add_argument("--provider", choices=sorted(agent_core.PROVIDERS), default="ollama")
    ap.add_argument("--model", default=None)
    ap.add_argument("--plan", action="store_true")
    args = ap.parse_args()

    client, model = agent_core.setup_client(args.provider, args.model)
    load = lambda p: json.load(open(p, encoding="utf-8"))
    if args.environment and env is None:
        raise SystemExit("[config] environment package not importable")
    profile = env.load_profile(args.environment) if args.environment else None
    report, extras = analyze(client, model, load(args.findings), load(args.mappings),
                             load(args.kill_chain), profile=profile, plan_mode=args.plan)
    print("\n" + "=" * 70 + "\nINCIDENT REPORT\n" + "=" * 70 + "\n" + (report or ""))
    agent_core.save_report("report", model, report)
