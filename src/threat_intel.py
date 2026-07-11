"""
Threat Intelligence Agent — Week 3
==================================
Maps Network Analyst findings to MITRE ATT&CK techniques with explanations.
Same three-layer architecture as the Network Analyst, different dataset:

  1. DATA LAYER   — the real MITRE enterprise-attack STIX bundle, downloaded
                    and indexed in memory. The known failure mode for LLM
                    ATT&CK mapping is hallucinated or misnumbered technique
                    IDs, so the agent gets the actual dataset as ground truth.
  2. TOOL LAYER   — list_tactics / search_techniques / get_technique.
                    Deterministic, capped, and every technique ID a tool
                    returns is recorded for the grounding check below.
  3. AGENT LOOP   — agent_core.run_agent(), configured with this module's
                    prompt and tools.

Grounding enforcement (code, not prompt): after the agent finishes, every
technique ID in its output is checked against the set the tools actually
returned this run. Any ID the tools never returned is flagged loudly and
marked "verified": false in the JSON output. This is the Week 3 equivalent
of hiding the Label column — the "no memory citations" rule is auditable.

    python src/threat_intel.py --selftest              # tools + grounding, no LLM
    python src/threat_intel.py --findings outputs/<run>/findings.json --provider claude
"""

import argparse
import json
import os
import re
import textwrap
import urllib.request

import agent_core
from agent_core import MAX_TOOL_RESULT_CHARS

# ---------------------------------------------------------------------------
# 1. DATA LAYER — real ATT&CK data, not model memory
# ---------------------------------------------------------------------------
ATTACK_URL = ("https://raw.githubusercontent.com/mitre/cti/master/"
              "enterprise-attack/enterprise-attack.json")
ATTACK_LOCAL = os.path.join(agent_core.REPO_ROOT, "data",
                            "enterprise-attack.json")   # cached; in .gitignore

TACTICS: list = None      # kill-chain-ordered [{shortname, name, description}]
TECHNIQUES: dict = None   # "T1110" / "T1110.001" -> technique record


def _first_sentence(text: str) -> str:
    text = " ".join((text or "").split())
    m = re.search(r"[.!?](\s|$)", text)
    return text[:m.end()].strip() if m else text[:200]


def load_attack_data():
    """Download (once) and index the enterprise ATT&CK STIX bundle.
    Deprecated/revoked entries are filtered out at load time, so an ID the
    tools can return is always a currently-valid ID."""
    global TACTICS, TECHNIQUES
    if TECHNIQUES is not None:
        return

    if not os.path.exists(ATTACK_LOCAL):
        print(f"[attack] downloading enterprise-attack.json (~50 MB) from MITRE CTI...")
        urllib.request.urlretrieve(ATTACK_URL, ATTACK_LOCAL + ".part")
        os.replace(ATTACK_LOCAL + ".part", ATTACK_LOCAL)
        print(f"[attack] cached at {ATTACK_LOCAL}")
    with open(ATTACK_LOCAL, encoding="utf-8") as f:
        objects = json.load(f)["objects"]

    # Tactics, in kill-chain order: the x-mitre-matrix object lists its
    # tactic_refs in matrix (= kill chain) order.
    tactic_by_stix_id = {o["id"]: o for o in objects if o["type"] == "x-mitre-tactic"}
    matrix = next(o for o in objects if o["type"] == "x-mitre-matrix")
    TACTICS = []
    tactic_name_by_shortname = {}
    for ref in matrix["tactic_refs"]:
        t = tactic_by_stix_id[ref]
        TACTICS.append({"shortname": t["x_mitre_shortname"], "name": t["name"],
                        "description": _first_sentence(t.get("description"))})
        tactic_name_by_shortname[t["x_mitre_shortname"]] = t["name"]

    TECHNIQUES = {}
    for o in objects:
        if o["type"] != "attack-pattern":
            continue
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ext = next((r for r in o.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"), None)
        if not ext:
            continue
        tid = ext["external_id"]
        TECHNIQUES[tid] = {
            "id": tid,
            "name": o["name"],
            "tactics": [tactic_name_by_shortname.get(p["phase_name"], p["phase_name"])
                        for p in o.get("kill_chain_phases", [])],
            "description": " ".join((o.get("description") or "").split()),
            "platforms": o.get("x_mitre_platforms", []),
            "detection": " ".join((o.get("x_mitre_detection") or "").split()),
            "is_subtechnique": o.get("x_mitre_is_subtechnique", False),
            "subtechniques": [],
        }
    for tid, t in sorted(TECHNIQUES.items()):
        if t["is_subtechnique"]:
            parent = TECHNIQUES.get(tid.split(".")[0])
            if parent:
                parent["subtechniques"].append({"id": tid, "name": t["name"]})
    print(f"[attack] indexed {len(TECHNIQUES)} techniques "
          f"({sum(t['is_subtechnique'] for t in TECHNIQUES.values())} sub-techniques), "
          f"{len(TACTICS)} tactics")


# ---------------------------------------------------------------------------
# 2. TOOL LAYER — deterministic, capped, grounding-recorded
# ---------------------------------------------------------------------------
TECH_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

_returned_ids = set()   # every technique ID any tool returned this run


def _emit(payload: dict) -> str:
    """All tool results leave through here: serialize, and record every
    technique ID in the result for the post-run grounding check."""
    s = json.dumps(payload, default=str)
    _returned_ids.update(TECH_ID_RE.findall(s))
    return s


def list_tactics() -> str:
    """The enterprise tactics in kill-chain order, one-line descriptions.
    (15 as of ATT&CK v18, which split Defense Evasion into Stealth +
    Defense Impairment. Week 4's Kill Chain Agent will reuse this.)"""
    load_attack_data()
    return _emit({"tactics_in_kill_chain_order": [
        {"name": t["name"], "description": t["description"]} for t in TACTICS]})


def search_techniques(query: str, top_n: int = 5) -> str:
    """Keyword search over technique names + descriptions.
    Simple scoring: name match beats description match. No embeddings."""
    load_attack_data()
    top_n = min(int(top_n), 10)
    q = (query or "").lower().strip()
    words = [w for w in re.split(r"\W+", q) if len(w) > 2]
    scored = []
    for tid, t in TECHNIQUES.items():
        name, desc = t["name"].lower(), t["description"].lower()
        score = (10 if q and q in name else 0)
        score += sum(3 for w in words if w in name)
        score += sum(1 for w in words if w in desc)
        if score:
            scored.append((-score, tid))
    scored.sort()
    hits = [{"id": tid, "name": TECHNIQUES[tid]["name"],
             "tactics": TECHNIQUES[tid]["tactics"],
             "description_snippet": TECHNIQUES[tid]["description"][:200]}
            for _, tid in scored[:top_n]]
    if not hits:
        return _emit({"query": query, "hits": [],
                      "hint": "no matches — try fewer or different keywords"})
    return _emit({"query": query, "n_candidates": len(scored), "hits": hits})


def get_technique(technique_id: str) -> str:
    """Full detail for one technique: description, tactics, detection notes,
    sub-techniques. Long fields truncated to the usual cap."""
    load_attack_data()
    tid = (technique_id or "").strip().upper()
    t = TECHNIQUES.get(tid)
    if not t:
        return _emit({"error": f"unknown, deprecated, or revoked technique id "
                               f"{technique_id!r}",
                      "hint": "use search_techniques to find currently valid ids"})
    return _emit({"id": tid, "name": t["name"], "tactics": t["tactics"],
                  "platforms": t["platforms"],
                  "description": t["description"][:1500],
                  "detection": t["detection"][:800],
                  "subtechniques": t["subtechniques"]})


TOOLS_IMPL = {
    "list_tactics": list_tactics,
    "search_techniques": search_techniques,
    "get_technique": get_technique,
}

TOOL_DEFS = [
    {"type": "function", "function": {
        "name": "list_tactics",
        "description": "The enterprise ATT&CK tactics in kill-chain order with "
                       "one-line descriptions. Cheap orientation call.",
        "parameters": {"type": "object", "properties": {}, "required": []}}},
    {"type": "function", "function": {
        "name": "search_techniques",
        "description": "Keyword search over ATT&CK technique names and descriptions. "
                       "Returns id, name, tactics, and a description snippet per hit. "
                       "Search behaviors ('brute force', 'network scanning'), not IDs.",
        "parameters": {"type": "object", "properties": {
            "query": {"type": "string"},
            "top_n": {"type": "integer", "default": 5}},
            "required": ["query"]}}},
    {"type": "function", "function": {
        "name": "get_technique",
        "description": "Full detail for one technique ID (e.g. 'T1110' or 'T1110.001'): "
                       "description, tactics, platforms, detection notes, sub-techniques. "
                       "ALWAYS call this to confirm a technique before citing it.",
        "parameters": {"type": "object", "properties": {
            "technique_id": {"type": "string"}},
            "required": ["technique_id"]}}},
]


# ---------------------------------------------------------------------------
# Grounding enforcement — code, not prompt
# ---------------------------------------------------------------------------
def reset_grounding():
    _returned_ids.clear()


def verify_output_grounding(output: str):
    """Regex every technique ID out of the agent's output and check each one
    against the set the tools actually returned this run. Returns
    (cited_ids, unverified_ids)."""
    cited = set(TECH_ID_RE.findall(output or ""))
    unverified = sorted(cited - _returned_ids)
    for tid in unverified:
        print(f"[grounding] WARNING: unverified technique ID {tid} "
              f"— never returned by any tool this run")
    if cited and not unverified:
        print(f"[grounding] all {len(cited)} cited technique IDs verified "
              f"against tool output")
    return sorted(cited), unverified


def annotate_verification(mappings: dict) -> dict:
    """Set 'verified' on each mapping from the tool log. The model never
    writes this field — code computes it, so it can't be talked into it."""
    for m in mappings.get("mappings", []):
        m["verified"] = str(m.get("technique_id", "")).strip().upper() in _returned_ids
    return mappings


# ---------------------------------------------------------------------------
# 3. AGENT CONFIGURATION
# ---------------------------------------------------------------------------
TI_MAX_TURNS = 8   # mapping needs fewer turns than raw-data investigation


SYSTEM_PROMPT = textwrap.dedent(f"""\
    You are a threat intelligence analyst. You receive structured findings
    from a network analyst and map each one to MITRE ATT&CK technique(s),
    with reasoning a non-specialist manager can follow. Always respond in
    English only.

    You have a budget of {TI_MAX_TURNS} turns (you may batch several tool
    calls per turn). Plan so you finish and write your final mapping report
    within budget.

    Hard rules:
    1. Cite ONLY technique IDs that appeared in your tool results in this
       conversation. Your output is checked by code against the tool log,
       and any ID your tools never returned is flagged as unverified. Never
       cite from memory — confirm every ID with get_technique first.
    2. Prefer the most specific technique the evidence supports: cite a
       sub-technique when the evidence clearly matches it, otherwise stay
       at the parent technique.
    3. If a finding lacks enough evidence to map confidently, do NOT guess.
       Add an evidence request instead: a specific, answerable question for
       the network analyst, ideally with a suggested pandas filter over flow
       data (columns like `Source IP`, `Destination Port`, `Flow Duration`,
       `Total Fwd Packets`).
    4. While investigating, write AT MOST one short sentence between tool
       calls — save all prose for the final report.

    When done, output your MAPPINGS as markdown for humans: per finding, the
    technique(s) chosen, why the evidence supports them, and what evidence
    would raise confidence. Then end with a machine-readable summary: a
    fenced ```json code block of the form
    {{"mappings": [{{"finding_id": ..., "technique_id": ...,
    "technique_name": ..., "tactic": ..., "confidence": "high|medium|low",
    "reasoning": ..., "evidence": ...}}],
    "evidence_requests": [{{"finding_id": ..., "question": ...,
    "suggested_tool_query": ...}}]}}

    "evidence_requests" may be an empty list. Every mapping and every
    evidence request must reference a finding id (F1, F2, ...) from the task.
    """)


def build_task(findings: dict) -> str:
    """Format the Network Analyst's structured findings JSON into the TI task
    prompt, assigning stable ids F1..Fn. The eval sidecar reproduces this
    numbering, so it must stay: enumerate in list order, 1-based."""
    lines = ["For each finding below, identify the most likely ATT&CK "
             "technique(s). Use your tools to search and confirm — cite only "
             "technique IDs returned by your tools. Explain your reasoning "
             "per mapping. If a finding lacks enough evidence to map "
             "confidently, do not guess; add an evidence request instead.",
             "", "FINDINGS:"]
    for i, f in enumerate(findings.get("findings", []), 1):
        lines.append(f"\n[F{i}] {f.get('title', 'untitled finding')}")
        for key in ("severity", "confidence", "source_ips", "destination_ips",
                    "ports", "flow_count", "evidence_summary"):
            if f.get(key) not in (None, [], ""):
                lines.append(f"  {key}: {f[key]}")
    followup = findings.get("followup_answers")
    if followup:
        lines += ["", "FOLLOW-UP ANSWERS from the network analyst (responses "
                  "to your earlier evidence requests — use them to firm up or "
                  "revise your mappings):", "",
                  followup if isinstance(followup, str)
                  else json.dumps(followup, indent=2)]
    return "\n".join(lines)


def analyze(client, model, findings: dict):
    """Run the TI agent on Network Analyst findings.
    Returns (mappings_md, mappings_dict_or_None) with grounding checked and
    'verified' annotated."""
    reset_grounding()
    report = agent_core.run_agent(client, model, build_task(findings),
                                  SYSTEM_PROMPT, TOOL_DEFS, TOOLS_IMPL,
                                  max_turns=TI_MAX_TURNS, label="threat_intel")
    verify_output_grounding(report)
    structured, md = agent_core.extract_json_block(report)
    if structured is not None:
        annotate_verification(structured)
        structured.setdefault("mappings", [])
        structured.setdefault("evidence_requests", [])
    return md, structured


# ---------------------------------------------------------------------------
def selftest():
    """Run each tool once and exercise the grounding check. No LLM needed."""
    load_attack_data()

    print("\n--- list_tactics() ---")
    print(list_tactics()[:500] + " ...")

    print("\n--- search_techniques('brute force password guessing') ---")
    print(search_techniques("brute force password guessing")[:700] + " ...")

    print("\n--- get_technique('T1110.001') ---")
    print(get_technique("T1110.001")[:700] + " ...")

    print("\n--- get_technique('T9999') (bad id) ---")
    print(get_technique("T9999"))

    print("\n--- grounding check ---")
    reset_grounding()
    search_techniques("network service scanning")
    fake_output = "The scan maps to T1046. Memory says maybe T1595.002 too."
    cited, unverified = verify_output_grounding(fake_output)
    assert "T1046" in cited and "T1046" not in unverified, "T1046 should verify"
    assert "T1595.002" in unverified, "T1595.002 should be flagged"
    print(f"[selftest] grounding OK: cited={cited}, unverified={unverified}")
    print("\n[selftest] all tools ran; grounding check behaves as specified")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true",
                    help="run each tool once and test grounding (no LLM)")
    ap.add_argument("--findings",
                    help="path to a findings_*.json from the network analyst")
    ap.add_argument("--provider", choices=sorted(agent_core.PROVIDERS),
                    default="ollama")
    ap.add_argument("--model", default=None)
    args = ap.parse_args()

    if args.selftest:
        selftest()
        raise SystemExit(0)
    if not args.findings:
        ap.error("--findings is required (or use --selftest)")

    client, model = agent_core.setup_client(args.provider, args.model)
    with open(args.findings, encoding="utf-8") as f:
        findings = json.load(f)

    md, structured = analyze(client, model, findings)
    print("\n" + "=" * 70 + "\nMAPPINGS\n" + "=" * 70 + "\n" + (md or ""))
    agent_core.save_report("mappings", model, md, structured)
