"""
Kill Chain Reasoning Agent — Week 4 (M2)
========================================
The fourth agent. It reads the STRUCTURED output of the Threat Intelligence
agent (ATT&CK mappings) plus the Network Analyst's findings, and reasons about
the campaign as a whole: which Lockheed kill-chain phase each finding belongs
to, what the ordered narrative is, and what is missing. It does NOT re-read
raw flows — it reasons over distilled, structured input, which is the whole
point of keeping it a separate agent (constraint #4).

The crux — code/model split for phase assignment (handoff §2):

    The model PROPOSES.  Code independently DERIVES.  A comparison DIVERGES.

  1. The model produces `phase_assignments` with justifications. This prose is
     the artifact of interest — it is the model's reasoning, not a lookup.
  2. Independently, code derives an EXPECTED phase set from the ATT&CK tactics
     that Threat Intel actually returned, via a static tactic->phase crosswalk.
     This never touches the model. Technique->tactic comes from the STIX data
     in threat_intel.py; only tactic->phase is hardcoded here (the one asserted
     judgment call).
  3. `phase_divergence` = phases the model assigned that the crosswalk does not
     support, and phases the crosswalk implies that the model did not assign.
     Divergence is NOT an error — it is the most interesting demo material,
     the place where narrative reasoning departs from mechanical mapping.

Grounding (code, not prompt): every technique_id in this agent's output must
have appeared in Threat Intel's output this run, and every finding_id must
exist. Violations are flagged, never silently dropped.

    python src/kill_chain.py --selftest      # pure-code pipeline, no LLM
    python src/kill_chain.py --mappings outputs/<run>/mappings.json \\
                             --findings outputs/<run>/findings.json --provider claude
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import textwrap

# make the top-level environment/ package importable when run from src/
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import agent_core
import threat_intel as ti

try:                                    # environment context is optional
    import environment as env
except Exception:                       # pragma: no cover
    env = None


# ---------------------------------------------------------------------------
# The fixed vocabulary — six Lockheed Martin kill-chain phases, in order.
# Enforced in code: an out-of-vocabulary phase triggers exactly one re-prompt,
# then a hard error (no silent near-miss acceptance).
# ---------------------------------------------------------------------------
PHASES = ["Reconnaissance", "Delivery", "Exploitation", "Installation",
          "Command and Control", "Actions on Objectives"]
PHASE_ORDER = {p: i for i, p in enumerate(PHASES)}

PHASE_DEFINITIONS = {
    "Reconnaissance": "Researching and identifying targets: scanning, "
                      "enumeration, harvesting of hosts, ports, and services.",
    "Delivery": "Transmission of the weapon/access to the target environment: "
                "initial access, phishing payload arrival, exploit delivery.",
    "Exploitation": "Triggering the intrusion: code execution, exploiting a "
                    "vulnerability or a mis-config to gain a foothold.",
    "Installation": "Establishing persistence: implanting a backdoor, service, "
                    "or account that survives a reboot.",
    "Command and Control": "The compromised host establishing a channel to the "
                           "operator for remote control (beaconing, C2).",
    "Actions on Objectives": "The attacker acting on goals: collection, "
                             "credential theft, lateral movement, exfiltration, "
                             "or impact.",
}

# ---------------------------------------------------------------------------
# STATIC tactic -> kill-chain-phase crosswalk  (handoff §2)
# ---------------------------------------------------------------------------
# This dict is A DEFENDED JUDGMENT CALL, and it is the ONLY hardcoded mapping
# in this module. technique->tactic is NEVER hardcoded — it is read live from
# the STIX bundle in threat_intel.py. Keyed by ATT&CK tactic *names* exactly as
# threat_intel indexes them.
#
# ATT&CK v18 NOTE: v18 split the classic 'Defense Evasion' (TA0005) into
# 'Stealth' and 'Defense Impairment'. The handoff excludes Defense Evasion from
# derivation ("no single phase — spans all"), so BOTH successors inherit that
# exclusion here (mapped to None). If the loaded ATT&CK ever reverts to the old
# single tactic name, add 'Defense Evasion': None as well.
TACTIC_TO_PHASE = {
    "Reconnaissance":        "Reconnaissance",
    "Resource Development":  "Reconnaissance",
    "Initial Access":        "Delivery",
    "Execution":             "Exploitation",
    "Persistence":           "Installation",
    "Privilege Escalation":  "Exploitation",
    "Stealth":               None,   # ex-Defense Evasion — excluded (spans all)
    "Defense Impairment":    None,   # ex-Defense Evasion — excluded (spans all)
    "Defense Evasion":       None,   # kept for older ATT&CK versions
    "Credential Access":     "Actions on Objectives",
    "Discovery":             "Reconnaissance",
    "Lateral Movement":      "Actions on Objectives",
    "Collection":            "Actions on Objectives",
    "Command and Control":   "Command and Control",
    "Exfiltration":          "Actions on Objectives",
    "Impact":                "Actions on Objectives",
}

# Inverse of the crosswalk: phase -> the tactics that map to it. Used ONLY to
# phrase a retry follow-up to Threat Intel in tactic terms, so phase vocabulary
# never leaks into Threat Intel's context (it must stay phase-invariant).
PHASE_TO_TACTICS = {}
for _tac, _ph in TACTIC_TO_PHASE.items():
    if _ph:
        PHASE_TO_TACTICS.setdefault(_ph, []).append(_tac)


class KillChainError(Exception):
    """Raised when the model's output cannot be coerced to the fixed vocabulary."""


# ---------------------------------------------------------------------------
# Per-run context for the tools (module globals, mirroring network_analyst /
# threat_intel). Set by _load_run_context() at the top of analyze() / selftest.
# ---------------------------------------------------------------------------
_FINDING_BY_ID: dict = {}    # "F1" -> Network Analyst finding dict
_TI_TECHNIQUE_IDS: set = set()   # technique IDs Threat Intel returned this run


def finding_id_map(findings: dict) -> dict:
    """Reproduce threat_intel.build_task's F1..Fn numbering (list order,
    1-based) so Kill Chain, Threat Intel, and the eval sidecar all agree on
    which finding an id names."""
    return {f"F{i}": f for i, f in enumerate(findings.get("findings", []), 1)}


def _load_run_context(mappings: dict, findings: dict):
    global _FINDING_BY_ID, _TI_TECHNIQUE_IDS
    _FINDING_BY_ID = finding_id_map(findings)
    _TI_TECHNIQUE_IDS = {str(m.get("technique_id", "")).strip().upper()
                         for m in mappings.get("mappings", [])
                         if m.get("technique_id")}


# ---------------------------------------------------------------------------
# 2. TOOL LAYER — small; this agent reasons over structured input, not search
# ---------------------------------------------------------------------------
_TIMESTAMP_FIELDS = ("first_seen", "last_seen", "timestamp", "timestamps")


def get_finding_detail(finding_id: str) -> str:
    """Return the Network Analyst finding for an id, UNLABELLED and WITHOUT raw
    timestamps. Timestamps are withheld on purpose: ordering must come from
    get_temporal_ordering (code), not from the model eyeballing timestamps
    (handoff §2, acceptance: raw timestamps are not the model's path to
    ordering)."""
    fid = str(finding_id).strip().upper()
    f = _FINDING_BY_ID.get(fid)
    if not f:
        return json.dumps({"error": f"unknown finding id {finding_id!r}",
                           "known_ids": sorted(_FINDING_BY_ID)})
    view = {k: v for k, v in f.items() if k.lower() not in _TIMESTAMP_FIELDS}
    view["finding_id"] = fid
    return json.dumps(view, default=str)


def _clip(text: str, limit: int = 1000) -> str:
    """Clip long text at a sentence/word boundary (not mid-word). The tool
    feedback flagged descriptions ending mid-word ('...dur')."""
    text = text or ""
    if len(text) <= limit:
        return text
    cut = text[:limit]
    dot = cut.rfind(". ")
    if dot > limit * 0.5:
        return cut[:dot + 1]
    sp = cut.rfind(" ")
    return (cut[:sp] if sp > 0 else cut).rstrip() + " …"


def get_technique_context(technique_id: str) -> str:
    """Name, tactic(s), and description for one technique, from the local STIX
    dataset (threat_intel). Reasoning against the real dataset, not the model's
    memory. Description is clipped at a sentence boundary, not mid-word."""
    ti.load_attack_data()
    tid = str(technique_id).strip().upper()
    t = ti.TECHNIQUES.get(tid)
    if not t:
        return json.dumps({"error": f"unknown/deprecated technique {technique_id!r}"})
    return json.dumps({"id": tid, "name": t["name"], "tactics": t["tactics"],
                       "description": _clip(t["description"], 1000),
                       "returned_by_threat_intel": tid in _TI_TECHNIQUE_IDS},
                      default=str)


def _parse_ts(value):
    """Best-effort timestamp parse -> epoch seconds (float) or None. Accepts a
    scalar or a list (takes the min). CIC-IDS2017 uses e.g. '7/7/2017 3:30'."""
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        parsed = [p for p in (_parse_ts(v) for v in value) if p is not None]
        return min(parsed) if parsed else None
    try:
        import pandas as pd
        ts = pd.to_datetime(value, errors="coerce", dayfirst=False)
        if ts is not None and not pd.isna(ts):
            return ts.timestamp()
    except Exception:
        pass
    return None


def _finding_first_seen(f: dict):
    for key in ("first_seen", "timestamp", "timestamps", "last_seen"):
        if f.get(key) not in (None, "", []):
            ts = _parse_ts(f[key])
            if ts is not None:
                return ts
    return None


def get_temporal_ordering(finding_ids) -> str:
    """CODE computes first-seen ordering of the given findings, with gaps in
    seconds between consecutive findings. The model must not infer ordering
    from timestamps itself — it calls this. Findings lacking a usable timestamp
    are reported separately as 'undetermined' rather than guessed."""
    if isinstance(finding_ids, str):
        finding_ids = [finding_ids]
    ordered, undetermined = [], []
    for fid in finding_ids:
        f = _FINDING_BY_ID.get(str(fid).strip().upper())
        if not f:
            undetermined.append({"finding_id": fid, "reason": "unknown id"})
            continue
        ts = _finding_first_seen(f)
        (undetermined.append({"finding_id": str(fid).strip().upper(),
                              "reason": "no usable timestamp in finding"})
         if ts is None else
         ordered.append({"finding_id": str(fid).strip().upper(), "epoch": ts}))
    ordered.sort(key=lambda r: r["epoch"])
    seq = []
    for i, r in enumerate(ordered):
        seq.append({"finding_id": r["finding_id"],
                    "gap_seconds_from_previous":
                        None if i == 0 else round(r["epoch"] - ordered[i - 1]["epoch"], 1)})
    return json.dumps({"ordering": seq, "undetermined": undetermined,
                       "note": "ordering computed in code from finding "
                               "timestamps; gaps are seconds between "
                               "consecutive first-seen times"}, default=str)


def list_phase_definitions() -> str:
    """The six kill-chain phases in use, in order, with a one-line definition
    each — so the model reasons against a stated rubric, not its priors."""
    return json.dumps({"phases_in_order":
                       [{"phase": p, "definition": PHASE_DEFINITIONS[p]}
                        for p in PHASES]})


TOOLS_IMPL = {
    "get_finding_detail": get_finding_detail,
    "get_technique_context": get_technique_context,
    "get_temporal_ordering": get_temporal_ordering,
    "list_phase_definitions": list_phase_definitions,
}

TOOL_DEFS = [
    {"type": "function", "function": {
        "name": "get_finding_detail",
        "description": "Full detail for one Network Analyst finding by id "
                       "(F1, F2, ...). Returns the finding without raw "
                       "timestamps — use get_temporal_ordering for sequence.",
        "parameters": {"type": "object", "properties": {
            "finding_id": {"type": "string"}}, "required": ["finding_id"]}}},
    {"type": "function", "function": {
        "name": "get_technique_context",
        "description": "Name, tactic(s), and short description for an ATT&CK "
                       "technique id from the local dataset. Use to see which "
                       "tactic a mapped technique belongs to.",
        "parameters": {"type": "object", "properties": {
            "technique_id": {"type": "string"}}, "required": ["technique_id"]}}},
    {"type": "function", "function": {
        "name": "get_temporal_ordering",
        "description": "CODE-computed first-seen ordering of the given finding "
                       "ids, with gaps in seconds. Call this to sequence "
                       "findings — do NOT infer order from timestamps yourself.",
        "parameters": {"type": "object", "properties": {
            "finding_ids": {"type": "array", "items": {"type": "string"}}},
            "required": ["finding_ids"]}}},
    {"type": "function", "function": {
        "name": "list_phase_definitions",
        "description": "The six fixed kill-chain phases in order, each with a "
                       "one-line definition. Reason against this rubric.",
        "parameters": {"type": "object", "properties": {}, "required": []}}},
]


# ---------------------------------------------------------------------------
# CODE-DERIVED analysis (never touches the model) — the independent half of
# the code/model split, plus grounding.
# ---------------------------------------------------------------------------
def tactics_for_technique(technique_id: str) -> list:
    """technique -> tactic names, from STIX (NOT hardcoded)."""
    ti.load_attack_data()
    t = ti.TECHNIQUES.get(str(technique_id).strip().upper())
    return list(t["tactics"]) if t else []


def derive_expected_phases(mappings: dict) -> set:
    """The expected phase set from the tactics Threat Intel's techniques carry,
    via the static crosswalk. Independent of the model's assignments."""
    phases = set()
    for m in mappings.get("mappings", []):
        for tac in tactics_for_technique(m.get("technique_id", "")):
            phase = TACTIC_TO_PHASE.get(tac)
            if phase:
                phases.add(phase)
    return phases


def compute_phase_divergence(structured: dict, mappings: dict) -> dict:
    """model_only  = phases the model assigned the crosswalk does not support.
    crosswalk_only = phases the crosswalk implies the model did not assign.
    Neither is an error; both are recorded and surfaced."""
    model_phases = {a.get("phase") for a in structured.get("phase_assignments", [])
                    if a.get("phase")}
    expected = derive_expected_phases(mappings)
    return {
        "model_phases": sorted(model_phases, key=lambda p: PHASE_ORDER.get(p, 99)),
        "expected_phases_from_crosswalk":
            sorted(expected, key=lambda p: PHASE_ORDER.get(p, 99)),
        "model_only": sorted(model_phases - expected,
                             key=lambda p: PHASE_ORDER.get(p, 99)),
        "crosswalk_only": sorted(expected - model_phases,
                                 key=lambda p: PHASE_ORDER.get(p, 99)),
    }


def verify_kill_chain_grounding(structured: dict, mappings: dict,
                                findings: dict) -> dict:
    """Every technique_id in Kill Chain output must have come from Threat Intel
    this run; every finding_id must exist. Returns the violations; the caller
    records them in the manifest and never silently drops them."""
    ti_ids = {str(m.get("technique_id", "")).strip().upper()
              for m in mappings.get("mappings", []) if m.get("technique_id")}
    valid_fids = set(finding_id_map(findings))

    ungrounded_tech, unknown_fids = set(), set()
    for a in structured.get("phase_assignments", []):
        for tid in a.get("technique_ids", []) or []:
            if str(tid).strip().upper() not in ti_ids:
                ungrounded_tech.add(str(tid).strip().upper())
        for fid in a.get("finding_ids", []) or []:
            if str(fid).strip().upper() not in valid_fids:
                unknown_fids.add(str(fid).strip().upper())
    for fid in structured.get("unassigned_finding_ids", []) or []:
        if str(fid).strip().upper() not in valid_fids:
            unknown_fids.add(str(fid).strip().upper())

    result = {"ungrounded_technique_ids": sorted(ungrounded_tech),
              "unknown_finding_ids": sorted(unknown_fids)}
    for tid in result["ungrounded_technique_ids"]:
        print(f"[kc-grounding] WARNING: technique {tid} in Kill Chain output "
              f"was never returned by Threat Intel this run")
    for fid in result["unknown_finding_ids"]:
        print(f"[kc-grounding] WARNING: finding id {fid} does not exist")
    return result


# ---------------------------------------------------------------------------
# Phase-vocabulary enforcement — one re-prompt, then a hard error.
# ---------------------------------------------------------------------------
def invalid_phases(structured: dict) -> list:
    """Every phase / missing_phase string not in the fixed vocabulary."""
    bad = []
    for a in structured.get("phase_assignments", []) or []:
        p = a.get("phase")
        if p is not None and p not in PHASE_ORDER:
            bad.append(p)
    for g in structured.get("gaps", []) or []:
        p = g.get("missing_phase")
        if p is not None and p not in PHASE_ORDER:
            bad.append(p)
    return bad


def enforce_phase_vocabulary(client, model, structured: dict) -> dict:
    """If any phase is out-of-vocabulary, re-prompt the model ONCE to snap
    every phase to the fixed vocabulary. If it still fails, raise KillChainError
    (no silent near-miss acceptance)."""
    bad = invalid_phases(structured)
    if not bad:
        return structured
    print(f"[kill_chain] out-of-vocabulary phase(s) {bad}; re-prompting once")
    correction = (
        "Your previous kill-chain output used phase names outside the FIXED "
        f"vocabulary. The ONLY allowed phases are exactly: {PHASES}. "
        f"These values were invalid: {sorted(set(bad))}. Return the SAME JSON "
        "object with every 'phase' and every 'missing_phase' replaced by the "
        "closest allowed phase. Output ONLY the JSON object, no prose, no code "
        "fence.\n\nJSON:\n" + json.dumps(structured))
    resp = agent_core._chat(
        client, model,
        [{"role": "system", "content": "You output only a corrected JSON object."},
         {"role": "user", "content": correction}],
        TOOL_DEFS, tool_choice="none")
    raw = (resp.choices[0].message.content or "").strip()
    raw = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw, flags=re.S).strip()
    try:
        fixed = json.loads(raw)
    except json.JSONDecodeError:
        fixed, _ = agent_core.extract_json_block(raw)
    if fixed is None:
        raise KillChainError(
            f"re-prompt did not return parseable JSON; original bad phases {bad}")
    still_bad = invalid_phases(fixed)
    if still_bad:
        raise KillChainError(
            f"phase vocabulary still violated after one re-prompt: {still_bad}")
    print("[kill_chain] phase vocabulary corrected on the single allowed re-prompt")
    return fixed


# ---------------------------------------------------------------------------
# Retry evaluation (handoff §3) — computed in CODE, not by asking the model.
# Kept here so it is unit-testable; the workflow router calls it.
# ---------------------------------------------------------------------------
def _phase_is_mid_campaign(missing_phase: str, assigned_phases: set) -> bool:
    """A gap is a mid-campaign HOLE (worth a retry) rather than a missing
    bookend if assigned phases exist both before and after it in kill-chain
    order — the canonical order being the proxy for temporal ordering."""
    if missing_phase not in PHASE_ORDER:
        return False
    idx = PHASE_ORDER[missing_phase]
    before = any(PHASE_ORDER[p] < idx for p in assigned_phases if p in PHASE_ORDER)
    after = any(PHASE_ORDER[p] > idx for p in assigned_phases if p in PHASE_ORDER)
    return before and after


def _is_high_severity(finding: dict) -> bool:
    return str((finding or {}).get("severity", "")).strip().lower() == "high"


def evaluate_retry(structured: dict, findings: dict, grounding: dict) -> dict:
    """Evaluate the three retry trigger conditions in code and, if any fires,
    build the STRUCTURED retry request Threat Intel will receive. Always
    returns a decision record (including the negatives) so the manifest can
    show the branch was considered.

    Conditions (any fires the edge):
      1. phase_gap             — a mid-campaign hole (not a missing bookend)
      2. unassigned_high_severity — an unassigned finding is NA-high-severity
      3. ungrounded_technique  — grounding flagged a technique TI never returned
    """
    fmap = finding_id_map(findings)
    assigned = {a.get("phase") for a in structured.get("phase_assignments", [])
                if a.get("phase")}

    gap_ids = [g.get("missing_phase") for g in structured.get("gaps", []) or []
               if _phase_is_mid_campaign(g.get("missing_phase"), assigned)]
    cond_phase_gap = bool(gap_ids)

    high_unassigned = [fid for fid in structured.get("unassigned_finding_ids", []) or []
                       if _is_high_severity(fmap.get(str(fid).strip().upper()))]
    cond_high = bool(high_unassigned)

    ungrounded = list(grounding.get("ungrounded_technique_ids", []))
    cond_ungrounded = bool(ungrounded)

    conditions = {"phase_gap": cond_phase_gap,
                  "unassigned_high_severity": cond_high,
                  "ungrounded_technique": cond_ungrounded}

    # priority order matches the handoff's listing. The `reason` codes are
    # internal (manifest/routing); the `question` sent to Threat Intel is kept
    # strictly in technique/tactic terms — never phase language — so Threat
    # Intel stays phase-invariant (its job is mapping, not phase assignment).
    if cond_phase_gap:
        reason, targets = "phase_gap", []
        tactics = sorted({t for gp in gap_ids for t in PHASE_TO_TACTICS.get(gp, [])})
        question = ("Re-examine the findings for an additional ATT&CK technique "
                    "the evidence supports"
                    + (f", especially in the {', '.join(tactics)} tactic(s)"
                       if tactics else "")
                    + ". If none applies, say so explicitly.")
    elif cond_high:
        reason, targets = "unassigned_high_severity", high_unassigned
        question = (f"High-severity finding(s) {high_unassigned} received no "
                    "ATT&CK technique mapping. Can you map them to a technique, "
                    "or state why they resist mapping?")
    elif cond_ungrounded:
        reason, targets = "ungrounded_technique", []
        question = (f"Your mappings did not include technique(s) {ungrounded} "
                    "that a downstream step relied on. Supply a grounded mapping "
                    "for the relevant finding(s), or confirm none applies.")
    else:
        return {"retry": False, "conditions": conditions}

    return {"retry": True, "reason": reason, "conditions": conditions,
            "target_finding_ids": [str(t).strip().upper() for t in targets],
            "question": question}


# ---------------------------------------------------------------------------
# 3. AGENT CONFIGURATION
# ---------------------------------------------------------------------------
KC_MAX_TURNS = 8

SYSTEM_PROMPT = textwrap.dedent(f"""\
    You are a kill-chain analyst. You receive (a) a set of ATT&CK technique
    mappings produced by a threat-intelligence analyst and (b) the original
    network-analyst findings they refer to. You reason about the intrusion AS
    A WHOLE: which kill-chain phase each finding belongs to, the ordered story
    of the campaign, and what appears to be missing. Respond in English only.

    The kill-chain phases are FIXED and are exactly these six, in order:
    {PHASES}. Use ONLY these strings — no synonyms, no near-misses.

    You have a budget of {KC_MAX_TURNS} turns. Method:
    1. Call list_phase_definitions first to reason against the stated rubric.
    2. For each mapping, consider the finding (get_finding_detail) and the
       technique's tactic (get_technique_context).
    3. To sequence findings, call get_temporal_ordering — do NOT infer order
       from timestamps yourself; ordering is computed for you in code.
    4. Assign findings to phases with a short justification each. Cite ONLY
       technique IDs that appear in the mappings you were given; do not invent
       techniques. Note phases that appear MISSING (gaps) and findings you
       cannot place (unassigned).
    5. While investigating, write at most one short sentence between tool
       calls. Save the analysis for the final report.

    When done, output your analysis as markdown for humans (the phase story,
    the gaps, and why). Then end with a machine-readable summary: a fenced
    ```json code block of exactly this shape —
    {{"phase_assignments": [{{"phase": "<one of the six>",
      "finding_ids": ["F1", ...], "technique_ids": ["T1046", ...],
      "justification": "2-4 sentences", "confidence": "high|medium|low"}}],
     "narrative": "ordered prose account of the campaign as understood",
     "gaps": [{{"missing_phase": "<one of the six>", "reasoning": "..."}}],
     "unassigned_finding_ids": ["F11", ...]}}

    Every finding_id and technique_id must come from the input. gaps and
    unassigned_finding_ids may be empty lists.
    """)


def build_task(mappings: dict, findings: dict) -> str:
    """Render the TI mappings + NA findings into the Kill Chain task prompt,
    using the shared F1..Fn numbering."""
    fmap = finding_id_map(findings)
    lines = ["Assign each finding below to a kill-chain phase and reason about "
             "the campaign as a whole.", "", "NETWORK ANALYST FINDINGS:"]
    for fid, f in fmap.items():
        lines.append(f"\n[{fid}] {f.get('title', 'untitled')}")
        for key in ("severity", "confidence", "source_ips", "destination_ips",
                    "ports", "flow_count", "evidence_summary"):
            if f.get(key) not in (None, [], ""):
                lines.append(f"  {key}: {f[key]}")
    lines += ["", "THREAT INTEL ATT&CK MAPPINGS:"]
    for m in mappings.get("mappings", []):
        lines.append(f"\n- finding {m.get('finding_id')}: "
                     f"{m.get('technique_id')} ({m.get('technique_name')}) "
                     f"tactic={m.get('tactic')} confidence={m.get('confidence')}")
        if m.get("reasoning") or m.get("rationale"):
            lines.append(f"    rationale: {m.get('reasoning') or m.get('rationale')}")
    retry = mappings.get("_kill_chain_followup")   # set on a second pass (M3)
    if retry:
        lines += ["", "NOTE: this is a re-analysis after Threat Intel answered "
                  "a follow-up. Incorporate any new/'declined' mappings above."]
    return "\n".join(lines)


def analyze(client, model, mappings: dict, findings: dict, profile: dict = None,
            plan_mode: bool = False, tool_feedback: bool = False):
    """Run the Kill Chain agent over structured TI mappings + NA findings.
    Returns (markdown, structured_dict_or_None, extras) where extras =
    {"injection": <manifest entry or None>, "grounding": {...},
     "phase_divergence": {...}}. Phase vocabulary is enforced (one re-prompt,
     then hard error); grounding and divergence are computed in code and
     attached to the structured output."""
    _load_run_context(mappings, findings)
    system_prompt = SYSTEM_PROMPT
    injection_entry = None
    if profile is not None and env is not None:
        system_prompt, injection_entry = env.inject(system_prompt, profile, "kill_chain")

    report = agent_core.run_agent(
        client, model, build_task(mappings, findings), system_prompt,
        TOOL_DEFS, TOOLS_IMPL, max_turns=KC_MAX_TURNS, label="kill_chain",
        plan_mode=plan_mode, tool_feedback=tool_feedback)

    structured, md = agent_core.extract_json_block(report)
    if structured is None:
        print("[kill_chain] WARNING: no parseable JSON block in Kill Chain output")
        return md, None, {"injection": injection_entry, "grounding": {},
                          "phase_divergence": {}}

    structured = enforce_phase_vocabulary(client, model, structured)
    structured.setdefault("phase_assignments", [])
    structured.setdefault("gaps", [])
    structured.setdefault("unassigned_finding_ids", [])
    structured.setdefault("narrative", "")

    grounding = verify_kill_chain_grounding(structured, mappings, findings)
    divergence = compute_phase_divergence(structured, mappings)
    structured["phase_divergence"] = divergence
    structured["grounding"] = grounding
    return md, structured, {"injection": injection_entry, "grounding": grounding,
                            "phase_divergence": divergence}


# ---------------------------------------------------------------------------
def selftest():
    """Exercise the pure-code pipeline (crosswalk, divergence, grounding,
    temporal ordering, retry evaluation, vocab check) on a fixture. No LLM."""
    ti.load_attack_data()
    findings = {"findings": [
        {"title": "SYN scan across many ports", "severity": "High",
         "source_ips": ["172.16.0.1"], "ports": [22, 80, 443],
         "first_seen": "7/7/2017 9:00", "flow_count": 5000},
        {"title": "SSH brute force", "severity": "High",
         "source_ips": ["172.16.0.1"], "ports": [22],
         "first_seen": "7/7/2017 9:20", "flow_count": 2000},
        {"title": "Odd outbound beacon", "severity": "Medium",
         "source_ips": ["10.0.0.9"], "ports": [443],
         "first_seen": "7/7/2017 10:00", "flow_count": 40},
    ]}
    mappings = {"mappings": [
        {"finding_id": "F1", "technique_id": "T1046", "technique_name": "Network Service Discovery",
         "tactic": "Discovery", "confidence": "high"},
        {"finding_id": "F2", "technique_id": "T1110", "technique_name": "Brute Force",
         "tactic": "Credential Access", "confidence": "high"},
        {"finding_id": "F3", "technique_id": "T1071", "technique_name": "Application Layer Protocol",
         "tactic": "Command and Control", "confidence": "medium"},
    ]}
    _load_run_context(mappings, findings)

    print("--- expected phases from crosswalk ---")
    print(sorted(derive_expected_phases(mappings)))
    # a model output that mostly agrees but adds an unsupported 'Delivery'
    model_out = {"phase_assignments": [
        {"phase": "Reconnaissance", "finding_ids": ["F1"], "technique_ids": ["T1046"],
         "justification": "port scan", "confidence": "high"},
        {"phase": "Actions on Objectives", "finding_ids": ["F2"], "technique_ids": ["T1110"],
         "justification": "cred access", "confidence": "high"},
        {"phase": "Delivery", "finding_ids": ["F3"], "technique_ids": ["T1071"],
         "justification": "model thinks delivery", "confidence": "low"}],
        "gaps": [{"missing_phase": "Exploitation", "reasoning": "no exec seen"}],
        "unassigned_finding_ids": []}

    print("--- phase divergence ---")
    print(json.dumps(compute_phase_divergence(model_out, mappings), indent=2))
    print("--- grounding (inject fake technique) ---")
    bad = json.loads(json.dumps(model_out))
    bad["phase_assignments"][0]["technique_ids"].append("T9999")
    print(json.dumps(verify_kill_chain_grounding(bad, mappings, findings), indent=2))
    print("--- temporal ordering ---")
    print(get_temporal_ordering(["F1", "F2", "F3"]))
    print("--- retry evaluation ---")
    print(json.dumps(evaluate_retry(model_out, findings,
                     verify_kill_chain_grounding(model_out, mappings, findings)), indent=2))
    print("--- vocab check ---")
    assert invalid_phases({"phase_assignments": [{"phase": "Recon"}]}) == ["Recon"]
    assert invalid_phases(model_out) == []
    print("[selftest] Kill Chain pure-code pipeline OK")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true",
                    help="run the pure-code pipeline on a fixture (no LLM)")
    ap.add_argument("--mappings", help="path to a mappings.json from Threat Intel")
    ap.add_argument("--findings", help="path to a findings.json from Network Analyst")
    ap.add_argument("--environment", help="environment profile id (optional)")
    ap.add_argument("--provider", choices=sorted(agent_core.PROVIDERS), default="ollama")
    ap.add_argument("--model", default=None)
    ap.add_argument("--plan", action="store_true")
    ap.add_argument("--tool-feedback", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        selftest()
        raise SystemExit(0)
    if not (args.mappings and args.findings):
        ap.error("--mappings and --findings are required (or use --selftest)")

    client, model = agent_core.setup_client(args.provider, args.model)
    with open(args.mappings, encoding="utf-8") as f:
        mappings = json.load(f)
    with open(args.findings, encoding="utf-8") as f:
        findings = json.load(f)
    profile = None
    if args.environment:
        if env is None:
            raise SystemExit("[config] environment package not importable")
        profile = env.load_profile(args.environment)
        from environment.validator import validate_or_raise, CIC_IDS2017_LABELS
        validate_or_raise(profile, CIC_IDS2017_LABELS)

    md, structured, extras = analyze(client, model, mappings, findings, profile=profile,
                                     plan_mode=args.plan, tool_feedback=args.tool_feedback)
    print("\n" + "=" * 70 + "\nKILL CHAIN\n" + "=" * 70 + "\n" + (md or ""))
    if structured is not None:
        print("\n[divergence]", json.dumps(structured.get("phase_divergence", {})))
    agent_core.save_report("kill_chain", model, md, structured)
