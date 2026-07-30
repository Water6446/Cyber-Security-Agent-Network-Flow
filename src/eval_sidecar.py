"""
Evaluation sidecar — OUTSIDE the agent graph
============================================
Ground truth stays quarantined: the CIC-IDS2017 Label column and the
attack -> technique answer key below live only here. No agent ever sees
either; evaluation happens after the agents finish, as a sidecar.

Two scorers:
  - evaluate_findings()  — Week 2, unchanged: HIT/PARTIAL/MISS per attack,
                           plus candidate false positives.
  - evaluate_mappings()  — Week 3: CORRECT/PLAUSIBLE/WRONG per attack that
                           the findings covered, plus grounding stats.
"""

import re

# ---------------------------------------------------------------------------
# Week 2 scorer — compares NA findings vs the hidden Label column
# ---------------------------------------------------------------------------
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _flows_touching(ip: str, df) -> int:
    """How many flows have this IP as source or destination (0 if columns absent)."""
    n = 0
    for col in ("Source IP", "Destination IP"):
        if col in df.columns:
            n += int((df[col] == ip).sum())
    return n


def evaluate_findings(findings: str, df, labels):
    """Tally the agent's findings against the hidden Label column:
    - HIT     = the attack's actual source IP is named in the findings
    - PARTIAL = attacker missed, but the victim IP is named
    - MISS    = neither appears
    Plus: every benign IP the findings named = candidate false positive."""
    if labels is None:
        print("[eval] no Label column found")
        return
    print("\n" + "=" * 70 + "\nEVALUATION (agent never saw the Label column)\n" + "=" * 70)
    print("[eval] ground-truth label distribution:")
    print(labels.value_counts().to_string())

    attack_ips = set()
    print("\n[eval] per-attack detection:")
    for label in labels[labels != "BENIGN"].unique():
        sub = df.loc[labels[labels == label].index]
        attacker = str(sub["Source IP"].mode()[0]) if "Source IP" in sub.columns else "?"
        victim = str(sub["Destination IP"].mode()[0]) if "Destination IP" in sub.columns else "?"
        port = str(sub["Destination Port"].mode()[0]) if "Destination Port" in sub.columns else "?"
        attack_ips.update({attacker, victim})
        verdict = ("HIT" if attacker in findings
                   else "PARTIAL (victim named, attacker missed)" if victim in findings
                   else "MISS")
        print(f"  {label:<15} attacker={attacker} -> victim={victim}:{port} "
              f"({len(sub):,} flows)  ...  {verdict}")

    mentioned = set(IP_RE.findall(findings))
    fps = sorted(ip for ip in mentioned - attack_ips if _flows_touching(ip, df) > 0)
    print(f"\n[eval] benign IPs named in findings (candidate false positives): {len(fps)}")
    for ip in fps:
        print(f"  {ip}  (touches {_flows_touching(ip, df):,} flows, none attack-labeled)")


# ---------------------------------------------------------------------------
# Week 3 scorer — TI mappings vs the answer key
# ---------------------------------------------------------------------------
# CIC-IDS2017 label families -> ACCEPTABLE technique IDs ("any of" passes:
# reasonable analysts disagree on exact sub-techniques). Patterns are matched
# with re.search against the raw label, which absorbs the dataset's mangled
# dash encodings ("Web Attack \x96 Brute Force" etc.).
# verify_answer_key() checks every ID against the live ATT&CK dataset.
ANSWER_KEY = [
    (re.compile(r"patator", re.I),                 {"T1110", "T1110.001", "T1110.003"}),
    (re.compile(r"^DoS|DDoS", re.I),               {"T1498", "T1499"}),
    (re.compile(r"portscan", re.I),                {"T1046", "T1595", "T1595.001"}),
    (re.compile(r"web attack.*brute", re.I),       {"T1110", "T1110.001"}),
    (re.compile(r"web attack.*(sql|xss)", re.I),   {"T1190"}),
    (re.compile(r"heartbleed", re.I),              {"T1190", "T1211"}),
    (re.compile(r"^bot", re.I),                    {"T1071", "T1584.005"}),
    (re.compile(r"infiltration", re.I),            {"T1203", "T1204"}),
]


def _acceptable_for(label: str):
    for pattern, ids in ANSWER_KEY:
        if pattern.search(str(label)):
            return ids
    return None


def verify_answer_key() -> list:
    """Check every ID in the answer key against the live ATT&CK dataset
    (exists, not deprecated/revoked). The handoff's starting-point key is not
    to be trusted blindly. Returns the list of bad (pattern, id) pairs."""
    import threat_intel as ti
    ti.load_attack_data()
    bad = []
    for pattern, ids in ANSWER_KEY:
        for tid in sorted(ids):
            if tid not in ti.TECHNIQUES:
                bad.append((pattern.pattern, tid))
                print(f"[eval] ANSWER KEY PROBLEM: {tid} (for /{pattern.pattern}/) "
                      f"is not a current ATT&CK technique")
    if not bad:
        n = sum(len(ids) for _, ids in ANSWER_KEY)
        print(f"[eval] answer key verified: all {n} technique IDs exist and "
              f"are current in ATT&CK")
    return bad


def evaluate_mappings(mappings: dict, findings: dict, df, labels):
    """Score the TI agent's technique mappings against the answer key,
    per attack that the NA findings actually covered:
    - CORRECT    = a mapped ID is in the attack's acceptable set
    - PLAUSIBLE  = wrong technique, but shares a tactic with an acceptable one
    - WRONG      = neither
    Attacks whose attacker IP no finding named are NOT COVERED (that is the
    Week 2 scorer's problem, not the TI agent's). Also reports grounding
    stats: technique IDs cited vs verified against tool output."""
    import threat_intel as ti
    ti.load_attack_data()

    if labels is None:
        print("[eval] no Label column found")
        return
    print("\n" + "=" * 70 + "\nMAPPING EVALUATION (answer key lives only in this sidecar)\n" + "=" * 70)

    # Reproduce threat_intel.build_task's F1..Fn numbering (list order, 1-based)
    finding_by_id = {f"F{i}": f for i, f in enumerate(findings.get("findings", []), 1)}
    maps_by_fid = {}
    for m in mappings.get("mappings", []):
        maps_by_fid.setdefault(str(m.get("finding_id", "")).strip(), []).append(m)

    def _tactics_of(ids):
        out = set()
        for tid in ids:
            out.update(ti.TECHNIQUES.get(tid, {}).get("tactics", []))
        return out

    print("\n[eval] per-attack mapping quality:")
    for label in labels[labels != "BENIGN"].unique():
        sub = df.loc[labels[labels == label].index]
        attacker = str(sub["Source IP"].mode()[0]) if "Source IP" in sub.columns else "?"

        covering = [fid for fid, f in finding_by_id.items()
                    if attacker in [str(ip) for ip in
                                    (f.get("source_ips") or []) + (f.get("destination_ips") or [])]]
        if not covering:
            print(f"  {label:<15} ... NOT COVERED (no finding names attacker {attacker})")
            continue

        acceptable = _acceptable_for(label)
        if acceptable is None:
            print(f"  {label:<15} ... no answer-key entry; skipped")
            continue

        mapped = [m for fid in covering for m in maps_by_fid.get(fid, [])]
        if not mapped:
            print(f"  {label:<15} covered by {'/'.join(covering)} but the TI agent "
                  f"emitted no mapping ... WRONG (unmapped)")
            continue

        mapped_ids = {str(m.get("technique_id", "")).strip().upper() for m in mapped}
        hits = mapped_ids & acceptable
        if hits:
            verdict = f"CORRECT (via {', '.join(sorted(hits))})"
        elif _tactics_of(mapped_ids) & _tactics_of(acceptable):
            verdict = (f"PLAUSIBLE (mapped {', '.join(sorted(mapped_ids))}; same "
                       f"tactic as acceptable {', '.join(sorted(acceptable))})")
        else:
            verdict = (f"WRONG (mapped {', '.join(sorted(mapped_ids))}; acceptable "
                       f"was {', '.join(sorted(acceptable))})")
        print(f"  {label:<15} findings {'/'.join(covering)} ... {verdict}")

    all_maps = mappings.get("mappings", [])
    n_verified = sum(1 for m in all_maps if m.get("verified"))
    print(f"\n[eval] grounding: {n_verified}/{len(all_maps)} mapped technique IDs "
          f"verified against tool output")
    n_ev = len(mappings.get("evidence_requests", []))
    if n_ev:
        print(f"[eval] evidence requests emitted: {n_ev}")


# ---------------------------------------------------------------------------
# Week 4/5 scorer — kill-chain PHASE quality (M5)
# ---------------------------------------------------------------------------
# DAPT stage -> kill-chain phase crosswalk. This table is an ASSERTED JUDGMENT
# CALL, not a fact, and it lives in the sidecar because it encodes the answer.
# DAPT uses four APT stages (plus Benign); this system uses six Lockheed phases;
# they do not align cleanly, and Lockheed has no lateral-movement phase at all
# (it describes a single intrusion from the outside in, not post-compromise
# internal movement). Do not paper over that: 'primary' is the best single
# mapping, 'alternates' are other defensible readings, and scoring reports
# three buckets — NEVER one blended accuracy number.
DAPT_STAGE_TO_PHASE = {
    "benign":                 {"primary": None,          "alternates": set()},
    "reconnaissance":         {"primary": "Reconnaissance", "alternates": set()},
    "foothold establishment": {"primary": "Exploitation",
                               "alternates": {"Delivery", "Installation"}},
    "lateral movement":       {"primary": "Reconnaissance",
                               "alternates": {"Exploitation", "Actions on Objectives"}},
    "data exfiltration":      {"primary": "Actions on Objectives",
                               "alternates": {"Command and Control"}},
}


def _norm_stage(s):
    return " ".join(str(s).strip().lower().split())


def stage_to_phase(stage):
    """(primary_phase_or_None, set_of_acceptable_alternates) for a DAPT stage."""
    entry = DAPT_STAGE_TO_PHASE.get(_norm_stage(stage))
    if not entry:
        return None, set()
    return entry["primary"], set(entry["alternates"])


def _phase_bits():
    import kill_chain as kc          # lazy to avoid import cost / drift
    return kc.PHASE_ORDER, kc.PHASES


def score_phases(pairs):
    """Three-bucket scoring over (predicted_phase, true_stage) pairs:
      primary     — predicted == primary mapping
      alternate   — predicted in the acceptable-alternates set
      disagreement— neither
    Benign / unmapped stages are counted separately, never folded in. Also
    returns a confusion tally keyed (primary_phase, predicted_phase)."""
    buckets = {"primary": 0, "alternate": 0, "disagreement": 0, "benign_or_unmapped": 0}
    confusion, detail = {}, []
    for pred, stage in pairs:
        primary, alts = stage_to_phase(stage)
        if primary is None:
            buckets["benign_or_unmapped"] += 1
            detail.append({"stage": stage, "predicted": pred, "bucket": "benign_or_unmapped"})
            continue
        bucket = ("primary" if pred == primary
                  else "alternate" if pred in alts else "disagreement")
        buckets[bucket] += 1
        confusion[(primary, pred)] = confusion.get((primary, pred), 0) + 1
        detail.append({"stage": stage, "primary": primary, "predicted": pred,
                       "bucket": bucket})
    return {"buckets": buckets, "confusion": confusion, "detail": detail}


def confusion_matrix_text(confusion):
    """Render the (true-primary-phase x predicted-phase) confusion over the six
    phases as a readable grid."""
    _, phases = _phase_bits()
    short = {p: p[:6] for p in phases}
    header = "true\\pred".ljust(16) + "".join(short[p].ljust(8) for p in phases)
    lines = [header]
    for tp in phases:
        row = short[tp].ljust(16)
        for pp in phases:
            row += str(confusion.get((tp, pp), 0)).ljust(8)
        lines.append(row)
    return "\n".join(lines)


# ---- code-only checks (need NO ground truth; generalise to Max's data) ----
def impossible_jumps(assigned_phases):
    """Actions on Objectives asserted with no prior Delivery or Exploitation
    ANYWHERE in the run — an impossible campaign jump. No labels needed."""
    a = set(p for p in assigned_phases if p)
    violations = []
    if "Actions on Objectives" in a and not ({"Delivery", "Exploitation"} & a):
        violations.append("Actions on Objectives assigned with no prior Delivery "
                          "or Exploitation anywhere in the run")
    return violations


def ordering_coherence(ordered_phases):
    """Given the assigned phases in TEMPORAL order (findings sorted by time),
    does the phase sequence respect kill-chain order, or does it claim e.g.
    Installation preceded Delivery? Reports inversions. No labels needed."""
    order, _ = _phase_bits()
    seq = [(p, order[p]) for p in ordered_phases if p in order]
    inversions = [{"position": i, "phase": seq[i][0], "preceded_by": seq[i - 1][0]}
                  for i in range(1, len(seq)) if seq[i][1] < seq[i - 1][1]]
    return {"coherent": not inversions, "inversions": inversions}


def divergence_summary(kill_chain):
    d = (kill_chain or {}).get("phase_divergence", {}) or {}
    mo, co = d.get("model_only", []), d.get("crosswalk_only", [])
    return {"model_only": mo, "crosswalk_only": co, "diverged": bool(mo or co)}


def predicted_phase_by_finding(kill_chain):
    out = {}
    for a in (kill_chain or {}).get("phase_assignments", []):
        for fid in a.get("finding_ids", []) or []:
            out[str(fid).strip().upper()] = a.get("phase")
    return out


def _ordered_finding_ids(findings):
    import kill_chain as kc
    rows = []
    for fid, f in kc.finding_id_map(findings).items():
        ts = kc._finding_first_seen(f)
        if ts is not None:
            rows.append((ts, fid))
    rows.sort()
    return [fid for _, fid in rows]


def true_stage_by_finding(findings, df, phase_labels):
    """Attribute a DAPT stage to each finding by the modal (non-benign) stage
    of the flows touching its named IPs — mirrors evaluate_mappings' attacker
    attribution. phase_labels is a per-flow stage Series aligned to df."""
    import kill_chain as kc
    out = {}
    for fid, f in kc.finding_id_map(findings).items():
        ips = [str(x) for x in (f.get("source_ips") or []) + (f.get("destination_ips") or [])]
        if not ips:
            continue
        mask = None
        for col in ("Source IP", "Destination IP"):
            if col in df.columns:
                m = df[col].astype(str).isin(ips)
                mask = m if mask is None else (mask | m)
        if mask is None:
            continue
        sub = phase_labels[mask]
        sub = sub[sub.astype(str).str.lower() != "benign"]
        if len(sub):
            out[fid] = sub.mode().iloc[0]
    return out


def evaluate_phases(kill_chain, findings, df=None, phase_labels=None,
                    true_stages=None):
    """Kill-chain phase report. The code-only checks (coherence, impossible
    jumps, divergence) ALWAYS run — including when phase_ground_truth is None
    (e.g. CIC-IDS2017). Three-bucket scoring + confusion run only when per-flow
    stage labels are available (DAPT)."""
    print("\n" + "=" * 70 + "\nKILL-CHAIN PHASE EVALUATION (crosswalk lives only "
          "in this sidecar)\n" + "=" * 70)
    pred = predicted_phase_by_finding(kill_chain)
    ordered_phases = [pred[fid] for fid in _ordered_finding_ids(findings) if fid in pred]
    coherence = ordering_coherence(ordered_phases)
    jumps = impossible_jumps([a.get("phase") for a in
                              (kill_chain or {}).get("phase_assignments", [])])
    div = divergence_summary(kill_chain)

    print(f"[eval] ordering coherence: "
          f"{'coherent' if coherence['coherent'] else 'INVERSIONS ' + str(coherence['inversions'])}")
    print(f"[eval] impossible jumps: {jumps or 'none'}")
    print(f"[eval] model/crosswalk divergence: model_only={div['model_only']} "
          f"crosswalk_only={div['crosswalk_only']}")

    result = {"coherence": coherence, "impossible_jumps": jumps, "divergence": div}

    if true_stages is None and df is not None and phase_labels is not None:
        true_stages = true_stage_by_finding(findings, df, phase_labels)
    if true_stages:
        scored = score_phases([(pred.get(fid), stg) for fid, stg in true_stages.items()])
        b = scored["buckets"]
        print(f"[eval] phase agreement — primary={b['primary']} "
              f"alternate={b['alternate']} disagreement={b['disagreement']} "
              f"(benign/unmapped={b['benign_or_unmapped']})")
        print("[eval] confusion (true primary phase x predicted):")
        print(confusion_matrix_text(scored["confusion"]))
        result["phase_agreement"] = scored
    else:
        print("[eval] no phase ground truth for this dataset — code-only checks "
              "reported above (these generalise to unlabelled data)")
    return result


if __name__ == "__main__":
    # No CLI of its own — but "verify the answer key" is a useful standalone check.
    verify_answer_key()
