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


if __name__ == "__main__":
    # No CLI of its own — but "verify the answer key" is a useful standalone check.
    verify_answer_key()
