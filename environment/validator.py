"""
Environment profile validator — the ground-truth gate for context (M1)
======================================================================
An environment profile carries the SAME leakage risk as lessons.md: whoever
writes "the DDoS traffic comes from 172.16.0.1" has handed the agent the
answer. Constraint #2 (ground truth is quarantined) therefore extends to the
profile, and this validator is where that is enforced.

Design principle the rules encode: *the file describes what IS, not what is
BAD about a specific flow or host.* analyst_policy is the one place judgment
is permitted; it is fenced, length-limited, and rendered separately so a
reviewer sees it as opinion, not as a planted conclusion.

The validator is DATASET-AWARE on purpose: reject rule 1 needs the loaded
dataset's label vocabulary (passed in by the caller, which got it from the
dataset loader in datasets/). That is the whole point — a string is only a
"label collision" relative to a dataset's label set.

Behaviour on failure: raise loudly and refuse to run (validate_or_raise).
Either way the structured verdict is returned so the caller can write it into
the run manifest (constraint #5).

    from environment.validator import validate, validate_or_raise, CIC_IDS2017_LABELS
    verdict = validate(profile_dict, label_vocabulary=CIC_IDS2017_LABELS)
    if not verdict.passed: ...
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Any


# ---------------------------------------------------------------------------
# Reference label vocabularies. The loader is the real source (§4:
# Loader.label_vocabulary()); these constants exist so the validator and its
# tests can run without importing the dataset layer, and so the CIC list in
# the handoff is captured verbatim in one place.
# ---------------------------------------------------------------------------
CIC_IDS2017_LABELS = [
    "DDoS", "PortScan", "Bot", "Infiltration", "Heartbleed", "Web Attack",
    "Brute Force", "XSS", "Sql Injection", "DoS Hulk", "DoS GoldenEye",
    "DoS slowloris", "DoS Slowhttptest", "FTP-Patator", "SSH-Patator",
]

# DAPT 2020's activity/stage vocabulary (see datasets/dapt2020.py). Kept here
# so the validator stays dataset-aware for the second dataset too.
DAPT2020_LABELS = [
    "Benign", "Reconnaissance", "Foothold Establishment",
    "Lateral Movement", "Data Exfiltration",
    # activity-level values that also appear as labels:
    "SQL Injection", "XSS", "Authentication Bypass", "Scanning",
    "Directory Bruteforce", "Account Bruteforce", "CSRF", "Malware Download",
    "Command Injection",
]

# The six kill-chain phases in use (kept in sync with kill_chain.PHASES; a
# test asserts they match so this list can't silently drift).
KILL_CHAIN_PHASES = [
    "Reconnaissance", "Delivery", "Exploitation", "Installation",
    "Command and Control", "Actions on Objectives",
]

# ---- regexes ----
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# A loose FQDN/hostname token: at least one dot, alnum/hyphen labels. Excludes
# bare IPs (handled above) and plain words. Deliberately conservative — the
# concrete leakage vector is IP-based; this just widens the net a little.
HOST_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
                     r"[a-zA-Z]{2,}\b")
TECH_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Rule 2 — maliciousness predicates. An IP/host within ~60 chars of one of
# these is asserting who is bad, which is exactly what must not be in a
# profile. Kept as raw predicates; the window check is done in code.
MALICIOUSNESS_PREDICATES = re.compile(
    r"is\s+(?:the\s+)?(?:attacker|malicious|compromised|infected|"
    r"the\s+source\s+of|hostile)"
    r"|belongs\s+to\s+the\s+attacker"
    r"|is\s+conducting"
    r"|performed\s+the",
    re.IGNORECASE)
MALICIOUSNESS_WINDOW = 60

# Rule 4 — verdict language. A profile states facts and policy, never a verdict.
VERDICT_LANGUAGE = re.compile(
    r"this\s+(?:flow|traffic|host)\s+is\s+(?:an\s+)?attack"
    r"|confirmed\s+(?:attack|breach|intrusion)",
    re.IGNORECASE)

# Warn-level: absolute quantifiers over-steer the model. Word-boundary matched.
ABSOLUTE_QUANTIFIERS = re.compile(
    r"\b(?:always|never|all|no\s+legitimate)\b", re.IGNORECASE)

ANALYST_POLICY_ENTRY_MAX_CHARS = 200
DEFAULT_TOKEN_BUDGET = 1200
# Rough char->token estimate (~4 chars/token for English). Good enough for a
# budget warning; the manifest records the estimate, not a promise.
CHARS_PER_TOKEN = 4


@dataclass
class Finding:
    rule: str            # e.g. "label_collision"
    message: str
    path: str            # dotted path into the profile, e.g. "assets[0].role"
    snippet: str = ""


@dataclass
class Verdict:
    profile_id: str
    passed: bool
    rejections: list = field(default_factory=list)   # list[Finding]
    warnings: list = field(default_factory=list)      # list[Finding]
    rendered_char_len: int = 0
    estimated_tokens: int = 0
    label_vocabulary_size: int = 0

    def to_manifest(self) -> dict:
        """Flat, JSON-serialisable form for the run manifest."""
        return {
            "profile_id": self.profile_id,
            "passed": self.passed,
            "rejections": [asdict(f) for f in self.rejections],
            "warnings": [asdict(f) for f in self.warnings],
            "rendered_char_len": self.rendered_char_len,
            "estimated_tokens": self.estimated_tokens,
            "label_vocabulary_size": self.label_vocabulary_size,
        }


class ProfileValidationError(Exception):
    """Raised by validate_or_raise when a profile is rejected."""


# ---------------------------------------------------------------------------
# Leaf collection — every string in the profile, with its dotted path. Rules
# 2 and 3 need per-field windows, so we keep strings field-by-field rather
# than concatenating the whole document (which would create false adjacencies).
# ---------------------------------------------------------------------------
def _iter_string_leaves(node: Any, path: str = ""):
    if isinstance(node, dict):
        for k, v in node.items():
            child = f"{path}.{k}" if path else str(k)
            yield from _iter_string_leaves(v, child)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _iter_string_leaves(v, f"{path}[{i}]")
    elif isinstance(node, str):
        # collapse internal newlines/whitespace so YAML block scalars don't
        # break word-boundary matches across line wraps
        yield path, " ".join(node.split())


def _label_pattern(label: str) -> re.Pattern:
    # Word-boundary around the whole (possibly multi-word) label, spaces
    # allowed to be any whitespace run. Case-insensitive.
    escaped = r"\s+".join(re.escape(part) for part in label.split())
    return re.compile(rf"(?<!\w){escaped}(?!\w)", re.IGNORECASE)


# ---------------------------------------------------------------------------
# The rules
# ---------------------------------------------------------------------------
def _rule_label_collision(leaves, label_vocabulary):
    """Reject 1 — any profile string containing a dataset label value
    (case-insensitive, word-boundary)."""
    out = []
    patterns = [(lbl, _label_pattern(lbl)) for lbl in label_vocabulary]
    for path, text in leaves:
        for lbl, pat in patterns:
            m = pat.search(text)
            if m:
                out.append(Finding(
                    "label_collision",
                    f"contains dataset label value {lbl!r} — a profile must "
                    f"not name attack classes (that is the answer key)",
                    path, _around(text, m.start(), m.end())))
    return out


def _rule_maliciousness(leaves):
    """Reject 2 — an IP or host within ~60 chars of a maliciousness predicate."""
    out = []
    for path, text in leaves:
        for pm in MALICIOUSNESS_PREDICATES.finditer(text):
            lo = max(0, pm.start() - MALICIOUSNESS_WINDOW)
            hi = min(len(text), pm.end() + MALICIOUSNESS_WINDOW)
            window = text[lo:hi]
            if IP_RE.search(window) or HOST_RE.search(window):
                out.append(Finding(
                    "maliciousness_assertion",
                    "an IP/host sits within 60 characters of a maliciousness "
                    f"predicate ({text[pm.start():pm.end()]!r}) — the profile "
                    "must not assert who is malicious",
                    path, _around(text, lo, hi)))
    return out


def _rule_phase_or_technique_pinning(leaves):
    """Reject 3 — a kill-chain phase name OR an ATT&CK technique ID
    co-occurring (in the same field) with a specific IP/host. The profile
    describes the environment; it does not pre-assign phases or techniques to
    hosts. Co-occurrence is scoped to a single field to avoid cross-field
    false positives — a documented, deliberately conservative reading of the
    handoff's 'any co-occurrence'."""
    out = []
    phase_pats = [(p, _label_pattern(p)) for p in KILL_CHAIN_PHASES]
    for path, text in leaves:
        has_ip_or_host = bool(IP_RE.search(text) or HOST_RE.search(text))
        if not has_ip_or_host:
            continue
        tech = TECH_ID_RE.search(text)
        if tech:
            out.append(Finding(
                "technique_pinning",
                f"ATT&CK technique ID {tech.group()} co-occurs with an "
                "IP/host — technique mapping is the Threat Intel agent's job, "
                "not the profile's",
                path, text[:160]))
        for name, pat in phase_pats:
            if pat.search(text):
                out.append(Finding(
                    "phase_pinning",
                    f"kill-chain phase {name!r} co-occurs with an IP/host — the "
                    "profile must not pre-assign phases",
                    path, text[:160]))
                break
    return out


def _rule_verdict_language(leaves):
    """Reject 4 — 'this flow is an attack', 'confirmed breach', etc."""
    out = []
    for path, text in leaves:
        m = VERDICT_LANGUAGE.search(text)
        if m:
            out.append(Finding(
                "verdict_language",
                "states a verdict rather than a fact/policy "
                f"({text[m.start():m.end()]!r})",
                path, _around(text, m.start(), m.end())))
    return out


def _warnings(profile, leaves, rendered_char_len, token_budget):
    out = []
    # absolute quantifiers, but only inside analyst_policy (where they steer)
    policy = profile.get("analyst_policy", {}) or {}
    for path, text in _iter_string_leaves(policy, "analyst_policy"):
        m = ABSOLUTE_QUANTIFIERS.search(text)
        if m:
            out.append(Finding(
                "absolute_quantifier",
                f"analyst_policy uses an absolute quantifier "
                f"({text[m.start():m.end()]!r}); these tend to over-steer the "
                "model", path, _around(text, m.start(), m.end())))
        if len(text) > ANALYST_POLICY_ENTRY_MAX_CHARS:
            out.append(Finding(
                "policy_entry_too_long",
                f"analyst_policy entry is {len(text)} chars (> "
                f"{ANALYST_POLICY_ENTRY_MAX_CHARS}); likely smuggling reasoning "
                "rather than stating a preference", path, text[:80] + "…"))
    est_tokens = rendered_char_len // CHARS_PER_TOKEN
    if est_tokens > token_budget:
        out.append(Finding(
            "over_token_budget",
            f"rendered profile ~{est_tokens} tokens (> budget {token_budget})",
            "<whole profile>"))
    return out


def _around(text, start, end, pad=30):
    lo, hi = max(0, start - pad), min(len(text), end + pad)
    s = text[lo:hi]
    return ("…" if lo else "") + s + ("…" if hi < len(text) else "")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def validate(profile: dict, label_vocabulary, token_budget: int = DEFAULT_TOKEN_BUDGET) -> Verdict:
    """Run every rule. Returns a Verdict (never raises for a rejected profile —
    use validate_or_raise for that). label_vocabulary is the dataset's label
    list (Loader.label_vocabulary())."""
    leaves = list(_iter_string_leaves(profile))
    rendered_char_len = sum(len(t) for _, t in leaves)

    rejections = []
    rejections += _rule_label_collision(leaves, label_vocabulary)
    rejections += _rule_maliciousness(leaves)
    rejections += _rule_phase_or_technique_pinning(leaves)
    rejections += _rule_verdict_language(leaves)

    warnings = _warnings(profile, leaves, rendered_char_len, token_budget)

    return Verdict(
        profile_id=str(profile.get("profile_id", "<unknown>")),
        passed=(len(rejections) == 0),
        rejections=rejections,
        warnings=warnings,
        rendered_char_len=rendered_char_len,
        estimated_tokens=rendered_char_len // CHARS_PER_TOKEN,
        label_vocabulary_size=len(list(label_vocabulary)),
    )


def validate_or_raise(profile: dict, label_vocabulary,
                      token_budget: int = DEFAULT_TOKEN_BUDGET) -> Verdict:
    """Validate and, on rejection, print loudly and raise. Warnings are printed
    but never block. Returns the Verdict on success so the caller can record it
    in the manifest."""
    verdict = validate(profile, label_vocabulary, token_budget)
    for w in verdict.warnings:
        print(f"[profile-validator] WARN [{w.rule}] {w.path}: {w.message}")
    if not verdict.passed:
        print("\n" + "!" * 70)
        print(f"[profile-validator] REJECTED profile {verdict.profile_id!r} — "
              f"refusing to run ({len(verdict.rejections)} violation(s)):")
        for r in verdict.rejections:
            print(f"  [{r.rule}] {r.path}: {r.message}")
            if r.snippet:
                print(f"        …{r.snippet}")
        print("!" * 70)
        raise ProfileValidationError(
            f"profile {verdict.profile_id!r} rejected: "
            + "; ".join(f"{r.rule}@{r.path}" for r in verdict.rejections))
    print(f"[profile-validator] profile {verdict.profile_id!r} passed "
          f"({len(verdict.warnings)} warning(s), ~{verdict.estimated_tokens} "
          f"tokens rendered)")
    return verdict
