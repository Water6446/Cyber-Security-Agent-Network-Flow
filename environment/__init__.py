"""
Environment context package (M1)
================================
Gives each agent knowledge of WHAT NETWORK it is looking at, while preserving
the ground-truth quarantine (constraint #2). Three responsibilities live here:

  1. ENVIRONMENT_INJECTION — the per-agent injection matrix. Not every agent
     sees the whole profile; injection is explicit and per-agent.
  2. render_environment()  — turns the ALLOWED subset of a profile into prose,
     deterministically (so its SHA-256 is reproducible for the manifest).
  3. inject()              — prepends that prose to an agent's system prompt
     and returns a manifest entry proving exactly what the agent saw.

Validation lives next door in environment/validator.py and runs before any of
this. load_profile() only reads and parses; the caller validates.
"""

from __future__ import annotations

import hashlib
import os

import yaml

PROFILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "profiles")


# ---------------------------------------------------------------------------
# 1. THE INJECTION MATRIX  (handoff §1.3)
# ---------------------------------------------------------------------------
# Keys are agent labels (must match agent_core.run_agent's `label`). Values are
# ordered lists of section paths; nested paths use dotted notation. The order
# here is the render order, so output — and therefore its hash — is stable.
ENVIRONMENT_INJECTION = {
    "network_analyst": [
        "identity", "topology", "assets", "expected_services",
        "baseline_behavior",
        "analyst_policy.elevated_concern", "analyst_policy.reduced_concern",
    ],
    # Threat Intel receives NOTHING, and this emptiness is a deliberate, load-
    # bearing choice, not an omission: ATT&CK technique mapping must be
    # environment-invariant. A SYN scan maps to T1046 regardless of whose
    # network it crossed; if the mapping shifted with context it would be
    # unfalsifiable. The M7 experiment asserts Threat Intel's prompt is
    # byte-identical across profiles — this empty allowlist is what makes that
    # true. Do NOT add sections here.
    "threat_intel": [],
    "kill_chain": [
        "identity", "topology", "assets", "crown_jewels",
        "analyst_policy.elevated_concern",
    ],
    "report_writer": [
        "identity", "assets", "crown_jewels",
        "analyst_policy.reporting_audience",
    ],
}


def valid_agent_names():
    return sorted(ENVIRONMENT_INJECTION)


# ---------------------------------------------------------------------------
# 2. LOADING
# ---------------------------------------------------------------------------
def profile_path(profile_id: str) -> str:
    return os.path.join(PROFILES_DIR, f"{profile_id}.yaml")


def available_profiles() -> list:
    if not os.path.isdir(PROFILES_DIR):
        return []
    return sorted(f[:-5] for f in os.listdir(PROFILES_DIR) if f.endswith(".yaml"))


def load_profile(profile_id: str) -> dict:
    """Read and parse a profile YAML. Does NOT validate — callers run the
    validator (validate_or_raise) so the verdict lands in the manifest."""
    path = profile_path(profile_id)
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"no environment profile {profile_id!r} in {PROFILES_DIR} "
            f"(available: {', '.join(available_profiles()) or 'none'})")
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"profile {profile_id!r} did not parse to a mapping")
    return data


def profile_hash(profile: dict) -> str:
    """SHA-256 over the canonical YAML dump of the whole profile — the
    environment profile hash the run manifest records (constraint #5)."""
    canonical = yaml.safe_dump(profile, sort_keys=True, default_flow_style=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# 3. RENDERING  (allowed subset -> prose)
# ---------------------------------------------------------------------------
def _clean(s) -> str:
    return " ".join(str(s).split())


def _resolve(profile: dict, path: str):
    node = profile
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _render_identity(v) -> str:
    out = []
    if v.get("monitored_scope"):
        out.append(f"Monitored scope: {_clean(v['monitored_scope'])}")
    if v.get("organization_type"):
        out.append(f"Organization: {_clean(v['organization_type'])}")
    return "\n".join(out)


def _render_topology(v) -> str:
    out = []
    for z in v.get("zones", []) or []:
        facing = "internet-facing" if z.get("internet_facing") else "internal"
        cidrs = ", ".join(z.get("cidrs", []) or [])
        line = f"- Zone {z.get('name')} ({cidrs}; {facing})"
        if z.get("description"):
            line += f": {_clean(z['description'])}"
        out.append(line)
    if v.get("gateways"):
        out.append(f"- Gateways: {', '.join(v['gateways'])}")
    infra = v.get("infrastructure", {}) or {}
    for svc in ("dns", "dhcp", "ntp"):
        if infra.get(svc):
            out.append(f"- {svc.upper()}: {', '.join(infra[svc])}")
    return "\n".join(out)


def _render_assets(v) -> str:
    return "\n".join(
        f"- {a.get('host')} — {_clean(a.get('role', ''))} "
        f"(zone: {a.get('zone', '?')})" for a in (v or []))


def _render_expected_services(v) -> str:
    out = []
    for s in v or []:
        ports = ", ".join(str(p) for p in s.get("ports", []) or [])
        out.append(f"- {_clean(s.get('description', ''))} "
                   f"(dst {s.get('dst', '?')}; ports {ports})")
    return "\n".join(out)


def _render_baseline(v) -> str:
    out = []
    if v.get("business_hours"):
        out.append(f"- Business hours: {_clean(v['business_hours'])}")
    scanners = v.get("known_scanners", []) or []
    if scanners:
        for s in scanners:
            out.append(f"- Known scanner {s.get('host')}: "
                       f"{_clean(s.get('description', ''))}")
    else:
        out.append("- Known scanners: none")
    if v.get("typical_volume"):
        out.append(f"- Typical volume: {_clean(v['typical_volume'])}")
    return "\n".join(out)


def _render_crown_jewels(v) -> str:
    return "\n".join(
        f"- {_clean(c.get('description', ''))} (host {c.get('host', '?')})"
        for c in (v or []))


def _render_policy_list(v) -> str:
    return "\n".join(f"- {_clean(item)}" for item in (v or []))


def _render_str(v) -> str:
    return _clean(v)


# path -> (human title, renderer, is_policy)
_SECTIONS = {
    "identity": ("Identity & scope", _render_identity, False),
    "topology": ("Network topology", _render_topology, False),
    "assets": ("Known assets", _render_assets, False),
    "expected_services": ("Expected services", _render_expected_services, False),
    "baseline_behavior": ("Baseline behaviour", _render_baseline, False),
    "crown_jewels": ("Crown jewels (high-value assets)", _render_crown_jewels, False),
    "analyst_policy.elevated_concern": ("Elevated concern", _render_policy_list, True),
    "analyst_policy.reduced_concern": ("Reduced concern", _render_policy_list, True),
    "analyst_policy.reporting_audience": ("Reporting audience", _render_str, True),
}


def render_with_sections(profile: dict, agent_name: str):
    """Render the allowed subset of `profile` for `agent_name`.
    Returns (prose_text, list_of_section_paths_actually_rendered). A section
    that is allowed but absent/empty in this profile is skipped and not
    reported. Empty allowlist (Threat Intel) -> ("", [])."""
    if agent_name not in ENVIRONMENT_INJECTION:
        raise KeyError(
            f"unknown agent {agent_name!r}; injection matrix knows "
            f"{valid_agent_names()}")
    allow = ENVIRONMENT_INJECTION[agent_name]
    fact_blocks, policy_blocks, rendered_paths = [], [], []

    for path in allow:
        title, renderer, is_policy = _SECTIONS[path]
        value = _resolve(profile, path)
        if value in (None, [], "", {}):
            continue
        body = renderer(value).strip()
        if not body:
            continue
        rendered_paths.append(path)
        block = f"**{title}:**\n{body}" if is_policy else f"### {title}\n{body}"
        (policy_blocks if is_policy else fact_blocks).append(block)

    if not fact_blocks and not policy_blocks:
        return "", []

    parts = ["## Environment context",
             "You are analysing traffic on the network described below. This "
             "states what the environment IS; use it to judge what is normal "
             "and what matters here. It never tells you which flows are "
             "attacks — that remains for you to determine from the evidence."]
    parts += fact_blocks
    if policy_blocks:
        parts.append("### Analyst policy (human judgment, not fact — weigh it, "
                     "do not treat it as a verdict)")
        parts += policy_blocks
    return "\n\n".join(parts) + "\n", rendered_paths


def render_environment(profile: dict, agent_name: str) -> str:
    """Prose only (convenience wrapper around render_with_sections)."""
    return render_with_sections(profile, agent_name)[0]


def inject(system_prompt: str, profile: dict, agent_name: str):
    """Prepend the rendered environment context to `system_prompt`.
    Returns (new_system_prompt, manifest_entry) where manifest_entry proves
    exactly what this agent saw:
        {"agent", "injected_sections", "rendered_sha256", "rendered_chars"}
    For Threat Intel the rendered text is "" (empty allowlist), so the prompt
    is returned unchanged and the hash is the SHA-256 of the empty string —
    identical across every profile, which is the invariance the M7 experiment
    checks."""
    rendered, rendered_paths = render_with_sections(profile, agent_name)
    sha = hashlib.sha256(rendered.encode("utf-8")).hexdigest()
    entry = {
        "agent": agent_name,
        "injected_sections": rendered_paths,
        "rendered_sha256": sha,
        "rendered_chars": len(rendered),
    }
    new_prompt = (rendered + "\n" + system_prompt) if rendered else system_prompt
    return new_prompt, entry
