"""
M1 tests — environment profiles, validator, injection matrix.

Covers every reject rule with a positive AND a negative case, the handoff's
named acceptance checks (the DDoS/172.16.0.1 profile, Threat-Intel byte
invariance), and the manifest hashing contract.
"""
import hashlib

import pytest

import environment as env
from environment import validator as V


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------
LABELS = V.CIC_IDS2017_LABELS


def _base_profile(**overrides):
    """A minimal, clean, passing profile; overrides splice in a bad section."""
    p = {
        "schema_version": 1,
        "profile_id": "unit_test",
        "identity": {"monitored_scope": "A small test network.",
                     "organization_type": "Lab."},
        "assets": [{"host": "10.0.0.5", "role": "the web server", "zone": "lan"}],
        "analyst_policy": {"reporting_audience": "engineers"},
    }
    p.update(overrides)
    return p


def _rules_fired(profile):
    return {f.rule for f in V.validate(profile, LABELS).rejections}


# ---------------------------------------------------------------------------
# Shipped profiles load and pass
# ---------------------------------------------------------------------------
def test_two_profiles_ship_and_load():
    assert set(["enterprise_dmz", "personal_laptop"]).issubset(env.available_profiles())
    for pid in ("enterprise_dmz", "personal_laptop"):
        prof = env.load_profile(pid)
        assert prof["profile_id"] == pid


def test_shipped_profiles_pass_validation():
    for pid in ("enterprise_dmz", "personal_laptop"):
        verdict = V.validate(env.load_profile(pid), LABELS)
        assert verdict.passed, (pid, verdict.rejections)


# ---------------------------------------------------------------------------
# Reject rule 1 — label collision
# ---------------------------------------------------------------------------
def test_label_collision_positive():
    prof = _base_profile(identity={"monitored_scope": "We mostly see DDoS here."})
    assert "label_collision" in _rules_fired(prof)


def test_label_collision_negative():
    prof = _base_profile(identity={"monitored_scope": "We mostly see web browsing."})
    assert "label_collision" not in _rules_fired(prof)


def test_label_collision_word_boundary_no_false_positive():
    # 'Bot' is a label; 'robot'/'bottleneck' must NOT trigger it.
    prof = _base_profile(identity={"monitored_scope": "A robot avoids the bottleneck."})
    assert "label_collision" not in _rules_fired(prof)


# ---------------------------------------------------------------------------
# Reject rule 2 — maliciousness assertion
# ---------------------------------------------------------------------------
def test_maliciousness_positive():
    prof = _base_profile(
        assets=[{"host": "10.0.0.5", "role": "10.0.0.5 is the attacker on this LAN",
                 "zone": "lan"}])
    assert "maliciousness_assertion" in _rules_fired(prof)


def test_maliciousness_negative():
    prof = _base_profile(
        assets=[{"host": "10.0.0.5", "role": "10.0.0.5 is the web server", "zone": "lan"}])
    assert "maliciousness_assertion" not in _rules_fired(prof)


def test_maliciousness_predicate_without_ip_does_not_fire():
    # predicate present but no IP/host within the window -> not a rule-2 hit
    prof = _base_profile(identity={"monitored_scope": "Sometimes a device is compromised."})
    assert "maliciousness_assertion" not in _rules_fired(prof)


# ---------------------------------------------------------------------------
# Reject rule 3 — phase / technique pinning
# ---------------------------------------------------------------------------
def test_technique_pinning_positive():
    prof = _base_profile(
        identity={"monitored_scope": "Traffic from 10.0.0.5 maps to T1046."})
    assert "technique_pinning" in _rules_fired(prof)


def test_phase_pinning_positive():
    prof = _base_profile(
        identity={"monitored_scope": "Host 10.0.0.5 handles Reconnaissance."})
    assert "phase_pinning" in _rules_fired(prof)


def test_phase_technique_pinning_negative():
    # phase word alone, no host -> fine; host alone, no phase -> fine
    prof = _base_profile(
        identity={"monitored_scope": "We describe Reconnaissance generally.",
                  "organization_type": "Host 10.0.0.5 is present."})
    fired = _rules_fired(prof)
    assert "phase_pinning" not in fired and "technique_pinning" not in fired


# ---------------------------------------------------------------------------
# Reject rule 4 — verdict language
# ---------------------------------------------------------------------------
def test_verdict_language_positive():
    prof = _base_profile(identity={"monitored_scope": "This flow is an attack."})
    assert "verdict_language" in _rules_fired(prof)


def test_verdict_language_negative():
    prof = _base_profile(identity={"monitored_scope": "This flow is HTTPS to the server."})
    assert "verdict_language" not in _rules_fired(prof)


# ---------------------------------------------------------------------------
# Named acceptance checks from the handoff
# ---------------------------------------------------------------------------
def test_ddos_172_profile_fails_and_names_the_rule():
    prof = _base_profile(
        baseline_behavior={"typical_volume": "the DDoS traffic comes from 172.16.0.1"})
    verdict = V.validate(prof, LABELS)
    assert not verdict.passed
    fired = {r.rule for r in verdict.rejections}
    assert "label_collision" in fired
    # the message must name the offending value so a reviewer can see why
    assert any("DDoS" in r.message for r in verdict.rejections)


def test_validate_or_raise_raises_on_reject():
    prof = _base_profile(identity={"monitored_scope": "the DDoS is from 172.16.0.1"})
    with pytest.raises(V.ProfileValidationError):
        V.validate_or_raise(prof, LABELS)


def test_validate_or_raise_returns_verdict_on_pass():
    verdict = V.validate_or_raise(env.load_profile("enterprise_dmz"), LABELS)
    assert verdict.passed


# ---------------------------------------------------------------------------
# Warnings (log, don't block)
# ---------------------------------------------------------------------------
def test_absolute_quantifier_warns_not_blocks():
    prof = _base_profile(
        analyst_policy={"elevated_concern": ["always treat inbound as hostile"]})
    verdict = V.validate(prof, LABELS)
    assert verdict.passed                       # warning, not rejection
    assert any(w.rule == "absolute_quantifier" for w in verdict.warnings)


# ---------------------------------------------------------------------------
# Injection matrix + renderer
# ---------------------------------------------------------------------------
def test_threat_intel_allowlist_is_explicitly_empty():
    assert env.ENVIRONMENT_INJECTION["threat_intel"] == []


def test_threat_intel_prompt_byte_identical_across_profiles():
    """The §1.3 invariance: Threat Intel sees no environment context, so its
    injected prompt (and hash) is identical for every profile."""
    base = "SYSTEM PROMPT BODY"
    p1, e1 = env.inject(base, env.load_profile("enterprise_dmz"), "threat_intel")
    p2, e2 = env.inject(base, env.load_profile("personal_laptop"), "threat_intel")
    assert p1 == p2 == base                     # unchanged
    assert e1["rendered_sha256"] == e2["rendered_sha256"]
    assert e1["rendered_sha256"] == hashlib.sha256(b"").hexdigest()
    assert e1["injected_sections"] == []


def test_network_analyst_prompt_differs_across_profiles():
    base = "SYSTEM PROMPT BODY"
    p1, e1 = env.inject(base, env.load_profile("enterprise_dmz"), "network_analyst")
    p2, e2 = env.inject(base, env.load_profile("personal_laptop"), "network_analyst")
    assert p1 != p2
    assert e1["rendered_sha256"] != e2["rendered_sha256"]
    assert base in p1 and "## Environment context" in p1


def test_injection_respects_matrix_sections():
    prof = env.load_profile("enterprise_dmz")
    # Kill Chain gets crown_jewels; Network Analyst does not.
    _, kc = env.inject("x", prof, "kill_chain")
    _, na = env.inject("x", prof, "network_analyst")
    assert "crown_jewels" in kc["injected_sections"]
    assert "crown_jewels" not in na["injected_sections"]
    # Network Analyst gets expected_services / baseline_behavior; Kill Chain not.
    assert "expected_services" in na["injected_sections"]
    assert "expected_services" not in kc["injected_sections"]


def test_report_writer_gets_reporting_audience_only_policy():
    prof = env.load_profile("enterprise_dmz")
    _, rw = env.inject("x", prof, "report_writer")
    assert "analyst_policy.reporting_audience" in rw["injected_sections"]
    assert "analyst_policy.elevated_concern" not in rw["injected_sections"]


def test_unknown_agent_raises():
    with pytest.raises(KeyError):
        env.render_environment(env.load_profile("enterprise_dmz"), "nope")


def test_render_is_deterministic():
    prof = env.load_profile("enterprise_dmz")
    a = env.render_environment(prof, "kill_chain")
    b = env.render_environment(prof, "kill_chain")
    assert a == b and a  # stable and non-empty
