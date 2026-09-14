"""pytest path shim and shared fixtures.

The repo mixes top-level packages (environment/, datasets/) with flat modules
in src/ (agent_core, threat_intel, ...). Scripts run as `python src/workflow.py`,
which puts src/ on sys.path; tests run from the repo root. This conftest puts
BOTH on the path so either import style resolves during testing.
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.abspath(__file__))
for p in (ROOT, os.path.join(ROOT, "src")):
    if p not in sys.path:
        sys.path.insert(0, p)


@pytest.fixture(scope="session")
def attack_data():
    """The MITRE ATT&CK STIX bundle, loaded once per session.

    The bundle (~50 MB) is downloaded from MITRE CTI on first use and cached in
    the git-ignored data/. Tests that need it request this fixture, so an
    offline machine or a CI runner without egress reports skips instead of a
    wall of failures. Everything not asking for it runs with no network at all.
    """
    import threat_intel as ti
    try:
        ti.load_attack_data()
    except Exception as exc:                      # network, DNS, TLS, disk, ...
        pytest.skip(f"MITRE ATT&CK bundle unavailable ({type(exc).__name__}: "
                    f"{exc}); needs network on first run")
    return ti
