"""pytest path shim.

The repo mixes top-level packages (environment/, datasets/) with flat modules
in src/ (agent_core, threat_intel, ...). Scripts run as `python src/workflow.py`,
which puts src/ on sys.path; tests run from the repo root. This conftest puts
BOTH on the path so either import style resolves during testing.
"""
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
for p in (ROOT, os.path.join(ROOT, "src")):
    if p not in sys.path:
        sys.path.insert(0, p)
