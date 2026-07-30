"""
M4 quarantine test — mechanically enforce that ground truth never reaches an
agent. The Loader's ground_truth()/phase_ground_truth() are sidecar-only; this
greps every agent module source and fails if either symbol appears. Cheap, and
it makes the quarantine enforced rather than merely intended (handoff §4).
"""
import os

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")

# The agent modules — code that runs INSIDE the agent graph and could leak a
# label into a prompt or tool return. eval_sidecar.py is intentionally NOT
# here: it is the one place ground truth is allowed to live.
AGENT_MODULES = ["agent_core.py", "network_analyst.py", "threat_intel.py",
                 "kill_chain.py", "report_writer.py", "workflow.py"]

QUARANTINED = ["ground_truth", "phase_ground_truth"]


def test_agent_modules_do_not_reference_ground_truth():
    offenders = []
    for mod in AGENT_MODULES:
        path = os.path.join(SRC, mod)
        with open(path, encoding="utf-8") as f:
            text = f.read()
        for sym in QUARANTINED:
            if sym in text:
                offenders.append(f"{mod} references quarantined symbol {sym!r}")
    assert not offenders, offenders


def test_sidecar_symbols_exist_on_loader():
    # sanity: the quarantined methods really are on the Loader interface
    from datasets.cic_ids2017 import CicIds2017Loader
    loader = CicIds2017Loader()
    assert hasattr(loader, "ground_truth") and hasattr(loader, "phase_ground_truth")
