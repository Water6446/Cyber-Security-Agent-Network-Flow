"""
Run manifest — reproducibility ledger (constraint #5)
=====================================================
Every run records enough to be reconstructed and audited after the fact:
sampling params, model + provider, OLLAMA_CONTEXT_LENGTH, dataset + slice
identifiers, environment profile hash, git SHA, per-agent injected sections
and their hashes, the profile validator verdict, retry decisions (including
the "no retry" case), and grounding violations. No exceptions — a run without
a manifest is not a valid run.

Auditability over cleverness (constraint #6): this is a plain accumulator that
writes one JSON file. It holds no logic that changes agent behaviour; it only
records what happened so the transcript can be trusted later.

    m = RunManifest(provider="claude", model="claude-haiku-4-5")
    m.set_dataset("cic_ids2017", "Friday-...-PortScan")
    m.record_environment("enterprise_dmz", phash, verdict.to_manifest())
    m.record_agent_injection(entry)          # from environment.inject()
    m.record_retry_decision({...})           # from the Kill Chain router
    path = m.write()                         # -> outputs/<run>/manifest.json
"""

from __future__ import annotations

import json
import os
import subprocess
import time

import agent_core


def _git_sha() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=agent_core.REPO_ROOT, capture_output=True, text=True, timeout=5)
        sha = out.stdout.strip()
        if out.returncode == 0 and sha:
            dirty = subprocess.run(
                ["git", "status", "--porcelain"], cwd=agent_core.REPO_ROOT,
                capture_output=True, text=True, timeout=5).stdout.strip()
            return sha + ("-dirty" if dirty else "")
    except Exception as e:
        return f"<unavailable: {e}>"
    return "<unavailable>"


class RunManifest:
    def __init__(self, provider: str = None, model: str = None):
        self.data = {
            "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "git_sha": _git_sha(),
            "provider": provider,
            "model": model,
            # sampling params are read at write() time from the live _params
            # dict, because agent_core._chat() mutates it on provider push-back
            # (dropping top_p, renaming max_tokens). We want what actually ran.
            "sampling_params": None,
            "ollama_context_length": os.environ.get("OLLAMA_CONTEXT_LENGTH"),
            "dataset": None,
            "slice": None,
            "environment": None,          # {profile_id, profile_hash, validator_verdict}
            "agent_injection": [],        # list of environment.inject() entries
            "retry_decisions": [],        # every route decision, incl. negatives
            "grounding_violations": [],   # ungrounded technique/finding ids
            "node_visits": [],            # ordered node-visit log (M3 ceiling proof)
            "notes": [],
        }

    # -- configuration --------------------------------------------------------
    def set_run_config(self, provider=None, model=None):
        if provider is not None:
            self.data["provider"] = provider
        if model is not None:
            self.data["model"] = model
        return self

    def set_dataset(self, dataset_id: str, slice_spec):
        self.data["dataset"] = dataset_id
        self.data["slice"] = slice_spec
        return self

    def record_environment(self, profile_id, profile_hash, validator_verdict):
        self.data["environment"] = {
            "profile_id": profile_id,
            "profile_hash": profile_hash,
            "validator_verdict": validator_verdict,
        }
        return self

    def record_no_environment(self):
        """--environment omitted: record that the run had no context, so the
        absence is auditable rather than silent (acceptance criterion M1)."""
        self.data["environment"] = {"profile_id": None,
                                     "note": "run executed with NO environment context"}
        return self

    # -- per-run events -------------------------------------------------------
    def record_agent_injection(self, entry: dict):
        self.data["agent_injection"].append(entry)
        return self

    def record_retry_decision(self, entry: dict):
        self.data["retry_decisions"].append(entry)
        return self

    def record_grounding_violations(self, agent: str, violations: list):
        if violations:
            self.data["grounding_violations"].append(
                {"agent": agent, "violations": list(violations)})
        return self

    def record_node_visit(self, node: str):
        self.data["node_visits"].append(node)
        return self

    def note(self, text: str):
        self.data["notes"].append(text)
        return self

    # -- output ---------------------------------------------------------------
    def write(self, model: str = None, path: str = None) -> str:
        model = model or self.data.get("model") or "unknown-model"
        # snapshot the sampling params that actually ran
        self.data["sampling_params"] = dict(agent_core._params)
        if path is None:
            path = os.path.join(agent_core.run_dir(model), "manifest.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2, default=str)
        print(f"[manifest] run manifest written to {path}")
        return path
