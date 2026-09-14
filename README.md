# AI Cyber Analyst

A multi-agent AI system that investigates and *explains* threats in network flow
data. Raw flows go in; a four-agent pipeline detects suspicious activity, maps it
to MITRE ATT&CK, reasons about it as a kill-chain narrative, and writes an
incident report — with every claim grounded in verifiable evidence. Built across
a summer internship on the *See One → Do One → Teach One* model.

## What this is — and what it is NOT

**This is an explanation-and-triage system that sits *downstream* of detection.**
It helps a human get through the alert queue and understand what they're looking
at.

**This is NOT a production intrusion detector.** It is not tuned for a real SOC,
not benchmarked for detection accuracy, and not safe to point at a live network
as a gatekeeper. It runs on labeled research datasets so its *explanations* can
be measured. The language model is deliberately not used as a detector — it's a
poor one. Treat this as a research and teaching artifact.

## The four agents

1. **Network Analyst** — reads a flow CSV through narrow, deterministic pandas
   tools (it never sees raw rows) and produces plain-language findings with cited
   evidence. The `Label` column is quarantined at load time.
2. **Threat Intelligence** — maps findings to MITRE ATT&CK techniques, querying
   the real STIX bundle so IDs can't be hallucinated. Grounding is enforced in
   code: any technique ID the tools didn't return is flagged unverified.
3. **Kill Chain** — assigns findings to kill-chain phases with justifications;
   code independently derives an expected phase set and reports the *divergence*.
4. **Report Writer** — synthesizes the three structured outputs into the final
   report for a stated audience, computing nothing new.

Two capped feedback edges (Threat Intel → Network Analyst, Kill Chain → Threat
Intel) add the only dynamism; routing is otherwise deterministic code, no
supervisor LLM. Ground truth lives only in the evaluation sidecar, which scores
runs *after* the agents finish. See `docs/architecture.md` for the diagram and
the all-important quarantine boundary, and `docs/design_decisions.md` for the
reasoning behind every non-obvious choice.

## Setup

```
python -m venv .venv
# Windows: .venv\Scripts\Activate.ps1   |   macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

Provider key (for `--provider claude`): set `ANTHROPIC_API_KEY`. For local
inference use `--provider ollama` with `OLLAMA_CONTEXT_LENGTH` set. The MITRE
ATT&CK bundle (~50 MB) downloads and caches on the first Threat Intel run.

## Usage

```
# full four-agent workflow: flows -> findings -> mappings -> kill chain -> report + eval
python src/workflow.py --csv <day>.csv --provider claude --environment enterprise_dmz --plan

# demo the Network Analyst <-> Threat Intel feedback edge
python src/workflow.py --csv <day>.csv --force-evidence-request

# no model / no data needed — just export the graph diagram
python src/workflow.py --diagram-only

# single agents (for testing a stage in isolation)
python src/threat_intel.py --selftest        # tools + grounding, no LLM
python src/kill_chain.py --selftest          # pure-code pipeline, no LLM

# tests
python -m pytest -q
```

Providers: `--provider claude | ollama | openai | custom`. Omit `--environment`
to run with no environment context (the absence is logged in the manifest).

Each run writes `outputs/<timestamp>_<model>/` with `findings`, `mappings`,
`kill_chain`, `report.md`, `eval.txt`, and `manifest.json` (the reproducibility
ledger).

## Datasets

- **CIC-IDS2017** (`GeneratedLabelledFlows`) — from the Canadian Institute for
  Cybersecurity (University of New Brunswick), search "CIC-IDS2017". Extract into
  `GeneratedLabelledFlows/TrafficLabelling/`. Large and git-ignored.
- **DAPT 2020** — the phase-labeled APT dataset (Myneni et al.), used for
  kill-chain phase scoring. Not committed; point the loader at it with
  `root=...`.
- **Teaching slice** — a small (~2.9 MB) real slice with a genuine brute-force
  attack is committed at `course/lab/data/` so the lab needs no large download.
- The MITRE ATT&CK STIX bundle is cached under `data/` on first run (git-ignored).

## Repository layout

| Path | Purpose |
|---|---|
| `src/agent_core.py` | Shared machinery: providers, compat + transient retry, the agent loop, report I/O |
| `src/network_analyst.py` | Network Analyst: data layer, tools, prompt, CLI |
| `src/threat_intel.py` | Threat Intel: ATT&CK data layer, tools, grounding check, CLI |
| `src/kill_chain.py` | Kill Chain: crosswalk, divergence, tools, retry evaluation, CLI |
| `src/report_writer.py` | Report Writer: synthesis agent, grounding recheck, CLI |
| `src/workflow.py` | LangGraph graph: nodes, two feedback edges, routers, diagram export |
| `src/run_manifest.py` | The per-run reproducibility ledger |
| `src/eval_sidecar.py` | All scorers + the answer key and phase crosswalk (agents never see it) |
| `environment/` | Environment profiles, validator, per-agent injection matrix |
| `datasets/` | Canonical flow schema, loader registry, CIC + DAPT loaders |
| `tests/` | Full test suite (run from repo root: `pytest -q`) |
| `course/` | Five modules, the tiered lab (+ committed data slice), outline, descriptions |
| `docs/` | `architecture.md`, `design_decisions.md`, `reflections.md`, briefings, diagrams |

## License

See `LICENSE`. Note this is university internship work — confirm the intended
license with the University of Utah before any public release.
