# AI Cyber Analyst — Summer Internship Project

A multi-agent AI system that assists cybersecurity analysts in detecting,
investigating, and explaining threats in network log data. Built as part of a
summer internship following the *See One → Do One → Teach One* model.

**Status: Week 3** — Network Analyst + Threat Intelligence agents connected
in a LangGraph workflow with one capped feedback edge.
Upcoming: Kill Chain Reasoning Agent (week 4), Report Agent + course
materials (week 5).

## The agents

**Network Analyst** reads a CIC-IDS2017 network-flow CSV, investigates it
through six deterministic pandas tools, and produces plain-language findings
with cited evidence — plus a machine-readable JSON summary for downstream
agents. The dataset's ground-truth `Label` column is quarantined at load time
(the agent never sees it) and used afterward by the evaluation sidecar:
HIT / PARTIAL / MISS per attack, plus candidate false positives.

**Threat Intelligence** (new in Week 3) maps those findings to MITRE ATT&CK
techniques. Same three-layer design, different dataset: it queries the real
`enterprise-attack.json` STIX bundle (downloaded and cached on first run)
through three tools — `list_tactics`, `search_techniques`, `get_technique`.
Grounding is enforced by code, not prompt: every technique ID the tools
return is recorded, and any ID in the agent's output that the tools never
returned is flagged `"verified": false` with a loud warning. If a finding
lacks evidence to map confidently, the agent emits an *evidence request*
instead of guessing.

**Workflow** (LangGraph): deterministic routing *between* agents, agentic
tool-calling loops *within* agents — no supervisor LLM. The one dynamic
element is a single, capped feedback edge: if the TI agent requests more
evidence, the Network Analyst gets exactly one targeted follow-up pass.
The communication diagram (`workflow_diagram.mmd` / `.png`) is generated
from the compiled graph, so it cannot drift from the code.

## Setup

```
python -m venv .venv && .venv/bin/pip install -r requirements.txt
```

API key (for `--provider claude`): put `ANTHROPIC_API_KEY=sk-ant-...` in a
`.env` file (gitignored), then load it into your shell before running:
`set -a; source .env; set +a`.

Dataset: CIC-IDS2017 `GeneratedLabelledFlows.zip` from cicresearch.ca,
extracted into `data/TrafficLabelling/` (not committed — see .gitignore).
The MITRE ATT&CK bundle downloads itself into `data/` on first Threat
Intel run.

## Usage

```
# full workflow: CSV -> findings -> mappings -> both evals -> diagram
python src/workflow.py --csv data/TrafficLabelling/<day>.csv --provider claude   # needs ANTHROPIC_API_KEY
python src/workflow.py --csv <day>.csv --force-evidence-request  # demo the feedback edge
python src/workflow.py --diagram-only                            # just the diagram, no LLM

# agents standalone (Week 2 demos still work)
python src/network_analyst.py --provider claude --csv data/TrafficLabelling/<day>.csv
python src/threat_intel.py --findings outputs/<run>/findings.json --provider claude
python src/threat_intel.py --selftest                            # tools + grounding, no LLM

# providers: --provider ollama (default; needs OLLAMA_CONTEXT_LENGTH=16384),
#            claude, openai, or custom (LLM_BASE_URL / LLM_API_KEY / LLM_MODEL)
```

Every run gets its own folder, `outputs/<timestamp>_<model>/` (gitignored),
holding `findings.md`/`.json`, `mappings.md`/`.json`, and `eval.txt` (both
ground-truth evaluations, same text that prints to the terminal). The
generated workflow diagram lands at `outputs/workflow_diagram.mmd`/`.png`
(same every run, so it's just overwritten).

## Repository layout

| Path | Purpose |
|---|---|
| `src/agent_core.py` | Shared machinery: providers, compat retry, the agent loop, report I/O |
| `src/network_analyst.py` | NA agent: CSV data layer, 6 pandas tools, system prompt, CLI |
| `src/threat_intel.py` | TI agent: ATT&CK data layer, 3 tools, grounding check, CLI |
| `src/workflow.py` | LangGraph graph: nodes, feedback edge, Mermaid diagram export |
| `src/eval_sidecar.py` | Both scorers + the attack→technique answer key (agents never see it) |
| `data/` | CIC-IDS2017 CSVs, cached ATT&CK bundle, `sample_findings.json` (synthetic NA output for exercising the TI agent without a live run) |
| `outputs/` | One folder per run (`<timestamp>_<model>/` with findings + mappings), plus the generated workflow diagram |
| `docs/` | Week 2 architecture diagram + briefing, week 3 handoff notes |
