# AI Cyber Analyst — Summer Internship Project

A multi-agent AI system that assists cybersecurity analysts in detecting,
investigating, and explaining threats in network log data. Built as part of a
summer internship following the *See One → Do One → Teach One* model.

**Status: Week 2** — the Network Analyst Agent is working end to end.
Upcoming: Threat Intelligence Agent (MITRE ATT&CK mapping, week 3), Kill Chain
Reasoning Agent (week 4), Report Agent + course materials (week 5).

## Network Analyst Agent

Reads a CIC-IDS2017 network-flow CSV, investigates it through six
deterministic pandas tools, and produces plain-language findings with cited
evidence — plus a machine-readable JSON summary for downstream agents.
The dataset's ground-truth `Label` column is quarantined at load time (the
agent never sees it) and used afterward by an evaluation sidecar that scores
each run: HIT / PARTIAL / MISS per attack, plus candidate false positives.

See `architecture_diagram.svg` and `week2_demo_notes.md` for design and results.

## Setup

```
pip install openai pandas
```

Dataset: CIC-IDS2017 `GeneratedLabelledFlows.zip` from cicresearch.ca,
extracted locally (not committed — see .gitignore).

## Usage

```
# local model via Ollama (default; needs OLLAMA_CONTEXT_LENGTH=16384)
python network_analyst_agent.py --provider ollama --csv <day>.csv

# hosted models (need ANTHROPIC_API_KEY / OPENAI_API_KEY)
python network_analyst_agent.py --provider claude --csv <day>.csv
python network_analyst_agent.py --provider openai --csv <day>.csv

# compare runs / models
python compare_findings.py
```

Each run writes `findings_<date-time>_<model>.md` (+ `.json`) and prints the
evaluation against ground truth.

## Repository layout

| File | Purpose |
|---|---|
| `network_analyst_agent.py` | The agent: data layer, tool layer, agent loop, eval sidecar |
| `compare_findings.py` | Run-to-run / model-to-model consistency matrix |
| `architecture_diagram.svg` | Week 2 deliverable diagram |
| `week2_demo_notes.md` | Results, improvement story, reflection answer |
| `findings_*.md` / `.json` | Sample analyses (deliverable) |
