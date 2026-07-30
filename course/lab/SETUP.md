# Lab Setup

Follow these once before the session. Budget ~15 minutes.

## 1. Python and dependencies

You need Python 3.10+ (3.13 is fine). From the repository root:

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
```

## 2. A model provider

Pick one:

- **Anthropic (Claude)** — set an API key. Fastest and most reliable for the lab.
  ```
  # PowerShell
  $env:ANTHROPIC_API_KEY = "sk-ant-..."
  ```
  Run with `--provider claude`.
- **Local (Ollama)** — install Ollama, pull a model, and set the context length so nothing silently truncates:
  ```
  ollama pull qwen2.5:14b
  $env:OLLAMA_CONTEXT_LENGTH = "8192"
  ```
  Run with `--provider ollama`. Slower on a laptop; plan for it.

The MITRE ATT&CK data (~50 MB) downloads and caches automatically on the first run that touches the Threat Intel agent. After that it's offline.

## 3. The data

**You do not need the full datasets.** A small, real slice is committed at:

```
course/lab/data/tuesday_teaching_slice.csv
```

It is ~2.9 MB, 6,500 flows, and contains a genuine FTP/SSH brute-force attack (from 172.16.0.1) mixed with benign traffic — enough for a real triage exercise without a multi-gigabyte download.

If you *want* the full CIC-IDS2017 data (not required), it's available from the University of New Brunswick (search "CIC-IDS2017 GeneratedLabelledFlows"). It is git-ignored on purpose.

## 4. Smoke test (no model, ~10 seconds)

Confirm the code runs before you rely on it:

```
python -m pytest -q
python src/workflow.py --diagram-only
```

The first should report all tests passing; the second writes the pipeline diagram without needing a model or data.

## 5. Expected runtimes (modest hardware)

On the provided slice:

| Provider | Full 4-agent run |
|---|---|
| Claude (haiku) | ~1–2 minutes |
| Ollama (qwen2.5:14b, laptop GPU) | ~4–8 minutes |

The full CIC days (300k–450k flows) take longer to load but the per-agent time is similar, since the agents work over computed summaries, not raw rows. Add `--plan` to watch the agents narrate their reasoning as they go.

## Troubleshooting

- **`SchemaError: unrecognised CIC-IDS2017 schema`** — you pointed `--csv` at a non-CICFlowMeter file. Use the provided slice.
- **`no API key found`** — set the provider's key (Section 2) or switch `--provider`.
- **A run stops with a connection error** — transient network blips are retried automatically; if it persists, check connectivity or your key.
- **Ollama run is very slow / out of memory** — lower `OLLAMA_CONTEXT_LENGTH`, or use the Claude provider for the lab.
