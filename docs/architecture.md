# Architecture

This system turns raw network flow data into a grounded incident report through
four agents connected by a small, mostly-deterministic graph. This document
shows the data flow, the two capped feedback edges, the per-agent environment
injection, and — most importantly — the **quarantine boundary** between what
the evaluation sidecar can see and what the agents can.

> A diagram generated directly from the compiled graph is at
> `docs/workflow_diagram.png` (source: `docs/workflow_diagram.mmd`). The Mermaid
> below is hand-authored to add the two things the auto-generated graph cannot
> show: the injection matrix and the sidecar boundary.

## The pipeline and its two retry loops

```mermaid
flowchart LR
    CSV[("Raw flows<br/>(CIC-IDS2017 / DAPT)")] --> NA

    subgraph AGENTS["Agent graph — sees NO ground truth"]
        direction LR
        NA["Network Analyst<br/><i>detect + evidence</i>"]
        TI["Threat Intelligence<br/><i>ATT&CK mapping</i>"]
        KC["Kill Chain<br/><i>phase narrative</i>"]
        RW["Report Writer<br/><i>synthesis</i>"]
        NA -->|findings| TI
        TI -->|mappings| KC
        KC -->|phases| RW
        TI -. "evidence request<br/>(≤1 retry)" .-> NA
        KC -. "mapping request<br/>(≤1 retry)" .-> TI
    end

    RW --> REPORT[["report.md"]]
    NA -. tool calls .- DATA[("flows in pandas<br/>Label column removed")]

    ENV[["Environment profile<br/>(per-agent injection)"]] -.->|identity, topology,<br/>assets, baseline, policy| NA
    ENV -.->|NOTHING<br/>(invariance)| TI
    ENV -.->|identity, topology,<br/>assets, crown jewels| KC
    ENV -.->|identity, assets,<br/>crown jewels, audience| RW

    %% ===== the boundary that matters =====
    SIDE["Evaluation Sidecar<br/><i>HIT/MISS, mapping quality,<br/>phase three-bucket scoring</i>"]
    LABELS[("GROUND TRUTH<br/>Label column · phase stages · answer key · crosswalk")]
    LABELS --> SIDE
    REPORT --> SIDE
    DATA --> SIDE

    MANIFEST[["manifest.json<br/>reproducibility ledger"]]
    AGENTS --> MANIFEST

    classDef gt fill:#7f1d1d,stroke:#7f1d1d,color:#fff;
    classDef agent fill:#eef5f7,stroke:#028090,color:#13293d;
    class LABELS,SIDE gt;
    class NA,TI,KC,RW agent;
```

**Read the boundary as the most important line on the page.** Everything inside
`AGENTS` reasons without ever seeing a label. Ground truth — the `Label` column,
DAPT's phase stages, the ATT&CK answer key, and the stage→phase crosswalk —
lives **only** in the sidecar (red), which runs *after* the agents and compares
their output to the truth. No label ever enters an agent's prompt, a tool
return, or any file an agent reads. A test (`tests/test_quarantine.py`) greps
the agent modules and fails if the quarantined symbols appear there, so this is
enforced mechanically, not just by intention.

## Data flow, step by step

1. **Load.** `datasets/` normalizes the CSV to a canonical flow schema and
   splits off the `Label` column (kept for the sidecar only). Schema probing
   raises a clear error on an unrecognized header rather than producing nulls.
2. **Network Analyst** investigates the flows with narrow, code-computed tools
   (it never sees raw rows) and emits structured **findings** with evidence.
3. **Threat Intelligence** maps each finding to ATT&CK **techniques**, citing
   only IDs its tools returned (grounding-checked in code).
4. **Kill Chain** assigns findings to kill-chain **phases** with justifications,
   and code independently derives an expected phase set to compute
   **divergence**.
5. **Report Writer** synthesizes the three structured outputs into the final
   **report** — computing nothing new.
6. **Sidecar** scores everything against ground truth; the **manifest** records
   how the run was configured and what happened.

## The two feedback edges (both capped at one)

The graph is deterministic except for two feedback edges, each firing at most
once and each *decided in code*, never by asking the model whether it wants to
retry:

- **Threat Intel → Network Analyst.** If Threat Intel needs more evidence to map
  a finding, the Network Analyst gets one targeted follow-up pass.
- **Kill Chain → Threat Intelligence.** If the kill-chain view has a mid-campaign
  gap, an unassigned high-severity finding, or an ungrounded technique, Threat
  Intel gets one follow-up pass — phrased purely in technique/tactic terms so
  no kill-chain-phase language leaks into Threat Intel's (deliberately
  phase-invariant) context.

A per-loop counter guarantees the cap; an absolute node-visit ceiling backs it
up as a safety net. Every routing decision, including "no retry needed," is
logged to the manifest.

## The environment injection matrix

An environment profile tells agents *what network they're looking at*. Injection
is **per-agent and explicit** — not every agent gets every section:

| Section | Network Analyst | Threat Intel | Kill Chain | Report Writer |
|---|:-:|:-:|:-:|:-:|
| identity | ✓ | — | ✓ | ✓ |
| topology | ✓ | — | ✓ | — |
| assets | ✓ | — | ✓ | ✓ |
| expected_services | ✓ | — | — | — |
| baseline_behavior | ✓ | — | — | — |
| crown_jewels | — | — | ✓ | ✓ |
| analyst_policy.elevated_concern | ✓ | — | ✓ | — |
| analyst_policy.reduced_concern | ✓ | — | — | — |
| analyst_policy.reporting_audience | — | — | — | ✓ |

**Threat Intel receives nothing, on purpose.** ATT&CK mapping must be
environment-invariant — a SYN scan maps to T1046 regardless of whose network it
crossed — so its injected prompt is byte-identical across every profile (the
SHA-256 of the empty string). The manifest records, per agent, exactly which
sections were injected and a hash of the rendered text, so you can prove after
the fact what each agent saw.

## Where computation lives

The standing rule is **code computes, the model transcribes.** Every number,
count, ordering, and membership check that can be derived deterministically is
derived in code; the model selects tools, reasons over the returned evidence,
and writes prose. The model never produces a figure that a tool didn't compute,
and grounding checks verify it after the fact.
