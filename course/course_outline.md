# Course Outline — AI Agents for Cybersecurity Defense

## Audience and prerequisites

Undergraduate. Assumes comfort with basic networking (IP addresses, ports, protocols) and a scripting language. **No** prior security or machine-learning background is required — the modules build both from the ground up.

## What the course is about

A hands-on introduction to using LLM *agents* for cybersecurity investigation, built around one real system: a four-agent pipeline that takes raw network flow data, investigates it, maps findings to MITRE ATT&CK, reasons about the attack as a kill-chain narrative, and writes an incident report — with every claim grounded in verifiable evidence. The through-line is a single distinction: this is an **explanation-and-triage** system that sits *downstream* of detection, not a detector.

## Module sequence

| # | Module | Focus | Depends on |
|---|---|---|---|
| 1 | AI in Cybersecurity | Why detection is hard; alert fatigue; where ML has and hasn't worked; why LLMs change the *shape* of the problem | — |
| 2 | AI Agents | Pipeline vs. agent; the tool-calling loop; structured returns; why grounding is necessary | 1 |
| 3 | Cyber Threat Detection | Flows vs. packets; CICFlowMeter features; signatures vs. anomalies; the base-rate problem; label scarcity | 1 |
| 4 | MITRE ATT&CK | Tactics/techniques/procedures; reading a technique page; why an ID vocabulary matters; the hallucination fix | 1, 2 |
| 5 | Kill Chain Reasoning | The Lockheed model and its limits; phases as narrative; the DAPT taxonomy gap; model-vs-crosswalk divergence | 2, 4 |

Modules 2, 4, and 5 are the load-bearing ones — they cover the project's specific contribution (agency, grounded ATT&CK mapping, and measured reasoning). Modules 1 and 3 provide the security and detection background that makes the rest legible.

## The lab

A single tiered session (`lab/`) that works for a mixed-ability class:

- **Part A (everyone, no code):** run the pipeline on a provided slice, write an environment profile for a new scenario, re-run, and diff the reports. Teaches the core insight — *context changes conclusions* — with zero code.
- **Part B (technical):** implement a stubbed tool and observe what happens when a computation is moved from code to the model.
- **Part C (stretch):** attempt a prompt injection against the grounding verifier and propose a fix — security thinking about the AI system itself.

A small, real, attack-containing data slice is committed (`lab/data/`), so students don't download gigabytes. Setup and expected runtimes are in `lab/SETUP.md`.

## Contact hours (suggested)

| Component | Hours |
|---|---|
| Modules 1–5 (reading + discussion, ~1 hr each) | 5 |
| Lab session (Parts A–C) | 2–3 |
| **Total** | **7–8** |

Delivered as five ~1-hour sessions plus one 2–3 hour lab, or compressed into a two-day intensive. Each module ends with check-your-understanding questions (answers included) suitable for a quick formative check.

## Assessment ideas

- Module quizzes from the check-your-understanding sets.
- Lab Part A's 300-word write-up (context changes conclusions).
- Lab Part C's injection-and-fix report as the capstone — it best tests whether a student can reason about the system's own attack surface.
