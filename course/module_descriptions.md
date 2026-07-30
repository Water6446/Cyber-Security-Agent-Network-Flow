# Module Descriptions (catalog-style)

Short descriptions suitable for a syllabus or course catalog.

**Module 1 — AI in Cybersecurity.**
What a security analyst's day actually looks like, and why the sheer volume of alerts — not any single hard case — is the core problem. Introduces alert fatigue and the base-rate problem, surveys where machine learning has genuinely helped in security and where it has repeatedly disappointed, and explains why large language models change the *shape* of the problem by reasoning and explaining rather than detecting. Frames the whole course's system as explanation-and-triage sitting downstream of detection, not a replacement for it.

**Module 2 — AI Agents.**
The load-bearing distinction between a pipeline (fixed steps) and an agent (chooses the next tool based on what previous calls returned), illustrated with the project's own tool-call logs. Covers the tool-calling loop, why structured tool returns beat free text, and why grounding verification is necessary — because an agent that can call a tool can also fabricate a plausible tool result. Students leave able to read an agent's log as a story and point to the moment its behavior proves it is not a script.

**Module 3 — Cyber Threat Detection.**
The detection background the rest of the course assumes: flows versus packets and why this project uses flows; what CICFlowMeter computes and why each feature exists (tied to the attacks that disturb it); signature-based versus anomaly-based detection and their trade-offs; the base-rate problem restated in terms of precision; and why labeled attack data is scarce and what that scarcity does to the entire field.

**Module 4 — MITRE ATT&CK.**
Tactics, techniques, and procedures and how they relate; how to read a technique page and extract what matters; and why a controlled ID vocabulary matters more than it first appears — it is unambiguous, checkable, and acts as a join key across systems. Culminates in the hallucination problem this project solves by binding the model to the local STIX dataset and verifying every cited ID in code.

**Module 5 — Kill Chain Reasoning.**
The Lockheed Martin Cyber Kill Chain, its history, and its real limits (notably the absence of a lateral-movement phase). Distinguishes phases as *narrative structure* from phases as a *classification target*, and walks through this project's taxonomy gap with DAPT 2020 as the worked example. Introduces the model-proposes / code-derives / verifier-diverges design and argues that divergence between the model's reasoning and the mechanical crosswalk is a feature, not a bug. Ends on the theme that models are lenses, not truth.
