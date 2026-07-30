# Module 4 — MITRE ATT&CK

**Estimated time:** 45–60 minutes
**Prerequisites:** Modules 1–2.

The second load-bearing module. ATT&CK is the shared vocabulary the whole system reasons in, and it is also where the project solves a concrete hallucination problem.

## Learning objectives

1. Define tactics, techniques, and procedures, and how they relate.
2. Read an ATT&CK technique page and pull out what matters.
3. Explain why a controlled *ID vocabulary* matters more than it first appears.
4. Explain the hallucination problem this project solves by binding the model to the local STIX dataset.

## 1. Tactics, techniques, procedures (TTPs)

ATT&CK is a curated knowledge base of how real adversaries behave, organized in three layers of increasing specificity.

- A **tactic** is the adversary's *goal* — the "why." Examples: Reconnaissance, Credential Access, Command and Control, Exfiltration. There are roughly a dozen-plus tactics, and they loosely correspond to stages of an intrusion.
- A **technique** is *how* they achieve that goal. "Brute Force" (T1110) is a technique under the Credential Access tactic. Techniques have stable IDs of the form `T####`, sometimes with a **sub-technique**: T1110.001 is "Password Guessing," a more specific flavor of Brute Force.
- A **procedure** is the concrete, in-the-wild implementation — the specific tool or command a particular group used to carry out the technique.

The mental model: tactic = *why*, technique = *what*, procedure = *exactly how, this time*. This project works mostly at the technique level (the Threat Intelligence agent maps findings to techniques) and uses the tactic layer as the bridge to kill-chain phases (Module 5).

## 2. Reading a technique page

Every technique has a page with a predictable structure. When you open T1110 (Brute Force), the parts worth reading are:

- **The ID and name** — the stable handle everyone agrees on (`T1110`).
- **The tactic(s)** it belongs to — here, Credential Access. A technique can sit under more than one tactic, which matters for phase mapping later.
- **The description** — what the behavior is.
- **Sub-techniques** — the more specific children (Password Guessing, Password Cracking, Password Spraying, Credential Stuffing). "Prefer the most specific technique the evidence supports" is the analyst's rule: cite T1110.001 when you can see it's password guessing, T1110 when you can't tell which flavor.
- **Detection and data sources** — how you'd actually see it, which tells you whether your data (flows) can even support the mapping.

In this project, the Threat Intelligence agent's tools return exactly these fields, and its `list_subtechniques` tool exists precisely so it can compare the four Brute Force children in one call before choosing.

## 3. Why an ID vocabulary matters more than it looks

At first glance "T1110" is just a label — why not describe the attack in plain English? Because a **controlled vocabulary** buys you things prose cannot:

- **It is unambiguous and checkable.** "Brute force" in prose could mean a dozen things; `T1110.001` means exactly one, and you can verify it exists.
- **It is a join key.** Because everyone uses the same IDs, a finding tagged `T1110.001` connects to detection guidance, to threat-intel reports about groups that use it, to the crosswalk that maps it to a kill-chain phase. The ID is what lets separate systems talk.
- **It bounds the space.** There is a finite, published set of valid IDs. That finiteness is what makes the next section's defense possible — you can check membership.

The whole system's reasoning is more trustworthy *because* it flows through this vocabulary. A finding that maps to a technique ID is a finding you can audit; a finding described only in prose is one you have to take on faith.

## 4. The hallucination problem, and the fix

Here is the specific failure this project was built to prevent. Ask a language model to map a behavior to ATT&CK and it will happily produce an ID — but the model's memory of ATT&CK is fuzzy. It will sometimes invent a plausible-looking ID (`T1595.002` when it means something else), misnumber a real one, or cite a technique that was deprecated years ago. These are **hallucinated technique IDs**, and they are dangerous precisely because they look authoritative — a wrong `T####` sails past a human who assumes the machine looked it up.

The fix has two parts, both structural:

1. **Bind the model to the local STIX dataset.** ATT&CK is published in a machine-readable format called STIX. This project downloads and indexes the real bundle, and the Threat Intelligence agent's tools (`search_techniques`, `get_technique`, `list_subtechniques`) return only IDs that exist in that dataset, with deprecated/revoked entries filtered out at load time. The model doesn't recall an ID; it *looks one up*.

2. **Verify grounding in code (Module 2).** After the agent finishes, code extracts every `T####` from its output and checks each against the set of IDs the tools actually returned this run. Any ID the tools never returned is flagged **unverified**. The model cannot argue with the log.

Together these turn "trust the model's ATT&CK knowledge" into "the model may only cite what the real dataset returned, and we check." That is the difference between a demo and something an analyst could rely on.

## Key terms

- **Tactic / technique / sub-technique / procedure:** why / what / a specific flavor of what / exactly-how-this-time.
- **Technique ID (`T####`):** the stable, unambiguous handle for a technique.
- **STIX:** the machine-readable format ATT&CK is published in.
- **Controlled vocabulary:** a fixed, published set of valid terms you can check membership against.
- **Hallucinated ID:** a technique ID the model asserts that no real lookup produced.
- **Grounding (again):** code-side verification that every cited ID came from a tool.

## Check your understanding

1. **Put tactic, technique, and procedure in order of specificity and give the T1110 example.**
   Tactic (Credential Access, the goal) → technique (T1110 Brute Force, the how) → procedure (the exact tool a group used). Sub-technique T1110.001 sits between technique and procedure.

2. **Name two things a technique ID gives you that a prose description does not.**
   Unambiguous checkability and a join key that connects to detection guidance, threat intel, and the phase crosswalk.

3. **Why is a hallucinated technique ID especially dangerous?**
   It looks authoritative, so a human assumes it was looked up and doesn't re-check it.

4. **Describe the two-part fix and why each part is needed.**
   Bind the model to the real STIX dataset so tools return only valid IDs, *and* verify in code that every cited ID came from a tool — the first constrains the source, the second catches anything the model emits from memory anyway.

5. **Why prefer the most specific technique the evidence supports, rather than always citing the parent?**
   Specificity carries more analytical information (Password Guessing vs. generic Brute Force), but only when the evidence actually distinguishes it — otherwise you'd be asserting more than you know.

## Further reading

- MITRE ATT&CK website — browse T1110 and its sub-techniques as you read Section 2.
- The `mitreattack-python` library and the enterprise-attack STIX bundle.
- This project's `threat_intel.py` — the data layer and the `verify_output_grounding` function.
