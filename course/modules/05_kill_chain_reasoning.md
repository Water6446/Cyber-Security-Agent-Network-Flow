# Module 5 — Kill Chain Reasoning

**Estimated time:** 45–60 minutes
**Prerequisites:** Modules 2 and 4.

The third load-bearing module, and the one where the project's most interesting idea lives: making a model's *reasoning* the object of study, and measuring where it departs from a mechanical mapping.

## Learning objectives

1. Describe the Lockheed Martin Cyber Kill Chain, its history, and its limits.
2. Explain "phases as narrative structure" versus "phases as a classification target."
3. Walk through this project's taxonomy gap between its six phases and DAPT 2020's four stages.
4. Explain the model-proposes / code-derives / verifier-diverges design and why divergence is a feature.
5. End on the right note: models are lenses, not truth.

## 1. The Lockheed Martin kill chain

In 2011, Lockheed Martin published the **Cyber Kill Chain**: a model of an intrusion as an ordered sequence of stages an attacker must pass through. This project uses a six-phase form: **Reconnaissance → Delivery → Exploitation → Installation → Command and Control → Actions on Objectives.** The idea is intuitive and useful: an attacker researches a target, delivers a payload, exploits a weakness to run code, installs persistence, establishes a control channel, and finally acts on their goal (steal data, disrupt, etc.).

Its value is *narrative*: it turns a pile of disconnected alerts into a story with a direction, and it tells a defender that breaking any one link disrupts the chain.

Its **limits** matter just as much, and the project leans into them rather than hiding them:

- It was designed from the **defender's outside-in view** of a *single* intrusion — malware arriving from outside. It describes perimeter breach well.
- It has **no lateral-movement phase** at all. Once an attacker is inside and moving host-to-host, the classic kill chain has no vocabulary for it — a real gap for modern, post-compromise activity.
- Real intrusions are **not strictly linear**; stages overlap, repeat, or are skipped. Treating the chain as a rigid checklist misleads.

## 2. Phases as narrative vs. phases as a classification target

There are two very different things you can do with the six phases, and confusing them is a common mistake.

You can treat a phase as a **classification target** — a label you're trying to predict correctly, scored against a "right answer." Or you can treat it as **narrative structure** — a frame the analyst uses to organize what happened into a coherent story.

This project deliberately treats phases as *narrative*. The Kill Chain agent's job is to produce a justified account of the campaign — which findings belong to which phase and *why* — not to hit a label. This is why its output is prose with justifications, and why the interesting measurement is not "accuracy" but *coherence* and *divergence* (Section 4). The moment you make phase a classification target, you're back to needing labels you don't have (Module 3) and you've thrown away the thing the model is actually good at: reasoning you can read.

## 3. The taxonomy gap (DAPT 2020 as the worked example)

To measure phase reasoning at all, the project uses DAPT 2020, one of the few datasets with per-flow *stage* labels. But DAPT uses **four** APT stages, and this system uses **six** Lockheed phases, and they do not line up cleanly. Rather than paper over the mismatch, the project builds the crosswalk explicitly, with *primary* and *acceptable-alternate* mappings:

| DAPT stage | Primary phase | Acceptable alternates | Why it's messy |
|---|---|---|---|
| Reconnaissance | Reconnaissance | — | clean 1:1 |
| Foothold Establishment | Exploitation | Delivery, Installation | delivery and exploitation collapse when you only have flow data |
| Lateral Movement | Reconnaissance | Exploitation, Actions on Objectives | **genuine gap** — Lockheed has no lateral-movement phase |
| Data Exfiltration | Actions on Objectives | Command and Control | the data is exfiltrated *to* a C&C host, so both are defensible |

Because the mapping is genuinely ambiguous, scoring **never reports a single blended number**. It reports three buckets — *primary agreement*, *alternate agreement*, *disagreement* — so a reader can see how much of a "miss" is real error versus honest taxonomy ambiguity. This honesty is the point: a system that reported "72% accurate" here would be hiding the fact that the 28% includes cases where two experts would also disagree.

## 4. Model proposes, code derives, the verifier diverges

Here is the design that makes this more than a lookup table. There is a tension in the project: it wants to *emphasize the model's reasoning*, but its standing rule is *code computes*. The resolution:

1. **The model proposes.** The Kill Chain agent assigns findings to phases *with written justifications*. This prose is the artifact of interest — it is the model's reasoning, and it is allowed to be creative.
2. **Code derives, independently.** Separately, code computes an *expected* set of phases purely mechanically: for each technique the Threat Intel agent returned, look up its tactic in the real ATT&CK data and map that tactic to a phase via a fixed crosswalk. This computation never touches the model.
3. **The verifier diverges.** A comparison step reports **phase divergence** — phases the model assigned that the crosswalk doesn't support, and phases the crosswalk implies that the model didn't assign.

Divergence is **not an error** — it is the most interesting output the system produces. When the model's narrative departs from the mechanical mapping, one of two things is true, and both are worth seeing. Sometimes the model is wrong (and you've caught it). Sometimes the crosswalk is too coarse and the model's reasoning is *better* — for example, arguing that a brute-force attempt against a public server is best read as *Exploitation* (a perimeter-breach attempt) even though the mechanical tactic→phase table files Credential Access under *Actions on Objectives*. A lookup table can never disagree with itself; an agent that can reason will, and those disagreements are exactly where the analytical value is.

The project also computes two label-free checks that generalize to data with no ground truth at all: **ordering coherence** (does the assigned phase sequence respect the timeline, or does it claim Installation happened before Delivery?) and **impossible jumps** (Actions on Objectives with no prior Delivery or Exploitation anywhere in the run). These need no answer key, which is why they'll still work on your own network later.

## 5. Models are lenses, not truth

End here. The kill chain is a *lens* — a way of looking that clarifies some things and distorts others (it has no lateral-movement phase, remember). ATT&CK is another lens. The language model is a third. None of them is the territory; each is a way of seeing it.

The reason the project measures *divergence* rather than *accuracy* is that it takes this seriously. It does not ask "did the model get the phase right?" as if there were a single truth to get. It asks "where do these lenses disagree, and what does each disagreement teach us?" That is a more honest, and ultimately more useful, way to build and evaluate a reasoning system — and it is the habit of mind worth carrying out of this course.

## Key terms

- **Cyber Kill Chain:** Lockheed Martin's ordered model of an intrusion's stages.
- **Phase (this project):** one of six — Reconnaissance, Delivery, Exploitation, Installation, Command and Control, Actions on Objectives.
- **Narrative vs. classification target:** a frame for telling the story vs. a label to predict.
- **Crosswalk:** the explicit tactic→phase (and DAPT-stage→phase) mapping, with primary + alternates.
- **Phase divergence:** where the model's assignment and the code-derived crosswalk disagree — recorded, not treated as error.
- **Ordering coherence / impossible jump:** label-free checks that the phase story respects time and can't skip prerequisites.

## Check your understanding

1. **Name a real limitation of the Lockheed kill chain and why it matters here.**
   No lateral-movement phase — which is exactly why DAPT's Lateral Movement stage has no clean home and forces an acceptable-alternates mapping.

2. **What's the difference between treating a phase as narrative vs. as a classification target?**
   Narrative organizes the story with justifications; a classification target is a label to predict against a right answer (which we mostly don't have).

3. **Why does phase scoring report three buckets instead of one accuracy number?**
   Because the taxonomy mapping is genuinely ambiguous; three buckets separate real error from honest disagreement, which one number would hide.

4. **Why is model/crosswalk divergence a feature rather than a bug?**
   It's where reasoning departs from mechanical mapping — sometimes catching a model error, sometimes revealing the crosswalk is too coarse; a lookup table can't produce that signal at all.

5. **Which two checks still work with no ground truth, and what do they test?**
   Ordering coherence (does the phase sequence respect the timeline) and impossible jumps (Actions on Objectives with no prior Delivery/Exploitation).

## Further reading

- Lockheed Martin, "The Cyber Kill Chain" (original whitepaper).
- Myneni et al., DAPT 2020 (and its Unraveled follow-up) — the phase-labeled datasets.
- This project's `kill_chain.py` (the crosswalk and divergence functions) and `eval_sidecar.py` (three-bucket scoring, coherence, impossible jumps).
