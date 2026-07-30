# Reflections

These answer the project's reflection questions directly. They're written in the
first person because they're mine — the decisions and second-guesses are what I
actually thought through.

## How does the agent justify its conclusions?

The honest version of this answer is: it justifies them by making every claim
traceable to a tool result, and by keeping the ground truth out of its sight so
the justification is earned rather than copied. The best way to show that is to
trace a single finding all the way from a flow to the final report and mark
where each claim entered.

Take the brute-force finding from the Tuesday run.

**In the flows.** The raw CSV has ~446,000 flow records. Somewhere in there,
13,835 of them share a source (172.16.0.1), a destination (192.168.10.50), two
ports (21 and 22), tiny payloads, and short durations. The Network Analyst never
sees these rows. It has the `Label` column removed before it gets anything.

**Network Analyst.** The agent calls `top_talkers`, then — this is the important
part — it does *not* immediately accuse the busiest host. It sees 192.168.10.3
with 60k flows, forms the hypothesis "port scan," tests it with `count_by`, finds
it's 59,833 DNS queries, and *drops it*. It then finds 172.16.0.1 owns SSH and
FTP, confirms with `count_by` (who), `flow_time_range` (when: 02:09–10:30), and
`flag_summary` (how: SYN-heavy, consistent with failed attempts). The finding it
writes — "brute force against 192.168.10.50 on FTP/SSH, 13,835 flows" — is
**entirely composed of numbers its tools computed**. That's the first place a
claim enters, and every number in it is code-derived. Nothing was estimated from
a sample.

**Threat Intelligence.** It receives the finding (not the flows) and searches
the real ATT&CK STIX data. It confirms T1110.001 (Password Guessing) with
`get_technique`, which lists SSH and FTP as commonly targeted services. The claim
"this is T1110.001" enters here — and it is grounded: after the agent finishes,
code checks that T1110.001 was actually returned by a tool this run. It was, so
it's marked verified. If the model had typed a technique ID from memory, the
grounding check would have flagged it.

**Kill Chain.** It receives the mapping and the finding (still not the flows). It
uses `get_temporal_ordering` (code, not its own reading of timestamps) to
sequence, and assigns the finding to a phase — arguing, in prose, for
Exploitation because a brute-force attempt against a public server is a
perimeter-breach attempt. The claim "this belongs to the Exploitation phase"
enters here as the *model's reasoning*. Separately, code derived that the
crosswalk expects Actions on Objectives (Credential Access tactic), and the run
recorded the divergence. So even the phase claim carries its own audit trail:
here's what the model argued, here's what the mechanical mapping said, here's
where they differ.

**Report Writer.** It synthesizes the three structured outputs into prose for
the SOC audience. It introduces no new numbers or techniques — a final grounding
check confirms it cited only T1110.001. The report's every figure can be walked
backward through this exact chain.

So the justification isn't "the model said so." It's a chain in which each claim
entered at a known point, was computed by code or checked against code, and never
touched the answer key. That's what I mean by a report you can trust.

## What would a human analyst still do better?

Plenty, and it's worth being specific rather than gracious about it.

- **Knowing what's normal for *this* network without being told.** My system
  only knows the environment because I wrote it a profile. A human analyst who
  has watched this network for six months knows that 192.168.10.3 is the DNS box
  and that the Sunday 2am scan is just Nessus — tacit context my system has to be
  handed explicitly, and gets wrong when the profile is wrong (as the Friday run
  showed, where the environment policy nudged it toward a false positive).

- **Deciding an alert isn't worth pursuing.** My system investigates what it's
  given and reports what it finds. A good analyst exercises judgment about
  *opportunity cost* — this one's probably nothing, my time is better spent on
  that one. That triage-of-the-triage is exactly the scarce human skill, and I
  don't model it.

- **Picking up the phone.** A human can call the person whose laptop it is and
  ask "were you running a scan at 2am?" — resolving in thirty seconds what the
  system can only speculate about. Out-of-band, social, contextual
  investigation is invisible to a flow-only system.

- **Recognizing that a dataset artifact is a dataset artifact.** CIC-IDS2017 is
  synthetic; some of its "benign" traffic is unnaturally clean and some attacks
  are textbook. A seasoned analyst smells when the data itself is lying. My
  system takes the flows at face value.

The pattern is that everything the human does better is *judgment around the
edges of the evidence* — knowing what to ignore, what's not worth it, and when
the data itself can't be trusted. My system is good at the thing in the middle
(reason over the evidence you're given and explain it), which is real value, but
it's a slice of the job, not the job.

## How would you teach this to another student?

I'd point them at the course (`course/`) — the five modules build the security
and agent concepts from nothing, and the lab makes the three ideas physical: Part
A shows that context changes conclusions, Part B shows why the code/model
boundary is a real decision, and Part C shows that the AI system is itself an
attack surface. I'd have them do Part C even if they skip the rest, because
breaking the grounding verifier teaches more than reading about it.

But I'd also be honest about what I'd do differently knowing what I know now:

- **I'd build the evaluation sidecar and the manifest first, not last.** Almost
  every debugging session came back to "what did this run actually see and do?"
  and the manifest is what answers that. I treated reproducibility as a
  deliverable when it should have been the substrate.

- **I'd design the agent boundaries more defensively from the start.** The
  overlap I had to fix later — Threat Intel drifting into phase reasoning because
  a retry prompt used phase words — was avoidable. Boundaries between agents need
  to be defended in the prompts, not just in the diagram.

- **I'd distrust the model's requests for new tools more, sooner.** When I turned
  on tool feedback, the models lobbied hard for tools that would let each one do
  its neighbor's job or peek at what it shouldn't. The useful signal was there,
  but it was tangled with self-serving requests, and telling them apart took the
  architecture as the referee.

If I could give the next student one sentence, it'd be the one Module 5 ends on:
the model is a lens, not the truth — so build the parts around it that let you
see where the lens is bending the light.
