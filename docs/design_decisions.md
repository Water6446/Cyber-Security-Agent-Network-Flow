# Design Decisions

Every non-obvious choice in this project, the reasoning behind it, and the
alternative that was rejected. This is the document that answers "can you
explain *why* it's built this way?" — which is the real test of understanding
the system.

## 1. Code computes, the model transcribes

**Decision.** Any number, count, ratio, ordering, or membership check that can
be derived deterministically is derived in code. The model's job is to select
tools, reason over returned evidence, and produce prose — never to compute.

**Why.** LLMs are unreliable arithmetic engines and confident fabricators. If
the model produces the numbers, you cannot trust them and cannot audit them.
Pushing all computation into code makes every figure in the output traceable to
a deterministic function.

**Rejected alternative.** Let the model read raw data and report what it sees.
This is simpler and more flexible, but it makes hallucinated counts and invented
IPs inevitable and unverifiable. The whole value proposition — a report you can
trust — collapses.

## 2. Ground truth is quarantined in the sidecar

**Decision.** Labels (the `Label` column, DAPT phase stages, the ATT&CK answer
key, the stage→phase crosswalk) live only in `eval_sidecar.py`. No label enters
any agent's context, tool return, prompt, or readable file. This extends to
environment profiles, which are validated to contain no label values.

**Why.** If any label leaks into the agents, the evaluation measures leakage,
not capability. Quarantine is what makes the numbers mean something. It's
enforced mechanically by a grep test, not left to discipline.

**Rejected alternative.** Trust that we simply won't pass labels in. Intentions
drift across weeks of edits; a mechanical check does not.

## 3. Four agents, not three

**Decision.** Kill Chain is a distinct fourth agent, kept separate from Threat
Intelligence even where the split looks redundant.

**Why.** The separation is pedagogical and load-bearing. Technique mapping
(Threat Intel) must be environment- and phase-invariant; phase reasoning (Kill
Chain) is explicitly contextual and narrative. Collapsing them would entangle an
invariant mapping with a contextual judgment, and it's exactly that entanglement
that a real run exposed — when the retry prompt let phase language bleed into
Threat Intel, its output started making phase conclusions. Keeping them separate
keeps each one's job falsifiable.

**Rejected alternative.** Fold phase assignment into Threat Intel (it already has
the tactic, and tactic→phase is a table). Rejected because it destroys the
model-vs-crosswalk divergence measurement and blurs the invariance boundary.

## 4. The model proposes, code derives, the verifier diverges

**Decision.** The Kill Chain model assigns phases with justifications; code
*independently* derives an expected phase set from ATT&CK tactics via a fixed
crosswalk; a comparison reports where they diverge. Divergence is recorded and
surfaced, not treated as error.

**Why.** It resolves the tension between "emphasize reasoning" and "code
computes." The model's justified assignment is the artifact of interest; the
code's derivation is the check. Where they disagree is the most informative
output — sometimes the model is wrong, sometimes the crosswalk is too coarse and
the model reasoned better. A lookup table can never disagree with itself.

**Rejected alternative.** Score the model's phase against the crosswalk as
"right/wrong." Rejected because it presumes the crosswalk is ground truth, which
it isn't — it's an asserted judgment call.

## 5. LangGraph, used minimally

**Decision.** Plain `StateGraph` (Graph API) only. No `langgraph.prebuilt`, no
LangChain tool/model wrappers, no `@tool` decorator or `bind_tools`. Our own
`run_agent` loop lives inside each node.

**Why.** We want the orchestration to be a transparent, auditable function of our
code — the exported diagram cannot drift from behavior — and we want to
understand every layer rather than inherit a framework's opinions. The framework
earns its place only for the graph structure between agents.

**Rejected alternative.** Use the prebuilt agent/executor abstractions. Faster to
start, but they hide the tool loop, the guardrails, and the control flow — the
exact things this project exists to teach and to keep inspectable.

## 6. No supervisor LLM for routing

**Decision.** Routing between agents is code (pure functions of state), not an
LLM deciding the next step.

**Why.** The agent order never varies, so an LLM router would add nondeterminism
and a new failure mode without adding capability. The dynamic elements (the two
retry edges) are decided by code evaluating explicit conditions, so every branch
is reproducible and logged.

**Rejected alternative.** A supervisor agent that picks the next node. Rejected
as nondeterminism for its own sake.

## 7. Feedback edges capped at one, decided in code

**Decision.** Each of the two feedback loops fires at most once, and the trigger
is evaluated in code, not by asking the model whether it wants a retry.

**Why.** Asking the model "do you want to retry?" invites unbounded loops (a real
run showed the Kill Chain wanting a retry on *both* passes for a genuine,
unresolvable gap — the cap is what ended it). A code-evaluated condition plus a
hard cap makes worst-case cost bounded and every decision auditable.

**Rejected alternative.** Let the loop run until the model is satisfied. Rejected
because "satisfied" is not a bounded or reproducible stopping condition.

## 8. Environment injection is per-agent and asymmetric

**Decision.** An explicit matrix controls which profile sections each agent sees;
Threat Intel sees nothing (an explicit empty allowlist, not an omission).

**Why.** Different agents need different context, and one agent — Threat Intel —
must stay invariant to context for its mapping to be falsifiable. The asymmetry
is the point, and the empty allowlist is asserted loudly so no one "helpfully"
adds a section later. The M7 experiment tests the invariance directly: Threat
Intel's prompt must be byte-identical across profiles.

**Rejected alternative.** Give every agent the whole profile. Simpler, but it
would make ATT&CK mapping shift with context, which would make the mapping
unfalsifiable.

## 9. The environment profile is validated like a leak risk

**Decision.** Profiles pass a load-time validator that hard-rejects label
collisions, maliciousness assertions, phase/technique pinning, and verdict
language; it warns on absolute quantifiers and over-length policy entries.

**Why.** A profile is free text a human writes, and "the DDoS comes from
172.16.0.1" is a planted answer. The validator enforces *the file describes what
is, not what is bad* — with `analyst_policy` as the one fenced place judgment is
allowed.

**Rejected alternative.** Trust profile authors. Rejected for the same reason as
the ground-truth quarantine: a mechanical gate beats good intentions, and its
verdict is recorded in the manifest.

## 10. A dataset adapter layer before a second dataset

**Decision.** All loaders normalize to a canonical flow schema behind a registry;
schema probing is mandatory and raises on unrecognized headers.

**Why.** Generalizing *before* adding DAPT keeps the second dataset small and
keeps downstream code dataset-agnostic. Silent null columns from a mismatched
header are a classic, hard-to-debug failure; a loud error at load time is worth
the few lines it costs.

**Rejected alternative.** Special-case each dataset in the loader. Rejected as the
path to a tangle of `if dataset == ...` branches.

## 11. Tools added from the agents' own feedback — but selectively

**Decision.** The `--tool-feedback` instrument surfaces what each agent wishes it
had. We granted the code-computed, in-scope requests (a host profile, a flag
summary, a proper time filter, sub-technique listing) and fixed the real bugs it
found. We **declined** the requests that would erase agent boundaries (Kill Chain
re-querying raw findings; any tactic→phase tool that would expose the crosswalk;
payload inspection the data can't support).

**Why.** The instrument is genuinely useful — the objective log ("brute-forced
`count_by` 3× in a row") corroborated the subjective ask ("I want a host
profile"). But a model's tool requests often lobby to do the neighboring agent's
job or to see what it's meant not to see. The deciding principle is the
architecture, not the model's convenience.

**Rejected alternative.** Grant every request. Rejected because several would
have re-created the exact overlap the four-agent split exists to prevent.

## 12. Every run writes a manifest

**Decision.** Each run records sampling params (as they actually ran), model +
provider, `OLLAMA_CONTEXT_LENGTH`, dataset + slice, environment profile hash and
validator verdict, per-agent injected sections and hashes, node visits, retry
decisions (including negatives), and git SHA.

**Why.** Reproducibility and auditability are first-class requirements. Without
the manifest you cannot tell whether a surprising result came from the code, the
data, the model, or the settings. The manifest is the receipt.

**Rejected alternative.** Log to stdout and move on. Rejected because ephemeral
logs can't reconstruct a run three weeks later.
