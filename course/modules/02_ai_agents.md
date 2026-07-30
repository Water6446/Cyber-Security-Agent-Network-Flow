# Module 2 — AI Agents (Pipelines vs. Agents)

**Estimated time:** 45–60 minutes
**Prerequisites:** a scripting language; Module 1.

This is one of the three load-bearing modules — the distinction it teaches is the reason the project is built the way it is.

## Learning objectives

1. State the load-bearing difference between a *pipeline* and an *agent*.
2. Trace a tool-calling loop and identify where the model's choice enters.
3. Explain why structured tool returns beat free text.
4. Explain why grounding verification is necessary — an agent that can call a tool can also make one up.
5. Read one of this project's own tool-call logs and say what the agent decided and why.

## 1. The load-bearing distinction

A **pipeline** runs a fixed sequence of steps. Step 1 always feeds step 2, which always feeds step 3. It is a recipe: predictable, testable, and completely determined in advance.

An **agent** chooses *which tool to call next based on what the previous calls returned*. It is given a goal and a set of tools, and at each step it looks at everything it has learned so far and decides the next move. The sequence is not fixed; it emerges from the evidence.

That single sentence — *the model selects the next action based on accumulated prior results* — is the whole difference. It is easy to blur, because both a pipeline and an agent can "use tools." The test is: **if you changed the data, would the sequence of steps change?** In a pipeline, no. In an agent, yes.

In this project, the Network Analyst is an agent. On a port-scan dataset it calls `top_talkers`, notices one host hitting hundreds of ports, and drills into that host. On a brute-force dataset it notices one host hammering a single port and drills there instead. Same tools, same prompt, *different* investigation — because the evidence differed. A pipeline could not do that.

## 2. The tool-calling loop

Here is the loop every agent in this project runs (it lives in `agent_core.run_agent`):

```
1. Send the model: the goal + the tools available + everything so far.
2. The model replies with EITHER
     (a) one or more tool calls, or
     (b) a final answer.
3. If tool calls: run them in code, append the results, go to 1.
   If final answer: stop.
```

Step 2 is where the intelligence lives. The model is not told which tool to use; it decides. The code's job is narrow and mechanical: run the tool the model asked for, hand back the result, and enforce guardrails (a turn cap so it cannot loop forever, truncation so a giant result cannot blow up the context, and error feedback so a bad tool call becomes a message instead of a crash).

Notice what the model never touches: the data itself. The Network Analyst never sees the 400,000-row CSV. It sees only the small, computed answers its tools return. This is the project's standing rule — **code computes, the model transcribes** — and the loop is where it is enforced.

## 3. Why structured tool returns beat free text

A tool could return "there were a lot of connections to port 22 from that host." That is free text, and it is poison for two reasons. First, the next step has to *re-parse* it, and parsing prose is error-prone. Second, and worse, prose invites the model to round, embellish, or drift — "a lot" becomes "thousands" becomes a number that was never measured.

So every tool in this project returns **structured** data — JSON with exact fields: `{"n_matching_total": 5898, "count_by_Source IP": {"172.16.0.1": 5898}}`. The number is computed by code and passed through verbatim. The model's job is to *reason over* and *transcribe* that number, never to produce it. When you read the agents' outputs, every count and IP in them can be traced back to a structured tool result. That traceability is only possible because the returns are structured.

## 4. Grounding: an agent that can call a tool can fake one

Here is the uncomfortable insight that a lot of "agent" demos skip: an LLM that has learned the *format* of a tool result can simply *emit* something that looks like a tool result, without ever calling the tool. It can write "T1046 (Network Service Discovery)" from memory and present it as if a lookup returned it. If your ATT&CK technique IDs come from the model's memory, some fraction will be subtly wrong or entirely invented — a **hallucination**.

The defense is **grounding verification**, done in code, not by asking the model to be careful. After the Threat Intelligence agent finishes, code extracts every technique ID from its output and checks each one against the set of IDs the tools *actually returned* during that run. Any ID the tools never returned is flagged as **unverified**. The model cannot talk its way past this check, because the check does not consult the model — it consults the log.

This is the general principle: *anything the model asserts that could have been computed must be checkable against what code actually produced.* An agent without grounding is a confident narrator you cannot trust.

## 5. Reading a real tool-call log

Here is a lightly-trimmed excerpt from an actual Network Analyst run (Tuesday, brute-force data):

```
turn 0  tool: get_overview()
turn 0  tool: top_talkers(n=15)
turn 1  narration: "192.168.10.3 stands out — 60K flows across 408 ports.
                    Let me check whether that's a scan or just DNS."
turn 1  tool: count_by(filter="Source IP == '192.168.10.3'", column="Destination Port")
turn 2  narration: "It's DNS (59,833 of 60,814 to port 53) — normal.
                    Let me look at SSH/FTP for brute force."
turn 2  tool: count_by(filter="Destination Port == 22", column="Source IP")
turn 3  narration: "172.16.0.1 owns SSH and FTP — likely brute force."
turn 3  tool: flag_summary(filter="Source IP=='172.16.0.1' and Destination Port==22")
```

Read it as a story. The agent did **not** follow a script. It formed a hypothesis (192.168.10.3 looks like a scan), *tested it with a tool*, was proven wrong (it's DNS), discarded it, formed a new hypothesis (SSH brute force), and confirmed it. Each tool call was chosen in response to the last result. That is an agent. A pipeline would have run the same four tools in the same order no matter what the data said — and would have reported the DNS server as a scanner.

## Key terms

- **Pipeline:** fixed sequence of steps, independent of the data.
- **Agent:** chooses the next action based on accumulated results.
- **Tool-calling loop:** model → tool call → result → model, until a final answer.
- **Structured return:** tool output as typed fields (JSON), not prose.
- **Grounding verification:** code-side check that the model only cited things a tool actually produced.
- **Hallucination:** the model asserting a fact (e.g., a technique ID) that no tool returned.

## Check your understanding

1. **What one test tells a pipeline from an agent?**
   Change the input data; if the sequence of steps changes, it's an agent.

2. **Where in the tool-calling loop does the "intelligence" live, and what does the code do?**
   In the model's step-2 choice of which tool to call; the code just runs tools and enforces guardrails.

3. **Give a concrete reason structured returns beat prose returns.**
   Prose has to be re-parsed and invites the model to embellish a number; structured returns pass a code-computed value through verbatim and stay traceable.

4. **Why can't you fix hallucination by telling the model "don't make up technique IDs"?**
   Because the model can still emit a memorized-looking ID; only a code check against the actual tool log can catch it, and that check doesn't consult the model.

5. **In the Section 5 log, name the moment the agent's behavior proves it isn't a pipeline.**
   When it tested the "192.168.10.3 is a scan" hypothesis, found it was DNS, and *changed course* to SSH — a data-driven branch a pipeline can't take.

## Further reading

- The project's `agent_core.py` — read `run_agent` and the guardrails around it.
- Any primer on "tool use / function calling" with LLMs.
- This project's `docs/design_decisions.md` — the "four agents, not three" and "code computes, model transcribes" entries.
