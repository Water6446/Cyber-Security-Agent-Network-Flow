"""
Shared agent machinery — Week 3 refactor (Part 0)
=================================================
(Plan-mode narration and advisory tool feedback added post-Week-3 review.)
The Week 2 agent loop is needed twice now (Network Analyst + Threat Intel),
so the reusable parts live here. An "agent" is just a configuration of this
machinery: a system prompt + tool definitions + tool implementations.
run_agent() drives the same model -> tool call -> result -> model loop for
every agent, with the same guardrails: hard turn cap, forced final turn,
error feedback instead of crashes, truncated tool results.

Provider note: uses the `openai` SDK because its API shape is supported
by OpenAI, Ollama (local), Anthropic (compat endpoint), vLLM, Groq, etc.
Pick a provider at the command line; the loop never changes.
"""

import json
import os
import re
import time

from openai import OpenAI, BadRequestError

# Transient error types worth retrying (network blip, timeout, rate limit).
# Guarded import so the module still works on odd SDK versions.
try:
    from openai import APIConnectionError, APITimeoutError, RateLimitError
    _TRANSIENT_ERRORS = (APIConnectionError, APITimeoutError, RateLimitError)
except Exception:                                     # pragma: no cover
    _TRANSIENT_ERRORS = ()

# ---------------------------------------------------------------------------
# Provider presets, selected with --provider on the command line. All of them
# speak the OpenAI chat-completions API shape (Anthropic via its OpenAI
# compatibility endpoint), so the agent loop below never changes.
# Each preset owns its API-key env var and default model; the --model flag is
# the only override. The "custom" provider reads LLM_BASE_URL / LLM_API_KEY /
# LLM_MODEL for any other OpenAI-compatible service (vLLM, Groq, ...).
PROVIDERS = {
    "ollama": {"base_url": "http://localhost:11434/v1",
               "key_env": None, "key_default": "ollama",  # Ollama ignores the key
               "model": "qwen2.5:14b"},
    "openai": {"base_url": None,                     # SDK default: api.openai.com
               "key_env": "OPENAI_API_KEY", "key_default": None,
               "model": "gpt-4o-mini"},
    "claude": {"base_url": "https://api.anthropic.com/v1/",
               "key_env": "ANTHROPIC_API_KEY", "key_default": None,
               "model": "claude-haiku-4-5"},
    "custom": {"base_url": None,                     # from LLM_BASE_URL
               "key_env": "LLM_API_KEY", "key_default": None,
               "model": None},                       # from LLM_MODEL or --model
}

MAX_TURNS = 12          # hard cap: prevents runaway loops / runaway cost
MAX_ROWS_RETURNED = 10  # tools never dump more than this many raw rows
MAX_TOOL_RESULT_CHARS = 4000  # truncate tool results fed back to the model


def setup_client(provider: str, model: str = None):
    """Build an OpenAI-compatible client for the chosen provider.
    Returns (client, model_name)."""
    p = PROVIDERS[provider]

    base_url = p["base_url"]
    if provider == "custom":
        base_url = os.environ.get("LLM_BASE_URL")
        if not base_url:
            raise SystemExit("[config] provider 'custom' needs LLM_BASE_URL set")

    api_key = (os.environ.get(p["key_env"]) if p["key_env"] else None) or p["key_default"]
    if not api_key:
        raise SystemExit(f"[config] no API key found for {provider!r}: "
                         f"set the {p['key_env']} environment variable")

    model = model or p["model"]
    if provider == "custom":
        model = model or os.environ.get("LLM_MODEL")
    if not model:
        raise SystemExit(f"[config] no model for {provider!r}: pass --model")

    client = OpenAI(api_key=api_key, base_url=base_url)
    print(f"[config] provider={provider}  model={model}")
    return client, model


# Sampling params. Near-deterministic temp for consistent demo runs; 4000-token
# cap is plenty for a full findings report. Providers disagree on these:
#   - OpenAI reasoning models: want max_completion_tokens, reject temperature/top_p
#   - Anthropic: allows temperature OR top_p, not both
# _chat() adapts on the fly and remembers what worked for subsequent calls
# (shared across agents — they talk to the same provider).
# Priority when forced to choose: keep temperature (drop top_p first) — it's
# what makes demo runs repeatable.
_params = {"temperature": 0.1, "top_p": 0.9, "max_tokens": 4000}

TRANSIENT_RETRIES = 4          # attempts for a network blip / timeout / rate limit
TRANSIENT_BACKOFF = 2.0        # seconds, doubled each attempt


def _create(client, model, messages, tool_defs, tool_choice):
    """One chat call, with retry+backoff on TRANSIENT errors only. A single
    network blip at the last agent used to crash the whole run (losing every
    prior agent's work); this keeps the run alive. Non-transient errors —
    including BadRequestError for param adaptation — propagate immediately."""
    delay = TRANSIENT_BACKOFF
    for attempt in range(TRANSIENT_RETRIES):
        try:
            return client.chat.completions.create(
                model=model, messages=messages, tools=tool_defs,
                tool_choice=tool_choice, **_params)
        except _TRANSIENT_ERRORS as e:
            if attempt == TRANSIENT_RETRIES - 1:
                raise
            print(f"[net] transient error ({type(e).__name__}); "
                  f"retry {attempt + 1}/{TRANSIENT_RETRIES - 1} in {delay:.0f}s")
            time.sleep(delay)
            delay *= 2


def _chat(client, model, messages, tool_defs, tool_choice="auto"):
    # Every retry renames or removes one param, so this terminates. The cap
    # is a belt-and-suspenders guard against an unforeseen error loop.
    for _ in range(1 + 4):
        try:
            return _create(client, model, messages, tool_defs, tool_choice)
        except BadRequestError as e:
            err = str(e)
            # Case 1 — OpenAI reasoning models: max_tokens was renamed
            if "max_completion_tokens" in err and "max_tokens" in _params:
                _params["max_completion_tokens"] = _params.pop("max_tokens")
                print("[compat] max_tokens -> max_completion_tokens")
            # Case 2 — Anthropic: temperature and top_p are mutually exclusive
            elif ("both" in err and "temperature" in _params and "top_p" in _params):
                _params.pop("top_p")
                print("[compat] dropped top_p (this model wants temperature OR top_p)")
            # Case 3 — generic: drop whichever sampling param the error names,
            # regardless of how the provider quotes it
            elif any(k in err for k in _params):
                k = next(k for k in _params if k in err)
                _params.pop(k)
                print(f"[compat] model rejected {k!r}; dropped it"
                      + (" (runs will be less repeatable)" if k == "temperature" else ""))
            else:
                raise                                         # a real error — surface it
    raise RuntimeError("[compat] couldn't find a parameter set this model accepts; "
                       f"still failing with params {list(_params)}")


# ---------------------------------------------------------------------------
# Plan mode & tool feedback — BOTH OFF BY DEFAULT (opt-in flags).
# --plan: the model narrates its opening plan and per-turn reasoning in the
#   SAME responses it uses for tool calls — no extra API round trips.
# --tool-feedback: after the final report, ONE extra API call asks the model
#   to critique its tool set; it is printed beside a code-derived summary of
#   the actual tool-call log. ADVISORY ONLY: nothing acts on the feedback —
#   the human reads it and decides what (if anything) to change.
# ---------------------------------------------------------------------------
PLAN_MODE_PROMPT = """

PLAN MODE (narration) is ON for this run. It overrides any earlier
instruction to stay silent between tool calls:
- On your FIRST turn, before any tool call, state your investigation plan
  in 2-3 sentences in the message content, alongside your tool calls.
- On every later turn that includes tool calls, write 2-3 sentences in the
  message content: what the last tool results showed, and why you chose
  the next tool call(s). Hard cap: 3 sentences per turn.
- Narration is commentary only. Never introduce numbers, IPs, ports, or
  counts that did not appear verbatim in a prior tool result. Save all
  findings prose for the final report."""

TOOL_FEEDBACK_PROMPT = (
    "The investigation is complete. Now give feedback on the TOOL SET you "
    "were given (not on the investigation itself). Respond with JSON only, "
    "no markdown fences, with exactly these keys:\n"
    '  "missing_tools": array of {"name", "description", '
    '"why_it_would_have_helped"}\n'
    '  "unused_or_low_value_tools": array of {"name", "reason"} — only tools '
    "that were actually in your tool set\n"
    '  "schema_friction": array of short strings describing parameter or '
    "format annoyances\n"
    "All arrays may be empty. Be specific; do not invent usage that did not "
    "happen.")


def _classify_result(result: str) -> str:
    """Outcome tag for the tool-call log: ok / empty_result / error.
    Code-derived — the model plays no part in this."""
    try:
        data = json.loads(result)
    except Exception:
        return "ok"                       # non-JSON tool output; assume fine
    if isinstance(data, dict):
        if "error" in data:
            return "error"
        for key in ("rows", "hits"):
            if key in data and not data[key]:
                return "empty_result"
        if data.get("n_matching_total") == 0:
            return "empty_result"
    if isinstance(data, list) and not data:
        return "empty_result"
    return "ok"


def _report_tool_feedback(client, model, messages, final_msg,
                          tool_defs, tool_log, label):
    """The --tool-feedback report: objective log summary (code) + the model's
    subjective critique (one extra API call). Prints both and saves them to
    the run folder. Changes nothing else — advisory output for the human."""
    # -- objective half: computed from the log, no model involvement --------
    per = {}
    for e in tool_log:
        d = per.setdefault(e["tool"], {"calls": 0, "errors": 0,
                                       "empty": 0, "seconds": 0.0})
        d["calls"] += 1
        d["seconds"] += e["seconds"]
        if e["outcome"] == "error":
            d["errors"] += 1
        elif e["outcome"] == "empty_result":
            d["empty"] += 1
    streak_tool = best_tool = None
    streak = best = 0
    for e in tool_log:
        streak = streak + 1 if e["tool"] == streak_tool else 1
        streak_tool = e["tool"]
        if streak > best:
            best, best_tool = streak, streak_tool
    all_tools = [d["function"]["name"] for d in (tool_defs or [])]
    never_called = [t for t in all_tools if t not in per]

    print("\n" + "=" * 70 + f"\nTOOL FEEDBACK — {label}")
    print("-- objective (code-derived from the tool-call log) --")
    for t, d in sorted(per.items(), key=lambda kv: -kv[1]["calls"]):
        avg = d["seconds"] / d["calls"]
        print(f"  {t:<20} {d['calls']:>2} calls  {d['errors']} errors  "
              f"{d['empty']} empty  {avg:.2f}s avg")
    if never_called:
        print(f"  never called: {', '.join(never_called)}")
    if best >= 3:
        print(f"  repeated calls: {best_tool} called {best}x in a row "
              "(a missing aggregation tool may be emulated by brute force)")

    # -- subjective half: ONE extra API call, parsed defensively ------------
    print("-- subjective (the model's own critique) --")
    msgs = list(messages) + [final_msg,
                             {"role": "user", "content": TOOL_FEEDBACK_PROMPT}]
    try:
        resp = _chat(client, model, msgs, tool_defs, tool_choice="none")
        raw = (resp.choices[0].message.content or "").strip()
    except Exception as e:                # never let feedback sink a good run
        raw = ""
        print(f"  (feedback call failed: {e})")
    txt = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw, flags=re.S).strip()
    try:
        subjective = json.loads(txt)
    except json.JSONDecodeError:
        subjective = {"parse_failed": True, "raw": raw}
    print(json.dumps(subjective, indent=2)[:3000])

    out = {"agent": label, "model": model,
           "objective": {"per_tool": per, "never_called": never_called,
                         "max_consecutive_same_tool": best,
                         "max_consecutive_tool": best_tool},
           "subjective": subjective}
    path = os.path.join(run_dir(model), f"tool_feedback_{label}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, default=str)
    print(f"[out] tool feedback saved to {path}")


def run_agent(client, model, task: str, system_prompt: str,
              tool_defs: list, tools_impl: dict,
              max_turns: int = MAX_TURNS, label: str = "agent",
              plan_mode: bool = False, tool_feedback: bool = False) -> str:
    """The Week 2 agent loop, parameterized. Everything else — forced final
    turn, error feedback, truncation — stays exactly as it was.
    plan_mode: narrate plan + per-turn reasoning (no extra API calls).
    tool_feedback: after the final report, print + save the model's critique
    of its tool set next to the objective tool-call log. Both default OFF;
    with both off, behavior is identical to before these flags existed."""
    if plan_mode:
        system_prompt = system_prompt + PLAN_MODE_PROMPT
    messages = [{"role": "system", "content": system_prompt},
                {"role": "user", "content": task}]
    tool_log = []          # per call: tool, args, seconds, chars, outcome

    for turn in range(max_turns):
        final_turn = (turn == max_turns - 1)
        if final_turn:                       # budget exhausted -> force the report
            print(f"[{label}] investigation budget exhausted; forcing final report")
            messages.append({"role": "user", "content":
                             "Your investigation budget is used up. Do NOT call "
                             "more tools. Write your final report now, "
                             "using only the evidence you have already gathered."})
        print(f"[{label} turn {turn}] waiting on model...", flush=True)
        t0 = time.time()
        resp = _chat(client, model, messages, tool_defs,
                     tool_choice="none" if final_turn else "auto")
        msg = resp.choices[0].message
        toks = f" ({resp.usage.completion_tokens} tokens)" if resp.usage else ""
        print(f"[{label} turn {turn}] model responded in {time.time() - t0:.0f}s{toks}",
              flush=True)

        if plan_mode and msg.content and msg.tool_calls:      # narration rides along
            head = "plan" if turn == 0 else f"narration turn {turn}"
            print(f"[{label} {head}] {msg.content.strip()}", flush=True)

        if not msg.tool_calls:                                # model is done -> final report
            if tool_feedback:                                 # advisory report, then return
                _report_tool_feedback(client, model, messages, msg,
                                      tool_defs, tool_log, label)
            return msg.content

        messages.append(msg)
        for tc in msg.tool_calls:
            name = tc.function.name
            args = json.loads(tc.function.arguments or "{}")
            print(f"[{label} turn {turn}] tool: {name}({args})")
            t1 = time.time()
            try:
                result = tools_impl[name](**args)
                outcome = _classify_result(result)
            except Exception as e:                            # feed errors back, don't crash
                result = json.dumps({"error": str(e)})
                outcome = "error"
            tool_log.append({"tool": name, "args": args,
                             "seconds": round(time.time() - t1, 3),
                             "result_chars": len(result), "outcome": outcome})
            messages.append({"role": "tool", "tool_call_id": tc.id,
                             "content": result[:MAX_TOOL_RESULT_CHARS]})

    return (f"[{label}] hit max_turns without a final report — "
            "raise the cap or simplify the task.")


# ---------------------------------------------------------------------------
# Report I/O shared by both agents and the workflow
# ---------------------------------------------------------------------------
# Repo layout: this file lives in src/; run artifacts go to outputs/ at the
# repo root no matter which directory the script was launched from.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(REPO_ROOT, "outputs")

JSON_BLOCK_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.S)


def extract_json_block(report: str):
    """Split the machine-readable ```json block out of a report: it goes to
    the .json sidecar for downstream agents; the markdown stays
    human-readable. Returns (dict_or_None, remaining_markdown). If the block
    doesn't parse, it stays in the markdown so nothing is lost."""
    m = JSON_BLOCK_RE.search(report or "")
    if not m:
        return None, report
    try:
        structured = json.loads(m.group(1))
    except json.JSONDecodeError as e:
        print(f"[out] JSON block didn't parse ({e}); leaving it in the markdown")
        return None, report
    return structured, (report[:m.start()] + report[m.end():]).rstrip() + "\n"


_run_dir = None


def run_dir(model: str) -> str:
    """One folder per run: outputs/<timestamp>_<model>/. Created lazily on the
    first save and reused for the rest of the process, so a workflow run's
    findings and mappings land in the same folder. Timestamp + model on the
    folder means runs never overwrite each other and reliability/model
    comparisons are easy to line up."""
    global _run_dir
    if _run_dir is None:
        safe_model = model.replace(":", "-").replace("/", "-")
        _run_dir = os.path.join(
            OUTPUT_DIR, f"{time.strftime('%Y-%m-%d_%H%M%S')}_{safe_model}")
        os.makedirs(_run_dir, exist_ok=True)
    return _run_dir


def save_report(prefix: str, model: str, markdown: str, structured=None) -> str:
    """Write <prefix>.md (+ .json when structured output parsed) into this
    run's folder — see run_dir()."""
    out_name = os.path.join(run_dir(model), f"{prefix}.md")
    with open(out_name, "w", encoding="utf-8") as f:
        f.write(markdown or "")
    print(f"[out] {prefix} saved to {out_name}")

    if structured is not None:
        json_name = out_name.replace(".md", ".json")
        with open(json_name, "w", encoding="utf-8") as f:
            json.dump(structured, f, indent=2)
        print(f"[out] structured {prefix} saved to {json_name}")
    else:
        print(f"[out] no parseable JSON summary block for {prefix}; markdown only")
    return out_name
