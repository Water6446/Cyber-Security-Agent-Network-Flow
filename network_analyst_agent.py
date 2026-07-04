"""
Network Analyst Agent — Week 2 skeleton
========================================
Reads CIC-IDS2017 flow CSVs, identifies unusual activity via an LLM
tool-calling loop, and produces plain-language findings.

Architecture (three layers):
  1. DATA LAYER   — pandas loads/cleans the CSV. Deterministic code.
  2. TOOL LAYER   — small, narrow functions the LLM can call. Code
                    computes; the model never sees raw multi-MB data.
  3. AGENT LOOP   — while-loop: model -> tool call -> result -> model,
                    until the model emits final findings or hits the cap.

Provider note: uses the `openai` SDK because its API shape is supported
by OpenAI, Ollama (local), Anthropic (compat endpoint), vLLM, Groq, etc.
Pick a provider at the command line; the loop never changes.

    pip install openai pandas
    python network_analyst_agent.py --provider ollama --csv Tuesday-....csv
    python network_analyst_agent.py --provider claude --csv Tuesday-....csv   # needs ANTHROPIC_API_KEY
    python network_analyst_agent.py --provider openai --csv Tuesday-....csv   # needs OPENAI_API_KEY
    python network_analyst_agent.py --provider claude --model claude-sonnet-5 --csv ...
"""

import argparse
import json
import os
import re
import textwrap
import time

import pandas as pd
from openai import OpenAI, BadRequestError

# ---------------------------------------------------------------------------
# Config
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

client: OpenAI = None   # set by setup_client() after CLI args are parsed
MODEL: str = None


def setup_client(provider: str, model: str = None):
    global client, MODEL
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

    MODEL = model or p["model"]
    if provider == "custom":
        MODEL = model or os.environ.get("LLM_MODEL")
    if not MODEL:
        raise SystemExit(f"[config] no model for {provider!r}: pass --model")

    client = OpenAI(api_key=api_key, base_url=base_url)
    print(f"[config] provider={provider}  model={MODEL}")

# ---------------------------------------------------------------------------
# 1. DATA LAYER
# ---------------------------------------------------------------------------
# CIC-IDS2017 quirks handled here:
#   - column names have stray leading spaces (" Destination Port")
#   - some rows contain Infinity/NaN in rate columns
#   - the "Label" column is GROUND TRUTH. We strip it from what the agent
#     can see so it must *detect* anomalies, not read the answer key.
#     We keep it separately for our own evaluation afterward.

df: pd.DataFrame = None          # agent-visible data (no Label)
labels: pd.Series = None         # ground truth, for eval only


def load_data(csv_path: str):
    global df, labels
    try:
        raw = pd.read_csv(csv_path, low_memory=False)
    except UnicodeDecodeError:                                # Thursday/Friday files
        print("[data] utf-8 decode failed; retrying with latin-1")
        raw = pd.read_csv(csv_path, low_memory=False, encoding="latin-1")
    raw.columns = raw.columns.str.strip()                     # fix " Fwd..." names
    raw = raw.replace([float("inf"), -float("inf")], pd.NA)
    if "Label" in raw.columns:
        labels = raw["Label"]
        raw = raw.drop(columns=["Label"])                     # hide answer key
    df = raw
    print(f"[data] loaded {len(df):,} flows, {len(df.columns)} columns")


# ---------------------------------------------------------------------------
# 2. TOOL LAYER — deterministic, narrow, capped output
# ---------------------------------------------------------------------------

def get_overview() -> str:
    """High-level shape of the dataset: size, columns, basic distributions."""
    out = {
        "n_flows": len(df),
        "columns": list(df.columns),
        "top_destination_ports": df["Destination Port"].value_counts().head(10).to_dict()
        if "Destination Port" in df.columns else "n/a",
    }
    return json.dumps(out, default=str)


def get_stats(column: str, top_n: int = 10) -> str:
    """Distribution stats for one column. Numeric -> describe(); else value_counts."""
    if column not in df.columns:
        return json.dumps({"error": f"unknown column {column!r}", "hint": list(df.columns)[:20]})
    s = df[column]
    if pd.api.types.is_numeric_dtype(s):
        desc = s.describe(percentiles=[0.5, 0.95, 0.99]).to_dict()
        return json.dumps({"column": column, "numeric_summary": desc}, default=str)
    return json.dumps({"column": column,
                       "top_values": s.value_counts().head(top_n).to_dict()}, default=str)


def find_outliers(column: str, direction: str = "high", top_n: int = 10) -> str:
    """Rows with the most extreme values in a numeric column (row indices included
    so findings can cite evidence)."""
    if column not in df.columns or not pd.api.types.is_numeric_dtype(df[column]):
        return json.dumps({"error": f"{column!r} missing or not numeric"})
    sub = df.nlargest(top_n, column) if direction == "high" else df.nsmallest(top_n, column)
    keep = [c for c in ["Destination Port", "Flow Duration", "Total Fwd Packets",
                        "Total Backward Packets", "Flow Bytes/s", column] if c in sub.columns]
    return sub[keep].reset_index().to_json(orient="records")


QUERY_DEFAULT_COLS = ["Source IP", "Source Port", "Destination IP", "Destination Port",
                      "Protocol", "Timestamp", "Flow Duration", "Total Fwd Packets",
                      "Total Backward Packets", "Flow Bytes/s"]


def query_flows(filter_expr: str, limit: int = MAX_ROWS_RETURNED,
                columns: list = None) -> str:
    """Drill into raw flows with a pandas query expression,
    e.g. "`Destination Port` == 22 and `Flow Duration` > 1000000".
    Returns key columns only (84 full columns blow up the context);
    pass `columns` to request specific others. Capped at MAX_ROWS_RETURNED rows."""
    try:
        matches = df.query(filter_expr)                       # query once, reuse
    except Exception as e:                                    # bad expr -> tell model, don't crash
        return json.dumps({"error": f"bad filter: {e}"})
    keep = [c for c in (columns or QUERY_DEFAULT_COLS) if c in df.columns]
    unknown = [c for c in (columns or []) if c not in df.columns]
    sub = matches[keep].head(min(limit, MAX_ROWS_RETURNED))
    out = {"n_matching_total": int(len(matches)),
           "rows": json.loads(sub.reset_index().to_json(orient="records"))}
    if unknown:
        out["ignored_unknown_columns"] = unknown
    return json.dumps(out)


def count_by(filter_expr: str, column: str, top_n: int = 10) -> str:
    """Aggregate attribution: of the flows matching filter_expr, count them
    grouped by `column`. Answers questions like 'WHO sends the most flows to
    port 22?' deterministically, instead of guessing from sample rows."""
    if column not in df.columns:
        return json.dumps({"error": f"unknown column {column!r}", "hint": list(df.columns)[:20]})
    try:
        matches = df.query(filter_expr)
    except Exception as e:
        return json.dumps({"error": f"bad filter: {e}"})
    return json.dumps({"n_matching_total": int(len(matches)),
                       f"count_by_{column}": matches[column].value_counts()
                                                    .head(top_n).to_dict()}, default=str)


def top_talkers(n: int = 10) -> str:
    """Most active source IPs: flow count, distinct destination ports/IPs,
    total bytes. Port scans and brute force light up here — one source
    hitting many ports (scan) or hammering one port with many flows
    (brute force)."""
    if "Source IP" not in df.columns:
        return json.dumps({"error": "no 'Source IP' column — this file may be the "
                           "anonymized MachineLearningCSV variant",
                           "hint": list(df.columns)[:20]})
    n = min(n, MAX_ROWS_RETURNED)
    g = df.groupby("Source IP")
    out = pd.DataFrame({"flow_count": g.size()})
    if "Destination Port" in df.columns:
        out["distinct_dest_ports"] = g["Destination Port"].nunique()
    if "Destination IP" in df.columns:
        out["distinct_dest_ips"] = g["Destination IP"].nunique()
    byte_cols = [c for c in ("Total Length of Fwd Packets",
                             "Total Length of Bwd Packets") if c in df.columns]
    if byte_cols:
        out["total_bytes"] = sum(g[c].sum() for c in byte_cols)
    out = out.sort_values("flow_count", ascending=False).head(n)
    return out.reset_index().to_json(orient="records")


TOOLS_IMPL = {
    "get_overview": get_overview,
    "get_stats": get_stats,
    "find_outliers": find_outliers,
    "query_flows": query_flows,
    "count_by": count_by,
    "top_talkers": top_talkers,
}

TOOL_DEFS = [
    {"type": "function", "function": {
        "name": "get_overview",
        "description": "Get dataset size, column list, and top destination ports. Call this FIRST.",
        "parameters": {"type": "object", "properties": {}, "required": []}}},
    {"type": "function", "function": {
        "name": "get_stats",
        "description": "Summary statistics for a single column (percentiles for numeric, "
                       "top values otherwise). Use to establish what 'normal' looks like.",
        "parameters": {"type": "object", "properties": {
            "column": {"type": "string"},
            "top_n": {"type": "integer", "default": 10}},
            "required": ["column"]}}},
    {"type": "function", "function": {
        "name": "find_outliers",
        "description": "Return the rows with the most extreme values in a numeric column, "
                       "with row indices for evidence citation.",
        "parameters": {"type": "object", "properties": {
            "column": {"type": "string"},
            "direction": {"type": "string", "enum": ["high", "low"], "default": "high"},
            "top_n": {"type": "integer", "default": 10}},
            "required": ["column"]}}},
    {"type": "function", "function": {
        "name": "query_flows",
        "description": "Drill into raw flows with a pandas query expression, e.g. "
                       "\"`Destination Port` == 22 and `Flow Duration` > 1000000\". "
                       "Returns the total match count plus at most 10 EXAMPLE rows — the "
                       "FIRST matches, not a representative sample, so never generalize "
                       "about who/what dominates from them; use count_by for that. Rows "
                       "include key columns only (IPs, ports, timing, packet counts); use "
                       "the 'columns' parameter to request specific other columns.",
        "parameters": {"type": "object", "properties": {
            "filter_expr": {"type": "string"},
            "limit": {"type": "integer", "default": 10},
            "columns": {"type": "array", "items": {"type": "string"},
                        "description": "optional: exact column names to return instead "
                                       "of the defaults"}},
            "required": ["filter_expr"]}}},
    {"type": "function", "function": {
        "name": "count_by",
        "description": "Count the flows matching a pandas query expression, grouped by any "
                       "column. THE tool for attribution: e.g. filter_expr=\"`Destination "
                       "Port` == 22\", column=\"Source IP\" tells you exactly who is hitting "
                       "SSH and how many times. Always use this before naming an attacker.",
        "parameters": {"type": "object", "properties": {
            "filter_expr": {"type": "string"},
            "column": {"type": "string"},
            "top_n": {"type": "integer", "default": 10}},
            "required": ["filter_expr", "column"]}}},
    {"type": "function", "function": {
        "name": "top_talkers",
        "description": "Most active source IPs, sorted by flow count, with distinct "
                       "destination ports/IPs and total bytes per source. Use to spot "
                       "port scans (one source, many ports) and brute force "
                       "(one source, many flows to one port).",
        "parameters": {"type": "object", "properties": {
            "n": {"type": "integer", "default": 10}},
            "required": []}}},
]

# ---------------------------------------------------------------------------
# 3. AGENT LOOP
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = textwrap.dedent(f"""\
    You are a network security analyst reviewing network flow records
    (CIC-IDS2017 format). Your job: identify unusual or suspicious activity
    and explain it in plain language a non-specialist manager can follow.
    Always respond in English only.

    You have a budget of {MAX_TURNS} turns (you may batch several tool calls
    per turn). Plan your investigation so you finish and WRITE YOUR FINAL
    REPORT within budget — a solid report on time beats a perfect
    investigation that never concludes.

    Method:
    1. Start with get_overview, then use get_stats to baseline normal behavior.
    2. Investigate anomalies with top_talkers, find_outliers, and query_flows.
       top_talkers surfaces sources doing port scans or brute force. Every claim
       must cite evidence: row indices, counts, or statistics from tool results.
    3. NEVER report a finding from a single summary tool call. Before accusing
       a host, drill down: use count_by to establish exactly who is responsible
       for a pattern (query_flows rows are the FIRST matches, not a sample —
       never attribute activity from them), and query_flows to inspect the
       flows themselves. A busy host may be a normal server or client — high
       volume alone is not suspicious. Infrastructure hosts (DNS on 53,
       Kerberos on 88, LDAP on 389) legitimately touch many peers.
       Concentration is: many flows to ONE port (brute force), or many distinct
       ports on ONE destination (scan).
    4. Investigate at least the top 3 candidate sources before writing your
       report, and report every distinct suspicious behavior you verified,
       not just the first one.
    5. Never invent data. If tools don't support a claim, say so.
    6. While investigating, write AT MOST one short sentence between tool
       calls — no analysis, no partial conclusions. Save ALL prose for the
       final findings report.

    When done investigating, output FINDINGS as markdown. For each finding:
    - **What happened** (one plain-language sentence)
    - **Evidence** (specific numbers / row indices from tool calls)
    - **Severity** (Low / Medium / High) and **Confidence** (Low / Medium / High)
    - **Recommended next step**
    If you find nothing unusual, say so explicitly — that is a valid finding.

    After the markdown, end the report with a machine-readable summary for
    downstream analysis agents: a fenced ```json code block of the form
    {{"findings": [{{"title": ..., "severity": ..., "confidence": ...,
    "source_ips": [...], "destination_ips": [...], "ports": [...],
    "flow_count": ..., "evidence_summary": ...}}]}}
    """)


# Sampling params. Near-deterministic temp for consistent demo runs; 4000-token
# cap is plenty for a full findings report. Providers disagree on these:
#   - OpenAI reasoning models: want max_completion_tokens, reject temperature/top_p
#   - Anthropic: allows temperature OR top_p, not both
# _chat() adapts on the fly and remembers what worked for subsequent calls.
# Priority when forced to choose: keep temperature (drop top_p first) — it's
# what makes demo runs repeatable.
_params = {"temperature": 0.1, "top_p": 0.9, "max_tokens": 4000}


def _chat(messages, tool_choice="auto"):
    # Every retry renames or removes one param, so this terminates. The cap
    # is a belt-and-suspenders guard against an unforeseen error loop.
    for _ in range(1 + 4):
        try:
            return client.chat.completions.create(
                model=MODEL, messages=messages, tools=TOOL_DEFS,
                tool_choice=tool_choice, **_params)
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


def run_agent(task: str) -> str:
    messages = [{"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": task}]

    for turn in range(MAX_TURNS):
        final_turn = (turn == MAX_TURNS - 1)
        if final_turn:                       # budget exhausted -> force the report
            print("[agent] investigation budget exhausted; forcing final report")
            messages.append({"role": "user", "content":
                             "Your investigation budget is used up. Do NOT call "
                             "more tools. Write your final FINDINGS report now, "
                             "using only the evidence you have already gathered."})
        print(f"[turn {turn}] waiting on model...", flush=True)
        t0 = time.time()
        resp = _chat(messages, tool_choice="none" if final_turn else "auto")
        msg = resp.choices[0].message
        toks = f" ({resp.usage.completion_tokens} tokens)" if resp.usage else ""
        print(f"[turn {turn}] model responded in {time.time() - t0:.0f}s{toks}", flush=True)

        if not msg.tool_calls:                                # model is done -> final findings
            return msg.content

        messages.append(msg)
        for tc in msg.tool_calls:
            name = tc.function.name
            args = json.loads(tc.function.arguments or "{}")
            print(f"[turn {turn}] tool: {name}({args})")
            try:
                result = TOOLS_IMPL[name](**args)
            except Exception as e:                            # feed errors back, don't crash
                result = json.dumps({"error": str(e)})
            messages.append({"role": "tool", "tool_call_id": tc.id,
                             "content": result[:MAX_TOOL_RESULT_CHARS]})

    return "[agent] hit MAX_TURNS without final findings — raise the cap or simplify the task."


# ---------------------------------------------------------------------------
# Evaluation sidecar (YOURS, not the agent's) — compares findings vs Label
# ---------------------------------------------------------------------------
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _flows_touching(ip: str) -> int:
    """How many flows have this IP as source or destination (0 if columns absent)."""
    n = 0
    for col in ("Source IP", "Destination IP"):
        if col in df.columns:
            n += int((df[col] == ip).sum())
    return n


def evaluate_findings(findings: str):
    """Tally the agent's findings against the hidden Label column:
    - HIT     = the attack's actual source IP is named in the findings
    - PARTIAL = attacker missed, but the victim IP is named
    - MISS    = neither appears
    Plus: every benign IP the findings named = candidate false positive."""
    if labels is None:
        print("[eval] no Label column found")
        return
    print("\n" + "=" * 70 + "\nEVALUATION (agent never saw the Label column)\n" + "=" * 70)
    print("[eval] ground-truth label distribution:")
    print(labels.value_counts().to_string())

    attack_ips = set()
    print("\n[eval] per-attack detection:")
    for label in labels[labels != "BENIGN"].unique():
        sub = df.loc[labels[labels == label].index]
        attacker = str(sub["Source IP"].mode()[0]) if "Source IP" in sub.columns else "?"
        victim = str(sub["Destination IP"].mode()[0]) if "Destination IP" in sub.columns else "?"
        port = str(sub["Destination Port"].mode()[0]) if "Destination Port" in sub.columns else "?"
        attack_ips.update({attacker, victim})
        verdict = ("HIT" if attacker in findings
                   else "PARTIAL (victim named, attacker missed)" if victim in findings
                   else "MISS")
        print(f"  {label:<15} attacker={attacker} -> victim={victim}:{port} "
              f"({len(sub):,} flows)  ...  {verdict}")

    mentioned = set(IP_RE.findall(findings))
    fps = sorted(ip for ip in mentioned - attack_ips if _flows_touching(ip) > 0)
    print(f"\n[eval] benign IPs named in findings (candidate false positives): {len(fps)}")
    for ip in fps:
        print(f"  {ip}  (touches {_flows_touching(ip):,} flows, none attack-labeled)")


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True, help="path to a CIC-IDS2017 CSV")
    ap.add_argument("--provider", choices=sorted(PROVIDERS), default="ollama",
                    help="which LLM provider to use (default: ollama)")
    ap.add_argument("--model", default=None,
                    help="override the provider's default model")
    ap.add_argument("--task", default="Analyze this network flow data for unusual "
                                      "or suspicious activity and report your findings.")
    args = ap.parse_args()

    setup_client(args.provider, args.model)
    load_data(args.csv)
    findings = run_agent(args.task)

    # Split the machine-readable JSON block out of the report: it goes to the
    # .json sidecar for downstream agents (week 3: Threat Intel Agent); the
    # .md stays human-readable. If the block doesn't parse, leave it in the
    # markdown so nothing is lost.
    structured = None
    m = re.search(r"```json\s*(\{.*?\})\s*```", findings, re.S)
    if m:
        try:
            structured = json.loads(m.group(1))
            findings = (findings[:m.start()] + findings[m.end():]).rstrip() + "\n"
        except json.JSONDecodeError as e:
            print(f"[out] JSON block didn't parse ({e}); leaving it in the markdown")

    print("\n" + "=" * 70 + "\nFINDINGS\n" + "=" * 70 + "\n" + findings)

    # sample-analyses deliverable; timestamp + model so runs never overwrite
    # each other and reliability/model comparisons are easy to line up
    safe_model = MODEL.replace(":", "-").replace("/", "-")
    out_name = f"findings_{time.strftime('%Y-%m-%d_%H%M%S')}_{safe_model}.md"
    with open(out_name, "w", encoding="utf-8") as f:
        f.write(findings)
    print(f"[out] findings saved to {out_name}")

    if structured is not None:
        json_name = out_name.replace(".md", ".json")
        with open(json_name, "w", encoding="utf-8") as f:
            json.dump(structured, f, indent=2)
        print(f"[out] structured findings saved to {json_name}")
    else:
        print("[out] no parseable JSON summary block; markdown only")

    evaluate_findings(findings)
