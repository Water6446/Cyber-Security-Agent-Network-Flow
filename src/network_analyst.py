"""
Network Analyst Agent — Week 2 (refactored in Week 3 to use agent_core)
=======================================================================
Reads CIC-IDS2017 flow CSVs, identifies unusual activity via an LLM
tool-calling loop, and produces plain-language findings.

Architecture (three layers):
  1. DATA LAYER   — pandas loads/cleans the CSV. Deterministic code.
  2. TOOL LAYER   — small, narrow functions the LLM can call. Code
                    computes; the model never sees raw multi-MB data.
  3. AGENT LOOP   — agent_core.run_agent(): model -> tool call -> result
                    -> model, until final findings or the turn cap.

Still runnable standalone (Week 2 demos must not break):

    python src/network_analyst.py --provider ollama --csv data/TrafficLabelling/Tuesday-....csv
    python src/network_analyst.py --provider claude --csv ...   # needs ANTHROPIC_API_KEY
    python src/network_analyst.py --provider openai --csv ...   # needs OPENAI_API_KEY
    python src/network_analyst.py --provider claude --model claude-sonnet-5 --csv ...
"""

import argparse
import json
import textwrap
from typing import Optional

import pandas as pd

import agent_core
from agent_core import MAX_TURNS, MAX_ROWS_RETURNED

# ---------------------------------------------------------------------------
# 1. DATA LAYER
# ---------------------------------------------------------------------------
# CIC-IDS2017 quirks handled here:
#   - column names have stray leading spaces (" Destination Port")
#   - some rows contain Infinity/NaN in rate columns
#   - the "Label" column is GROUND TRUTH. We strip it from what the agent
#     can see so it must *detect* anomalies, not read the answer key.
#     We keep it separately for the evaluation sidecar afterward.

df: Optional[pd.DataFrame] = None    # agent-visible data (no Label)
labels: Optional[pd.Series] = None   # ground truth, for eval_sidecar only


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
# 3. AGENT CONFIGURATION (the loop itself lives in agent_core.run_agent)
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

DEFAULT_TASK = ("Analyze this network flow data for unusual or suspicious "
                "activity and report your findings.")


def analyze(client, model, task: str = DEFAULT_TASK,
            max_turns: int = MAX_TURNS) -> str:
    """Run the Network Analyst agent. load_data() must have been called.
    Returns the raw report (markdown + trailing ```json block)."""
    return agent_core.run_agent(client, model, task, SYSTEM_PROMPT,
                                TOOL_DEFS, TOOLS_IMPL,
                                max_turns=max_turns, label="network_analyst")


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import eval_sidecar

    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True, help="path to a CIC-IDS2017 CSV")
    ap.add_argument("--provider", choices=sorted(agent_core.PROVIDERS), default="ollama",
                    help="which LLM provider to use (default: ollama)")
    ap.add_argument("--model", default=None,
                    help="override the provider's default model")
    ap.add_argument("--task", default=DEFAULT_TASK)
    args = ap.parse_args()

    client, model = agent_core.setup_client(args.provider, args.model)
    load_data(args.csv)
    report = analyze(client, model, args.task)

    structured, findings_md = agent_core.extract_json_block(report)
    print("\n" + "=" * 70 + "\nFINDINGS\n" + "=" * 70 + "\n" + findings_md)
    agent_core.save_report("findings", model, findings_md, structured)

    eval_sidecar.evaluate_findings(findings_md, df, labels)
