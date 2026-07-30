# Tooling changes from the agents' own feedback (Week 4)

**For the presentation.** This log records what changed after reviewing the
`--tool-feedback` output across three real Tuesday (FTP/SSH-Patator) runs, and —
just as important — what we deliberately refused to change. The story is that
the system critiques its own tools, a human decides which critiques to act on,
and the deciding principle is the project's architecture, not the model's
preferences.

## Why this is a good slide

The `--tool-feedback` instrument pairs an **objective** tool-call log (computed
in code) with the model's **subjective** critique. On these runs the two halves
agreed: the log flagged *"count_by called 3× in a row — a missing aggregation
tool may be emulated by brute force,"* and independently the model asked for a
one-shot host-profile tool. Objective evidence corroborating the subjective ask
is exactly the signal we act on. The model's more ambitious requests, by
contrast, were asks to erase the agent boundaries — those we declined.

## Bugs fixed

1. **`find_outliers` crashed on every run.** It appended the requested `column`
   to a fixed column list that already contained the columns the model always
   picks (Flow Duration, Total Fwd Packets), producing a duplicate label; pandas
   then raised *"DataFrame columns must be unique"* on `to_json`. Fixed by
   de-duplicating the selection. (Not a data problem — a tool bug the feedback
   surfaced.)
2. **`get_technique_context` truncated descriptions mid-word** ("…dur"), flagged
   by Threat Intel, Kill Chain, and Report Writer. Now clipped at a sentence/word
   boundary with a larger cap.
3. **A transient network error killed a whole run.** Run 2 died at the Report
   Writer with `APIConnectionError` (a DNS blip), discarding every prior agent's
   work. `_chat` now retries transient connection/timeout/rate-limit errors with
   exponential backoff before giving up.

## Tools added (all code-computed — the model transcribes, code derives)

| Tool | Agent | Replaces / fixes |
|---|---|---|
| `host_profile(ip)` | Network Analyst | The brute-forced `count_by` chains — one call summarises a host's flows, distinct ports/IPs, busiest ports, and active window. |
| `flag_summary(filter)` | Network Analyst | The repeated "I need TCP flags to confirm failed vs. established connections" request. Sums the dataset's own SYN/ACK/RST/FIN columns. Payloads are **not** exposed — flow data doesn't contain them. |
| `flows_in_time_range(start,end,…)` | Network Analyst | The off-hours query where the model's hand-written regex on `Timestamp` failed silently. Timestamps are parsed in code. |
| `count_by(… , column2)` | Network Analyst | The recurring "group by two columns at once" friction (e.g. Source IP × Destination Port). |
| `list_subtechniques(parent)` | Threat Intel | Several `get_technique` round-trips to compare T1110.001 / .003 / .004. Returned sub-technique IDs are grounding-recorded, so they stay citable. |

## Requests deliberately DECLINED (and why)

These are the ones worth mentioning out loud — the model asked for tools that
would dissolve the very boundaries the architecture is built on:

- **Kill Chain asking for `get_all_findings` / `get_finding_by_criteria` /
  `get_asset_details`.** That is Kill Chain asking to re-investigate raw data and
  re-query findings — i.e. do the Network Analyst's job. Granting it recreates the
  agent-overlap we removed. Kill Chain reasons over the structured input it is
  handed, nothing more.
- **A `tactic → phase` mapping or `validate_technique_to_phase_mapping` tool**
  (requested by Kill Chain and Report Writer). That tool *is* the code crosswalk,
  which lives in the sidecar precisely so the model cannot see it. Handing it over
  would collapse the model-vs-crosswalk divergence signal that distinguishes an
  agent from a lookup table.
- **Packet/payload inspection** (Network Analyst). Flow records contain no
  payloads; a tool that "returned" them would invite fabrication. We exposed the
  real flag columns instead.

## Verification

All changes are covered by regression tests in `tests/test_tools.py`
(the `find_outliers` dup-column fix, each new tool, the description clip, and the
`_chat` transient-retry path). Full suite: **100 passing**.
