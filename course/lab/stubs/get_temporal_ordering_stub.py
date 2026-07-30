"""
Lab Part B — implement this stub.

Given a list of finding IDs, return them ordered by first-seen time, with the
gap in seconds between each finding and the previous one. This is the CODE that
the Kill Chain agent calls so the MODEL never has to order timestamps itself.

Your task:
  1. For each finding id, look up its finding and parse its earliest timestamp.
  2. Sort the findings by that time.
  3. Return JSON: an "ordering" list of {finding_id, gap_seconds_from_previous}
     (gap is null for the first), and an "undetermined" list for any finding
     with no usable timestamp.

You are given `finding_by_id`: {"F1": {...finding dict...}, ...}. A finding dict
may contain a "first_seen" field like "2017-04-07 02:09:00" (or None).

When you're done, compare your output to the real implementation in
src/kill_chain.py (get_temporal_ordering + _parse_ts). Then do step 2 of the
lab: hand the raw timestamps to the model instead and see whether it agrees.
"""

import json


def get_temporal_ordering(finding_ids, finding_by_id):
    # ---- TODO: implement ----
    # Hints:
    #   import pandas as pd; ts = pd.to_datetime(value, errors="coerce")
    #   epoch = ts.timestamp()  # seconds since 1970, good for sorting + gaps
    raise NotImplementedError("implement get_temporal_ordering for Lab Part B")


if __name__ == "__main__":
    findings = {
        "F1": {"title": "port scan", "first_seen": "2017-04-07 02:09:00"},
        "F2": {"title": "ssh brute force", "first_seen": "2017-04-07 02:20:00"},
        "F3": {"title": "no timestamp finding", "first_seen": None},
    }
    print(get_temporal_ordering(["F3", "F1", "F2"], findings))
    # Expected shape:
    # {"ordering": [{"finding_id": "F1", "gap_seconds_from_previous": null},
    #               {"finding_id": "F2", "gap_seconds_from_previous": 660.0}],
    #  "undetermined": [{"finding_id": "F3", "reason": "no usable timestamp"}]}
