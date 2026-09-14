"""
Tool-feedback follow-up (Week 4): regression tests for the fixes and the new
code-computed tools added in response to the agents' --tool-feedback output.
"""
import json

import pandas as pd
import pytest

import agent_core
import kill_chain as kc
import network_analyst as na
import threat_intel as ti


@pytest.fixture
def small_df():
    na.df = pd.DataFrame({
        "Source IP": ["172.16.0.1", "172.16.0.1", "10.0.0.5"],
        "Destination IP": ["192.168.10.50", "192.168.10.50", "10.0.0.9"],
        "Destination Port": [22, 21, 443],
        "Flow Duration": [100, 200, 300],
        "Total Fwd Packets": [1, 2, 3],
        "Total Backward Packets": [0, 1, 2],
        "Flow Bytes/s": [1.0, 2.0, 3.0],
        "SYN Flag Count": [1, 1, 0], "ACK Flag Count": [0, 1, 1],
        "RST Flag Count": [1, 0, 0], "FIN Flag Count": [0, 0, 1],
        "PSH Flag Count": [0, 0, 0], "URG Flag Count": [0, 0, 0],
        "CWE Flag Count": [0, 0, 0], "ECE Flag Count": [0, 0, 0],
        "Timestamp": ["2017-04-07 02:10", "2017-04-07 02:20", "2017-04-07 09:00"],
    })
    yield
    na.df = None


# ---------------------------------------------------------------------------
# find_outliers no longer crashes when `column` overlaps the fixed keep list
# ---------------------------------------------------------------------------
def test_find_outliers_no_dup_column_crash(small_df):
    for col in ("Flow Duration", "Total Fwd Packets"):     # both are in the keep list
        out = json.loads(na.find_outliers(col))
        assert isinstance(out, list) and out                # parsed, non-empty, no crash


# ---------------------------------------------------------------------------
# New Network Analyst tools
# ---------------------------------------------------------------------------
def test_flag_summary(small_df):
    out = json.loads(na.flag_summary("`Source IP` == '172.16.0.1'"))
    assert out["n_matching_total"] == 2
    assert out["flag_totals"]["SYN"] == 2 and out["flag_totals"]["RST"] == 1


def test_host_profile(small_df):
    out = json.loads(na.host_profile("172.16.0.1"))
    assert out["flows_as_source"] == 2
    assert out["distinct_dest_ports_as_source"] == 2
    assert out["active_from"].startswith("2017-04-07 02:10")


def test_flows_in_time_range_parses_and_groups(small_df):
    out = json.loads(na.flows_in_time_range("2017-04-07 02:00", "2017-04-07 03:00",
                                            group_by="Source IP"))
    assert out["n_matching_total"] == 2                     # 09:00 flow excluded
    assert out["count_by_Source IP"]["172.16.0.1"] == 2


def test_flows_in_time_range_bad_dates(small_df):
    out = json.loads(na.flows_in_time_range("not-a-date", "also-bad"))
    assert "error" in out


def test_count_by_two_columns(small_df):
    out = json.loads(na.count_by("`Source IP` == '172.16.0.1'", "Destination Port",
                                 column2="Destination IP"))
    assert out["grouped_by"] == ["Destination Port", "Destination IP"]
    assert len(out["top"]) == 2


# ---------------------------------------------------------------------------
# Threat Intel: list_subtechniques (and grounding-record its ids)
# ---------------------------------------------------------------------------
def test_list_subtechniques_and_grounding(attack_data):
    ti.reset_grounding()
    out = json.loads(ti.list_subtechniques("T1110"))
    ids = [s["id"] for s in out["subtechniques"]]
    assert "T1110.001" in ids and out["n_subtechniques"] >= 3
    assert "T1110.003" in ti._returned_ids                  # now citable/grounded


def test_list_subtechniques_bad_id(attack_data):
    out = json.loads(ti.list_subtechniques("T9999"))
    assert "error" in out


# ---------------------------------------------------------------------------
# get_technique_context description is clipped cleanly, not mid-word
# ---------------------------------------------------------------------------
def test_clip_is_word_boundary():
    long = "alpha beta gamma delta " * 100
    clipped = kc._clip(long, 40)
    assert not clipped.rstrip(" …").endswith("delt")        # not mid-word
    assert kc._clip("short text", 40) == "short text"        # short passes through


# ---------------------------------------------------------------------------
# _chat retries transient network errors instead of dying
# ---------------------------------------------------------------------------
def test_create_retries_transient(monkeypatch):
    class Boom(Exception):
        pass
    monkeypatch.setattr(agent_core, "_TRANSIENT_ERRORS", (Boom,))
    monkeypatch.setattr(agent_core.time, "sleep", lambda *_: None)
    calls = {"n": 0}

    class Completions:
        def create(self, **kw):
            calls["n"] += 1
            if calls["n"] == 1:
                raise Boom("network blip")
            return "ok"

    client = type("C", (), {"chat": type("Ch", (), {"completions": Completions()})()})()
    assert agent_core._create(client, "m", [], [], "auto") == "ok"
    assert calls["n"] == 2                                   # failed once, retried, succeeded
