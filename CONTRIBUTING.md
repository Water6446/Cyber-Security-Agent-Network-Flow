# Contributing

Thanks for looking. This is a personal research and teaching project, not a
product, and it is maintained by one person. That shapes what is useful to send.

## Before you open a PR

**Open an issue first for anything non-trivial.** The architecture has a few
load-bearing constraints (below) that are easy to violate by accident, and I'd
rather discuss the approach than reject a finished patch.

Good contributions, roughly in order of how welcome they are:

- Bug reports with a reproduction.
- Fixes to the course modules and the lab — wrong explanations, broken steps,
  unclear exercises.
- New dataset loaders that conform to `datasets/base.Loader`.
- Test coverage for a path that isn't covered.

## The constraints that are not up for negotiation

These are the project's whole point; a change that breaks one will not be
merged, however convenient it is.

1. **Code computes, the model transcribes.** Every factual claim in agent output
   must trace to a tool result visible in the model's context. No agent
   estimates a number.
2. **Ground truth stays quarantined.** The `Label` column, the answer key, and
   the phase crosswalk live in `src/eval_sidecar.py` and never enter any
   agent's context. `tests/test_quarantine.py` enforces this by grepping the
   agent modules — if your change makes that test fail, the change is wrong,
   not the test.
3. **Narrow tools, capped outputs, hard turn limits.** `MAX_TURNS`,
   `MAX_ROWS_RETURNED`, `MAX_TOOL_RESULT_CHARS` exist so a run cannot become
   unbounded. Don't raise them to make an agent "smarter."
4. **Routing is deterministic code.** No supervisor LLM. The only dynamism is
   the two capped feedback edges.
5. **Evaluation stays outside the graph.** Scoring happens after agents finish.

`docs/design_decisions.md` explains the reasoning behind each of these.

## Running the checks

From the repository root:

```
python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m pytest -q
```

All tests must pass. Tests that need the MITRE ATT&CK bundle (~50 MB, fetched
on first run and cached in the git-ignored `data/`) skip automatically when it
can't be downloaded, so an offline run reports skips rather than failures — but
please run with network before sending a PR so those actually execute.

No LLM provider or API key is needed for the test suite: the model-driven paths
use a scripted fake client.

Keep the existing style — the codebase favors explanatory comments about *why*
a non-obvious choice was made. Match the density of the file you're editing.

## Licensing of contributions

This project is licensed under the [PolyForm Noncommercial License
1.0.0](LICENSE): free for noncommercial use, with commercial use requiring a
separate license from me.

By submitting a contribution you agree that it is your own work and that it is
licensed to the project under those same terms, and that I may also license the
project — including your contribution — commercially. If you are not able to
agree to that, please open an issue to discuss before sending code.

## Datasets

Don't commit dataset files. The only committed data is the small teaching slice
in `course/lab/data/`, and it has its own attribution requirements — see
[`course/lab/data/README.md`](course/lab/data/README.md). `.gitignore` blocks
`*.csv`, `*.zip`, and `*.pcap` deliberately.
