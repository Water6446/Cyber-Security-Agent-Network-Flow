# Lab data — provenance and attribution

## `tuesday_teaching_slice.csv`

A 6,500-flow slice (~2.9 MB) of **CIC-IDS2017**, taken from the Tuesday capture,
containing a genuine FTP/SSH brute-force attack (source `172.16.0.1`) mixed with
benign background traffic. It is committed so the lab needs no multi-gigabyte
download. Columns are unmodified CICFlowMeter output, including the `Label`
column — which the Network Analyst never sees (it is dropped at load time; see
`docs/architecture.md`).

### Source

**CIC-IDS2017**, created by the Canadian Institute for Cybersecurity (CIC) at
the University of New Brunswick.

- Dataset page: <https://www.unb.ca/cic/datasets/ids-2017.html>

### Required citation

If you use this slice — or the full dataset — in published work, cite the
authors' paper as they request:

> Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani.
> "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic
> Characterization." *4th International Conference on Information Systems
> Security and Privacy (ICISSP)*, Portugal, January 2018.

```bibtex
@inproceedings{sharafaldin2018toward,
  title     = {Toward Generating a New Intrusion Detection Dataset and
               Intrusion Traffic Characterization},
  author    = {Sharafaldin, Iman and Lashkari, Arash Habibi and
               Ghorbani, Ali A.},
  booktitle = {Proceedings of the 4th International Conference on Information
               Systems Security and Privacy (ICISSP)},
  pages     = {108--116},
  year      = {2018},
  address   = {Funchal, Madeira, Portugal}
}
```

### Terms

CIC makes the dataset publicly available for research and educational use, and
asks that the paper above be cited in any work that uses it. This slice is
redistributed here on that basis, for teaching. The dataset remains the work of
its authors — **the project license does not apply to it**, and nothing in this
repository grants you rights to CIC's data beyond what CIC itself grants. Check
the dataset page for the current terms before redistributing it further.

## Other datasets used by this project (not committed here)

- **CIC-IDS2017 (full)** — `GeneratedLabelledFlows`, same source and citation as
  above. Git-ignored; see the main `README.md` for where to extract it.
- **DAPT 2020** — the phase-labeled APT dataset used for kill-chain phase
  scoring. Not committed; separately licensed by its authors. Cite:

  > Sowmya Myneni, Ankur Chowdhary, Abdulhakim Sabur, Sailik Sengupta,
  > Garima Agrawal, Dijiang Huang, and Myong Kang. "DAPT 2020 — Constructing a
  > Benchmark Dataset for Advanced Persistent Threats." *Deployable Machine
  > Learning for Security Defense (MLHat), Springer*, 2020.

- **MITRE ATT&CK** — the Enterprise STIX bundle, downloaded and cached at
  runtime from <https://github.com/mitre/cti>. © The MITRE Corporation,
  redistributed by MITRE under the ATT&CK Terms of Use
  (<https://attack.mitre.org/resources/legal-and-branding/terms-of-use/>).
  Not committed; fetched on first run.
