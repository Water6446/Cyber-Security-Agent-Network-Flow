# Module 3 — Cyber Threat Detection

**Estimated time:** 45–60 minutes
**Prerequisites:** basic networking; Module 1.

## Learning objectives

1. Explain the difference between packets and flows, and why this project uses flows.
2. Describe what CICFlowMeter computes and why those features exist.
3. Contrast signature-based and anomaly-based detection, with the trade-offs of each.
4. Restate the base-rate problem in detection terms and explain what it does to precision.
5. Explain why labeled datasets are scarce and what that scarcity does to the whole field.

## 1. Packets vs. flows

At the lowest level, a network moves **packets** — individual chunks of data, each with a header (who sent it, to whom, which port, which protocol) and a payload (the actual bytes). A busy network moves millions of packets a second. Analyzing every packet is expensive and, for encrypted traffic, largely uninformative — you can see the envelope but not the letter.

A **flow** is a summary of a conversation. Take all the packets that share the same "5-tuple" — source IP, source port, destination IP, destination port, protocol — over a period of time, and describe them with statistics: how long the conversation lasted, how many packets and bytes went each way, the average packet size, the timing between packets, which TCP flags appeared. One flow record stands in for potentially thousands of packets.

This project uses flows, for three reasons. They are far smaller and faster to process. They survive encryption — you lose the payload but keep the *behavioral* shape, and much of what betrays an attack (a host touching hundreds of ports, or hammering one port thousands of times) is behavioral. And they are what the available labeled datasets provide.

## 2. What CICFlowMeter computes, and why

**CICFlowMeter** is the tool that turns raw packet captures (pcaps) into flow records with roughly 80 statistical features each. Both datasets in this project (CIC-IDS2017 and DAPT 2020) are its output, which is why the dataset adapter work is small — same feature language, different content.

The features are not arbitrary; each exists because some attack disturbs it:

- **Flow duration, packets/bytes per direction:** a brute-force login attempt is short with tiny payloads (a rejected password exchange); a file transfer is long with large payloads. The shape distinguishes them.
- **Inter-arrival times:** automated tools produce mechanically regular timing; humans don't. Beaconing malware "phones home" on a clock.
- **TCP flag counts (SYN, ACK, RST, FIN):** a completed handshake looks different from a scan (many SYNs, few completions) or a rejected connection (RSTs). This project's `flag_summary` tool sums exactly these to tell failed attempts from real sessions.
- **Forward/backward asymmetry:** who is doing the talking. A scanner sends much and receives little.

The lesson for building tools: you don't need payloads to catch a lot of behavior, but you *do* need to know which feature each attack disturbs — otherwise you are computing 80 numbers and reasoning about none of them.

## 3. Signatures vs. anomalies

Two philosophies of detection, each with a failure mode.

**Signature-based** detection looks for known-bad patterns: "if you see exactly this byte sequence / this port / this behavior, alert." It is precise and explainable — a hit tells you *what* it matched. Its weakness is that it only catches what someone already wrote a signature for. A novel attack, or a small variation on a known one, walks straight past.

**Anomaly-based** detection learns what "normal" looks like and flags deviations. It can, in principle, catch novel attacks — anything unusual is suspicious. Its weakness is brutal: *normal* on a real network is enormously varied, so "unusual" fires constantly. Every new server, every quarterly backup, every developer experiment looks anomalous. Anomaly detectors are false-positive machines unless carefully tuned, and tuning them requires exactly the labeled data the field lacks (Section 5).

Most real systems blend both. This project's Network Analyst is closer to anomaly reasoning — it establishes a baseline and investigates deviations — but crucially it does not *classify*; it surfaces findings for downstream agents and a human, which is how it avoids the anomaly detector's false-positive trap becoming the final word.

## 4. The base-rate problem, in detection terms

Module 1 introduced the base rate; here is what it does to a detector's numbers. **Precision** is: of everything you flagged, how much was really bad? When attacks are rare, precision is dominated by false positives no matter how good your recall (how much of the real bad you caught). A detector that catches 100% of attacks but also flags 0.5% of an ocean of benign traffic will still hand the analyst a queue that is mostly wrong.

This is why "accuracy" is a near-useless headline number in security, and why this project **never reports a single blended accuracy figure** for its phase scoring. It reports the pieces separately — agreement, plausible-but-different, and outright disagreement — because a single number hides exactly the false-positive story that matters.

## 5. Why labeled data is scarce — and what that does to the field

To train or fairly evaluate a detector, you need data labeled with the truth: which flows were attacks, and ideally which kind. This is painfully scarce, and the reasons compound:

- **Real attack traffic is rare and sensitive.** Organizations that have it usually cannot share it (it contains real victims and real infrastructure).
- **Labeling requires expert time** — someone has to know that *this* flow was the attack — and experts are the bottleneck the whole field is trying to relieve.
- **Labels go stale.** Attacks evolve; a 2017 dataset teaches 2017 attacks.
- **Synthetic datasets have artifacts.** Labs like CIC generate attacks in a controlled network, which is the only way to get clean labels — but it also means the "benign" traffic is cleaner and the attacks more textbook than reality, and models can learn the artifact instead of the attack.

The downstream effect is large. Scarcity is *why* supervised ML struggles here (Module 1), *why* datasets like DAPT 2020 with per-stage labels are precious enough to build a milestone around, and *why* this project leans on a framework (ATT&CK) and code-computed grounding rather than a trained classifier: when you cannot trust a label distribution, you lean on structure you *can* verify.

## Key terms

- **Packet / flow:** an individual data chunk / a statistical summary of a whole conversation.
- **5-tuple:** src IP, src port, dst IP, dst port, protocol — the identity of a flow.
- **CICFlowMeter:** tool that converts pcaps into ~80-feature flow records.
- **Signature detection / anomaly detection:** match known-bad / flag deviations from normal.
- **Precision / recall:** fraction of flags that were right / fraction of real attacks caught.
- **Label scarcity:** the chronic shortage of ground-truth-labeled attack data.

## Check your understanding

1. **Why use flows instead of packets here?**
   Smaller and faster, they survive encryption (behavior is preserved), and the labeled datasets are provided as flows.

2. **Pick a CICFlowMeter feature and name an attack that disturbs it.**
   E.g., TCP SYN flag count — a port scan produces many SYNs with few completed handshakes; or flow duration — brute-force logins are very short.

3. **State one strength and one weakness of signature detection.**
   Strength: precise and explainable. Weakness: blind to novel or slightly-varied attacks.

4. **Why is "accuracy" a misleading headline for a detector?**
   Because attacks are rare; the base rate makes false positives dominate, so a high accuracy can still mean a mostly-wrong queue.

5. **Give two reasons labeled attack data is scarce, and one consequence.**
   Real attack data is sensitive/unshareable and labeling needs expert time (also: labels go stale). Consequence: supervised ML struggles, so the field leans on frameworks and verifiable structure.

## Further reading

- CICFlowMeter documentation and its feature list.
- CIC-IDS2017 and DAPT 2020 dataset papers (note the "known caveats" — class imbalance, capture-window artifacts).
- Axelsson, "The base-rate fallacy and the difficulty of intrusion detection."
