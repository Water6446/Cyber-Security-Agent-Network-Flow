# Module 1 — AI in Cybersecurity

**Estimated time:** 45–60 minutes
**Prerequisites:** comfort with basic networking (IP addresses, ports) and a scripting language. No security or machine-learning background assumed.

## Learning objectives

By the end of this module you should be able to:

1. Describe what a security analyst actually does in a day, and why the volume of alerts is the core problem.
2. Explain "alert fatigue" and the base-rate problem in your own words.
3. Say where machine learning has helped in security and where it has repeatedly disappointed.
4. Explain why large language models (LLMs) change the *shape* of the problem — and why they are **not** detectors.
5. Place this project correctly: an *explanation and triage* system that sits **downstream** of detection.

## 1. The analyst's day

Picture a Security Operations Center (SOC). Sensors all over the network — firewalls, intrusion-detection systems, endpoint agents — generate *alerts*. An alert is a machine saying "this looks like it might be bad." A tier-1 analyst's job is to work through a queue of these alerts and decide, for each one, whether it is a real problem or noise.

The catch is the queue never ends. A mid-size organization can generate tens of thousands of alerts a day. The overwhelming majority are false alarms — a backup job that looks like data exfiltration, a vulnerability scanner doing its scheduled Sunday run, a developer's script hammering an API. The analyst has to triage: dismiss the noise fast, escalate the few that matter, and do it without missing the one alert in ten thousand that is a genuine breach.

## 2. Alert fatigue and the base-rate problem

Two forces make this hard.

**Alert fatigue** is the human cost of that queue. When 99% of what you see is a false alarm, you learn — rationally — to dismiss quickly. But that same reflex is exactly how a real attack slips through: it looks like all the other noise you have been trained by experience to ignore.

**The base-rate problem** is the math underneath the fatigue. Suppose attacks are genuinely rare — say 1 in 10,000 flows is malicious. Even a very good detector that is 99% accurate will produce a flood of false positives simply because there are so many benign events to be wrong about. If you flag 1% of 10,000 benign flows, that is 100 false alarms for every single real one. High accuracy on a rare event still buries the analyst. This is not a solvable-by-trying-harder problem; it is a property of rare events, and every detection system lives with it.

## 3. Where ML has and has not worked

Machine learning has a real track record in security, but an uneven one.

It has worked well where there is a large, clean, labeled signal and the cost of a mistake is bounded: **spam filtering** is the classic success — billions of labeled examples, fast feedback, and a wrong call is merely annoying. It has helped in **malware classification** and in flagging **statistical anomalies** in well-understood traffic.

It has repeatedly disappointed as a general "find the intrusion" box for reasons that trace straight back to Sections 1–2: labeled attack data is scarce and quickly stale, attackers adapt on purpose (unlike spam, the adversary is trying to look normal), and the base rate guarantees false positives. A model trained on last year's attacks does not recognize this year's, and a model tuned to catch everything drowns the analyst. The lesson is not "ML is useless in security" but "ML is a tool with sharp edges, and detection is the hardest place to point it."

## 4. Why LLMs change the shape of the problem

Large language models are good at something the earlier tools were not: **reasoning over evidence and explaining a conclusion in language a human can check**. That is a different capability from *detecting*.

This distinction is the whole thesis of the project. An LLM is a poor detector — ask it "is this flow an attack?" and it will guess, confidently, from priors it cannot show you. But give it *findings that a detector already surfaced* and ask it to investigate them with tools, map them to a known framework, and write up what it found — and now it is doing the analyst's *triage and explanation* work, which is exactly the expensive, human-bottlenecked part.

So this project deliberately does not build a detector. It builds a system that sits **downstream** of detection: raw flows come in, a chain of agents investigates and reasons, and a written incident report comes out — with every claim traceable to evidence. The point is not to replace the detector; it is to help a human get through the queue and understand what they are looking at.

## 5. Framing this project

Hold onto one sentence: **this is an explanation-and-triage system, not a detector.** Everything else in the course follows from it. When we measure the system (Module 3), we measure whether its *explanations* are grounded and useful, not whether it "caught the attack" — because catching is the detector's job. When we worry about hallucination (Module 4), it is because an explanation that invents evidence is worse than no explanation. And when we talk about what a human analyst still does better (the reflections), it is the judgment around the explanation, not the raw pattern-matching.

## Key terms

- **SOC (Security Operations Center):** the team and tooling that monitors an organization for security events.
- **Alert:** a machine-generated signal that something might be malicious.
- **Triage:** deciding, per alert, whether it is noise or worth escalating.
- **Alert fatigue:** the desensitization that comes from a queue dominated by false alarms.
- **Base rate:** how common the thing you are looking for actually is; when it is rare, even accurate detectors produce many false positives.
- **False positive / false negative:** a benign event flagged as malicious / a malicious event missed.
- **Detection vs. triage:** finding candidate events vs. investigating and explaining them.

## Check your understanding

1. **Why doesn't a 99%-accurate detector solve the SOC's problem?**
   Because attacks are rare. If benign events vastly outnumber attacks, even a 1% false-positive rate produces far more false alarms than true detections (the base-rate problem). Accuracy alone is the wrong measure for a rare event.

2. **Give an example of a security task where ML clearly succeeded, and say what made it different.**
   Spam filtering — enormous clean labeled data, fast feedback, and low cost of error. Intrusion detection has none of those properties.

3. **In one sentence, what is the difference between what a detector does and what this project's system does?**
   A detector finds candidate suspicious events; this system investigates those findings, maps them to known techniques, and explains them for a human.

4. **Why is an LLM a bad detector but a plausible triage assistant?**
   As a detector it guesses from hidden priors; as a triage assistant it reasons over evidence it is given and produces an explanation a human can verify.

5. **What would it mean for this system to "work well," given that it is not a detector?**
   Its explanations are grounded in real evidence, correctly mapped, honest about uncertainty, and genuinely save analyst time — not that it caught every attack.

## Further reading

- MITRE ATT&CK "Getting Started" — orientation to the framework used later in the course.
- CIC-IDS2017 dataset description (University of New Brunswick) — the data this project runs on.
- Any introductory piece on the "base rate fallacy in intrusion detection" (Axelsson's 1999 paper is the classic).
