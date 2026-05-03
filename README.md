# llm-security-playbook

A practical security reference for AI engineers: covering LLM threat modeling, attack demonstrations, and mitigation patterns for production AI systems.

> After working on enterprise grade LLM based applications, one thing I have realised is that most LLM security issues aren't exotic. They're the same trust boundary violations we've seen in software for decades, just wearing a new coat. This playbook documents them, demonstrates them, and shows how to defend against them.

---

## Why this exists

As LLMs move into enterprise production, meaning, handling sensitive documents, calling external APIs, executing code, and making decisions, the attack surface grows significantly. Yet most AI engineers, very well versed with the programmatic nuances of LLMs, ship systems without ever thinking about:

- What happens when a user tries to override the system prompt?
- How an attacker can exfiltrate data through a RAG pipeline?
- What a malicious document injected into the knowledge base can do?
- How to validate that the model's output isn't leaking PII?

I got these questions asked by the experienced code reviewers, as well as the veterans of Data Science present in the industry for more than 15 years. I did my research and found some very interesting insights I was not even aware of before this. This playbook is a living reference for the same. It combines threat modeling theory with working demonstrations and practical mitigations, written for engineers like me, who build these systems, not just security researchers who study them.

---

## Structure

```
llm-security-playbook/
├── threat-modeling/          # Threat modeling frameworks and templates
├── demos/
│   ├── prompt-injection/     # Direct and indirect injection demos
│   ├── jailbreaks/           # Jailbreak techniques and defenses
│   ├── data-exfiltration/    # RAG pipeline data leakage demos
│   └── red-teaming/          # Automated red-teaming scripts
├── mitigations/              # Defense patterns and guardrails code
├── notebooks/                # Research and analysis notebooks
└── references/               # OWASP LLM Top 10 and further reading
```
