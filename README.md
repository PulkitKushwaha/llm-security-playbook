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

---
 
## Scope
 
This playbook covers threats specific to **LLM-powered systems** — RAG pipelines, AI agents, copilots, and multi-modal systems. It does not cover general application security (SQL injection, XSS, etc.) except where they intersect with LLM behavior.
 
**Threat categories covered:**
 
| Category | Description |
|---|---|
| Prompt Injection | Manipulating LLM behavior through crafted inputs: both direct (user input) and indirect (via documents, tool outputs) |
| Jailbreaking | Bypassing safety constraints and policy guardrails through adversarial prompts |
| Data Exfiltration | Extracting sensitive data from context windows, system prompts, or RAG knowledge bases |
| Insecure Output Handling | Trusting LLM output without validation: leading to XSS, code execution, or incorrect decisions |
| RAG Pipeline Attacks | Poisoning knowledge bases with malicious documents to manipulate retrieval and generation |
| Excessive Agency | Agents taking unintended real-world actions due to overpermissioned tools or weak guardrails |
| Model Denial of Service | Overloading models with resource-intensive or recursive prompts to degrade availability |
 
---

## Status
 
| Section | Status |
|---|---|
| Threat modeling overview | Done |
| OWASP LLM Top 10 breakdown | In progress |
| Prompt injection demos | Coming soon |
| Jailbreak demos | Coming soon |
| Data exfiltration demos | Coming soon |
| Red-teaming scripts | Coming soon |
| Mitigation patterns | Coming soon |
 
---
 
*Part of the [ai-engineering-portfolio](https://github.com/pulkitkushwaha/ai-engineering-portfolio) — built by [Pulkit Kushwaha](https://linkedin.com/in/pulkit-kushwaha)*
 
