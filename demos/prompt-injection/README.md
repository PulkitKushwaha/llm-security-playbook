# Prompt Injection Demos
 
This folder contains working demonstrations of prompt injection
attacks against LLM-powered systems. It does not just stop here, it also covers the defenses that stop them.
 
---
 
## What is prompt injection?
 
Prompt injection occurs when an attacker crafts input that causes
the LLM to treat their content as instructions rather than data.
The LLM has no reliable way to distinguish between the developer's
instructions (system prompt) and the attacker's instructions
(injected via user input or retrieved content), unless the system
is explicitly designed to enforce that boundary.
 
There are two types:
 
**Direct injection**: attacker controls the user input field directly.
They type instructions designed to override the system prompt.
 
**Indirect injection**: attacker plants malicious instructions in
content the system will retrieve like documents, web pages, tool outputs.
The LLM retrieves and processes this content, following the embedded
instructions as if they were legitimate.
 
---
 
## Demos in this folder
 
| File | Attack type | Status |
|---|---|---|
| `direct_injection.py` | Direct prompt injection — 5 attack payloads | ✅ Done |
| `indirect_injection.py` | Indirect injection via documents and tool output | 🟡 Coming soon |
| `system_prompt_extraction.py` | System prompt extraction techniques | ⬜ Coming soon |
 
---
 
## Running the demos
 
```bash
# Direct injection demo
python demos/prompt-injection/direct_injection.py
 
# With real OpenAI API (set in .env first)
USE_REAL_LLM=true python demos/prompt-injection/direct_injection.py
```
 
---
 
## Key takeaway
 
The vulnerable pipeline and hardened pipeline in these demos
receive the exact same attack payloads. The difference is entirely
in how the system is designed, not in the LLM itself.
 
Prompt injection is not an LLM problem. It is a system design problem.
