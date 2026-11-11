# AI Red-Teaming & Code Security Audit: Multi-Tool Agents (Python & Go)

**Author:** Kausar Khokhar (AI Model Evaluator & Backend Software Engineer, MSc Advanced Computer Science)  
**Focus Areas:** Indirect Prompt Injection · Privilege Escalation · `MEMORY.md` State Poisoning · Go/Python Security Code Review · TDD (`PyTest`)

---

## Executive Summary
Autonomous AI agents connected to live tools (**Gmail API**, **Supabase/PostgreSQL**, and persistent **`MEMORY.md`** state files) introduce severe attack surfaces when untrusted external inputs mix with high-privilege execution contexts.

This repository presents a complete **Red-Team Audit & Remediation Benchmark** covering both **Python Agentic Workflows** and **Go Backend Microservices**.

---

## Threat Matrix & Audit Findings

| ID | Vulnerability Category | Component | Attack Vector (Red Team) | Gold-Standard Fix Implemented |
| :--- | :--- | :--- | :--- | :--- |
| **VULN-01** | **Indirect Prompt Injection** | `src/vulnerable_agent.py` | Malicious instructions hidden inside an incoming Gmail body hijack the LLM into calling administrative tools. | Structural XML data isolation (`<untrusted_email_payload>`), delimiter escaping, and regex control-override detection. |
| **VULN-02** | **Cross-Tenant Privilege Escalation (IDOR)** | `src/vulnerable_agent.py` & `vulnerable_handler.go` | Agent manipulates `target_user_id` in tool arguments to query other customers' records in Supabase. | Zero-trust session binding: tool execution enforces `authenticated_user_id == target_user_id` at the API contract layer. |
| **VULN-03** | **Persistent State Poisoning (`MEMORY.md`)** | `src/vulnerable_agent.py` | Attacker tricks agent into writing a rogue directive into `MEMORY.md`, infecting all future multi-turn sessions. | Pre-write state validation guardrails scanning for instruction overrides before committing to `MEMORY.md`. |
| **VULN-04** | **Data Exfiltration & PII Leakage** | `src/vulnerable_agent.py` & `vulnerable_handler.go` | Compromised agent emails sensitive data to an external domain; Go microservice logs raw API keys and PII to stdout. | Strict outbound domain allowlisting + automated regex redaction for credit cards, PII, and API secrets (`sk-...`, `supa_...`). |

---

## Running the Automated Security Test Suite (`PyTest`)

```bash
pip install pytest
pytest -v
```
