# Project Context: AI Red Teaming Toolkit

> **Status**: Setup & Initialization Phase  
> **Last Updated**: 2026-08-20

---

## 1. Overview

The **AI Red Teaming Toolkit** is an automated security evaluation suite for RAG (Retrieval-Augmented Generation) chatbots. It tests target LLM applications for security vulnerabilities across 5 attack categories using the **Groq API** for high-speed inference and evaluation.

---

## 2. LLM Architecture & Models

| Role                  | Model Name                | Provider | Purpose                                                    |
| --------------------- | ------------------------- | -------- | ---------------------------------------------------------- |
| **Target Chatbot**    | `llama-3.1-8b-instant`    | Groq API | Fast inference for RAG query handling under test           |
| **Evaluator / Judge** | `llama-3.3-70b-versatile` | Groq API | Strong reasoning judge model to score & classify responses |

---

## 3. Directory Structure

```
red-team-toolkit/
├── app/
│   ├── __init__.py
│   ├── target_chatbot.py      # RAG chatbot being tested (llama-3.1-8b-instant)
│   ├── attack_engine.py       # Orchestrator for 5 attack categories
│   ├── evaluator.py           # Judge model (llama-3.3-70b-versatile) response classifier
│   ├── guardrails.py          # Security defense & filtering mechanisms
│   ├── reporter.py            # Generates Markdown + JSON audit reports
│   └── main.py                # Streamlit interactive dashboard
├── attacks/
│   ├── __init__.py
│   ├── prompt_injection.py    # Direct & indirect prompt injection payloads
│   ├── jailbreak.py           # DAN, hypothetical, & persona jailbreaks
│   ├── role_confusion.py      # System role override & confusion payloads
│   ├── system_prompt_leakage.py # Extraction & leak payloads
│   └── data_extraction.py     # RAG context & knowledge base exfiltration
├── reports/                   # Output assessment logs (Gitignored)
├── data/
│   └── aiseason-document.txt  # Sample RAG knowledge base document
├── chroma_db/                 # Vector store directory (Gitignored)
├── .env                       # Environment variables (Gitignored)
├── .env.example               # Template environment configuration
├── .gitignore                 # Git exclusion rules
├── requirements.txt           # Python package dependencies
├── context.md                 # Active session context tracker (this file)
└── README.md                  # Project documentation & usage guide
```

---

## 4. Attack Categories

1. **Prompt Injection** (Direct instruction override & indirect payload injection)
2. **Jailbreak** (Persona adoption, fictional scenarios, restriction bypass)
3. **Role Confusion** (Assistant identity trickery & system prompt override)
4. **System Prompt Leakage** (Exposing instructions, system prompts & safety constraints)
5. **Data Extraction** (Exfiltrating out-of-context RAG documents & database secrets)

---

## 5. Development Progress & Checklist

- [x] Project directory structure & initial file scaffolding
- [x] Environment configuration (`.env`, `.env.example`, `.gitignore`)
- [x] Session context tracker (`context.md`)
- [x] Task 1: RAG Chatbot Implementation (`app/target_chatbot.py`)
- [x] Task 2: Attack Payloads (`attacks/*.py` - 25 attacks)
- [x] Task 3: Attack Orchestration Engine (`app/attack_engine.py`)
- [x] Task 4: LLM Judge Evaluator (`app/evaluator.py` - Two-Stage)
- [x] Task 5: Security Guardrails (`app/guardrails.py` - 3 Layers)
- [x] Task 6: Security Audit Reporting (`app/reporter.py` - Md & JSON)
- [x] Task 7: Streamlit Dashboard (`app/main.py` - 4 Tabs & Plotly)
- [x] Task 8: CLI Runner (`run_tests.py`)
- [x] Task 9: Production Requirements & Verification (`requirements.txt`, `README.md`)

---

## 6. Status Summary

- **Status**: Production Ready ✅
- **All Python Files Compiled**: Verified cleanly with `py_compile`.
- **Execution Modes**: CLI (`python run_tests.py --compare`) and Web Dashboard (`streamlit run app/main.py`).

---

## 6. Next Steps

- Await user prompts for detailed component implementations (Task 1 to Task 7).
- Update this `context.md` file after each session or major update.
