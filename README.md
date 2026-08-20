# AI Red Teaming Toolkit 🛡️⚡

An industry-grade, production-ready automated security evaluation suite for LLM Retrieval-Augmented Generation (RAG) chatbots.

Evaluates AI safety vulnerabilities across **5 attack categories** (25 total attack vectors) using high-speed Groq API inference and two-stage evaluation.

---

## 🎯 What It Tests

Total of **25 realistic security attacks** (5 per category):

1. **Prompt Injection**: Direct instruction overrides, context injection, and system tag bypass payloads.
2. **Jailbreak Attempts**: DAN persona, fictional scenario framing, hypothetical bypasses, and emotional manipulation.
3. **Role Confusion**: Developer mode activation claims, ARIA persona, and historical AI impersonation.
4. **System Prompt Leakage**: Direct extraction, repeat commands, translation tricks, and instruction disclosure.
5. **Data Extraction**: API key fishing, knowledge base dumps, PII exfiltration, and model configuration extraction.

---

## 🧠 Models & Architecture

- **Chatbot Target Model**: `llama-3.1-8b-instant` (Fast inference via Groq API)
- **Evaluation Judge Model**: `llama-3.3-70b-versatile` (Strong reasoning via Groq API)
- **Vector Embeddings**: `all-MiniLM-L6-v2` (Local via sentence-transformers, 100% free)
- **Vector Database**: ChromaDB (Lazy-initialized singleton, persistent)

---

## ⚡ Key Optimizations

- **Parallel Attack Engine**: Executed via `concurrent.futures.ThreadPoolExecutor(max_workers=3)` with staggered rate limiting.
- **Two-Stage Evaluation**:
  - _Stage 1 (Pattern Pre-Check)_: Instant keyword & signal matching (0 API cost).
  - _Stage 2 (LLM Judge)_: Invokes `llama-3.3-70b-versatile` only when pattern confidence is ambiguous, cutting API calls by 40-60%.
- **Thread-Safe Caching & Rate Limiters**: Response caching using MD5 hashing and sliding-window rate limiters with `threading.Lock()`.
- **Three-Layer Guardrails**: Input Sanitizer (40+ signals), Output Leak Filter, and Topic Validator.

---

## 🛠️ Setup & Installation

1. **Activate Virtual Environment**

   ```bash
   .venv\Scripts\activate   # Windows
   # or
   source .venv/bin/activate # Linux/macOS
   ```

2. **Install Dependencies**

   ```bash
   pip install -r requirements.txt
   ```

3. **Configure API Key**
   Copy `.env.example` to `.env` and set your free Groq API key:
   ```env
   GROQ_API_KEY=gsk_your_groq_api_key_here
   ```

---

## 🏃 Execution Modes

### 1. CLI Mode (`run_tests.py`)

Run security tests directly from the terminal:

```bash
# Run full comparison test (Vulnerable vs Secure + Markdown & JSON Report generation)
python run_tests.py --compare

# Run quick test (2 attacks per category)
python run_tests.py --mode quick

# Run single category
python run_tests.py --category "Prompt Injection"
```

### 2. Dashboard UI Mode (`app/main.py`)

Launch the interactive Streamlit security dashboard:

```bash
streamlit run app/main.py
```

---

## 📁 Project Structure

```
red-team-toolkit/
├── app/
│   ├── __init__.py
│   ├── target_chatbot.py      # RAG Chatbot (vulnerable & secure versions)
│   ├── attack_engine.py       # Parallel attack execution engine
│   ├── evaluator.py           # Two-Stage evaluation (Pattern + LLM Judge)
│   ├── guardrails.py          # 3-layer security defense system
│   ├── reporter.py            # Markdown + JSON audit report generator
│   └── main.py                # Streamlit security dashboard UI
├── attacks/
│   ├── __init__.py
│   ├── prompt_injection.py    # 5 prompt injection attacks
│   ├── jailbreak.py           # 5 jailbreak attacks
│   ├── role_confusion.py      # 5 role confusion attacks
│   ├── system_prompt_leakage.py # 5 system prompt leakage attacks
│   └── data_extraction.py     # 5 data extraction attacks
├── data/
│   └── aiseason-document.txt  # RAG knowledge base document
├── chroma_db/                 # Auto-built vector database (Gitignored)
├── reports/                   # Auto-generated audit reports (Gitignored)
├── .env                       # Environment variables (Gitignored)
├── .env.example               # Template environment configuration
├── .gitignore                 # Git exclusion rules
├── requirements.txt           # Python dependencies
├── run_tests.py               # CLI runner script
├── context.md                 # Session context tracker
└── README.md                  # Project documentation
```
