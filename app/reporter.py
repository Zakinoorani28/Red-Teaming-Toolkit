"""
Reporter Module - Production Security Report Generator & Audit Exporter.
Generates comprehensive Markdown reports, structured JSON exports, and files saved with ISO timestamps.
"""

import os
import json
from datetime import datetime
from typing import List, Dict, Any

from app.guardrails import get_guardrail_stats


def generate_markdown_report(
    before_results: List[Dict[str, Any]],
    after_results: List[Dict[str, Any]],
    before_summary: Dict[str, Any],
    after_summary: Dict[str, Any]
) -> str:
    """
    Generates a full structured security audit report in Markdown format.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    b_rate = before_summary.get("vulnerability_rate_percent", 0.0)
    a_rate = after_summary.get("vulnerability_rate_percent", 0.0)
    improvement = round(max(0.0, b_rate - a_rate), 2)
    b_level = before_summary.get("overall_risk_level", "UNKNOWN")
    a_level = after_summary.get("overall_risk_level", "UNKNOWN")

    # Posture Score calculation (0-100)
    posture_score = round(max(0.0, 100.0 - a_rate), 1)

    report = []

    # Title & Metadata
    report.append("# 🛡️ AI Red Teaming Security Audit Report")
    report.append(f"**Date**: {timestamp}  ")
    report.append("**Target**: AI Season RAG Chatbot (`llama-3.1-8b-instant`)  ")
    report.append("**Evaluator**: LLM Judge (`llama-3.3-70b-versatile`)  ")
    report.append("**Embeddings**: `all-MiniLM-L6-v2` (Local ChromaDB)  ")
    report.append("**Toolkit Version**: AI Red Teaming Toolkit v1.0 Production  \n")
    report.append("---")

    # 1. Executive Summary
    report.append("## 1. Executive Summary\n")
    report.append(f"- **Vulnerability Rate (Before Guardrails)**: `{b_rate}%` ({before_summary.get('total_succeeded', 0)}/{before_summary.get('total_attacks', 0)} exploits succeeded)")
    report.append(f"- **Vulnerability Rate (After Guardrails)**: `{a_rate}%` ({after_summary.get('total_succeeded', 0)}/{after_summary.get('total_attacks', 0)} exploits succeeded)")
    report.append(f"- **Security Risk Reduction**: `{improvement}%` improvement")
    report.append(f"- **Overall Risk Level**: **{b_level}** (Before) → **{a_level}** (After)")
    report.append(f"- **Overall Security Posture Score**: `{posture_score} / 100`\n")

    # 2. Attack Results Overview Table
    report.append("## 2. Attack Results Overview Table\n")
    report.append("| Attack ID | Category | Attack Name | Severity | Verdict (Before) | Verdict (After) | Response Time (ms) |")
    report.append("|---|---|---|---|---|---|---|")

    # Map after_results by attack_id for easy lookup
    after_map = {r["attack_id"]: r for r in after_results}

    for b_item in before_results:
        aid = b_item.get("attack_id", "N/A")
        cat = b_item.get("category", "N/A")
        name = b_item.get("attack_name", "N/A")
        sev = b_item.get("severity", "N/A")
        v_b = b_item.get("verdict", "N/A")
        
        a_item = after_map.get(aid, {})
        v_a = a_item.get("verdict", "N/A")
        t_ms = b_item.get("response_time_ms", 0)

        report.append(f"| {aid} | {cat} | {name} | `{sev}` | **{v_b}** | **{v_a}** | {t_ms} ms |")

    report.append("\n")

    # 3. Critical Findings
    report.append("## 3. Critical Findings (Before Guardrails)\n")
    critical_findings = before_summary.get("critical_findings", [])

    if not critical_findings:
        report.append("No critical severity attacks succeeded during testing.\n")
    else:
        for idx, item in enumerate(critical_findings, 1):
            prompt_snip = item.get("prompt", "")[:200]
            resp_snip = item.get("response", "")[:100]
            report.append(f"### Finding {idx}: [{item.get('attack_id')}] {item.get('attack_name')}")
            report.append(f"- **Category**: {item.get('category')} | **Severity**: `{item.get('severity')}`")
            report.append(f"- **Prompt**: `{prompt_snip}`")
            report.append(f"- **Chatbot Response Excerpt**: `{resp_snip}...`")
            report.append(f"- **Impact & Vulnerability**: {item.get('reason', 'Presents severe risk of system override, key disclosure, or prompt extraction.')}\n")

    # 4. Vulnerability Analysis by Category
    report.append("## 4. Vulnerability Analysis by Category\n")
    by_cat_b = before_summary.get("by_category", {})
    by_cat_a = after_summary.get("by_category", {})

    for cat in sorted(by_cat_b.keys()):
        b_s = by_cat_b.get(cat, {})
        a_s = by_cat_a.get(cat, {})
        cat_attacks = [r for r in before_results if r.get("category") == cat and r.get("verdict") == "SUCCEEDED"]
        most_dangerous = cat_attacks[0].get("attack_name", "None (All Defended)") if cat_attacks else "None"

        report.append(f"### {cat}")
        report.append(f"- **Attacks Tested**: {b_s.get('total', 0)}")
        report.append(f"- **Exploited Before Guardrails**: {b_s.get('succeeded', 0)} ({b_s.get('vulnerability_rate_percent', 0.0)}%)")
        report.append(f"- **Exploited After Guardrails**: {a_s.get('succeeded', 0)} ({a_s.get('vulnerability_rate_percent', 0.0)}%)")
        report.append(f"- **Most Dangerous Vector**: {most_dangerous}\n")

    # 5. Security Improvements Applied
    g_stats = get_guardrail_stats()
    report.append("## 5. Security Improvements Applied & Defense Audit\n")
    report.append("1. **Layer 1 — Input Sanitizer (`sanitize_input`)**: Intercepts 40+ injection signals (DAN, developer mode, override commands) before model invocation.")
    report.append(f"   - *Triggered*: `{g_stats.get('input_sanitizer_triggered', 0)} times`")
    report.append("2. **Layer 2 — Output Filter (`filter_output`)**: Scrubs accidental system instruction leaks and API credential strings (`gsk_`, `sk-`).")
    report.append(f"   - *Triggered*: `{g_stats.get('output_filter_triggered', 0)} times`")
    report.append("3. **Layer 3 — Topic Guardrail (`validate_topic`)**: Validates RAG context presence and restricts response scope strictly to AI Season course material.")
    report.append(f"   - *Triggered*: `{g_stats.get('topic_validator_triggered', 0)} times`\n")

    # 6. Before vs After Comparison
    report.append("## 6. Before vs After Side-by-Side Comparisons\n")
    sample_ids = [r["attack_id"] for r in before_results[:5]]

    for aid in sample_ids:
        b_item = next((r for r in before_results if r["attack_id"] == aid), {})
        a_item = next((r for r in after_results if r["attack_id"] == aid), {})

        if b_item and a_item:
            b_resp = b_item.get("response", "")[:120].replace("\n", " ")
            a_resp = a_item.get("response", "")[:120].replace("\n", " ")
            report.append(f"#### [{aid}] {b_item.get('attack_name')} ({b_item.get('category')})")
            report.append(f"**Prompt**: `{b_item.get('prompt')}`  ")
            report.append(f"- **Vulnerable Response**: `{b_resp}...` *(Verdict: {b_item.get('verdict')})*")
            report.append(f"- **Secure Response**: `{a_resp}...` *(Verdict: {a_item.get('verdict')})*\n")

    # 7. Timing Analysis
    t_b = before_summary.get("timing_stats", {})
    report.append("## 7. Performance & Timing Analysis\n")
    report.append(f"- **Average Chatbot Response Time**: `{t_b.get('avg_response_time_ms', 0)} ms`")
    report.append(f"- **Minimum Response Time**: `{t_b.get('min_response_time_ms', 0)} ms`")
    report.append(f"- **Maximum Response Time**: `{t_b.get('max_response_time_ms', 0)} ms`\n")

    # 8. Recommendations
    report.append("## 8. Actionable Security Recommendations\n")
    report.append("1. **Strict System Prompt Hardening**: Maintain explicit rule definitions prohibiting role modification, developer mode simulation, or instruction disclosure.")
    report.append("2. **Multi-Tier Input/Output Gateways**: Enforce production input sanitizers and output pattern filters at the API gateway layer.")
    report.append("3. **Vector Context Distance Thresholding**: Set similarity score minimums in ChromaDB to reject out-of-domain queries before generation.")
    report.append("4. **Credential & Config Isolation**: Ensure administrative secrets and internal server keys are kept out of RAG index text files.")
    report.append("5. **Continuous Automated Red Teaming**: Integrate red teaming evaluation suites into CI/CD deployment pipelines.\n")

    # 9. Conclusion
    report.append("## 9. Conclusion & Final Assessment\n")
    report.append(f"The AI Red Teaming Toolkit evaluation confirms that applying multi-layered security guardrails reduced the target RAG chatbot's vulnerability rate from **{b_rate}%** down to **{a_rate}%**, resulting in an overall posture score of **{posture_score} / 100**.")

    return "\n".join(report)


def generate_json_results(
    before_results: List[Dict[str, Any]],
    after_results: List[Dict[str, Any]],
    before_summary: Dict[str, Any],
    after_summary: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Generates structured, validated JSON serializable assessment dataset.
    """
    return {
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "target_model": "llama-3.1-8b-instant",
            "judge_model": "llama-3.3-70b-versatile",
            "embedding_model": "all-MiniLM-L6-v2",
            "toolkit_version": "1.0-production"
        },
        "before_summary": before_summary,
        "after_summary": after_summary,
        "before_results": before_results,
        "after_results": after_results
    }


def save_all_reports(
    before_results: List[Dict[str, Any]],
    after_results: List[Dict[str, Any]],
    before_summary: Dict[str, Any],
    after_summary: Dict[str, Any],
    output_dir: str = "reports"
) -> Dict[str, str]:
    """
    Saves timestamped Markdown report and validated JSON file to reports/ directory.
    """
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    md_path = os.path.join(output_dir, f"red_team_report_{ts}.md")
    json_path = os.path.join(output_dir, f"red_team_results_{ts}.json")

    md_content = generate_markdown_report(before_results, after_results, before_summary, after_summary)
    json_content = generate_json_results(before_results, after_results, before_summary, after_summary)

    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_content, f, indent=2, ensure_ascii=False)

    return {
        "markdown_path": md_path,
        "json_path": json_path
    }
