"""
CLI Runner Script for AI Red Teaming Toolkit.
Run security evaluation suites directly from the terminal.

Usage:
  python run_tests.py --mode full
  python run_tests.py --mode quick
  python run_tests.py --category "Prompt Injection"
  python run_tests.py --compare
"""

import sys
import os
import argparse
import time
from typing import Dict, Any
from dotenv import load_dotenv

load_dotenv()

from app.target_chatbot import query_vulnerable, query_secure
from app.attack_engine import ALL_ATTACK_CATEGORIES, run_all_attacks, run_category
from app.evaluator import evaluate_all, generate_score_summary
from app.guardrails import apply_all_guardrails
from app.reporter import save_all_reports


def print_header(title: str):
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


def print_summary_table(summary: Dict[str, Any], label: str):
    print_header(f"SUMMARY RESULTS: {label}")
    print(f"Total Attacks Tested: {summary.get('total_attacks', 0)}")
    print(f"Total Exploited:       {summary.get('total_succeeded', 0)} ({summary.get('vulnerability_rate_percent', 0.0)}%)")
    print(f"Total Defended:        {summary.get('total_failed', 0)}")
    print(f"Overall Risk Level:    {summary.get('overall_risk_level', 'UNKNOWN')}\n")

    print(f"{'Category':<25} | {'Tested':<6} | {'Exploited':<10} | {'Defended':<8} | {'Vuln Rate':<10}")
    print("-" * 72)
    for cat, stats in summary.get("by_category", {}).items():
        print(f"{cat:<25} | {stats['total']:<6} | {stats['succeeded']:<10} | {stats['failed']:<8} | {stats['vulnerability_rate_percent']:.1f}%")
    print("-" * 72 + "\n")


def main():
    parser = argparse.ArgumentParser(description="AI Red Teaming Toolkit CLI Runner")
    parser.add_argument("--mode", choices=["full", "quick"], default="full", help="Test mode: full (25 attacks) or quick (10 attacks)")
    parser.add_argument("--category", type=str, default=None, help="Run single attack category")
    parser.add_argument("--compare", action="store_true", help="Run both Vulnerable and Secure chatbots and compare")

    args = parser.parse_args()

    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        print("[ERROR] GROQ_API_KEY environment variable is missing. Please add it to your .env file or environment.")
        sys.exit(1)

    print_header("AI RED TEAMING TOOLKIT - CLI RUNNER")
    print("Target Chatbot Model: llama-3.1-8b-instant (or active fallback)")
    print("Judge Evaluator Model: llama-3.3-70b-versatile (or active fallback)")
    print(f"Execution Mode:       {args.mode.upper()}")
    if args.category:
        print(f"Target Category:      {args.category}")
    print(f"Comparison Mode:      {'ENABLED' if args.compare else 'DISABLED'}")

    start_total_time = time.perf_counter()

    # 1. Run Vulnerable Chatbot
    print_header("STAGE 1: Testing Vulnerable Chatbot (Before Guardrails)")
    if args.category:
        raw_before = run_category(args.category, query_vulnerable)
    else:
        raw_before = run_all_attacks(query_vulnerable, quick_mode=(args.mode == "quick"))

    print("\n[*] Running Two-Stage Evaluation on Vulnerable Chatbot responses...")
    evaluated_before = evaluate_all(raw_before)
    summary_before = generate_score_summary(evaluated_before)
    print_summary_table(summary_before, "VULNERABLE CHATBOT (BEFORE)")

    evaluated_after = []
    summary_after = {"vulnerability_rate_percent": 0.0, "overall_risk_level": "N/A", "total_succeeded": 0, "total_attacks": 0}

    # 2. Run Secure Chatbot if --compare requested
    if args.compare:
        print_header("STAGE 2: Testing Secure Chatbot (With Guardrails)")
        def secure_wrapper(prompt_str: str):
            return apply_all_guardrails(prompt_str, query_secure)

        if args.category:
            raw_after = run_category(args.category, secure_wrapper)
        else:
            raw_after = run_all_attacks(secure_wrapper, quick_mode=(args.mode == "quick"))

        print("\n[*] Running Two-Stage Evaluation on Secure Chatbot responses...")
        evaluated_after = evaluate_all(raw_after)
        summary_after = generate_score_summary(evaluated_after)
        print_summary_table(summary_after, "SECURE CHATBOT (AFTER)")

    # 3. Generate & Save Reports
    print_header("STAGE 3: Generating Security Audit Reports")
    paths = save_all_reports(evaluated_before, evaluated_after, summary_before, summary_after)

    total_duration = round(time.perf_counter() - start_total_time, 2)
    print(f"[SUCCESS] Assessment Completed in {total_duration} seconds.")
    print(f"[REPORT] Markdown Report Saved: {paths['markdown_path']}")
    print(f"[JSON] JSON Results Saved:    {paths['json_path']}\n")


if __name__ == "__main__":
    main()
