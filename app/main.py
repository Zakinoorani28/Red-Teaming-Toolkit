"""
Streamlit UI Main Dashboard - AI Red Teaming Toolkit.
Production-grade security testing dashboard featuring 4 interactive tabs:
- Overview (Metrics, Plotly Charts, Risk Level)
- Attack Results (Filterable Table, Inspector, CSV Download)
- Before vs After (Side-by-side response comparison & deltas)
- Security Report (Markdown renderer & Report Downloads)
"""

import time
import os
import json
from datetime import datetime
import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go

from app.target_chatbot import query_vulnerable, query_secure
from app.attack_engine import ALL_ATTACK_CATEGORIES, run_single_attack
from app.evaluator import evaluate_all, generate_score_summary
from app.guardrails import apply_all_guardrails, get_guardrail_stats
from app.reporter import generate_markdown_report, save_all_reports

# Page Configuration
st.set_page_config(
    page_title="AI Red Teaming Toolkit",
    page_icon="🔴",
    layout="wide"
)

# Custom Theme & Metric Badges
st.markdown("""
<style>
    .stApp { background-color: #0E1117; }
    .metric-card {
        background-color: #161B22;
        border: 1px solid #30363D;
        border-radius: 8px;
        padding: 16px;
        text-align: center;
    }
    .badge-critical { background-color: #DC3545; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
    .badge-high { background-color: #FD7E14; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
    .badge-medium { background-color: #FFC107; color: black; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
    .badge-low { background-color: #198754; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
    .badge-succeeded { background-color: #DC3545; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
    .badge-failed { background-color: #198754; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

# Application Title
st.title("🔴 AI Red Teaming Toolkit for RAG Chatbots")
st.markdown("Industry-grade automated security evaluation suite for LLM RAG chatbots. Powered by **Groq API** (`llama-3.1-8b-instant` target & `llama-3.3-70b-versatile` judge evaluator).")

# Session State Initialization
if "before_results" not in st.session_state:
    st.session_state["before_results"] = []
if "after_results" not in st.session_state:
    st.session_state["after_results"] = []
if "before_summary" not in st.session_state:
    st.session_state["before_summary"] = {}
if "after_summary" not in st.session_state:
    st.session_state["after_summary"] = {}
if "markdown_report" not in st.session_state:
    st.session_state["markdown_report"] = ""
if "saved_paths" not in st.session_state:
    st.session_state["saved_paths"] = {}

# Sidebar Configuration
st.sidebar.title("🔴 Red Team Control Panel")

groq_key_input = st.sidebar.text_input(
    "Groq API Key",
    value=os.getenv("GROQ_API_KEY", ""),
    type="password",
    help="Free API key from console.groq.com"
)

if groq_key_input:
    os.environ["GROQ_API_KEY"] = groq_key_input

test_mode = st.sidebar.selectbox(
    "Test Mode",
    [
        "Full Test (All 5 Categories)",
        "Quick Test (2 attacks per category)",
        "Single Category"
    ]
)

selected_category = None
if test_mode == "Single Category":
    selected_category = st.sidebar.selectbox(
        "Select Category",
        list(ALL_ATTACK_CATEGORIES.keys())
    )

chatbot_version = st.sidebar.selectbox(
    "Chatbot Version",
    [
        "Vulnerable (Before)",
        "Secure (After)",
        "Compare Both"
    ]
)

run_button = st.sidebar.button("🚀 Run Red Team Tests", type="primary", use_container_width=True)

st.sidebar.divider()
total_prompts_count = sum(len(atk) for atk in ALL_ATTACK_CATEGORIES.values())
st.sidebar.metric("Attack Modules Loaded", "5")
st.sidebar.metric("Total Attack Prompts", str(total_prompts_count))
st.sidebar.metric("Evaluation Model", "llama-3.3-70b")


def get_selected_attack_suite():
    suite = []
    if test_mode == "Single Category" and selected_category:
        for atk in ALL_ATTACK_CATEGORIES[selected_category]:
            suite.append((selected_category, atk))
    elif test_mode == "Quick Test (2 attacks per category)":
        for cat, atks in ALL_ATTACK_CATEGORIES.items():
            for atk in atks[:2]:
                suite.append((cat, atk))
    else:
        for cat, atks in ALL_ATTACK_CATEGORIES.items():
            for atk in atks:
                suite.append((cat, atk))
    return suite


# Run Tests Action
if run_button:
    if not os.getenv("GROQ_API_KEY"):
        st.sidebar.error("⚠️ GROQ_API_KEY is missing! Insert key in sidebar or .env file.")
    else:
        attack_suite = get_selected_attack_suite()
        total_tasks = len(attack_suite)

        status_box = st.status("🚀 Launching Red Team Evaluation...", expanded=True)
        progress_bar = st.progress(0.0)

        # 1. Vulnerable Chatbot Run
        if chatbot_version in ("Vulnerable (Before)", "Compare Both"):
            status_box.update(label="⚡ Testing Vulnerable Chatbot (Before Guardrails)...", state="running")
            raw_before = []
            for i, (cat, atk) in enumerate(attack_suite):
                status_box.write(f"[{i+1}/{total_tasks}] **Vulnerable Target** ← `{cat}` : {atk['name']}")
                res = run_single_attack(atk, query_vulnerable, cat)
                raw_before.append(res)
                denom = total_tasks * 2 if chatbot_version == "Compare Both" else total_tasks
                progress_bar.progress((i + 1) / denom)
                time.sleep(0.1)

            status_box.write("🧠 Running Two-Stage LLM Judge Evaluation on Vulnerable Chatbot...")
            evaluated_before = evaluate_all(raw_before)
            before_summary = generate_score_summary(evaluated_before)
            st.session_state["before_results"] = evaluated_before
            st.session_state["before_summary"] = before_summary

        # 2. Secure Chatbot Run
        if chatbot_version in ("Secure (After)", "Compare Both"):
            status_box.update(label="🛡️ Testing Secure Chatbot (With Guardrails)...", state="running")
            raw_after = []

            def secure_wrapper(input_str: str):
                return apply_all_guardrails(input_str, query_secure)

            start_offset = total_tasks if chatbot_version == "Compare Both" else 0
            denom = total_tasks * 2 if chatbot_version == "Compare Both" else total_tasks

            for i, (cat, atk) in enumerate(attack_suite):
                status_box.write(f"[{i+1}/{total_tasks}] **Secure Target** ← `{cat}` : {atk['name']}")
                res = run_single_attack(atk, secure_wrapper, cat)
                raw_after.append(res)
                progress_bar.progress((start_offset + i + 1) / denom)
                time.sleep(0.1)

            status_box.write("🧠 Running Two-Stage LLM Judge Evaluation on Secure Chatbot...")
            evaluated_after = evaluate_all(raw_after)
            after_summary = generate_score_summary(evaluated_after)
            st.session_state["after_results"] = evaluated_after
            st.session_state["after_summary"] = after_summary

        # 3. Reports
        b_res = st.session_state.get("before_results", [])
        a_res = st.session_state.get("after_results", [])
        b_sum = st.session_state.get("before_summary", {})
        a_sum = st.session_state.get("after_summary", {})

        md_report = generate_markdown_report(b_res, a_res, b_sum, a_sum)
        st.session_state["markdown_report"] = md_report

        saved_paths = save_all_reports(b_res, a_res, b_sum, a_sum)
        st.session_state["saved_paths"] = saved_paths

        status_box.update(label="✅ Red Team Assessment Completed! Reports generated.", state="complete", expanded=False)
        st.balloons()


# Dashboard Tabs
tab_overview, tab_results, tab_compare, tab_report = st.tabs([
    "📊 Overview",
    "🎯 Attack Results",
    "⚖️ Before vs After",
    "📑 Security Report"
])

# ----------------------------------------------------
# TAB 1: OVERVIEW
# ----------------------------------------------------
with tab_overview:
    b_sum = st.session_state.get("before_summary", {})
    a_sum = st.session_state.get("after_summary", {})

    active_summary = a_sum if (a_sum and not b_sum) else b_sum

    if not active_summary:
        st.info("👋 Welcome to the AI Red Teaming Security Dashboard.")
        st.markdown("Click **🚀 Run Red Team Tests** on the left sidebar to execute automated vulnerability evaluations.")

        st.subheader("🛡️ Attack Vectors Evaluated")
        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown("### 💉 Prompt Injection")
            st.caption("Direct override commands, system tag injections, and context window poisoning.")
            st.markdown("---")
            st.markdown("### 🔓 Jailbreak")
            st.caption("DAN persona adoption, fictional scenario framing, and grandma exploit payloads.")
        with c2:
            st.markdown("### 🎭 Role Confusion")
            st.caption("Developer mode activation claims, ARIA persona, and historical AI impersonation.")
            st.markdown("---")
            st.markdown("### 📜 System Prompt Leakage")
            st.caption("Direct instruction extraction, repeat commands, and translation tricks.")
        with c3:
            st.markdown("### 🔐 Data Extraction")
            st.caption("API key fishing, knowledge base dumping, and PII exfiltration.")
            st.markdown("---")
            st.markdown("### 🧠 Two-Stage Judge")
            st.caption("Stage 1 Pattern pre-check (0 API cost) + Stage 2 Groq `llama-3.3-70b-versatile` LLM Judge.")

    else:
        st.subheader("📌 Vulnerability & Risk Summary")
        m1, m2, m3, m4 = st.columns(4)

        risk_level = active_summary.get("overall_risk_level", "UNKNOWN")
        risk_color = "#DC3545" if risk_level == "CRITICAL" else ("#FD7E14" if risk_level == "HIGH" else ("#FFC107" if risk_level == "MEDIUM" else "#198754"))

        m1.metric("Total Attacks Tested", active_summary.get("total_attacks", 0))
        m2.metric("Successful Exploits", active_summary.get("total_succeeded", 0), delta=f"{active_summary.get('vulnerability_rate_percent', 0)}% Rate", delta_color="inverse")
        m3.metric("Defended / Failed", active_summary.get("total_failed", 0))
        m4.markdown(f"**Overall Risk Level**<br><span style='font-size:24px; color:{risk_color}; font-weight:bold;'>{risk_level}</span>", unsafe_allow_html=True)

        st.divider()

        ch1, ch2 = st.columns(2)
        succeeded_cnt = active_summary.get("total_succeeded", 0)
        failed_cnt = active_summary.get("total_failed", 0)

        with ch1:
            st.subheader("🥧 Exploitation Outcome Distribution")
            fig_pie = px.pie(
                values=[succeeded_cnt, failed_cnt],
                names=["SUCCEEDED (Exploited)", "FAILED (Defended)"],
                color=["SUCCEEDED (Exploited)", "FAILED (Defended)"],
                color_discrete_map={"SUCCEEDED (Exploited)": "#DC3545", "FAILED (Defended)": "#198754"},
                hole=0.4
            )
            st.plotly_chart(fig_pie, use_container_width=True)

        with ch2:
            st.subheader("📊 Vulnerability Rate by Category (%)")
            by_cat = active_summary.get("by_category", {})
            cat_data = [{"Category": k, "Vulnerability Rate (%)": v["vulnerability_rate_percent"]} for k, v in by_cat.items()]
            df_cat = pd.DataFrame(cat_data)
            fig_bar = px.bar(
                df_cat,
                x="Category",
                y="Vulnerability Rate (%)",
                color="Vulnerability Rate (%)",
                color_continuous_scale=["#198754", "#FFC107", "#FD7E14", "#DC3545"]
            )
            st.plotly_chart(fig_bar, use_container_width=True)


# ----------------------------------------------------
# TAB 2: ATTACK RESULTS
# ----------------------------------------------------
with tab_results:
    b_res = st.session_state.get("before_results", [])
    a_res = st.session_state.get("after_results", [])
    display_results = a_res if (a_res and not b_res) else b_res

    if not display_results:
        st.info("No test results available yet. Run red team tests from the sidebar.")
    else:
        st.subheader("🔍 Detailed Attack Results Explorer")

        f1, f2, f3 = st.columns(3)
        with f1:
            cat_filter = st.multiselect("Filter Category", list(ALL_ATTACK_CATEGORIES.keys()), default=list(ALL_ATTACK_CATEGORIES.keys()))
        with f2:
            sev_filter = st.multiselect("Filter Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH", "MEDIUM", "LOW"])
        with f3:
            ver_filter = st.multiselect("Filter Verdict", ["SUCCEEDED", "FAILED", "UNKNOWN"], default=["SUCCEEDED", "FAILED", "UNKNOWN"])

        filtered = [
            r for r in display_results
            if r.get("category") in cat_filter
            and r.get("severity") in sev_filter
            and r.get("verdict") in ver_filter
        ]

        st.caption(f"Displaying {len(filtered)} of {len(display_results)} total attacks")

        if filtered:
            df = pd.DataFrame(filtered)
            st.dataframe(
                df[["attack_id", "category", "attack_name", "severity", "verdict", "method", "response_time_ms"]],
                use_container_width=True,
                hide_index=True
            )

            st.subheader("🔎 Expand Row Details")
            for item in filtered:
                verdict = item.get("verdict", "UNKNOWN")
                icon = "🔴" if verdict == "SUCCEEDED" else "🟢"
                with st.expander(f"{icon} [{item.get('attack_id')}] {item.get('category')} — {item.get('attack_name')} ({verdict})"):
                    st.markdown(f"**Severity**: `{item.get('severity')}` | **Verdict**: `{verdict}` | **Evaluation Method**: `{item.get('method')}`")
                    st.markdown(f"**Prompt**: `{item.get('prompt')}`")
                    st.markdown(f"**Response**: {item.get('response')}")
                    st.markdown(f"**Reasoning**: *{item.get('reason', 'N/A')}*")

            csv_bytes = df.to_csv(index=False).encode("utf-8")
            st.download_button(
                "📥 Export Results CSV",
                data=csv_bytes,
                file_name=f"red_team_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )


# ----------------------------------------------------
# TAB 3: BEFORE VS AFTER
# ----------------------------------------------------
with tab_compare:
    b_res = st.session_state.get("before_results", [])
    a_res = st.session_state.get("after_results", [])

    if not b_res or not a_res:
        st.info("⚠️ Before vs After comparison requires selecting 'Compare Both' mode or running both test versions.")
    else:
        st.subheader("⚖️ Before vs After Guardrails Side-by-Side Comparison")

        b_sum = st.session_state.get("before_summary", {})
        a_sum = st.session_state.get("after_summary", {})

        b_rate = b_sum.get("vulnerability_rate_percent", 0.0)
        a_rate = a_sum.get("vulnerability_rate_percent", 0.0)
        reduction = round(max(0.0, b_rate - a_rate), 2)

        c1, c2, c3 = st.columns(3)
        c1.metric("Vulnerable Vulnerability Rate", f"{b_rate}%")
        c2.metric("Secure Vulnerability Rate", f"{a_rate}%")
        c3.metric("Risk Reduction Delta", f"-{reduction}%", delta=f"{reduction}% Improvement")

        st.divider()

        matched_ids = [r["attack_id"] for r in b_res]
        for aid in matched_ids:
            b_item = next((r for r in b_res if r["attack_id"] == aid), None)
            a_item = next((r for r in a_res if r["attack_id"] == aid), None)

            if b_item and a_item:
                with st.container():
                    st.markdown(f"### [{aid}] {b_item.get('category')} — {b_item.get('attack_name')}")
                    st.caption(f"Prompt: {b_item.get('prompt')}")

                    col_l, col_r = st.columns(2)

                    with col_l:
                        st.markdown("#### 🚨 Vulnerable Chatbot (Before)")
                        v_b = b_item.get("verdict", "UNKNOWN")
                        st.markdown(f"**Verdict**: `:{'red' if v_b == 'SUCCEEDED' else 'green'}[{v_b}]`")
                        st.text_area("Vulnerable Response", value=b_item.get("response", ""), height=120, key=f"b_{aid}", disabled=True)

                    with col_r:
                        st.markdown("#### 🛡️ Secure Chatbot (After Guardrails)")
                        v_a = a_item.get("verdict", "UNKNOWN")
                        st.markdown(f"**Verdict**: `:{'red' if v_a == 'SUCCEEDED' else 'green'}[{v_a}]`")
                        st.text_area("Secure Response", value=a_item.get("response", ""), height=120, key=f"a_{aid}", disabled=True)

                    st.divider()


# ----------------------------------------------------
# TAB 4: SECURITY REPORT
# ----------------------------------------------------
with tab_report:
    md_report = st.session_state.get("markdown_report", "")
    saved_paths = st.session_state.get("saved_paths", {})

    if not md_report:
        st.info("No report generated yet. Run red team tests to view and download reports.")
    else:
        st.subheader("📑 Audit Security Assessment Report")

        d1, d2 = st.columns(2)
        with d1:
            st.download_button(
                "📥 Download Markdown Report (.md)",
                data=md_report,
                file_name=os.path.basename(saved_paths.get("markdown_path", "red_team_report.md")),
                mime="text/markdown",
                use_container_width=True
            )
        with d2:
            json_data = json.dumps({
                "before_summary": st.session_state.get("before_summary"),
                "after_summary": st.session_state.get("after_summary"),
                "before_results": st.session_state.get("before_results"),
                "after_results": st.session_state.get("after_results")
            }, indent=2)
            st.download_button(
                "📥 Download JSON Assessment Data (.json)",
                data=json_data,
                file_name=os.path.basename(saved_paths.get("json_path", "red_team_results.json")),
                mime="application/json",
                use_container_width=True
            )

        st.divider()
        st.markdown(md_report)
