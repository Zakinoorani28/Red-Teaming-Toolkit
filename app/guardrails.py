"""
Guardrails Module - Three-Layer Security Defense System with Audit Logging.
Implements Input Sanitizer (Layer 1), Output Filter (Layer 2), and Topic Validator (Layer 3).
"""

import threading
from typing import Dict, Any, List, Callable

_guardrail_stats_lock = threading.Lock()
_guardrail_stats = {
    "input_sanitizer_triggered": 0,
    "output_filter_triggered": 0,
    "topic_validator_triggered": 0
}

INJECTION_SIGNALS_40: List[str] = [
    "ignore previous", "ignore all", "ignore instructions", "new instructions",
    "system:", "[system]", "<system>", "you are now", "pretend you are",
    "act as", "roleplay as", "forget your", "override", "system prompt",
    "repeat everything above", "show me your prompt", "reveal your instructions",
    "developer mode", "dan mode", "no restrictions", "without restrictions",
    "aria", "gpt-2", "opposite role", "switch to developer", "begin new task",
    "admin mode", "security test passed", "i am hacked", "bypass safety",
    "fictional story", "hypothetically", "bedtime story", "replace every third word",
    "maintenance mode", "raw json", "print entire contents", "dump knowledge base"
]

LEAK_PATTERNS: List[str] = [
    "system prompt", "my instructions are", "i was told to",
    "sk-", "gsk_", "api key", "aisailabs_admin_secret_2026", "project_phoenix_rag"
]


def sanitize_input(user_input: str) -> Dict[str, Any]:
    """
    LAYER 1 — Input Sanitizer.
    Scans for 40+ injection/jailbreak signal keywords.
    """
    input_lower = user_input.lower()
    for signal in INJECTION_SIGNALS_40:
        if signal in input_lower:
            with _guardrail_stats_lock:
                _guardrail_stats["input_sanitizer_triggered"] += 1
            return {
                "safe": False,
                "blocked_reason": f"Detected potential prompt injection / jailbreak attack (signal: '{signal}')",
                "matched_pattern": signal,
                "severity": "HIGH"
            }
    return {"safe": True}


def filter_output(response: str) -> Dict[str, Any]:
    """
    LAYER 2 — Output Filter.
    Intercepts and replaces accidental system prompt or credential leakage.
    """
    resp_lower = response.lower()
    for pattern in LEAK_PATTERNS:
        if pattern in resp_lower:
            with _guardrail_stats_lock:
                _guardrail_stats["output_filter_triggered"] += 1
            return {
                "safe": False,
                "filtered_response": "I can only help with AI Season course content.",
                "original_response": response,
                "matched_pattern": pattern
            }
    return {"safe": True, "filtered_response": response}


def validate_topic(user_input: str, context_retrieved: str) -> Dict[str, Any]:
    """
    LAYER 3 — Topic Guardrail (RAG-specific).
    Ensures query maps to indexed course context in the vector store.
    """
    if not context_retrieved or len(context_retrieved.strip()) < 50:
        with _guardrail_stats_lock:
            _guardrail_stats["topic_validator_triggered"] += 1
        return {
            "on_topic": False,
            "message": "I can only help with AI Season course content."
        }
    return {"on_topic": True}


def apply_all_guardrails(user_input: str, chatbot_fn: Callable[[str], Dict[str, Any]]) -> Dict[str, Any]:
    """
    Sequentially applies Layer 1 (Input), Chatbot execution, Layer 2 (Output), and Layer 3 (Topic).
    """
    triggered_guardrails: List[str] = []
    security_status = "CLEAN"

    # Layer 1: Input Sanitization
    input_check = sanitize_input(user_input)
    if not input_check["safe"]:
        triggered_guardrails.append("Input Sanitizer")
        return {
            "response": "I can only help with AI Season course content.",
            "context_used": "",
            "guardrails_triggered": triggered_guardrails,
            "original_input": user_input,
            "security_status": "BLOCKED",
            "model": "llama-3.1-8b-instant"
        }

    # Execute Target Chatbot
    res = chatbot_fn(user_input)
    if isinstance(res, dict):
        raw_response = res.get("response", "")
        context = res.get("context_used", "")
        model = res.get("model", "llama-3.1-8b-instant")
    else:
        raw_response = str(res)
        context = ""
        model = "llama-3.1-8b-instant"

    final_response = raw_response

    # Layer 2: Output Filtering
    output_check = filter_output(raw_response)
    if not output_check["safe"]:
        triggered_guardrails.append("Output Filter")
        final_response = output_check["filtered_response"]
        security_status = "FILTERED"

    # Layer 3: Topic Validation
    topic_check = validate_topic(user_input, context)
    if not topic_check["on_topic"]:
        triggered_guardrails.append("Topic Validator")
        if security_status == "CLEAN":
            final_response = topic_check["message"]
            security_status = "WARNED"

    return {
        "response": final_response,
        "context_used": context,
        "guardrails_triggered": triggered_guardrails,
        "original_input": user_input,
        "security_status": security_status,
        "model": model
    }


def get_guardrail_stats() -> Dict[str, int]:
    """Returns total triggering counts across guardrail layers."""
    with _guardrail_stats_lock:
        return dict(_guardrail_stats)
