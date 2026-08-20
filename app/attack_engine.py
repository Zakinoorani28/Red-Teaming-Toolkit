"""
Attack Engine Module - Parallel attack execution engine with rate limiting and timing.
"""

import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Callable, Optional

from attacks.prompt_injection import get_attacks as pi_attacks
from attacks.jailbreak import get_attacks as jb_attacks
from attacks.role_confusion import get_attacks as rc_attacks
from attacks.system_prompt_leakage import get_attacks as spl_attacks
from attacks.data_extraction import get_attacks as de_attacks

ALL_ATTACK_CATEGORIES: Dict[str, List[Dict[str, Any]]] = {
    "Prompt Injection": pi_attacks(),
    "Jailbreak": jb_attacks(),
    "Role Confusion": rc_attacks(),
    "System Prompt Leakage": spl_attacks(),
    "Data Extraction": de_attacks()
}


def run_single_attack(attack: Dict[str, Any], chatbot_fn: Callable[[str], Any], category: str) -> Dict[str, Any]:
    """
    Executes a single attack prompt with exact timing using time.perf_counter().
    """
    start_time = time.perf_counter()
    try:
        result = chatbot_fn(attack["prompt"])
    except Exception as e:
        result = {"response": f"ERROR: Execution exception: {str(e)}", "context_used": ""}

    elapsed_ms = round((time.perf_counter() - start_time) * 1000)

    if isinstance(result, dict):
        response_text = result.get("response", "")
        context_used = result.get("context_used", "")
        # Prefer reported response_time_ms if present
        if "response_time_ms" in result and result["response_time_ms"] > 0:
            elapsed_ms = result["response_time_ms"]
    else:
        response_text = str(result)
        context_used = ""

    return {
        "attack_id": attack["id"],
        "category": category,
        "attack_name": attack["name"],
        "prompt": attack["prompt"],
        "severity": attack["severity"],
        "what_to_detect": attack.get("what_to_detect", ""),
        "expected_safe_behavior": attack.get("expected_safe_behavior", ""),
        "response": response_text,
        "context_used": context_used,
        "response_time_ms": elapsed_ms,
        "timestamp": datetime.now().isoformat()
    }


def run_all_attacks(
    chatbot_fn: Callable[[str], Any],
    max_workers: int = 3,
    quick_mode: bool = False
) -> List[Dict[str, Any]]:
    """
    Runs all attacks across categories in parallel with thread pool.
    
    Args:
        chatbot_fn: Target chatbot function.
        max_workers: Maximum worker threads (default 3 for rate limits).
        quick_mode: If True, runs only first 2 attacks per category (10 total).
        
    Returns:
        List of attack result dictionaries sorted by category and attack_id.
    """
    tasks = []
    total_attacks = 0

    for category, attack_list in ALL_ATTACK_CATEGORIES.items():
        selected_list = attack_list[:2] if quick_mode else attack_list
        total_attacks += len(selected_list)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for category, attack_list in ALL_ATTACK_CATEGORIES.items():
            selected_list = attack_list[:2] if quick_mode else attack_list
            for attack in selected_list:
                future = executor.submit(run_single_attack, attack, chatbot_fn, category)
                tasks.append((category, attack["id"], attack["name"], future))
                time.sleep(0.3)  # Stagger submission to respect Groq free tier limits

        results = []
        completed_count = 0

        for category, aid, name, future in tasks:
            res = future.result()
            completed_count += 1
            results.append(res)
            print(f"[{completed_count}/{total_attacks}] [+] {aid} — {category} : {name}")

    results.sort(key=lambda x: (x["category"], x["attack_id"]))
    return results


def run_category(category_name: str, chatbot_fn: Callable[[str], Any], max_workers: int = 3) -> List[Dict[str, Any]]:
    """
    Executes attacks belonging strictly to a single category.
    """
    if category_name not in ALL_ATTACK_CATEGORIES:
        raise ValueError(f"Unknown category '{category_name}'. Available: {list(ALL_ATTACK_CATEGORIES.keys())}")

    attack_list = ALL_ATTACK_CATEGORIES[category_name]
    results = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for attack in attack_list:
            futures.append((attack["id"], executor.submit(run_single_attack, attack, chatbot_fn, category_name)))
            time.sleep(0.3)

        for aid, future in futures:
            results.append(future.result())

    results.sort(key=lambda x: x["attack_id"])
    return results
