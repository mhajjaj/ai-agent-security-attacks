"""
Shared utilities for the attack algorithm.
"""

import hashlib
import json
from typing import Any, Dict, List


def trace_signature(tool_calls: List[Dict[str, Any]]) -> str:
    """
    Produce a stable string signature for a list of tool calls.
    Used to identify unique attack patterns (cells) for diversity scoring.
    """
    simplified = []
    for call in tool_calls:
        name = call.get("tool", call.get("name", "unknown"))
        args = call.get("args", call.get("arguments", {}))
        # Sort keys for stability
        args_str = json.dumps(args, sort_keys=True, ensure_ascii=True)
        simplified.append(f"{name}:{args_str}")
    combined = "|".join(simplified)
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()[:16]


def extract_tool_calls(trace: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Flatten an agent trace and extract only successful tool call records.
    """
    tool_calls = []
    for step in trace:
        if step.get("type") == "tool_call" and step.get("status") == "success":
            tool_calls.append(step)
    return tool_calls


def count_unique_cells(candidates: List[Any]) -> int:
    """
    Count unique tool-call signatures across all candidates.
    """
    seen = set()
    for cand in candidates:
        trace = getattr(cand, "trace", []) if hasattr(cand, "trace") else cand.get("trace", [])
        sig = trace_signature(extract_tool_calls(trace))
        seen.add(sig)
    return len(seen)
