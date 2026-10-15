"""
VulnBastion / TawasolPay CyberSentinel — Security Guardrails & Sanitization
Protects against prompt injection, malicious inputs, and data leakage.
"""
import re
from typing import Any, Dict


# Common prompt injection patterns
INJECTION_PATTERNS = [
    r"(?i)ignore\s+(all\s+)?(previous|prior)\s+(instructions|prompts|rules)",
    r"(?i)disregard\s+(all\s+)?(previous|prior)\s+(instructions|prompts|rules)",
    r"(?i)system\s*:\s*",
    r"(?i)you\s+are\s+now\s+a",
    r"(?i)<\|im_start\|>",
    r"(?i)<\|im_end\|>",
    r"(?i)\[INST\]",
    r"(?i)\[/INST\]",
    r"(?i)new\s+system\s+prompt",
    r"(?i)override\s+(system|safety)\s+(prompt|settings)",
]

COMPILED_INJECTION_REGEXES = [re.compile(p) for p in INJECTION_PATTERNS]


def detect_prompt_injection(text: str) -> bool:
    """Check if a string contains known prompt injection vectors."""
    if not text or not isinstance(text, str):
        return False
    return any(regex.search(text) for regex in COMPILED_INJECTION_REGEXES)


def sanitize_input_text(text: Any, max_length: int = 1000) -> str:
    """
    Sanitize text before embedding or prompt insertion:
    - Strips control characters
    - Truncates excessive length
    - Neutralizes injection attempts
    """
    if text is None:
        return ""
    
    val = str(text).strip()
    
    # Neutralize injection keywords by defanging
    for regex in COMPILED_INJECTION_REGEXES:
        val = regex.sub("[NEUTRALIZED_INPUT]", val)

    # Strip dangerous control characters but preserve newlines and spaces
    val = "".join(ch for ch in val if ch == "\n" or ch == "\t" or (32 <= ord(ch) <= 126) or ord(ch) > 127)

    # Enforce safe upper bound
    if len(val) > max_length:
        val = val[:max_length] + " [TRUNCATED]"

    return val


def sanitize_risk_record(risk: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize all fields in a risk record dictionary before prompt formatting."""
    sanitized: Dict[str, Any] = {}
    for key, val in risk.items():
        if isinstance(val, str):
            sanitized[key] = sanitize_input_text(val, max_length=500)
        else:
            sanitized[key] = val
    return sanitized

