"""Optional LLM reasoning pass, shared by the IR Agent and Incident Commander Agent.

Data gathering and correlation (inventory/vuln/threat-intel matching,
criticality scoring) are always deterministic -- see the individual agents.
This module only generates the *explanatory text* on top of that already-
computed structured data, and only when ANTHROPIC_API_KEY is set. Without a
key, callers get a deterministic templated string instead and the pipeline
behaves identically otherwise. An LLM call failing (network, rate limit,
bad key) degrades the same way -- never blocks the pipeline.
"""
import os

TRIAGE_MODEL = "claude-haiku-4-5-20251001"  # fast/cheap: runs on every incident
COMMANDER_MODEL = "claude-sonnet-5"  # higher-stakes: runs once per incident, after triage


def _client():
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None
    try:
        import anthropic

        return anthropic.Anthropic(api_key=api_key)
    except Exception:
        return None


def reason(system_prompt: str, user_prompt: str, fallback_text: str, model: str) -> tuple[str, str]:
    """Returns (text, mode) where mode is 'llm' or 'deterministic'."""
    client = _client()
    if client is None:
        return fallback_text, "deterministic"

    try:
        response = client.messages.create(
            model=model,
            max_tokens=400,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        text = "".join(block.text for block in response.content if block.type == "text").strip()
        return (text or fallback_text), "llm"
    except Exception as e:
        return f"{fallback_text}\n[LLM reasoning unavailable: {e}]", "deterministic"
