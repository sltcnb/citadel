"""The reasoning-model null-content failure, pinned.

A 10-token probe against a reasoning model returns HTTP 200 with
finish_reason="length" and content=null. That null reached `reply[:300]` and
`raw.strip()` as a plain None, so a correctly-configured endpoint surfaced as
"Internal server error" with nothing pointing at the real cause.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pytest

from routers.llm_config import LLMBudgetExhausted, _extract_llm_text  # noqa: E402


def _SERVICE_SRC() -> str:
    return (
        Path(__file__).resolve().parents[2] / "tools" / "pilot" / "pilot" / "service.py"
    ).read_text()


def test_normal_reply_passes_through():
    data = {"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]}
    assert _extract_llm_text(data, 512, "m") == "ok"


def test_reasoning_model_null_content_raises_a_named_error():
    """The exact shape GLM-5.2 returns at max_tokens=10."""
    data = {"choices": [{"message": {"content": None}, "finish_reason": "length"}]}
    with pytest.raises(LLMBudgetExhausted) as e:
        _extract_llm_text(data, 10, "Zai/GLM-5.2")
    msg = str(e.value)
    assert "10 tokens" in msg          # names the budget that was too small
    assert "reasoning model" in msg     # names the cause
    assert "raise max_tokens" in msg    # names the fix
    assert "Zai/GLM-5.2" in msg         # names which model


def test_reasoning_content_alone_is_enough_to_diagnose():
    """Some gateways omit finish_reason but expose the chain of thought."""
    data = {"choices": [{"message": {"content": None, "reasoning_content": "..."}}]}
    with pytest.raises(LLMBudgetExhausted):
        _extract_llm_text(data, 64, "m")


def test_empty_answer_without_truncation_is_not_an_error():
    """A model that simply says nothing is a result, not a crash."""
    data = {"choices": [{"message": {"content": None}, "finish_reason": "stop"}]}
    assert _extract_llm_text(data, 512, "m") == ""


def test_malformed_response_never_returns_none():
    for data in ({}, {"choices": []}, {"choices": [{}]}, {"choices": [{"message": {}}]}):
        out = _extract_llm_text(data, 512, "m")
        assert out == "" and isinstance(out, str), data


def test_probe_budget_is_no_longer_ten():
    src = _SERVICE_SRC()
    assert 'Reply with exactly the word: OK", max_tokens=512' in src


def test_json_call_sites_request_json_mode():
    """Qwen emits valid JSONC — // comments — which json.loads rejects."""
    src = _SERVICE_SRC()
    for prompt in ("_CASE_ANALYSIS_PROMPT", "_CASE_INVESTIGATE_PROMPT"):
        i = src.index(prompt + ", user_msg")
        call = src[i - 120: i + 160]
        assert "json_mode=True" in call, prompt
        assert "max_tokens=3000" in call, prompt


def test_no_unguarded_none_subscript_remains():
    src = _SERVICE_SRC()
    assert '"response": reply[:300]' not in src
    assert '(reply or "")[:300]' in src
    # The code form, not the prose: the docstring above legitimately names
    # raw.strip() when explaining what used to break.
    assert "clean = raw.strip()" not in src
    assert 'clean = (raw or "").strip()' in src
