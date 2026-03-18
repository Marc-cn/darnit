"""Tests for LLM backends.

We test parsing and the factory function. We do NOT make real API calls —
the _call() method is patched out in every test.
"""

from unittest.mock import MagicMock, patch

from darnit.llm.backends import (
    AnthropicBackend,
    OllamaBackend,
    OpenAIBackend,
    get_backend,
)
from darnit.sieve.models import PassOutcome


class TestResponseParsing:
    """Tests for _parse_response() — the logic that reads LLM output."""

    def test_parses_pass(self) -> None:
        backend = AnthropicBackend()
        result = backend._parse_response(
            "STATUS: PASS\nCONFIDENCE: 0.9\nREASONING: Looks good"
        )
        assert result.status == PassOutcome.PASS
        assert result.confidence == 0.9
        assert result.reasoning == "Looks good"

    def test_parses_fail(self) -> None:
        backend = AnthropicBackend()
        result = backend._parse_response(
            "STATUS: FAIL\nCONFIDENCE: 0.95\nREASONING: Missing file"
        )
        assert result.status == PassOutcome.FAIL
        assert result.confidence == 0.95

    def test_parses_inconclusive(self) -> None:
        backend = AnthropicBackend()
        result = backend._parse_response(
            "STATUS: INCONCLUSIVE\nCONFIDENCE: 0.4\nREASONING: Not sure"
        )
        assert result.status == PassOutcome.INCONCLUSIVE

    def test_handles_malformed_response(self) -> None:
        """Falls back to INCONCLUSIVE with 0.5 confidence on garbage input."""
        backend = AnthropicBackend()
        result = backend._parse_response("I don't know what to say")
        assert result.status == PassOutcome.INCONCLUSIVE
        assert result.confidence == 0.5

    def test_handles_bad_confidence_value(self) -> None:
        """Falls back to 0.5 when confidence is not a number."""
        backend = AnthropicBackend()
        result = backend._parse_response(
            "STATUS: PASS\nCONFIDENCE: high\nREASONING: ok"
        )
        assert result.confidence == 0.5


class TestPromptBuilding:
    """Tests for _build_prompt()."""

    def test_prompt_contains_control_id(self) -> None:
        backend = AnthropicBackend()
        prompt = backend._build_prompt({
            "control_id": "OSPS-VM-01",
            "control_name": "HasSecurityPolicy",
            "question": "Does a security policy exist?",
            "evidence": {"file_found": "SECURITY.md"},
        })
        assert "OSPS-VM-01" in prompt
        assert "HasSecurityPolicy" in prompt
        assert "Does a security policy exist?" in prompt
        assert "SECURITY.md" in prompt

    def test_prompt_contains_format_instructions(self) -> None:
        """Prompt always includes the STATUS/CONFIDENCE/REASONING format."""
        backend = AnthropicBackend()
        prompt = backend._build_prompt({"question": "anything?"})
        assert "STATUS:" in prompt
        assert "CONFIDENCE:" in prompt
        assert "REASONING:" in prompt


class TestConsultHandlesErrors:
    """Tests for consult() error handling."""

    def test_returns_inconclusive_on_call_failure(self) -> None:
        """consult() catches exceptions and returns INCONCLUSIVE."""
        backend = AnthropicBackend()
        with patch.object(backend, "_call", side_effect=RuntimeError("API down")):
            result = backend.consult({"question": "does this pass?"})
        assert result.status == PassOutcome.INCONCLUSIVE
        assert result.confidence == 0.0
        assert "API down" in result.reasoning


class TestGetBackendFactory:
    """Tests for get_backend() factory function."""

    def test_returns_anthropic_by_default(self) -> None:
        backend = get_backend({})
        assert isinstance(backend, AnthropicBackend)

    def test_returns_anthropic_explicitly(self) -> None:
        backend = get_backend({"backend": "anthropic"})
        assert isinstance(backend, AnthropicBackend)

    def test_returns_openai(self) -> None:
        backend = get_backend({"backend": "openai"})
        assert isinstance(backend, OpenAIBackend)

    def test_returns_ollama(self) -> None:
        backend = get_backend({"backend": "ollama"})
        assert isinstance(backend, OllamaBackend)

    def test_unknown_backend_falls_back_to_anthropic(self) -> None:
        backend = get_backend({"backend": "something_weird"})
        assert isinstance(backend, AnthropicBackend)

    def test_model_is_passed_through(self) -> None:
        backend = get_backend({"backend": "anthropic", "model": "claude-opus-4-6"})
        assert isinstance(backend, AnthropicBackend)
        assert backend.model == "claude-opus-4-6"

    def test_ollama_uses_custom_model(self) -> None:
        backend = get_backend({"backend": "ollama", "model": "mistral"})
        assert isinstance(backend, OllamaBackend)
        assert backend.model == "mistral"