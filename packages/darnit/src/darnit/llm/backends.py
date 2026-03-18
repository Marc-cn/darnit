"""LLM backends for standalone agentic mode.

When Darnit runs inside Claude Code, the LLM phase is handled by Claude
itself — the orchestrator returns PENDING_LLM and Claude answers it.

When Darnit runs as a standalone agent (Phase 3 LangGraph), there is no
Claude Code sitting there. This module lets Darnit call an LLM directly
using a configured API key.

Configuration in .baseline.toml:
    [llm]
    backend = "anthropic"       # or "openai" or "ollama"
    model = "claude-sonnet-4-6"

API keys come from environment variables, never hardcoded:
    ANTHROPIC_API_KEY
    OPENAI_API_KEY
    OLLAMA_HOST (optional, defaults to http://localhost:11434)
"""

import os
from typing import Any

from darnit.core.logging import get_logger
from darnit.sieve.models import LLMConsultationResponse, PassOutcome

logger = get_logger("llm.backends")


# =============================================================================
# Base protocol
# =============================================================================

class LLMBackend:
    """Base class for LLM backends.

    Subclasses implement _call() which sends a prompt and returns
    the raw text response. This class handles parsing that response
    into a structured LLMConsultationResponse.
    """

    def consult(
        self,
        consultation_request: dict[str, Any],
    ) -> LLMConsultationResponse:
        """Send a consultation request to the LLM and parse the response.

        Args:
            consultation_request: The dict from the PENDING_LLM evidence,
                                  containing the question and evidence for
                                  the LLM to judge.

        Returns:
            LLMConsultationResponse with status, confidence, and reasoning.
        """
        prompt = self._build_prompt(consultation_request)
        try:
            raw_response = self._call(prompt)
            return self._parse_response(raw_response)
        except Exception as e:
            logger.error(f"LLM consultation failed: {e}")
            return LLMConsultationResponse(
                status=PassOutcome.INCONCLUSIVE,
                confidence=0.0,
                reasoning=f"LLM call failed: {e}",
                evidence_cited=[],
            )

    def _build_prompt(self, consultation_request: dict[str, Any]) -> str:
        """Turn the consultation request into a prompt string."""
        question = consultation_request.get("question", "")
        evidence = consultation_request.get("evidence", {})
        control_id = consultation_request.get("control_id", "")
        control_name = consultation_request.get("control_name", "")

        evidence_text = "\n".join(
            f"  - {k}: {v}" for k, v in evidence.items()
        )

        return f"""You are a compliance auditor reviewing a software project.

Control: {control_id} - {control_name}
Question: {question}

Evidence collected:
{evidence_text}

Based on the evidence, does this control PASS or FAIL?
Respond in this exact format:
STATUS: PASS or FAIL or INCONCLUSIVE
CONFIDENCE: a number between 0.0 and 1.0
REASONING: one sentence explaining your decision
"""

    def _parse_response(self, raw: str) -> LLMConsultationResponse:
        """Parse the raw LLM text response into a structured object."""
        status = PassOutcome.INCONCLUSIVE
        confidence = 0.5
        reasoning = raw.strip()

        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("STATUS:"):
                value = line.replace("STATUS:", "").strip().upper()
                if value == "PASS":
                    status = PassOutcome.PASS
                elif value == "FAIL":
                    status = PassOutcome.FAIL
                else:
                    status = PassOutcome.INCONCLUSIVE
            elif line.startswith("CONFIDENCE:"):
                try:
                    confidence = float(line.replace("CONFIDENCE:", "").strip())
                except ValueError:
                    confidence = 0.5
            elif line.startswith("REASONING:"):
                reasoning = line.replace("REASONING:", "").strip()

        return LLMConsultationResponse(
            status=status,
            confidence=confidence,
            reasoning=reasoning,
            evidence_cited=[],
        )

    def _call(self, prompt: str) -> str:
        """Send the prompt to the LLM. Subclasses implement this."""
        raise NotImplementedError


# =============================================================================
# Anthropic backend
# =============================================================================

class AnthropicBackend(LLMBackend):
    """Calls the Anthropic API using the ANTHROPIC_API_KEY env var."""

    def __init__(self, model: str = "claude-sonnet-4-6"):
        self.model = model
        self.api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not self.api_key:
            logger.warning("ANTHROPIC_API_KEY not set")

    def _call(self, prompt: str) -> str:
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=self.api_key)
            message = client.messages.create(
                model=self.model,
                max_tokens=256,
                messages=[{"role": "user", "content": prompt}],
            )
            return message.content[0].text
        except ImportError:
            raise RuntimeError(
                "anthropic package not installed. Run: uv add anthropic"
            )


# =============================================================================
# OpenAI backend
# =============================================================================

class OpenAIBackend(LLMBackend):
    """Calls the OpenAI API using the OPENAI_API_KEY env var."""

    def __init__(self, model: str = "gpt-4o-mini"):
        self.model = model
        self.api_key = os.environ.get("OPENAI_API_KEY", "")
        if not self.api_key:
            logger.warning("OPENAI_API_KEY not set")

    def _call(self, prompt: str) -> str:
        try:
            import openai
            client = openai.OpenAI(api_key=self.api_key)
            response = client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=256,
            )
            return response.choices[0].message.content
        except ImportError:
            raise RuntimeError(
                "openai package not installed. Run: uv add openai"
            )


# =============================================================================
# Ollama backend (local, no API key needed)
# =============================================================================

class OllamaBackend(LLMBackend):
    """Calls a local Ollama instance. No API key required."""

    def __init__(self, model: str = "llama3"):
        self.model = model
        self.host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")

    def _call(self, prompt: str) -> str:
        try:
            import urllib.request
            import json

            payload = json.dumps({
                "model": self.model,
                "prompt": prompt,
                "stream": False,
            }).encode()

            req = urllib.request.Request(
                f"{self.host}/api/generate",
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read())
                return data.get("response", "")
        except Exception as e:
            raise RuntimeError(f"Ollama call failed: {e}")


# =============================================================================
# Factory — pick the right backend from config
# =============================================================================

def get_backend(config: dict[str, Any]) -> LLMBackend:
    """Return the configured LLM backend.

    Args:
        config: The [llm] section from .baseline.toml, e.g.:
                {"backend": "anthropic", "model": "claude-sonnet-4-6"}

    Returns:
        An LLMBackend instance ready to call.
    """
    backend_name = config.get("backend", "anthropic").lower()
    model = config.get("model")

    if backend_name == "anthropic":
        return AnthropicBackend(model=model or "claude-sonnet-4-6")
    elif backend_name == "openai":
        return OpenAIBackend(model=model or "gpt-4o-mini")
    elif backend_name == "ollama":
        return OllamaBackend(model=model or "llama3")
    else:
        logger.warning(f"Unknown backend '{backend_name}', falling back to Anthropic")
        return AnthropicBackend(model=model or "claude-sonnet-4-6")