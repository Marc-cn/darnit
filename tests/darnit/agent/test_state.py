"""Tests for the DarnitState dataclass."""

from darnit.agent.state import DarnitState


class TestDarnitState:
    """Tests for DarnitState default values and structure."""

    def test_default_values(self) -> None:
        """State initialises with sensible defaults."""
        state = DarnitState()
        assert state.local_path == ""
        assert state.project_context == {}
        assert state.controls == []
        assert state.check_results == []
        assert state.pending_context == []
        assert state.remediation_queue == []
        assert state.human_messages == []
        assert state.llm_backend == "anthropic"
        assert state.llm_api_key == ""
        assert state.current_step == "idle"
        assert state.completed is False
        assert state.errors == []

    def test_fields_are_independent(self) -> None:
        """Two State instances do not share mutable defaults."""
        a = DarnitState()
        b = DarnitState()
        a.errors.append("oops")
        assert b.errors == []

    def test_can_set_local_path(self) -> None:
        """local_path can be set at construction time."""
        state = DarnitState(local_path="/some/repo")
        assert state.local_path == "/some/repo"

    def test_llm_backend_configurable(self) -> None:
        """llm_backend can be set to any string."""
        state = DarnitState(llm_backend="ollama")
        assert state.llm_backend == "ollama"
