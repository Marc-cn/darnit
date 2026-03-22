"""Tests for the LangGraph routing functions.

We test the routing functions directly rather than running the full graph,
because the graph nodes depend on external systems (file system, LLMs).
Routing logic is pure and easy to unit test.
"""

from darnit.agent.graph import route_after_checks, route_after_context
from darnit.agent.state import DarnitState


class TestRouteAfterChecks:
    """Tests for route_after_checks()."""

    def test_routes_to_finish_when_no_pending(self) -> None:
        """Goes straight to finish when all checks pass."""
        state = DarnitState()
        state.pending_context = []
        assert route_after_checks(state) == "finish"

    def test_routes_to_collect_context_when_pending(self) -> None:
        """Routes to collect_context when there are WARN/FAIL results."""
        state = DarnitState()
        state.pending_context = [{"control_id": "X", "status": "FAIL"}]
        assert route_after_checks(state) == "collect_context"

    def test_routes_to_finish_on_errors(self) -> None:
        """Skips to finish immediately when there are errors."""
        state = DarnitState()
        state.errors = ["something broke"]
        state.pending_context = [{"control_id": "X", "status": "FAIL"}]
        assert route_after_checks(state) == "finish"


class TestRouteAfterContext:
    """Tests for route_after_context()."""

    def test_routes_to_remediate_when_queue_has_items(self) -> None:
        """Routes to remediate when there are items to fix."""
        state = DarnitState()
        state.remediation_queue = [{"control_id": "X", "status": "FAIL"}]
        assert route_after_context(state) == "remediate"

    def test_routes_to_finish_when_queue_is_empty(self) -> None:
        """Routes to finish when nothing needs remediation."""
        state = DarnitState()
        state.remediation_queue = []
        assert route_after_context(state) == "finish"


class TestFinishNode:
    """Tests for the finish node."""

    def test_finish_marks_completed(self) -> None:
        """finish() sets completed=True and current_step='finished'."""
        from darnit.agent.graph import finish
        state = DarnitState()
        result = finish(state)
        assert result.completed is True
        assert result.current_step == "finished"
