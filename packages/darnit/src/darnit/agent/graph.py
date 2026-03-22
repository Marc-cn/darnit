"""LangGraph state machine for the Darnit agentic workflow.

This is the brain that drives a full audit autonomously:
  1. Load project context from .project.yaml
  2. Run deterministic checks (file existence, git commands)
  3. Run pattern checks (regex, heuristics)
  4. Run LLM checks (ask the configured LLM to judge)
  5. Collect context for anything still unclear
  6. Remediate failures
  7. Commit and open a PR

Each step is a plain Python function that receives the state,
does its work, and returns the updated state.
"""

from langgraph.graph import END, StateGraph

from darnit.agent.state import DarnitState
from darnit.core.logging import get_logger

logger = get_logger("agent.graph")


# =============================================================================
# Nodes — each one is a step in the workflow
# =============================================================================

def load_project_context(state: DarnitState) -> DarnitState:
    """Step 1: Load .project.yaml and populate project_context."""
    from darnit.config.loader import init_project_config, load_project_config, save_project_config

    logger.info(f"Loading project context from {state.local_path}")
    state.current_step = "load_project_context"

    config = load_project_config(state.local_path)
    if config is None:
        # No .project.yaml yet — create one using our detectors
        logger.info("No .project.yaml found, initializing with detectors")
        config = init_project_config(state.local_path)
        save_project_config(config, state.local_path)

    state.project_context = config.model_dump(exclude_none=True)
    return state


def run_checks(state: DarnitState) -> DarnitState:
    """Step 2-4: Run all sieve phases (deterministic, pattern, LLM)."""
    from darnit.core.discovery import get_default_implementation
    from darnit.llm.backends import get_backend
    from darnit.tools.audit import run_sieve_audit

    logger.info("Running checks")
    state.current_step = "run_checks"

    # Build LLM config from state so the sieve can resolve PENDING_LLM
    llm_config = {
        "backend": state.llm_backend,
    }
    llm_backend = get_backend(llm_config)

    try:
        get_default_implementation()
        from darnit.core.utils import detect_owner_repo
        owner, repo = detect_owner_repo(state.local_path)

        results, _summary = run_sieve_audit(
            owner=owner,
            repo=repo,
            local_path=state.local_path,
            default_branch="main",
            level=3,
            controls=None,
            apply_user_config=True,
            stop_on_llm=False,
        )

        # Resolve any PENDING_LLM results using the configured backend
        resolved_results = []
        for result in results:
            if isinstance(result, dict) and result.get("status") == "PENDING_LLM":
                consultation = result.get("evidence", {}).get("llm_consultation", {})
                if consultation:
                    logger.info(f"Resolving LLM consultation for {result.get('control_id')}")
                    llm_response = llm_backend.consult(consultation)
                    # Mark it resolved with the LLM's answer
                    result["status"] = llm_response.status.value if hasattr(llm_response.status, "value") else str(llm_response.status)
                    result["message"] = llm_response.reasoning
                    result["confidence"] = llm_response.confidence
            resolved_results.append(result)

        state.check_results = resolved_results

        # Anything that is WARN or FAIL goes into pending_context
        state.pending_context = [
            r for r in resolved_results
            if isinstance(r, dict) and r.get("status") in ("WARN", "FAIL", "ERROR")
        ]

    except Exception as e:
        logger.error(f"Check phase failed: {e}")
        state.errors.append(str(e))

    return state


def collect_context(state: DarnitState) -> DarnitState:
    """Step 5: Try to gather more info for controls that are still unclear."""
    logger.info(f"Collecting context for {len(state.pending_context)} pending controls")
    state.current_step = "collect_context"

    # For now: anything still pending after checks goes into the
    # remediation queue if it is a FAIL, or gets a human message if WARN
    remediation_queue = []
    human_messages = []

    for result in state.pending_context:
        if result.get("status") in ("FAIL", "ERROR"):
            remediation_queue.append(result)
        else:
            # WARN means we need a human to confirm something
            human_messages.append(
                f"Control {result.get('id')} needs manual verification: "
                f"{result.get('details', 'no details')}"
            )

    state.remediation_queue = remediation_queue
    state.human_messages = human_messages
    return state


def remediate(state: DarnitState) -> DarnitState:
    """Step 6: Fix the controls in the remediation queue."""
    logger.info(f"Remediating {len(state.remediation_queue)} controls")
    state.current_step = "remediate"

    # Placeholder — full remediation wiring comes in a later phase
    # For now we just log what would be fixed
    for item in state.remediation_queue:
        logger.info(f"Would remediate: {item.get('id')} — {item.get('details', '')}")

    return state


def finish(state: DarnitState) -> DarnitState:
    """Final step: mark the run as complete."""
    state.current_step = "finished"
    state.completed = True
    logger.info("Darnit agent run complete")
    return state


# =============================================================================
# Routing — decides what to do after checks
# =============================================================================

def route_after_checks(state: DarnitState) -> str:
    """After checks: if there are failures, collect context. Otherwise finish."""
    if state.errors:
        return "finish"
    if state.pending_context:
        return "collect_context"
    return "finish"


def route_after_context(state: DarnitState) -> str:
    """After collecting context: if there is stuff to fix, remediate. Otherwise finish."""
    if state.remediation_queue:
        return "remediate"
    return "finish"


# =============================================================================
# Build the graph
# =============================================================================

def build_graph() -> StateGraph:
    """Assemble the LangGraph state machine."""
    graph = StateGraph(DarnitState)

    # Add all nodes
    graph.add_node("load_project_context", load_project_context)
    graph.add_node("run_checks", run_checks)
    graph.add_node("collect_context", collect_context)
    graph.add_node("remediate", remediate)
    graph.add_node("finish", finish)

    # Entry point
    graph.set_entry_point("load_project_context")

    # Fixed edges (always go to the next step)
    graph.add_edge("load_project_context", "run_checks")

    # Conditional edges (route based on state)
    graph.add_conditional_edges("run_checks", route_after_checks)
    graph.add_conditional_edges("collect_context", route_after_context)

    # Always finish after remediation
    graph.add_edge("remediate", "finish")
    graph.add_edge("finish", END)

    return graph.compile()


# Singleton — import this to run the agent
darnit_graph = build_graph()
