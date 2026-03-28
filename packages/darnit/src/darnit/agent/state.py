"""State definition for the Darnit agentic workflow.

This is the shared memory that gets passed between every step of the
LangGraph state machine. Each node reads from it and writes back to it.
"""

from dataclasses import dataclass, field


@dataclass
class DarnitState:
    # Where is the repo we are auditing?
    local_path: str = ""

    # Basic project info loaded from .project.yaml at the start
    project_context: dict = field(default_factory=dict)

    # The list of controls we need to check (populated after loading)
    controls: list = field(default_factory=list)

    # Results from running the checks (one entry per control)
    check_results: list = field(default_factory=list)

    # Controls that failed or warned and need more info before remediation
    pending_context: list = field(default_factory=list)

    # Controls that are ready to be fixed
    remediation_queue: list = field(default_factory=list)

    # Messages to send to a human when running non-interactively
    # e.g. GitHub issues, emails, Slack messages
    human_messages: list = field(default_factory=list)

    # Which LLM to use for the LLM sieve phase
    # "anthropic" | "openai" | "ollama"
    llm_backend: str = "anthropic"

    # The LLM API key (read from env var, not hardcoded)
    llm_api_key: str = ""

    # How to handle human feedback questions
    # "interactive" — pauses and prompts in the terminal
    # "noninteractive" — collects questions and prints at the end
    feedback_mode: str = "noninteractive"

    # Questions collected during the run that need human answers
    feedback_questions: list = field(default_factory=list)

    # Track what step we are on for logging/debugging
    current_step: str = "idle"

    # Whether the full run completed successfully
    completed: bool = False

    # Any errors that stopped the run
    errors: list = field(default_factory=list)
