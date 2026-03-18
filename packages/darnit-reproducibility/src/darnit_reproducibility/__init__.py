"""Scientific reproducibility plugin for darnit."""

from pathlib import Path
from .implementation import ReproducibilityImplementation


def register() -> ReproducibilityImplementation:
    """Entry point called by darnit plugin discovery."""
    impl = ReproducibilityImplementation()
    impl.register_controls()
    impl.register_sieve_handlers()
    return impl


def get_framework_path() -> Path:
    """Entry point for framework TOML discovery."""
    return Path(__file__).parent.parent.parent / "reproducibility.toml"


__all__ = ["ReproducibilityImplementation", "register", "get_framework_path"]