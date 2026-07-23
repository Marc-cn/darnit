"""darnit-csl — Community Specification License (CSL 1.0) compliance plugin.

Adds a darnit compliance standard for repositories that develop specifications
under the Community Specification License 1.0. It audits for, and remediates,
the file set the Linux Foundation / Joint Development Foundation requires
(CLA, license, scope, notices, dual-license, governance).
"""

from pathlib import Path

from .implementation import CommunitySpecImplementation


def register() -> CommunitySpecImplementation:
    """Entry point called by darnit plugin discovery.

    Wired in pyproject.toml via:

        [project.entry-points."darnit.implementations"]
        community-spec = "darnit_csl:register"
    """
    return CommunitySpecImplementation()


def get_framework_path() -> Path:
    """Entry point for framework TOML config discovery.

    Wired in pyproject.toml via:

        [project.entry-points."darnit.frameworks"]
        community-spec = "darnit_csl:get_framework_path"
    """
    return Path(__file__).parent / "community-spec.toml"


def get_optional_framework_path() -> Path:
    """Entry point for the OPTIONAL (facultative) framework TOML.

    Registers the separate `community-spec-optional` framework, which presence-
    checks the optional Community Specification files (06 contributing, 07 spec-
    template, 08 code-of-conduct). Kept separate so it never affects the required
    CSL compliance score. Wired in pyproject.toml via:

        [project.entry-points."darnit.frameworks"]
        community-spec-optional = "darnit_csl:get_optional_framework_path"
    """
    return Path(__file__).parent / "community-spec-optional.toml"


__all__ = [
    "CommunitySpecImplementation",
    "register",
    "get_framework_path",
    "get_optional_framework_path",
]

# Register custom sieve handlers on import.
from . import handlers  # noqa: E402,F401
