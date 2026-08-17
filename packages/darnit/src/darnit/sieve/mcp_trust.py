"""Sigstore sidecar verification for MCP server binaries.

Isolated so the sandboxing follow-up (issue #375) can extend the pre-spawn
hooks (bubblewrap, nono.sh, landlock, nsjail) without touching the pool's
session cache or the handler.

Verification model: an operator declares ``trusted_publisher`` in a
``[mcp_servers.<name>]`` block; the pool looks for
``<binary>.sigstore`` or ``<binary>.sigstore.json`` next to the resolved
binary path and verifies it against a GitHub-workflow identity policy
derived from ``trusted_publisher``. Failure returns a ``(False, reason)``
tuple; the pool maps that to :class:`McpServerVerificationFailed`, which
the handler resolves ERROR. There is NO code path from verification failure
to PASS.

Alternatives considered:

* Fetching a transparency-log attestation by SHA-256 at spawn time was
  rejected because Constitution II ("conservative-by-default") forbids
  silently requiring network I/O during an audit.
* Chaining verification into the plugin-signing surface was rejected
  because MCP server binaries are external tools, not darnit plugins;
  the two trust domains are different.
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def verify(binary_path: Path, trusted_publisher: str) -> tuple[bool, str]:
    """Verify a Sigstore sidecar next to ``binary_path``.

    Args:
        binary_path: The resolved path of the MCP server binary.
        trusted_publisher: Either a full GitHub identity URL
            (``https://github.com/<owner>[/<repo>]``) or a bare
            ``<owner>`` / ``<owner>/<repo>`` string.

    Returns:
        ``(True, reason)`` if verification succeeds against a policy
        derived from ``trusted_publisher``; ``(False, reason)`` on any
        failure -- missing sidecar, malformed bundle, sigstore SDK not
        installed, or policy mismatch. The pool never sees an exception
        from this function.
    """
    sidecar = _find_sidecar(binary_path)
    if sidecar is None:
        return False, (
            f"no Sigstore sidecar found next to {binary_path} "
            f"(looked for .sigstore and .sigstore.json)"
        )

    try:
        from sigstore.models import Bundle  # type: ignore[import-not-found]
        from sigstore.verify import Verifier  # type: ignore[import-not-found]
        from sigstore.verify.policy import (  # type: ignore[import-not-found]
            GitHubWorkflowRepository,
        )
    except ImportError:
        return False, (
            "sigstore not installed -- install darnit-core[attestation] "
            "to enable trusted_publisher verification"
        )

    try:
        bundle = Bundle.from_json(sidecar.read_bytes())
    except Exception as err:  # noqa: BLE001 - sigstore raises assorted subclasses
        return False, f"Sigstore verification failed: could not parse bundle: {err}"

    repo_ref = _extract_repo_ref(trusted_publisher)
    if repo_ref is None:
        return False, (
            f"Sigstore verification failed: trusted_publisher "
            f"{trusted_publisher!r} does not name a GitHub owner/repo"
        )

    try:
        policy = GitHubWorkflowRepository(repo_ref)
        verifier = Verifier.production()
        verifier.verify_dsse(bundle, policy)
    except Exception as err:  # noqa: BLE001 - sigstore raises assorted subclasses
        return False, f"Sigstore verification failed: {err}"

    return True, f"verified against {trusted_publisher}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_sidecar(binary_path: Path) -> Path | None:
    for suffix in (".sigstore", ".sigstore.json"):
        candidate = binary_path.with_name(binary_path.name + suffix)
        if candidate.exists():
            return candidate
    return None


def _extract_repo_ref(trusted_publisher: str) -> str | None:
    """Extract the ``owner/repo`` reference from a ``trusted_publisher`` value.

    Accepts:

    * ``https://github.com/<owner>``
    * ``https://github.com/<owner>/<repo>``
    * ``<owner>`` (bare)
    * ``<owner>/<repo>`` (bare)

    Returns ``owner/repo`` when a repo is present; ``owner/`` is invalid for
    :class:`GitHubWorkflowRepository`, so an owner-only value returns
    ``None`` and the caller reports the failure.
    """
    stripped = trusted_publisher.strip()
    for prefix in ("https://github.com/", "http://github.com/"):
        if stripped.startswith(prefix):
            stripped = stripped[len(prefix) :]
            break
    stripped = stripped.strip("/")
    parts = stripped.split("/", 1)
    if len(parts) == 2 and parts[0] and parts[1]:
        return f"{parts[0]}/{parts[1]}"
    return None


__all__ = ["verify"]
