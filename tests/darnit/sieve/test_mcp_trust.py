"""Tests for the Sigstore sidecar verification helper.

The ``verify`` function is deliberately isolated so the sandboxing
follow-up (issue #375) can extend it without touching the pool. These
tests lock the four operator-observable outcomes: sidecar absent,
sidecar malformed, sigstore SDK unavailable, and (implicitly, via
mcp_handler coverage) success/failure verification.
"""

from __future__ import annotations

import importlib
import sys

import pytest

from darnit.sieve.mcp_trust import verify


def _has_sigstore() -> bool:
    try:
        importlib.import_module("sigstore.models")
        importlib.import_module("sigstore.verify")
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# T033: no sidecar -> (False, reason)
# ---------------------------------------------------------------------------


def test_no_sidecar_returns_false_with_reason(tmp_path):
    binary = tmp_path / "scorecard-mcp"
    binary.write_bytes(b"fake elf")
    ok, reason = verify(binary, "https://github.com/example/example")
    assert ok is False
    assert "no Sigstore sidecar" in reason
    assert str(binary) in reason


# ---------------------------------------------------------------------------
# T034: malformed sidecar -> (False, "Sigstore verification failed: ...")
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not _has_sigstore(),
    reason="sigstore extra not installed in this environment",
)
def test_malformed_sidecar_returns_false(tmp_path):
    binary = tmp_path / "scorecard-mcp"
    binary.write_bytes(b"fake elf")
    sidecar = tmp_path / "scorecard-mcp.sigstore"
    sidecar.write_text('{"not": "a bundle"}')
    ok, reason = verify(binary, "https://github.com/example/example")
    assert ok is False
    assert "Sigstore verification failed" in reason


# ---------------------------------------------------------------------------
# T035: sigstore SDK unavailable -> (False, "install darnit-core[attestation]")
# ---------------------------------------------------------------------------


def test_sigstore_unavailable_returns_false(tmp_path, monkeypatch):
    binary = tmp_path / "scorecard-mcp"
    binary.write_bytes(b"fake elf")
    sidecar = tmp_path / "scorecard-mcp.sigstore"
    sidecar.write_text("{}")

    # Blot out any pre-imported sigstore submodules so the ImportError
    # branch runs deterministically even when the extra is installed.
    for name in list(sys.modules):
        if name == "sigstore" or name.startswith("sigstore."):
            monkeypatch.setitem(sys.modules, name, None)

    ok, reason = verify(binary, "https://github.com/example/example")
    assert ok is False
    assert "sigstore not installed" in reason
    assert "darnit-core[attestation]" in reason
