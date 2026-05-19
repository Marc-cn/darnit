"""Group findings by tree-sitter query ID for multi-file threat model output."""

from __future__ import annotations

import os
from collections import defaultdict
from typing import Any

from .discovery_models import CandidateFinding, FindingGroup
from .renderers.common import query_id_to_slug


def group_by_query_id(
    findings: list[CandidateFinding],
    query_registries: dict[str, Any] | None = None,
) -> list[FindingGroup]:
    """Group findings by ``source_query_id`` and return sorted groups.

    Each group becomes one per-class detail file in the multi-file output.

    Args:
        findings: Ranked list of findings (ordering within each group is
            preserved from this list).
        query_registries: Optional merged dict mapping query IDs to query
            objects that have a ``mitigation_hint`` attribute.  Used to
            populate the group-level mitigation narrative.

    Returns:
        List of :class:`FindingGroup` sorted by ``max_severity_score``
        descending.
    """
    if not findings:
        return []

    registries = query_registries or {}

    # Bucket findings by query_id, preserving input order within each bucket.
    buckets: dict[str, list[CandidateFinding]] = defaultdict(list)
    for f in findings:
        buckets[f.query_id].append(f)

    groups: list[FindingGroup] = []
    for qid, bucket in buckets.items():
        slug = query_id_to_slug(qid)

        # Pick class_name from the highest-severity finding's title.
        best = max(bucket, key=lambda f: f.severity * f.confidence)
        class_name = best.title

        # Pick STRIDE category from the highest-severity finding.
        stride_category = best.category

        # Look up mitigation_hint from the query registry if available.
        mitigation_hint = ""
        query_obj = registries.get(qid)
        if query_obj is not None and hasattr(query_obj, "mitigation_hint"):
            mitigation_hint = query_obj.mitigation_hint or ""

        max_score = max(f.severity * f.confidence for f in bucket)

        groups.append(
            FindingGroup(
                query_id=qid,
                slug=slug,
                stride_category=stride_category,
                class_name=class_name,
                mitigation_hint=mitigation_hint,
                findings=tuple(bucket),
                max_severity_score=max_score,
            )
        )

    # Sort by max severity score descending.
    groups.sort(key=lambda g: g.max_severity_score, reverse=True)
    return groups


# ---------------------------------------------------------------------------
# CLI command-family grouping (feature 014-cobra-threat-model)
# ---------------------------------------------------------------------------


def infer_command_root(file_paths: list[str]) -> str:
    """Infer the deepest directory ancestor common to a list of source files.

    Used to determine the project's ``command_root`` — the top-level
    directory beneath which CLI command definitions live (e.g.,
    ``internal/cmd/`` for gittuf, ``cmd/cosign/cli/`` for cosign). Family
    keys are then the first path component beneath this root.

    Args:
        file_paths: Repository-relative paths of source files that
            participated in CLI discovery. May be empty.

    Returns:
        The common directory prefix, with no trailing slash, or the empty
        string if no common prefix exists (e.g., the file list is empty
        or contains files in unrelated directory trees). An empty string
        signals the caller to degrade — typically by falling back to the
        single file's directory.
    """
    if not file_paths:
        return ""
    # Normalise to forward slashes (the audit pipeline emits POSIX paths
    # even on Windows). Then split into components and take the longest
    # shared prefix.
    components_per_file = [
        [p for p in path.replace("\\", "/").split("/") if p][:-1]  # drop filename
        for path in file_paths
    ]
    if not components_per_file or not components_per_file[0]:
        return ""
    shared: list[str] = []
    for parts in zip(*components_per_file, strict=False):
        first = parts[0]
        if all(p == first for p in parts):
            shared.append(first)
        else:
            break
    return "/".join(shared)


def family_key_for_path(file_path: str, command_root: str) -> str:
    """Compute the family key (first subdirectory beneath ``command_root``).

    For a file at ``internal/cmd/cache/init/init.go`` with command_root
    ``internal/cmd``, returns ``"cache"``. For a file directly at the
    command_root (e.g., ``internal/cmd/root.go``), returns the file's
    parent directory name as a degenerate-but-valid fallback. For an
    empty command_root, returns the immediate parent directory name.
    """
    path = file_path.replace("\\", "/")
    rel = path
    if command_root:
        # Strip the command_root prefix (with trailing slash).
        prefix = command_root.rstrip("/") + "/"
        if path.startswith(prefix):
            rel = path[len(prefix):]
    parts = [p for p in rel.split("/") if p]
    if len(parts) >= 2:
        # File at <key>/.../<file>; the first component is the family.
        return parts[0]
    # File directly under command_root with no nested directory — use the
    # file's parent dir name (degenerate fallback for single-file CLIs).
    parent = os.path.basename(os.path.dirname(path)) if "/" in path else ""
    return parent or "root"
