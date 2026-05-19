"""Tests for the finding grouping module."""

from __future__ import annotations

import pytest

from darnit_baseline.threat_model.discovery_models import (
    CandidateFinding,
    CodeSnippet,
    FindingGroup,
    FindingSource,
    Location,
)
from darnit_baseline.threat_model.grouping import group_by_query_id
from darnit_baseline.threat_model.models import StrideCategory


def _make_finding(
    query_id: str = "python.sink.dangerous_attr",
    severity: int = 5,
    confidence: float = 0.8,
    title: str = "Test finding",
    category: StrideCategory = StrideCategory.TAMPERING,
    file: str = "src/app.py",
    line: int = 10,
) -> CandidateFinding:
    """Helper to construct a minimal CandidateFinding."""
    return CandidateFinding(
        category=category,
        title=title,
        source=FindingSource.TREE_SITTER_STRUCTURAL,
        primary_location=Location(file=file, line=line, column=1, end_line=line, end_column=20),
        related_assets=(),
        code_snippet=CodeSnippet(lines=("x = 1",), start_line=line, marker_line=line),
        severity=severity,
        confidence=confidence,
        rationale="test rationale",
        query_id=query_id,
    )


class TestGroupByQueryId:
    def test_empty_input(self) -> None:
        assert group_by_query_id([]) == []

    def test_single_finding_single_group(self) -> None:
        f = _make_finding(query_id="python.sink.subprocess_shell")
        groups = group_by_query_id([f])
        assert len(groups) == 1
        assert groups[0].query_id == "python.sink.subprocess_shell"
        assert groups[0].slug == "python-sink-subprocess_shell"
        assert len(groups[0].findings) == 1

    def test_multiple_findings_same_query(self) -> None:
        f1 = _make_finding(query_id="python.sink.dangerous_attr", severity=9)
        f2 = _make_finding(query_id="python.sink.dangerous_attr", severity=5)
        groups = group_by_query_id([f1, f2])
        assert len(groups) == 1
        assert len(groups[0].findings) == 2

    def test_multiple_query_ids(self) -> None:
        f1 = _make_finding(query_id="python.sink.subprocess_shell", severity=9)
        f2 = _make_finding(query_id="python.sink.ssrf", severity=7)
        f3 = _make_finding(query_id="python.sink.subprocess_shell", severity=5)
        groups = group_by_query_id([f1, f2, f3])
        assert len(groups) == 2
        # Sorted by max_severity_score desc — subprocess (9*0.8=7.2) > ssrf (7*0.8=5.6)
        assert groups[0].query_id == "python.sink.subprocess_shell"
        assert groups[1].query_id == "python.sink.ssrf"

    def test_slug_derivation(self) -> None:
        f = _make_finding(query_id="go.entry.selector_string_arg")
        groups = group_by_query_id([f])
        assert groups[0].slug == "go-entry-selector_string_arg"

    def test_class_name_from_highest_severity(self) -> None:
        f1 = _make_finding(query_id="test.q", severity=3, title="Low finding")
        f2 = _make_finding(query_id="test.q", severity=9, title="Critical finding")
        groups = group_by_query_id([f1, f2])
        assert groups[0].class_name == "Critical finding"

    def test_max_severity_score(self) -> None:
        f1 = _make_finding(query_id="test.q", severity=5, confidence=0.8)
        f2 = _make_finding(query_id="test.q", severity=9, confidence=1.0)
        groups = group_by_query_id([f1, f2])
        assert groups[0].max_severity_score == 9.0

    def test_ordering_by_max_severity(self) -> None:
        low = _make_finding(query_id="low.q", severity=2, confidence=0.5)
        high = _make_finding(query_id="high.q", severity=9, confidence=1.0)
        med = _make_finding(query_id="med.q", severity=5, confidence=0.8)
        groups = group_by_query_id([low, high, med])
        assert [g.query_id for g in groups] == ["high.q", "med.q", "low.q"]

    def test_all_findings_share_query_id(self) -> None:
        f1 = _make_finding(query_id="test.q", file="a.py", line=1)
        f2 = _make_finding(query_id="test.q", file="b.py", line=2)
        f3 = _make_finding(query_id="test.q", file="c.py", line=3)
        groups = group_by_query_id([f1, f2, f3])
        for finding in groups[0].findings:
            assert finding.query_id == "test.q"

    def test_mitigation_hint_from_registry(self) -> None:
        f = _make_finding(query_id="python.sink.dangerous_attr")

        class FakeQuery:
            mitigation_hint = "Use parameterized APIs instead."

        registry = {"python.sink.dangerous_attr": FakeQuery()}
        groups = group_by_query_id([f], query_registries=registry)
        assert groups[0].mitigation_hint == "Use parameterized APIs instead."

    def test_mitigation_hint_missing_from_registry(self) -> None:
        f = _make_finding(query_id="unknown.query")
        groups = group_by_query_id([f], query_registries={})
        assert groups[0].mitigation_hint == ""


class TestFindingGroupValidation:
    def test_empty_findings_raises(self) -> None:
        with pytest.raises(ValueError, match="at least one finding"):
            FindingGroup(
                query_id="test.q",
                slug="test-q",
                stride_category=StrideCategory.TAMPERING,
                class_name="Test",
                mitigation_hint="",
                findings=(),
                max_severity_score=0.0,
            )

    def test_mismatched_query_id_raises(self) -> None:
        f = _make_finding(query_id="other.q")
        with pytest.raises(ValueError, match="same query_id"):
            FindingGroup(
                query_id="test.q",
                slug="test-q",
                stride_category=StrideCategory.TAMPERING,
                class_name="Test",
                mitigation_hint="",
                findings=(f,),
                max_severity_score=0.0,
            )

    def test_wrong_slug_raises(self) -> None:
        f = _make_finding(query_id="test.q")
        with pytest.raises(ValueError, match="slug"):
            FindingGroup(
                query_id="test.q",
                slug="wrong_slug",
                stride_category=StrideCategory.TAMPERING,
                class_name="Test",
                mitigation_hint="",
                findings=(f,),
                max_severity_score=0.0,
            )


# ---------------------------------------------------------------------------
# Feature 014-cobra-threat-model: CLI command-family grouping tests
# ---------------------------------------------------------------------------


class TestInferCommandRoot:
    """Tests for infer_command_root() — the command_root inference algorithm."""

    def test_empty_input_returns_empty(self) -> None:
        from darnit_baseline.threat_model.grouping import infer_command_root

        assert infer_command_root([]) == ""

    def test_single_file_returns_empty_below_threshold(self) -> None:
        """A 1-file project has no breadth — algorithm degrades to empty."""
        from darnit_baseline.threat_model.grouping import infer_command_root

        assert infer_command_root(["main.go"]) == ""

    def test_gittuf_like_layout_picks_command_root(self) -> None:
        """internal/cmd/<family>/... layout resolves to internal/cmd."""
        from darnit_baseline.threat_model.grouping import infer_command_root

        files = [
            "internal/cmd/cache/cache.go",
            "internal/cmd/cache/init/init.go",
            "internal/cmd/cache/delete/delete.go",
            "internal/cmd/attest/attest.go",
            "internal/cmd/rsl/rsl.go",
            "internal/cmd/verify/verify.go",
        ]
        assert infer_command_root(files) == "internal/cmd"

    def test_cosign_like_layout_picks_command_root(self) -> None:
        """cmd/cosign/cli/<family>/... layout resolves to cmd/cosign/cli."""
        from darnit_baseline.threat_model.grouping import infer_command_root

        files = [
            "cmd/cosign/cli/sign/sign.go",
            "cmd/cosign/cli/verify/verify.go",
            "cmd/cosign/cli/attest/attest.go",
        ]
        assert infer_command_root(files) == "cmd/cosign/cli"

    def test_outlier_files_dont_collapse_root(self) -> None:
        """A docs/ outlier with cobra imports shouldn't drag the root to ''."""
        from darnit_baseline.threat_model.grouping import infer_command_root

        files = [
            "internal/cmd/cache/cache.go",
            "internal/cmd/attest/attest.go",
            "internal/cmd/rsl/rsl.go",
            "internal/cmd/verify/verify.go",
            "docs/help-gen/main.go",  # outlier
        ]
        # internal/cmd should still win because it has 4 children vs docs's 1.
        assert infer_command_root(files) == "internal/cmd"


class TestFamilyKeyForPath:
    """Tests for family_key_for_path()."""

    def test_strips_command_root(self) -> None:
        from darnit_baseline.threat_model.grouping import family_key_for_path

        assert family_key_for_path(
            "internal/cmd/cache/init/init.go", "internal/cmd"
        ) == "cache"

    def test_handles_deep_nesting(self) -> None:
        from darnit_baseline.threat_model.grouping import family_key_for_path

        # Even deeper sub-subcommands still bucket under their top-level family.
        assert family_key_for_path(
            "internal/cmd/trust/policy/add-rule/add-rule.go", "internal/cmd"
        ) == "trust"


class TestGroupByCliFamily:
    """Tests for group_by_cli_family()."""

    def test_empty_entries_returns_empty(self) -> None:
        from darnit_baseline.threat_model.grouping import group_by_cli_family

        assert group_by_cli_family([]) == []

    def test_ignores_non_cli_command_entries(self) -> None:
        """HTTP entry points should be filtered out, not grouped."""
        from darnit_baseline.threat_model.discovery_models import (
            DiscoveredEntryPoint,
            EntryPointKind,
            Location,
        )
        from darnit_baseline.threat_model.grouping import group_by_cli_family

        http_ep = DiscoveredEntryPoint(
            kind=EntryPointKind.HTTP_ROUTE,
            name="/api",
            location=Location("server.go", 10, 1, 12, 1),
            language="go",
            framework="net/http",
            route_path="/api",
            http_method="GET",
            has_auth_decorator=False,
            source_query="go.entry.selector_string_arg",
        )
        assert group_by_cli_family([http_ep]) == []

    def test_groups_by_filesystem_layout(self) -> None:
        """gittuf-style layout produces one family per top-level cmd dir."""
        from darnit_baseline.threat_model.discovery_models import (
            DiscoveredEntryPoint,
            EntryPointKind,
            Location,
        )
        from darnit_baseline.threat_model.grouping import group_by_cli_family

        def _cobra_ep(name: str, path: str, line: int = 10) -> DiscoveredEntryPoint:
            return DiscoveredEntryPoint(
                kind=EntryPointKind.CLI_COMMAND,
                name=name,
                location=Location(path, line, 1, line + 2, 1),
                language="go",
                framework="cobra",
                route_path=None,
                http_method=None,
                has_auth_decorator=False,
                source_query="go.entry.cobra_command_literal",
            )

        entries = [
            _cobra_ep("cache", "internal/cmd/cache/cache.go"),
            _cobra_ep("init", "internal/cmd/cache/init/init.go"),
            _cobra_ep("delete", "internal/cmd/cache/delete/delete.go"),
            _cobra_ep("attest", "internal/cmd/attest/attest.go"),
            _cobra_ep("verify", "internal/cmd/verify/verify.go"),
        ]
        families = group_by_cli_family(entries)
        family_keys = {f.family_key for f in families}
        assert family_keys == {"cache", "attest", "verify"}
        cache = next(f for f in families if f.family_key == "cache")
        assert len(cache.members) == 3  # cache + init + delete

    def test_families_sorted_by_size_descending(self) -> None:
        """Largest family first; family_key ascending as tiebreaker."""
        from darnit_baseline.threat_model.discovery_models import (
            DiscoveredEntryPoint,
            EntryPointKind,
            Location,
        )
        from darnit_baseline.threat_model.grouping import group_by_cli_family

        def _cobra_ep(name: str, path: str, line: int = 10) -> DiscoveredEntryPoint:
            return DiscoveredEntryPoint(
                kind=EntryPointKind.CLI_COMMAND,
                name=name,
                location=Location(path, line, 1, line + 2, 1),
                language="go",
                framework="cobra",
                route_path=None,
                http_method=None,
                has_auth_decorator=False,
                source_query="go.entry.cobra_command_literal",
            )

        entries = [
            _cobra_ep("verify", "internal/cmd/verify/verify.go"),
            _cobra_ep("cache", "internal/cmd/cache/cache.go"),
            _cobra_ep("init", "internal/cmd/cache/init/init.go"),
            _cobra_ep("delete", "internal/cmd/cache/delete/delete.go"),
            _cobra_ep("attest", "internal/cmd/attest/attest.go"),
        ]
        families = group_by_cli_family(entries)
        # cache has 3 members; attest and verify each have 1; alphabetical tiebreak.
        assert [f.family_key for f in families] == ["cache", "attest", "verify"]

    def test_source_root_combines_command_root_and_family_key(self) -> None:
        from darnit_baseline.threat_model.discovery_models import (
            DiscoveredEntryPoint,
            EntryPointKind,
            Location,
        )
        from darnit_baseline.threat_model.grouping import group_by_cli_family

        def _ep(name: str, path: str) -> DiscoveredEntryPoint:
            return DiscoveredEntryPoint(
                kind=EntryPointKind.CLI_COMMAND,
                name=name,
                location=Location(path, 10, 1, 12, 1),
                language="go",
                framework="cobra",
                route_path=None,
                http_method=None,
                has_auth_decorator=False,
                source_query="go.entry.cobra_command_literal",
            )

        entries = [
            _ep("a", "internal/cmd/a/a.go"),
            _ep("b", "internal/cmd/b/b.go"),
            _ep("c", "internal/cmd/c/c.go"),
        ]
        families = group_by_cli_family(entries)
        assert all(f.source_root.startswith("internal/cmd/") for f in families)
        assert all(f.source_root.endswith("/") for f in families)
