import pytest

from darnit.sieve.models import CheckContext, PassOutcome, PassResult, SieveResult, VerificationPhase


@pytest.mark.unit
class TestEnums:
    def test_verification_phase_values(self):
        assert VerificationPhase.DETERMINISTIC.value == "deterministic"

    def test_pass_outcome_values(self):
        assert PassOutcome.PASS.value == "pass"


@pytest.mark.unit
class TestCheckContext:
    def test_construction(self):
        # create a CheckContext with required fields, assert they're stored
        ctx = CheckContext(
            owner="Shreyas",
            repo="darnit",
            local_path="/tmp/repo",
            default_branch="main",
            control_id="ctrl-001",
        )
        assert ctx.owner == "Shreyas"
        assert ctx.repo == "darnit"
        assert ctx.control_id == "ctrl-001"
        assert ctx.gathered_evidence == {}  # default


@pytest.mark.unit
class TestPassResult:
    def test_construction(self):
        result = PassResult(
            phase=VerificationPhase.DETERMINISTIC,
            outcome=PassOutcome.PASS,
            message="All checks passed",
        )
        assert result.phase == VerificationPhase.DETERMINISTIC
        assert result.outcome == PassOutcome.PASS
        assert result.message == "All checks passed"
        assert result.confidence is None  # default


@pytest.mark.unit
class TestSieveResult:
    def test_to_legacy_dict(self):
        result = SieveResult(
            control_id="ctrl-001",
            status="PASS",
            message="All good",
            level=1,
        )
        d = result.to_legacy_dict()
        assert d["id"] == "ctrl-001"
        assert d["status"] == "PASS"
        assert d["details"] == "All good"
        assert d["level"] == 1

    def test_defaults(self):
        result = SieveResult(
            control_id="ctrl-001",
            status="PASS",
            message="All good",
            level=1,
        )
        assert result.confidence is None
        assert result.evidence is None
        assert result.pass_history == []
