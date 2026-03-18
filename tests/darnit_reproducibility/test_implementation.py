"""Tests for ReproducibilityImplementation plugin protocol compliance."""

from darnit_reproducibility.implementation import ReproducibilityImplementation


class TestReproducibilityImplementation:
    """Tests that ReproducibilityImplementation satisfies the plugin protocol."""

    def setup_method(self):
        self.impl = ReproducibilityImplementation()

    def test_name(self) -> None:
        assert self.impl.name == "reproducibility"

    def test_display_name(self) -> None:
        assert len(self.impl.display_name) > 0

    def test_get_all_controls_returns_five(self) -> None:
        assert len(self.impl.get_all_controls()) == 5

    def test_control_ids(self) -> None:
        ids = {c.control_id for c in self.impl.get_all_controls()}
        assert ids == {"RE-01.01", "RE-01.02", "RE-02.01", "RE-02.02", "RE-03.01"}

    def test_level_1_has_two_controls(self) -> None:
        controls = self.impl.get_controls_by_level(1)
        assert len(controls) == 2

    def test_level_2_has_two_controls(self) -> None:
        controls = self.impl.get_controls_by_level(2)
        assert len(controls) == 2

    def test_level_3_has_one_control(self) -> None:
        controls = self.impl.get_controls_by_level(3)
        assert len(controls) == 1
        assert controls[0].control_id == "RE-03.01"

    def test_framework_config_path_exists(self) -> None:
        path = self.impl.get_framework_config_path()
        assert path is not None
        assert path.exists()

    def test_check_handlers_covers_all_controls(self) -> None:
        handlers = self.impl.get_check_handlers()
        assert len(handlers) == 5
        expected = {
            "repro_deps_pinned", "repro_build_env_declared",
            "repro_hermetic_build", "repro_provenance_exists",
            "repro_bit_for_bit",
        }
        assert set(handlers.keys()) == expected

    def test_all_check_handlers_are_callable(self) -> None:
        for name, fn in self.impl.get_check_handlers().items():
            assert callable(fn), f"{name} is not callable"