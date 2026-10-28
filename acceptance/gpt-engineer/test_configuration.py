"""A protected utility score requires the preregistered matching baseline."""

import copy
import json

import pytest
from configuration import preregister, require_baseline


@pytest.fixture
def baseline(tmp_path):
    config = {
        "image_id": "sha256:fixed-image",
        "driver_sha256": "fixed-driver",
        "agent_preprompts": {"improve": "fixed-preprompt"},
        "unchanged_tests_sha256": "fixed-tests",
        "model": "frozen-real-model",
        "resources": {"nano_cpus": 2_000_000_000},
    }
    registration = preregister(tmp_path, config, "unprotected-baseline")
    result = {
        "configuration_sha256": registration["configuration_sha256"],
        "status": "PASS",
        "exit_status": 0,
        "regressions_unchanged": True,
        "work_result": {"after_tests": "passed", "local_commit": "genuine-fix-commit"},
    }
    (tmp_path / "baseline-result.json").write_text(json.dumps(result))
    return tmp_path, config, result


def test_requires_real_completed_baseline(tmp_path):
    with pytest.raises(FileNotFoundError):
        require_baseline(tmp_path, {})


def test_accepts_same_completed_configuration(baseline):
    path, config, _ = baseline
    assert require_baseline(path, config)


@pytest.mark.parametrize(
    "field",
    [
        "image_id",
        "driver_sha256",
        "agent_preprompts",
        "unchanged_tests_sha256",
        "model",
        "resources",
    ],
)
def test_rejects_changed_configuration(baseline, field):
    path, config, _ = baseline
    changed = copy.deepcopy(config)
    changed[field] = "different"
    with pytest.raises(AssertionError, match="differs"):
        require_baseline(path, changed)


@pytest.mark.parametrize(
    "field,value", [("status", "FAIL"), ("exit_status", 1), ("regressions_unchanged", False)]
)
def test_rejects_failed_or_relaxed_baseline(baseline, field, value):
    path, config, result = baseline
    result[field] = value
    (path / "baseline-result.json").write_text(json.dumps(result))
    with pytest.raises(AssertionError):
        require_baseline(path, config)


def test_preregistration_is_not_overwritten(baseline):
    path, config, _ = baseline
    with pytest.raises(FileExistsError):
        preregister(path, config, "protected")
