from __future__ import annotations

import copy

import pytest

from conftest import Harness, check, deployment_object, pod_object
from test_evidence_package import PackageCase, publish, verify, write_signed


@pytest.fixture
def package_case(tmp_path, harness: Harness) -> PackageCase:
    return publish(harness, tmp_path / "operator")


@pytest.mark.parametrize("phase", ["Failed", "Succeeded"])
def test_same_uid_running_to_terminal_is_a_change(
    harness: Harness, phase: str
) -> None:
    terminal = pod_object()
    terminal["status"] = {
        "phase": phase,
        "reason": "Evicted" if phase == "Failed" else "Completed",
    }
    harness.set_runtime(second_pods={"items": [terminal]})

    report = harness.verify()

    assert check(report, "runtime.stable_observation")["reason"]["code"] == (
        "RUNTIME_CHANGED_DURING_VERIFICATION"
    )
    assert report["status"] == "unknown"


def test_first_snapshot_reason_precedes_later_changes(harness: Harness) -> None:
    deployment = deployment_object()
    deployment["spec"]["replicas"] = 2
    deployment["status"].update(
        {"updatedReplicas": 2, "readyReplicas": 2, "availableReplicas": 2}
    )
    harness.set_runtime(
        deployment=deployment,
        pods={"items": [pod_object()]},
        second_pods={"items": []},
    )

    report = harness.verify()

    assert check(report, "runtime.stable_observation")["reason"]["code"] == (
        "ROLLOUT_INCOMPLETE"
    )


@pytest.mark.parametrize("value", ["1", True, -1])
def test_terminal_count_rejects_invalid_values(
    package_case: PackageCase, value: object
) -> None:
    receipt = copy.deepcopy(package_case.receipt)
    receipt["evidence"]["excluded_terminal_pods"] = value
    write_signed(package_case.path, receipt, unchecked=True)

    decision = verify(package_case)

    assert decision["allow"] is False
    assert decision["reason"] == "RECEIPT_INVALID"
