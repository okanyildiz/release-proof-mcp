from __future__ import annotations

import pytest

from conftest import Harness, check, pod_object
from test_evidence_package import publish, verify


def terminal_pod(phase: str) -> dict:
    pod = pod_object(uid="pod-evicted", name="shop-api-abc-old")
    pod["status"] = {
        "phase": phase,
        "reason": "Evicted" if phase == "Failed" else "Completed",
        "message": "The node was low on resource: memory.",
    }
    return pod


@pytest.mark.parametrize("phase", ["Failed", "Succeeded"])
def test_terminal_pod_does_not_block_healthy_rollout(
    harness: Harness, phase: str
) -> None:
    harness.set_runtime(pods={"items": [pod_object(), terminal_pod(phase)]})

    report = harness.verify()

    assert report["status"] == "verified"
    assert report["evidence"]["excluded_terminal_pods"] == 1
    assert [pod["uid"] for pod in report["evidence"]["pods"]] == ["pod-uid"]


def test_only_terminal_pods_do_not_prove_rollout(harness: Harness) -> None:
    harness.set_runtime(pods={"items": [terminal_pod("Failed")]})

    report = harness.verify()

    assert report["status"] == "unknown"
    assert report["evidence"]["excluded_terminal_pods"] == 1
    assert report["evidence"]["pods"] == []
    assert check(report, "runtime.rollout")["reason"]["code"] == "ROLLOUT_INCOMPLETE"


def test_running_to_terminal_between_snapshots_is_a_change(harness: Harness) -> None:
    harness.set_runtime(
        pods={"items": [pod_object(), terminal_pod("Failed")]},
        second_pods={"items": [terminal_pod("Failed")]},
    )

    report = harness.verify()

    assert check(report, "runtime.stable_observation")["reason"]["code"] == (
        "RUNTIME_CHANGED_DURING_VERIFICATION"
    )
    assert report["status"] == "unknown"


def test_terminal_pod_disappearing_does_not_change_active_rollout(
    harness: Harness,
) -> None:
    harness.set_runtime(
        pods={"items": [pod_object(), terminal_pod("Failed")]},
        second_pods={"items": [pod_object()]},
    )

    report = harness.verify()

    assert report["status"] == "verified"
    assert report["evidence"]["excluded_terminal_pods"] == 1


def test_terminal_pod_count_is_signed_and_consumable(
    tmp_path, harness: Harness
) -> None:
    harness.set_runtime(pods={"items": [pod_object(), terminal_pod("Failed")]})

    case = publish(harness, tmp_path / "operator")
    decision = verify(case)

    assert case.receipt["evidence"]["excluded_terminal_pods"] == 1
    assert decision["allow"] is True
    assert decision["reason"] == "OK"
