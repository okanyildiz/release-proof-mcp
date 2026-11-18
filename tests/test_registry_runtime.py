from __future__ import annotations

import copy
import json

import pytest

from conftest import (
    ARTIFACT,
    CHILD_DIGEST,
    COMMIT,
    DIGEST,
    INDEX_DIGEST,
    Harness,
    attestation_result,
    check,
    deployment_object,
    pod_object,
    replicaset_object,
)
from release_proof_mcp.runner import CommandResult, CommandTimeout


def use_direct_digest_input(harness: Harness) -> None:
    pinned = f"ghcr.io/acme/shop@{DIGEST}"
    harness.request["artifact"] = pinned
    harness.runner.route(["crane", "digest", pinned], DIGEST)
    harness.set_attestation([attestation_result()])


def cosign_argv(harness: Harness) -> list[str]:
    return [
        "cosign",
        "verify",
        f"ghcr.io/acme/shop@{DIGEST}",
        "--certificate-identity",
        "https://github.com/acme/shop/.github/workflows/release.yml@refs/heads/main",
        "--certificate-oidc-issuer",
        "https://token.actions.githubusercontent.com",
        "--certificate-github-workflow-repository",
        "acme/shop",
        "--certificate-github-workflow-sha",
        COMMIT,
        "--output",
        "json",
    ]


def test_tag_moved_is_distinct_from_current_build_evidence(harness: Harness) -> None:
    old_digest = f"sha256:{'a' * 64}"
    harness.set_runtime(pods={"items": [pod_object(f"ghcr.io/acme/shop@{old_digest}")]})

    report = harness.verify()

    assert check(report, "attestation.verification")["status"] == "verified"
    assert check(report, "runtime.digest_match")["status"] == "failed"
    assert check(report, "runtime.digest_match")["reason"]["code"] == "TAG_MOVED"
    assert report["evidence"]["pods"][0]["digest_relation"] == "mismatch"


def test_direct_digest_input_mismatch_is_runtime_digest_mismatch(harness: Harness) -> None:
    use_direct_digest_input(harness)
    harness.set_runtime(pods={"items": [pod_object(f"ghcr.io/acme/shop@sha256:{'a' * 64}")]})

    report = harness.verify()

    assert check(report, "runtime.digest_match")["reason"]["code"] == "RUNTIME_DIGEST_MISMATCH"


def test_child_absent_from_pinned_index_fails(harness: Harness) -> None:
    harness.use_index(f"sha256:{'e' * 64}")

    report = harness.verify()

    assert check(report, "runtime.digest_match")["status"] == "failed"
    assert check(report, "runtime.digest_match")["reason"]["code"] == "TAG_MOVED"


def test_child_absent_with_digest_input_is_digest_mismatch(harness: Harness) -> None:
    harness.use_index(f"sha256:{'e' * 64}")
    pinned = f"ghcr.io/acme/shop@{INDEX_DIGEST}"
    harness.request["artifact"] = pinned
    harness.runner.route(["crane", "digest", pinned], INDEX_DIGEST)
    harness.set_attestation([attestation_result(INDEX_DIGEST)], digest=INDEX_DIGEST)

    report = harness.verify()

    assert check(report, "runtime.digest_match")["reason"]["code"] == "RUNTIME_DIGEST_MISMATCH"


@pytest.mark.parametrize("image_id", [f"sha256:{'a' * 64}", "a" * 64, "containerd://local-config"])
def test_bare_or_local_image_id_is_unknown(harness: Harness, image_id: str) -> None:
    harness.set_runtime(pods={"items": [pod_object(image_id)]})

    report = harness.verify()

    assert check(report, "runtime.digest_match")["status"] == "unknown"
    assert check(report, "runtime.digest_match")["reason"]["code"] == "IMAGE_ID_NOT_REGISTRY_COMPARABLE"
    assert report["status"] == "unknown"


def test_docker_pullable_image_id_is_normalized(harness: Harness) -> None:
    harness.set_runtime(pods={"items": [pod_object(f"docker-pullable://ghcr.io/acme/shop@{DIGEST}")]})

    report = harness.verify()

    assert report["status"] == "verified"
    assert report["evidence"]["pods"][0]["digest_relation"] == "direct"


def test_manifest_bytes_must_hash_to_resolved_digest(harness: Harness) -> None:
    harness.runner.route(["crane", "manifest", f"ghcr.io/acme/shop@{DIGEST}"], b"{}" )

    report = harness.verify()

    assert check(report, "registry.resolution")["status"] == "failed"
    assert check(report, "registry.resolution")["reason"]["code"] == "REGISTRY_DIGEST_MISMATCH"
    assert check(report, "attestation.verification")["status"] == "unknown"


def test_malformed_crane_digest_is_unknown(harness: Harness) -> None:
    harness.runner.route(["crane", "digest", ARTIFACT], "latest\n")

    report = harness.verify()

    assert check(report, "registry.resolution")["status"] == "unknown"
    assert check(report, "registry.resolution")["reason"]["code"] == "REGISTRY_RESPONSE_INVALID"


def test_registry_timeout_degrades_dependent_checks_to_unknown(harness: Harness) -> None:
    harness.runner.route(["crane", "digest", ARTIFACT], error=CommandTimeout("timeout"))

    report = harness.verify()

    assert check(report, "registry.resolution")["status"] == "unknown"
    assert check(report, "registry.resolution")["reason"]["code"] == "REGISTRY_UNAVAILABLE"
    assert check(report, "attestation.verification")["reason"]["code"] == "ATTESTATION_INPUT_UNAVAILABLE"
    assert check(report, "runtime.digest_match")["reason"]["code"] == "REGISTRY_DIGEST_UNAVAILABLE"


def test_unrelated_pod_with_duplicate_labels_is_excluded(harness: Harness) -> None:
    unrelated_rs = replicaset_object("unrelated-rs", "another-deployment")
    unrelated = pod_object(
        f"ghcr.io/acme/shop@sha256:{'f' * 64}",
        uid="unrelated-pod",
        name="unrelated-pod",
        rs_uid="unrelated-rs",
    )
    harness.set_runtime(
        replicasets={"items": [replicaset_object(), unrelated_rs]},
        pods={"items": [pod_object(), unrelated]},
    )

    report = harness.verify()

    assert report["status"] == "verified"
    assert [item["uid"] for item in report["evidence"]["pods"]] == ["pod-uid"]


def test_pending_pod_is_not_running_proof(harness: Harness) -> None:
    pod = pod_object()
    pod["status"]["phase"] = "Pending"
    pod["status"]["containerStatuses"][0]["ready"] = False
    pod["status"]["containerStatuses"][0]["state"] = {"waiting": {"reason": "ImagePullBackOff"}}
    harness.set_runtime(pods={"items": [pod]})

    report = harness.verify()

    assert check(report, "runtime.rollout")["status"] == "unknown"
    assert check(report, "runtime.digest_match")["status"] == "failed"
    assert check(report, "runtime.digest_match")["reason"]["code"] == "NO_RUNNING_PODS"


def test_unready_running_container_makes_rollout_unknown(harness: Harness) -> None:
    pod = pod_object()
    pod["status"]["containerStatuses"][0]["ready"] = False
    harness.set_runtime(pods={"items": [pod]})

    report = harness.verify()

    assert check(report, "runtime.rollout")["status"] == "unknown"
    assert check(report, "runtime.rollout")["reason"]["code"] == "ROLLOUT_INCOMPLETE"
    assert check(report, "runtime.digest_match")["status"] == "verified"
    assert report["status"] == "unknown"


def test_omitted_kubernetes_zero_counts_mean_incomplete_rollout(harness: Harness) -> None:
    deployment = deployment_object()
    for field in ("updatedReplicas", "readyReplicas", "availableReplicas"):
        del deployment["status"][field]
    harness.set_runtime(deployment=deployment)

    report = harness.verify()

    assert check(report, "runtime.rollout")["status"] == "unknown"
    assert check(report, "runtime.rollout")["reason"]["code"] == "ROLLOUT_INCOMPLETE"


def test_zero_replica_deployment_does_not_meet_nonzero_requirement(harness: Harness) -> None:
    deployment = deployment_object()
    deployment["spec"]["replicas"] = 0
    deployment["status"].update({"updatedReplicas": 0, "readyReplicas": 0, "availableReplicas": 0})
    harness.set_runtime(deployment=deployment, pods={"items": []})

    report = harness.verify()

    assert check(report, "runtime.rollout")["status"] == "unknown"
    assert check(report, "runtime.digest_match")["status"] == "unknown"
    assert report["status"] == "unknown"


def test_observed_generation_lag_is_rollout_unknown(harness: Harness) -> None:
    deployment = deployment_object()
    deployment["status"]["observedGeneration"] = 2
    harness.set_runtime(deployment=deployment)

    report = harness.verify()

    assert check(report, "runtime.rollout")["status"] == "unknown"
    assert check(report, "runtime.rollout")["reason"]["code"] == "ROLLOUT_INCOMPLETE"


def test_mixed_old_new_digests_fail_even_during_rollout(harness: Harness) -> None:
    deployment = deployment_object()
    deployment["spec"]["replicas"] = 2
    deployment["status"].update({"updatedReplicas": 1, "readyReplicas": 1, "availableReplicas": 1})
    old = pod_object(f"ghcr.io/acme/shop@sha256:{'a' * 64}", uid="old", name="old")
    new = pod_object(uid="new", name="new")
    harness.set_runtime(deployment=deployment, pods={"items": [old, new]})

    report = harness.verify()

    assert report["status"] == "failed"
    assert check(report, "runtime.rollout")["status"] == "unknown"
    assert check(report, "runtime.digest_match")["status"] == "failed"


def test_second_snapshot_change_is_unknown(harness: Harness) -> None:
    changed = pod_object()
    changed["status"]["containerStatuses"][0]["containerID"] = "containerd://changed"
    harness.set_runtime(second_pods={"items": [changed]})

    report = harness.verify()

    assert check(report, "runtime.stable_observation")["status"] == "unknown"
    assert check(report, "runtime.stable_observation")["reason"]["code"] == "RUNTIME_CHANGED_DURING_VERIFICATION"
    assert report["status"] == "unknown"


def test_wrong_container_name_fails_closed(harness: Harness) -> None:
    harness.request["container"] = "sidecar"

    report = harness.verify()

    assert check(report, "runtime.rollout")["status"] == "failed"
    assert check(report, "runtime.rollout")["reason"]["code"] == "CONTAINER_NOT_FOUND"
    assert check(report, "runtime.digest_match")["status"] == "unknown"


def test_missing_container_status_is_unknown_not_no_running_proof(harness: Harness) -> None:
    pod = pod_object()
    pod["status"]["containerStatuses"] = []
    harness.set_runtime(pods={"items": [pod]})

    report = harness.verify()

    assert check(report, "runtime.digest_match")["status"] == "unknown"
    assert check(report, "runtime.digest_match")["reason"]["code"] == "CONTAINER_STATUS_MISSING"


def test_kubectl_forbidden_is_unknown(harness: Harness) -> None:
    argv = [
        "kubectl", "--context", "production", "-n", "production",
        "get", "deployment", "shop-api", "-o", "json",
    ]
    harness.runner.route(argv, returncode=1, stderr="deployments.apps is forbidden")

    report = harness.verify()

    assert check(report, "runtime.rollout")["status"] == "unknown"
    assert check(report, "runtime.rollout")["reason"]["code"] == "RUNTIME_ACCESS_DENIED"
    assert check(report, "runtime.stable_observation")["status"] == "unknown"


def test_kubectl_timeout_is_unknown(harness: Harness) -> None:
    argv = [
        "kubectl", "--context", "production", "-n", "production",
        "get", "deployment", "shop-api", "-o", "json",
    ]
    harness.runner.route(argv, error=CommandTimeout("timeout"))

    report = harness.verify()

    assert check(report, "runtime.rollout")["status"] == "unknown"
    assert check(report, "runtime.rollout")["reason"]["code"] == "RUNTIME_UNAVAILABLE"


def test_required_cosign_signature_missing_fails(harness: Harness) -> None:
    harness.policy["require_cosign_signature"] = True
    harness.runner.route(["cosign", "version"], "v2.5.0")
    harness.runner.route(cosign_argv(harness), returncode=1, stderr="no signatures found")

    report = harness.verify()

    assert check(report, "signature.cosign")["status"] == "failed"
    assert check(report, "signature.cosign")["reason"]["code"] == "SIGNATURE_MISSING"


def test_unsigned_artifact_does_not_run_optional_cosign(harness: Harness) -> None:
    report = harness.verify()

    assert report["status"] == "verified"
    assert not any(call and call[0] == "cosign" for call in harness.runner.calls)
    assert all(item["name"] != "signature.cosign" for item in report["checks"])


def test_runtime_evidence_order_is_deterministic(harness: Harness) -> None:
    pod_z = pod_object(uid="z", name="z")
    pod_a = pod_object(uid="a", name="a")
    deployment = deployment_object()
    deployment["spec"]["replicas"] = 2
    deployment["status"].update({"updatedReplicas": 2, "readyReplicas": 2, "availableReplicas": 2})
    harness.set_runtime(deployment=deployment, pods={"items": [pod_z, pod_a]})

    report = harness.verify()

    assert report["status"] == "verified"
    assert [item["uid"] for item in report["evidence"]["pods"]] == ["a", "z"]


def test_digest_pinned_input_cannot_be_moved_by_crane(harness: Harness) -> None:
    pinned = f"ghcr.io/acme/shop@{DIGEST}"
    harness.request["artifact"] = pinned
    harness.runner.route(["crane", "digest", pinned], INDEX_DIGEST)

    report = harness.verify()

    resolution = check(report, "registry.resolution")
    assert resolution["status"] == "failed"
    assert resolution["reason"]["code"] == "REGISTRY_DIGEST_MISMATCH"
    assert resolution["reason"]["expected"] == DIGEST
    assert resolution["reason"]["actual"] == INDEX_DIGEST
    assert report["subject"]["pinned_artifact"] is None
    assert not any(call[:2] == ("crane", "manifest") for call in harness.runner.calls)


def test_image_manifest_with_forged_manifests_field_is_not_an_index(harness: Harness) -> None:
    import hashlib
    from conftest import MANIFEST

    forged = json.loads(MANIFEST)
    forged["manifests"] = [{"digest": CHILD_DIGEST, "size": 123}]
    forged_bytes = json.dumps(forged, separators=(",", ":")).encode()
    forged_digest = f"sha256:{hashlib.sha256(forged_bytes).hexdigest()}"
    harness.runner.route(["crane", "digest", ARTIFACT], forged_digest)
    harness.runner.route(["crane", "manifest", f"ghcr.io/acme/shop@{forged_digest}"], forged_bytes)
    harness.set_attestation([attestation_result(forged_digest)], digest=forged_digest)
    harness.set_runtime(pods={"items": [pod_object(f"ghcr.io/acme/shop@{CHILD_DIGEST}")]})

    report = harness.verify()

    resolution = check(report, "registry.resolution")
    assert resolution["status"] == "unknown"
    assert resolution["reason"]["code"] == "REGISTRY_RESPONSE_INVALID"
    assert check(report, "attestation.verification")["reason"]["code"] == "ATTESTATION_INPUT_UNAVAILABLE"
    assert report["status"] != "verified"
    assert all(pod.get("digest_relation") != "index_child" for pod in report["evidence"]["pods"])


def test_index_with_image_manifest_structure_is_rejected(harness: Harness) -> None:
    import hashlib

    contradictory = json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{"digest": CHILD_DIGEST}],
        "config": {},
        "layers": [],
    }, separators=(",", ":")).encode()
    digest = f"sha256:{hashlib.sha256(contradictory).hexdigest()}"
    harness.runner.route(["crane", "digest", ARTIFACT], digest)
    harness.runner.route(["crane", "manifest", f"ghcr.io/acme/shop@{digest}"], contradictory)

    report = harness.verify()

    assert check(report, "registry.resolution")["status"] == "unknown"
    assert check(report, "registry.resolution")["reason"]["code"] == "REGISTRY_RESPONSE_INVALID"
    assert report["status"] != "verified"


def test_crane_digest_accepts_one_trailing_newline(harness: Harness) -> None:
    harness.runner.route(["crane", "digest", ARTIFACT], DIGEST + "\n")

    report = harness.verify()

    assert report["status"] == "verified"
