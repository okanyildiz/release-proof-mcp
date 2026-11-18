from __future__ import annotations

import copy
import json

from conftest import (
    COMMIT,
    DIGEST,
    HEAD,
    INDEX_DIGEST,
    RUN_ID,
    Harness,
    attestation_argv,
    attestation_result,
    check,
    pr_object,
    reviews_page,
    run_object,
)


def test_single_platform_direct_image_id_happy_path(harness: Harness) -> None:
    report = harness.verify()

    assert report["status"] == "verified"
    assert report["schema_version"] == "release-deployment-proof/v1"
    assert all(item["status"] == "verified" for item in report["checks"])
    assert report["subject"]["pinned_artifact"] == f"ghcr.io/acme/shop@{DIGEST}"
    assert report["evidence"]["pods"][0]["digest_relation"] == "direct"
    assert report["evidence"]["pull_request"]["merge_commit_directly_reviewed"] is False
    assert report["missing_coverage"] == []
    assert report["reasons"] == []


def test_runtime_can_report_attested_index_digest(harness: Harness) -> None:
    harness.use_index(INDEX_DIGEST)

    report = harness.verify()

    assert report["status"] == "verified"
    assert report["evidence"]["registry"]["media_type"] == "application/vnd.oci.image.index.v1+json"
    assert report["evidence"]["pods"][0]["digest_relation"] == "direct"


def test_runtime_child_is_contained_in_attested_index(harness: Harness) -> None:
    from conftest import CHILD_DIGEST

    harness.use_index(CHILD_DIGEST)

    report = harness.verify()

    assert report["status"] == "verified"
    assert report["evidence"]["pods"][0]["digest_relation"] == "index_child"


def test_reusable_signer_workflow_and_exact_signer_digest(harness: Harness) -> None:
    harness.request["signer_workflow"] = "acme/builders/.github/workflows/reusable.yml"
    harness.set_attestation([
        attestation_result(
            subjectAlternativeName="https://github.com/acme/builders/.github/workflows/reusable.yml@refs/heads/main"
        )
    ])

    report = harness.verify()

    assert report["status"] == "verified"
    argv = harness.runner.calls[harness.runner.calls.index(tuple(attestation_argv(harness.request, DIGEST)))]
    assert "--signer-digest" in argv
    assert report["evidence"]["certificate"]["build_signer_digest"] == harness.request["signer_digest"]


def test_exact_head_review_mode(harness: Harness) -> None:
    harness.request["review"]["mode"] = "exact_head"
    pr = pr_object()
    pr["head"]["sha"] = COMMIT
    pr["merged_at"] = None
    pr["merge_commit_sha"] = None
    reviews = reviews_page()
    reviews[0][0]["commit_id"] = COMMIT
    harness.set_pr(pr)
    harness.set_reviews(reviews)

    report = harness.verify()

    assert report["status"] == "verified"
    assert report["evidence"]["pull_request"]["merge_commit_directly_reviewed"] is True
    assert not any("merge commit itself" in item for item in report["limitations"])


def test_merged_pr_states_merge_commit_review_limitation(harness: Harness) -> None:
    report = harness.verify()

    assert report["evidence"]["pull_request"]["head_sha"] == HEAD
    assert report["evidence"]["pull_request"]["merge_commit_sha"] == COMMIT
    assert any("merge commit itself" in item for item in report["limitations"])


def test_historical_production_approval_on_certified_run(harness: Harness) -> None:
    report = harness.verify()

    assert check(report, "release.approval")["status"] == "verified"
    assert report["evidence"]["release_approvals"] == [
        {"environment": "production", "approver_id": 2001, "state": "approved", "comment": "Ship it"}
    ]
    assert report["evidence"]["workflow_run"]["id"] == RUN_ID


def test_expired_leaf_with_verified_timestamp_is_not_rejected(harness: Harness) -> None:
    result = attestation_result()
    cert = result["verificationResult"]["signature"]["certificate"]
    cert["notBefore"] = "2020-01-01T00:00:00Z"
    cert["notAfter"] = "2020-01-01T00:10:00Z"
    harness.set_attestation([result])

    report = harness.verify()

    assert report["status"] == "verified"
    timestamps = report["evidence"]["attestation"]["verified_timestamps"]
    assert timestamps == [
        {
            "type": "TimestampAuthority",
            "uri": "https://timestamp.example",
            "timestamp": "2026-01-01T00:00:00Z",
        }
    ]
    assert "internal" not in json.dumps(timestamps)
    assert "resolvedDependencies" not in json.dumps(report)


def test_optional_cosign_signature_success(harness: Harness) -> None:
    harness.request["require_cosign_signature"] = True
    harness.runner.route(["cosign", "version"], "GitHub Cosign v2.5.0")
    harness.runner.route(
        [
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
        ],
        '[{"critical":{"identity":"redacted"}}]',
    )

    report = harness.verify()

    assert report["status"] == "verified"
    assert check(report, "signature.cosign")["status"] == "verified"
    assert report["evidence"]["cosign"] == {"verified": True, "result_count": 1}
    assert report["tools"]["cosign"] == "2.5.0"


def test_second_snapshot_is_actually_read(harness: Harness) -> None:
    before = copy.deepcopy(harness.runner.calls)

    report = harness.verify()

    pod_call = ("kubectl", "--context", "production", "-n", "production", "get", "pods", "-o", "json")
    assert harness.runner.calls.count(pod_call) == 2
    assert len(harness.runner.calls) > len(before)
    assert check(report, "runtime.stable_observation")["status"] == "verified"
