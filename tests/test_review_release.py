from __future__ import annotations

import copy

import pytest

from conftest import (
    COMMIT,
    HEAD,
    Harness,
    approvals_object,
    check,
    pr_object,
    reviews_page,
    run_object,
)


def approval(reviewer_id: int = 1001, review_id: int = 987, commit_id: str = HEAD) -> dict:
    return {
        "id": review_id,
        "user": {"id": reviewer_id},
        "state": "APPROVED",
        "commit_id": commit_id,
        "submitted_at": f"2026-11-18T10:{review_id % 60:02d}:00Z",
    }


def test_commit_lookup_requires_full_sha_equality(harness: Harness) -> None:
    harness.runner.route_json(
        ["gh", "api", f"repos/acme/shop/commits/{COMMIT}"], {"sha": COMMIT[:-1]}
    )

    report = harness.verify()

    assert check(report, "source.commit")["status"] == "failed"
    assert check(report, "source.commit")["reason"]["code"] == "SOURCE_COMMIT_MISMATCH"


def test_stale_approval_on_older_pr_head_fails(harness: Harness) -> None:
    harness.set_reviews([[approval(commit_id=COMMIT)]])

    report = harness.verify()

    assert check(report, "source.review")["status"] == "failed"
    assert check(report, "source.review")["reason"]["code"] == "REVIEW_POLICY_FAILED"


def test_latest_changes_requested_blocks_earlier_approval(harness: Harness) -> None:
    changes = approval(review_id=988)
    changes["state"] = "CHANGES_REQUESTED"
    harness.set_reviews([[approval()], [changes]])

    report = harness.verify()

    assert check(report, "source.review")["reason"]["code"] == "REVIEW_POLICY_FAILED"
    assert report["evidence"]["reviews"][-1]["state"] == "CHANGES_REQUESTED"


def test_latest_dismissed_review_removes_earlier_approval(harness: Harness) -> None:
    dismissed = approval(review_id=989)
    dismissed["state"] = "DISMISSED"
    harness.set_reviews([[approval(), dismissed]])

    report = harness.verify()

    assert check(report, "source.review")["status"] == "failed"
    assert check(report, "source.review")["reason"]["actual"] == 0


def test_comment_after_approval_does_not_erase_approval(harness: Harness) -> None:
    comment = approval(review_id=990)
    comment["state"] = "COMMENTED"
    harness.set_reviews([[approval(), comment]])

    report = harness.verify()

    assert report["status"] == "verified"


def test_pending_review_does_not_erase_or_add_approval(harness: Harness) -> None:
    pending = approval(review_id=991)
    pending["state"] = "PENDING"
    harness.set_reviews([[pending, approval()]])

    report = harness.verify()

    assert report["status"] == "verified"


def test_insufficient_distinct_approval_count_fails(harness: Harness) -> None:
    harness.policy["review"]["min_approvals"] = 2
    harness.set_reviews([[approval()]])

    report = harness.verify()

    reason = check(report, "source.review")["reason"]
    assert reason["code"] == "REVIEW_POLICY_FAILED"
    assert reason["expected"] == 2
    assert reason["actual"] == 1


def test_reviewer_outside_numeric_id_allowlist_fails(harness: Harness) -> None:
    harness.set_reviews([[approval(reviewer_id=9999)]])

    report = harness.verify()

    assert check(report, "source.review")["status"] == "failed"


def test_author_self_review_fails_non_author_policy(harness: Harness) -> None:
    harness.policy["review"]["allowed_reviewer_ids"] = [9001]
    harness.set_reviews([[approval(reviewer_id=9001)]])

    report = harness.verify()

    assert check(report, "source.review")["status"] == "failed"


def test_author_review_counts_when_non_author_policy_disabled(harness: Harness) -> None:
    harness.policy["review"]["allowed_reviewer_ids"] = [9001]
    harness.policy["review"]["require_non_author"] = False
    harness.set_reviews([[approval(reviewer_id=9001)]])

    report = harness.verify()

    assert report["status"] == "verified"


def test_duplicate_reviewer_approvals_count_once(harness: Harness) -> None:
    harness.policy["review"]["min_approvals"] = 2
    harness.set_reviews([[approval(review_id=1), approval(review_id=2)]])

    report = harness.verify()

    assert check(report, "source.review")["status"] == "failed"


def test_all_review_pages_are_counted_deterministically(harness: Harness) -> None:
    harness.policy["review"]["min_approvals"] = 2
    harness.set_reviews([[approval(1002, 2)], [approval(1001, 1)]])

    report = harness.verify()

    assert report["status"] == "verified"
    assert [item["reviewer_id"] for item in report["evidence"]["reviews"]] == [1001, 1002]


def test_wrong_pr_merge_sha_fails(harness: Harness) -> None:
    pr = pr_object()
    pr["merge_commit_sha"] = "f" * 40
    harness.set_pr(pr)

    report = harness.verify()

    assert check(report, "source.review")["status"] == "failed"
    assert check(report, "source.review")["reason"]["code"] == "REVIEW_POLICY_FAILED"


def test_unmerged_pr_fails_merged_mode(harness: Harness) -> None:
    pr = pr_object()
    pr["merged_at"] = None
    harness.set_pr(pr)

    report = harness.verify()

    assert check(report, "source.review")["status"] == "failed"


@pytest.mark.parametrize("mutation", ["draft", "base"])
def test_pr_trust_policy(harness: Harness, mutation: str) -> None:
    pr = pr_object()
    if mutation == "draft":
        pr["draft"] = True
    else:
        pr["base"]["repo"]["full_name"] = "acme/other"
    harness.set_pr(pr)

    report = harness.verify()

    assert check(report, "source.review")["status"] == "failed"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("run_attempt", 2),
        ("head_sha", "f" * 40),
        ("event", "workflow_dispatch"),
        ("path", ".github/workflows/other.yml"),
        ("conclusion", "failure"),
        ("status", "in_progress"),
        ("id", 999),
        ("id", True),
        ("run_attempt", True),
        ("run_attempt", 1.0),
    ],
)
def test_workflow_run_policy_failures(harness: Harness, field: str, value: object) -> None:
    run = run_object()
    run[field] = value
    harness.set_run(run)

    report = harness.verify()

    assert check(report, "workflow.run")["status"] == "failed"
    assert check(report, "workflow.run")["reason"]["code"] == "WORKFLOW_RUN_POLICY_FAILED"


def test_workflow_run_repository_must_match(harness: Harness) -> None:
    run = run_object()
    run["repository"]["full_name"] = "acme/other"
    harness.set_run(run)

    report = harness.verify()

    assert check(report, "workflow.run")["status"] == "failed"


def test_immutable_repository_id_mismatch_fails_run_link(harness: Harness) -> None:
    from conftest import attestation_result

    harness.set_attestation([attestation_result(sourceRepositoryIdentifier="556")])

    report = harness.verify()

    assert check(report, "workflow.run")["status"] == "failed"
    assert check(report, "workflow.run")["reason"]["code"] == "REPOSITORY_ID_MISMATCH"


def test_certificate_expected_run_disambiguator_is_enforced(harness: Harness) -> None:
    from conftest import attestation_result

    harness.set_attestation([
        attestation_result(runInvocationURI="https://github.com/acme/shop/actions/runs/123456789/attempts/2")
    ])

    report = harness.verify()

    assert check(report, "attestation.verification")["status"] == "failed"
    assert check(report, "attestation.verification")["reason"]["code"] == "WORKFLOW_RUN_POLICY_FAILED"


def test_missing_environment_approval_fails(harness: Harness) -> None:
    harness.set_approvals([])

    report = harness.verify()

    assert check(report, "release.approval")["status"] == "failed"
    assert check(report, "release.approval")["reason"]["code"] == "RELEASE_APPROVAL_MISSING"


def test_rejected_or_pending_approval_is_not_approval(harness: Harness) -> None:
    records = approvals_object()
    records[0]["state"] = "rejected"
    harness.set_approvals(records)

    report = harness.verify()

    assert check(report, "release.approval")["reason"]["code"] == "RELEASE_APPROVAL_MISSING"


def test_wrong_environment_fails(harness: Harness) -> None:
    records = approvals_object()
    records[0]["environments"] = [{"name": "staging"}]
    harness.set_approvals(records)

    report = harness.verify()

    assert check(report, "release.approval")["reason"]["code"] == "RELEASE_APPROVAL_MISSING"


def test_wrong_approver_fails_allowlist(harness: Harness) -> None:
    records = approvals_object()
    records[0]["user"]["id"] = 9999
    harness.set_approvals(records)

    report = harness.verify()

    assert check(report, "release.approval")["reason"]["code"] == "RELEASE_APPROVER_NOT_ALLOWED"


@pytest.mark.parametrize("actor", ["actor", "triggering_actor"])
def test_deployment_self_approval_is_rejected(harness: Harness, actor: str) -> None:
    records = approvals_object()
    records[0]["user"]["id"] = 3001
    run = run_object()
    run[actor]["id"] = 3001
    harness.set_run(run)
    harness.set_approvals(records)
    harness.policy["release"]["required_approver_ids"] = [3001]

    report = harness.verify()

    assert check(report, "release.approval")["status"] == "failed"
    assert check(report, "release.approval")["reason"]["code"] == "RELEASE_APPROVER_NOT_ALLOWED"


def test_self_approval_can_only_pass_when_explicitly_allowed(harness: Harness) -> None:
    records = approvals_object()
    records[0]["user"]["id"] = 3001
    harness.set_approvals(records)
    harness.policy["release"]["required_approver_ids"] = [3001]
    harness.policy["release"]["prevent_self_approval"] = False

    report = harness.verify()

    assert report["status"] == "verified"


def test_historical_not_current_environment_configuration_is_reported(harness: Harness) -> None:
    report = harness.verify()

    assert any("Historical branch-protection and environment configuration" in item for item in report["limitations"])
    assert not any("environments/production" in "/".join(call) for call in harness.runner.calls)


def test_run_actor_evidence_is_required_for_self_approval_policy(harness: Harness) -> None:
    harness.runner.route(
        ["gh", "api", "repos/acme/shop/actions/runs/123456789/attempts/1"],
        "forbidden",
        returncode=1,
        stderr="HTTP 403 forbidden",
    )

    report = harness.verify()

    assert check(report, "workflow.run")["status"] == "unknown"
    assert check(report, "release.approval")["status"] == "unknown"
    assert check(report, "release.approval")["reason"]["code"] == "RUN_ACTOR_EVIDENCE_UNAVAILABLE"


def test_approval_api_access_denied_is_unknown(harness: Harness) -> None:
    harness.runner.route(
        ["gh", "api", "repos/acme/shop/actions/runs/123456789/approvals"],
        returncode=1,
        stderr="HTTP 403 forbidden",
    )

    report = harness.verify()

    assert check(report, "release.approval")["status"] == "unknown"
    assert check(report, "release.approval")["reason"]["code"] == "GITHUB_ACCESS_DENIED"


@pytest.mark.parametrize("actor_name", ["actor", "triggering_actor"])
@pytest.mark.parametrize(
    "mutation",
    ["missing_actor", "null_actor", "missing_id", "null_id", "string_id", "zero_id", "bool_id"],
)
def test_self_approval_requires_complete_positive_actor_ids(
    harness: Harness, actor_name: str, mutation: str
) -> None:
    run = run_object()
    approver_id = run[actor_name]["id"]
    if mutation == "missing_actor":
        run.pop(actor_name)
    elif mutation == "null_actor":
        run[actor_name] = None
    elif mutation == "missing_id":
        run[actor_name].pop("id")
    elif mutation == "null_id":
        run[actor_name]["id"] = None
    elif mutation == "string_id":
        run[actor_name]["id"] = str(approver_id)
    elif mutation == "zero_id":
        run[actor_name]["id"] = 0
    else:
        run[actor_name]["id"] = True
    records = approvals_object()
    records[0]["user"]["id"] = approver_id
    harness.policy["release"]["required_approver_ids"] = [approver_id]
    harness.set_run(run)
    harness.set_approvals(records)

    report = harness.verify()

    approval_check = check(report, "release.approval")
    assert approval_check["status"] == "unknown"
    assert approval_check["reason"]["code"] == "RUN_ACTOR_EVIDENCE_UNAVAILABLE"
    assert report["status"] != "verified"


@pytest.mark.parametrize(
    "mutation", ["missing_user", "null_user", "missing_id", "null_id", "string_id", "zero_id"]
)
def test_non_author_policy_requires_valid_pr_author_id(harness: Harness, mutation: str) -> None:
    pr = pr_object()
    if mutation == "missing_user":
        pr.pop("user")
    elif mutation == "null_user":
        pr["user"] = None
    elif mutation == "missing_id":
        pr["user"].pop("id")
    elif mutation == "null_id":
        pr["user"]["id"] = None
    elif mutation == "string_id":
        pr["user"]["id"] = "9001"
    else:
        pr["user"]["id"] = 0
    harness.policy["review"]["allowed_reviewer_ids"] = [9001]
    harness.set_pr(pr)
    harness.set_reviews([[approval(reviewer_id=9001)]])

    report = harness.verify()

    review_check = check(report, "source.review")
    assert review_check["status"] == "unknown"
    assert review_check["reason"]["code"] == "REVIEW_AUTHOR_EVIDENCE_UNAVAILABLE"
    assert report["status"] != "verified"


def test_missing_author_is_allowed_when_non_author_policy_is_disabled(harness: Harness) -> None:
    pr = pr_object()
    pr.pop("user")
    harness.policy["review"]["require_non_author"] = False
    harness.set_pr(pr)

    report = harness.verify()

    assert report["status"] == "verified"


def test_rerun_attempt_is_rejected_because_approvals_are_run_level(harness: Harness) -> None:
    from conftest import attestation_result

    harness.request.pop("expected_run")
    harness.set_attestation([
        attestation_result(
            runInvocationURI="https://github.com/acme/shop/actions/runs/123456789/attempts/2"
        )
    ])

    report = harness.verify()

    assert check(report, "attestation.verification")["status"] == "verified"
    assert check(report, "workflow.run")["reason"]["code"] == "RUN_ATTEMPT_UNSUPPORTED"
    assert check(report, "release.approval")["reason"]["code"] == "RUN_ATTEMPT_UNSUPPORTED"
    assert report["status"] == "failed"
    assert not any("attempts/2" in "/".join(call) for call in harness.runner.calls if call[:2] == ("gh", "api"))


@pytest.mark.parametrize("state", ["APPROVED", "CHANGES_REQUESTED", "DISMISSED"])
@pytest.mark.parametrize("field", ["reviewer_id", "review_id", "submitted_at"])
def test_malformed_decision_reviews_invalidate_evidence(
    harness: Harness, state: str, field: str
) -> None:
    review = approval()
    review["state"] = state
    if field == "reviewer_id":
        review["user"]["id"] = 0
    elif field == "review_id":
        review["id"] = 0
    else:
        review["submitted_at"] = "2026-11-18T10:00:00"
    harness.set_reviews([[review]])

    report = harness.verify()

    review_check = check(report, "source.review")
    assert review_check["status"] == "unknown"
    assert review_check["reason"]["code"] == "REVIEW_EVIDENCE_INVALID"
    assert report["status"] != "verified"


def test_malformed_later_changes_requested_never_preserves_stale_approval(harness: Harness) -> None:
    changes = approval(review_id=988)
    changes["state"] = "CHANGES_REQUESTED"
    del changes["id"]
    harness.set_reviews([[approval(), changes]])

    report = harness.verify()

    review_check = check(report, "source.review")
    assert review_check["status"] == "unknown"
    assert review_check["reason"]["code"] == "REVIEW_EVIDENCE_INVALID"
    assert report["evidence"]["reviews"] == []
    assert report["status"] != "verified"


def test_unknown_review_state_is_conservatively_unknown(harness: Harness) -> None:
    review = approval(review_id=988)
    review["state"] = "APPROVED_WITH_COMMENTS"
    harness.set_reviews([[approval(), review]])

    report = harness.verify()

    assert check(report, "source.review")["status"] == "unknown"
    assert check(report, "source.review")["reason"]["code"] == "REVIEW_EVIDENCE_INVALID"


def test_review_order_uses_normalized_timezone_aware_timestamps(harness: Harness) -> None:
    changes = approval(review_id=988)
    changes["state"] = "CHANGES_REQUESTED"
    changes["submitted_at"] = "2026-11-18T09:30:00-01:00"
    harness.set_reviews([[approval(), changes]])

    report = harness.verify()

    assert check(report, "source.review")["status"] == "failed"
    assert check(report, "source.review")["reason"]["code"] == "REVIEW_POLICY_FAILED"
    assert report["evidence"]["reviews"][-1]["state"] == "CHANGES_REQUESTED"


def test_attempt_one_approval_is_rejected_after_a_current_rerun(harness: Harness) -> None:
    current = run_object()
    current["run_attempt"] = 2
    harness.set_current_run(current)

    report = harness.verify()

    assert check(report, "workflow.run")["status"] == "verified"
    approval_check = check(report, "release.approval")
    assert approval_check["status"] == "failed"
    assert approval_check["reason"]["code"] == "RUN_ATTEMPT_UNSUPPORTED"
    assert report["status"] != "verified"


@pytest.mark.parametrize("mutation", ["missing_id", "missing_attempt", "malformed_attempt"])
def test_current_run_attempt_evidence_is_required(harness: Harness, mutation: str) -> None:
    current = run_object()
    if mutation == "missing_id":
        del current["id"]
    elif mutation == "missing_attempt":
        del current["run_attempt"]
    else:
        current["run_attempt"] = "1"
    harness.set_current_run(current)

    report = harness.verify()

    approval_check = check(report, "release.approval")
    assert approval_check["status"] == "unknown"
    assert approval_check["reason"]["code"] == "RUN_ATTEMPT_UNAVAILABLE"
    assert report["status"] != "verified"


def test_current_run_id_mismatch_does_not_accept_approval(harness: Harness) -> None:
    current = run_object()
    current["id"] += 1
    harness.set_current_run(current)

    report = harness.verify()

    approval_check = check(report, "release.approval")
    assert approval_check["status"] == "failed"
    assert approval_check["reason"]["code"] == "RUN_IDENTITY_MISMATCH"
    assert report["status"] != "verified"


def test_missing_run_repository_id_counterpart_is_unknown(harness: Harness) -> None:
    from conftest import attestation_result

    harness.set_attestation([attestation_result(sourceRepositoryIdentifier="555")])
    run = run_object()
    del run["repository"]["id"]
    harness.set_run(run)

    report = harness.verify()

    run_check = check(report, "workflow.run")
    assert run_check["status"] == "unknown"
    assert run_check["reason"]["code"] == "REPOSITORY_ID_EVIDENCE_UNAVAILABLE"
    assert report["status"] != "verified"


def test_present_run_repository_id_requires_certificate_counterpart(harness: Harness) -> None:
    from conftest import attestation_result

    result = attestation_result()
    del result["verificationResult"]["signature"]["certificate"]["sourceRepositoryIdentifier"]
    harness.set_attestation([result])

    report = harness.verify()

    assert check(report, "workflow.run")["status"] == "unknown"
    assert check(report, "workflow.run")["reason"]["code"] == "REPOSITORY_ID_EVIDENCE_UNAVAILABLE"
    assert report["status"] != "verified"


def test_missing_run_owner_id_counterpart_is_unknown(harness: Harness) -> None:
    from conftest import attestation_result

    harness.set_attestation([attestation_result(sourceRepositoryOwnerIdentifier="777")])

    report = harness.verify()

    assert check(report, "workflow.run")["status"] == "unknown"
    assert check(report, "workflow.run")["reason"]["code"] == "REPOSITORY_ID_EVIDENCE_UNAVAILABLE"
    assert report["status"] != "verified"


def test_duplicate_decision_review_id_across_reviewers_is_invalid(harness: Harness) -> None:
    harness.policy["review"]["min_approvals"] = 2
    harness.set_reviews([[approval(1001, 987)], [approval(1002, 987)]])

    report = harness.verify()

    review_check = check(report, "source.review")
    assert review_check["status"] == "unknown"
    assert review_check["reason"]["code"] == "REVIEW_EVIDENCE_INVALID"
    assert report["status"] != "verified"


def test_same_id_negative_decision_cannot_preserve_earlier_approval(harness: Harness) -> None:
    changes = approval(review_id=987)
    changes["state"] = "CHANGES_REQUESTED"
    harness.set_reviews([[approval(), changes]])

    report = harness.verify()

    review_check = check(report, "source.review")
    assert review_check["status"] == "unknown"
    assert review_check["reason"]["code"] == "REVIEW_EVIDENCE_INVALID"
    assert report["evidence"]["reviews"] == []
    assert report["status"] != "verified"


@pytest.mark.parametrize("merged_at", [True, 1.0, "2026-11-18T11:00:00", "not-a-date"])
def test_merged_pr_requires_timezone_aware_rfc3339_merged_at(
    harness: Harness, merged_at: object
) -> None:
    pr = pr_object()
    pr["merged_at"] = merged_at
    harness.set_pr(pr)

    report = harness.verify()

    review_check = check(report, "source.review")
    assert review_check["status"] == "failed"
    assert review_check["reason"]["code"] == "REVIEW_POLICY_FAILED"
    assert report["status"] != "verified"


@pytest.mark.parametrize("mutation", ["environment_shape", "environment_entry", "missing_user", "bool_user_id"])
def test_malformed_required_approved_record_is_unknown(harness: Harness, mutation: str) -> None:
    records = approvals_object()
    if mutation == "environment_shape":
        records[0]["environments"] = {"name": "production"}
    elif mutation == "environment_entry":
        records[0]["environments"] = [{"name": "production"}, None]
    elif mutation == "missing_user":
        del records[0]["user"]
    else:
        records[0]["user"]["id"] = True
    harness.set_approvals(records)

    report = harness.verify()

    approval_check = check(report, "release.approval")
    assert approval_check["status"] == "unknown"
    assert approval_check["reason"]["code"] == "RELEASE_APPROVAL_EVIDENCE_INVALID"
    assert report["status"] != "verified"
