from __future__ import annotations

from conftest import COMMIT, RUN_ID, Harness, check
from release_proof_mcp.verifier import _network_error


def test_nonexistent_commit_is_a_conclusive_failure(harness: Harness) -> None:
    harness.runner.route(
        ["gh", "api", f"repos/acme/shop/commits/{COMMIT}"],
        "",
        stderr=f"gh: No commit found for SHA: {COMMIT} (HTTP 422)",
        returncode=1,
    )

    commit = check(harness.verify(), "source.commit")

    assert (commit["status"], commit["reason"]["code"]) == (
        "failed",
        "COMMIT_NOT_FOUND",
    )


def test_invisible_repository_is_unknown_and_stops_commit_lookup(harness: Harness) -> None:
    harness.runner.route(
        ["gh", "api", "repos/acme/shop"],
        "",
        stderr="gh: Not Found (HTTP 404)",
        returncode=1,
    )
    harness.set_attestation([], returncode=1, stderr="no attestations found")

    report = harness.verify()

    assert report["status"] == "unknown"
    for name in ("source.commit", "source.review", "workflow.run", "release.approval"):
        result = check(report, name)
        assert result["status"] == "unknown"
        assert result["reason"]["code"] == "REPOSITORY_NOT_VISIBLE"
    assert ("gh", "api", f"repos/acme/shop/commits/{COMMIT}") not in harness.runner.calls
    assert not any(call[:2] == ("gh", "attestation") for call in harness.runner.calls)


def test_repository_permission_denied_is_unknown(harness: Harness) -> None:
    harness.runner.route(
        ["gh", "api", "repos/acme/shop"],
        "",
        stderr="gh: Resource not accessible by integration (HTTP 403)",
        returncode=1,
    )

    report = harness.verify()

    commit = check(report, "source.commit")
    assert commit["status"] == "unknown"
    assert commit["reason"]["code"] == "GITHUB_ACCESS_DENIED"
    assert ("gh", "api", f"repos/acme/shop/commits/{COMMIT}") not in harness.runner.calls


def test_pull_request_404_is_conclusive_after_visibility_probe(harness: Harness) -> None:
    harness.runner.route(
        ["gh", "api", "repos/acme/shop/pulls/123"],
        "",
        stderr="gh: Not Found (HTTP 404)",
        returncode=1,
    )

    review = check(harness.verify(), "source.review")

    assert review["status"] == "failed"
    assert review["reason"]["code"] == "REVIEW_POLICY_FAILED"


def test_run_attempt_404_is_conclusive_after_visibility_probe(harness: Harness) -> None:
    harness.runner.route(
        ["gh", "api", f"repos/acme/shop/actions/runs/{RUN_ID}/attempts/1"],
        "",
        stderr="gh: Not Found (HTTP 404)",
        returncode=1,
    )

    run = check(harness.verify(), "workflow.run")

    assert run["status"] == "failed"
    assert run["reason"]["code"] == "WORKFLOW_RUN_POLICY_FAILED"


def test_approvals_404_is_conclusive_after_visibility_probe(harness: Harness) -> None:
    harness.runner.route(
        ["gh", "api", f"repos/acme/shop/actions/runs/{RUN_ID}/approvals"],
        "",
        stderr="gh: Not Found (HTTP 404)",
        returncode=1,
    )

    approval = check(harness.verify(), "release.approval")

    assert approval["status"] == "failed"
    assert approval["reason"]["code"] == "RELEASE_APPROVAL_MISSING"


def test_rate_limited_403_is_unavailable_not_access_denied(harness: Harness) -> None:
    harness.runner.route(
        ["gh", "api", f"repos/acme/shop/commits/{COMMIT}"],
        "",
        stderr="gh: API rate limit exceeded for user ID 1001. (HTTP 403)",
        returncode=1,
    )

    commit = check(harness.verify(), "source.commit")

    assert commit["status"] == "unknown"
    assert commit["reason"]["code"] == "GITHUB_UNAVAILABLE"


def test_server_error_is_unavailable(harness: Harness) -> None:
    harness.runner.route(
        ["gh", "api", f"repos/acme/shop/commits/{COMMIT}"],
        "",
        stderr="gh: Server error (HTTP 502)",
        returncode=1,
    )

    commit = check(harness.verify(), "source.commit")

    assert commit["status"] == "unknown"
    assert commit["reason"]["code"] == "GITHUB_UNAVAILABLE"


def test_sha_containing_404_does_not_override_http_status(harness: Harness) -> None:
    sha = COMMIT[:10] + "404" + COMMIT[13:]
    harness.request["expected_commit"] = sha
    harness.runner.route(
        ["gh", "api", f"repos/acme/shop/commits/{sha}"],
        "",
        stderr=f"gh: No commit found for SHA: {sha} (HTTP 500)",
        returncode=1,
    )
    harness.set_attestation([])

    commit = check(harness.verify(), "source.commit")

    assert commit["status"] == "unknown"
    assert commit["reason"]["code"] == "GITHUB_UNAVAILABLE"


def test_repository_name_does_not_trigger_network_heuristic() -> None:
    assert not _network_error("request failed for acme/network")
    assert _network_error("network timeout while connecting")


def test_repository_name_does_not_trigger_tuf_heuristic(harness: Harness) -> None:
    harness.set_attestation(
        [],
        returncode=1,
        stderr="verification rejected for acme/tuf",
    )

    result = check(harness.verify(), "attestation.verification")

    assert result["status"] == "failed"
    assert result["reason"]["code"] == "ATTESTATION_VERIFICATION_FAILED"
