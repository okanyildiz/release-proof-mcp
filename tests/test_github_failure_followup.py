from __future__ import annotations

import pytest

from conftest import COMMIT, RUN_ID, Harness, check
from release_proof_mcp.verifier import _http_status
from test_registry_runtime import cosign_argv


@pytest.mark.parametrize(
    ("stderr", "expected_code"),
    [
        ("gh: Unauthorized (HTTP 401)", "GITHUB_ACCESS_DENIED"),
        ("gh: Resource not accessible by integration (HTTP 403)", "GITHUB_ACCESS_DENIED"),
        ("gh: API rate limit exceeded (HTTP 403)", "GITHUB_UNAVAILABLE"),
        ("gh: Rate limited (HTTP 429)", "GITHUB_UNAVAILABLE"),
        ("gh: Server error (HTTP 503)", "GITHUB_UNAVAILABLE"),
    ],
)
def test_probe_failure_preserves_reason_and_skips_attestation(
    harness: Harness, stderr: str, expected_code: str
) -> None:
    harness.runner.route(
        ["gh", "api", "repos/acme/shop"],
        "",
        stderr=stderr,
        returncode=1,
    )
    harness.set_attestation([], returncode=1, stderr="no attestations found")

    report = harness.verify()

    assert report["status"] == "unknown"
    for name in (
        "source.commit",
        "source.review",
        "attestation.verification",
        "workflow.run",
        "release.approval",
    ):
        result = check(report, name)
        assert result["status"] == "unknown"
        assert result["reason"]["code"] == expected_code
    assert not any(call[:2] == ("gh", "attestation") for call in harness.runner.calls)


def test_repository_probe_name_is_case_insensitive(harness: Harness) -> None:
    harness.runner.route_json(
        ["gh", "api", "repos/acme/shop"],
        {"full_name": "ACME/SHOP", "id": 555, "owner": {"id": 556}},
    )

    assert harness.verify()["status"] == "verified"


def test_plain_text_rate_limit_on_commit_is_unavailable(harness: Harness) -> None:
    harness.runner.route(
        ["gh", "api", f"repos/acme/shop/commits/{COMMIT}"],
        "",
        stderr="HTTP 403: API rate limit exceeded",
        returncode=1,
    )

    result = check(harness.verify(), "source.commit")

    assert result["status"] == "unknown"
    assert result["reason"]["code"] == "GITHUB_UNAVAILABLE"


def test_plain_text_rate_limit_on_attestation_is_unavailable(harness: Harness) -> None:
    harness.set_attestation(
        [],
        returncode=1,
        stderr="HTTP 403: API rate limit exceeded",
    )

    result = check(harness.verify(), "attestation.verification")

    assert result["status"] == "unknown"
    assert result["reason"]["code"] == "ATTESTATION_UNAVAILABLE"


def test_v12_403_is_not_http_or_access_denied_evidence(harness: Harness) -> None:
    assert _http_status("gh: V12 403") is None
    harness.set_attestation([], returncode=1, stderr="gh: V12 403")

    result = check(harness.verify(), "attestation.verification")

    assert result["status"] == "failed"
    assert result["reason"]["code"] == "ATTESTATION_VERIFICATION_FAILED"


def test_current_run_404_remains_unknown(harness: Harness) -> None:
    harness.runner.route(
        ["gh", "api", f"repos/acme/shop/actions/runs/{RUN_ID}"],
        "",
        stderr="gh: Not Found (HTTP 404)",
        returncode=1,
    )

    result = check(harness.verify(), "release.approval")

    assert result["status"] == "unknown"
    assert result["reason"]["code"] == "RUN_ATTEMPT_UNAVAILABLE"


@pytest.mark.parametrize(
    "stderr",
    [
        "HTTP 403: API rate limit exceeded",
        "gh: service unavailable (HTTP 503)",
    ],
)
def test_cosign_rate_limit_and_server_errors_are_unavailable(
    harness: Harness, stderr: str
) -> None:
    harness.policy["require_cosign_signature"] = True
    harness.runner.route(["cosign", "version"], "v2.5.0")
    harness.runner.route(cosign_argv(harness), returncode=1, stderr=stderr)

    result = check(harness.verify(), "signature.cosign")

    assert result["status"] == "unknown"
    assert result["reason"]["code"] == "COSIGN_UNAVAILABLE"


@pytest.mark.parametrize("status", [500, 502, 503])
def test_plain_status_attestation_errors_are_unavailable(
    harness: Harness, status: int
) -> None:
    harness.set_attestation([], returncode=1, stderr=f"gh: HTTP {status}")

    result = check(harness.verify(), "attestation.verification")

    assert result["status"] == "unknown"
    assert result["reason"]["code"] == "ATTESTATION_UNAVAILABLE"


@pytest.mark.parametrize("status", [500, 502, 503])
def test_plain_status_cosign_errors_are_unavailable(
    harness: Harness, status: int
) -> None:
    harness.policy["require_cosign_signature"] = True
    harness.runner.route(["cosign", "version"], "v2.5.0")
    harness.runner.route(
        cosign_argv(harness), returncode=1, stderr=f"gh: HTTP {status}"
    )

    result = check(harness.verify(), "signature.cosign")

    assert result["status"] == "unknown"
    assert result["reason"]["code"] == "COSIGN_UNAVAILABLE"


@pytest.mark.parametrize("status", [404, 422])
def test_plain_status_absence_codes_are_conclusive_after_probe(
    harness: Harness, status: int
) -> None:
    harness.runner.route(
        ["gh", "api", f"repos/acme/shop/commits/{COMMIT}"],
        "",
        stderr=f"gh: HTTP {status}",
        returncode=1,
    )

    result = check(harness.verify(), "source.commit")

    assert result["status"] == "failed"
    assert result["reason"]["code"] == "COMMIT_NOT_FOUND"
