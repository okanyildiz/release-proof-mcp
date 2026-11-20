from __future__ import annotations

import json

import pytest

from conftest import (
    COMMIT,
    DIGEST,
    Harness,
    attestation_argv,
    attestation_result,
    certificate,
    check,
)
from release_proof_mcp.runner import CommandTimeout


def test_gh_version_floor_rejected_before_attestation_verification(harness: Harness) -> None:
    harness.runner.route(["gh", "--version"], "gh version 2.101.0 (2025-01-01)")

    report = harness.verify()

    assert check(report, "attestation.verification")["status"] == "unknown"
    assert check(report, "attestation.verification")["reason"]["code"] == "GH_VERSION_UNSUPPORTED"
    assert not any(call[:3] == ("gh", "attestation", "verify") for call in harness.runner.calls)
    assert report["status"] == "unknown"


def test_missing_attestation_is_authoritative_failure(harness: Harness) -> None:
    harness.set_attestation([], returncode=1, stderr="no attestations found for subject")

    report = harness.verify()

    assert check(report, "attestation.verification")["status"] == "failed"
    assert check(report, "attestation.verification")["reason"]["code"] == "ATTESTATION_MISSING"


def test_sbom_or_custom_evidence_does_not_replace_slsa_provenance(harness: Harness) -> None:
    result = attestation_result()
    result["verificationResult"]["statement"]["predicateType"] = "https://spdx.dev/Document"
    harness.set_attestation([result])

    report = harness.verify()

    assert check(report, "attestation.verification")["reason"]["code"] == "PROVENANCE_MISSING"
    assert check(report, "attestation.verification")["status"] == "failed"


@pytest.mark.parametrize("output", ["[]", "{}", "not-json", ""])
def test_successful_verifier_requires_nonempty_json_array(harness: Harness, output: str) -> None:
    harness.runner.route(attestation_argv(harness.request, DIGEST), output)

    report = harness.verify()

    assert check(report, "attestation.verification")["status"] == "unknown"
    assert check(report, "attestation.verification")["reason"]["code"] == "VERIFIER_OUTPUT_INVALID"
    assert report["status"] == "unknown"
    assert {item["check"] for item in report["missing_coverage"]} >= {
        "attestation.verification",
        "workflow.run",
        "release.approval",
    }


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"sourceRepositoryDigest": "f" * 40}, "SOURCE_COMMIT_MISMATCH"),
        ({"sourceRepositoryRef": "refs/heads/Main"}, "SOURCE_REF_MISMATCH"),
        ({"sourceRepositoryURI": "https://github.com/acme/other"}, "SIGNER_MISMATCH"),
        (
            {
                "subjectAlternativeName": "https://github.com/acme/shop/.github/workflows/release.yml.evil@refs/heads/main"
            },
            "SIGNER_MISMATCH",
        ),
        ({"buildSignerDigest": "e" * 40}, "SIGNER_DIGEST_MISMATCH"),
        ({"runnerEnvironment": "self-hosted"}, "RUNNER_ENVIRONMENT_MISMATCH"),
        ({"issuer": "https://issuer.example"}, "SIGNER_MISMATCH"),
    ],
)
def test_certificate_policy_mismatches(
    harness: Harness, overrides: dict[str, str], code: str
) -> None:
    harness.set_attestation([attestation_result(**overrides)])

    report = harness.verify()

    assert check(report, "attestation.verification")["status"] == "failed"
    assert check(report, "attestation.verification")["reason"]["code"] == code
    assert check(report, "workflow.run")["status"] == "unknown"


def test_signer_identity_prefix_never_counts_as_exact_match(harness: Harness) -> None:
    harness.request.pop("signer_digest")
    harness.policy["signer_digest"] = None
    prefix_identity = "https://github.com/acme/shop/.github/workflows/release.yml@refs/heads/main-extra"
    harness.set_attestation([attestation_result(subjectAlternativeName=prefix_identity)])

    report = harness.verify()

    assert check(report, "attestation.verification")["reason"]["code"] == "SIGNER_MISMATCH"


def test_source_ref_comparison_is_case_sensitive(harness: Harness) -> None:
    harness.set_attestation([attestation_result(sourceRepositoryRef="refs/heads/MAIN")])

    report = harness.verify()

    reason = check(report, "attestation.verification")["reason"]
    assert reason["code"] == "SOURCE_REF_MISMATCH"
    assert reason["expected"] == "refs/heads/main"
    assert reason["actual"] == "refs/heads/MAIN"


def test_build_signer_uri_is_accepted_as_certificate_identity(harness: Harness) -> None:
    identity = "https://github.com/acme/shop/.github/workflows/release.yml@refs/heads/main"
    harness.set_attestation([
        attestation_result(subjectAlternativeName=None, buildSignerURI=identity)
    ])

    report = harness.verify()

    assert report["status"] == "verified"


def test_in_toto_subject_must_cover_exact_artifact_digest(harness: Harness) -> None:
    result = attestation_result(f"sha256:{'a' * 64}")

    harness.set_attestation([result])
    report = harness.verify()

    assert check(report, "attestation.verification")["status"] == "failed"
    assert check(report, "attestation.verification")["reason"]["code"] == "ATTESTED_DIGEST_MISMATCH"


@pytest.mark.parametrize(
    ("stderr", "code", "status"),
    [
        ("invalid signature while verifying DSSE", "SIGNATURE_INVALID", "failed"),
        ("invalid timestamp from timestamp authority", "SIGNING_TIME_INVALID", "failed"),
        ("certificate has expired and no signing time is available", "SIGNING_TIME_UNVERIFIED", "unknown"),
        ("unable to fetch trust root from TUF", "TRUST_ROOT_UNAVAILABLE", "unknown"),
        ("dns failure reaching service", "TRUST_ROOT_UNAVAILABLE", "unknown"),
        ("HTTP 403: forbidden", "ATTESTATION_ACCESS_DENIED", "unknown"),
        ("opaque verification rejection", "ATTESTATION_VERIFICATION_FAILED", "failed"),
    ],
)
def test_verifier_failure_classification(
    harness: Harness, stderr: str, code: str, status: str
) -> None:
    harness.set_attestation(None, returncode=1, stderr=stderr)

    report = harness.verify()

    assert check(report, "attestation.verification")["status"] == status
    assert check(report, "attestation.verification")["reason"]["code"] == code


def test_attestation_timeout_is_unknown_not_absence(harness: Harness) -> None:
    harness.runner.route(
        attestation_argv(harness.request, DIGEST),
        error=CommandTimeout("timeout"),
    )

    report = harness.verify()

    assert check(report, "attestation.verification")["status"] == "unknown"
    assert check(report, "attestation.verification")["reason"]["code"] == "ATTESTATION_UNAVAILABLE"


def test_attestation_search_at_limit_without_decisive_result_is_unknown(harness: Harness) -> None:
    harness.set_attestation([attestation_result(sourceRepositoryDigest="f" * 40) for _ in range(100)])

    report = harness.verify()

    assert check(report, "attestation.verification")["status"] == "unknown"
    assert check(report, "attestation.verification")["reason"]["code"] == "ATTESTATION_SEARCH_TRUNCATED"


def test_one_acceptable_attestation_is_sufficient(harness: Harness) -> None:
    malformed = {"verificationResult": None}
    wrong = attestation_result(sourceRepositoryDigest="f" * 40)
    valid = attestation_result()
    harness.set_attestation([malformed, wrong, valid])

    report = harness.verify()

    assert report["status"] == "verified"
    assert report["evidence"]["attestation"]["subject_digest"] == DIGEST


def test_bundle_tlog_entries_are_used_when_legacy_field_is_absent(harness: Harness) -> None:
    result = attestation_result()
    del result["verificationResult"]["transparencyLogEntries"]
    harness.set_attestation([result])

    report = harness.verify()

    assert report["status"] == "verified"
    assert report["evidence"]["attestation"]["transparency_log_ids"] == ["9876"]


def test_verifier_argv_uses_digest_never_tag_and_all_policy_flags(harness: Harness) -> None:
    report = harness.verify()

    assert report["status"] == "verified"
    argv = next(call for call in harness.runner.calls if call[:3] == ("gh", "attestation", "verify"))
    assert argv[3] == f"oci://ghcr.io/acme/shop@{DIGEST}"
    assert ":v1.4.0" not in argv[3]
    assert "--owner" not in argv
    assert "--bundle-from-oci" not in argv
    assert "--deny-self-hosted-runners" in argv
    assert argv[argv.index("--limit") + 1] == "100"
    assert argv[argv.index("--source-ref") + 1] == "refs/heads/main"


@pytest.mark.parametrize(
    "field", ["sourceRepositoryIdentifier", "sourceRepositoryOwnerIdentifier"]
)
@pytest.mark.parametrize("value", [None, True, 0, -1, "0555", "not-numeric", 1.5])
def test_malformed_certificate_repository_ids_are_unknown(
    harness: Harness, field: str, value: object
) -> None:
    harness.set_attestation([attestation_result(**{field: value})])

    report = harness.verify()

    attestation_check = check(report, "attestation.verification")
    assert attestation_check["status"] == "unknown"
    assert attestation_check["reason"]["code"] == "ATTESTATION_EVIDENCE_INVALID"
    assert report["status"] != "verified"


@pytest.mark.parametrize(
    "field", ["sourceRepositoryIdentifier", "sourceRepositoryOwnerIdentifier"]
)
def test_malformed_certificate_id_is_not_hidden_when_run_counterpart_is_absent(
    harness: Harness, field: str
) -> None:
    from conftest import run_object

    harness.set_attestation([attestation_result(**{field: {"id": "555"}})])
    run = run_object()
    if field == "sourceRepositoryIdentifier":
        del run["repository"]["id"]
    harness.set_run(run)

    report = harness.verify()

    assert check(report, "attestation.verification")["status"] == "unknown"
    assert check(report, "attestation.verification")["reason"]["code"] == "ATTESTATION_EVIDENCE_INVALID"
    assert report["status"] != "verified"


def test_positive_integer_certificate_repository_id_is_valid(harness: Harness) -> None:
    harness.set_attestation([attestation_result(sourceRepositoryIdentifier=555)])

    report = harness.verify()

    assert report["status"] == "verified"
