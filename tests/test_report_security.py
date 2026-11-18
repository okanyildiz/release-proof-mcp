from __future__ import annotations

import hashlib
import io
import json
import threading

from conftest import Harness, approvals_object, base_policy, check, pod_object
from release_proof_mcp.report import CHECK_ORDER
from release_proof_mcp.runner import _BoundedReader, redact


def test_failed_takes_precedence_over_unknown(harness: Harness) -> None:
    harness.set_attestation([], returncode=1, stderr="no attestations found")
    harness.set_runtime(pods={"items": [pod_object(f"sha256:{'a' * 64}")]})

    report = harness.verify()

    assert report["status"] == "failed"
    assert any(item["status"] == "unknown" for item in report["checks"])


def test_unknown_when_no_check_conclusively_failed(harness: Harness) -> None:
    harness.set_runtime(pods={"items": [pod_object(f"sha256:{'a' * 64}")]})

    report = harness.verify()

    assert report["status"] == "unknown"
    assert all(item["status"] != "failed" for item in report["checks"])
    assert report["missing_coverage"] == [
        {"check": "runtime.digest_match", "code": "IMAGE_ID_NOT_REGISTRY_COMPARABLE"}
    ]


def test_stable_report_schema_and_check_order(harness: Harness) -> None:
    report = harness.verify()

    assert list(report) == [
        "schema_version",
        "status",
        "summary",
        "started_at",
        "completed_at",
        "subject",
        "effective_policy",
        "policy_hash",
        "checks",
        "reasons",
        "missing_coverage",
        "evidence",
        "evidence_truncation",
        "tools",
        "limitations",
    ]
    assert [item["name"] for item in report["checks"]] == [
        name for name in CHECK_ORDER if name != "signature.cosign"
    ]
    for item in report["checks"]:
        assert list(item) == ["name", "status", "reason", "evidence"]
    canonical_policy = json.dumps(report["effective_policy"], sort_keys=True, separators=(",", ":")).encode()
    assert report["policy_hash"] == f"sha256:{hashlib.sha256(canonical_policy).hexdigest()}"
    assert report["effective_policy"]["review"] == base_policy()["review"]
    json.dumps(report, allow_nan=False)


def test_repeated_verification_has_deterministic_json(harness: Harness) -> None:
    first = harness.verify()
    second = harness.verify()

    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_nonverified_reasons_are_aggregated_with_check_names(harness: Harness) -> None:
    harness.set_attestation([], returncode=1, stderr="no attestations found")

    report = harness.verify()

    assert report["reasons"]
    assert all("check" in reason and "code" in reason and "message" in reason for reason in report["reasons"])
    assert report["reasons"][0]["check"] == "attestation.verification"


def test_custom_predicate_and_internal_fields_are_not_disclosed(harness: Harness) -> None:
    report = harness.verify()
    encoded = json.dumps(report)

    assert "untrusted" not in encoded
    assert "resolvedDependencies" not in encoded
    assert "not copied" not in encoded


def test_signed_is_not_described_as_secure(harness: Harness) -> None:
    report = harness.verify()

    assert any("not that the artifact is secure" in item for item in report["limitations"])
    assert "vulnerability-free" not in report["summary"].lower()


def test_approval_comments_are_omitted_even_with_unlabeled_credentials(harness: Harness) -> None:
    github_token = "ghp_" + "a" * 36
    records = approvals_object()
    records[0]["comment"] = f"token=supersecret {github_token} GH_TOKEN=env-secret " + "x" * 1000
    harness.set_approvals(records)

    report = harness.verify()
    encoded = json.dumps(report)

    approval = report["evidence"]["release_approvals"][0]
    assert "comment" not in approval
    for secret in ("supersecret", github_token, "env-secret"):
        assert secret not in encoded


def test_receipt_evidence_arrays_are_capped(harness: Harness) -> None:
    harness.set_approvals(approvals_object() * 101)

    report = harness.verify()

    assert report["status"] == "verified"
    assert len(report["evidence"]["release_approvals"]) == 100
    assert report["evidence_truncation"]["release_approvals"] == {"retained": 100, "omitted": 1}


def test_overall_deadline_fails_closed_before_more_commands(harness: Harness) -> None:
    now = [0.0]

    def monotonic() -> float:
        value = now[0]
        now[0] += 1.0
        return value

    report = harness.verify(deadline_seconds=0.5, monotonic=monotonic)

    assert report["status"] == "unknown"
    assert check(report, "source.commit")["reason"]["code"] == "VERIFICATION_DEADLINE_EXCEEDED"
    assert harness.runner.calls == []


def test_cancellation_fails_closed_before_more_commands(harness: Harness) -> None:
    cancelled = threading.Event()
    cancelled.set()

    report = harness.verify(cancel_event=cancelled)

    assert report["status"] == "unknown"
    assert check(report, "source.commit")["reason"]["code"] == "VERIFICATION_CANCELLED"
    assert harness.runner.calls == []


def test_progress_is_reported_for_verification_stages(harness: Harness) -> None:
    stages: list[str] = []

    report = harness.verify(progress=stages.append)

    assert report["status"] == "verified"
    assert stages == [
        "tools.discovery",
        "source.commit",
        "source.review",
        "runtime.rollout",
        "registry.resolution",
        "attestation.verification",
        "workflow.run",
        "release.approval",
        "runtime.digest_match",
        "runtime.stable_observation",
    ]


def test_credential_redaction_covers_environment_headers_and_github_tokens() -> None:
    github_token = "ghp_" + "a" * 36
    fine_grained = "github_pat_" + "b" * 30
    text = (
        f"GH_TOKEN=abc123 Bearer my-secret Authorization: top-secret password=hunter2 "
        f"{github_token} {fine_grained}"
    )

    result = redact(text, {"GH_TOKEN": "abc123"})

    for secret in ("abc123", "my-secret", "top-secret", "hunter2", github_token, fine_grained):
        assert secret not in result


def test_bounded_reader_accepts_limit_and_rejects_overflow() -> None:
    exact = _BoundedReader(io.BytesIO(b"1234"), 4)
    exact.read()
    overflow = _BoundedReader(io.BytesIO(b"12345"), 4)
    overflow.read()

    assert exact.data == b"1234"
    assert exact.truncated is False
    assert overflow.data == b"1234"
    assert overflow.truncated is True


def test_all_external_commands_use_argument_vectors(harness: Harness) -> None:
    report = harness.verify()

    assert report["status"] == "verified"
    assert harness.runner.calls
    assert all(isinstance(call, tuple) and all(isinstance(part, str) for part in call) for call in harness.runner.calls)
    assert not any(any(part in {"sh", "bash"} and index == 0 for index, part in enumerate(call)) for call in harness.runner.calls)
