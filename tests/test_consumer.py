from __future__ import annotations

import base64
import copy
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from release_proof_mcp.consumer import (
    StrictJSONError,
    strict_json_loads,
    verify_receipt,
)
from release_proof_mcp.signing import PAYLOAD_TYPE, canonical_json_bytes, dsse_pae, statement_for_receipt
from test_signing import (
    FIXED_NOW,
    ISSUER,
    KEYID,
    NONCE,
    POLICY_HASH,
    PRIVATE_KEY,
    cosign_receipt,
    digest_input_receipt,
    exact_head_receipt,
    index_child_receipt,
    nonverified_receipt,
    resign_unchecked,
    reusable_signer_receipt,
    same_repo_pinned_signer_receipt,
    signed_receipt,
    unsigned_receipt,
)

DECISION_FIELDS = {
    "allow",
    "decision_id",
    "receipt_id",
    "receipt_digest",
    "policy_hash",
    "reason",
    "evaluated_at",
}


def verification_options() -> dict[str, Any]:
    receipt = unsigned_receipt()
    return {
        "trusted_public_keys": {KEYID: PRIVATE_KEY.public_key()},
        "expected_issuer": ISSUER,
        "expected_subject": copy.deepcopy(receipt["subject"]),
        "expected_policy_hash": POLICY_HASH,
        "expected_verifier": copy.deepcopy(receipt["verifier"]),
        "expected_nonce": NONCE,
        "now": FIXED_NOW,
        "max_age_seconds": 300,
    }


def verify(receipt: Any, **overrides: Any) -> dict[str, Any]:
    options = verification_options()
    options.update(overrides)
    return verify_receipt(receipt, **options)


def set_path(receipt: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    target = receipt
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value


def replace_payload_without_resigning(receipt: dict[str, Any]) -> None:
    predicate = {
        key: value for key, value in receipt.items() if key != "proof"
    }
    payload = canonical_json_bytes(statement_for_receipt(predicate))
    receipt["proof"]["envelope"]["payload"] = base64.b64encode(payload).decode("ascii")


def assert_valid_signature(receipt: dict[str, Any]) -> None:
    envelope = receipt["proof"]["envelope"]
    PRIVATE_KEY.public_key().verify(
        base64.b64decode(envelope["signatures"][0]["sig"], validate=True),
        dsse_pae(
            PAYLOAD_TYPE.encode("ascii"),
            base64.b64decode(envelope["payload"], validate=True),
        ),
    )


def test_verified_receipt_allows_with_bounded_decision() -> None:
    receipt = signed_receipt()

    decision = verify(receipt)

    assert decision["allow"] is True
    assert decision["reason"] == "OK"
    assert set(decision) == DECISION_FIELDS
    assert str(uuid.UUID(decision["decision_id"])) == decision["decision_id"]
    assert decision["receipt_id"] == receipt["receipt_id"]
    assert decision["receipt_digest"].startswith("sha256:")
    assert decision["policy_hash"] == POLICY_HASH
    assert decision["evaluated_at"] == "2026-11-18T12:00:00Z"


@pytest.mark.parametrize(
    ("path", "value", "reason"),
    [
        (("status",), "failed", "RECEIPT_INVALID"),
        (("subject", "repo"), "acme/other", "RECEIPT_INVALID"),
        (("policy_hash",), f"sha256:{'2' * 64}", "RECEIPT_INVALID"),
        (("policy_descriptor", "profile"), "other", "RECEIPT_INVALID"),
        (("evidence", "registry", "digest"), f"sha256:{'b' * 64}", "RECEIPT_INVALID"),
        (("consumer_nonce",), "Ab09_-abcdefghijklmnopqrstuv", "PAYLOAD_MISMATCH"),
        (("started_at",), "2026-11-18T11:58:00Z", "PAYLOAD_MISMATCH"),
        (("completed_at",), "2026-11-18T11:59:31Z", "PAYLOAD_MISMATCH"),
        (("verifier", "version"), "other-version", "PAYLOAD_MISMATCH"),
    ],
)
def test_signed_fields_are_bound_to_the_payload(
    path: tuple[str, ...], value: Any, reason: str
) -> None:
    receipt = signed_receipt()
    set_path(receipt, path, value)

    decision = verify(receipt)

    assert decision["allow"] is False
    assert decision["reason"] == reason


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("issuer", "https://issuer.example/attacker-relabel"),
        ("signed_at", "2026-11-18T11:59:59Z"),
    ],
)
def test_outer_proof_metadata_relabeling_is_denied(field: str, value: str) -> None:
    receipt = signed_receipt()
    receipt["proof"][field] = value

    decision = verify(receipt)

    assert decision["allow"] is False
    assert decision["reason"] == "RECEIPT_INVALID"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("issuer", "https://issuer.example/attacker-relabel"),
        ("signed_at", "2026-11-18T11:59:59Z"),
    ],
)
def test_signed_metadata_tampering_fails_signature_verification(field: str, value: str) -> None:
    receipt = signed_receipt()
    receipt["proof_metadata"][field] = value
    receipt["proof"][field] = value
    replace_payload_without_resigning(receipt)
    options = {"expected_issuer": value} if field == "issuer" else {}

    decision = verify(receipt, **options)

    assert decision["allow"] is False
    assert decision["reason"] == "SIGNATURE_INVALID"


def test_signature_tampering_is_denied() -> None:
    receipt = signed_receipt()
    record = receipt["proof"]["envelope"]["signatures"][0]
    signature = bytearray(base64.b64decode(record["sig"]))
    signature[0] ^= 1
    record["sig"] = base64.b64encode(signature).decode("ascii")

    decision = verify(receipt)

    assert decision["allow"] is False
    assert decision["reason"] == "SIGNATURE_INVALID"


def test_unknown_key_and_wrong_public_key_are_denied() -> None:
    unknown = verify(signed_receipt(), trusted_public_keys={})
    wrong_key = Ed25519PrivateKey.from_private_bytes(b"\x99" * 32).public_key()
    wrong = verify(signed_receipt(), trusted_public_keys={KEYID: wrong_key})

    assert unknown["reason"] == "KEY_NOT_TRUSTED"
    assert wrong["reason"] == "SIGNATURE_INVALID"
    assert not unknown["allow"] and not wrong["allow"]


@pytest.mark.parametrize(
    ("override", "reason"),
    [
        ({"expected_issuer": "https://issuer.example/other"}, "ISSUER_MISMATCH"),
        ({"expected_policy_hash": f"sha256:{'2' * 64}"}, "POLICY_MISMATCH"),
        ({"expected_nonce": "Ab09_-abcdefghijklmnopqrstuv"}, "NONCE_MISMATCH"),
    ],
)
def test_caller_expectations_are_enforced(override: dict[str, Any], reason: str) -> None:
    decision = verify(signed_receipt(), **override)

    assert decision["allow"] is False
    assert decision["reason"] == reason


@pytest.mark.parametrize(
    "field",
    [
        "pinned_artifact",
        "expected_commit",
        "expected_run",
        "namespace",
        "deployment",
        "container",
    ],
)
def test_full_subject_expectation_rejects_omitted_artifact_commit_run_and_workload(
    field: str,
) -> None:
    expected = copy.deepcopy(unsigned_receipt()["subject"])
    del expected[field]

    decision = verify(signed_receipt(), expected_subject=expected)

    assert decision["allow"] is False
    assert decision["reason"] == "SUBJECT_EXPECTATION_INVALID"


def test_subject_expectation_requires_exact_values_and_no_extra_fields() -> None:
    wrong = copy.deepcopy(unsigned_receipt()["subject"])
    wrong["expected_commit"] = "f" * 40
    extra = copy.deepcopy(unsigned_receipt()["subject"])
    extra["unexpected"] = "not-in-v2"

    assert verify(signed_receipt(), expected_subject=wrong)["reason"] == "SUBJECT_MISMATCH"
    assert verify(signed_receipt(), expected_subject=extra)["reason"] == "SUBJECT_EXPECTATION_INVALID"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("name", "other-verifier"),
        ("version", "9.9.9"),
        ("instance_id", "other-instance"),
        ("build_digest", f"sha256:{'e' * 64}"),
    ],
)
def test_full_verifier_identity_is_pinned_with_valid_signatures(field: str, value: Any) -> None:
    receipt = signed_receipt()
    receipt["verifier"][field] = value
    receipt = resign_unchecked(receipt)
    assert_valid_signature(receipt)

    decision = verify(receipt)

    assert decision["allow"] is False
    assert decision["reason"] == ("RECEIPT_INVALID" if field == "name" else "VERIFIER_MISMATCH")


@pytest.mark.parametrize("field", ["name", "version", "instance_id", "build_digest"])
def test_verifier_expectation_requires_every_identity_field(field: str) -> None:
    expected = copy.deepcopy(unsigned_receipt()["verifier"])
    del expected[field]

    decision = verify(signed_receipt(), expected_verifier=expected)

    assert decision["allow"] is False
    assert decision["reason"] == "VERIFIER_EXPECTATION_INVALID"


def test_weak_effective_policy_with_valid_trusted_signature_is_denied() -> None:
    receipt = signed_receipt()
    receipt["effective_policy"]["review"]["min_approvals"] = 0
    receipt = resign_unchecked(receipt)
    assert_valid_signature(receipt)

    decision = verify(receipt)

    assert decision["allow"] is False
    assert decision["reason"] == "RECEIPT_INVALID"


@pytest.mark.parametrize("field", ["profile", "version", "hash"])
def test_policy_descriptor_tampering_with_valid_signature_is_denied(field: str) -> None:
    receipt = signed_receipt()
    receipt["policy_descriptor"][field] = (
        f"sha256:{'2' * 64}" if field == "hash" else "other"
    )
    receipt = resign_unchecked(receipt)
    assert_valid_signature(receipt)

    decision = verify(receipt)

    assert decision["allow"] is False
    assert decision["reason"] == "RECEIPT_INVALID"


@pytest.mark.parametrize("status", ["failed", "unknown"])
def test_failed_and_unknown_receipts_are_denied_even_when_validly_signed(status: str) -> None:
    receipt = signed_receipt(nonverified_receipt(status))
    assert_valid_signature(receipt)

    decision = verify(receipt)

    assert decision["allow"] is False
    assert decision["reason"] == "STATUS_NOT_VERIFIED"


def test_check_aggregation_and_coverage_semantics_are_enforced_with_valid_signature() -> None:
    duplicate = signed_receipt()
    duplicate["checks"].append(copy.deepcopy(duplicate["checks"][0]))
    missing_reason = signed_receipt(nonverified_receipt("unknown"))
    missing_reason["reasons"] = []

    for receipt in (duplicate, missing_reason):
        receipt = resign_unchecked(receipt)
        assert_valid_signature(receipt)
        decision = verify(receipt)
        assert decision["allow"] is False
        assert decision["reason"] == "RECEIPT_INVALID"


def test_stale_future_and_inverted_observation_windows_are_denied() -> None:
    stale = verify(
        signed_receipt(),
        now=FIXED_NOW + timedelta(seconds=60),
        max_age_seconds=1,
    )
    future = verify(
        signed_receipt(
            unsigned_receipt(
                started_at="2026-11-18T12:00:01Z",
                completed_at="2026-11-18T12:00:02Z",
            )
        )
    )
    inverted = verify(
        signed_receipt(
            unsigned_receipt(
                started_at="2026-11-18T12:00:02Z",
                completed_at="2026-11-18T12:00:01Z",
            )
        )
    )

    assert stale["reason"] == "RECEIPT_STALE"
    assert future["reason"] == "OBSERVATION_TIME_FUTURE"
    assert inverted["reason"] == "OBSERVATION_WINDOW_INVERTED"
    assert not any(item["allow"] for item in (stale, future, inverted))


def test_replayed_receipt_must_match_current_consumer_nonce() -> None:
    receipt = signed_receipt()

    replay = verify(receipt, expected_nonce="Ab09_-abcdefghijklmnopqrstuv")
    missing = verify(receipt, expected_nonce=None)

    assert replay["reason"] == "NONCE_MISMATCH"
    assert missing["reason"] == "NONCE_REQUIRED"
    assert not replay["allow"] and not missing["allow"]


def test_unknown_schema_proof_and_algorithm_are_denied() -> None:
    unknown_schema = signed_receipt()
    unknown_schema["schema_version"] = "release-deployment-proof/v3"
    no_proof = unsigned_receipt()
    no_metadata = signed_receipt()
    del no_metadata["proof_metadata"]
    wrong_algorithm = signed_receipt()
    wrong_algorithm["proof"]["algorithm"] = "rsa"
    malformed_signatures = signed_receipt()
    malformed_signatures["proof"]["envelope"]["signatures"] = []

    assert verify(unknown_schema)["reason"] == "SCHEMA_VERSION_UNSUPPORTED"
    assert verify(no_proof)["reason"] == "PROOF_MISSING"
    assert verify(no_metadata)["reason"] == "PROOF_METADATA_MISSING"
    assert verify(wrong_algorithm)["reason"] == "ALGORITHM_UNSUPPORTED"
    assert verify(malformed_signatures)["reason"] == "RECEIPT_INVALID"


def test_noncanonical_duplicate_and_mismatched_payloads_are_denied() -> None:
    noncanonical = signed_receipt()
    envelope = noncanonical["proof"]["envelope"]
    statement = json.loads(base64.b64decode(envelope["payload"]))
    envelope["payload"] = base64.b64encode(json.dumps(statement).encode()).decode()

    duplicate = signed_receipt()
    duplicate["proof"]["envelope"]["payload"] = base64.b64encode(
        b'{"_type":"first","_type":"second"}'
    ).decode()

    mismatched = signed_receipt()
    other = unsigned_receipt()
    other["summary"] = "A different but otherwise valid signed summary."
    mismatched["proof"] = signed_receipt(other)["proof"]

    assert verify(noncanonical)["reason"] == "PAYLOAD_NONCANONICAL"
    assert verify(duplicate)["reason"] == "PAYLOAD_MALFORMED"
    assert verify(mismatched)["reason"] == "PAYLOAD_MISMATCH"


def test_future_signed_time_and_invalid_observation_time_are_denied() -> None:
    future_proof = signed_receipt()
    future_proof["proof_metadata"]["signed_at"] = "2026-11-18T12:00:01Z"
    future_proof["proof"]["signed_at"] = "2026-11-18T12:00:01Z"
    future_proof = resign_unchecked(future_proof)
    invalid_window = signed_receipt()
    invalid_window["started_at"] = "not-a-time"
    invalid_window = resign_unchecked(invalid_window)

    assert verify(future_proof)["reason"] == "PROOF_TIME_FUTURE"
    assert verify(invalid_window)["reason"] == "RECEIPT_INVALID"


@pytest.mark.parametrize(
    "raw",
    [
        b'{"key":1,"key":2}',
        b'{"outer":{"key":1,"key":2}}',
        b"\xff",
        b'{"number":NaN}',
        b'{"number":Infinity}',
        b'{"number":-Infinity}',
        b'{"number":1e999}',
        b'{"key":1} trailing',
    ],
)
def test_strict_json_rejects_duplicates_invalid_utf8_and_nonfinite_numbers(raw: bytes) -> None:
    with pytest.raises(StrictJSONError):
        strict_json_loads(raw)


def test_malformed_api_input_returns_denial_instead_of_raising() -> None:
    for value in (None, [], {"schema_version": "release-deployment-proof/v2"}):
        decision = verify(value)
        assert decision["allow"] is False
        assert set(decision) == DECISION_FIELDS


def test_denial_does_not_echo_huge_invalid_identifiers() -> None:
    receipt = signed_receipt()
    receipt["receipt_id"] = "x" * (2 * 1024 * 1024 + 1)
    receipt["policy_hash"] = "sha256:" + "z" * (2 * 1024 * 1024 + 1)

    decision = verify(receipt)
    encoded = json.dumps(decision, separators=(",", ":"))

    assert decision["allow"] is False
    assert decision["receipt_id"] is None
    assert decision["policy_hash"] is None
    assert len(encoded) < 1024


def test_consumer_uses_supplied_now_for_freshness_and_evaluated_at() -> None:
    now = datetime(2026, 11, 18, 14, 2, 0, tzinfo=timezone(timedelta(hours=2)))

    decision = verify(signed_receipt(), now=now, max_age_seconds=60)

    assert decision["evaluated_at"] == "2026-11-18T12:02:00Z"
    assert decision["reason"] == "RECEIPT_STALE"


@pytest.mark.parametrize(
    "builder",
    [
        exact_head_receipt,
        cosign_receipt,
        index_child_receipt,
        same_repo_pinned_signer_receipt,
        reusable_signer_receipt,
        digest_input_receipt,
    ],
)
def test_supported_verified_evidence_variants_are_allowed(builder: Any) -> None:
    receipt = signed_receipt(builder())

    decision = verify(
        receipt,
        expected_policy_hash=receipt["policy_hash"],
        expected_subject=receipt["subject"],
    )

    assert decision["allow"] is True
    assert decision["reason"] == "OK"


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("commit", {}),
        ("pull_request", {}),
        ("registry", {}),
        ("attestation", {}),
        ("certificate", {}),
        ("workflow_run", {}),
        ("reviews", []),
        ("release_approvals", []),
        ("pods", []),
        ("cosign", {}),
    ],
)
def test_blank_evidence_with_valid_signature_is_denied(name: str, value: Any) -> None:
    receipt = signed_receipt(cosign_receipt() if name == "cosign" else None)
    receipt["evidence"][name] = value
    receipt = resign_unchecked(receipt)
    assert_valid_signature(receipt)

    decision = verify(receipt, expected_policy_hash=receipt["policy_hash"])

    assert decision["allow"] is False
    assert decision["reason"] == "RECEIPT_INVALID"


@pytest.mark.parametrize(
    "check_name",
    [
        "source.commit",
        "source.review",
        "registry.resolution",
        "attestation.verification",
        "workflow.run",
        "release.approval",
        "runtime.rollout",
        "runtime.digest_match",
        "runtime.stable_observation",
        "signature.cosign",
    ],
)
def test_blank_evidence_reference_with_valid_signature_is_denied(check_name: str) -> None:
    receipt = signed_receipt(cosign_receipt() if check_name == "signature.cosign" else None)
    check = next(item for item in receipt["checks"] if item["name"] == check_name)
    check["evidence"] = []
    receipt = resign_unchecked(receipt)
    assert_valid_signature(receipt)

    decision = verify(receipt, expected_policy_hash=receipt["policy_hash"])

    assert decision["allow"] is False
    assert decision["reason"] == "RECEIPT_INVALID"


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("subject", "pinned_artifact"), f"ghcr.io/acme/shop@sha256:{'b' * 64}"),
        (("evidence", "commit", "sha"), "f" * 40),
        (("evidence", "certificate", "run_invocation_uri"), "https://github.com/acme/shop/actions/runs/987654321/attempts/1"),
        (("evidence", "pull_request", "number"), 124),
        (("evidence", "reviews", "reviewer_id"), 9999),
        (("evidence", "release_approvals", "environment"), "staging"),
        (("evidence", "pods", "ready"), False),
        (("evidence", "pods", "image_id"), f"ghcr.io/acme/shop@sha256:{'b' * 64}"),
        (("subject", "source_repository_id"), "999"),
        (("evidence", "workflow_run", "event"), "pull_request"),
        (("evidence", "certificate", "issuer"), "https://issuer.example/not-github"),
        (("evidence", "certificate", "runner_environment"), "self-hosted"),
        (("evidence", "certificate", "build_signer_digest"), "f" * 40),
        (
            ("evidence", "certificate", "subject_alternative_name"),
            "https://github.com/acme/shop/.github/workflows/release.yml.evil@refs/heads/main",
        ),
        (
            ("evidence", "certificate", "build_signer_uri"),
            "https://github.com/acme/other/.github/workflows/release.yml@refs/heads/main",
        ),
        (("evidence", "attestation", "predicate_type"), None),
        (("tools", "gh"), "2.101.0"),
        (("subject", "artifact_input"), f"ghcr.io/acme/shop@sha256:{'b' * 64}"),
        (("evidence", "registry", "media_type"), "application/vnd.example.unknown+json"),
        (("evidence", "pods", "started_at"), None),
    ],
)
def test_internal_evidence_inconsistencies_with_valid_signature_are_denied(
    path: tuple[str, ...], value: Any
) -> None:
    receipt = signed_receipt()
    target: Any = receipt
    for key in path[:-1]:
        if key in {"reviews", "release_approvals", "pods"}:
            target = target[key][0]
        else:
            target = target[key]
    target[path[-1]] = value
    receipt = resign_unchecked(receipt)
    assert_valid_signature(receipt)

    decision = verify(receipt)

    assert decision["allow"] is False
    assert decision["reason"] == "RECEIPT_INVALID"


@pytest.mark.parametrize("mutation", ["zero", "duplicate"])
def test_review_ids_must_be_positive_and_unique(mutation: str) -> None:
    receipt = signed_receipt()
    if mutation == "zero":
        receipt["evidence"]["reviews"][0]["id"] = 0
    else:
        second = copy.deepcopy(receipt["evidence"]["reviews"][0])
        second["reviewer_id"] = 1002
        receipt["evidence"]["reviews"].append(second)
    receipt = resign_unchecked(receipt)
    assert_valid_signature(receipt)

    decision = verify(receipt)

    assert decision["allow"] is False
    assert decision["reason"] == "RECEIPT_INVALID"


@pytest.mark.parametrize(
    "cosign_evidence",
    [
        {"verified": False, "result_count": 1},
        {"verified": True, "result_count": 0},
    ],
)
def test_invalid_cosign_evidence_with_valid_signature_is_denied(
    cosign_evidence: dict[str, Any]
) -> None:
    receipt = signed_receipt(cosign_receipt())
    receipt["evidence"]["cosign"] = cosign_evidence
    receipt = resign_unchecked(receipt)
    assert_valid_signature(receipt)

    decision = verify(receipt, expected_policy_hash=receipt["policy_hash"])

    assert decision["allow"] is False
    assert decision["reason"] == "RECEIPT_INVALID"


def test_both_signer_identities_null_with_valid_signature_is_denied() -> None:
    receipt = signed_receipt()
    receipt["evidence"]["certificate"]["subject_alternative_name"] = None
    receipt["evidence"]["certificate"]["build_signer_uri"] = None
    receipt = resign_unchecked(receipt)
    assert_valid_signature(receipt)

    decision = verify(receipt)

    assert decision["allow"] is False
    assert decision["reason"] == "RECEIPT_INVALID"


def test_duplicate_retained_pod_uid_with_valid_signature_is_denied() -> None:
    receipt = signed_receipt()
    second = copy.deepcopy(receipt["evidence"]["pods"][0])
    second["name"] = "shop-api-second"
    receipt["evidence"]["pods"].append(second)
    receipt = resign_unchecked(receipt)
    assert_valid_signature(receipt)

    decision = verify(receipt)

    assert decision["allow"] is False
    assert decision["reason"] == "RECEIPT_INVALID"


def test_different_retained_pod_revision_with_valid_signature_is_denied() -> None:
    receipt = signed_receipt()
    second = copy.deepcopy(receipt["evidence"]["pods"][0])
    second["uid"] = "pod-uid-second"
    second["name"] = "shop-api-second"
    second["revision"] = "4"
    receipt["evidence"]["pods"].append(second)
    receipt = resign_unchecked(receipt)
    assert_valid_signature(receipt)

    decision = verify(receipt)

    assert decision["allow"] is False
    assert decision["reason"] == "RECEIPT_INVALID"
