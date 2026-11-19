from __future__ import annotations

import copy
import json
from importlib.metadata import version
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError

from conftest import COMMIT, DIGEST, Harness, attestation_result, run_object
from release_proof_mcp.verifier import ReleaseVerifier

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads(
    (ROOT / "src/release_proof_mcp/schemas/receipt-v2.json").read_text(encoding="utf-8")
)
GOLDEN = json.loads(
    (ROOT / "tests/fixtures/receipt-v2.golden.json").read_text(encoding="utf-8")
)
NONCE = "Ab09_-abcdefghijklmnopqrst"
BUILD_DIGEST = f"sha256:{'d' * 64}"


@pytest.fixture(scope="module")
def receipt_validator() -> Draft202012Validator:
    Draft202012Validator.check_schema(SCHEMA)
    return Draft202012Validator(SCHEMA, format_checker=FormatChecker())


def test_sanitized_golden_receipt_validates(receipt_validator: Draft202012Validator) -> None:
    receipt_validator.validate(GOLDEN)
    assert "proof" not in GOLDEN


def test_v2_receipt_contains_enterprise_metadata_and_full_subject(
    harness: Harness, receipt_validator: Draft202012Validator
) -> None:
    harness.request["consumer_nonce"] = NONCE
    run = run_object()
    run["repository"]["owner"] = {"id": 556}
    harness.set_run(run)
    harness.set_current_run(run)
    harness.set_attestation([attestation_result(sourceRepositoryOwnerIdentifier="556")])

    receipt = harness.verify(
        verifier_instance_id="verifier-prod-01",
        build_digest=BUILD_DIGEST,
    )

    receipt_validator.validate(receipt)
    assert receipt["status"] == "verified"
    assert receipt["schema_version"] == "release-deployment-proof/v2"
    assert UUID(receipt["receipt_id"]).version == 4
    assert receipt["consumer_nonce"] == NONCE
    assert receipt["verifier"] == {
        "name": "release-proof-mcp",
        "version": version("release-proof-mcp"),
        "instance_id": "verifier-prod-01",
        "build_digest": BUILD_DIGEST,
    }
    assert receipt["subject"] == {
        "repo": "acme/shop",
        "expected_commit": COMMIT,
        "artifact_input": "ghcr.io/acme/shop:v1.4.0",
        "pinned_artifact": f"ghcr.io/acme/shop@{DIGEST}",
        "source_ref": "refs/heads/main",
        "workflow": ".github/workflows/release.yml",
        "expected_run": {"id": 123456789, "attempt": 1},
        "source_repository_id": "555",
        "source_repository_owner_id": "556",
        "kube_context": "production",
        "namespace": "production",
        "deployment": "shop-api",
        "container": "api",
    }
    assert receipt["policy_descriptor"] == {
        "profile": "production",
        "version": "test-v1",
        "hash": receipt["policy_hash"],
    }
    assert "proof" not in receipt


def test_legacy_request_and_missing_certificate_have_explicit_nulls(
    harness: Harness, receipt_validator: Draft202012Validator
) -> None:
    harness.request.pop("expected_run")
    harness.set_attestation([], returncode=1, stderr="no attestations found")

    receipt = harness.verify()

    receipt_validator.validate(receipt)
    assert receipt["consumer_nonce"] is None
    assert receipt["verifier"]["instance_id"] is None
    assert receipt["verifier"]["build_digest"] is None
    assert receipt["subject"]["expected_run"] is None
    assert receipt["subject"]["source_repository_id"] is None
    assert receipt["subject"]["source_repository_owner_id"] is None
    assert receipt["evidence"]["certificate"] is None


def test_receipt_ids_are_unique_uuid4_values_across_verifications(
    harness: Harness, receipt_validator: Draft202012Validator
) -> None:
    first = harness.verify()
    second = harness.verify()

    receipt_validator.validate(first)
    receipt_validator.validate(second)
    assert UUID(first["receipt_id"]).version == 4
    assert UUID(second["receipt_id"]).version == 4
    assert first["receipt_id"] != second["receipt_id"]


@pytest.mark.parametrize(
    "options",
    [
        {"verifier_instance_id": ""},
        {"verifier_instance_id": "x" * 129},
        {"verifier_instance_id": " leading"},
        {"verifier_instance_id": "line\nbreak"},
        {"verifier_instance_id": 123},
        {"build_digest": f"sha256:{'A' * 64}"},
        {"build_digest": "sha256:abc"},
        {"build_digest": 123},
    ],
)
def test_verifier_metadata_is_conservatively_validated(options: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        ReleaseVerifier(**options)


@pytest.mark.parametrize(
    "field", ["receipt_id", "consumer_nonce", "verifier", "policy_descriptor"]
)
def test_schema_requires_new_top_level_fields(
    field: str, receipt_validator: Draft202012Validator
) -> None:
    receipt = copy.deepcopy(GOLDEN)
    del receipt[field]

    with pytest.raises(JsonSchemaValidationError):
        receipt_validator.validate(receipt)


@pytest.mark.parametrize(
    "field",
    [
        "source_ref",
        "workflow",
        "expected_run",
        "source_repository_id",
        "source_repository_owner_id",
    ],
)
def test_schema_requires_new_subject_fields(
    field: str, receipt_validator: Draft202012Validator
) -> None:
    receipt = copy.deepcopy(GOLDEN)
    del receipt["subject"][field]

    with pytest.raises(JsonSchemaValidationError):
        receipt_validator.validate(receipt)


@pytest.mark.parametrize("status", ["failed", "unknown"])
def test_schema_preserves_nonverified_reason_semantics(
    status: str, receipt_validator: Draft202012Validator
) -> None:
    receipt = copy.deepcopy(GOLDEN)
    check = receipt["checks"][0]
    check["status"] = status

    with pytest.raises(JsonSchemaValidationError):
        receipt_validator.validate(receipt)

    check["reason"] = {"code": "TEST_REASON", "message": "Synthetic contract test."}
    receipt_validator.validate(receipt)


def test_schema_requires_strict_proof_and_authenticated_metadata(
    receipt_validator: Draft202012Validator,
) -> None:
    receipt = copy.deepcopy(GOLDEN)
    receipt["proof"] = {
        "issuer": "https://issuer.example",
        "keyid": "key-1",
        "algorithm": "ed25519",
        "signed_at": "2026-11-18T12:00:00Z",
        "envelope": {
            "payload": "cGF5bG9hZA==",
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [{"sig": "c2lnbmF0dXJl", "keyid": "key-1"}],
        },
    }
    receipt["proof_metadata"] = {
        key: receipt["proof"][key]
        for key in ("issuer", "keyid", "algorithm", "signed_at")
    }
    receipt_validator.validate(receipt)

    without_metadata = copy.deepcopy(receipt)
    del without_metadata["proof_metadata"]
    with pytest.raises(JsonSchemaValidationError):
        receipt_validator.validate(without_metadata)
    without_proof = copy.deepcopy(receipt)
    del without_proof["proof"]
    with pytest.raises(JsonSchemaValidationError):
        receipt_validator.validate(without_proof)

    receipt["proof"] = None
    with pytest.raises(JsonSchemaValidationError):
        receipt_validator.validate(receipt)
