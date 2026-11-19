from __future__ import annotations

import pytest

from conftest import COMMIT, DIGEST, base_input, base_policy
from release_proof_mcp.policy import TrustedPolicy
from release_proof_mcp.request import INPUT_SCHEMA, ValidationError, VerificationRequest, parse_artifact


def test_signer_workflow_defaults() -> None:
    value = base_input()
    for key in ("signer_workflow", "signer_digest", "expected_run"):
        value.pop(key)

    request = VerificationRequest.from_dict(value)

    assert request.signer_workflow == "acme/shop/.github/workflows/release.yml"
    assert request.signer_digest is None
    assert request.expected_run is None
    assert request.consumer_nonce is None


@pytest.mark.parametrize("nonce", ["A" * 22, "Ab09_-" + "a" * 16, "_" * 128])
def test_consumer_nonce_accepts_unpadded_base64url(nonce: str) -> None:
    value = base_input()
    value["consumer_nonce"] = nonce

    request = VerificationRequest.from_dict(value)

    assert request.consumer_nonce == nonce


@pytest.mark.parametrize(
    "nonce",
    ["", "A" * 21, "A" * 129, "A" * 21 + "=", "A" * 21 + "+", "A" * 21 + "\n", None, 123],
)
def test_consumer_nonce_rejects_invalid_values(nonce: object) -> None:
    value = base_input()
    value["consumer_nonce"] = nonce

    with pytest.raises(ValidationError, match="consumer_nonce"):
        VerificationRequest.from_dict(value)


def test_signer_defaults_can_come_from_trusted_policy() -> None:
    value = base_input()
    value.pop("signer_workflow")
    value.pop("signer_digest")
    policy = base_policy()
    signer_workflow = "acme/builders/.github/workflows/reusable.yml"

    request = VerificationRequest.from_dict(
        value,
        signer_workflow_default=signer_workflow,
        signer_digest_default=policy["signer_digest"],
    )

    assert request.signer_workflow == signer_workflow
    assert request.signer_digest == policy["signer_digest"]


def test_explicit_null_signer_digest_is_rejected_like_the_schema() -> None:
    value = base_input()
    value["signer_digest"] = None

    with pytest.raises(ValidationError, match="signer_digest"):
        VerificationRequest.from_dict(value, signer_digest_default=None)


def test_digest_artifact_is_accepted_and_normalized() -> None:
    value = base_input()
    value["artifact"] = f"ghcr.io/acme/shop@{DIGEST}"

    request = VerificationRequest.from_dict(value)

    assert request.artifact.is_digest is True
    assert request.artifact.path == "acme/shop"
    assert request.pinned_artifact(DIGEST) == value["artifact"]


def test_github_host_prefixed_signer_workflow() -> None:
    value = base_input()
    value["signer_workflow"] = "github.com/acme/shop/.github/workflows/release.yml"

    request = VerificationRequest.from_dict(value)

    assert request.certificate_identity == (
        "https://github.com/acme/shop/.github/workflows/release.yml@refs/heads/main"
    )


def test_external_reusable_builder_requires_signer_digest() -> None:
    value = base_input()
    value["signer_workflow"] = "acme/builders/.github/workflows/reusable.yml"
    value.pop("signer_digest")

    with pytest.raises(ValidationError, match="signer_digest is required"):
        VerificationRequest.from_dict(value)


def test_rerun_attempt_is_rejected_before_verification() -> None:
    value = base_input()
    value["expected_run"]["attempt"] = 2

    with pytest.raises(ValidationError, match="not attempt-bound"):
        VerificationRequest.from_dict(value)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("repo", "acme/shop;rm"),
        ("repo", "acme"),
        ("expected_commit", COMMIT[:-1]),
        ("expected_commit", COMMIT.upper()),
        ("artifact", "ghcr.io/acme/shop"),
        ("artifact", "docker.io/acme/shop:latest"),
        ("artifact", "ghcr.io/Acme/shop:latest"),
        ("artifact", "ghcr.io/acme/shop:latest --help"),
        ("artifact", f"ghcr.io/acme/shop@{DIGEST};x"),
        ("workflow", "release.yml"),
        ("workflow", ".github/workflows/release.yml --help"),
        ("source_ref", "main"),
        ("source_ref", "refs/heads/main --help"),
        ("source_ref", "refs/heads/main..other"),
        ("signer_workflow", "evil.com/acme/shop/.github/workflows/release.yml"),
        ("signer_digest", "abc"),
        ("policy_profile", "../weak"),
        ("namespace", "--all-namespaces"),
        ("deployment", "--help"),
        ("container", "API"),
        ("kube_context", " production"),
    ],
)
def test_invalid_or_argument_injection_fields_are_rejected(field: str, value: str) -> None:
    payload = base_input()
    payload[field] = value

    with pytest.raises(ValidationError):
        VerificationRequest.from_dict(payload)


@pytest.mark.parametrize("container", ["", "-x", "api;rm", "api sidecar"])
def test_container_must_be_explicit_safe_name(container: str) -> None:
    payload = base_input()
    payload["container"] = container

    with pytest.raises(ValidationError):
        VerificationRequest.from_dict(payload)


def test_missing_container_is_rejected() -> None:
    payload = base_input()
    del payload["container"]

    with pytest.raises(ValidationError):
        VerificationRequest.from_dict(payload)


@pytest.mark.parametrize("field", ["review", "release", "require_cosign_signature", "policy_profile"])
def test_caller_cannot_supply_select_or_weaken_policy(field: str) -> None:
    payload = base_input()
    payload[field] = base_policy().get(field, "production" if field == "policy_profile" else False)

    with pytest.raises(ValidationError, match="Unknown input field"):
        VerificationRequest.from_dict(payload)


@pytest.mark.parametrize("location", ["input", "expected_run"])
def test_unknown_fields_are_rejected(location: str) -> None:
    payload = base_input()
    if location == "input":
        payload["unexpected"] = True
    else:
        payload[location]["unexpected"] = True

    with pytest.raises(ValidationError):
        VerificationRequest.from_dict(payload)


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("review", "allowed_reviewer_ids", ["mutable-login"]),
        ("release", "required_approver_ids", [True]),
        ("review", "allowed_reviewer_ids", [1001, 1001]),
        ("review", "min_approvals", 0),
        ("review", "require_non_author", "true"),
        ("release", "prevent_self_approval", 1),
        ("expected_run", "id", True),
        ("expected_run", "attempt", 0),
    ],
)
def test_nested_schema_types_are_strict(section: str, field: str, value: object) -> None:
    if section == "expected_run":
        payload = base_input()
        payload[section][field] = value
        with pytest.raises(ValidationError):
            VerificationRequest.from_dict(payload)
    else:
        policy = base_policy()
        policy[section][field] = value
        with pytest.raises(ValueError):
            TrustedPolicy.from_dict("production", policy)


def test_input_schema_is_closed_and_policy_is_not_model_visible() -> None:
    assert INPUT_SCHEMA["additionalProperties"] is False
    assert INPUT_SCHEMA["properties"]["expected_run"]["additionalProperties"] is False
    assert "container" in INPUT_SCHEMA["required"]
    assert not {"review", "release", "require_cosign_signature", "policy_profile"} & set(INPUT_SCHEMA["properties"])


def test_non_object_input_is_rejected() -> None:
    with pytest.raises(ValidationError):
        VerificationRequest.from_dict([])
