from __future__ import annotations

import copy

import pytest

from conftest import COMMIT, DIGEST, base_input
from release_proof_mcp.request import INPUT_SCHEMA, ValidationError, VerificationRequest, parse_artifact


def test_signer_workflow_and_cosign_defaults() -> None:
    value = base_input()
    for key in ("signer_workflow", "signer_digest", "expected_run", "require_cosign_signature"):
        value.pop(key)

    request = VerificationRequest.from_dict(value)

    assert request.signer_workflow == "acme/shop/.github/workflows/release.yml"
    assert request.signer_digest is None
    assert request.expected_run is None
    assert request.require_cosign_signature is False


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


@pytest.mark.parametrize("location", ["input", "review", "release", "expected_run"])
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
    payload = base_input()
    payload[section][field] = value

    with pytest.raises(ValidationError):
        VerificationRequest.from_dict(payload)


def test_input_schema_is_closed_at_every_object_level() -> None:
    assert INPUT_SCHEMA["additionalProperties"] is False
    assert INPUT_SCHEMA["properties"]["review"]["additionalProperties"] is False
    assert INPUT_SCHEMA["properties"]["release"]["additionalProperties"] is False
    assert INPUT_SCHEMA["properties"]["expected_run"]["additionalProperties"] is False
    assert "container" in INPUT_SCHEMA["required"]


def test_non_object_input_is_rejected() -> None:
    with pytest.raises(ValidationError):
        VerificationRequest.from_dict([])
