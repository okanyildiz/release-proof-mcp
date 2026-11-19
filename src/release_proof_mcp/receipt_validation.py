from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime, timezone
from functools import lru_cache
from importlib.resources import files
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError

from .report import CHECK_ORDER
from .request import ISSUER, PREDICATE_TYPE, ValidationError, VerificationRequest
from .verifier import GH_MINIMUM, INDEX_MEDIA_TYPES, MANIFEST_MEDIA_TYPES

SCHEMA_VERSION = "release-deployment-proof/v2"
VERIFIER_FIELDS = frozenset({"name", "version", "instance_id", "build_digest"})
_RFC3339 = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})"
)
_REPOSITORY_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*"
_PINNED_GHCR_ARTIFACT = re.compile(
    rf"(ghcr\.io/{_REPOSITORY_COMPONENT}(?:/{_REPOSITORY_COMPONENT})*)"
    r"@sha256:([0-9a-f]{64})"
)


class ReceiptValidationError(ValueError):
    pass


def canonical_json_bytes(value: Any) -> bytes:
    try:
        _validate_json_value(value)
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise ValueError("Value must be finite, UTF-8 encodable JSON.") from error


@lru_cache(maxsize=1)
def receipt_validator() -> Draft202012Validator:
    schema = json.loads(
        files("release_proof_mcp")
        .joinpath("schemas/receipt-v2.json")
        .read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def subject_fields() -> frozenset[str]:
    return frozenset(receipt_validator().schema["$defs"]["subject"]["required"])


def validate_receipt(receipt: Any, *, require_proof: bool = False) -> None:
    if not isinstance(receipt, dict):
        raise ReceiptValidationError("Receipt must be a JSON object.")
    try:
        canonical_json_bytes(receipt)
        receipt_validator().validate(receipt)
    except (ValueError, JsonSchemaValidationError, RecursionError) as error:
        raise ReceiptValidationError("Receipt does not satisfy the v2 schema.") from error
    if require_proof and "proof" not in receipt:
        raise ReceiptValidationError("Signed receipt proof is required.")
    try:
        _validate_semantics(receipt)
    except ReceiptValidationError:
        raise
    except (KeyError, TypeError, ValueError, RecursionError) as error:
        raise ReceiptValidationError("Receipt semantic validation failed.") from error


def pinned_ghcr_artifact(value: Any) -> tuple[str, str] | None:
    if not isinstance(value, str):
        return None
    match = _PINNED_GHCR_ARTIFACT.fullmatch(value)
    return (match.group(1), match.group(2)) if match is not None else None


def parse_rfc3339(value: Any) -> datetime:
    if not isinstance(value, str) or not _RFC3339.fullmatch(value):
        raise ValueError("Timestamp must be RFC3339.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError, OverflowError) as error:
        raise ValueError("Timestamp must be RFC3339.") from error
    if parsed.tzinfo is None:
        raise ValueError("Timestamp must have a timezone.")
    return parsed.astimezone(timezone.utc)


def _validate_semantics(receipt: dict[str, Any]) -> None:
    try:
        parse_rfc3339(receipt["started_at"])
        parse_rfc3339(receipt["completed_at"])
        effective_policy = receipt["effective_policy"]
        descriptor = receipt["policy_descriptor"]
        calculated_hash = (
            "sha256:"
            + hashlib.sha256(canonical_json_bytes(effective_policy)).hexdigest()
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ReceiptValidationError("Receipt timestamps or policy are invalid.") from error
    if (
        receipt["policy_hash"] != calculated_hash
        or descriptor.get("hash") != calculated_hash
        or descriptor.get("profile") != effective_policy.get("profile")
        or descriptor.get("version") != effective_policy.get("version")
    ):
        raise ReceiptValidationError("Receipt policy integrity does not match effective_policy.")
    require_cosign = effective_policy.get("require_cosign_signature")
    if not isinstance(require_cosign, bool):
        raise ReceiptValidationError("Effective policy Cosign requirement must be boolean.")

    checks = receipt["checks"]
    names = [check["name"] for check in checks]
    if len(names) != len(set(names)):
        raise ReceiptValidationError("Receipt check names must be unique.")
    applicable = [
        name
        for name in CHECK_ORDER
        if name != "signature.cosign" or require_cosign
    ]
    if names != applicable:
        raise ReceiptValidationError("Receipt checks do not exactly cover applicable core checks.")
    expected_reasons = [
        {"check": check["name"], **check["reason"]}
        for check in checks
        if check["reason"] is not None
    ]
    expected_missing = [
        {"check": check["name"], "code": check["reason"]["code"]}
        for check in checks
        if check["status"] == "unknown"
    ]
    if not _json_equal(receipt["reasons"], expected_reasons):
        raise ReceiptValidationError("Receipt reasons do not exactly reflect checks.")
    if not _json_equal(receipt["missing_coverage"], expected_missing):
        raise ReceiptValidationError("Receipt missing coverage does not exactly reflect checks.")
    statuses = [check["status"] for check in checks]
    aggregated = (
        "failed"
        if "failed" in statuses
        else "unknown"
        if "unknown" in statuses
        else "verified"
    )
    if receipt["status"] != aggregated:
        raise ReceiptValidationError("Receipt status does not match check aggregation.")
    if receipt["status"] == "verified":
        if (
            any(status != "verified" for status in statuses)
            or receipt["reasons"]
            or receipt["missing_coverage"]
        ):
            raise ReceiptValidationError("Verified receipt contains incomplete or failed checks.")
        if pinned_ghcr_artifact(receipt["subject"]["pinned_artifact"]) is None:
            raise ReceiptValidationError("Verified receipt requires a pinned GHCR sha256 artifact.")
        _validate_verified_evidence(receipt)

    if "proof" in receipt:
        proof = receipt["proof"]
        metadata = receipt["proof_metadata"]
        names = ("issuer", "keyid", "algorithm", "signed_at")
        if any(proof[name] != metadata[name] for name in names):
            raise ReceiptValidationError("Outer proof metadata differs from signed metadata.")
        if proof["envelope"]["signatures"][0]["keyid"] != proof["keyid"]:
            raise ReceiptValidationError("DSSE signature key ID differs from proof key ID.")
        parse_rfc3339(proof["signed_at"])


_VERIFIED_EVIDENCE_REFERENCES = {
    "source.commit": ("commit",),
    "source.review": ("pull_request", "reviews"),
    "registry.resolution": ("registry",),
    "attestation.verification": ("attestation", "certificate"),
    "workflow.run": ("workflow_run",),
    "release.approval": ("release_approvals",),
    "signature.cosign": ("cosign",),
    "runtime.rollout": ("pods",),
    "runtime.digest_match": ("pods",),
    "runtime.stable_observation": ("pods",),
}
_RUN_INVOCATION_URI = re.compile(
    r"^https://github\.com/([^/]+/[^/]+)/actions/runs/([1-9][0-9]*)/attempts/([1-9][0-9]*)$"
)
_REGISTRY_IMAGE_ID = re.compile(
    r"^(?:docker-pullable://)?[^\s/@]+(?:/[^\s/@]+)+@(?P<digest>sha256:[0-9a-f]{64})$"
)
_COMMIT = re.compile(r"[0-9a-f]{40}")


def _validate_verified_evidence(receipt: dict[str, Any]) -> None:
    evidence = receipt["evidence"]
    for check in receipt["checks"]:
        expected = _VERIFIED_EVIDENCE_REFERENCES[check["name"]]
        if check["evidence"] != list(expected):
            raise ReceiptValidationError("Verified check evidence references are invalid.")
    for name in (
        "commit",
        "pull_request",
        "registry",
        "attestation",
        "certificate",
        "workflow_run",
    ):
        if not isinstance(evidence[name], dict) or not evidence[name]:
            raise ReceiptValidationError("Verified receipt contains empty object evidence.")
    for name in ("reviews", "release_approvals", "pods"):
        if not isinstance(evidence[name], list) or not evidence[name]:
            raise ReceiptValidationError("Verified receipt contains empty array evidence.")
    if receipt["effective_policy"]["require_cosign_signature"]:
        cosign = evidence["cosign"]
        if (
            not isinstance(cosign, dict)
            or cosign.get("verified") is not True
            or not _positive_integer(cosign.get("result_count"))
        ):
            raise ReceiptValidationError("Verified Cosign evidence is missing or invalid.")

    producer_request = _request_from_receipt(receipt)
    _validate_artifact_and_source(receipt, producer_request)
    _validate_certificate_and_tools(receipt, producer_request)
    _validate_review(receipt)
    _validate_workflow_and_release(receipt)
    _validate_pods(receipt)


def _request_from_receipt(receipt: dict[str, Any]) -> VerificationRequest:
    subject = receipt["subject"]
    policy = receipt["effective_policy"]
    value = {
        "repo": subject["repo"],
        "expected_commit": subject["expected_commit"],
        "artifact": subject["artifact_input"],
        "workflow": subject["workflow"],
        "source_ref": subject["source_ref"],
        "signer_workflow": policy["signer_workflow"],
        "kube_context": subject["kube_context"],
        "namespace": subject["namespace"],
        "deployment": subject["deployment"],
        "container": subject["container"],
    }
    if policy["signer_digest"] is not None:
        value["signer_digest"] = policy["signer_digest"]
    if subject["expected_run"] is not None:
        value["expected_run"] = subject["expected_run"]
    if receipt["consumer_nonce"] is not None:
        value["consumer_nonce"] = receipt["consumer_nonce"]
    try:
        return VerificationRequest.from_dict(value)
    except (ValidationError, TypeError, ValueError) as error:
        raise ReceiptValidationError("Verified subject does not satisfy producer input rules.") from error


def _validate_artifact_and_source(
    receipt: dict[str, Any], producer_request: VerificationRequest
) -> None:
    subject = receipt["subject"]
    evidence = receipt["evidence"]
    registry = evidence["registry"]
    artifact = pinned_ghcr_artifact(subject["pinned_artifact"])
    if artifact is None:
        raise ReceiptValidationError("Verified receipt has no valid pinned artifact.")
    digest = f"sha256:{artifact[1]}"
    if (
        producer_request.artifact.repository != artifact[0]
        or (
            producer_request.artifact.is_digest
            and producer_request.artifact.reference != digest
        )
    ):
        raise ReceiptValidationError("Verified artifact input differs from the pinned artifact.")
    if (
        subject["pinned_artifact"] != registry.get("pinned_artifact")
        or registry.get("digest") != digest
        or evidence["attestation"].get("subject_digest") != digest
    ):
        raise ReceiptValidationError("Verified artifact digests are inconsistent.")
    if registry.get("media_type") not in INDEX_MEDIA_TYPES | MANIFEST_MEDIA_TYPES:
        raise ReceiptValidationError("Verified registry media type is not recognized.")
    if evidence["commit"].get("sha") != subject["expected_commit"]:
        raise ReceiptValidationError("Verified commit evidence differs from the subject.")

    certificate = evidence["certificate"]
    if (
        certificate.get("source_repository_uri") != producer_request.source_repository_uri
        or certificate.get("source_repository_digest") != subject["expected_commit"]
        or certificate.get("source_repository_ref") != subject["source_ref"]
    ):
        raise ReceiptValidationError("Verified certificate source identity differs from the subject.")
    for subject_name, certificate_name in (
        ("source_repository_id", "source_repository_identifier"),
        ("source_repository_owner_id", "source_repository_owner_identifier"),
    ):
        subject_id = subject[subject_name]
        certificate_id = certificate.get(certificate_name)
        if (subject_id is not None or certificate_id is not None) and subject_id != certificate_id:
            raise ReceiptValidationError("Verified repository identifiers are inconsistent.")


def _validate_certificate_and_tools(
    receipt: dict[str, Any], producer_request: VerificationRequest
) -> None:
    certificate = receipt["evidence"]["certificate"]
    if (
        certificate.get("issuer") != ISSUER
        or certificate.get("runner_environment") != "github-hosted"
    ):
        raise ReceiptValidationError("Verified certificate issuer or runner is invalid.")
    if receipt["evidence"]["attestation"].get("predicate_type") != PREDICATE_TYPE:
        raise ReceiptValidationError("Verified attestation predicate type is invalid.")
    identities = (
        certificate.get("subject_alternative_name"),
        certificate.get("build_signer_uri"),
    )
    string_identities = [value for value in identities if isinstance(value, str)]
    if not string_identities or any(
        not producer_request.certificate_identity_matches(value)
        for value in string_identities
    ):
        raise ReceiptValidationError("Verified certificate signer identity is not approved.")
    if (
        producer_request.signer_digest is not None
        and certificate.get("build_signer_digest") != producer_request.signer_digest
    ):
        raise ReceiptValidationError("Verified certificate signer digest differs from policy.")
    gh_version = receipt["tools"]["gh"]
    if not isinstance(gh_version, str) or not re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+", gh_version
    ):
        raise ReceiptValidationError("Verified GH tool version is invalid.")
    if tuple(int(part) for part in gh_version.split(".")) < GH_MINIMUM:
        raise ReceiptValidationError("Verified GH tool version is below the producer minimum.")


def _validate_review(receipt: dict[str, Any]) -> None:
    policy = receipt["effective_policy"]["review"]
    subject = receipt["subject"]
    pull_request = receipt["evidence"]["pull_request"]
    if (
        pull_request.get("number") != policy["pull_request"]
        or pull_request.get("mode") != policy["mode"]
    ):
        raise ReceiptValidationError("Verified pull request differs from effective policy.")
    head_sha = pull_request.get("head_sha")
    if not isinstance(head_sha, str) or not _COMMIT.fullmatch(head_sha):
        raise ReceiptValidationError("Verified pull request has an invalid head commit.")
    if policy["mode"] == "merged_pr":
        if (
            pull_request.get("merge_commit_sha") != subject["expected_commit"]
            or pull_request.get("expected_commit_directly_reviewed") is not False
        ):
            raise ReceiptValidationError("Merged pull request evidence is inconsistent.")
    else:
        if (
            head_sha != subject["expected_commit"]
            or pull_request.get("expected_commit_directly_reviewed") is not True
        ):
            raise ReceiptValidationError("Exact-head pull request evidence is inconsistent.")

    reviews = receipt["evidence"]["reviews"]
    review_ids = [review.get("id") for review in reviews]
    reviewer_ids = [review.get("reviewer_id") for review in reviews]
    if (
        any(review.get("state") != "APPROVED" for review in reviews)
        or any(not _positive_integer(value) for value in review_ids)
        or len(set(review_ids)) != len(review_ids)
        or any(not _positive_integer(value) for value in reviewer_ids)
        or len(set(reviewer_ids)) != len(reviewer_ids)
        or any(value not in policy["allowed_reviewer_ids"] for value in reviewer_ids)
        or len(reviewer_ids) < policy["min_approvals"]
        or any(review.get("commit_id") != head_sha for review in reviews)
    ):
        raise ReceiptValidationError("Verified review evidence does not satisfy effective policy.")


def _validate_workflow_and_release(receipt: dict[str, Any]) -> None:
    subject = receipt["subject"]
    policy = receipt["effective_policy"]["release"]
    run = receipt["evidence"]["workflow_run"]
    if (
        run.get("head_sha") != subject["expected_commit"]
        or run.get("event") != policy["event"]
        or run.get("conclusion") != "success"
    ):
        raise ReceiptValidationError("Verified workflow run differs from subject or policy.")
    run_id = run.get("id")
    attempt = run.get("attempt")
    if not _positive_integer(run_id) or attempt != 1 or isinstance(attempt, bool):
        raise ReceiptValidationError("Verified workflow run identity is invalid.")
    uri = receipt["evidence"]["certificate"].get("run_invocation_uri")
    match = _RUN_INVOCATION_URI.fullmatch(uri) if isinstance(uri, str) else None
    if (
        match is None
        or match.group(1) != subject["repo"]
        or int(match.group(2)) != run_id
        or int(match.group(3)) != attempt
    ):
        raise ReceiptValidationError("Certificate and workflow run identities are inconsistent.")
    expected_run = subject["expected_run"]
    if expected_run is not None and (
        expected_run.get("id") != run_id or expected_run.get("attempt") != 1
    ):
        raise ReceiptValidationError("Workflow run differs from the expected run.")

    approvals = receipt["evidence"]["release_approvals"]
    approver_ids = [approval.get("approver_id") for approval in approvals]
    if (
        any(approval.get("state") != "approved" for approval in approvals)
        or any(approval.get("environment") != policy["environment"] for approval in approvals)
        or any(not _positive_integer(value) for value in approver_ids)
        or len(set(approver_ids)) != len(approver_ids)
        or any(value not in policy["required_approver_ids"] for value in approver_ids)
    ):
        raise ReceiptValidationError("Verified release approvals do not satisfy effective policy.")


def _validate_pods(receipt: dict[str, Any]) -> None:
    subject = receipt["subject"]
    registry_digest = receipt["evidence"]["registry"]["digest"]
    pods = receipt["evidence"]["pods"]
    for pod in pods:
        if (
            pod.get("container") != subject["container"]
            or pod.get("ready") is not True
            or pod.get("phase") != "Running"
            or pod.get("deletion_timestamp") is not None
            or any(
                not _nonempty_string(pod.get(name))
                for name in ("uid", "container_id", "revision", "started_at")
            )
        ):
            raise ReceiptValidationError("Verified pod identity or running state is invalid.")
        image_id = pod.get("image_id")
        match = _REGISTRY_IMAGE_ID.fullmatch(image_id) if isinstance(image_id, str) else None
        if match is None:
            raise ReceiptValidationError("Verified pod image ID is not registry-comparable.")
        relation = pod.get("digest_relation")
        if relation == "direct":
            if match.group("digest") != registry_digest:
                raise ReceiptValidationError("Direct pod digest differs from registry evidence.")
        elif relation != "index_child":
            raise ReceiptValidationError("Verified pod digest relation is invalid.")
    pod_uids = [pod["uid"] for pod in pods]
    revisions = [pod["revision"] for pod in pods]
    if len(set(pod_uids)) != len(pod_uids) or len(set(revisions)) != 1:
        raise ReceiptValidationError("Verified pods require unique UIDs and one revision.")


def _positive_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _json_equal(first: Any, second: Any) -> bool:
    return canonical_json_bytes(first) == canonical_json_bytes(second)


def _validate_json_value(value: Any) -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Non-finite number.")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_value(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("JSON object keys must be strings.")
            _validate_json_value(item)
        return
    raise ValueError("Value is not JSON serializable.")
