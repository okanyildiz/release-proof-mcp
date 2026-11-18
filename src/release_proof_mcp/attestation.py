from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .report import Reason
from .request import ISSUER, PREDICATE_TYPE, SHA256_RE, VerificationRequest

RUN_URI_RE = re.compile(r"^https://github\.com/([^/]+/[^/]+)/actions/runs/([0-9]+)/attempts/([1-9][0-9]*)$")


class AttestationError(ValueError):
    def __init__(self, reason: Reason) -> None:
        super().__init__(reason.message)
        self.reason = reason


def select_attestation(
    value: Any,
    request: VerificationRequest,
    expected_digest: str,
) -> tuple[dict[str, Any], dict[str, Any], int, int]:
    if not isinstance(value, list) or not value:
        raise AttestationError(
            Reason(
                "VERIFIER_OUTPUT_INVALID",
                "The verifier exited successfully but did not return a nonempty JSON array.",
            )
        )
    errors: list[AttestationError] = []
    for result in value:
        try:
            certificate, attestation, run_id, attempt = validate_attestation(
                result, request, expected_digest
            )
            return certificate, attestation, run_id, attempt
        except AttestationError as error:
            errors.append(error)
    if len(value) >= 100:
        raise AttestationError(
            Reason(
                "ATTESTATION_SEARCH_TRUNCATED",
                "The configured attestation limit was reached without an acceptable result; absence is not proven.",
                "fewer than 100 fetched results or one acceptable result",
                len(value),
            )
        )
    failed = [error for error in errors if error.reason.code != "VERIFIER_OUTPUT_INVALID"]
    if failed:
        raise failed[0]
    raise AttestationError(
        Reason("VERIFIER_OUTPUT_INVALID", "No verifier result contained a complete, parseable evidence structure.")
    )


def validate_attestation(
    result: Any,
    request: VerificationRequest,
    expected_digest: str,
) -> tuple[dict[str, Any], dict[str, Any], int, int]:
    if not isinstance(result, dict):
        raise AttestationError(Reason("VERIFIER_OUTPUT_INVALID", "An attestation result is not an object."))
    verification = result.get("verificationResult")
    if not isinstance(verification, dict):
        raise AttestationError(Reason("VERIFIER_OUTPUT_INVALID", "The attestation has no verificationResult."))
    signature = verification.get("signature")
    certificate = signature.get("certificate") if isinstance(signature, dict) else None
    statement = verification.get("statement")
    if not isinstance(certificate, dict) or not isinstance(statement, dict):
        raise AttestationError(
            Reason("VERIFIER_OUTPUT_INVALID", "The attestation lacks a certificate or statement.")
        )

    _require_certificate(
        certificate.get("issuer") == ISSUER,
        "SIGNER_MISMATCH",
        "The certificate OIDC issuer differs from GitHub Actions.",
        ISSUER,
        certificate.get("issuer"),
    )
    _require_certificate(
        certificate.get("sourceRepositoryURI") == request.source_repository_uri,
        "SIGNER_MISMATCH",
        "The certificate source repository differs from the requested repository.",
        request.source_repository_uri,
        certificate.get("sourceRepositoryURI"),
    )
    _require_certificate(
        certificate.get("sourceRepositoryDigest") == request.expected_commit,
        "SOURCE_COMMIT_MISMATCH",
        "The attested source commit differs from the expected commit.",
        request.expected_commit,
        certificate.get("sourceRepositoryDigest"),
    )
    _require_certificate(
        certificate.get("sourceRepositoryRef") == request.source_ref,
        "SOURCE_REF_MISMATCH",
        "The attested source ref differs by value or case from the expected ref.",
        request.source_ref,
        certificate.get("sourceRepositoryRef"),
    )
    identities = [
        certificate.get("subjectAlternativeName"),
        certificate.get("buildSignerURI"),
    ]
    present_identities = [item for item in identities if isinstance(item, str)]
    _require_certificate(
        bool(present_identities)
        and all(request.certificate_identity_matches(item) for item in present_identities),
        "SIGNER_MISMATCH",
        "The certificate signer workflow/ref is not approved; a pinned reusable signer may use its own valid ref or digest.",
        request.certificate_identity,
        present_identities or None,
    )
    if request.signer_digest is not None:
        _require_certificate(
            certificate.get("buildSignerDigest") == request.signer_digest,
            "SIGNER_DIGEST_MISMATCH",
            "The reusable workflow signer digest differs from the approved digest.",
            request.signer_digest,
            certificate.get("buildSignerDigest"),
        )
    _require_certificate(
        certificate.get("runnerEnvironment") == "github-hosted",
        "RUNNER_ENVIRONMENT_MISMATCH",
        "The attestation was not issued to a GitHub-hosted runner.",
        "github-hosted",
        certificate.get("runnerEnvironment"),
    )

    run_uri = certificate.get("runInvocationURI")
    match = RUN_URI_RE.fullmatch(run_uri) if isinstance(run_uri, str) else None
    if not match or match.group(1) != request.repo:
        raise AttestationError(
            Reason(
                "RUN_INVOCATION_MISMATCH",
                "The certificate run invocation URI is invalid or belongs to another repository.",
                request.repo,
                run_uri,
            )
        )
    run_id, attempt = int(match.group(2)), int(match.group(3))
    if request.expected_run and (
        run_id != request.expected_run.id or attempt != request.expected_run.attempt
    ):
        raise AttestationError(
            Reason(
                "WORKFLOW_RUN_POLICY_FAILED",
                "The certificate run or attempt differs from expected_run.",
                {"id": request.expected_run.id, "attempt": request.expected_run.attempt},
                {"id": run_id, "attempt": attempt},
            )
        )

    if statement.get("predicateType") != PREDICATE_TYPE:
        raise AttestationError(
            Reason(
                "PROVENANCE_MISSING",
                "The result is not SLSA v1 provenance; SBOM or custom evidence is insufficient.",
                PREDICATE_TYPE,
                statement.get("predicateType"),
            )
        )
    subjects = statement.get("subject")
    subject_digest = None
    if isinstance(subjects, list):
        for subject in subjects:
            if not isinstance(subject, dict) or not isinstance(subject.get("digest"), dict):
                continue
            digest = subject["digest"].get("sha256")
            if isinstance(digest, str) and SHA256_RE.fullmatch(f"sha256:{digest}"):
                candidate = f"sha256:{digest}"
                if candidate == expected_digest:
                    subject_digest = candidate
                    break
    if subject_digest is None:
        actual_digests = []
        if isinstance(subjects, list):
            for subject in subjects:
                if isinstance(subject, dict) and isinstance(subject.get("digest"), dict):
                    actual_digests.append(subject["digest"])
        raise AttestationError(
            Reason(
                "ATTESTED_DIGEST_MISMATCH",
                "No in-toto subject covers the exact pinned OCI digest.",
                expected_digest,
                actual_digests or None,
            )
        )

    certificate_evidence = {
        "issuer": ISSUER,
        "subject_alternative_name": certificate.get("subjectAlternativeName"),
        "build_signer_uri": certificate.get("buildSignerURI"),
        "source_repository_uri": request.source_repository_uri,
        "source_repository_digest": request.expected_commit,
        "source_repository_ref": request.source_ref,
        "build_signer_digest": certificate.get("buildSignerDigest"),
        "runner_environment": "github-hosted",
        "run_invocation_uri": run_uri,
    }
    for key in ("sourceRepositoryIdentifier", "sourceRepositoryOwnerIdentifier"):
        if key in certificate and isinstance(certificate[key], (str, int)):
            certificate_evidence[_snake_case(key)] = certificate[key]
    attestation_evidence = {
        "predicate_type": PREDICATE_TYPE,
        "subject_digest": subject_digest,
        "verified_timestamps": _timestamp_evidence(verification.get("verifiedTimestamps")),
        "transparency_log_ids": _transparency_ids(verification),
        "bundle_sha256": _bundle_digest(result),
    }
    return certificate_evidence, attestation_evidence, run_id, attempt


def _require_certificate(
    condition: bool,
    code: str,
    message: str,
    expected: Any,
    actual: Any,
) -> None:
    if not condition:
        raise AttestationError(Reason(code, message, expected, actual))


def _timestamp_evidence(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    evidence = []
    for item in value:
        if not isinstance(item, dict):
            continue
        safe = {key: item[key] for key in ("type", "uri", "timestamp") if isinstance(item.get(key), str)}
        if safe:
            evidence.append(safe)
    return evidence


def _transparency_ids(verification: dict[str, Any]) -> list[str]:
    entries = verification.get("transparencyLogEntries")
    if not isinstance(entries, list):
        return []
    identifiers = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for key in ("logIndex", "logId", "entryUuid"):
            value = entry.get(key)
            if isinstance(value, (str, int)) and not isinstance(value, bool):
                identifiers.append(str(value))
                break
    return sorted(set(identifiers))


def _bundle_digest(result: dict[str, Any]) -> str | None:
    attestation = result.get("attestation")
    bundle = attestation.get("bundle") if isinstance(attestation, dict) else None
    if not isinstance(bundle, dict):
        return None
    try:
        canonical = json.dumps(
            bundle, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        return None
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


def _snake_case(value: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", value).lower()
