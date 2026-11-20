from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .evidence_package import export_evidence_package
from .policy import PolicyConfigurationError, PolicyStore
from .request import VerificationRequest
from .signing import ReceiptSigner, sign_receipt
from .verifier import ReleaseVerifier

MAX_RECEIPT_BYTES = 512 * 1024
SigningConfiguration = tuple[Ed25519PrivateKey | ReceiptSigner, str, str]


class ReceiptSizeError(ValueError):
    pass


@dataclass(frozen=True)
class CaptureResult:
    receipt: dict[str, Any]
    encoded: bytes


def verifier_from_environment(
    verifier_type: type[ReleaseVerifier] = ReleaseVerifier,
) -> ReleaseVerifier:
    return verifier_type(
        verifier_instance_id=os.environ.get("RELEASE_PROOF_VERIFIER_INSTANCE_ID"),
        build_digest=os.environ.get("RELEASE_PROOF_BUILD_DIGEST"),
    )


def load_policy_store(policy_file: str | None = None) -> PolicyStore:
    path = policy_file or os.environ.get("RELEASE_PROOF_POLICY_FILE")
    if not path:
        raise PolicyConfigurationError("Trusted policy is not configured.")
    return PolicyStore.from_file(path)


def normalize_evidence_package_root(
    value: str | os.PathLike[str] | None,
) -> str | None:
    if value is None:
        return None
    try:
        path = os.fspath(value)
    except TypeError as error:
        raise ValueError("evidence_package_root must be a filesystem path") from error
    if not isinstance(path, str) or not path or "\x00" in path:
        raise ValueError("evidence_package_root must be a nonempty filesystem path")
    return path


def capture_release(
    arguments: Any,
    *,
    policy_store: PolicyStore,
    verifier: ReleaseVerifier,
    active_profile: str | None,
    signing: SigningConfiguration | None = None,
    evidence_package_root: str | os.PathLike[str] | None = None,
    cancel_event: threading.Event | None = None,
    progress: Callable[[str], None] | None = None,
    max_receipt_bytes: int = MAX_RECEIPT_BYTES,
    receipt_signer: Callable[..., dict[str, Any]] = sign_receipt,
) -> CaptureResult:
    evidence_package_root = normalize_evidence_package_root(evidence_package_root)
    if evidence_package_root is not None and signing is None:
        raise ValueError("Evidence package export requires a signing backend")
    policy = policy_store.select(active_profile)
    request = VerificationRequest.from_dict(
        arguments,
        signer_workflow_default=policy.signer_workflow,
        signer_digest_default=policy.signer_digest,
    )
    if evidence_package_root is not None:
        receipt, artifacts = verifier.verify_detailed(
            request,
            policy,
            cancel_event=cancel_event,
            progress=progress,
        )
        signer, issuer, keyid = signing
        if receipt["status"] == "verified" and not receipt["evidence_truncation"]:
            report = export_evidence_package(
                receipt,
                artifacts,
                signer,
                issuer,
                keyid,
                evidence_package_root,
                cancel_event=cancel_event,
                max_receipt_bytes=max_receipt_bytes,
            )
        else:
            report = receipt_signer(
                receipt,
                signer,
                issuer,
                keyid,
                cancel_event=cancel_event,
            )
    else:
        report = verifier.verify(
            request,
            policy,
            cancel_event=cancel_event,
            progress=progress,
        )
        if signing is not None:
            signer, issuer, keyid = signing
            report = receipt_signer(
                report,
                signer,
                issuer,
                keyid,
                cancel_event=cancel_event,
            )
    encoded = json.dumps(
        report,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    if len(encoded) > max_receipt_bytes:
        raise ReceiptSizeError("Verification receipt exceeded the size limit")
    return CaptureResult(report, encoded)
