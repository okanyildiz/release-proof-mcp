from __future__ import annotations

import base64
import copy
import hashlib
import os
import stat
import threading
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from .receipt_validation import (
    SCHEMA_VERSION,
    canonical_json_bytes,
    pinned_ghcr_artifact,
    validate_receipt,
)

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://release-proof.dev/predicate/release-deployment-proof/v2"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
ALGORITHM = "ed25519"
MAX_SIGNING_KEY_BYTES = 16 * 1024


@runtime_checkable
class ReceiptSigner(Protocol):
    @property
    def public_key(self) -> Ed25519PublicKey: ...

    def sign(
        self,
        message: bytes,
        *,
        cancel_event: threading.Event | None = None,
    ) -> bytes: ...


def load_ed25519_private_key(path: str | Path) -> Ed25519PrivateKey:
    try:
        with Path(path).open("rb") as key_file:
            if os.name == "posix":
                mode = stat.S_IMODE(os.fstat(key_file.fileno()).st_mode)
                if mode & 0o077:
                    raise ValueError("Signing key file must be owner-only.")
            encoded = key_file.read(MAX_SIGNING_KEY_BYTES + 1)
        if len(encoded) > MAX_SIGNING_KEY_BYTES:
            raise ValueError("Signing key file exceeds the size limit.")
        key = load_pem_private_key(encoded, password=None)
    except (OSError, TypeError, ValueError) as error:
        raise ValueError("Invalid Ed25519 private key file configuration.") from error
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Invalid Ed25519 private key file configuration.")
    return key


def receipt_digest(receipt: Mapping[str, Any]) -> str:
    predicate = {key: value for key, value in receipt.items() if key != "proof"}
    return f"sha256:{hashlib.sha256(canonical_json_bytes(predicate)).hexdigest()}"


def dsse_pae(payload_type: bytes, payload: bytes) -> bytes:
    return b"".join(
        (
            b"DSSEv1 ",
            str(len(payload_type)).encode("ascii"),
            b" ",
            payload_type,
            b" ",
            str(len(payload)).encode("ascii"),
            b" ",
            payload,
        )
    )


def statement_for_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    predicate = copy.deepcopy(
        {key: value for key, value in receipt.items() if key != "proof"}
    )
    if not isinstance(predicate.get("proof_metadata"), dict):
        raise ValueError("Authenticated proof metadata is required.")
    return {
        "_type": STATEMENT_TYPE,
        "subject": _statement_subject(predicate),
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }


def sign_receipt(
    receipt: Mapping[str, Any],
    signer: Ed25519PrivateKey | ReceiptSigner,
    issuer: str,
    keyid: str,
    clock: Callable[[], datetime] | None = None,
    *,
    cancel_event: threading.Event | None = None,
) -> dict[str, Any]:
    if not isinstance(receipt, dict):
        raise ValueError("Receipt must be a JSON object.")
    if "proof" in receipt or "proof_metadata" in receipt:
        raise ValueError("An unsigned receipt must not contain proof or proof_metadata.")
    if not isinstance(signer, (Ed25519PrivateKey, ReceiptSigner)):
        raise ValueError("An Ed25519 private key or receipt signer is required.")
    if not isinstance(issuer, str) or not issuer.strip() or len(issuer) > 512:
        raise ValueError("Issuer must be a nonempty string of at most 512 characters.")
    if not isinstance(keyid, str) or not keyid.strip() or len(keyid) > 256:
        raise ValueError("Key ID must be a nonempty string of at most 256 characters.")
    validate_receipt(receipt)

    metadata = {
        "issuer": issuer,
        "keyid": keyid,
        "algorithm": ALGORITHM,
        "signed_at": _signed_at(clock),
    }
    signed = copy.deepcopy(receipt)
    signed["proof_metadata"] = metadata
    statement = statement_for_receipt(signed)
    payload = canonical_json_bytes(statement)
    payload_type = PAYLOAD_TYPE.encode("ascii")
    pae = dsse_pae(payload_type, payload)
    if isinstance(signer, Ed25519PrivateKey):
        signature = signer.sign(pae)
    else:
        signature = _remote_signature(signer, pae, cancel_event)
    signed["proof"] = {
        **metadata,
        "envelope": {
            "payloadType": PAYLOAD_TYPE,
            "payload": base64.b64encode(payload).decode("ascii"),
            "signatures": [
                {
                    "keyid": keyid,
                    "sig": base64.b64encode(signature).decode("ascii"),
                }
            ],
        },
    }
    validate_receipt(signed, require_proof=True)
    return signed


def _remote_signature(
    signer: ReceiptSigner,
    pae: bytes,
    cancel_event: threading.Event | None,
) -> bytes:
    public_key = signer.public_key
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("A receipt signer must pin an Ed25519 public key.")
    signature = signer.sign(pae, cancel_event=cancel_event)
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise ValueError("A receipt signer must return a raw 64-byte signature.")
    try:
        public_key.verify(signature, pae)
    except (InvalidSignature, ValueError) as error:
        raise ValueError("The receipt signer returned an invalid signature.") from error
    return signature


def _statement_subject(receipt: Mapping[str, Any]) -> list[dict[str, Any]]:
    subject = receipt.get("subject")
    pinned = subject.get("pinned_artifact") if isinstance(subject, dict) else None
    artifact = (
        pinned_ghcr_artifact(pinned)
        if receipt.get("status") == "verified"
        else None
    )
    if artifact is not None:
        repository, digest = artifact
        return [{"name": repository, "digest": {"sha256": digest}}]
    receipt_id = receipt.get("receipt_id")
    if not isinstance(receipt_id, str):
        raise ValueError("Receipt ID must be a UUID string.")
    return [
        {
            "name": f"https://release-proof.dev/receipt/{receipt_id}",
            "digest": {"sha256": receipt_digest(receipt).removeprefix("sha256:")},
        }
    ]


def _signed_at(clock: Callable[[], datetime] | None) -> str:
    value = (clock or (lambda: datetime.now(timezone.utc)))()
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("Signing clock must return an aware datetime.")
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )
