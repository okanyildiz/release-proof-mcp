from __future__ import annotations

import base64
import copy
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from release_proof_mcp.receipt_validation import ReceiptValidationError, validate_receipt
from release_proof_mcp.signing import (
    ALGORITHM,
    PAYLOAD_TYPE,
    PREDICATE_TYPE,
    SCHEMA_VERSION,
    STATEMENT_TYPE,
    canonical_json_bytes,
    dsse_pae,
    receipt_digest,
    sign_receipt,
    statement_for_receipt,
)

FIXED_NOW = datetime(2026, 11, 18, 12, 0, 0, tzinfo=timezone.utc)
ISSUER = "https://issuer.example/release-proof"
KEYID = "release-proof-test-key"
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
GOLDEN = json.loads(
    (Path(__file__).parent / "fixtures/receipt-v2.golden.json").read_text(encoding="utf-8")
)
POLICY_HASH = GOLDEN["policy_hash"]
NONCE = GOLDEN["consumer_nonce"]
ARTIFACT_DIGEST = GOLDEN["subject"]["pinned_artifact"].split("@", 1)[1]


def unsigned_receipt(**overrides: Any) -> dict[str, Any]:
    receipt = copy.deepcopy(GOLDEN)
    receipt.update(overrides)
    return receipt


def signed_receipt(receipt: dict[str, Any] | None = None) -> dict[str, Any]:
    return sign_receipt(
        receipt or unsigned_receipt(),
        PRIVATE_KEY,
        ISSUER,
        KEYID,
        clock=lambda: FIXED_NOW,
    )


def public_key_pem() -> bytes:
    return PRIVATE_KEY.public_key().public_bytes(
        Encoding.PEM,
        PublicFormat.SubjectPublicKeyInfo,
    )


def resign(receipt: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    unsigned = copy.deepcopy(
        {
            key: value
            for key, value in receipt.items()
            if key not in {"proof", "proof_metadata"}
        }
    )
    unsigned.update(overrides)
    return signed_receipt(unsigned)


def resign_unchecked(receipt: dict[str, Any]) -> dict[str, Any]:
    signed = copy.deepcopy(receipt)
    metadata = copy.deepcopy(signed.get("proof_metadata") or {
        "issuer": ISSUER,
        "keyid": KEYID,
        "algorithm": ALGORITHM,
        "signed_at": "2026-11-18T12:00:00Z",
    })
    signed.pop("proof", None)
    signed["proof_metadata"] = metadata
    payload = canonical_json_bytes(statement_for_receipt(signed))
    signature = PRIVATE_KEY.sign(dsse_pae(PAYLOAD_TYPE.encode("ascii"), payload))
    signed["proof"] = {
        **metadata,
        "envelope": {
            "payloadType": PAYLOAD_TYPE,
            "payload": base64.b64encode(payload).decode("ascii"),
            "signatures": [
                {"keyid": KEYID, "sig": base64.b64encode(signature).decode("ascii")}
            ],
        },
    }
    return signed


def nonverified_receipt(status: str) -> dict[str, Any]:
    receipt = unsigned_receipt(status=status)
    check = receipt["checks"][0]
    check["status"] = status
    check["reason"] = {"code": "TEST_REASON", "message": "Synthetic audit result."}
    receipt["reasons"] = [{"check": check["name"], **check["reason"]}]
    receipt["missing_coverage"] = (
        [{"check": check["name"], "code": "TEST_REASON"}]
        if status == "unknown"
        else []
    )
    return receipt


def update_policy_hash(receipt: dict[str, Any]) -> None:
    digest = hashlib.sha256(canonical_json_bytes(receipt["effective_policy"])).hexdigest()
    receipt["policy_hash"] = f"sha256:{digest}"
    receipt["policy_descriptor"]["hash"] = receipt["policy_hash"]


def cosign_receipt() -> dict[str, Any]:
    receipt = unsigned_receipt()
    receipt["effective_policy"]["require_cosign_signature"] = True
    update_policy_hash(receipt)
    receipt["checks"].insert(
        6,
        {
            "name": "signature.cosign",
            "status": "verified",
            "reason": None,
            "evidence": ["cosign"],
        },
    )
    receipt["evidence"]["cosign"] = {"verified": True, "result_count": 1}
    return receipt


def exact_head_receipt() -> dict[str, Any]:
    receipt = unsigned_receipt()
    receipt["effective_policy"]["review"]["mode"] = "exact_head"
    update_policy_hash(receipt)
    pull_request = receipt["evidence"]["pull_request"]
    pull_request["mode"] = "exact_head"
    pull_request["head_sha"] = receipt["subject"]["expected_commit"]
    pull_request["merge_commit_sha"] = None
    pull_request["expected_commit_directly_reviewed"] = True
    receipt["evidence"]["reviews"][0]["commit_id"] = pull_request["head_sha"]
    return receipt


def index_child_receipt() -> dict[str, Any]:
    receipt = unsigned_receipt()
    pod = receipt["evidence"]["pods"][0]
    pod["image_id"] = f"ghcr.io/acme/shop@sha256:{'b' * 64}"
    pod["digest_relation"] = "index_child"
    return receipt


def same_repo_pinned_signer_receipt() -> dict[str, Any]:
    receipt = unsigned_receipt()
    certificate = receipt["evidence"]["certificate"]
    certificate["subject_alternative_name"] = (
        "https://github.com/acme/shop/.github/workflows/release.yml@"
        + receipt["effective_policy"]["signer_digest"]
    )
    return receipt


def test_same_repo_null_signer_digest_is_omitted_during_reconstruction() -> None:
    receipt = unsigned_receipt()
    receipt["effective_policy"]["signer_digest"] = None
    receipt["evidence"]["certificate"]["build_signer_digest"] = None
    update_policy_hash(receipt)

    signed = sign_receipt(receipt, PRIVATE_KEY, ISSUER, KEYID)

    assert signed["proof"]["algorithm"] == "ed25519"


def reusable_signer_receipt() -> dict[str, Any]:
    receipt = unsigned_receipt()
    receipt["effective_policy"]["signer_workflow"] = (
        "acme/builders/.github/workflows/reusable.yml"
    )
    update_policy_hash(receipt)
    receipt["evidence"]["certificate"]["subject_alternative_name"] = (
        "https://github.com/acme/builders/.github/workflows/reusable.yml@refs/heads/main"
    )
    return receipt


def digest_input_receipt() -> dict[str, Any]:
    receipt = unsigned_receipt()
    receipt["subject"]["artifact_input"] = receipt["subject"]["pinned_artifact"]
    return receipt


def test_standard_statement_authenticates_metadata_without_input_mutation() -> None:
    receipt = unsigned_receipt()
    original = copy.deepcopy(receipt)

    first = signed_receipt(receipt)
    second = signed_receipt(receipt)

    assert receipt == original
    assert "proof" not in receipt
    assert "proof_metadata" not in receipt
    assert first == second
    assert first is not receipt
    assert first["subject"] is not receipt["subject"]
    metadata = {
        "issuer": ISSUER,
        "keyid": KEYID,
        "algorithm": ALGORITHM,
        "signed_at": "2026-11-18T12:00:00Z",
    }
    assert first["proof_metadata"] == metadata
    assert first["proof"] == {
        **metadata,
        "envelope": first["proof"]["envelope"],
    }

    envelope = first["proof"]["envelope"]
    assert envelope["payloadType"] == PAYLOAD_TYPE
    payload = base64.b64decode(envelope["payload"], validate=True)
    statement = json.loads(payload)
    assert payload == canonical_json_bytes(statement)
    assert statement == {
        "_type": STATEMENT_TYPE,
        "subject": [
            {
                "name": "ghcr.io/acme/shop",
                "digest": {"sha256": ARTIFACT_DIGEST.removeprefix("sha256:")},
            }
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": {**original, "proof_metadata": metadata},
    }
    assert receipt_digest(first) == (
        "sha256:"
        + hashlib.sha256(canonical_json_bytes(statement["predicate"])).hexdigest()
    )
    signature = base64.b64decode(envelope["signatures"][0]["sig"], validate=True)
    PRIVATE_KEY.public_key().verify(signature, dsse_pae(PAYLOAD_TYPE.encode(), payload))
    with pytest.raises(InvalidSignature):
        PRIVATE_KEY.public_key().verify(signature, dsse_pae(PAYLOAD_TYPE.encode(), payload + b" "))


def test_dsse_pae_known_vector() -> None:
    assert dsse_pae(b"http://example.com/HelloWorld", b"hello world") == (
        b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
    )


@pytest.mark.parametrize("status", ["failed", "unknown"])
def test_nonverified_signing_uses_receipt_digest_with_authenticated_metadata(status: str) -> None:
    receipt = nonverified_receipt(status)

    signed = signed_receipt(receipt)
    statement = json.loads(base64.b64decode(signed["proof"]["envelope"]["payload"]))
    subject = statement["subject"][0]

    assert signed["status"] == status
    assert subject["name"] == f"https://release-proof.dev/receipt/{receipt['receipt_id']}"
    assert subject["digest"] == {
        "sha256": receipt_digest(signed).removeprefix("sha256:")
    }
    assert subject["digest"]["sha256"] != ARTIFACT_DIGEST.removeprefix("sha256:")
    assert statement["predicate"]["proof_metadata"] == signed["proof_metadata"]
    assert "proof" not in statement["predicate"]
    validate_receipt(signed, require_proof=True)


@pytest.mark.parametrize("field", ["min_approvals", "require_non_author"])
def test_signing_rejects_weak_effective_policy_tampering(field: str) -> None:
    receipt = unsigned_receipt()
    receipt["effective_policy"]["review"][field] = 0 if field == "min_approvals" else False

    with pytest.raises(ReceiptValidationError):
        sign_receipt(receipt, PRIVATE_KEY, ISSUER, KEYID)


@pytest.mark.parametrize("field", ["profile", "version", "hash"])
def test_signing_rejects_policy_descriptor_tampering(field: str) -> None:
    receipt = unsigned_receipt()
    receipt["policy_descriptor"][field] = (
        f"sha256:{'2' * 64}" if field == "hash" else "other"
    )

    with pytest.raises(ReceiptValidationError, match="policy integrity"):
        sign_receipt(receipt, PRIVATE_KEY, ISSUER, KEYID)


def test_signing_rejects_duplicate_missing_and_inapplicable_checks() -> None:
    duplicate = unsigned_receipt()
    duplicate["checks"].append(copy.deepcopy(duplicate["checks"][0]))
    missing = unsigned_receipt()
    missing["checks"].pop(0)
    unexpected_cosign = unsigned_receipt()
    unexpected_cosign["checks"].insert(
        6,
        {"name": "signature.cosign", "status": "verified", "reason": None, "evidence": []},
    )
    missing_cosign = unsigned_receipt()
    missing_cosign["effective_policy"]["require_cosign_signature"] = True
    update_policy_hash(missing_cosign)

    for receipt in (duplicate, missing, unexpected_cosign, missing_cosign):
        with pytest.raises(ReceiptValidationError):
            sign_receipt(receipt, PRIVATE_KEY, ISSUER, KEYID)


def test_signing_rejects_inconsistent_status_reasons_and_missing_coverage() -> None:
    bad_status = nonverified_receipt("failed")
    bad_status["status"] = "verified"
    bad_reasons = nonverified_receipt("unknown")
    bad_reasons["reasons"] = []
    bad_missing = nonverified_receipt("unknown")
    bad_missing["missing_coverage"] = []
    missing_pin = unsigned_receipt()
    missing_pin["subject"]["pinned_artifact"] = None

    for receipt in (bad_status, bad_reasons, bad_missing, missing_pin):
        with pytest.raises(ReceiptValidationError):
            sign_receipt(receipt, PRIVATE_KEY, ISSUER, KEYID)


def test_canonical_json_is_compact_sorted_utf8_and_finite_only() -> None:
    assert canonical_json_bytes({"b": 1, "a": "\u00e9"}) == b'{"a":"\xc3\xa9","b":1}'
    for value in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValueError):
            canonical_json_bytes({"value": value})


def test_signing_rejects_preexisting_proof_material_and_does_not_alias_input() -> None:
    receipt = unsigned_receipt()
    signed = signed_receipt(receipt)
    with pytest.raises(ValueError, match="must not contain proof"):
        sign_receipt(signed, PRIVATE_KEY, ISSUER, KEYID)
    metadata_only = unsigned_receipt(proof_metadata=signed["proof_metadata"])
    with pytest.raises(ValueError, match="must not contain proof"):
        sign_receipt(metadata_only, PRIVATE_KEY, ISSUER, KEYID)

    signed["subject"]["repo"] = "changed/only-in-copy"
    assert receipt["subject"]["repo"] == "acme/shop"


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
def test_supported_verified_evidence_variants_remain_signable(builder: Any) -> None:
    signed = signed_receipt(builder())

    assert signed["status"] == "verified"
    validate_receipt(signed, require_proof=True)


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
def test_signing_rejects_blank_verified_evidence(name: str, value: Any) -> None:
    receipt = cosign_receipt() if name == "cosign" else unsigned_receipt()
    receipt["evidence"][name] = value

    with pytest.raises(ReceiptValidationError):
        sign_receipt(receipt, PRIVATE_KEY, ISSUER, KEYID)


def test_signing_requires_exact_evidence_references_for_every_core_check() -> None:
    for index in range(len(unsigned_receipt()["checks"])):
        receipt = unsigned_receipt()
        receipt["checks"][index]["evidence"] = []
        with pytest.raises(ReceiptValidationError):
            sign_receipt(receipt, PRIVATE_KEY, ISSUER, KEYID)

    reversed_refs = unsigned_receipt()
    reversed_refs["checks"][1]["evidence"] = ["reviews", "pull_request"]
    with pytest.raises(ReceiptValidationError):
        sign_receipt(reversed_refs, PRIVATE_KEY, ISSUER, KEYID)
    cosign = cosign_receipt()
    cosign["checks"][6]["evidence"] = ["cosign", "registry"]
    with pytest.raises(ReceiptValidationError):
        sign_receipt(cosign, PRIVATE_KEY, ISSUER, KEYID)


@pytest.mark.parametrize("status", ["failed", "unknown"])
def test_nonverified_audit_signing_does_not_require_complete_evidence(status: str) -> None:
    receipt = nonverified_receipt(status)
    receipt["evidence"]["commit"] = None
    receipt["evidence"]["reviews"] = []
    receipt["evidence"]["pods"] = []

    signed = signed_receipt(receipt)

    assert signed["status"] == status
    validate_receipt(signed, require_proof=True)


def test_receipt_signer_protocol_uses_exact_pae_and_matches_legacy_signature() -> None:
    import threading

    class RemoteSigner:
        public_key = PRIVATE_KEY.public_key()

        def __init__(self) -> None:
            self.messages: list[bytes] = []
            self.cancel_events: list[Any] = []

        def sign(self, message: bytes, *, cancel_event: Any = None) -> bytes:
            self.messages.append(message)
            self.cancel_events.append(cancel_event)
            return PRIVATE_KEY.sign(message)

    signer = RemoteSigner()
    cancellation = threading.Event()

    signed = sign_receipt(
        unsigned_receipt(),
        signer,
        ISSUER,
        KEYID,
        clock=lambda: FIXED_NOW,
        cancel_event=cancellation,
    )

    assert signed == signed_receipt()
    payload = base64.b64decode(signed["proof"]["envelope"]["payload"], validate=True)
    assert signer.messages == [dsse_pae(PAYLOAD_TYPE.encode("ascii"), payload)]
    assert signer.cancel_events == [cancellation]


def test_receipt_signer_protocol_rejects_wrong_pinned_public_key() -> None:
    class WrongPinnedKeySigner:
        public_key = Ed25519PrivateKey.generate().public_key()

        def sign(self, message: bytes, *, cancel_event: Any = None) -> bytes:
            return PRIVATE_KEY.sign(message)

    with pytest.raises(ValueError, match="invalid signature"):
        sign_receipt(
            unsigned_receipt(),
            WrongPinnedKeySigner(),
            ISSUER,
            KEYID,
            clock=lambda: FIXED_NOW,
        )


@pytest.mark.parametrize(
    "signature",
    [b"x" * 63, base64.b64encode(b"x" * 64), bytearray(b"x" * 64)],
)
def test_receipt_signer_protocol_requires_raw_64_byte_signature(signature: Any) -> None:
    class MalformedSigner:
        public_key = PRIVATE_KEY.public_key()

        def sign(self, message: bytes, *, cancel_event: Any = None) -> Any:
            return signature

    with pytest.raises(ValueError, match="raw 64-byte"):
        sign_receipt(
            unsigned_receipt(),
            MalformedSigner(),
            ISSUER,
            KEYID,
            clock=lambda: FIXED_NOW,
        )
