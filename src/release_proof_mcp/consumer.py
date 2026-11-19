from __future__ import annotations

import base64
import copy
import json
import math
import re
import uuid
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .receipt_validation import (
    SCHEMA_VERSION,
    VERIFIER_FIELDS,
    ReceiptValidationError,
    canonical_json_bytes,
    parse_rfc3339,
    subject_fields,
    validate_receipt,
)
from .signing import (
    ALGORITHM,
    PAYLOAD_TYPE,
    dsse_pae,
    receipt_digest,
    statement_for_receipt,
)

MAX_CONSUMER_FILE_BYTES = 2 * 1024 * 1024
_POLICY_HASH = re.compile(r"sha256:[0-9a-f]{64}")


class StrictJSONError(ValueError):
    pass


class _VerificationFailure(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def read_bounded_file(path: str | Path) -> bytes:
    with Path(path).open("rb") as source:
        raw = source.read(MAX_CONSUMER_FILE_BYTES + 1)
    if len(raw) > MAX_CONSUMER_FILE_BYTES:
        raise StrictJSONError("Consumer input exceeds the 2 MiB limit.")
    return raw


def strict_json_loads(raw: bytes) -> Any:
    if not isinstance(raw, bytes):
        raise StrictJSONError("Strict JSON input must be bytes.")
    try:
        text = raw.decode("utf-8")
        return json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_nonfinite,
            parse_float=_finite_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as error:
        raise StrictJSONError("Input is not strict, finite UTF-8 JSON.") from error


def load_strict_json_file(path: str | Path) -> Any:
    return strict_json_loads(read_bounded_file(path))


def verify_receipt(
    receipt: Mapping[str, Any],
    trusted_public_keys: Mapping[str, Ed25519PublicKey],
    expected_issuer: str,
    expected_subject: Mapping[str, Any],
    expected_policy_hash: str,
    expected_verifier: Mapping[str, Any],
    expected_nonce: str,
    now: datetime,
    max_age_seconds: float,
) -> dict[str, Any]:
    receipt_id = _canonical_receipt_id(receipt.get("receipt_id")) if isinstance(receipt, dict) else None
    policy_hash = receipt.get("policy_hash") if isinstance(receipt, dict) else None
    if not isinstance(policy_hash, str) or not _POLICY_HASH.fullmatch(policy_hash):
        policy_hash = None
    try:
        digest = receipt_digest(receipt) if isinstance(receipt, dict) else None
    except (TypeError, ValueError, AttributeError, RecursionError):
        digest = None
    try:
        consumer_now = _aware_utc(now)
        evaluated_at: str | None = _format_time(consumer_now)
    except (TypeError, ValueError, OverflowError):
        consumer_now = None
        evaluated_at = None
    decision: dict[str, Any] = {
        "allow": False,
        "decision_id": str(uuid.uuid4()),
        "receipt_id": receipt_id,
        "receipt_digest": digest,
        "policy_hash": policy_hash,
        "reason": "RECEIPT_MALFORMED",
        "evaluated_at": evaluated_at,
    }

    try:
        if consumer_now is None:
            raise _VerificationFailure("CONSUMER_TIME_INVALID")
        expected_subject_value, expected_verifier_value = _validate_expectations(
            expected_issuer,
            expected_subject,
            expected_policy_hash,
            expected_verifier,
            expected_nonce,
            max_age_seconds,
        )
        if (
            isinstance(receipt, dict)
            and "schema_version" in receipt
            and receipt["schema_version"] != SCHEMA_VERSION
        ):
            raise _VerificationFailure("SCHEMA_VERSION_UNSUPPORTED")
        if isinstance(receipt, dict) and "proof" not in receipt:
            raise _VerificationFailure("PROOF_MISSING")
        if isinstance(receipt, dict) and "proof_metadata" not in receipt:
            raise _VerificationFailure("PROOF_METADATA_MISSING")
        if isinstance(receipt, dict) and isinstance(receipt.get("proof"), dict):
            if receipt["proof"].get("algorithm") != ALGORITHM:
                raise _VerificationFailure("ALGORITHM_UNSUPPORTED")
        try:
            validate_receipt(receipt, require_proof=True)
        except (ReceiptValidationError, ValueError, KeyError, TypeError, RecursionError) as error:
            raise _VerificationFailure("RECEIPT_INVALID") from error

        proof = receipt["proof"]
        metadata = receipt["proof_metadata"]
        issuer = metadata["issuer"]
        keyid = metadata["keyid"]
        if issuer != expected_issuer:
            raise _VerificationFailure("ISSUER_MISMATCH")
        try:
            public_key = trusted_public_keys.get(keyid)
        except (AttributeError, TypeError):
            public_key = None
        if not isinstance(public_key, Ed25519PublicKey):
            raise _VerificationFailure("KEY_NOT_TRUSTED")
        signed_at = parse_rfc3339(metadata["signed_at"])
        if signed_at > consumer_now:
            raise _VerificationFailure("PROOF_TIME_FUTURE")

        envelope = proof["envelope"]
        payload = _base64_field(envelope["payload"], "ENVELOPE_MALFORMED")
        signature_record = envelope["signatures"][0]
        if signature_record["keyid"] != keyid:
            raise _VerificationFailure("KEYID_MISMATCH")
        signature = _base64_field(signature_record["sig"], "ENVELOPE_MALFORMED")
        try:
            statement = strict_json_loads(payload)
        except StrictJSONError as error:
            raise _VerificationFailure("PAYLOAD_MALFORMED") from error
        if not isinstance(statement, dict):
            raise _VerificationFailure("PAYLOAD_MALFORMED")
        try:
            if canonical_json_bytes(statement) != payload:
                raise _VerificationFailure("PAYLOAD_NONCANONICAL")
            predicate = {
                key: value for key, value in receipt.items() if key != "proof"
            }
            if canonical_json_bytes(statement_for_receipt(predicate)) != payload:
                raise _VerificationFailure("PAYLOAD_MISMATCH")
        except (TypeError, ValueError, RecursionError) as error:
            raise _VerificationFailure("PAYLOAD_MALFORMED") from error
        try:
            public_key.verify(
                signature,
                dsse_pae(PAYLOAD_TYPE.encode("ascii"), payload),
            )
        except (InvalidSignature, ValueError) as error:
            raise _VerificationFailure("SIGNATURE_INVALID") from error

        _verify_policy(
            receipt,
            expected_subject_value,
            expected_policy_hash,
            expected_verifier_value,
            expected_nonce,
            consumer_now,
            max_age_seconds,
        )
        decision["allow"] = True
        decision["reason"] = "OK"
    except _VerificationFailure as error:
        decision["reason"] = error.reason
    except Exception:
        decision["reason"] = "RECEIPT_MALFORMED"
    return decision


def _validate_expectations(
    issuer: str,
    subject: Mapping[str, Any],
    policy_hash: str,
    verifier: Mapping[str, Any],
    nonce: str,
    max_age_seconds: float,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(issuer, str) or not issuer:
        raise _VerificationFailure("ISSUER_EXPECTATION_REQUIRED")
    if not isinstance(policy_hash, str) or not _POLICY_HASH.fullmatch(policy_hash):
        raise _VerificationFailure("POLICY_HASH_EXPECTATION_INVALID")
    if not isinstance(nonce, str) or not nonce:
        raise _VerificationFailure("NONCE_REQUIRED")
    if (
        isinstance(max_age_seconds, bool)
        or not isinstance(max_age_seconds, (int, float))
        or not math.isfinite(max_age_seconds)
        or max_age_seconds < 0
    ):
        raise _VerificationFailure("MAX_AGE_INVALID")
    if not isinstance(subject, Mapping) or set(subject) != subject_fields():
        raise _VerificationFailure("SUBJECT_EXPECTATION_INVALID")
    if not isinstance(verifier, Mapping) or set(verifier) != VERIFIER_FIELDS:
        raise _VerificationFailure("VERIFIER_EXPECTATION_INVALID")
    try:
        expected_subject = copy.deepcopy(dict(subject))
        expected_verifier = copy.deepcopy(dict(verifier))
        canonical_json_bytes(expected_subject)
        canonical_json_bytes(expected_verifier)
    except (TypeError, ValueError, RecursionError) as error:
        raise _VerificationFailure("EXPECTATION_INVALID") from error
    return expected_subject, expected_verifier


def _base64_field(value: Any, reason: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise _VerificationFailure(reason)
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as error:
        raise _VerificationFailure(reason) from error
    if base64.b64encode(decoded).decode("ascii") != value:
        raise _VerificationFailure(reason)
    return decoded


def _verify_policy(
    receipt: Mapping[str, Any],
    expected_subject: Mapping[str, Any],
    expected_policy_hash: str,
    expected_verifier: Mapping[str, Any],
    expected_nonce: str,
    now: datetime,
    max_age_seconds: float,
) -> None:
    if receipt["status"] != "verified":
        raise _VerificationFailure("STATUS_NOT_VERIFIED")
    if receipt["missing_coverage"]:
        raise _VerificationFailure("MISSING_COVERAGE")
    if any(check["status"] != "verified" for check in receipt["checks"]):
        raise _VerificationFailure("CHECKS_NOT_VERIFIED")
    if receipt["policy_hash"] != expected_policy_hash:
        raise _VerificationFailure("POLICY_MISMATCH")
    if not _json_equal(receipt["verifier"], expected_verifier):
        raise _VerificationFailure("VERIFIER_MISMATCH")
    if not _json_equal(receipt["subject"], expected_subject):
        raise _VerificationFailure("SUBJECT_MISMATCH")
    if receipt["consumer_nonce"] != expected_nonce:
        raise _VerificationFailure("NONCE_MISMATCH")

    started_at = parse_rfc3339(receipt["started_at"])
    completed_at = parse_rfc3339(receipt["completed_at"])
    if started_at > completed_at:
        raise _VerificationFailure("OBSERVATION_WINDOW_INVERTED")
    if completed_at > now:
        raise _VerificationFailure("OBSERVATION_TIME_FUTURE")
    if (now - completed_at).total_seconds() > max_age_seconds:
        raise _VerificationFailure("RECEIPT_STALE")


def _json_equal(first: Any, second: Any) -> bool:
    try:
        return canonical_json_bytes(first) == canonical_json_bytes(second)
    except ValueError:
        return False


def _canonical_receipt_id(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        return None
    return value if parsed.version == 4 and str(parsed) == value else None


def _aware_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("An aware datetime is required.")
    return value.astimezone(timezone.utc)


def _format_time(value: datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJSONError("Duplicate JSON object key.")
        result[key] = value
    return result


def _reject_nonfinite(_value: str) -> Any:
    raise StrictJSONError("Non-finite JSON number.")


def _finite_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise StrictJSONError("Non-finite JSON number.")
    return result
