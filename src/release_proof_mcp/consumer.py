from __future__ import annotations

import base64
import copy
import hashlib
import math
import os
import re
import stat
import uuid
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .evidence_package import (
    ATTACHMENT_PATHS,
    MANIFEST_FILE,
    MAX_PACKAGE_TOTAL_BYTES,
    PACKAGE_FILE_LIMITS,
    PACKAGE_FILENAMES,
    RECEIPT_FILE,
    EvidencePackageError,
    validate_bundle_attachment,
    validate_evidence_manifest,
    validate_oci_attachment,
    validate_policy_attachment,
)
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
from .strict_json import StrictJSONError, strict_json_loads

MAX_CONSUMER_FILE_BYTES = 2 * 1024 * 1024
_POLICY_HASH = re.compile(r"sha256:[0-9a-f]{64}")


class _VerificationFailure(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _FileTooLarge(StrictJSONError):
    pass


def read_bounded_file(path: str | Path) -> bytes:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(path, flags)
    try:
        return _read_bounded_descriptor(descriptor, MAX_CONSUMER_FILE_BYTES)
    finally:
        os.close(descriptor)


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
    *,
    _package_context: bool = False,
) -> dict[str, Any]:
    decision, consumer_now = _new_decision(receipt, now)

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
        if "evidence_package" in receipt and not _package_context:
            raise _VerificationFailure("PACKAGE_REQUIRED")
        decision["allow"] = True
        decision["reason"] = "OK"
    except _VerificationFailure as error:
        decision["reason"] = error.reason
    except Exception:
        decision["reason"] = "RECEIPT_MALFORMED"
    return decision


def verify_evidence_package(
    package_path: str | Path,
    trusted_public_keys: Mapping[str, Ed25519PublicKey],
    expected_issuer: str,
    expected_subject: Mapping[str, Any],
    expected_policy_hash: str,
    expected_verifier: Mapping[str, Any],
    expected_nonce: str,
    now: datetime,
    max_age_seconds: float,
) -> dict[str, Any]:
    try:
        package_files = _read_package_files(package_path)
        receipt = strict_json_loads(package_files[RECEIPT_FILE])
    except _VerificationFailure as error:
        return _early_package_decision(error.reason, now)
    except StrictJSONError:
        return _early_package_decision("PACKAGE_JSON_INVALID", now)
    except Exception:
        return _early_package_decision("PACKAGE_INVALID", now)

    decision = verify_receipt(
        receipt,
        trusted_public_keys,
        expected_issuer,
        expected_subject,
        expected_policy_hash,
        expected_verifier,
        expected_nonce,
        now,
        max_age_seconds,
        _package_context=True,
    )
    if not decision["allow"]:
        return decision
    try:
        _verify_package_attachments(receipt, package_files)
        return decision
    except _VerificationFailure as error:
        decision["allow"] = False
        decision["reason"] = error.reason
    except Exception:
        decision["allow"] = False
        decision["reason"] = "PACKAGE_INVALID"
    return decision


def _verify_package_attachments(
    receipt: Mapping[str, Any], package_files: Mapping[str, bytes]
) -> None:
    descriptor = receipt.get("evidence_package")
    if descriptor is None:
        raise _VerificationFailure("PACKAGE_DESCRIPTOR_MISSING")
    try:
        manifest = strict_json_loads(package_files[MANIFEST_FILE])
    except StrictJSONError as error:
        raise _VerificationFailure("PACKAGE_JSON_INVALID") from error
    try:
        validate_evidence_manifest(manifest)
        if canonical_json_bytes(manifest) != package_files[MANIFEST_FILE]:
            raise EvidencePackageError("The manifest is not canonical.")
    except (EvidencePackageError, ValueError, TypeError) as error:
        raise _VerificationFailure("MANIFEST_INVALID") from error
    if _sha256(package_files[MANIFEST_FILE]) != descriptor["manifest_sha256"]:
        raise _VerificationFailure("MANIFEST_DIGEST_MISMATCH")
    if manifest["receipt_id"] != receipt["receipt_id"]:
        raise _VerificationFailure("RECEIPT_ID_MISMATCH")

    for role, path in ATTACHMENT_PATHS.items():
        raw = package_files[path]
        expected = {"path": path, "size": len(raw), "sha256": _sha256(raw)}
        if manifest["attachments"][role] != expected:
            raise _VerificationFailure("ATTACHMENT_METADATA_MISMATCH")

    try:
        validate_policy_attachment(package_files[ATTACHMENT_PATHS["policy"]], receipt)
    except StrictJSONError as error:
        raise _VerificationFailure("PACKAGE_JSON_INVALID") from error
    except (EvidencePackageError, ValueError, KeyError, TypeError) as error:
        raise _VerificationFailure("POLICY_ATTACHMENT_MISMATCH") from error
    try:
        validate_bundle_attachment(package_files[ATTACHMENT_PATHS["bundle"]], receipt)
    except StrictJSONError as error:
        raise _VerificationFailure("PACKAGE_JSON_INVALID") from error
    except (EvidencePackageError, ValueError, KeyError, TypeError) as error:
        raise _VerificationFailure("BUNDLE_ATTACHMENT_MISMATCH") from error
    try:
        children = validate_oci_attachment(
            package_files[ATTACHMENT_PATHS["oci"]], receipt
        )
    except StrictJSONError as error:
        raise _VerificationFailure("PACKAGE_JSON_INVALID") from error
    except (EvidencePackageError, ValueError, KeyError, TypeError) as error:
        raise _VerificationFailure("OCI_MANIFEST_MISMATCH") from error

    for pod in receipt["evidence"]["pods"]:
        if pod["digest_relation"] == "index_child":
            runtime_digest = pod["image_id"].rsplit("@", 1)[-1]
            if runtime_digest not in children:
                raise _VerificationFailure("OCI_CHILD_MISSING")


def _read_package_files(package_path: str | Path) -> dict[str, bytes]:
    if os.name != "posix":
        return _read_package_files_windows(package_path)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        root_descriptor = os.open(package_path, flags)
    except OSError as error:
        raise _VerificationFailure("PACKAGE_FILE_INVALID") from error
    try:
        if not stat.S_ISDIR(os.fstat(root_descriptor).st_mode):
            raise _VerificationFailure("PACKAGE_FILE_INVALID")
        if set(os.listdir(root_descriptor)) != PACKAGE_FILENAMES:
            raise _VerificationFailure("PACKAGE_FILE_SET_INVALID")
        package_files: dict[str, bytes] = {}
        total = 0
        for name, limit in PACKAGE_FILE_LIMITS.items():
            file_flags = (
                os.O_RDONLY
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
            )
            try:
                descriptor = os.open(name, file_flags, dir_fd=root_descriptor)
            except OSError as error:
                raise _VerificationFailure("PACKAGE_FILE_INVALID") from error
            try:
                raw = _read_bounded_descriptor(descriptor, limit)
            finally:
                os.close(descriptor)
            package_files[name] = raw
            total += len(raw)
            if total > MAX_PACKAGE_TOTAL_BYTES:
                raise _VerificationFailure("PACKAGE_TOTAL_TOO_LARGE")
        if set(os.listdir(root_descriptor)) != PACKAGE_FILENAMES:
            raise _VerificationFailure("PACKAGE_FILE_SET_INVALID")
        return package_files
    except _FileTooLarge as error:
        raise _VerificationFailure("PACKAGE_FILE_TOO_LARGE") from error
    except StrictJSONError as error:
        raise _VerificationFailure("PACKAGE_FILE_INVALID") from error
    except OSError as error:
        raise _VerificationFailure("PACKAGE_FILE_INVALID") from error
    finally:
        os.close(root_descriptor)


def _read_package_files_windows(package_path: str | Path) -> dict[str, bytes]:
    try:
        root = os.fspath(package_path)
        root_before = os.lstat(root)
        if not stat.S_ISDIR(root_before.st_mode):
            raise _VerificationFailure("PACKAGE_FILE_INVALID")
        if set(os.listdir(root)) != PACKAGE_FILENAMES:
            raise _VerificationFailure("PACKAGE_FILE_SET_INVALID")
        package_files: dict[str, bytes] = {}
        total = 0
        for name, limit in PACKAGE_FILE_LIMITS.items():
            path = os.path.join(root, name)
            before = os.lstat(path)
            if not stat.S_ISREG(before.st_mode):
                raise _VerificationFailure("PACKAGE_FILE_INVALID")
            file_flags = (
                os.O_RDONLY
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
            )
            descriptor = os.open(path, file_flags)
            try:
                raw = _read_bounded_descriptor(descriptor, limit)
            finally:
                os.close(descriptor)
            after = os.lstat(path)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise _VerificationFailure("PACKAGE_FILE_INVALID")
            package_files[name] = raw
            total += len(raw)
            if total > MAX_PACKAGE_TOTAL_BYTES:
                raise _VerificationFailure("PACKAGE_TOTAL_TOO_LARGE")
        root_after = os.lstat(root)
        if (root_before.st_dev, root_before.st_ino) != (
            root_after.st_dev,
            root_after.st_ino,
        ):
            raise _VerificationFailure("PACKAGE_FILE_INVALID")
        if set(os.listdir(root)) != PACKAGE_FILENAMES:
            raise _VerificationFailure("PACKAGE_FILE_SET_INVALID")
        return package_files
    except _FileTooLarge as error:
        raise _VerificationFailure("PACKAGE_FILE_TOO_LARGE") from error
    except StrictJSONError as error:
        raise _VerificationFailure("PACKAGE_FILE_INVALID") from error
    except OSError as error:
        raise _VerificationFailure("PACKAGE_FILE_INVALID") from error


def _read_bounded_descriptor(descriptor: int, limit: int) -> bytes:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise StrictJSONError("Consumer input must be a regular file.")
    if before.st_size > limit:
        raise _FileTooLarge("Consumer input exceeds its size limit.")
    chunks = []
    remaining = limit + 1
    while remaining:
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(chunks)
    after = os.fstat(descriptor)
    if len(raw) > limit:
        raise _FileTooLarge("Consumer input exceeds its size limit.")
    if (
        not stat.S_ISREG(after.st_mode)
        or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
        or before.st_size != len(raw)
        or after.st_size != len(raw)
    ):
        raise StrictJSONError("Consumer input changed or is not a regular file.")
    return raw


def _early_package_decision(reason: str, now: datetime) -> dict[str, Any]:
    decision, consumer_now = _new_decision(None, now)
    decision["reason"] = (
        "CONSUMER_TIME_INVALID" if consumer_now is None else reason
    )
    return decision


def _new_decision(receipt: Any, now: datetime) -> tuple[dict[str, Any], datetime | None]:
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
    return decision, consumer_now


def _sha256(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


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
    if receipt["evidence_truncation"]:
        raise _VerificationFailure("EVIDENCE_TRUNCATED")
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
