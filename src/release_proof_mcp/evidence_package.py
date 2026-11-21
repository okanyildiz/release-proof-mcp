from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import Any, Callable, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError

from .receipt_validation import (
    canonical_json_bytes,
    pinned_ghcr_artifact,
    validate_receipt,
)
from .signing import (
    PAYLOAD_TYPE,
    STATEMENT_TYPE,
    ReceiptSigner,
    sign_receipt,
)
from .strict_json import StrictJSONError, strict_json_loads
from .verifier import (
    INDEX_MEDIA_TYPES,
    MANIFEST_MEDIA_TYPES,
    VerificationArtifacts,
)

EVIDENCE_PACKAGE_SCHEMA_VERSION = "release-proof-evidence-package/v1"
RECEIPT_FILE = "receipt.json"
MANIFEST_FILE = "manifest.json"
POLICY_FILE = "effective-policy.json"
BUNDLE_FILE = "sigstore-bundle.json"
OCI_FILE = "oci-manifest.json"
PACKAGE_FILENAMES = frozenset(
    {RECEIPT_FILE, MANIFEST_FILE, POLICY_FILE, BUNDLE_FILE, OCI_FILE}
)
ATTACHMENT_PATHS = {
    "policy": POLICY_FILE,
    "bundle": BUNDLE_FILE,
    "oci": OCI_FILE,
}
PACKAGE_FILE_LIMITS = {
    RECEIPT_FILE: 2 * 1024 * 1024,
    POLICY_FILE: 1024 * 1024,
    MANIFEST_FILE: 64 * 1024,
    BUNDLE_FILE: 8 * 1024 * 1024,
    OCI_FILE: 8 * 1024 * 1024,
}
MAX_PACKAGE_TOTAL_BYTES = 20 * 1024 * 1024
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")


class EvidencePackageError(ValueError):
    pass


@dataclass(frozen=True)
class PreparedEvidencePackage:
    receipt: dict[str, Any]
    manifest: dict[str, Any]
    manifest_bytes: bytes
    policy_bytes: bytes
    bundle_bytes: bytes
    oci_bytes: bytes


@lru_cache(maxsize=1)
def evidence_package_validator() -> Draft202012Validator:
    schema = json.loads(
        files("release_proof_mcp")
        .joinpath("schemas/evidence-package-v1.json")
        .read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def validate_evidence_manifest(manifest: Any) -> None:
    try:
        canonical_json_bytes(manifest)
        evidence_package_validator().validate(manifest)
    except (ValueError, JsonSchemaValidationError, RecursionError) as error:
        raise EvidencePackageError("Evidence package manifest is invalid.") from error


def prepare_evidence_package(
    receipt: Mapping[str, Any],
    artifacts: VerificationArtifacts,
) -> PreparedEvidencePackage:
    if not isinstance(receipt, dict) or not isinstance(artifacts, VerificationArtifacts):
        raise EvidencePackageError("A receipt and detailed verification artifacts are required.")
    if "proof" in receipt or "proof_metadata" in receipt or "evidence_package" in receipt:
        raise EvidencePackageError("Package preparation requires an unsigned ordinary v2 receipt.")
    try:
        validate_receipt(receipt)
    except (ValueError, TypeError) as error:
        raise EvidencePackageError("The receipt is not valid for package export.") from error
    if receipt["status"] != "verified" or receipt["evidence_truncation"]:
        raise EvidencePackageError("Only verified, non-truncated receipts can be exported.")

    policy_bytes = canonical_json_bytes(receipt["effective_policy"])
    bundle_bytes = artifacts.sigstore_bundle
    oci_bytes = artifacts.oci_manifest
    if not isinstance(bundle_bytes, bytes) or not isinstance(oci_bytes, bytes):
        raise EvidencePackageError("The accepted Sigstore bundle and exact OCI bytes are required.")
    validate_policy_attachment(policy_bytes, receipt)
    validate_bundle_attachment(bundle_bytes, receipt)
    validate_oci_attachment(oci_bytes, receipt)

    manifest = {
        "schema_version": EVIDENCE_PACKAGE_SCHEMA_VERSION,
        "receipt_id": receipt["receipt_id"],
        "attachments": {
            role: _attachment(path, raw)
            for role, path, raw in (
                ("policy", POLICY_FILE, policy_bytes),
                ("bundle", BUNDLE_FILE, bundle_bytes),
                ("oci", OCI_FILE, oci_bytes),
            )
        },
    }
    validate_evidence_manifest(manifest)
    manifest_bytes = canonical_json_bytes(manifest)
    prepared_receipt = copy.deepcopy(receipt)
    prepared_receipt["evidence_package"] = {
        "schema_version": EVIDENCE_PACKAGE_SCHEMA_VERSION,
        "manifest_sha256": _sha256(manifest_bytes),
    }
    try:
        validate_receipt(prepared_receipt)
    except (ValueError, TypeError) as error:
        raise EvidencePackageError("The evidence package descriptor is invalid.") from error
    prepared = PreparedEvidencePackage(
        receipt=prepared_receipt,
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        policy_bytes=policy_bytes,
        bundle_bytes=bundle_bytes,
        oci_bytes=oci_bytes,
    )
    _check_bounds(
        {
            MANIFEST_FILE: manifest_bytes,
            POLICY_FILE: policy_bytes,
            BUNDLE_FILE: bundle_bytes,
            OCI_FILE: oci_bytes,
        }
    )
    return prepared


def export_evidence_package(
    receipt: Mapping[str, Any],
    artifacts: VerificationArtifacts,
    signer: Ed25519PrivateKey | ReceiptSigner,
    issuer: str,
    keyid: str,
    operator_root: str | os.PathLike[str],
    *,
    clock: Callable[[], datetime] | None = None,
    cancel_event: threading.Event | None = None,
    max_receipt_bytes: int = PACKAGE_FILE_LIMITS[RECEIPT_FILE],
) -> dict[str, Any]:
    if signer is None:
        raise EvidencePackageError("Evidence package export requires signing.")
    prepared = prepare_evidence_package(receipt, artifacts)
    signed = sign_receipt(
        prepared.receipt,
        signer,
        issuer,
        keyid,
        clock,
        cancel_event=cancel_event,
    )
    publish_evidence_package(
        prepared,
        signed,
        operator_root,
        max_receipt_bytes=max_receipt_bytes,
    )
    return signed


def publish_evidence_package(
    prepared: PreparedEvidencePackage,
    signed_receipt: Mapping[str, Any],
    operator_root: str | os.PathLike[str],
    *,
    max_receipt_bytes: int = PACKAGE_FILE_LIMITS[RECEIPT_FILE],
) -> Path:
    if not isinstance(prepared, PreparedEvidencePackage) or not isinstance(signed_receipt, dict):
        raise EvidencePackageError("A prepared package and signed receipt are required.")
    if (
        isinstance(max_receipt_bytes, bool)
        or not isinstance(max_receipt_bytes, int)
        or not 1 <= max_receipt_bytes <= PACKAGE_FILE_LIMITS[RECEIPT_FILE]
    ):
        raise EvidencePackageError("The receipt size limit is invalid.")
    try:
        validate_receipt(signed_receipt, require_proof=True)
        expected = copy.deepcopy(prepared.receipt)
        expected["proof_metadata"] = signed_receipt["proof_metadata"]
        actual = {
            key: value for key, value in signed_receipt.items() if key != "proof"
        }
        if canonical_json_bytes(actual) != canonical_json_bytes(expected):
            raise EvidencePackageError("The signed receipt differs from the prepared package.")
        if prepared.manifest_bytes != canonical_json_bytes(prepared.manifest):
            raise EvidencePackageError("The prepared manifest is not canonical.")
        descriptor = signed_receipt["evidence_package"]
        if descriptor["manifest_sha256"] != _sha256(prepared.manifest_bytes):
            raise EvidencePackageError("The signed descriptor differs from the manifest.")
        validate_policy_attachment(prepared.policy_bytes, signed_receipt)
        validate_bundle_attachment(prepared.bundle_bytes, signed_receipt)
        validate_oci_attachment(prepared.oci_bytes, signed_receipt)
        receipt_bytes = canonical_json_bytes(signed_receipt)
        encoded_receipt = json.dumps(
            signed_receipt,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        if max(len(receipt_bytes), len(encoded_receipt)) > max_receipt_bytes:
            raise EvidencePackageError("The signed receipt exceeds the configured size limit.")
        package_files = {
            RECEIPT_FILE: receipt_bytes,
            MANIFEST_FILE: prepared.manifest_bytes,
            POLICY_FILE: prepared.policy_bytes,
            BUNDLE_FILE: prepared.bundle_bytes,
            OCI_FILE: prepared.oci_bytes,
        }
        _check_bounds(package_files)
        return _publish_files(
            operator_root,
            signed_receipt["receipt_id"],
            package_files,
        )
    except EvidencePackageError:
        raise
    except (KeyError, OSError, TypeError, ValueError, StrictJSONError) as error:
        raise EvidencePackageError("Evidence package publication failed.") from error


def validate_policy_attachment(raw: bytes, receipt: Mapping[str, Any]) -> None:
    policy = strict_json_loads(raw)
    if (
        canonical_json_bytes(policy) != raw
        or canonical_json_bytes(policy)
        != canonical_json_bytes(receipt["effective_policy"])
        or _sha256(raw) != receipt["policy_hash"]
    ):
        raise EvidencePackageError("The effective-policy attachment is inconsistent.")


def validate_bundle_attachment(
    raw: bytes, receipt: Mapping[str, Any]
) -> dict[str, Any]:
    bundle = strict_json_loads(raw)
    if (
        not isinstance(bundle, dict)
        or canonical_json_bytes(bundle) != raw
        or _sha256(raw) != receipt["evidence"]["attestation"].get("bundle_sha256")
    ):
        raise EvidencePackageError("The Sigstore bundle attachment is inconsistent.")
    statement = _bundle_statement(bundle)
    expected_digest = receipt["evidence"]["registry"]["digest"]
    artifact = pinned_ghcr_artifact(receipt["subject"]["pinned_artifact"])
    if (
        statement.get("_type") != STATEMENT_TYPE
        or statement.get("predicateType")
        != receipt["evidence"]["attestation"].get("predicate_type")
        or artifact is None
        or artifact[1] != expected_digest.removeprefix("sha256:")
    ):
        raise EvidencePackageError("The Sigstore statement is inconsistent with the receipt.")
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or not any(
        isinstance(subject, dict)
        and subject.get("name") == artifact[0]
        and isinstance(subject.get("digest"), dict)
        and subject["digest"].get("sha256") == artifact[1]
        for subject in subjects
    ):
        raise EvidencePackageError("The Sigstore statement subject is inconsistent.")
    return statement


def validate_oci_attachment(
    raw: bytes, receipt: Mapping[str, Any]
) -> frozenset[str]:
    manifest, children = _parse_oci_manifest(raw)
    registry = receipt["evidence"]["registry"]
    if (
        _sha256(raw) != registry.get("digest")
        or manifest["mediaType"] != registry.get("media_type")
    ):
        raise EvidencePackageError("The OCI attachment is inconsistent with the receipt.")
    return children


def _bundle_statement(bundle: Mapping[str, Any]) -> dict[str, Any]:
    envelope = bundle.get("dsseEnvelope")
    if not isinstance(envelope, dict) or envelope.get("payloadType") != PAYLOAD_TYPE:
        raise EvidencePackageError("The Sigstore bundle has no in-toto DSSE statement.")
    encoded = envelope.get("payload")
    if not isinstance(encoded, str) or not encoded:
        raise EvidencePackageError("The Sigstore statement payload is missing.")
    try:
        payload = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as error:
        raise EvidencePackageError("The Sigstore statement payload is malformed.") from error
    if base64.b64encode(payload).decode("ascii") != encoded:
        raise EvidencePackageError("The Sigstore statement payload is noncanonical base64.")
    statement = strict_json_loads(payload)
    if not isinstance(statement, dict):
        raise EvidencePackageError("The Sigstore statement is not an object.")
    return statement


def _parse_oci_manifest(raw: bytes) -> tuple[dict[str, Any], frozenset[str]]:
    manifest = strict_json_loads(raw)
    if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 2:
        raise EvidencePackageError("The OCI object lacks schemaVersion 2.")
    media_type = manifest.get("mediaType")
    if media_type not in INDEX_MEDIA_TYPES | MANIFEST_MEDIA_TYPES:
        raise EvidencePackageError("The OCI media type is not recognized.")
    children: frozenset[str] = frozenset()
    if media_type in INDEX_MEDIA_TYPES:
        if "config" in manifest or "layers" in manifest:
            raise EvidencePackageError("An OCI index cannot contain config or layers.")
        descriptors = manifest.get("manifests")
        if not isinstance(descriptors, list):
            raise EvidencePackageError("The OCI index manifests field is invalid.")
        digests = []
        for descriptor in descriptors:
            digest = descriptor.get("digest") if isinstance(descriptor, dict) else None
            if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
                raise EvidencePackageError("An OCI child descriptor digest is invalid.")
            digests.append(digest)
        children = frozenset(digests)
    else:
        if "manifests" in manifest:
            raise EvidencePackageError("An image manifest cannot contain an index.")
        if not isinstance(manifest.get("config"), dict) or not isinstance(
            manifest.get("layers"), list
        ):
            raise EvidencePackageError("An image manifest requires config and layers.")
    return manifest, children


def _attachment(path: str, raw: bytes) -> dict[str, Any]:
    return {"path": path, "size": len(raw), "sha256": _sha256(raw)}


def _sha256(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _check_bounds(package_files: Mapping[str, bytes]) -> None:
    total = 0
    for name, raw in package_files.items():
        if name not in PACKAGE_FILE_LIMITS or not isinstance(raw, bytes):
            raise EvidencePackageError("The package file set is invalid.")
        if len(raw) > PACKAGE_FILE_LIMITS[name]:
            raise EvidencePackageError("A package file exceeds its size limit.")
        total += len(raw)
    if total > MAX_PACKAGE_TOTAL_BYTES:
        raise EvidencePackageError("The package exceeds its total size limit.")


def _publish_files(
    operator_root: str | os.PathLike[str],
    receipt_id: str,
    package_files: Mapping[str, bytes],
) -> Path:
    if set(package_files) != PACKAGE_FILENAMES:
        raise EvidencePackageError("The package must contain exactly five fixed files.")
    root = Path(operator_root)
    final = root / receipt_id
    staging: Path | None = None
    lock = root / f".{receipt_id}.publish-lock"
    lock_created = False
    renamed = False
    try:
        root.mkdir(parents=True, mode=0o700, exist_ok=True)
        if root.is_symlink() or not root.is_dir():
            raise EvidencePackageError("The operator root must be a real directory.")
        root.chmod(0o700)
        os.mkdir(lock, 0o700)
        lock_created = True
        if os.path.lexists(final):
            raise FileExistsError("The evidence package already exists.")
        staging = Path(tempfile.mkdtemp(prefix=f".{receipt_id}.tmp-", dir=root))
        staging.chmod(0o700)
        for name in sorted(package_files):
            _write_new_file(staging / name, package_files[name])
        if os.path.lexists(final):
            raise FileExistsError("The evidence package already exists.")
        os.rename(staging, final)
        renamed = True
        staging = None
        return final
    except Exception:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
        if renamed:
            shutil.rmtree(final, ignore_errors=True)
        raise
    finally:
        if lock_created:
            try:
                os.rmdir(lock)
            except OSError:
                pass


def _write_new_file(path: Path, raw: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("The package file write did not advance.")
            view = view[written:]
        os.fsync(descriptor)
        mode = stat.S_IMODE(os.fstat(descriptor).st_mode)
        if os.name == "posix" and mode != 0o600:
            raise OSError("The package file permissions are invalid.")
    finally:
        os.close(descriptor)
