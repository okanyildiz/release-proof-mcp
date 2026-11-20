from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import stat
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from conftest import (
    CHILD_DIGEST,
    DIGEST,
    INDEX_DIGEST,
    MANIFEST,
    Harness,
    approvals_object,
    attestation_result,
    pod_object,
    policy_store,
)
from release_proof_mcp import evidence_package as package_module
from release_proof_mcp.consumer import verify_evidence_package, verify_receipt
from release_proof_mcp.evidence_package import (
    ATTACHMENT_PATHS,
    BUNDLE_FILE,
    EVIDENCE_PACKAGE_SCHEMA_VERSION,
    MANIFEST_FILE,
    OCI_FILE,
    PACKAGE_FILE_LIMITS,
    PACKAGE_FILENAMES,
    POLICY_FILE,
    RECEIPT_FILE,
    EvidencePackageError,
    evidence_package_validator,
    export_evidence_package,
    prepare_evidence_package,
)
from release_proof_mcp.mcp import MCPServer
from release_proof_mcp.policy import TrustedPolicy
from release_proof_mcp.receipt_validation import canonical_json_bytes, validate_receipt
from release_proof_mcp.request import VerificationRequest
from release_proof_mcp.signing import sign_receipt
from release_proof_mcp.verifier import ReleaseVerifier, VerificationArtifacts
from test_signed_mcp import call_receipt
from test_signing import (
    FIXED_NOW,
    ISSUER,
    KEYID,
    NONCE,
    PRIVATE_KEY,
    nonverified_receipt,
    resign_unchecked,
)


@dataclass
class PackageCase:
    path: Path
    receipt: dict[str, Any]
    options: dict[str, Any]


def sha256(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def set_valid_attestation(harness: Harness, digest: str = DIGEST) -> None:
    result = attestation_result(digest)
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": "ghcr.io/acme/shop",
                "digest": {"sha256": digest.removeprefix("sha256:")},
            }
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "resolvedDependencies": [{"digest": {"sha1": "untrusted"}}]
            }
        },
    }
    envelope = result["attestation"]["bundle"]["dsseEnvelope"]
    envelope["payload"] = base64.b64encode(canonical_json_bytes(statement)).decode("ascii")
    harness.set_attestation([result], digest=digest)


def detailed(harness: Harness) -> tuple[dict[str, Any], VerificationArtifacts]:
    request = VerificationRequest.from_dict(copy.deepcopy(harness.request))
    policy = TrustedPolicy.from_dict("production", copy.deepcopy(harness.policy))
    verifier = ReleaseVerifier(harness.runner, clock=lambda: FIXED_NOW)
    return verifier.verify_detailed(request, policy)


def publish(harness: Harness, root: Path, *, digest: str = DIGEST) -> PackageCase:
    harness.request["consumer_nonce"] = NONCE
    set_valid_attestation(harness, digest)
    receipt, artifacts = detailed(harness)
    signed = export_evidence_package(
        receipt,
        artifacts,
        PRIVATE_KEY,
        ISSUER,
        KEYID,
        root,
        clock=lambda: FIXED_NOW,
    )
    options = {
        "trusted_public_keys": {KEYID: PRIVATE_KEY.public_key()},
        "expected_issuer": ISSUER,
        "expected_subject": copy.deepcopy(signed["subject"]),
        "expected_policy_hash": signed["policy_hash"],
        "expected_verifier": copy.deepcopy(signed["verifier"]),
        "expected_nonce": NONCE,
        "now": FIXED_NOW,
        "max_age_seconds": 300,
    }
    return PackageCase(root / signed["receipt_id"], signed, options)


@pytest.fixture
def package_case(tmp_path: Path, harness: Harness) -> PackageCase:
    return publish(harness, tmp_path / "operator")


def verify(case: PackageCase, **overrides: Any) -> dict[str, Any]:
    options = copy.deepcopy(case.options)
    options.update(overrides)
    return verify_evidence_package(case.path, **options)


def write_signed(package: Path, receipt: dict[str, Any], *, unchecked: bool = False) -> None:
    unsigned = {
        key: copy.deepcopy(value)
        for key, value in receipt.items()
        if key not in {"proof", "proof_metadata"}
    }
    signed = (
        resign_unchecked(receipt)
        if unchecked
        else sign_receipt(unsigned, PRIVATE_KEY, ISSUER, KEYID, clock=lambda: FIXED_NOW)
    )
    (package / RECEIPT_FILE).write_bytes(canonical_json_bytes(signed))


def rebind_descriptor(package: Path) -> None:
    manifest_raw = (package / MANIFEST_FILE).read_bytes()
    receipt = json.loads((package / RECEIPT_FILE).read_text(encoding="utf-8"))
    receipt["evidence_package"]["manifest_sha256"] = sha256(manifest_raw)
    write_signed(package, receipt)


def refresh_manifest_attachments(package: Path) -> None:
    manifest = json.loads((package / MANIFEST_FILE).read_text(encoding="utf-8"))
    for role, name in ATTACHMENT_PATHS.items():
        raw = (package / name).read_bytes()
        manifest["attachments"][role]["size"] = len(raw)
        manifest["attachments"][role]["sha256"] = sha256(raw)
    (package / MANIFEST_FILE).write_bytes(canonical_json_bytes(manifest))
    rebind_descriptor(package)


def test_real_harness_exports_exact_signed_five_file_package(
    package_case: PackageCase,
) -> None:
    case = package_case
    assert {item.name for item in case.path.iterdir()} == PACKAGE_FILENAMES
    assert all(item.is_file() and not item.is_symlink() for item in case.path.iterdir())
    manifest_raw = (case.path / MANIFEST_FILE).read_bytes()
    manifest = json.loads(manifest_raw)
    evidence_package_validator().validate(manifest)
    assert manifest_raw == canonical_json_bytes(manifest)
    assert set(manifest) == {"schema_version", "receipt_id", "attachments"}
    assert manifest["receipt_id"] == case.receipt["receipt_id"]
    assert set(manifest["attachments"]) == {"policy", "bundle", "oci"}
    assert all(
        record["path"] not in {RECEIPT_FILE, MANIFEST_FILE}
        for record in manifest["attachments"].values()
    )
    assert case.receipt["evidence_package"] == {
        "schema_version": EVIDENCE_PACKAGE_SCHEMA_VERSION,
        "manifest_sha256": sha256(manifest_raw),
    }
    assert (case.path / OCI_FILE).read_bytes() == MANIFEST
    assert (case.path / POLICY_FILE).read_bytes() == canonical_json_bytes(
        case.receipt["effective_policy"]
    )
    bundle_raw = (case.path / BUNDLE_FILE).read_bytes()
    assert bundle_raw == canonical_json_bytes(json.loads(bundle_raw))
    assert sha256(bundle_raw) == case.receipt["evidence"]["attestation"]["bundle_sha256"]
    if os.name == "posix":
        assert stat.S_IMODE(case.path.stat().st_mode) == 0o700
        assert all(
            stat.S_IMODE(item.stat().st_mode) == 0o600
            for item in case.path.iterdir()
        )

    decision = verify(case)

    assert decision["allow"] is True
    assert decision["reason"] == "OK"


def test_verify_detailed_captures_only_accepted_artifacts(harness: Harness) -> None:
    malformed = {"verificationResult": None}
    wrong = attestation_result(sourceRepositoryDigest="f" * 40)
    valid = attestation_result()
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {"name": "ghcr.io/acme/shop", "digest": {"sha256": DIGEST[7:]}}
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {"custom": "not copied into the receipt"},
    }
    valid["attestation"]["bundle"]["dsseEnvelope"]["payload"] = base64.b64encode(
        canonical_json_bytes(statement)
    ).decode()
    harness.set_attestation([malformed, wrong, valid])

    receipt, artifacts = detailed(harness)

    assert receipt["status"] == "verified"
    assert "evidence_package" not in receipt
    assert "not copied into the receipt" not in json.dumps(receipt)
    assert artifacts.oci_manifest == MANIFEST
    assert artifacts.sigstore_bundle == canonical_json_bytes(
        valid["attestation"]["bundle"]
    )
    assert sha256(artifacts.sigstore_bundle) == receipt["evidence"]["attestation"][
        "bundle_sha256"
    ]


def test_manifest_preparation_is_deterministic_and_signing_covers_descriptor(
    harness: Harness,
) -> None:
    harness.request["consumer_nonce"] = NONCE
    set_valid_attestation(harness)
    receipt, artifacts = detailed(harness)
    original = copy.deepcopy(receipt)

    first = prepare_evidence_package(receipt, artifacts)
    second = prepare_evidence_package(receipt, artifacts)
    signed = sign_receipt(
        first.receipt,
        PRIVATE_KEY,
        ISSUER,
        KEYID,
        clock=lambda: FIXED_NOW,
    )
    payload = base64.b64decode(signed["proof"]["envelope"]["payload"], validate=True)
    statement = json.loads(payload)

    assert receipt == original
    assert first.manifest_bytes == second.manifest_bytes
    assert first.receipt == second.receipt
    assert statement["predicate"]["evidence_package"] == signed["evidence_package"]
    assert "proof" not in first.receipt


def test_package_descriptor_requires_package_for_standalone_receipt(
    package_case: PackageCase,
) -> None:
    decision = verify_receipt(package_case.receipt, **package_case.options)

    assert decision["allow"] is False
    assert decision["reason"] == "PACKAGE_REQUIRED"


@pytest.mark.parametrize("name", [POLICY_FILE, BUNDLE_FILE, OCI_FILE])
def test_every_attachment_tamper_is_denied(
    package_case: PackageCase, name: str
) -> None:
    path = package_case.path / name
    raw = bytearray(path.read_bytes())
    raw[0] ^= 1
    path.write_bytes(raw)

    decision = verify(package_case)

    assert decision["allow"] is False
    assert decision["reason"] == "ATTACHMENT_METADATA_MISMATCH"


@pytest.mark.parametrize("name", [POLICY_FILE, BUNDLE_FILE, OCI_FILE])
def test_attachment_substitution_with_rebound_manifest_is_denied(
    package_case: PackageCase, name: str
) -> None:
    path = package_case.path / name
    value = json.loads(path.read_text(encoding="utf-8"))
    if name == POLICY_FILE:
        value["version"] = "substituted"
    elif name == BUNDLE_FILE:
        value["verificationMaterial"]["substituted"] = True
    else:
        value["annotations"] = {"substituted": "true"}
    path.write_bytes(canonical_json_bytes(value))
    refresh_manifest_attachments(package_case.path)

    decision = verify(package_case)

    assert decision["allow"] is False
    assert decision["reason"] == {
        POLICY_FILE: "POLICY_ATTACHMENT_MISMATCH",
        BUNDLE_FILE: "BUNDLE_ATTACHMENT_MISMATCH",
        OCI_FILE: "OCI_MANIFEST_MISMATCH",
    }[name]


def test_descriptor_tamper_fails_signature_and_rebound_wrong_digest_fails(
    package_case: PackageCase,
) -> None:
    receipt = copy.deepcopy(package_case.receipt)
    receipt["evidence_package"]["manifest_sha256"] = f"sha256:{'0' * 64}"
    write_signed(package_case.path, receipt)
    unsigned_tamper = copy.deepcopy(receipt)
    unsigned_tamper["evidence_package"]["manifest_sha256"] = f"sha256:{'1' * 64}"
    (package_case.path / RECEIPT_FILE).write_bytes(
        canonical_json_bytes(unsigned_tamper)
    )

    signature_failure = verify(package_case)
    write_signed(package_case.path, receipt)
    digest_failure = verify(package_case)

    assert signature_failure["reason"] == "PAYLOAD_MISMATCH"
    assert signature_failure["allow"] is False
    assert digest_failure["reason"] == "MANIFEST_DIGEST_MISMATCH"
    assert digest_failure["allow"] is False


def test_manifest_receipt_id_and_noncanonical_encoding_are_denied(
    package_case: PackageCase,
) -> None:
    manifest_path = package_case.path / MANIFEST_FILE
    manifest = json.loads(manifest_path.read_text())
    manifest["receipt_id"] = "123e4567-e89b-42d3-a456-426614174000"
    manifest_path.write_bytes(canonical_json_bytes(manifest))
    rebind_descriptor(package_case.path)

    wrong_id = verify(package_case)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    rebind_descriptor(package_case.path)
    noncanonical = verify(package_case)

    assert wrong_id["reason"] == "RECEIPT_ID_MISMATCH"
    assert noncanonical["reason"] == "MANIFEST_INVALID"


@pytest.mark.parametrize(
    "mutation",
    ["extra_role", "extra_property", "wrong_schema", "traversal", "absolute_path"],
)
def test_manifest_schema_and_paths_are_closed(
    package_case: PackageCase, mutation: str
) -> None:
    manifest_path = package_case.path / MANIFEST_FILE
    manifest = json.loads(manifest_path.read_text())
    if mutation == "extra_role":
        manifest["attachments"]["receipt"] = {"path": "receipt.json", "size": 1, "sha256": f"sha256:{'0' * 64}"}
    elif mutation == "extra_property":
        manifest["receipt_sha256"] = f"sha256:{'0' * 64}"
    elif mutation == "wrong_schema":
        manifest["schema_version"] = "release-proof-evidence-package/v2"
    elif mutation == "traversal":
        manifest["attachments"]["policy"]["path"] = "../outside.json"
    else:
        manifest["attachments"]["policy"]["path"] = "/tmp/outside.json"
    manifest_path.write_bytes(canonical_json_bytes(manifest))
    rebind_descriptor(package_case.path)

    decision = verify(package_case)

    assert decision["allow"] is False
    assert decision["reason"] == "MANIFEST_INVALID"


@pytest.mark.parametrize("field", ["size", "sha256"])
def test_false_attachment_size_and_hash_are_denied(
    package_case: PackageCase, field: str
) -> None:
    manifest_path = package_case.path / MANIFEST_FILE
    manifest = json.loads(manifest_path.read_text())
    record = manifest["attachments"]["bundle"]
    record[field] = record["size"] + 1 if field == "size" else f"sha256:{'0' * 64}"
    manifest_path.write_bytes(canonical_json_bytes(manifest))
    rebind_descriptor(package_case.path)

    decision = verify(package_case)

    assert decision["allow"] is False
    assert decision["reason"] == "ATTACHMENT_METADATA_MISMATCH"


@pytest.mark.parametrize("name", sorted(PACKAGE_FILENAMES))
def test_missing_file_is_denied(package_case: PackageCase, name: str) -> None:
    (package_case.path / name).unlink()

    decision = verify(package_case)

    assert decision["allow"] is False
    assert decision["reason"] == "PACKAGE_FILE_SET_INVALID"


@pytest.mark.parametrize("kind", ["file", "directory", "zip"])
def test_extra_entries_and_archives_are_denied(
    package_case: PackageCase, kind: str
) -> None:
    extra = package_case.path / f"extra.{kind}"
    if kind == "directory":
        extra.mkdir()
    else:
        extra.write_bytes(b"PK\x03\x04" if kind == "zip" else b"extra")

    decision = verify(package_case)

    assert decision["allow"] is False
    assert decision["reason"] == "PACKAGE_FILE_SET_INVALID"


@pytest.mark.parametrize("kind", ["symlink", "directory", "fifo"])
def test_nonregular_or_following_attachment_is_denied(
    package_case: PackageCase, kind: str, tmp_path: Path
) -> None:
    if kind == "fifo" and not hasattr(os, "mkfifo"):
        pytest.skip("FIFOs are not available on this host")
    target = package_case.path / POLICY_FILE
    outside = tmp_path / "outside.json"
    outside.write_bytes(target.read_bytes())
    target.unlink()
    if kind == "symlink":
        target.symlink_to(outside)
    elif kind == "directory":
        target.mkdir()
    else:
        os.mkfifo(target)

    decision = verify(package_case)

    assert decision["allow"] is False
    assert decision["reason"] == "PACKAGE_FILE_INVALID"
    assert outside.read_bytes() == canonical_json_bytes(
        package_case.receipt["effective_policy"]
    )


def test_package_root_symlink_is_not_followed(
    package_case: PackageCase, tmp_path: Path
) -> None:
    link = tmp_path / "package-link"
    link.symlink_to(package_case.path, target_is_directory=True)
    options = copy.deepcopy(package_case.options)

    decision = verify_evidence_package(link, **options)

    assert decision["allow"] is False
    assert decision["reason"] == "PACKAGE_FILE_INVALID"


@pytest.mark.parametrize("name", sorted(PACKAGE_FILENAMES))
@pytest.mark.parametrize(
    "raw",
    [
        b'{"key":1,"key":2}',
        b'{"key":1,"\\u006bey":2}',
        b"\xff",
        b'{"number":NaN}',
        b'{"number":1e999}',
        b'{"value":' + b"[" * 70 + b"0" + b"]" * 70 + b"}",
    ],
)
def test_package_json_is_strictly_bounded_and_parsed(
    package_case: PackageCase, name: str, raw: bytes
) -> None:
    (package_case.path / name).write_bytes(raw)
    if name in ATTACHMENT_PATHS.values():
        refresh_manifest_attachments(package_case.path)
    elif name == MANIFEST_FILE and raw.startswith(b'{"key"'):
        rebind_descriptor(package_case.path)

    decision = verify(package_case)

    assert decision["allow"] is False
    assert decision["reason"] == "PACKAGE_JSON_INVALID"


@pytest.mark.parametrize("name", sorted(PACKAGE_FILENAMES))
@pytest.mark.parametrize("extra", [0, 1])
def test_exact_and_one_over_file_size_boundaries(
    package_case: PackageCase, name: str, extra: int
) -> None:
    limit = PACKAGE_FILE_LIMITS[name]
    (package_case.path / name).write_bytes(b" " * (limit + extra))

    decision = verify(package_case)

    assert decision["allow"] is False
    if extra:
        assert decision["reason"] == "PACKAGE_FILE_TOO_LARGE"
    else:
        assert decision["reason"] != "PACKAGE_FILE_TOO_LARGE"


@pytest.mark.parametrize("mutation", ["predicate", "name", "digest"])
def test_bundle_statement_predicate_and_subject_are_checked(
    package_case: PackageCase, mutation: str
) -> None:
    bundle_path = package_case.path / BUNDLE_FILE
    bundle = json.loads(bundle_path.read_text())
    envelope = bundle["dsseEnvelope"]
    statement = json.loads(base64.b64decode(envelope["payload"], validate=True))
    if mutation == "predicate":
        statement["predicateType"] = "https://example.dev/custom"
    elif mutation == "name":
        statement["subject"][0]["name"] = "ghcr.io/acme/other"
    else:
        statement["subject"][0]["digest"]["sha256"] = "f" * 64
    envelope["payload"] = base64.b64encode(canonical_json_bytes(statement)).decode()
    bundle_path.write_bytes(canonical_json_bytes(bundle))
    receipt = copy.deepcopy(package_case.receipt)
    receipt["evidence"]["attestation"]["bundle_sha256"] = sha256(
        bundle_path.read_bytes()
    )
    write_signed(package_case.path, receipt)
    refresh_manifest_attachments(package_case.path)

    decision = verify(package_case)

    assert decision["allow"] is False
    assert decision["reason"] == "BUNDLE_ATTACHMENT_MISMATCH"


def test_oci_media_type_mismatch_is_denied(package_case: PackageCase) -> None:
    receipt = copy.deepcopy(package_case.receipt)
    receipt["evidence"]["registry"]["media_type"] = (
        "application/vnd.oci.image.index.v1+json"
    )
    write_signed(package_case.path, receipt)

    decision = verify(package_case)

    assert decision["allow"] is False
    assert decision["reason"] == "OCI_MANIFEST_MISMATCH"


@pytest.mark.parametrize("runtime_digest", [INDEX_DIGEST, CHILD_DIGEST])
def test_direct_and_index_child_oci_packages_are_allowed(
    tmp_path: Path, harness: Harness, runtime_digest: str
) -> None:
    harness.use_index(runtime_digest=runtime_digest)
    harness.request["consumer_nonce"] = NONCE
    set_valid_attestation(harness, INDEX_DIGEST)
    receipt, artifacts = detailed(harness)
    signed = export_evidence_package(
        receipt,
        artifacts,
        PRIVATE_KEY,
        ISSUER,
        KEYID,
        tmp_path / "operator",
        clock=lambda: FIXED_NOW,
    )
    options = {
        "trusted_public_keys": {KEYID: PRIVATE_KEY.public_key()},
        "expected_issuer": ISSUER,
        "expected_subject": signed["subject"],
        "expected_policy_hash": signed["policy_hash"],
        "expected_verifier": signed["verifier"],
        "expected_nonce": NONCE,
        "now": FIXED_NOW,
        "max_age_seconds": 300,
    }

    decision = verify_evidence_package(tmp_path / "operator" / signed["receipt_id"], **options)

    assert decision["allow"] is True
    assert decision["reason"] == "OK"


def test_index_child_absent_from_exact_oci_bytes_is_denied(
    tmp_path: Path, harness: Harness
) -> None:
    harness.use_index(runtime_digest=INDEX_DIGEST)
    case = publish(harness, tmp_path / "operator", digest=INDEX_DIGEST)
    receipt = copy.deepcopy(case.receipt)
    pod = receipt["evidence"]["pods"][0]
    pod["digest_relation"] = "index_child"
    pod["image_id"] = f"ghcr.io/acme/shop@sha256:{'f' * 64}"
    write_signed(case.path, receipt)

    decision = verify(case)

    assert decision["allow"] is False
    assert decision["reason"] == "OCI_CHILD_MISSING"


@pytest.mark.parametrize(
    ("override", "reason"),
    [
        ({"expected_issuer": "https://issuer.example/other"}, "ISSUER_MISMATCH"),
        ({"expected_nonce": "Ab09_-abcdefghijklmnopqrstuv"}, "NONCE_MISMATCH"),
        ({"expected_policy_hash": f"sha256:{'2' * 64}"}, "POLICY_MISMATCH"),
        ({"now": FIXED_NOW + timedelta(seconds=301)}, "RECEIPT_STALE"),
        ({"trusted_public_keys": {}}, "KEY_NOT_TRUSTED"),
        (
            {
                "trusted_public_keys": {
                    KEYID: Ed25519PrivateKey.from_private_bytes(b"\x99" * 32).public_key()
                }
            },
            "SIGNATURE_INVALID",
        ),
    ],
)
def test_package_enforces_issuer_nonce_policy_freshness_and_key(
    package_case: PackageCase, override: dict[str, Any], reason: str
) -> None:
    decision = verify(package_case, **override)

    assert decision["allow"] is False
    assert decision["reason"] == reason


@pytest.mark.parametrize("kind", ["subject", "verifier"])
def test_package_enforces_full_subject_and_verifier(
    package_case: PackageCase, kind: str
) -> None:
    expected = copy.deepcopy(package_case.receipt[kind])
    if kind == "subject":
        expected["deployment"] = "other"
        override = {"expected_subject": expected}
        reason = "SUBJECT_MISMATCH"
    else:
        expected["version"] = "other"
        override = {"expected_verifier": expected}
        reason = "VERIFIER_MISMATCH"

    decision = verify(package_case, **override)

    assert decision["allow"] is False
    assert decision["reason"] == reason


@pytest.mark.parametrize("status", ["failed", "unknown"])
def test_failed_and_unknown_package_receipts_are_denied(
    package_case: PackageCase, status: str
) -> None:
    signed = sign_receipt(
        nonverified_receipt(status),
        PRIVATE_KEY,
        ISSUER,
        KEYID,
        clock=lambda: FIXED_NOW,
    )
    (package_case.path / RECEIPT_FILE).write_bytes(canonical_json_bytes(signed))

    decision = verify(package_case)

    assert decision["allow"] is False
    assert decision["reason"] == "STATUS_NOT_VERIFIED"


def test_truncated_signed_descriptor_is_denied(package_case: PackageCase) -> None:
    receipt = copy.deepcopy(package_case.receipt)
    receipt["evidence_truncation"] = {
        "pods": {"retained": 100, "omitted": 1}
    }
    write_signed(package_case.path, receipt, unchecked=True)

    decision = verify(package_case)

    assert decision["allow"] is False
    assert decision["reason"] == "RECEIPT_INVALID"


def test_producer_rejects_real_truncated_receipt_without_output(
    tmp_path: Path, harness: Harness
) -> None:
    harness.set_approvals(approvals_object() * 101)
    set_valid_attestation(harness)
    receipt, artifacts = detailed(harness)
    assert receipt["status"] == "verified"
    assert receipt["evidence_truncation"]
    root = tmp_path / "operator"

    with pytest.raises(EvidencePackageError):
        export_evidence_package(
            receipt, artifacts, PRIVATE_KEY, ISSUER, KEYID, root
        )

    assert not root.exists()


@pytest.mark.parametrize("status", ["failed", "unknown"])
def test_producer_exports_only_verified_receipts(
    tmp_path: Path, harness: Harness, status: str
) -> None:
    if status == "failed":
        harness.set_attestation([], returncode=1, stderr="no attestations found")
    else:
        harness.runner.route(["gh", "--version"], "gh version 2.101.0")
    receipt, artifacts = detailed(harness)
    assert receipt["status"] == status
    root = tmp_path / "operator"

    with pytest.raises(EvidencePackageError):
        export_evidence_package(
            receipt, artifacts, PRIVATE_KEY, ISSUER, KEYID, root
        )

    assert not root.exists()


def test_export_requires_signing_and_complete_artifacts(
    tmp_path: Path, harness: Harness
) -> None:
    set_valid_attestation(harness)
    receipt, artifacts = detailed(harness)

    with pytest.raises(EvidencePackageError):
        export_evidence_package(
            receipt, artifacts, None, ISSUER, KEYID, tmp_path / "operator"
        )
    with pytest.raises(EvidencePackageError):
        prepare_evidence_package(receipt, VerificationArtifacts())

    assert not (tmp_path / "operator").exists()


@pytest.mark.parametrize("failure", ["sign", "write", "rename"])
def test_signing_write_and_rename_failures_leave_no_partial_package(
    tmp_path: Path,
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    set_valid_attestation(harness)
    receipt, artifacts = detailed(harness)
    root = tmp_path / "operator"
    if failure == "sign":
        def fail_signing(*args: Any, **kwargs: Any) -> dict[str, Any]:
            raise ValueError("signing failed")
        monkeypatch.setattr(package_module, "sign_receipt", fail_signing)
    elif failure == "write":
        def fail_write(*args: Any) -> None:
            raise OSError("write failed")
        monkeypatch.setattr(package_module, "_write_new_file", fail_write)
    else:
        def fail_rename(*args: Any) -> None:
            raise OSError("rename failed")
        monkeypatch.setattr(package_module.os, "rename", fail_rename)

    with pytest.raises((OSError, ValueError)):
        export_evidence_package(
            receipt, artifacts, PRIVATE_KEY, ISSUER, KEYID, root
        )

    assert not root.exists() or list(root.iterdir()) == []


def test_existing_package_is_never_overwritten(
    tmp_path: Path, harness: Harness
) -> None:
    set_valid_attestation(harness)
    receipt, artifacts = detailed(harness)
    final = tmp_path / "operator" / receipt["receipt_id"]
    final.mkdir(parents=True)
    sentinel = final / "keep.txt"
    sentinel.write_text("unchanged", encoding="utf-8")

    with pytest.raises((OSError, ValueError)):
        export_evidence_package(
            receipt,
            artifacts,
            PRIVATE_KEY,
            ISSUER,
            KEYID,
            tmp_path / "operator",
        )

    assert sentinel.read_text(encoding="utf-8") == "unchanged"
    assert {item.name for item in final.iterdir()} == {"keep.txt"}


def test_mcp_operator_root_uses_same_detailed_signing_path(
    tmp_path: Path, harness: Harness
) -> None:
    set_valid_attestation(harness)
    root = tmp_path / "operator"
    server = MCPServer(
        lambda: ReleaseVerifier(harness.runner),
        policy_store=policy_store(),
        signer=PRIVATE_KEY,
        signing_issuer=ISSUER,
        signing_keyid=KEYID,
        evidence_package_root=root,
    )

    response = call_receipt(server)

    assert "result" in response, response
    receipt = response["result"]["structuredContent"]
    package = root / receipt["receipt_id"]
    assert receipt["evidence_package"]["schema_version"] == EVIDENCE_PACKAGE_SCHEMA_VERSION
    assert {item.name for item in package.iterdir()} == PACKAGE_FILENAMES
    assert json.loads((package / RECEIPT_FILE).read_text()) == receipt


def test_mcp_package_root_requires_signing(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        MCPServer(policy_store=policy_store(), evidence_package_root=tmp_path)


@pytest.mark.parametrize(
    "descriptor",
    [
        None,
        {},
        {
            "schema_version": "release-proof-evidence-package/v2",
            "manifest_sha256": f"sha256:{'0' * 64}",
        },
        {
            "schema_version": EVIDENCE_PACKAGE_SCHEMA_VERSION,
            "manifest_sha256": f"sha256:{'A' * 64}",
        },
        {
            "schema_version": EVIDENCE_PACKAGE_SCHEMA_VERSION,
            "manifest_sha256": f"sha256:{'0' * 64}",
            "path": "caller-selected",
        },
    ],
)
def test_invalid_optional_descriptor_cannot_be_signed(
    package_case: PackageCase, descriptor: Any
) -> None:
    receipt = {
        key: copy.deepcopy(value)
        for key, value in package_case.receipt.items()
        if key not in {"proof", "proof_metadata"}
    }
    receipt["evidence_package"] = descriptor

    with pytest.raises(ValueError):
        sign_receipt(receipt, PRIVATE_KEY, ISSUER, KEYID)


def test_truncation_metadata_must_match_retained_arrays(
    package_case: PackageCase,
) -> None:
    receipt = {
        key: copy.deepcopy(value)
        for key, value in package_case.receipt.items()
        if key not in {"proof", "proof_metadata", "evidence_package"}
    }
    receipt["evidence_truncation"] = {"pods": {"retained": 1, "omitted": 1}}

    with pytest.raises(ValueError):
        sign_receipt(receipt, PRIVATE_KEY, ISSUER, KEYID)


def test_package_directory_with_ordinary_receipt_requires_descriptor(
    package_case: PackageCase,
) -> None:
    receipt = copy.deepcopy(package_case.receipt)
    del receipt["evidence_package"]
    write_signed(package_case.path, receipt)

    decision = verify(package_case)

    assert decision["allow"] is False
    assert decision["reason"] == "PACKAGE_DESCRIPTOR_MISSING"


@pytest.mark.parametrize("artifact", ["bundle", "oci"])
def test_prepare_rejects_artifact_hash_substitution(
    harness: Harness, artifact: str
) -> None:
    set_valid_attestation(harness)
    receipt, artifacts = detailed(harness)
    if artifact == "bundle":
        bundle = json.loads(artifacts.sigstore_bundle)
        bundle["verificationMaterial"]["substituted"] = True
        artifacts.sigstore_bundle = canonical_json_bytes(bundle)
    else:
        artifacts.oci_manifest = MANIFEST + b"\n"

    with pytest.raises(ValueError):
        prepare_evidence_package(receipt, artifacts)


def test_receipt_size_failure_happens_before_publication(
    tmp_path: Path, harness: Harness
) -> None:
    set_valid_attestation(harness)
    receipt, artifacts = detailed(harness)
    root = tmp_path / "operator"

    with pytest.raises(EvidencePackageError):
        export_evidence_package(
            receipt,
            artifacts,
            PRIVATE_KEY,
            ISSUER,
            KEYID,
            root,
            max_receipt_bytes=1024,
        )

    assert not root.exists()


def test_mcp_signing_failure_returns_no_claim_or_partial_package(
    tmp_path: Path,
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    set_valid_attestation(harness)
    root = tmp_path / "operator"

    def fail_signing(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise ValueError("signing failed")

    monkeypatch.setattr(package_module, "sign_receipt", fail_signing)
    server = MCPServer(
        lambda: ReleaseVerifier(harness.runner),
        policy_store=policy_store(),
        signer=PRIVATE_KEY,
        signing_issuer=ISSUER,
        signing_keyid=KEYID,
        evidence_package_root=root,
    )

    response = call_receipt(server)

    assert response["error"]["code"] == -32603
    assert "result" not in response
    assert not root.exists()


def assert_signed_audit_result(
    response: dict[str, Any], root: Path, status: str
) -> dict[str, Any]:
    assert "error" not in response
    assert "result" in response
    result = response["result"]
    receipt = result["structuredContent"]
    assert result["isError"] is False
    assert json.loads(result["content"][0]["text"]) == receipt
    assert receipt["status"] == status
    assert receipt["consumer_nonce"] == NONCE
    assert isinstance(receipt["proof"], dict)
    assert isinstance(receipt["proof_metadata"], dict)
    assert "evidence_package" not in receipt
    validate_receipt(receipt, require_proof=True)
    assert not root.exists()
    return receipt


@pytest.mark.parametrize("status", ["failed", "unknown"])
def test_mcp_package_root_returns_signed_failed_and_unknown_audit_receipts(
    tmp_path: Path, harness: Harness, status: str
) -> None:
    if status == "failed":
        harness.set_attestation([], returncode=1, stderr="no attestations found")
    else:
        harness.runner.route(["gh", "--version"], "gh version 2.101.0")
    root = tmp_path / "operator"
    server = MCPServer(
        lambda: ReleaseVerifier(harness.runner),
        policy_store=policy_store(),
        signer=PRIVATE_KEY,
        signing_issuer=ISSUER,
        signing_keyid=KEYID,
        evidence_package_root=root,
    )

    response = call_receipt(server)

    receipt = assert_signed_audit_result(response, root, status)
    statuses = {check["status"] for check in receipt["checks"]}
    if status == "failed":
        assert "failed" in statuses
        assert receipt["reasons"]
    else:
        assert "failed" not in statuses
        assert "unknown" in statuses
        assert receipt["missing_coverage"]


def test_mcp_package_root_returns_signed_truncated_audit_receipt(
    tmp_path: Path, harness: Harness
) -> None:
    pods = [
        pod_object(uid=f"pod-{index}", name=f"shop-api-abc-{index}")
        for index in range(101)
    ]
    harness.set_runtime(pods={"items": pods})
    root = tmp_path / "operator"
    server = MCPServer(
        lambda: ReleaseVerifier(harness.runner),
        policy_store=policy_store(),
        signer=PRIVATE_KEY,
        signing_issuer=ISSUER,
        signing_keyid=KEYID,
        evidence_package_root=root,
    )

    response = call_receipt(server)

    receipt = assert_signed_audit_result(response, root, "unknown")
    assert receipt["evidence_truncation"] == {
        "pods": {"retained": 100, "omitted": 1}
    }
    assert len(receipt["evidence"]["pods"]) == 100
    assert receipt["missing_coverage"]
