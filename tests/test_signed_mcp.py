from __future__ import annotations

import base64
import copy
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
)
from jsonschema import Draft202012Validator, FormatChecker

from conftest import Harness, base_input, policy_store
from release_proof_mcp import mcp as mcp_module
from release_proof_mcp.consumer import verify_receipt
from release_proof_mcp.mcp import (
    MAX_RECEIPT_BYTES,
    OPENBAO_SIGNING_ENVIRONMENT,
    MCPServer,
)
from release_proof_mcp.signing import (
    MAX_SIGNING_KEY_BYTES,
    PAYLOAD_TYPE,
    dsse_pae,
    load_ed25519_private_key,
    sign_receipt,
)
from release_proof_mcp.verifier import ReleaseVerifier
from test_mcp import initialize, request
from test_signing import unsigned_receipt

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads(
    (ROOT / "src/release_proof_mcp/schemas/receipt-v2.json").read_text(encoding="utf-8")
)
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
ISSUER = "https://issuer.example/release-proof"
KEYID = "release-proof-test-key"
NONCE = "Ab09_-abcdefghijklmnopqrst"
BUILD_DIGEST = f"sha256:{'d' * 64}"
SIGNING_ENVIRONMENT = (
    "RELEASE_PROOF_SIGNING_KEY_FILE",
    "RELEASE_PROOF_ALLOW_FILE_SIGNING_KEY",
    "RELEASE_PROOF_SIGNING_ISSUER",
    "RELEASE_PROOF_SIGNING_KEY_ID",
    *OPENBAO_SIGNING_ENVIRONMENT,
)


@pytest.fixture(autouse=True)
def clear_signing_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in SIGNING_ENVIRONMENT:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(scope="module")
def receipt_validator() -> Draft202012Validator:
    Draft202012Validator.check_schema(SCHEMA)
    return Draft202012Validator(SCHEMA, format_checker=FormatChecker())


class StaticVerifier:
    def __init__(self, receipt: dict[str, Any] | None = None) -> None:
        self.receipt = receipt

    def verify(self, request, policy, *, cancel_event, progress) -> dict:
        return copy.deepcopy(self.receipt) if self.receipt is not None else unsigned_receipt()


def call_receipt(server: MCPServer) -> dict:
    initialize(server)
    arguments = base_input()
    arguments["consumer_nonce"] = NONCE
    return server.handle(request(900, "tools/call", {
        "name": "verify_release_deployment",
        "arguments": arguments,
    }))


def real_signed_receipt(harness: Harness) -> dict:
    server = MCPServer(
        lambda: ReleaseVerifier(harness.runner),
        policy_store=policy_store(),
        signer=PRIVATE_KEY,
        signing_issuer=ISSUER,
        signing_keyid=KEYID,
    )
    response = call_receipt(server)
    assert "result" in response, response
    return response["result"]["structuredContent"]


def consumer_options(receipt: dict) -> dict[str, Any]:
    return {
        "trusted_public_keys": {KEYID: PRIVATE_KEY.public_key()},
        "expected_issuer": ISSUER,
        "expected_subject": copy.deepcopy(receipt["subject"]),
        "expected_policy_hash": receipt["policy_hash"],
        "expected_verifier": copy.deepcopy(receipt["verifier"]),
        "expected_nonce": NONCE,
        "now": datetime.now(timezone.utc),
        "max_age_seconds": 300,
    }


def write_private_key(path: Path, *, encrypted: bool = False) -> None:
    encryption = BestAvailableEncryption(b"test-password") if encrypted else NoEncryption()
    path.write_bytes(PRIVATE_KEY.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, encryption))
    path.chmod(0o600)


def set_file_environment(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    monkeypatch.setenv("RELEASE_PROOF_SIGNING_KEY_FILE", str(path))
    monkeypatch.setenv("RELEASE_PROOF_ALLOW_FILE_SIGNING_KEY", "1")
    monkeypatch.setenv("RELEASE_PROOF_SIGNING_ISSUER", ISSUER)
    monkeypatch.setenv("RELEASE_PROOF_SIGNING_KEY_ID", KEYID)


def test_signed_verified_mcp_receipt_meets_schema_and_consumer_contract(
    harness: Harness,
    receipt_validator: Draft202012Validator,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_metadata: dict[str, Any] = {}

    def default_factory(
        *, verifier_instance_id: str | None = None, build_digest: str | None = None
    ) -> ReleaseVerifier:
        captured_metadata.update(
            verifier_instance_id=verifier_instance_id, build_digest=build_digest
        )
        return ReleaseVerifier(
            harness.runner,
            verifier_instance_id=verifier_instance_id,
            build_digest=build_digest,
        )

    monkeypatch.setattr(mcp_module, "ReleaseVerifier", default_factory)
    monkeypatch.setenv("RELEASE_PROOF_VERIFIER_INSTANCE_ID", "verifier-prod-01")
    monkeypatch.setenv("RELEASE_PROOF_BUILD_DIGEST", BUILD_DIGEST)
    server = MCPServer(
        policy_store=policy_store(),
        signer=PRIVATE_KEY,
        signing_issuer=ISSUER,
        signing_keyid=KEYID,
    )

    response = call_receipt(server)

    assert "result" in response, response
    result = response["result"]
    receipt = result["structuredContent"]
    assert json.loads(result["content"][0]["text"]) == receipt
    assert receipt["status"] == "verified"
    assert receipt["consumer_nonce"] == NONCE
    assert receipt["proof"]["issuer"] == ISSUER
    assert receipt["proof"]["keyid"] == KEYID
    assert receipt["proof_metadata"] == {
        key: receipt["proof"][key]
        for key in ("issuer", "keyid", "algorithm", "signed_at")
    }
    assert receipt["verifier"]["instance_id"] == "verifier-prod-01"
    assert receipt["verifier"]["build_digest"] == BUILD_DIGEST
    assert captured_metadata == {
        "verifier_instance_id": "verifier-prod-01",
        "build_digest": BUILD_DIGEST,
    }
    receipt_validator.validate(receipt)

    decision = verify_receipt(receipt, **consumer_options(receipt))

    assert decision["allow"] is True
    assert decision["reason"] == "OK"


def test_signed_mcp_receipt_rejects_wrong_consumer_nonce(harness: Harness) -> None:
    receipt = real_signed_receipt(harness)
    options = consumer_options(receipt)
    options["expected_nonce"] = "Ab09_-abcdefghijklmnopqrstuv"

    decision = verify_receipt(receipt, **options)

    assert decision["allow"] is False
    assert decision["reason"] == "NONCE_MISMATCH"


def test_signed_mcp_receipt_rejects_tampering(harness: Harness) -> None:
    receipt = real_signed_receipt(harness)
    tampered = copy.deepcopy(receipt)
    tampered["subject"]["repo"] = "acme/other"

    decision = verify_receipt(tampered, **consumer_options(receipt))

    assert decision["allow"] is False
    assert decision["reason"] == "RECEIPT_INVALID"


def test_default_mcp_receipt_remains_unsigned(
    harness: Harness, receipt_validator: Draft202012Validator
) -> None:
    server = MCPServer(
        lambda: ReleaseVerifier(harness.runner), policy_store=policy_store()
    )

    response = call_receipt(server)

    receipt = response["result"]["structuredContent"]
    assert receipt["status"] == "verified"
    assert "proof" not in receipt
    assert "proof_metadata" not in receipt
    receipt_validator.validate(receipt)


def test_signing_failure_never_returns_an_unsigned_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_signing(*args: Any) -> dict:
        raise ValueError("signing failed")

    monkeypatch.setattr(mcp_module, "sign_receipt", fail_signing)
    server = MCPServer(
        StaticVerifier,
        policy_store=policy_store(),
        signer=PRIVATE_KEY,
        signing_issuer=ISSUER,
        signing_keyid=KEYID,
    )

    response = call_receipt(server)

    assert response["error"]["code"] == -32603
    assert response["error"]["message"] == (
        "Verification failed internally; no evidence claim was produced"
    )
    assert "result" not in response


def test_receipt_size_limit_is_enforced_after_signing() -> None:
    receipt = unsigned_receipt()
    encoded_size = len(json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode())
    receipt["evidence"]["commit"]["padding"] = "x" * (MAX_RECEIPT_BYTES - encoded_size - 128)
    unsigned_size = len(json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode())
    signed_size = len(json.dumps(
        sign_receipt(receipt, PRIVATE_KEY, ISSUER, KEYID),
        sort_keys=True,
        separators=(",", ":"),
    ).encode())
    assert unsigned_size <= MAX_RECEIPT_BYTES
    assert signed_size > MAX_RECEIPT_BYTES
    server = MCPServer(
        lambda: StaticVerifier(receipt),
        policy_store=policy_store(),
        signer=PRIVATE_KEY,
        signing_issuer=ISSUER,
        signing_keyid=KEYID,
    )

    response = call_receipt(server)

    assert response["error"]["code"] == -32603
    assert "size limit" in response["error"]["message"]
    assert "result" not in response


@pytest.mark.parametrize(
    "configuration",
    [
        {"signer": PRIVATE_KEY},
        {"signing_issuer": ISSUER, "signing_keyid": KEYID},
        {"signer": PRIVATE_KEY, "signing_keyid": KEYID},
    ],
)
def test_injected_signing_configuration_requires_all_fields(configuration: dict) -> None:
    with pytest.raises(ValueError):
        MCPServer(**configuration)


@pytest.mark.parametrize("opt_in", [None, "0", "true"])
def test_environment_file_key_requires_explicit_opt_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, opt_in: str | None
) -> None:
    key_path = tmp_path / "signing-key.pem"
    write_private_key(key_path)
    set_file_environment(monkeypatch, key_path)
    if opt_in is None:
        monkeypatch.delenv("RELEASE_PROOF_ALLOW_FILE_SIGNING_KEY")
    else:
        monkeypatch.setenv("RELEASE_PROOF_ALLOW_FILE_SIGNING_KEY", opt_in)

    with pytest.raises(ValueError):
        MCPServer()


@pytest.mark.parametrize(
    "missing",
    [
        "RELEASE_PROOF_SIGNING_KEY_FILE",
        "RELEASE_PROOF_SIGNING_ISSUER",
        "RELEASE_PROOF_SIGNING_KEY_ID",
    ],
)
def test_environment_file_key_requires_key_file_issuer_and_key_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, missing: str
) -> None:
    key_path = tmp_path / "signing-key.pem"
    write_private_key(key_path)
    set_file_environment(monkeypatch, key_path)
    monkeypatch.delenv(missing)

    with pytest.raises(ValueError):
        MCPServer()


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("RELEASE_PROOF_SIGNING_ISSUER", ISSUER),
        ("RELEASE_PROOF_SIGNING_KEY_ID", KEYID),
        ("RELEASE_PROOF_ALLOW_FILE_SIGNING_KEY", "1"),
    ],
)
def test_any_partial_signing_environment_is_a_startup_error(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str
) -> None:
    monkeypatch.setenv(name, value)

    with pytest.raises(ValueError):
        MCPServer()


def test_environment_file_key_signs_with_configured_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_path = tmp_path / "signing-key.pem"
    write_private_key(key_path)
    set_file_environment(monkeypatch, key_path)
    server = MCPServer(StaticVerifier, policy_store=policy_store())

    response = call_receipt(server)

    receipt = response["result"]["structuredContent"]
    proof = receipt["proof"]
    assert proof["issuer"] == ISSUER
    assert proof["keyid"] == KEYID
    envelope = proof["envelope"]
    payload = base64.b64decode(envelope["payload"], validate=True)
    signature = base64.b64decode(envelope["signatures"][0]["sig"], validate=True)
    PRIVATE_KEY.public_key().verify(
        signature, dsse_pae(PAYLOAD_TYPE.encode("ascii"), payload)
    )


def test_environment_file_key_rejects_group_or_other_permissions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_path = tmp_path / "signing-key.pem"
    write_private_key(key_path)
    key_path.chmod(0o640)
    set_file_environment(monkeypatch, key_path)

    with pytest.raises(ValueError):
        MCPServer()


def test_key_loader_rejects_encrypted_keys(tmp_path: Path) -> None:
    key_path = tmp_path / "encrypted-signing-key.pem"
    write_private_key(key_path, encrypted=True)

    with pytest.raises(ValueError):
        load_ed25519_private_key(key_path)


def test_key_loader_rejects_files_over_16_kib(tmp_path: Path) -> None:
    key_path = tmp_path / "oversized-signing-key.pem"
    key_path.write_bytes(b"x" * (MAX_SIGNING_KEY_BYTES + 1))
    key_path.chmod(0o600)

    with pytest.raises(ValueError):
        load_ed25519_private_key(key_path)


def test_custom_verifier_factory_does_not_receive_metadata_arguments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("RELEASE_PROOF_VERIFIER_INSTANCE_ID", "custom-client")
    monkeypatch.setenv("RELEASE_PROOF_BUILD_DIGEST", BUILD_DIGEST)
    server = MCPServer(StaticVerifier, policy_store=policy_store())

    response = call_receipt(server)

    assert response["result"]["structuredContent"]["status"] == "verified"
    assert "proof" not in response["result"]["structuredContent"]


def test_protocol_signer_can_be_injected_without_private_key_type() -> None:
    class InjectedRemoteSigner:
        public_key = PRIVATE_KEY.public_key()

        def sign(self, message: bytes, *, cancel_event: Any = None) -> bytes:
            assert cancel_event is not None
            return PRIVATE_KEY.sign(message)

    server = MCPServer(
        StaticVerifier,
        policy_store=policy_store(),
        signer=InjectedRemoteSigner(),
        signing_issuer=ISSUER,
        signing_keyid=KEYID,
    )

    response = call_receipt(server)

    receipt = response["result"]["structuredContent"]
    envelope = receipt["proof"]["envelope"]
    payload = base64.b64decode(envelope["payload"], validate=True)
    signature = base64.b64decode(envelope["signatures"][0]["sig"], validate=True)
    PRIVATE_KEY.public_key().verify(
        signature, dsse_pae(PAYLOAD_TYPE.encode("ascii"), payload)
    )
