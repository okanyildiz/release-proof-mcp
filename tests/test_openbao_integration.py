from __future__ import annotations

import copy
import os
from datetime import datetime, timedelta, timezone

import pytest

from release_proof_mcp.consumer import verify_receipt
from release_proof_mcp.signers.openbao import (
    DEFAULT_OPENBAO_TIMEOUT_SECONDS,
    OpenBaoTransitSigner,
    load_openbao_public_key,
)
from release_proof_mcp.signing import sign_receipt
from test_signing import unsigned_receipt

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("RELEASE_PROOF_OPENBAO_INTEGRATION") != "1",
        reason="real OpenBao integration requires RELEASE_PROOF_OPENBAO_INTEGRATION=1",
    ),
]


def required_environment(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required for the OpenBao integration test")
    return value


def test_real_openbao_signature_allows_consumer_and_tampering_denies() -> None:
    address = required_environment("RELEASE_PROOF_OPENBAO_ADDRESS")
    transit_mount = required_environment("RELEASE_PROOF_OPENBAO_TRANSIT_MOUNT")
    key_name = required_environment("RELEASE_PROOF_OPENBAO_KEY_NAME")
    key_version = int(required_environment("RELEASE_PROOF_OPENBAO_KEY_VERSION"))
    public_key_file = required_environment("RELEASE_PROOF_OPENBAO_PUBLIC_KEY_FILE")
    token = required_environment("RELEASE_PROOF_OPENBAO_TOKEN")
    issuer = required_environment("RELEASE_PROOF_SIGNING_ISSUER")
    keyid = required_environment("RELEASE_PROOF_SIGNING_KEY_ID")
    public_key = load_openbao_public_key(public_key_file)
    signer = OpenBaoTransitSigner(
        address=address,
        transit_mount=transit_mount,
        key_name=key_name,
        key_version=key_version,
        keyid=keyid,
        public_key=public_key,
        token=token,
        ca_file=os.environ.get("RELEASE_PROOF_OPENBAO_CA_FILE"),
        timeout_seconds=float(
            os.environ.get(
                "RELEASE_PROOF_OPENBAO_TIMEOUT_SECONDS",
                str(DEFAULT_OPENBAO_TIMEOUT_SECONDS),
            )
        ),
        allow_insecure_loopback=(
            os.environ.get("RELEASE_PROOF_OPENBAO_ALLOW_INSECURE_LOOPBACK") == "1"
        ),
    )
    now = datetime.now(timezone.utc).replace(microsecond=0)
    unsigned = unsigned_receipt()
    unsigned["started_at"] = _timestamp(now - timedelta(seconds=2))
    unsigned["completed_at"] = _timestamp(now - timedelta(seconds=1))

    receipt = sign_receipt(
        unsigned,
        signer,
        issuer,
        keyid,
        clock=lambda: now,
    )
    options = {
        "trusted_public_keys": {keyid: public_key},
        "expected_issuer": issuer,
        "expected_subject": copy.deepcopy(receipt["subject"]),
        "expected_policy_hash": receipt["policy_hash"],
        "expected_verifier": copy.deepcopy(receipt["verifier"]),
        "expected_nonce": receipt["consumer_nonce"],
        "now": now + timedelta(seconds=1),
        "max_age_seconds": 300,
    }

    allowed = verify_receipt(receipt, **options)
    tampered = copy.deepcopy(receipt)
    tampered["subject"]["repo"] = "acme/tampered"
    denied = verify_receipt(tampered, **options)

    assert allowed["allow"] is True, allowed
    assert allowed["reason"] == "OK"
    assert denied["allow"] is False
    assert denied["reason"] == "RECEIPT_INVALID"


def _timestamp(value: datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")
