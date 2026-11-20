from __future__ import annotations

import copy
import json
from pathlib import Path

from conftest import Harness, reviews_page
from release_proof_mcp.consumer import verify_receipt
from release_proof_mcp.mcp import MCPServer
from release_proof_mcp.policy import PolicyStore
from release_proof_mcp.receipt_validation import canonical_json_bytes
from release_proof_mcp.verifier import ReleaseVerifier
from test_consumer_cli import cli_arguments, run_cli
from test_evidence_package import assert_signed_audit_result
from test_signed_mcp import call_receipt, consumer_options
from test_signing import ISSUER, KEYID, PRIVATE_KEY, public_key_pem


def verified_truncated_audit_receipt(harness: Harness, root: Path) -> dict:
    original = reviews_page()[0][0]
    reviews = []
    for index in range(101):
        review = copy.deepcopy(original)
        review["id"] = 10000 + index
        review["user"]["id"] = 1001 + index
        review["html_url"] = (
            f"https://github.com/acme/shop/pull/123#pullrequestreview-{review['id']}"
        )
        reviews.append(review)
    harness.policy["review"]["allowed_reviewer_ids"] = [
        review["user"]["id"] for review in reviews
    ]
    harness.set_reviews([reviews])
    policies = PolicyStore.from_dict(
        {
            "schema_version": "release-proof-policy/v1",
            "profiles": {"production": copy.deepcopy(harness.policy)},
        }
    )
    assert policies.select("production") is not None
    server = MCPServer(
        lambda: ReleaseVerifier(harness.runner),
        policy_store=policies,
        signer=PRIVATE_KEY,
        signing_issuer=ISSUER,
        signing_keyid=KEYID,
        evidence_package_root=root,
    )

    response = call_receipt(server)

    receipt = assert_signed_audit_result(response, root, "verified")
    assert receipt["evidence_truncation"] == {
        "reviews": {"retained": 100, "omitted": 1}
    }
    assert len(receipt["evidence"]["reviews"]) == 100
    assert not receipt["missing_coverage"]
    return receipt


def test_verified_truncated_audit_receipt_is_denied_by_consumer(
    tmp_path: Path, harness: Harness
) -> None:
    receipt = verified_truncated_audit_receipt(harness, tmp_path / "operator")

    decision = verify_receipt(receipt, **consumer_options(receipt))

    assert decision["allow"] is False
    assert decision["reason"] == "EVIDENCE_TRUNCATED"


def test_verified_truncated_audit_receipt_has_cli_exit_one(
    tmp_path: Path, harness: Harness
) -> None:
    receipt = verified_truncated_audit_receipt(harness, tmp_path / "operator")
    receipt_path = tmp_path / "truncated-audit.json"
    key_path = tmp_path / "trusted-public.pem"
    expectations_path = tmp_path / "expectations.json"
    receipt_path.write_bytes(canonical_json_bytes(receipt))
    key_path.write_bytes(public_key_pem())
    expectations_path.write_text(
        json.dumps({"subject": receipt["subject"], "verifier": receipt["verifier"]}),
        encoding="utf-8",
    )
    paths = {
        "receipt": receipt_path,
        "key": key_path,
        "expectations": expectations_path,
    }

    result = run_cli(cli_arguments(paths, policy_hash=receipt["policy_hash"]))

    assert result.returncode == 1
    decision = json.loads(result.stdout)
    assert decision["allow"] is False
    assert decision["reason"] == "EVIDENCE_TRUNCATED"
