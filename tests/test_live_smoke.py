from __future__ import annotations

import json
import os

import pytest

from release_proof_mcp.policy import PolicyStore
from release_proof_mcp.request import VerificationRequest
from release_proof_mcp.verifier import ReleaseVerifier


@pytest.mark.live
@pytest.mark.skipif(
    os.environ.get("RELEASE_PROOF_LIVE_SMOKE") != "1",
    reason="Opt-in live smoke test; set RELEASE_PROOF_LIVE_SMOKE=1 and RELEASE_PROOF_LIVE_INPUT.",
)
def test_dedicated_live_release_proof_smoke() -> None:
    raw_input = os.environ.get("RELEASE_PROOF_LIVE_INPUT")
    if not raw_input:
        pytest.fail("RELEASE_PROOF_LIVE_INPUT must contain the dedicated smoke-test tool input as JSON.")
    policy_file = os.environ.get("RELEASE_PROOF_POLICY_FILE")
    if not policy_file:
        pytest.fail("RELEASE_PROOF_POLICY_FILE must identify the operator's trusted policy config.")
    request = VerificationRequest.from_dict(json.loads(raw_input))
    policy = PolicyStore.from_file(policy_file).select(
        os.environ.get("RELEASE_PROOF_POLICY_PROFILE")
    )

    report = ReleaseVerifier().verify(request, policy)

    assert report["status"] == "verified", json.dumps(report["reasons"])
