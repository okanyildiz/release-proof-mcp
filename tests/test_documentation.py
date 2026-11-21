from __future__ import annotations

import json
import re
from pathlib import Path

from release_proof_mcp.request import VerificationRequest

ROOT = Path(__file__).resolve().parents[1]


def test_live_smoke_input_matches_request_schema() -> None:
    match = re.search(
        r"export RELEASE_PROOF_LIVE_INPUT='([^']+)'",
        (ROOT / "docs/reference.md").read_text(encoding="utf-8"),
    )
    assert match is not None
    payload = json.loads(match.group(1))

    request = VerificationRequest.from_dict(payload)

    assert request.signer_workflow == "acme/shop/.github/workflows/release.yml"
    assert request.signer_digest is None
    assert "signer_digest" not in payload
