from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from conftest import base_input, base_policy
from release_proof_mcp.mcp import MCPServer
from release_proof_mcp.policy import PolicyConfigurationError, PolicyStore, TrustedPolicy


def policy_config(profiles: dict | None = None) -> dict:
    return {
        "schema_version": "release-proof-policy/v1",
        "profiles": profiles or {"production": base_policy()},
    }


def test_operator_policy_file_is_loaded_and_hashed(tmp_path: Path) -> None:
    path = tmp_path / "release-policy.json"
    path.write_text(json.dumps(policy_config()))

    store = PolicyStore.from_file(path)
    policy = store.select()

    assert policy.profile == "production"
    assert policy.effective()["review"]["min_approvals"] == 1
    canonical = json.dumps(policy.effective(), sort_keys=True, separators=(",", ":")).encode()
    assert policy.sha256 == f"sha256:{hashlib.sha256(canonical).hexdigest()}"


def test_multiple_profiles_require_operator_side_selection() -> None:
    staging = copy.deepcopy(base_policy())
    staging["review"]["min_approvals"] = 1
    staging["release"]["prevent_self_approval"] = False
    store = PolicyStore.from_dict(policy_config({"production": base_policy(), "staging": staging}))

    with pytest.raises(PolicyConfigurationError):
        store.select()
    assert store.select("staging").release.prevent_self_approval is False


def test_policy_hash_covers_complete_effective_policy() -> None:
    strong = TrustedPolicy.from_dict("production", base_policy())
    changed_value = base_policy()
    changed_value["review"]["min_approvals"] = 2
    changed = TrustedPolicy.from_dict("production", changed_value)

    assert strong.sha256 != changed.sha256
    assert changed.effective()["review"]["min_approvals"] == 2


def test_mcp_loads_active_policy_from_operator_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy_config()))
    monkeypatch.setenv("RELEASE_PROOF_POLICY_FILE", str(path))
    monkeypatch.delenv("RELEASE_PROOF_POLICY_PROFILE", raising=False)

    class CaptureVerifier:
        def verify(self, request, policy, *, cancel_event, progress) -> dict:
            return {"status": "verified", "effective_policy": policy.effective(), "policy_hash": policy.sha256}

    response = MCPServer(CaptureVerifier).handle({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "verify_release_deployment", "arguments": base_input()},
    })

    result = response["result"]["structuredContent"]
    assert result["effective_policy"]["profile"] == "production"
    assert result["effective_policy"]["release"]["prevent_self_approval"] is True


def test_policy_file_rejects_unknown_fields(tmp_path: Path) -> None:
    value = policy_config()
    value["profiles"]["production"]["allow_self_approval"] = True
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(value))

    with pytest.raises(PolicyConfigurationError, match="Unknown policy field"):
        PolicyStore.from_file(path)
