from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from typing import Any, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import demo_data
from .consumer import verify_receipt
from .policy import TrustedPolicy
from .receipt_validation import canonical_json_bytes
from .request import VerificationRequest
from .runner import CommandResult, CommandTimeout
from .signing import sign_receipt
from .strict_json import strict_json_loads
from .verifier import ReleaseVerifier
from .version import __version__

DEMO_ISSUER = "https://demo.invalid/release-proof"
DEMO_KEYID = "demo/ephemeral-ed25519/v1"
DEMO_INSTANCE = "simulated-demo"


class DemoRunner:
    def __init__(self, scenario: str = "verified") -> None:
        self.scenario = scenario
        self.environment: dict[str, str] = {}
        self.calls: list[tuple[str, ...]] = []

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float | None = None,
        cancel_event: Any = None,
    ) -> CommandResult:
        del timeout, cancel_event
        key = tuple(argv)
        self.calls.append(key)
        if self.scenario == "registry_unavailable" and key[:2] == ("crane", "digest"):
            raise CommandTimeout("simulated registry timeout")
        routes = _routes(self.scenario)
        if key not in routes:
            raise AssertionError(f"Unexpected non-simulated command: {key!r}")
        result = copy.deepcopy(routes[key])
        if isinstance(result, Exception):
            raise result
        return result


def _json(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def _routes(scenario: str) -> dict[tuple[str, ...], Any]:
    pod = demo_data.pod_object(
        f"ghcr.io/acme/shop@sha256:{'a' * 64}" if scenario == "digest_mismatch" else None
    )
    deployment_base = ["kubectl", "--context", "production", "-n", "production"]
    selector = ["--selector", "app=shop"]
    return {
        ("gh", "--version"): CommandResult(0, b"gh version 2.102.0 (2026-01-01)", ""),
        ("crane", "version"): CommandResult(0, b"0.20.0", ""),
        ("kubectl", "version", "--client", "-o", "json"): CommandResult(
            0, _json({"clientVersion": {"gitVersion": "v1.34.0"}}), ""
        ),
        ("gh", "api", "repos/acme/shop"): CommandResult(
            0,
            _json({"full_name": "acme/shop", "id": 555, "owner": {"id": 556}}),
            "",
        ),
        ("gh", "api", f"repos/acme/shop/commits/{demo_data.COMMIT}"): CommandResult(
            0, _json({"sha": demo_data.COMMIT}), ""
        ),
        ("gh", "api", "repos/acme/shop/pulls/123"): CommandResult(
            0, _json(demo_data.pr_object()), ""
        ),
        (
            "gh",
            "api",
            "--paginate",
            "--slurp",
            "repos/acme/shop/pulls/123/reviews?per_page=100",
        ): CommandResult(0, _json(demo_data.reviews_page()), ""),
        ("crane", "digest", demo_data.ARTIFACT): CommandResult(
            0, demo_data.DIGEST.encode("ascii"), ""
        ),
        ("crane", "manifest", f"ghcr.io/acme/shop@{demo_data.DIGEST}"): CommandResult(
            0, demo_data.MANIFEST, ""
        ),
        tuple(demo_data.attestation_argv()): CommandResult(
            0, _json([demo_data.attestation_result()]), ""
        ),
        (
            "gh",
            "api",
            f"repos/acme/shop/actions/runs/{demo_data.RUN_ID}/attempts/1",
        ): CommandResult(0, _json(demo_data.run_object()), ""),
        (
            "gh",
            "api",
            f"repos/acme/shop/actions/runs/{demo_data.RUN_ID}",
        ): CommandResult(0, _json(demo_data.run_object()), ""),
        (
            "gh",
            "api",
            f"repos/acme/shop/actions/runs/{demo_data.RUN_ID}/approvals",
        ): CommandResult(0, _json(demo_data.approvals_object()), ""),
        tuple(
            deployment_base + ["get", "deployment", "shop-api", "-o", "json"]
        ): CommandResult(0, _json(demo_data.deployment_object()), ""),
        tuple(
            deployment_base + ["get", "replicasets", *selector, "-o", "json"]
        ): CommandResult(0, _json({"items": [demo_data.replicaset_object()]}), ""),
        tuple(
            deployment_base + ["get", "pods", *selector, "-o", "json"]
        ): CommandResult(0, _json({"items": [pod]}), ""),
    }


def _request_and_policy() -> tuple[VerificationRequest, TrustedPolicy]:
    request = VerificationRequest.from_dict(
        copy.deepcopy(demo_data.REQUEST),
        signer_workflow_default=demo_data.POLICY["signer_workflow"],
        signer_digest_default=demo_data.POLICY["signer_digest"],
    )
    policy = TrustedPolicy.from_dict("demo", copy.deepcopy(demo_data.POLICY))
    return request, policy


def _expected_subject() -> dict[str, Any]:
    return {
        "repo": "acme/shop",
        "expected_commit": demo_data.COMMIT,
        "artifact_input": demo_data.ARTIFACT,
        "pinned_artifact": f"ghcr.io/acme/shop@{demo_data.DIGEST}",
        "source_ref": "refs/heads/main",
        "workflow": ".github/workflows/release.yml",
        "expected_run": {"id": demo_data.RUN_ID, "attempt": 1},
        "source_repository_id": "555",
        "source_repository_owner_id": "556",
        "kube_context": "production",
        "namespace": "production",
        "deployment": "shop-api",
        "container": "api",
    }


def _expected_verifier() -> dict[str, Any]:
    return {
        "name": "release-proof-mcp",
        "version": __version__,
        "instance_id": DEMO_INSTANCE,
        "build_digest": None,
    }


def run_demo() -> int:
    request, policy = _request_and_policy()
    receipt = ReleaseVerifier(
        DemoRunner(), verifier_instance_id=DEMO_INSTANCE
    ).verify(request, policy)
    if receipt["status"] != "verified":
        raise RuntimeError("The simulated happy path did not verify")
    private_key = Ed25519PrivateKey.generate()
    signed = sign_receipt(
        receipt,
        private_key,
        DEMO_ISSUER,
        DEMO_KEYID,
    )
    options = {
        "trusted_public_keys": {DEMO_KEYID: private_key.public_key()},
        "expected_issuer": DEMO_ISSUER,
        "expected_subject": _expected_subject(),
        "expected_policy_hash": policy.sha256,
        "expected_verifier": _expected_verifier(),
        "expected_nonce": demo_data.NONCE,
        "now": datetime.now(timezone.utc),
        "max_age_seconds": 60,
    }
    allowed = verify_receipt(signed, **options)
    if not allowed["allow"] or allowed["reason"] != "OK":
        raise RuntimeError(f"Simulated consumer rejected valid evidence: {allowed}")

    raw = bytearray(canonical_json_bytes(signed))
    index = raw.index(b'"verified"') + 1
    raw[index] = ord("x")
    tampered = verify_receipt(strict_json_loads(bytes(raw)), **options)
    if tampered["allow"] or tampered["reason"] != "RECEIPT_INVALID":
        raise RuntimeError(f"Simulated tamper was not denied: {tampered}")

    failed = ReleaseVerifier(DemoRunner("digest_mismatch")).verify(
        *_request_and_policy()
    )
    failed_code = next(
        reason["code"] for reason in failed["reasons"] if reason["code"] == "TAG_MOVED"
    )
    unknown = ReleaseVerifier(DemoRunner("registry_unavailable")).verify(
        *_request_and_policy()
    )
    unknown_code = next(
        reason["code"]
        for reason in unknown["missing_coverage"]
        if reason["code"] == "REGISTRY_UNAVAILABLE"
    )

    print(f"[SIMULATED] Verified signed receipt: id={signed['receipt_id']}")
    print(f"[SIMULATED] Independent consumer: allow={allowed['allow']}, reason={allowed['reason']}")
    print(f"[SIMULATED] One-byte tamper: allow={tampered['allow']}, reason={tampered['reason']}")
    print(f"[SIMULATED] Digest mismatch: status={failed['status']}, reason={failed_code}")
    print(f"[SIMULATED] Registry unavailable: status={unknown['status']}, reason={unknown_code}")
    print("[SIMULATED] No network, provider, cluster, or external signing service was used")
    return 0
