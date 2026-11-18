from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Sequence

import pytest

from release_proof_mcp.request import VerificationRequest
from release_proof_mcp.runner import CommandResult
from release_proof_mcp.verifier import ReleaseVerifier

COMMIT = "0123456789abcdef0123456789abcdef01234567"
HEAD = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
SIGNER_DIGEST = "89abcdef0123456789abcdef0123456789abcdef"
RUN_ID = 123456789
ATTEMPT = 1
ARTIFACT = "ghcr.io/acme/shop:v1.4.0"
IMAGE_ID_REPOSITORY = "ghcr.io/acme/shop"


def manifest_bytes(media_type: str = "application/vnd.oci.image.manifest.v2+json") -> bytes:
    return json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": media_type,
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "size": 2, "digest": f"sha256:{'c' * 64}"},
            "layers": [],
        },
        separators=(",", ":"),
    ).encode()


MANIFEST = manifest_bytes()
DIGEST = f"sha256:{hashlib.sha256(MANIFEST).hexdigest()}"
CHILD_DIGEST = f"sha256:{'b' * 64}"
INDEX = json.dumps(
    {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v2+json",
                "digest": CHILD_DIGEST,
                "size": 123,
                "platform": {"os": "linux", "architecture": "amd64"},
            }
        ],
    },
    separators=(",", ":"),
).encode()
INDEX_DIGEST = f"sha256:{hashlib.sha256(INDEX).hexdigest()}"


def base_input() -> dict[str, Any]:
    return {
        "repo": "acme/shop",
        "expected_commit": COMMIT,
        "artifact": ARTIFACT,
        "workflow": ".github/workflows/release.yml",
        "source_ref": "refs/heads/main",
        "signer_workflow": "acme/shop/.github/workflows/release.yml",
        "signer_digest": SIGNER_DIGEST,
        "kube_context": "production",
        "namespace": "production",
        "deployment": "shop-api",
        "container": "api",
        "expected_run": {"id": RUN_ID, "attempt": ATTEMPT},
    }


def base_policy() -> dict[str, Any]:
    return {
        "version": "test-v1",
        "signer_workflow": "acme/shop/.github/workflows/release.yml",
        "signer_digest": SIGNER_DIGEST,
        "review": {
            "pull_request": 123,
            "mode": "merged_pr",
            "min_approvals": 1,
            "allowed_reviewer_ids": [1001, 1002],
            "require_non_author": True,
        },
        "release": {
            "event": "push",
            "environment": "production",
            "required_approver_ids": [2001, 2002],
            "prevent_self_approval": True,
        },
        "require_cosign_signature": False,
    }


def policy_store():
    from release_proof_mcp.policy import PolicyStore

    return PolicyStore.from_dict(
        {
            "schema_version": "release-proof-policy/v1",
            "profiles": {"production": base_policy()},
        }
    )


def certificate(**overrides: Any) -> dict[str, Any]:
    value = {
        "issuer": "https://token.actions.githubusercontent.com",
        "subjectAlternativeName": "https://github.com/acme/shop/.github/workflows/release.yml@refs/heads/main",
        "buildSignerDigest": SIGNER_DIGEST,
        "sourceRepositoryURI": "https://github.com/acme/shop",
        "sourceRepositoryDigest": COMMIT,
        "sourceRepositoryRef": "refs/heads/main",
        "runnerEnvironment": "github-hosted",
        "runInvocationURI": f"https://github.com/acme/shop/actions/runs/{RUN_ID}/attempts/{ATTEMPT}",
    }
    value.update(overrides)
    return value


def attestation_result(digest: str = DIGEST, **certificate_overrides: Any) -> dict[str, Any]:
    return {
        "attestation": {
            "bundle": {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "verificationMaterial": {
                    "certificate": {"rawBytes": "Q0VSVElGSUNBVEU="},
                    "tlogEntries": [{"logIndex": "9876"}],
                },
                "dsseEnvelope": {
                    "payload": "U1RBVEVNRU5U",
                    "payloadType": "application/vnd.in-toto+json",
                    "signatures": [{"sig": "U0lHTkFUVVJF"}],
                },
            }
        },
        "verificationResult": {
            "signature": {"certificate": certificate(**certificate_overrides)},
            "verifiedTimestamps": [
                {
                    "type": "TimestampAuthority",
                    "uri": "https://timestamp.example",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "internal": "not copied",
                }
            ],
            "transparencyLogEntries": [{"logIndex": 9876, "ignored": "value"}],
            "statement": {
                "subject": [{"name": "ghcr.io/acme/shop", "digest": {"sha256": digest.removeprefix("sha256:")}}],
                "predicateType": "https://slsa.dev/provenance/v1",
                "predicate": {"buildDefinition": {"resolvedDependencies": [{"digest": {"sha1": "untrusted"}}]}},
            },
        },
    }


def deployment_object() -> dict[str, Any]:
    return {
        "metadata": {
            "uid": "deployment-uid",
            "generation": 3,
            "annotations": {"deployment.kubernetes.io/revision": "3"},
        },
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": "shop"}},
            "template": {
                "metadata": {"labels": {"app": "shop"}},
                "spec": {"containers": [{"name": "api", "image": ARTIFACT}]},
            },
        },
        "status": {
            "observedGeneration": 3,
            "updatedReplicas": 1,
            "readyReplicas": 1,
            "availableReplicas": 1,
        },
    }


def replicaset_object(uid: str = "rs-uid", owner_uid: str = "deployment-uid") -> dict[str, Any]:
    return {
        "metadata": {
            "uid": uid,
            "name": "shop-api-abc",
            "annotations": {"deployment.kubernetes.io/revision": "3"},
            "ownerReferences": [{"kind": "Deployment", "uid": owner_uid}],
        }
    }


def pod_object(
    image_id: str = f"{IMAGE_ID_REPOSITORY}@{DIGEST}",
    *,
    uid: str = "pod-uid",
    name: str = "shop-api-abc-xyz",
    rs_uid: str = "rs-uid",
) -> dict[str, Any]:
    return {
        "metadata": {
            "uid": uid,
            "name": name,
            "labels": {"app": "shop"},
            "ownerReferences": [{"kind": "ReplicaSet", "uid": rs_uid}],
        },
        "spec": {"nodeName": "node-1", "containers": [{"name": "api", "image": ARTIFACT}]},
        "status": {
            "phase": "Running",
            "containerStatuses": [
                {
                    "name": "api",
                    "image": ARTIFACT,
                    "imageID": image_id,
                    "containerID": "containerd://container-1",
                    "ready": True,
                    "state": {"running": {"startedAt": "2026-11-18T11:55:00Z"}},
                }
            ],
        },
    }


def pr_object() -> dict[str, Any]:
    return {
        "number": 123,
        "html_url": "https://github.com/acme/shop/pull/123",
        "draft": False,
        "merged_at": "2026-11-18T11:00:00Z",
        "merge_commit_sha": COMMIT,
        "user": {"id": 9001},
        "base": {"repo": {"full_name": "acme/shop"}},
        "head": {"sha": HEAD},
    }


def reviews_page() -> list[list[dict[str, Any]]]:
    return [[
        {
            "id": 987,
            "user": {"id": 1001},
            "state": "APPROVED",
            "commit_id": HEAD,
            "submitted_at": "2026-11-18T10:00:00Z",
            "html_url": "https://github.com/acme/shop/pull/123#pullrequestreview-987",
        }
    ]]


def run_object() -> dict[str, Any]:
    return {
        "id": RUN_ID,
        "run_attempt": ATTEMPT,
        "repository": {"full_name": "acme/shop", "id": 555},
        "head_sha": COMMIT,
        "path": ".github/workflows/release.yml",
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "html_url": f"https://github.com/acme/shop/actions/runs/{RUN_ID}",
        "actor": {"id": 3001},
        "triggering_actor": {"id": 3002},
    }


def approvals_object() -> list[dict[str, Any]]:
    return [
        {
            "state": "approved",
            "environments": [{"name": "production"}],
            "user": {"id": 2001},
            "comment": "Ship it",
        }
    ]


def attestation_argv(request: dict[str, Any], digest: str) -> list[str]:
    from release_proof_mcp.request import parse_artifact

    repository = f"ghcr.io/{parse_artifact(request['artifact']).path}"
    argv = [
        "gh",
        "attestation",
        "verify",
        f"oci://{repository}@{digest}",
        "--repo",
        request["repo"],
        "--signer-workflow",
        request.get("signer_workflow", f"{request['repo']}/{request['workflow']}"),
    ]
    if request.get("signer_digest"):
        argv.extend(["--signer-digest", request["signer_digest"]])
    argv.extend([
        "--source-digest",
        request["expected_commit"],
        "--source-ref",
        request["source_ref"],
        "--cert-oidc-issuer",
        "https://token.actions.githubusercontent.com",
        "--deny-self-hosted-runners",
        "--predicate-type",
        "https://slsa.dev/provenance/v1",
        "--limit",
        "100",
        "--format",
        "json",
    ])
    return argv


class FakeRunner:
    def __init__(self) -> None:
        self.routes: dict[tuple[str, ...], list[CommandResult | Exception]] = {}
        self.calls: list[tuple[str, ...]] = []

    def route(
        self,
        argv: Sequence[str],
        stdout: bytes | str = b"",
        *,
        stderr: str = "",
        returncode: int = 0,
        error: Exception | None = None,
    ) -> None:
        self.route_many(argv, [error or CommandResult(returncode, _bytes(stdout), stderr)])

    def route_many(
        self,
        argv: Sequence[str],
        results: Sequence[CommandResult | Exception],
    ) -> None:
        self.routes[tuple(argv)] = list(results)

    def route_json(self, argv: Sequence[str], value: Any, *, returncode: int = 0, stderr: str = "") -> None:
        self.route(argv, json.dumps(value, separators=(",", ":")), returncode=returncode, stderr=stderr)

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float | None = None,
        cancel_event: Any | None = None,
    ) -> CommandResult:
        del timeout, cancel_event
        key = tuple(argv)
        self.calls.append(key)
        if key not in self.routes:
            raise AssertionError(f"Unexpected live or unmocked command: {key!r}")
        results = self.routes[key]
        result = results.pop(0) if len(results) > 1 else results[0]
        if isinstance(result, Exception):
            raise result
        return result


@dataclass
class Harness:
    runner: FakeRunner
    request: dict[str, Any]
    policy: dict[str, Any]

    def verify(
        self,
        *,
        cancel_event: Any | None = None,
        progress: Any | None = None,
        deadline_seconds: float = 120.0,
        monotonic: Any | None = None,
    ) -> dict[str, Any]:
        from release_proof_mcp.policy import TrustedPolicy

        parsed = VerificationRequest.from_dict(copy.deepcopy(self.request))
        policy = TrustedPolicy.from_dict("production", copy.deepcopy(self.policy))
        options: dict[str, Any] = {}
        if monotonic is not None:
            options["monotonic"] = monotonic
        verifier = ReleaseVerifier(
            self.runner,
            clock=lambda: datetime(2026, 11, 18, 12, 0, 0, tzinfo=timezone.utc),
            deadline_seconds=deadline_seconds,
            **options,
        )
        return verifier.verify(
            parsed,
            policy,
            cancel_event=cancel_event,
            progress=progress,
        )

    def set_attestation(
        self,
        value: Any,
        *,
        returncode: int = 0,
        stderr: str = "",
        digest: str = DIGEST,
    ) -> None:
        self.runner.route(attestation_argv(self.request, digest), json.dumps(value), returncode=returncode, stderr=stderr)

    def set_pr(self, value: Any) -> None:
        self.runner.route_json(["gh", "api", "repos/acme/shop/pulls/123"], value)

    def set_reviews(self, value: Any) -> None:
        self.runner.route_json(
            ["gh", "api", "--paginate", "--slurp", "repos/acme/shop/pulls/123/reviews?per_page=100"],
            value,
        )

    def set_run(self, value: Any) -> None:
        self.runner.route_json(
            ["gh", "api", f"repos/acme/shop/actions/runs/{RUN_ID}/attempts/{ATTEMPT}"], value
        )

    def set_approvals(self, value: Any) -> None:
        self.runner.route_json(
            ["gh", "api", f"repos/acme/shop/actions/runs/{RUN_ID}/approvals"], value
        )

    def set_runtime(
        self,
        *,
        deployment: Any | None = None,
        replicasets: Any | None = None,
        pods: Any | None = None,
        second_pods: Any | None = None,
    ) -> None:
        from release_proof_mcp.runtime import deployment_label_selector

        base = ["kubectl", "--context", "production", "-n", "production"]
        deployment_value = deployment or deployment_object()
        selector = deployment_label_selector(deployment_value)
        list_options = ["--selector", selector] if selector is not None else []
        self.runner.route_json(
            base + ["get", "deployment", "shop-api", "-o", "json"], deployment_value
        )
        self.runner.route_json(
            base + ["get", "replicasets", *list_options, "-o", "json"],
            replicasets or {"items": [replicaset_object()]},
        )
        first = pods or {"items": [pod_object()]}
        second = second_pods if second_pods is not None else first
        self.runner.route_many(
            base + ["get", "pods", *list_options, "-o", "json"],
            [CommandResult(0, _bytes(json.dumps(first)), ""), CommandResult(0, _bytes(json.dumps(second)), "")],
        )

    def use_index(self, runtime_digest: str = INDEX_DIGEST) -> None:
        self.runner.route(["crane", "digest", ARTIFACT], INDEX_DIGEST)
        self.runner.route(["crane", "manifest", f"ghcr.io/acme/shop@{INDEX_DIGEST}"], INDEX)
        self.set_attestation([attestation_result(INDEX_DIGEST)], digest=INDEX_DIGEST)
        self.set_runtime(pods={"items": [pod_object(f"ghcr.io/acme/shop@{runtime_digest}")]})


def check(report: dict[str, Any], name: str) -> dict[str, Any]:
    return next(item for item in report["checks"] if item["name"] == name)


def _bytes(value: bytes | str) -> bytes:
    return value if isinstance(value, bytes) else value.encode()


@pytest.fixture
def harness() -> Harness:
    runner = FakeRunner()
    request = base_input()
    runner.route(["gh", "--version"], "gh version 2.102.0 (2026-01-01)")
    runner.route(["crane", "version"], "0.20.0")
    runner.route_json(
        ["kubectl", "version", "--client", "-o", "json"],
        {"clientVersion": {"gitVersion": "v1.34.0"}},
    )
    runner.route_json(["gh", "api", f"repos/acme/shop/commits/{COMMIT}"], {"sha": COMMIT})
    runner.route_json(["gh", "api", "repos/acme/shop/pulls/123"], pr_object())
    runner.route_json(
        ["gh", "api", "--paginate", "--slurp", "repos/acme/shop/pulls/123/reviews?per_page=100"],
        reviews_page(),
    )
    runner.route(["crane", "digest", ARTIFACT], DIGEST)
    runner.route(["crane", "manifest", f"ghcr.io/acme/shop@{DIGEST}"], MANIFEST)
    runner.route(attestation_argv(request, DIGEST), json.dumps([attestation_result()]))
    runner.route_json(
        ["gh", "api", f"repos/acme/shop/actions/runs/{RUN_ID}/attempts/{ATTEMPT}"], run_object()
    )
    runner.route_json(
        ["gh", "api", f"repos/acme/shop/actions/runs/{RUN_ID}/approvals"], approvals_object()
    )
    harness = Harness(runner, request, base_policy())
    harness.set_runtime()
    return harness
