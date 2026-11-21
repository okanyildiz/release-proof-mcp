from __future__ import annotations

import hashlib
import json
from typing import Any

from .receipt_validation import canonical_json_bytes
from .request import parse_artifact

COMMIT = "0123456789abcdef0123456789abcdef01234567"
HEAD = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
SIGNER_DIGEST = "89abcdef0123456789abcdef0123456789abcdef"
RUN_ID = 123456789
ARTIFACT = "ghcr.io/acme/shop:v1.4.0"
NONCE = "Ab09_-abcdefghijklmnopqrstuv"
MANIFEST = canonical_json_bytes(
    {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "size": 2,
            "digest": f"sha256:{'c' * 64}",
        },
        "layers": [],
    }
)
DIGEST = f"sha256:{hashlib.sha256(MANIFEST).hexdigest()}"
REQUEST = {
    "repo": "acme/shop",
    "expected_commit": COMMIT,
    "artifact": ARTIFACT,
    "workflow": ".github/workflows/release.yml",
    "source_ref": "refs/heads/main",
    "signer_workflow": "acme/shop/.github/workflows/release.yml",
    "kube_context": "production",
    "namespace": "production",
    "deployment": "shop-api",
    "container": "api",
    "expected_run": {"id": RUN_ID, "attempt": 1},
    "consumer_nonce": NONCE,
}
POLICY = {
    "version": "demo-v1",
    "signer_workflow": "acme/shop/.github/workflows/release.yml",
    "signer_digest": None,
    "review": {
        "pull_request": 123,
        "mode": "merged_pr",
        "min_approvals": 1,
        "allowed_reviewer_ids": [1001],
        "require_non_author": True,
    },
    "release": {
        "event": "push",
        "environment": "production",
        "required_approver_ids": [2001],
        "prevent_self_approval": True,
    },
    "require_cosign_signature": False,
}


def attestation_result() -> dict[str, Any]:
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
            "signature": {
                "certificate": {
                    "issuer": "https://token.actions.githubusercontent.com",
                    "subjectAlternativeName": "https://github.com/acme/shop/.github/workflows/release.yml@refs/heads/main",
                    "buildSignerURI": "https://github.com/acme/shop/.github/workflows/release.yml@refs/heads/main",
                    "buildSignerDigest": COMMIT,
                    "sourceRepositoryURI": "https://github.com/acme/shop",
                    "sourceRepositoryIdentifier": "555",
                    "sourceRepositoryOwnerIdentifier": "556",
                    "sourceRepositoryDigest": COMMIT,
                    "sourceRepositoryRef": "refs/heads/main",
                    "runnerEnvironment": "github-hosted",
                    "runInvocationURI": f"https://github.com/acme/shop/actions/runs/{RUN_ID}/attempts/1",
                }
            },
            "verifiedTimestamps": [
                {
                    "type": "https://timestamp.example",
                    "uri": "https://timestamp.example",
                    "timestamp": "2026-01-01T00:00:00Z",
                }
            ],
            "statement": {
                "subject": [
                    {
                        "name": "ghcr.io/acme/shop",
                        "digest": {"sha256": DIGEST.removeprefix("sha256:")},
                    }
                ],
                "predicateType": "https://slsa.dev/provenance/v1",
                "predicate": {"buildDefinition": {"resolvedDependencies": []}},
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


def replicaset_object() -> dict[str, Any]:
    return {
        "metadata": {
            "uid": "rs-uid",
            "name": "shop-api-abc",
            "annotations": {"deployment.kubernetes.io/revision": "3"},
            "ownerReferences": [{"kind": "Deployment", "uid": "deployment-uid"}],
        }
    }


def pod_object(image_id: str | None = None) -> dict[str, Any]:
    return {
        "metadata": {
            "uid": "pod-uid",
            "name": "shop-api-abc-xyz",
            "labels": {"app": "shop"},
            "ownerReferences": [{"kind": "ReplicaSet", "uid": "rs-uid"}],
        },
        "spec": {"nodeName": "demo-node", "containers": [{"name": "api", "image": ARTIFACT}]},
        "status": {
            "phase": "Running",
            "containerStatuses": [
                {
                    "name": "api",
                    "image": f"ghcr.io/acme/shop@{DIGEST}",
                    "imageID": image_id or f"ghcr.io/acme/shop@{DIGEST}",
                    "containerID": "containerd://demo-container",
                    "ready": True,
                    "state": {"running": {"startedAt": "2026-01-01T00:00:00Z"}},
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


def approvals_object() -> list[dict[str, Any]]:
    return [
        {
            "state": "approved",
            "environments": [{"name": "production"}],
            "user": {"id": 2001},
        }
    ]


def run_object() -> dict[str, Any]:
    return {
        "id": RUN_ID,
        "run_attempt": 1,
        "repository": {"full_name": "acme/shop", "id": 555, "owner": {"id": 556}},
        "head_sha": COMMIT,
        "path": ".github/workflows/release.yml",
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "html_url": f"https://github.com/acme/shop/actions/runs/{RUN_ID}",
        "actor": {"id": 3001},
        "triggering_actor": {"id": 3002},
    }


def attestation_argv() -> list[str]:
    repository = f"ghcr.io/{parse_artifact(ARTIFACT).path}"
    return [
        "gh",
        "attestation",
        "verify",
        f"oci://{repository}@{DIGEST}",
        "--repo",
        "acme/shop",
        "--signer-workflow",
        "acme/shop/.github/workflows/release.yml",
        "--source-digest",
        COMMIT,
        "--source-ref",
        "refs/heads/main",
        "--cert-oidc-issuer",
        "https://token.actions.githubusercontent.com",
        "--deny-self-hosted-runners",
        "--predicate-type",
        "https://slsa.dev/provenance/v1",
        "--limit",
        "100",
        "--format",
        "json",
    ]
