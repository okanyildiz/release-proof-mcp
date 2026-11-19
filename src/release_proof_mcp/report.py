from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from .version import __version__

SCHEMA_VERSION = "release-deployment-proof/v2"
VERIFIER_NAME = "release-proof-mcp"
CHECK_ORDER = [
    "source.commit",
    "source.review",
    "registry.resolution",
    "attestation.verification",
    "workflow.run",
    "release.approval",
    "signature.cosign",
    "runtime.rollout",
    "runtime.digest_match",
    "runtime.stable_observation",
]


@dataclass(frozen=True)
class Reason:
    code: str
    message: str
    expected: Any = None
    actual: Any = None

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.expected is not None:
            result["expected"] = self.expected
        if self.actual is not None:
            result["actual"] = self.actual
        return result


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    reason: Reason | None
    evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.status not in {"verified", "failed", "unknown"}:
            raise ValueError("Invalid check status.")
        if self.status == "verified" and self.reason is not None:
            raise ValueError("A verified check cannot have a failure reason.")
        if self.status != "verified" and self.reason is None:
            raise ValueError("A non-verified check requires a reason.")

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "reason": self.reason.as_dict() if self.reason else None,
            "evidence": list(self.evidence),
        }


class ReportBuilder:
    MAX_EVIDENCE_ITEMS = 100

    def __init__(
        self,
        request: Any,
        policy: Any,
        started_at: str,
        *,
        verifier_instance_id: str | None = None,
        build_digest: str | None = None,
    ) -> None:
        self.request = request
        self.policy = policy
        self.started_at = started_at
        self.receipt_id = str(uuid4())
        self.verifier = {
            "name": VERIFIER_NAME,
            "version": __version__,
            "instance_id": verifier_instance_id,
            "build_digest": build_digest,
        }
        self.checks: dict[str, Check] = {}
        self.evidence: dict[str, Any] = {
            "commit": None,
            "pull_request": None,
            "reviews": [],
            "certificate": None,
            "attestation": None,
            "workflow_run": None,
            "release_approvals": [],
            "registry": None,
            "pods": [],
            "cosign": None,
        }
        self.tools: dict[str, str | None] = {
            "gh": None,
            "crane": None,
            "kubectl": None,
            "cosign": None,
        }

    def add(
        self,
        name: str,
        status: str,
        reason: Reason | None = None,
        evidence: tuple[str, ...] = (),
    ) -> None:
        if name in self.checks:
            raise ValueError(f"Duplicate check: {name}")
        self.checks[name] = Check(name, status, reason, evidence)

    def verified(self, name: str, evidence: tuple[str, ...]) -> None:
        self.add(name, "verified", evidence=evidence)

    def failed(self, name: str, reason: Reason, evidence: tuple[str, ...] = ()) -> None:
        self.add(name, "failed", reason, evidence)

    def unknown(self, name: str, reason: Reason, evidence: tuple[str, ...] = ()) -> None:
        self.add(name, "unknown", reason, evidence)

    def finalize(self, completed_at: str) -> dict[str, Any]:
        for name in CHECK_ORDER:
            if name == "signature.cosign" and not self.policy.require_cosign_signature:
                continue
            if name not in self.checks:
                self.unknown(
                    name,
                    Reason("CHECK_NOT_RUN", "The check did not produce evidence; coverage is incomplete."),
                )
        ordered = [self.checks[name] for name in CHECK_ORDER if name in self.checks]
        extra = sorted(set(self.checks) - set(CHECK_ORDER))
        ordered.extend(self.checks[name] for name in extra)
        if any(check.status == "failed" for check in ordered):
            status = "failed"
            summary = "Release deployment proof failed; no security or remediation claim is made."
        elif any(check.status == "unknown" for check in ordered):
            status = "unknown"
            summary = "Release deployment proof is incomplete; explicit missing coverage remains."
        else:
            status = "verified"
            summary = (
                "Kubernetes reported the OCI image attested by the approved workflow at the "
                "expected commit; the server-side review and release policy passed."
            )
        reasons = [
            {"check": check.name, **check.reason.as_dict()}
            for check in ordered
            if check.reason is not None
        ]
        missing_coverage = [
            {"check": check.name, "code": check.reason.code}
            for check in ordered
            if check.status == "unknown" and check.reason is not None
        ]
        limitations = [
            "Observation-window evidence only; future tag pulls and concurrent remote changes are not constrained.",
            "Historical branch-protection and environment configuration are not reconstructed.",
            "GitHub approvals are run-level, so only certified run attempt 1 is supported.",
            "No vulnerability, reproducibility, node-integrity, or post-start filesystem claim.",
            "A verified signature proves an identity signed evidence, not that the artifact is secure.",
        ]
        if self.policy.review.mode == "merged_pr":
            limitations.insert(
                1,
                "Merged-PR review evidence does not mean the merge commit itself was directly reviewed.",
            )
        truncation: dict[str, Any] = {}
        for key in ("reviews", "release_approvals", "pods"):
            values = self.evidence[key]
            if isinstance(values, list) and len(values) > self.MAX_EVIDENCE_ITEMS:
                omitted = len(values) - self.MAX_EVIDENCE_ITEMS
                self.evidence[key] = values[: self.MAX_EVIDENCE_ITEMS]
                truncation[key] = {
                    "retained": self.MAX_EVIDENCE_ITEMS,
                    "omitted": omitted,
                }
        if truncation:
            limitations.append(
                "Receipt evidence arrays are capped at 100 entries; evidence_truncation records omitted entries."
            )
        certificate = self.evidence["certificate"] or {}
        expected_run = self.request.expected_run
        return {
            "schema_version": SCHEMA_VERSION,
            "receipt_id": self.receipt_id,
            "consumer_nonce": self.request.consumer_nonce,
            "verifier": self.verifier,
            "status": status,
            "summary": summary,
            "started_at": self.started_at,
            "completed_at": completed_at,
            "subject": {
                "repo": self.request.repo,
                "expected_commit": self.request.expected_commit,
                "artifact_input": self.request.artifact.original,
                "pinned_artifact": (
                    self.evidence["registry"]["pinned_artifact"]
                    if self.evidence["registry"]
                    else None
                ),
                "source_ref": self.request.source_ref,
                "workflow": self.request.workflow,
                "expected_run": (
                    {"id": expected_run.id, "attempt": expected_run.attempt}
                    if expected_run
                    else None
                ),
                "source_repository_id": certificate.get("source_repository_identifier"),
                "source_repository_owner_id": certificate.get(
                    "source_repository_owner_identifier"
                ),
                "kube_context": self.request.kube_context,
                "namespace": self.request.namespace,
                "deployment": self.request.deployment,
                "container": self.request.container,
            },
            "policy_descriptor": {
                "profile": self.policy.profile,
                "version": self.policy.version,
                "hash": self.policy.sha256,
            },
            "effective_policy": self.policy.effective(),
            "policy_hash": self.policy.sha256,
            "checks": [check.as_dict() for check in ordered],
            "reasons": reasons,
            "missing_coverage": missing_coverage,
            "evidence": self.evidence,
            "evidence_truncation": truncation,
            "tools": self.tools,
            "limitations": limitations,
        }
