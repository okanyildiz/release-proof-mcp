from __future__ import annotations

from dataclasses import dataclass
from typing import Any

SCHEMA_VERSION = "release-deployment-proof/v1"
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
    def __init__(self, request: Any, started_at: str) -> None:
        self.request = request
        self.started_at = started_at
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
            if name == "signature.cosign" and not self.request.require_cosign_signature:
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
                "expected commit; declared review and release policies passed."
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
            "Point-in-time observation only; future tag pulls are not constrained.",
            "Historical branch-protection and environment configuration are not reconstructed.",
            "No vulnerability, reproducibility, node-integrity, or post-start filesystem claim.",
            "A verified signature proves an identity signed evidence, not that the artifact is secure.",
        ]
        if self.request.review.mode == "merged_pr":
            limitations.insert(
                1,
                "Merged-PR review evidence does not mean the merge commit itself was directly reviewed.",
            )
        return {
            "schema_version": SCHEMA_VERSION,
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
                "kube_context": self.request.kube_context,
                "namespace": self.request.namespace,
                "deployment": self.request.deployment,
                "container": self.request.container,
            },
            "checks": [check.as_dict() for check in ordered],
            "reasons": reasons,
            "missing_coverage": missing_coverage,
            "evidence": self.evidence,
            "tools": self.tools,
            "limitations": limitations,
        }
