from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Callable, Sequence

from .attestation import AttestationError, select_attestation
from .github_policy import (
    PolicyViolation,
    validate_commit,
    validate_release_approval,
    validate_review,
    validate_workflow_run,
)
from .report import Reason, ReportBuilder
from .request import ISSUER, PREDICATE_TYPE, SHA256_RE, VerificationRequest
from .runner import (
    CommandResult,
    CommandTimeout,
    OutputLimitExceeded,
    ProcessRunner,
    RunnerError,
    ToolUnavailable,
)
from .runtime import RuntimeEvidenceError, RuntimeSnapshot, build_snapshot, reconcile_runtime_digests

GH_MINIMUM = (2, 102, 0)


class EvidenceError(RuntimeError):
    def __init__(self, reason: Reason) -> None:
        super().__init__(reason.message)
        self.reason = reason


class ReleaseVerifier:
    def __init__(
        self,
        runner: ProcessRunner | None = None,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.runner = runner or ProcessRunner()
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def verify(self, request: VerificationRequest) -> dict[str, Any]:
        started_at = self._now()
        report = ReportBuilder(request, started_at)
        gh_version_reason = self._discover_tools(request, report)

        self._verify_source(request, report)
        first_snapshot = self._first_runtime_snapshot(request, report)
        registry = self._resolve_registry(request, report)
        attestation = self._verify_attestation(request, report, registry, gh_version_reason)
        self._verify_run_and_release(request, report, attestation)
        if request.require_cosign_signature:
            self._verify_cosign(request, report, registry)
        self._reconcile_runtime(request, report, first_snapshot, registry)
        self._verify_stable_observation(request, report, first_snapshot)
        return report.finalize(self._now())

    def _discover_tools(self, request: VerificationRequest, report: ReportBuilder) -> Reason | None:
        reason: Reason | None = None
        try:
            result = self.runner.run(["gh", "--version"])
            match = re.search(r"\bgh version ([0-9]+\.[0-9]+\.[0-9]+)\b", result.text)
            if result.returncode != 0 or not match:
                reason = Reason("GH_VERSION_UNKNOWN", "The installed gh version could not be established.")
            else:
                version = match.group(1)
                report.tools["gh"] = version
                if _version_tuple(version) < GH_MINIMUM:
                    reason = Reason(
                        "GH_VERSION_UNSUPPORTED",
                        "gh 2.102.0 or newer is required for exact signer-workflow and source-ref policy enforcement.",
                        ">=2.102.0",
                        version,
                    )
        except (RunnerError, UnicodeDecodeError):
            reason = Reason("GH_UNAVAILABLE", "gh is unavailable or its version check timed out.")

        try:
            result = self.runner.run(["crane", "version"])
            if result.returncode == 0:
                match = re.search(r"[0-9]+\.[0-9]+\.[0-9]+", result.text)
                report.tools["crane"] = match.group(0) if match else result.text.strip()[:100]
        except (RunnerError, UnicodeDecodeError):
            pass
        try:
            result = self.runner.run(["kubectl", "version", "--client", "-o", "json"])
            if result.returncode == 0:
                payload = json.loads(result.text)
                version = payload.get("clientVersion", {}).get("gitVersion")
                if isinstance(version, str):
                    report.tools["kubectl"] = version.removeprefix("v")
        except (RunnerError, UnicodeDecodeError, json.JSONDecodeError, AttributeError):
            pass
        if request.require_cosign_signature:
            try:
                result = self.runner.run(["cosign", "version"])
                if result.returncode == 0:
                    match = re.search(r"v?([0-9]+\.[0-9]+\.[0-9]+)", result.text)
                    report.tools["cosign"] = match.group(1) if match else result.text.strip()[:100]
            except (RunnerError, UnicodeDecodeError):
                pass
        return reason

    def _verify_source(self, request: VerificationRequest, report: ReportBuilder) -> None:
        try:
            result = self._json_command(
                ["gh", "api", f"repos/{request.repo}/commits/{request.expected_commit}"],
                unavailable="GITHUB_UNAVAILABLE",
                denied="GITHUB_ACCESS_DENIED",
                not_found=Reason("COMMIT_NOT_FOUND", "The repository does not expose the expected commit."),
            )
            report.evidence["commit"] = validate_commit(result, request.repo, request.expected_commit)
            report.verified("source.commit", ("commit",))
        except (EvidenceError, PolicyViolation) as error:
            self._record_error(report, "source.commit", error, ("commit",))

        try:
            pr = self._json_command(
                ["gh", "api", f"repos/{request.repo}/pulls/{request.review.pull_request}"],
                unavailable="GITHUB_UNAVAILABLE",
                denied="GITHUB_ACCESS_DENIED",
                not_found=Reason("REVIEW_POLICY_FAILED", "The requested pull request was not found."),
            )
            reviews = self._json_command(
                [
                    "gh",
                    "api",
                    "--paginate",
                    "--slurp",
                    f"repos/{request.repo}/pulls/{request.review.pull_request}/reviews?per_page=100",
                ],
                unavailable="GITHUB_UNAVAILABLE",
                denied="GITHUB_ACCESS_DENIED",
            )
            pr_evidence, review_evidence = validate_review(
                pr, reviews, request.review, request.repo, request.expected_commit
            )
            report.evidence["pull_request"] = pr_evidence
            report.evidence["reviews"] = review_evidence
            report.verified("source.review", ("pull_request", "reviews"))
        except (EvidenceError, PolicyViolation) as error:
            if isinstance(error, PolicyViolation):
                report.evidence.update(error.evidence)
            evidence = ("pull_request", "reviews") if report.evidence["pull_request"] else ()
            self._record_error(report, "source.review", error, evidence)

    def _first_runtime_snapshot(
        self, request: VerificationRequest, report: ReportBuilder
    ) -> RuntimeSnapshot | None:
        try:
            snapshot = self._fetch_runtime_snapshot(request)
            report.evidence["pods"] = [pod.evidence() for pod in snapshot.pods]
            reason = snapshot.rollout_reason()
            if reason:
                report.unknown("runtime.rollout", reason, ("pods",))
            else:
                report.verified("runtime.rollout", ("pods",))
            return snapshot
        except (EvidenceError, RuntimeEvidenceError) as error:
            reason = error.reason
            if reason.code == "CONTAINER_NOT_FOUND":
                report.failed("runtime.rollout", reason)
            else:
                report.unknown("runtime.rollout", reason)
            return None

    def _fetch_runtime_snapshot(self, request: VerificationRequest) -> RuntimeSnapshot:
        base = ["kubectl", "--context", request.kube_context, "-n", request.namespace]
        deployment = self._json_command(
            base + ["get", "deployment", request.deployment, "-o", "json"],
            unavailable="RUNTIME_UNAVAILABLE",
            denied="RUNTIME_ACCESS_DENIED",
            invalid="RUNTIME_EVIDENCE_INVALID",
        )
        replicasets = self._json_command(
            base + ["get", "replicasets", "-o", "json"],
            unavailable="RUNTIME_UNAVAILABLE",
            denied="RUNTIME_ACCESS_DENIED",
            invalid="RUNTIME_EVIDENCE_INVALID",
        )
        pods = self._json_command(
            base + ["get", "pods", "-o", "json"],
            unavailable="RUNTIME_UNAVAILABLE",
            denied="RUNTIME_ACCESS_DENIED",
            invalid="RUNTIME_EVIDENCE_INVALID",
        )
        return build_snapshot(deployment, replicasets, pods, request.container)

    def _resolve_registry(
        self, request: VerificationRequest, report: ReportBuilder
    ) -> dict[str, Any] | None:
        try:
            result = self._command(
                ["crane", "digest", request.artifact.original],
                unavailable="REGISTRY_UNAVAILABLE",
                denied="REGISTRY_ACCESS_DENIED",
            )
            digest = result.text.strip()
            if not SHA256_RE.fullmatch(digest) or digest != result.text.strip("\r\n").strip():
                raise EvidenceError(
                    Reason("REGISTRY_RESPONSE_INVALID", "crane digest did not return exactly one sha256 digest.")
                )
            pinned = request.pinned_artifact(digest)
            manifest_result = self._command(
                ["crane", "manifest", pinned],
                unavailable="REGISTRY_UNAVAILABLE",
                denied="REGISTRY_ACCESS_DENIED",
            )
            actual_digest = f"sha256:{hashlib.sha256(manifest_result.stdout).hexdigest()}"
            if actual_digest != digest:
                raise EvidenceError(
                    Reason(
                        "REGISTRY_DIGEST_MISMATCH",
                        "The returned manifest bytes do not hash to the resolved registry digest.",
                        digest,
                        actual_digest,
                    )
                )
            try:
                manifest = json.loads(manifest_result.text)
            except (json.JSONDecodeError, UnicodeDecodeError) as error:
                raise EvidenceError(
                    Reason("REGISTRY_RESPONSE_INVALID", "The registry returned malformed manifest JSON.")
                ) from error
            if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 2:
                raise EvidenceError(
                    Reason("REGISTRY_RESPONSE_INVALID", "The OCI manifest lacks schemaVersion 2.")
                )
            children: frozenset[str] = frozenset()
            if "manifests" in manifest:
                descriptors = manifest.get("manifests")
                if not isinstance(descriptors, list):
                    raise EvidenceError(
                        Reason("REGISTRY_RESPONSE_INVALID", "The OCI index manifests field is not an array.")
                    )
                child_digests = [
                    item.get("digest")
                    for item in descriptors
                    if isinstance(item, dict)
                    and isinstance(item.get("digest"), str)
                    and SHA256_RE.fullmatch(item["digest"])
                ]
                children = frozenset(child_digests)
            media_type = manifest.get("mediaType")
            report.evidence["registry"] = {
                "digest": digest,
                "pinned_artifact": pinned,
                "media_type": media_type if isinstance(media_type, str) else None,
                "manifest_url": f"https://ghcr.io/v2/{request.artifact.path}/manifests/{digest}",
                "resolved_at": self._now(),
            }
            report.verified("registry.resolution", ("registry",))
            return {"digest": digest, "pinned": pinned, "children": children, "manifest": manifest}
        except (EvidenceError, UnicodeDecodeError) as error:
            if isinstance(error, EvidenceError):
                reason = error.reason
            else:
                reason = Reason("REGISTRY_RESPONSE_INVALID", "Registry output is not valid UTF-8.")
            self._record_reason(report, "registry.resolution", reason, ("registry",))
            return None

    def _verify_attestation(
        self,
        request: VerificationRequest,
        report: ReportBuilder,
        registry: dict[str, Any] | None,
        gh_version_reason: Reason | None,
    ) -> tuple[int, int] | None:
        if gh_version_reason:
            self._record_reason(report, "attestation.verification", gh_version_reason)
            return None
        if registry is None:
            report.unknown(
                "attestation.verification",
                Reason("ATTESTATION_INPUT_UNAVAILABLE", "A verified pinned artifact is required before attestation verification."),
            )
            return None
        argv = [
            "gh",
            "attestation",
            "verify",
            f"oci://{registry['pinned']}",
            "--repo",
            request.repo,
            "--signer-workflow",
            request.signer_workflow,
        ]
        if request.signer_digest:
            argv.extend(["--signer-digest", request.signer_digest])
        argv.extend(
            [
                "--source-digest",
                request.expected_commit,
                "--source-ref",
                request.source_ref,
                "--cert-oidc-issuer",
                ISSUER,
                "--deny-self-hosted-runners",
                "--predicate-type",
                PREDICATE_TYPE,
                "--limit",
                "100",
                "--format",
                "json",
            ]
        )
        try:
            result = self.runner.run(argv)
        except CommandTimeout:
            report.unknown("attestation.verification", Reason("ATTESTATION_UNAVAILABLE", "Attestation verification timed out."))
            return None
        except (ToolUnavailable, OutputLimitExceeded, RunnerError):
            report.unknown("attestation.verification", Reason("ATTESTATION_UNAVAILABLE", "Attestation evidence could not be retrieved safely."))
            return None
        if result.returncode != 0:
            reason = _attestation_failure_reason(result)
            self._record_reason(report, "attestation.verification", reason)
            return None
        try:
            payload = json.loads(result.text)
        except (json.JSONDecodeError, UnicodeDecodeError):
            report.unknown(
                "attestation.verification",
                Reason("VERIFIER_OUTPUT_INVALID", "A successful verifier returned malformed or non-UTF-8 JSON."),
            )
            return None
        try:
            certificate, attestation, run_id, attempt = select_attestation(
                payload, request, registry["digest"]
            )
            report.evidence["certificate"] = certificate
            report.evidence["attestation"] = attestation
            report.verified("attestation.verification", ("attestation", "certificate"))
            return run_id, attempt
        except AttestationError as error:
            self._record_reason(report, "attestation.verification", error.reason, ("attestation", "certificate"))
            return None

    def _verify_run_and_release(
        self,
        request: VerificationRequest,
        report: ReportBuilder,
        attestation: tuple[int, int] | None,
    ) -> None:
        if attestation is None:
            report.unknown(
                "workflow.run",
                Reason("RUN_IDENTITY_UNAVAILABLE", "No accepted certificate supplied a run invocation identity."),
            )
            report.unknown(
                "release.approval",
                Reason("RUN_IDENTITY_UNAVAILABLE", "Release approval cannot be linked without a certified run identity."),
            )
            return
        run_id, attempt = attestation
        run: Any = None
        try:
            run = self._json_command(
                ["gh", "api", f"repos/{request.repo}/actions/runs/{run_id}/attempts/{attempt}"],
                unavailable="GITHUB_UNAVAILABLE",
                denied="GITHUB_ACCESS_DENIED",
                not_found=Reason("WORKFLOW_RUN_POLICY_FAILED", "The certified workflow run attempt was not found."),
            )
            repository = run.get("repository") if isinstance(run, dict) else None
            repository = repository if isinstance(repository, dict) else {}
            certificate = report.evidence["certificate"] or {}
            identity_pairs = (
                (certificate.get("source_repository_identifier"), repository.get("id")),
                (
                    certificate.get("source_repository_owner_identifier"),
                    repository.get("owner", {}).get("id")
                    if isinstance(repository.get("owner"), dict)
                    else None,
                ),
            )
            if any(
                certified is not None and current is not None and str(certified) != str(current)
                for certified, current in identity_pairs
            ):
                raise PolicyViolation(
                    Reason(
                        "REPOSITORY_ID_MISMATCH",
                        "Immutable repository or owner identifiers differ between the certificate and run records.",
                    )
                )
            report.evidence["workflow_run"] = validate_workflow_run(
                run,
                repo=request.repo,
                run_id=run_id,
                attempt=attempt,
                expected_commit=request.expected_commit,
                workflow=request.workflow,
                event=request.release.event,
            )
            report.verified("workflow.run", ("workflow_run",))
        except (EvidenceError, PolicyViolation) as error:
            self._record_error(report, "workflow.run", error, ("workflow_run",))

        try:
            approvals = self._json_command(
                ["gh", "api", f"repos/{request.repo}/actions/runs/{run_id}/approvals"],
                unavailable="GITHUB_UNAVAILABLE",
                denied="GITHUB_ACCESS_DENIED",
                not_found=Reason("RELEASE_APPROVAL_MISSING", "No approval records exist for the certified run."),
            )
            if not isinstance(run, dict) and request.release.prevent_self_approval:
                raise EvidenceError(
                    Reason(
                        "RUN_ACTOR_EVIDENCE_UNAVAILABLE",
                        "Self-approval cannot be evaluated without run actor and triggering actor records.",
                    )
                )
            report.evidence["release_approvals"] = validate_release_approval(
                approvals, run, request.release
            )
            report.verified("release.approval", ("release_approvals",))
        except (EvidenceError, PolicyViolation) as error:
            self._record_error(report, "release.approval", error, ("release_approvals",))

    def _verify_cosign(
        self,
        request: VerificationRequest,
        report: ReportBuilder,
        registry: dict[str, Any] | None,
    ) -> None:
        if registry is None:
            report.unknown(
                "signature.cosign",
                Reason("SIGNATURE_INPUT_UNAVAILABLE", "A verified pinned artifact is required for Cosign verification."),
            )
            return
        argv = [
            "cosign",
            "verify",
            registry["pinned"],
            "--certificate-identity",
            request.certificate_identity,
            "--certificate-oidc-issuer",
            ISSUER,
            "--certificate-github-workflow-repository",
            request.repo,
            "--certificate-github-workflow-sha",
            request.expected_commit,
            "--output",
            "json",
        ]
        try:
            result = self.runner.run(argv)
        except RunnerError:
            report.unknown("signature.cosign", Reason("COSIGN_UNAVAILABLE", "Cosign verification was unavailable or timed out."))
            return
        if result.returncode != 0:
            stderr = result.stderr.lower()
            if _access_denied(stderr):
                report.unknown("signature.cosign", Reason("COSIGN_ACCESS_DENIED", "Cosign evidence retrieval was denied."))
            elif "no signatures found" in stderr or "no matching signatures" in stderr:
                report.failed("signature.cosign", Reason("SIGNATURE_MISSING", "The required independent Cosign signature is missing."))
            elif _network_error(stderr) or "trust root" in stderr or "tuf" in stderr:
                report.unknown("signature.cosign", Reason("COSIGN_UNAVAILABLE", "Cosign verification dependencies were unavailable."))
            else:
                report.failed("signature.cosign", Reason("SIGNATURE_INVALID", "Cosign rejected the required independent signature."))
            return
        try:
            payload = json.loads(result.text)
        except (json.JSONDecodeError, UnicodeDecodeError):
            report.unknown("signature.cosign", Reason("VERIFIER_OUTPUT_INVALID", "Cosign returned malformed successful JSON."))
            return
        if not isinstance(payload, list) or not payload:
            report.unknown("signature.cosign", Reason("VERIFIER_OUTPUT_INVALID", "Cosign returned no parseable signature results despite exit zero."))
            return
        report.evidence["cosign"] = {"verified": True, "result_count": len(payload)}
        report.verified("signature.cosign", ("cosign",))

    def _reconcile_runtime(
        self,
        request: VerificationRequest,
        report: ReportBuilder,
        snapshot: RuntimeSnapshot | None,
        registry: dict[str, Any] | None,
    ) -> None:
        if snapshot is None:
            report.unknown(
                "runtime.digest_match",
                Reason("RUNTIME_OBSERVATION_INCOMPLETE", "No valid first runtime snapshot is available for digest comparison."),
            )
            return
        if registry is None:
            report.unknown(
                "runtime.digest_match",
                Reason("REGISTRY_DIGEST_UNAVAILABLE", "No verified registry digest is available for runtime comparison."),
                ("pods",),
            )
            return
        reason = reconcile_runtime_digests(
            snapshot, registry["digest"], registry["children"], not request.artifact.is_digest
        )
        report.evidence["pods"] = [pod.evidence() for pod in snapshot.pods]
        if reason:
            if reason.code == "NO_RUNNING_PODS" and snapshot.desired > 0:
                report.failed("runtime.digest_match", reason, ("pods",))
            else:
                self._record_reason(report, "runtime.digest_match", reason, ("pods",))
        else:
            report.verified("runtime.digest_match", ("pods",))

    def _verify_stable_observation(
        self,
        request: VerificationRequest,
        report: ReportBuilder,
        first: RuntimeSnapshot | None,
    ) -> None:
        if first is None:
            report.unknown(
                "runtime.stable_observation",
                Reason("RUNTIME_OBSERVATION_INCOMPLETE", "The first snapshot is unavailable, so stability cannot be established."),
            )
            return
        try:
            second = self._fetch_runtime_snapshot(request)
        except (EvidenceError, RuntimeEvidenceError) as error:
            report.unknown("runtime.stable_observation", error.reason, ("pods",))
            return
        if first.stability_fingerprint() != second.stability_fingerprint():
            report.unknown(
                "runtime.stable_observation",
                Reason(
                    "RUNTIME_CHANGED_DURING_VERIFICATION",
                    "Target Pod identity, container identity, imageID, rollout revision, or readiness changed during verification.",
                ),
                ("pods",),
            )
        else:
            report.verified("runtime.stable_observation", ("pods",))

    def _json_command(
        self,
        argv: Sequence[str],
        *,
        unavailable: str,
        denied: str,
        invalid: str | None = None,
        not_found: Reason | None = None,
    ) -> Any:
        result = self._command(
            argv, unavailable=unavailable, denied=denied, not_found=not_found
        )
        try:
            return json.loads(result.text)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise EvidenceError(
                Reason(invalid or unavailable, "The evidence command did not return valid JSON.")
            ) from error

    def _command(
        self,
        argv: Sequence[str],
        *,
        unavailable: str,
        denied: str,
        not_found: Reason | None = None,
    ) -> CommandResult:
        try:
            result = self.runner.run(argv)
        except CommandTimeout as error:
            raise EvidenceError(Reason(unavailable, "The evidence command timed out.")) from error
        except (ToolUnavailable, OutputLimitExceeded, RunnerError) as error:
            raise EvidenceError(Reason(unavailable, "The evidence command was unavailable or exceeded safety limits.")) from error
        if result.returncode == 0:
            return result
        stderr = result.stderr.lower()
        if _access_denied(stderr):
            raise EvidenceError(Reason(denied, "Authorization or RBAC prevented evidence retrieval."))
        if _network_error(stderr):
            raise EvidenceError(Reason(unavailable, "A network, DNS, rate-limit, or service failure prevented evidence retrieval."))
        if not_found and ("404" in stderr or "not found" in stderr):
            raise EvidenceError(not_found)
        raise EvidenceError(Reason(unavailable, "The evidence command failed without conclusive policy evidence."))

    def _record_error(
        self,
        report: ReportBuilder,
        name: str,
        error: EvidenceError | PolicyViolation,
        evidence: tuple[str, ...],
    ) -> None:
        self._record_reason(report, name, error.reason, evidence)

    def _record_reason(
        self,
        report: ReportBuilder,
        name: str,
        reason: Reason,
        evidence: tuple[str, ...] = (),
    ) -> None:
        if reason.code in {
            "VERIFIER_OUTPUT_INVALID",
            "ATTESTATION_SEARCH_TRUNCATED",
            "GH_UNAVAILABLE",
            "GH_VERSION_UNKNOWN",
            "IMAGE_ID_NOT_REGISTRY_COMPARABLE",
            "CONTAINER_STATUS_MISSING",
            "NO_RUNNING_PODS",
            "ROLLOUT_INCOMPLETE",
            "RUNTIME_OBSERVATION_INCOMPLETE",
            "RUNTIME_EVIDENCE_INVALID",
            "RUNTIME_CHANGED_DURING_VERIFICATION",
            "RUN_ACTOR_EVIDENCE_UNAVAILABLE",
            "ATTESTATION_INPUT_UNAVAILABLE",
            "RUN_IDENTITY_UNAVAILABLE",
            "REGISTRY_DIGEST_UNAVAILABLE",
            "REGISTRY_RESPONSE_INVALID",
            "SIGNATURE_INPUT_UNAVAILABLE",
        } or reason.code.endswith("_UNAVAILABLE") or reason.code.endswith("_ACCESS_DENIED"):
            report.unknown(name, reason, evidence)
        else:
            report.failed(name, reason, evidence)

    def _now(self) -> str:
        value = self.clock()
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _attestation_failure_reason(result: CommandResult) -> Reason:
    stderr = result.stderr.lower()
    if _access_denied(stderr):
        return Reason("ATTESTATION_ACCESS_DENIED", "Attestation evidence retrieval was not authorized.")
    if "trust root" in stderr or "tuf" in stderr or _network_error(stderr):
        return Reason("TRUST_ROOT_UNAVAILABLE", "A network or trust-root dependency prevented verification.")
    if "no attestations found" in stderr or "no matching attestations" in stderr:
        return Reason("ATTESTATION_MISSING", "The authoritative lookup found no acceptable artifact attestation.")
    if "provenance" in stderr and ("missing" in stderr or "no slsa" in stderr):
        return Reason("PROVENANCE_MISSING", "No SLSA v1 provenance was found for the artifact.")
    if "invalid signature" in stderr or "signature invalid" in stderr or "dsse" in stderr:
        return Reason("SIGNATURE_INVALID", "The attestation signature or DSSE envelope is invalid.")
    if "signing time" in stderr or "timestamp" in stderr or "certificate has expired" in stderr:
        code = "SIGNING_TIME_INVALID" if "invalid timestamp" in stderr else "SIGNING_TIME_UNVERIFIED"
        return Reason(code, "The verifier could not establish an acceptable signing time.")
    return Reason(
        "ATTESTATION_VERIFICATION_FAILED",
        "gh rejected the attestation; the verifier did not provide a stable, more specific classification.",
    )


def _version_tuple(value: str) -> tuple[int, int, int]:
    major, minor, patch = value.split(".")
    return int(major), int(minor), int(patch)


def _access_denied(stderr: str) -> bool:
    return any(item in stderr for item in ("forbidden", "unauthorized", "http 403", "http 401", "access denied"))


def _network_error(stderr: str) -> bool:
    return any(
        item in stderr
        for item in ("timeout", "timed out", "dns", "connection refused", "rate limit", "temporarily unavailable", "network")
    )
