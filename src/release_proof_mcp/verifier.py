from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from dataclasses import dataclass
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
from .policy import TrustedPolicy
from .report import Reason, ReportBuilder
from .request import ISSUER, PREDICATE_TYPE, SHA256_RE, VerificationRequest
from .runner import (
    CommandCancelled,
    CommandResult,
    CommandTimeout,
    OutputLimitExceeded,
    ProcessRunner,
    RunnerError,
    ToolUnavailable,
    redact,
)
from .runtime import (
    RuntimeEvidenceError,
    RuntimeSnapshot,
    build_snapshot,
    deployment_label_selector,
    reconcile_runtime_digests,
)

GH_MINIMUM = (2, 102, 0)
INDEX_MEDIA_TYPES = frozenset(
    {
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    }
)
MANIFEST_MEDIA_TYPES = frozenset(
    {
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    }
)


@dataclass
class VerificationArtifacts:
    sigstore_bundle: bytes | None = None
    oci_manifest: bytes | None = None


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
        deadline_seconds: float = 120.0,
        monotonic: Callable[[], float] = time.monotonic,
        verifier_instance_id: str | None = None,
        build_digest: str | None = None,
    ) -> None:
        if deadline_seconds <= 0:
            raise ValueError("The overall verification deadline must be positive.")
        if verifier_instance_id is not None and (
            not isinstance(verifier_instance_id, str)
            or not verifier_instance_id
            or len(verifier_instance_id) > 128
            or verifier_instance_id.strip() != verifier_instance_id
            or any(ord(char) < 32 or ord(char) == 127 for char in verifier_instance_id)
        ):
            raise ValueError("verifier_instance_id must be a nonempty string of at most 128 characters.")
        if build_digest is not None and (
            not isinstance(build_digest, str) or not SHA256_RE.fullmatch(build_digest)
        ):
            raise ValueError("build_digest must be null or a lowercase sha256 digest.")
        self.runner = runner or ProcessRunner()
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.deadline_seconds = deadline_seconds
        self.monotonic = monotonic
        self.verifier_instance_id = verifier_instance_id
        self.build_digest = build_digest
        self._deadline: float | None = None
        self._cancel_event: threading.Event | None = None
        self._progress: Callable[[str], None] | None = None
        self._repository_visible: bool | None = None

    def verify(
        self,
        request: VerificationRequest,
        policy: TrustedPolicy,
        *,
        cancel_event: threading.Event | None = None,
        progress: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        receipt, _artifacts = self.verify_detailed(
            request,
            policy,
            cancel_event=cancel_event,
            progress=progress,
        )
        return receipt

    def verify_detailed(
        self,
        request: VerificationRequest,
        policy: TrustedPolicy,
        *,
        cancel_event: threading.Event | None = None,
        progress: Callable[[str], None] | None = None,
    ) -> tuple[dict[str, Any], VerificationArtifacts]:
        started_at = self._now()
        report = ReportBuilder(
            request,
            policy,
            started_at,
            verifier_instance_id=self.verifier_instance_id,
            build_digest=self.build_digest,
        )
        artifacts = VerificationArtifacts()
        self._repository_visible = None
        self._deadline = self.monotonic() + self.deadline_seconds
        self._cancel_event = cancel_event
        self._progress = progress
        try:
            self._emit_progress("tools.discovery")
            gh_version_reason = self._discover_tools(request, report, policy)
            self._verify_source(request, report, policy)
            self._emit_progress("runtime.rollout")
            first_snapshot = self._first_runtime_snapshot(request, report)
            self._emit_progress("registry.resolution")
            registry = self._resolve_registry(request, report)
            if registry is not None:
                artifacts.oci_manifest = registry["manifest_bytes"]
            self._emit_progress("attestation.verification")
            attestation = self._verify_attestation(
                request, report, registry, gh_version_reason, policy, artifacts
            )
            self._verify_run_and_release(request, report, attestation, policy)
            if policy.require_cosign_signature:
                self._emit_progress("signature.cosign")
                self._verify_cosign(request, report, registry)
            self._emit_progress("runtime.digest_match")
            self._reconcile_runtime(request, report, first_snapshot, registry)
            self._emit_progress("runtime.stable_observation")
            self._verify_stable_observation(request, report, first_snapshot)
            return report.finalize(self._now()), artifacts
        finally:
            self._deadline = None
            self._cancel_event = None
            self._progress = None

    def _discover_tools(
        self, request: VerificationRequest, report: ReportBuilder, policy: TrustedPolicy
    ) -> Reason | None:
        del request
        reason: Reason | None = None
        environment = getattr(self.runner, "environment", None)
        try:
            result = self._run(["gh", "--version"])
            text = redact(result.text, environment)
            match = re.search(r"\bgh version ([0-9]+\.[0-9]+\.[0-9]+)\b", text)
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
        except CommandCancelled:
            reason = self._cancelled_reason()
        except CommandTimeout:
            reason = self._timeout_reason("GH_UNAVAILABLE", "gh is unavailable or its version check timed out.")
        except (RunnerError, UnicodeDecodeError):
            reason = Reason("GH_UNAVAILABLE", "gh is unavailable or its version check timed out.")

        try:
            result = self._run(["crane", "version"])
            if result.returncode == 0:
                text = redact(result.text, environment)
                match = re.search(r"[0-9]+\.[0-9]+\.[0-9]+", text)
                report.tools["crane"] = match.group(0) if match else text.strip()[:100]
        except (RunnerError, UnicodeDecodeError):
            pass
        try:
            result = self._run(["kubectl", "version", "--client", "-o", "json"])
            if result.returncode == 0:
                payload = json.loads(result.text)
                version = payload.get("clientVersion", {}).get("gitVersion")
                if isinstance(version, str):
                    report.tools["kubectl"] = redact(version.removeprefix("v"), environment)[:100]
        except (RunnerError, UnicodeDecodeError, json.JSONDecodeError, AttributeError):
            pass
        if policy.require_cosign_signature:
            try:
                result = self._run(["cosign", "version"])
                if result.returncode == 0:
                    text = redact(result.text, environment)
                    match = re.search(r"v?([0-9]+\.[0-9]+\.[0-9]+)", text)
                    report.tools["cosign"] = match.group(1) if match else text.strip()[:100]
            except (RunnerError, UnicodeDecodeError):
                pass
        return reason

    def _probe_repository(self, request: VerificationRequest) -> Reason | None:
        try:
            result = self._json_command(
                ["gh", "api", f"repos/{request.repo}"],
                unavailable="GITHUB_UNAVAILABLE",
                denied="GITHUB_ACCESS_DENIED",
                not_found=_repository_not_visible_reason(),
            )
        except EvidenceError as error:
            self._repository_visible = False
            return error.reason
        if not isinstance(result, dict) or result.get("full_name") != request.repo:
            self._repository_visible = False
            return _repository_not_visible_reason()
        self._repository_visible = True
        return None

    def _verify_source(
        self, request: VerificationRequest, report: ReportBuilder, policy: TrustedPolicy
    ) -> None:
        self._emit_progress("source.commit")
        visibility_reason = self._probe_repository(request)
        if visibility_reason is not None:
            for name in ("source.commit", "source.review"):
                self._record_reason(report, name, visibility_reason)
            return
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

        self._emit_progress("source.review")
        try:
            pr = self._json_command(
                ["gh", "api", f"repos/{request.repo}/pulls/{policy.review.pull_request}"],
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
                    f"repos/{request.repo}/pulls/{policy.review.pull_request}/reviews?per_page=100",
                ],
                unavailable="GITHUB_UNAVAILABLE",
                denied="GITHUB_ACCESS_DENIED",
            )
            pr_evidence, review_evidence = validate_review(
                pr, reviews, policy.review, request.repo, request.expected_commit
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
        selector = deployment_label_selector(deployment)
        list_options = ["--selector", selector] if selector is not None else []
        replicasets = self._json_command(
            base + ["get", "replicasets", *list_options, "-o", "json"],
            unavailable="RUNTIME_UNAVAILABLE",
            denied="RUNTIME_ACCESS_DENIED",
            invalid="RUNTIME_EVIDENCE_INVALID",
        )
        pods = self._json_command(
            base + ["get", "pods", *list_options, "-o", "json"],
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
            raw_digest = result.text
            digest = raw_digest.strip()
            if not SHA256_RE.fullmatch(digest) or raw_digest not in {
                digest,
                digest + "\n",
                digest + "\r\n",
            }:
                raise EvidenceError(
                    Reason("REGISTRY_RESPONSE_INVALID", "crane digest did not return exactly one sha256 digest.")
                )
            if request.artifact.is_digest and digest != request.artifact.reference:
                raise EvidenceError(
                    Reason(
                        "REGISTRY_DIGEST_MISMATCH",
                        "crane moved a digest-pinned input to a different digest.",
                        request.artifact.reference,
                        digest,
                    )
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
            media_type = manifest.get("mediaType")
            if media_type not in INDEX_MEDIA_TYPES | MANIFEST_MEDIA_TYPES:
                raise EvidenceError(
                    Reason("REGISTRY_RESPONSE_INVALID", "The OCI object has no recognized manifest or index media type.")
                )
            children: frozenset[str] = frozenset()
            if media_type in INDEX_MEDIA_TYPES:
                if "config" in manifest or "layers" in manifest:
                    raise EvidenceError(
                        Reason("REGISTRY_RESPONSE_INVALID", "An OCI index cannot contain image-manifest config or layers fields.")
                    )
                descriptors = manifest.get("manifests")
                if not isinstance(descriptors, list):
                    raise EvidenceError(
                        Reason("REGISTRY_RESPONSE_INVALID", "The OCI index manifests field is missing or not an array.")
                    )
                child_digests: list[str] = []
                for item in descriptors:
                    digest_value = item.get("digest") if isinstance(item, dict) else None
                    if not isinstance(digest_value, str) or not SHA256_RE.fullmatch(digest_value):
                        raise EvidenceError(
                            Reason("REGISTRY_RESPONSE_INVALID", "An OCI index descriptor lacks a valid sha256 digest.")
                        )
                    child_digests.append(digest_value)
                children = frozenset(child_digests)
            else:
                if "manifests" in manifest:
                    raise EvidenceError(
                        Reason("REGISTRY_RESPONSE_INVALID", "An image manifest cannot contain an index manifests field.")
                    )
                if not isinstance(manifest.get("config"), dict) or not isinstance(manifest.get("layers"), list):
                    raise EvidenceError(
                        Reason("REGISTRY_RESPONSE_INVALID", "An image manifest requires config and layers fields.")
                    )
            report.evidence["registry"] = {
                "digest": digest,
                "pinned_artifact": pinned,
                "media_type": media_type,
                "manifest_url": f"https://ghcr.io/v2/{request.artifact.path}/manifests/{digest}",
                "resolved_at": self._now(),
            }
            report.verified("registry.resolution", ("registry",))
            return {
                "digest": digest,
                "pinned": pinned,
                "children": children,
                "manifest": manifest,
                "manifest_bytes": manifest_result.stdout,
            }
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
        policy: TrustedPolicy,
        artifacts: VerificationArtifacts,
    ) -> tuple[int, int] | None:
        if (
            request.signer_workflow != policy.signer_workflow
            or request.signer_digest != policy.signer_digest
        ):
            self._record_reason(
                report,
                "attestation.verification",
                Reason(
                    "SIGNER_POLICY_MISMATCH",
                    "The requested signer workflow or digest differs from the server-side trusted policy.",
                    {
                        "signer_workflow": policy.signer_workflow,
                        "signer_digest": policy.signer_digest,
                    },
                    {
                        "signer_workflow": request.signer_workflow,
                        "signer_digest": request.signer_digest,
                    },
                ),
            )
            return None
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
            result = self._run(argv)
        except CommandCancelled:
            report.unknown("attestation.verification", self._cancelled_reason())
            return None
        except CommandTimeout:
            report.unknown(
                "attestation.verification",
                self._timeout_reason("ATTESTATION_UNAVAILABLE", "Attestation verification timed out."),
            )
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
            def capture_bundle(raw: bytes | None) -> None:
                artifacts.sigstore_bundle = raw

            certificate, attestation, run_id, attempt = select_attestation(
                payload,
                request,
                registry["digest"],
                bundle_sink=capture_bundle,
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
        policy: TrustedPolicy,
    ) -> None:
        self._emit_progress("workflow.run")
        if self._repository_visible is False:
            for name in ("workflow.run", "release.approval"):
                report.unknown(name, _repository_not_visible_reason())
            return
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
        if attempt != 1:
            reason = Reason(
                "RUN_ATTEMPT_UNSUPPORTED",
                "GitHub environment approvals are run-level and are not bound to rerun attempts; only attempt 1 is accepted.",
                1,
                attempt,
            )
            report.failed("workflow.run", reason)
            report.failed("release.approval", reason)
            return
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
            for certified, current in identity_pairs:
                if certified is None and current is None:
                    continue
                certified_id = _normalize_github_id(certified)
                current_id = _normalize_github_id(current)
                if certified_id is None or current_id is None:
                    raise PolicyViolation(
                        Reason(
                            "REPOSITORY_ID_EVIDENCE_UNAVAILABLE",
                            "A supplied immutable repository or owner identifier lacks a valid counterpart.",
                        )
                    )
                if certified_id != current_id:
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
                event=policy.release.event,
            )
            report.verified("workflow.run", ("workflow_run",))
        except (EvidenceError, PolicyViolation) as error:
            self._record_error(report, "workflow.run", error, ("workflow_run",))

        self._emit_progress("release.approval")
        try:
            approvals = self._json_command(
                ["gh", "api", f"repos/{request.repo}/actions/runs/{run_id}/approvals"],
                unavailable="GITHUB_UNAVAILABLE",
                denied="GITHUB_ACCESS_DENIED",
                not_found=Reason("RELEASE_APPROVAL_MISSING", "No approval records exist for the certified run."),
            )
            current_run = self._json_command(
                ["gh", "api", f"repos/{request.repo}/actions/runs/{run_id}"],
                unavailable="GITHUB_UNAVAILABLE",
                denied="GITHUB_ACCESS_DENIED",
                not_found=Reason(
                    "RUN_ATTEMPT_UNAVAILABLE",
                    "The current workflow run attempt could not be retrieved.",
                ),
            )
            if not isinstance(current_run, dict):
                raise EvidenceError(
                    Reason("RUN_ATTEMPT_UNAVAILABLE", "The current workflow run evidence is malformed.")
                )
            current_id = current_run.get("id")
            if not isinstance(current_id, int) or isinstance(current_id, bool) or current_id <= 0:
                raise EvidenceError(
                    Reason("RUN_ATTEMPT_UNAVAILABLE", "The current workflow run has no valid ID.")
                )
            if current_id != run_id:
                raise PolicyViolation(
                    Reason(
                        "RUN_IDENTITY_MISMATCH",
                        "The current workflow run ID differs from the certified run ID.",
                        run_id,
                        current_id,
                    )
                )
            current_attempt = current_run.get("run_attempt")
            if (
                not isinstance(current_attempt, int)
                or isinstance(current_attempt, bool)
                or current_attempt <= 0
            ):
                raise EvidenceError(
                    Reason("RUN_ATTEMPT_UNAVAILABLE", "The current workflow run has no valid run_attempt.")
                )
            if current_attempt != 1:
                raise PolicyViolation(
                    Reason(
                        "RUN_ATTEMPT_UNSUPPORTED",
                        "The workflow has rerun since attempt 1, so historical run-level approval is not attempt-bound.",
                        1,
                        current_attempt,
                    )
                )
            report.evidence["release_approvals"] = validate_release_approval(
                approvals, run, policy.release
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
        certificate = report.evidence["certificate"] or {}
        identity = certificate.get("subject_alternative_name") or certificate.get("build_signer_uri")
        if not request.certificate_identity_matches(identity):
            report.unknown(
                "signature.cosign",
                Reason("SIGNATURE_INPUT_UNAVAILABLE", "A validated certificate identity is required for Cosign verification."),
            )
            return
        argv = [
            "cosign",
            "verify",
            registry["pinned"],
            "--certificate-identity",
            identity,
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
            result = self._run(argv)
        except CommandCancelled:
            report.unknown("signature.cosign", self._cancelled_reason())
            return
        except CommandTimeout:
            report.unknown(
                "signature.cosign",
                self._timeout_reason("COSIGN_UNAVAILABLE", "Cosign verification timed out."),
            )
            return
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
        reason = first.observation_reason() or second.observation_reason()
        if reason:
            report.unknown("runtime.stable_observation", reason, ("pods",))
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
            result = self._run(argv)
        except CommandCancelled as error:
            raise EvidenceError(self._cancelled_reason()) from error
        except CommandTimeout as error:
            raise EvidenceError(self._timeout_reason(unavailable, "The evidence command timed out.")) from error
        except (ToolUnavailable, OutputLimitExceeded, RunnerError) as error:
            raise EvidenceError(Reason(unavailable, "The evidence command was unavailable or exceeded safety limits.")) from error
        if result.returncode == 0:
            return result
        status = _http_status(result.stderr)
        stderr = result.stderr.lower()
        if status in {401, 403}:
            if _rate_limited(stderr):
                raise EvidenceError(Reason(unavailable, "GitHub rate limiting prevented evidence retrieval."))
            raise EvidenceError(Reason(denied, "Authorization or RBAC prevented evidence retrieval."))
        if status == 429 or (status is not None and status >= 500):
            raise EvidenceError(Reason(unavailable, "A rate-limit or service failure prevented evidence retrieval."))
        if status == 422 and not_found is not None and not_found.code == "COMMIT_NOT_FOUND":
            raise EvidenceError(not_found)
        if (
            status == 404
            and not_found is not None
            and self._repository_visible is not False
        ):
            raise EvidenceError(not_found)
        if status is not None:
            raise EvidenceError(Reason(unavailable, "The evidence command failed without conclusive policy evidence."))
        if _access_denied(stderr):
            raise EvidenceError(Reason(denied, "Authorization or RBAC prevented evidence retrieval."))
        if _network_error(stderr):
            raise EvidenceError(Reason(unavailable, "A network, DNS, rate-limit, or service failure prevented evidence retrieval."))
        if (
            not_found
            and self._repository_visible is not False
            and re.search(r"\bnot found\b", stderr)
        ):
            raise EvidenceError(not_found)
        raise EvidenceError(Reason(unavailable, "The evidence command failed without conclusive policy evidence."))

    def _run(self, argv: Sequence[str]) -> CommandResult:
        if self._cancel_event is not None and self._cancel_event.is_set():
            raise CommandCancelled("Verification was cancelled.")
        timeout: float | None = None
        if self._deadline is not None:
            timeout = self._deadline - self.monotonic()
            if timeout <= 0:
                raise CommandTimeout("The overall verification deadline was exceeded.")
            timeout = min(timeout, getattr(self.runner, "timeout_seconds", timeout))
        return self.runner.run(argv, timeout=timeout, cancel_event=self._cancel_event)

    def _timeout_reason(self, fallback_code: str, fallback_message: str) -> Reason:
        if self._deadline is not None and self.monotonic() >= self._deadline:
            return Reason(
                "VERIFICATION_DEADLINE_EXCEEDED",
                "The overall verification deadline was exceeded; remaining evidence is unknown.",
            )
        return Reason(fallback_code, fallback_message)

    @staticmethod
    def _cancelled_reason() -> Reason:
        return Reason(
            "VERIFICATION_CANCELLED",
            "Verification was cancelled; no complete evidence claim was produced.",
        )

    def _emit_progress(self, stage: str) -> None:
        if self._progress is not None:
            try:
                self._progress(stage)
            except Exception:
                pass

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
            "REPOSITORY_NOT_VISIBLE",
            "VERIFIER_OUTPUT_INVALID",
            "ATTESTATION_SEARCH_TRUNCATED",
            "ATTESTATION_EVIDENCE_INVALID",
            "RELEASE_APPROVAL_EVIDENCE_INVALID",
            "GH_UNAVAILABLE",
            "GH_VERSION_UNKNOWN",
            "GH_VERSION_UNSUPPORTED",
            "IMAGE_ID_NOT_REGISTRY_COMPARABLE",
            "CONTAINER_STATUS_MISSING",
            "NO_RUNNING_PODS",
            "ROLLOUT_INCOMPLETE",
            "RUNTIME_OBSERVATION_INCOMPLETE",
            "RUNTIME_EVIDENCE_INVALID",
            "RUNTIME_CHANGED_DURING_VERIFICATION",
            "RUN_ACTOR_EVIDENCE_UNAVAILABLE",
            "REVIEW_AUTHOR_EVIDENCE_UNAVAILABLE",
            "REVIEW_EVIDENCE_INVALID",
            "SIGNING_TIME_UNVERIFIED",
            "VERIFICATION_DEADLINE_EXCEEDED",
            "VERIFICATION_CANCELLED",
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
    status = _http_status(result.stderr)
    if status in {401, 403}:
        if _rate_limited(stderr):
            return Reason("ATTESTATION_UNAVAILABLE", "Rate limiting prevented attestation retrieval.")
        return Reason("ATTESTATION_ACCESS_DENIED", "Attestation evidence retrieval was not authorized.")
    if status == 429 or (status is not None and status >= 500):
        return Reason("ATTESTATION_UNAVAILABLE", "A rate-limit or service failure prevented attestation retrieval.")
    if _access_denied(stderr):
        return Reason("ATTESTATION_ACCESS_DENIED", "Attestation evidence retrieval was not authorized.")
    if (
        "trust root" in stderr
        or re.search(r"\btuf (?:error|failed|failure|timeout|unavailable)\b", stderr)
        or _network_error(stderr)
    ):
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


def _normalize_github_id(value: Any) -> str | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value) if value > 0 else None
    if isinstance(value, str) and re.fullmatch(r"[1-9][0-9]*", value):
        return value
    return None


def _version_tuple(value: str) -> tuple[int, int, int]:
    major, minor, patch = value.split(".")
    return int(major), int(minor), int(patch)


def _http_status(stderr: str) -> int | None:
    match = re.search(r"\(HTTP ([0-9]{3})\)\s*$", stderr.strip(), re.IGNORECASE)
    return int(match.group(1)) if match is not None else None


def _rate_limited(stderr: str) -> bool:
    return "rate limit" in stderr or "rate-limit" in stderr


def _access_denied(stderr: str) -> bool:
    return re.search(r"\b(?:forbidden|unauthorized|access denied|http (?:401|403))\b", stderr) is not None


def _network_error(stderr: str) -> bool:
    return re.search(
        r"\b(?:timeout|timed out|connection refused|rate limit|temporarily unavailable|"
        r"dns (?:error|failure|timeout|unavailable|resolution)|"
        r"network (?:error|timeout|failure|unavailable|unreachable))\b",
        stderr,
    ) is not None


def _repository_not_visible_reason() -> Reason:
    return Reason(
        "REPOSITORY_NOT_VISIBLE",
        "The repository is not visible to the configured GitHub credential, so later absence cannot be conclusive.",
    )
