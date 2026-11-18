from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
WORKFLOW_RE = re.compile(r"^\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml$")
IMAGE_SEGMENT_RE = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
KUBE_NAME_RE = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")
ISSUER = "https://token.actions.githubusercontent.com"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"

INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "repo",
        "expected_commit",
        "artifact",
        "workflow",
        "source_ref",
        "kube_context",
        "namespace",
        "deployment",
        "container",
        "review",
        "release",
    ],
    "properties": {
        "repo": {"type": "string", "pattern": REPO_RE.pattern},
        "expected_commit": {"type": "string", "pattern": COMMIT_RE.pattern},
        "artifact": {
            "type": "string",
            "minLength": 12,
            "maxLength": 512,
            "description": "A ghcr.io image reference with a tag or sha256 digest.",
        },
        "workflow": {"type": "string", "pattern": WORKFLOW_RE.pattern},
        "source_ref": {"type": "string", "minLength": 1, "maxLength": 255},
        "signer_workflow": {"type": "string", "minLength": 1, "maxLength": 512},
        "signer_digest": {"type": "string", "pattern": COMMIT_RE.pattern},
        "kube_context": {"type": "string", "minLength": 1, "maxLength": 255},
        "namespace": {"type": "string", "pattern": KUBE_NAME_RE.pattern, "maxLength": 63},
        "deployment": {"type": "string", "pattern": KUBE_NAME_RE.pattern, "maxLength": 253},
        "container": {"type": "string", "pattern": KUBE_NAME_RE.pattern, "maxLength": 63},
        "review": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "pull_request",
                "mode",
                "min_approvals",
                "allowed_reviewer_ids",
                "require_non_author",
            ],
            "properties": {
                "pull_request": {"type": "integer", "minimum": 1},
                "mode": {"type": "string", "enum": ["exact_head", "merged_pr"]},
                "min_approvals": {"type": "integer", "minimum": 1},
                "allowed_reviewer_ids": {
                    "type": "array",
                    "minItems": 1,
                    "uniqueItems": True,
                    "items": {"type": "integer", "minimum": 1},
                },
                "require_non_author": {"type": "boolean"},
            },
        },
        "release": {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "event",
                "environment",
                "required_approver_ids",
                "prevent_self_approval",
            ],
            "properties": {
                "event": {"type": "string", "minLength": 1, "maxLength": 100},
                "environment": {"type": "string", "minLength": 1, "maxLength": 255},
                "required_approver_ids": {
                    "type": "array",
                    "minItems": 1,
                    "uniqueItems": True,
                    "items": {"type": "integer", "minimum": 1},
                },
                "prevent_self_approval": {"type": "boolean"},
            },
        },
        "expected_run": {
            "type": "object",
            "additionalProperties": False,
            "required": ["id", "attempt"],
            "properties": {
                "id": {"type": "integer", "minimum": 1},
                "attempt": {"type": "integer", "minimum": 1},
            },
        },
        "require_cosign_signature": {"type": "boolean", "default": False},
    },
}


class ValidationError(ValueError):
    pass


@dataclass(frozen=True)
class ArtifactReference:
    original: str
    path: str
    reference: str
    is_digest: bool

    @property
    def repository(self) -> str:
        return f"ghcr.io/{self.path}"

    def pinned(self, digest: str) -> str:
        return f"{self.repository}@{digest}"


@dataclass(frozen=True)
class ReviewPolicy:
    pull_request: int
    mode: str
    min_approvals: int
    allowed_reviewer_ids: frozenset[int]
    require_non_author: bool


@dataclass(frozen=True)
class ReleasePolicy:
    event: str
    environment: str
    required_approver_ids: frozenset[int]
    prevent_self_approval: bool


@dataclass(frozen=True)
class ExpectedRun:
    id: int
    attempt: int


@dataclass(frozen=True)
class VerificationRequest:
    repo: str
    expected_commit: str
    artifact: ArtifactReference
    workflow: str
    source_ref: str
    signer_workflow: str
    signer_digest: str | None
    kube_context: str
    namespace: str
    deployment: str
    container: str
    review: ReviewPolicy
    release: ReleasePolicy
    expected_run: ExpectedRun | None
    require_cosign_signature: bool

    @property
    def certificate_identity(self) -> str:
        workflow = self.signer_workflow
        if not workflow.startswith("github.com/"):
            workflow = f"github.com/{workflow}"
        return f"https://{workflow}@{self.source_ref}"

    @property
    def source_repository_uri(self) -> str:
        return f"https://github.com/{self.repo}"

    def pinned_artifact(self, digest: str) -> str:
        return self.artifact.pinned(digest)

    @classmethod
    def from_dict(cls, value: Any) -> "VerificationRequest":
        if not isinstance(value, dict):
            raise ValidationError("Input must be a JSON object.")
        _reject_unknown(value, set(INPUT_SCHEMA["properties"]), "input")
        missing = set(INPUT_SCHEMA["required"]) - set(value)
        if missing:
            raise ValidationError(f"Missing required field(s): {', '.join(sorted(missing))}.")

        repo = _string(value, "repo", REPO_RE)
        if any(part.startswith((".", "-")) or part.endswith((".", "-")) for part in repo.split("/")):
            raise ValidationError("repo is not a valid GitHub owner/repository name.")
        expected_commit = _string(value, "expected_commit", COMMIT_RE)
        workflow = _string(value, "workflow", WORKFLOW_RE)
        source_ref = _string(value, "source_ref")
        if not source_ref.startswith(("refs/heads/", "refs/tags/")) or not _valid_ref(source_ref):
            raise ValidationError("source_ref must be an exact refs/heads/... or refs/tags/... ref.")
        artifact = parse_artifact(_string(value, "artifact"))

        signer_workflow = value.get("signer_workflow", f"{repo}/{workflow}")
        if not isinstance(signer_workflow, str):
            raise ValidationError("signer_workflow must be a string.")
        signer_workflow = _validate_signer_workflow(signer_workflow)
        signer_digest = value.get("signer_digest")
        if signer_digest is not None:
            if not isinstance(signer_digest, str) or not COMMIT_RE.fullmatch(signer_digest):
                raise ValidationError("signer_digest must be a full lowercase commit SHA.")

        kube_context = _string(value, "kube_context")
        if any(ord(char) < 32 for char in kube_context) or kube_context.strip() != kube_context:
            raise ValidationError("kube_context contains invalid whitespace or control characters.")
        namespace = _string(value, "namespace", KUBE_NAME_RE)
        deployment = _string(value, "deployment", KUBE_NAME_RE)
        container = _string(value, "container", KUBE_NAME_RE)

        review_value = value["review"]
        if not isinstance(review_value, dict):
            raise ValidationError("review must be an object.")
        review_schema = INPUT_SCHEMA["properties"]["review"]
        _reject_unknown(review_value, set(review_schema["properties"]), "review")
        _require_fields(review_value, review_schema["required"], "review")
        review = ReviewPolicy(
            pull_request=_integer(review_value, "pull_request", minimum=1),
            mode=_choice(review_value, "mode", {"exact_head", "merged_pr"}),
            min_approvals=_integer(review_value, "min_approvals", minimum=1),
            allowed_reviewer_ids=frozenset(
                _id_array(review_value, "allowed_reviewer_ids", nonempty=True)
            ),
            require_non_author=_boolean(review_value, "require_non_author"),
        )

        release_value = value["release"]
        if not isinstance(release_value, dict):
            raise ValidationError("release must be an object.")
        release_schema = INPUT_SCHEMA["properties"]["release"]
        _reject_unknown(release_value, set(release_schema["properties"]), "release")
        _require_fields(release_value, release_schema["required"], "release")
        event = _string(release_value, "event")
        environment = _string(release_value, "environment")
        if any(ord(char) < 32 for char in event + environment):
            raise ValidationError("release event and environment must not contain control characters.")
        release = ReleasePolicy(
            event=event,
            environment=environment,
            required_approver_ids=frozenset(
                _id_array(release_value, "required_approver_ids", nonempty=True)
            ),
            prevent_self_approval=_boolean(release_value, "prevent_self_approval"),
        )

        expected_run = None
        if "expected_run" in value:
            run_value = value["expected_run"]
            if not isinstance(run_value, dict):
                raise ValidationError("expected_run must be an object.")
            _reject_unknown(run_value, {"id", "attempt"}, "expected_run")
            _require_fields(run_value, ["id", "attempt"], "expected_run")
            expected_run = ExpectedRun(
                id=_integer(run_value, "id", minimum=1),
                attempt=_integer(run_value, "attempt", minimum=1),
            )

        require_cosign = value.get("require_cosign_signature", False)
        if not isinstance(require_cosign, bool):
            raise ValidationError("require_cosign_signature must be a boolean.")
        return cls(
            repo=repo,
            expected_commit=expected_commit,
            artifact=artifact,
            workflow=workflow,
            source_ref=source_ref,
            signer_workflow=signer_workflow,
            signer_digest=signer_digest,
            kube_context=kube_context,
            namespace=namespace,
            deployment=deployment,
            container=container,
            review=review,
            release=release,
            expected_run=expected_run,
            require_cosign_signature=require_cosign,
        )


def parse_artifact(value: str) -> ArtifactReference:
    if not value.startswith("ghcr.io/") or any(ord(char) < 33 for char in value):
        raise ValidationError("artifact must be a ghcr.io/...:tag or ghcr.io/...@sha256:... reference.")
    location = value[len("ghcr.io/") :]
    if "@" in location:
        path, separator, digest = location.partition("@")
        if not separator or not SHA256_RE.fullmatch(digest) or ":" in path:
            raise ValidationError("artifact has an invalid digest reference.")
        reference = digest
        is_digest = True
    else:
        path, separator, tag = location.rpartition(":")
        if not separator or "/" in tag or not TAG_RE.fullmatch(tag):
            raise ValidationError("artifact must include a valid tag or sha256 digest.")
        reference = tag
        is_digest = False
    segments = path.split("/")
    if len(segments) < 2 or any(not IMAGE_SEGMENT_RE.fullmatch(part) for part in segments):
        raise ValidationError("artifact image path is invalid; GHCR paths must be lowercase.")
    return ArtifactReference(value, path, reference, is_digest)


def _validate_signer_workflow(value: str) -> str:
    parts = value.split("/")
    if parts[0] == "github.com":
        parts = parts[1:]
        prefix = "github.com/"
    elif len(parts) >= 4 and "." in parts[0]:
        raise ValidationError("Only github.com signer workflows are supported in this MVP.")
    else:
        prefix = ""
    if len(parts) < 4:
        raise ValidationError("signer_workflow must be [github.com/]owner/repo/.github/workflows/name.yml.")
    owner, repository = parts[0], parts[1]
    workflow_path = "/".join(parts[2:])
    if not REPO_RE.fullmatch(f"{owner}/{repository}") or not WORKFLOW_RE.fullmatch(workflow_path):
        raise ValidationError("signer_workflow is not a valid GitHub workflow identity.")
    return f"{prefix}{owner}/{repository}/{workflow_path}"


def _valid_ref(value: str) -> bool:
    has_invalid_character = any(ord(char) <= 32 or ord(char) == 127 for char in value)
    return not has_invalid_character and not any(
        token in value for token in ("..", "//", "@{", "~", "^", ":", "?", "*", "[", "\\")
    ) and not value.endswith(("/", ".", ".lock"))


def _string(value: dict[str, Any], key: str, pattern: re.Pattern[str] | None = None) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item or (pattern and not pattern.fullmatch(item)):
        raise ValidationError(f"{key} is invalid.")
    return item


def _integer(value: dict[str, Any], key: str, minimum: int) -> int:
    item = value.get(key)
    if isinstance(item, bool) or not isinstance(item, int) or item < minimum:
        raise ValidationError(f"{key} must be an integer greater than or equal to {minimum}.")
    return item


def _boolean(value: dict[str, Any], key: str) -> bool:
    item = value.get(key)
    if not isinstance(item, bool):
        raise ValidationError(f"{key} must be a boolean.")
    return item


def _choice(value: dict[str, Any], key: str, choices: set[str]) -> str:
    item = _string(value, key)
    if item not in choices:
        raise ValidationError(f"{key} must be one of: {', '.join(sorted(choices))}.")
    return item


def _id_array(value: dict[str, Any], key: str, nonempty: bool) -> list[int]:
    item = value.get(key)
    if not isinstance(item, list) or (nonempty and not item):
        raise ValidationError(f"{key} must be a nonempty array of numeric user IDs.")
    result: list[int] = []
    for user_id in item:
        if isinstance(user_id, bool) or not isinstance(user_id, int) or user_id < 1:
            raise ValidationError(f"{key} must contain only positive numeric user IDs.")
        result.append(user_id)
    if len(set(result)) != len(result):
        raise ValidationError(f"{key} must not contain duplicate user IDs.")
    return result


def _reject_unknown(value: dict[str, Any], allowed: set[str], prefix: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise ValidationError(f"Unknown {prefix} field(s): {', '.join(sorted(unknown))}.")


def _require_fields(value: dict[str, Any], required: list[str], prefix: str) -> None:
    missing = set(required) - set(value)
    if missing:
        raise ValidationError(f"Missing {prefix} field(s): {', '.join(sorted(missing))}.")
