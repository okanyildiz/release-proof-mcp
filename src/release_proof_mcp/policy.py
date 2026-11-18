from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .request import (
    COMMIT_RE,
    POLICY_PROFILE_RE,
    ReleasePolicy,
    ReviewPolicy,
    ValidationError,
    release_policy_from_dict,
    review_policy_from_dict,
    validate_signer_workflow,
)

POLICY_SCHEMA_VERSION = "release-proof-policy/v1"
MAX_POLICY_FILE_BYTES = 1024 * 1024


class PolicyConfigurationError(ValueError):
    pass


@dataclass(frozen=True)
class TrustedPolicy:
    profile: str
    version: str
    signer_workflow: str
    signer_digest: str | None
    review: ReviewPolicy
    release: ReleasePolicy
    require_cosign_signature: bool

    @classmethod
    def from_dict(cls, profile: str, value: Any) -> "TrustedPolicy":
        if not POLICY_PROFILE_RE.fullmatch(profile):
            raise PolicyConfigurationError("Policy profile name is invalid.")
        if not isinstance(value, dict):
            raise PolicyConfigurationError("Policy profile must be an object.")
        unknown = set(value) - {
            "version",
            "signer_workflow",
            "signer_digest",
            "review",
            "release",
            "require_cosign_signature",
        }
        if unknown:
            raise PolicyConfigurationError(
                f"Unknown policy field(s): {', '.join(sorted(unknown))}."
            )
        missing = {
            "signer_workflow",
            "signer_digest",
            "review",
            "release",
            "require_cosign_signature",
        } - set(value)
        if missing:
            raise PolicyConfigurationError(
                f"Missing policy field(s): {', '.join(sorted(missing))}."
            )
        version = value.get("version", "1")
        if not isinstance(version, str) or not version or len(version) > 100:
            raise PolicyConfigurationError("Policy version must be a nonempty string of at most 100 characters.")
        require_cosign = value["require_cosign_signature"]
        if not isinstance(require_cosign, bool):
            raise PolicyConfigurationError("require_cosign_signature must be a boolean.")
        signer_digest = value["signer_digest"]
        if signer_digest is not None and (
            not isinstance(signer_digest, str) or not COMMIT_RE.fullmatch(signer_digest)
        ):
            raise PolicyConfigurationError("signer_digest must be null or a full lowercase commit SHA.")
        try:
            signer_workflow = validate_signer_workflow(value["signer_workflow"])
            review = review_policy_from_dict(value["review"])
            release = release_policy_from_dict(value["release"])
        except ValidationError as error:
            raise PolicyConfigurationError(str(error)) from error
        return cls(
            profile,
            version,
            signer_workflow,
            signer_digest,
            review,
            release,
            require_cosign,
        )

    def effective(self) -> dict[str, Any]:
        return {
            "profile": self.profile,
            "version": self.version,
            "signer_workflow": self.signer_workflow,
            "signer_digest": self.signer_digest,
            "review": {
                "pull_request": self.review.pull_request,
                "mode": self.review.mode,
                "min_approvals": self.review.min_approvals,
                "allowed_reviewer_ids": sorted(self.review.allowed_reviewer_ids),
                "require_non_author": self.review.require_non_author,
            },
            "release": {
                "event": self.release.event,
                "environment": self.release.environment,
                "required_approver_ids": sorted(self.release.required_approver_ids),
                "prevent_self_approval": self.release.prevent_self_approval,
            },
            "require_cosign_signature": self.require_cosign_signature,
        }

    @property
    def sha256(self) -> str:
        canonical = json.dumps(
            self.effective(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


class PolicyStore:
    def __init__(self, profiles: Mapping[str, TrustedPolicy]) -> None:
        self._profiles = dict(profiles)

    @classmethod
    def from_dict(cls, value: Any) -> "PolicyStore":
        if not isinstance(value, dict) or set(value) != {"schema_version", "profiles"}:
            raise PolicyConfigurationError(
                "Policy config must contain only schema_version and profiles."
            )
        if value.get("schema_version") != POLICY_SCHEMA_VERSION:
            raise PolicyConfigurationError("Unsupported policy schema_version.")
        profiles = value.get("profiles")
        if not isinstance(profiles, dict) or not profiles:
            raise PolicyConfigurationError("Policy config must define at least one profile.")
        try:
            parsed = {
                profile: TrustedPolicy.from_dict(profile, profile_value)
                for profile, profile_value in profiles.items()
            }
        except (TypeError, AttributeError) as error:
            raise PolicyConfigurationError("Policy profiles are malformed.") from error
        return cls(parsed)

    @classmethod
    def from_file(cls, path: str | Path) -> "PolicyStore":
        policy_path = Path(path)
        try:
            raw = policy_path.read_bytes()
        except OSError as error:
            raise PolicyConfigurationError("Trusted policy file could not be read.") from error
        if len(raw) > MAX_POLICY_FILE_BYTES:
            raise PolicyConfigurationError("Trusted policy file exceeds the size limit.")
        try:
            value = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise PolicyConfigurationError("Trusted policy file is not valid UTF-8 JSON.") from error
        return cls.from_dict(value)

    def get(self, profile: str) -> TrustedPolicy:
        try:
            return self._profiles[profile]
        except KeyError as error:
            raise PolicyConfigurationError("The requested trusted policy profile does not exist.") from error

    def select(self, profile: str | None = None) -> TrustedPolicy:
        if profile is not None:
            return self.get(profile)
        if len(self._profiles) == 1:
            return next(iter(self._profiles.values()))
        raise PolicyConfigurationError(
            "The server operator must select one trusted policy profile."
        )
