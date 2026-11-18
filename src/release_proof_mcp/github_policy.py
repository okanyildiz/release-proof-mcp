from __future__ import annotations

from typing import Any

from .report import Reason
from .request import ReleasePolicy, ReviewPolicy
from .runner import redact


class PolicyViolation(ValueError):
    def __init__(self, reason: Reason, evidence: dict[str, Any] | None = None) -> None:
        super().__init__(reason.message)
        self.reason = reason
        self.evidence = evidence or {}


def validate_commit(payload: Any, repo: str, expected_commit: str) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("sha") != expected_commit:
        actual = payload.get("sha") if isinstance(payload, dict) else None
        raise PolicyViolation(
            Reason(
                "SOURCE_COMMIT_MISMATCH",
                "The repository commit lookup did not return the expected full SHA.",
                expected_commit,
                actual,
            )
        )
    return {
        "sha": expected_commit,
        "url": payload.get("html_url") or f"https://github.com/{repo}/commit/{expected_commit}",
    }


def validate_review(
    pr: Any,
    review_pages: Any,
    policy: ReviewPolicy,
    repo: str,
    expected_commit: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not isinstance(pr, dict):
        raise PolicyViolation(Reason("REVIEW_POLICY_FAILED", "Pull request evidence is malformed."))
    number = policy.pull_request
    head = pr.get("head") if isinstance(pr.get("head"), dict) else {}
    head_sha = head.get("sha")
    merge_sha = pr.get("merge_commit_sha")
    pr_evidence = {
        "number": number,
        "url": pr.get("html_url") or f"https://github.com/{repo}/pull/{number}",
        "mode": policy.mode,
        "head_sha": head_sha,
        "merge_commit_sha": merge_sha,
        "merge_commit_directly_reviewed": policy.mode == "exact_head",
    }
    base = pr.get("base") if isinstance(pr.get("base"), dict) else {}
    base_repo = base.get("repo") if isinstance(base.get("repo"), dict) else {}
    if base_repo.get("full_name") != repo:
        raise PolicyViolation(
            Reason("REVIEW_POLICY_FAILED", "The pull request base repository differs from the subject repository."),
            {"pull_request": pr_evidence},
        )
    if pr.get("draft") is not False:
        raise PolicyViolation(
            Reason("REVIEW_POLICY_FAILED", "The pull request is a draft or has no trustworthy draft state."),
            {"pull_request": pr_evidence},
        )
    if policy.mode == "exact_head":
        if head_sha != expected_commit:
            raise PolicyViolation(
                Reason(
                    "REVIEW_POLICY_FAILED",
                    "exact_head mode requires the expected commit to equal the final PR head.",
                    expected_commit,
                    head_sha,
                ),
                {"pull_request": pr_evidence},
            )
    elif pr.get("merged_at") is None or merge_sha != expected_commit:
        raise PolicyViolation(
            Reason(
                "REVIEW_POLICY_FAILED",
                "merged_pr mode requires a merged PR whose merge commit equals the expected commit.",
                expected_commit,
                merge_sha,
            ),
            {"pull_request": pr_evidence},
        )
    if not isinstance(head_sha, str) or not head_sha:
        raise PolicyViolation(
            Reason("REVIEW_POLICY_FAILED", "The pull request has no final head SHA."),
            {"pull_request": pr_evidence},
        )

    reviews = _flatten_review_pages(review_pages)
    latest: dict[int, dict[str, Any]] = {}
    for review in reviews:
        if not isinstance(review, dict) or review.get("state") not in {
            "APPROVED",
            "CHANGES_REQUESTED",
            "DISMISSED",
        }:
            continue
        user = review.get("user") if isinstance(review.get("user"), dict) else {}
        reviewer_id = user.get("id")
        if isinstance(reviewer_id, bool) or not isinstance(reviewer_id, int):
            continue
        if reviewer_id not in latest or _review_order(review) > _review_order(latest[reviewer_id]):
            latest[reviewer_id] = review

    review_evidence = [
        _review_evidence(review, repo, number)
        for _, review in sorted(latest.items(), key=lambda item: (item[0], _review_order(item[1])))
    ]
    blocking = [
        review for review in latest.values() if review.get("state") == "CHANGES_REQUESTED"
    ]
    if blocking:
        raise PolicyViolation(
            Reason("REVIEW_POLICY_FAILED", "A reviewer's latest decision requests changes."),
            {"pull_request": pr_evidence, "reviews": review_evidence},
        )

    author = pr.get("user") if isinstance(pr.get("user"), dict) else {}
    author_id = author.get("id")
    approvals: list[dict[str, Any]] = []
    for reviewer_id, review in latest.items():
        if review.get("state") != "APPROVED" or review.get("commit_id") != head_sha:
            continue
        if reviewer_id not in policy.allowed_reviewer_ids:
            continue
        if policy.require_non_author and reviewer_id == author_id:
            continue
        approvals.append(_review_evidence(review, repo, number))
    approvals.sort(key=lambda item: (item["reviewer_id"], item["id"]))
    if len(approvals) < policy.min_approvals:
        raise PolicyViolation(
            Reason(
                "REVIEW_POLICY_FAILED",
                "The final PR head lacks sufficient distinct, allowed, current approvals.",
                policy.min_approvals,
                len(approvals),
            ),
            {"pull_request": pr_evidence, "reviews": review_evidence},
        )
    return pr_evidence, approvals


def validate_workflow_run(
    run: Any,
    *,
    repo: str,
    run_id: int,
    attempt: int,
    expected_commit: str,
    workflow: str,
    event: str,
) -> dict[str, Any]:
    if not isinstance(run, dict):
        raise PolicyViolation(Reason("WORKFLOW_RUN_POLICY_FAILED", "Workflow run evidence is malformed."))
    repository = run.get("repository") if isinstance(run.get("repository"), dict) else {}
    checks = {
        "run ID": run.get("id") == run_id,
        "run attempt": run.get("run_attempt") == attempt,
        "repository": repository.get("full_name") == repo,
        "source commit": run.get("head_sha") == expected_commit,
        "workflow path": run.get("path") == workflow,
        "event": run.get("event") == event,
        "status": run.get("status") == "completed",
        "conclusion": run.get("conclusion") == "success",
    }
    failed_fields = [name for name, passed in checks.items() if not passed]
    if failed_fields:
        raise PolicyViolation(
            Reason(
                "WORKFLOW_RUN_POLICY_FAILED",
                f"Workflow run policy failed: {', '.join(failed_fields)}.",
                actual=failed_fields,
            )
        )
    return {
        "id": run_id,
        "attempt": attempt,
        "url": run.get("html_url") or f"https://github.com/{repo}/actions/runs/{run_id}",
        "head_sha": expected_commit,
        "event": event,
        "conclusion": "success",
    }


def validate_release_approval(
    approvals: Any,
    run: Any,
    policy: ReleasePolicy,
) -> list[dict[str, Any]]:
    if not isinstance(approvals, list):
        raise PolicyViolation(Reason("RELEASE_APPROVAL_MISSING", "Release approval evidence is malformed."))
    actor_ids: set[int] = set()
    if isinstance(run, dict):
        for key in ("actor", "triggering_actor"):
            actor = run.get(key) if isinstance(run.get(key), dict) else {}
            actor_id = actor.get("id")
            if isinstance(actor_id, int) and not isinstance(actor_id, bool):
                actor_ids.add(actor_id)

    environment_matches: list[tuple[dict[str, Any], int]] = []
    for approval in approvals:
        if not isinstance(approval, dict) or approval.get("state") != "approved":
            continue
        environments = approval.get("environments")
        if not isinstance(environments, list):
            continue
        names = [item.get("name") for item in environments if isinstance(item, dict)]
        if policy.environment not in names:
            continue
        user = approval.get("user") if isinstance(approval.get("user"), dict) else {}
        user_id = user.get("id")
        if isinstance(user_id, int) and not isinstance(user_id, bool):
            environment_matches.append((approval, user_id))
    if not environment_matches:
        raise PolicyViolation(
            Reason(
                "RELEASE_APPROVAL_MISSING",
                "No historical approved record names the required environment for this run.",
                policy.environment,
            )
        )

    allowed: list[dict[str, Any]] = []
    for approval, user_id in environment_matches:
        if user_id not in policy.required_approver_ids:
            continue
        if policy.prevent_self_approval and user_id in actor_ids:
            continue
        allowed.append(_approval_evidence(approval, policy.environment, user_id))
    if not allowed:
        raise PolicyViolation(
            Reason(
                "RELEASE_APPROVER_NOT_ALLOWED",
                "Environment approvals exist, but none satisfy the approver allowlist and self-approval policy.",
            )
        )
    return sorted(allowed, key=lambda item: (item["approver_id"], item["environment"]))


def _flatten_review_pages(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise PolicyViolation(Reason("REVIEW_POLICY_FAILED", "Review pagination evidence is malformed."))
    if all(isinstance(item, dict) for item in value):
        return value
    reviews: list[dict[str, Any]] = []
    for page in value:
        if not isinstance(page, list) or any(not isinstance(item, dict) for item in page):
            raise PolicyViolation(Reason("REVIEW_POLICY_FAILED", "Review pagination evidence is malformed."))
        reviews.extend(page)
    return reviews


def _review_order(review: dict[str, Any]) -> tuple[str, int]:
    review_id = review.get("id")
    if isinstance(review_id, bool) or not isinstance(review_id, int):
        review_id = 0
    submitted_at = review.get("submitted_at")
    return (submitted_at if isinstance(submitted_at, str) else "", review_id)


def _review_evidence(review: dict[str, Any], repo: str, number: int) -> dict[str, Any]:
    review_id = review.get("id", 0)
    user = review.get("user") if isinstance(review.get("user"), dict) else {}
    return {
        "id": review_id,
        "reviewer_id": user.get("id"),
        "state": review.get("state"),
        "commit_id": review.get("commit_id"),
        "url": review.get("html_url")
        or f"https://github.com/{repo}/pull/{number}#pullrequestreview-{review_id}",
    }


def _approval_evidence(approval: dict[str, Any], environment: str, user_id: int) -> dict[str, Any]:
    comment = approval.get("comment")
    return {
        "environment": environment,
        "approver_id": user_id,
        "state": "approved",
        "comment": redact(comment[:500], None) if isinstance(comment, str) else None,
    }
