# Release & Deployment Proof MCP

Release & Deployment Proof MCP is a read-only MVP that produces an observation-window evidence receipt for one question:

> During verification, did Kubernetes report running the container image whose OCI digest was cryptographically attested by the trusted GitHub Actions identity at the expected commit, and do GitHub records satisfy the server operator's review and release-approval policy?

It exposes exactly one MCP tool over stdio: `verify_release_deployment`.

A `verified` result is a cryptographically linked and policy-qualified observation. It is not a statement that the artifact is secure. Both `failed` and `unknown` mean **not verified** and must fail closed if used as a deployment gate.

## Requirements

- Python 3.11 or newer; the runtime package has no third-party Python dependencies.
- `gh` 2.102.0 or newer. This is a hard floor: older versions are rejected before attestation verification because of signer-workflow prefix and case-insensitive source-ref verification vulnerabilities (GHSA-wjmr-j3rp-mh2g and GHSA-4mq3-hpgx-9cx8).
- `crane` for registry digest resolution and manifest retrieval.
- `kubectl` for explicit-context Deployment, ReplicaSet, and Pod reads.
- `cosign` only when the trusted policy sets `require_cosign_signature` to true.
- An operator-supplied trusted policy JSON file.

The verifier requires both a zero exit status and a nonempty JSON array from `gh attestation verify`. Process exit status alone is not evidence. Commands use argument vectors without a shell, a 30-second per-command cap, a 120-second overall verification deadline, bounded output, process-group termination, and credential redaction.

## Trusted server-side policy

Review rules, approver/reviewer IDs, self-approval controls, the signer workflow/digest, and the Cosign requirement are **not controlled by MCP arguments**. The server reads them from a file named by `RELEASE_PROOF_POLICY_FILE`. If the file contains multiple profiles, the operator must also set `RELEASE_PROOF_POLICY_PROFILE`; a single-profile file is unambiguous without it. The caller cannot select a profile or weaken its contents.

Example `release-policy.json`:

```json
{
  "schema_version": "release-proof-policy/v1",
  "profiles": {
    "production": {
      "version": "2026-11-18.1",
      "signer_workflow": "acme/shop/.github/workflows/release.yml",
      "signer_digest": "89abcdef0123456789abcdef0123456789abcdef",
      "review": {
        "pull_request": 123,
        "mode": "merged_pr",
        "min_approvals": 1,
        "allowed_reviewer_ids": [1001, 1002],
        "require_non_author": true
      },
      "release": {
        "event": "push",
        "environment": "production",
        "required_approver_ids": [2001, 2002],
        "prevent_self_approval": true
      },
      "require_cosign_signature": false
    }
  }
}
```

The profile schema is closed and strictly validated. `signer_digest` may be `null` only for a same-repository signer whose ref is pinned to `source_ref`; an external reusable builder always requires a full commit digest. Requests that identify a different signer workflow or digest fail with `SIGNER_POLICY_MISMATCH`.

Every receipt includes the complete `effective_policy`, including its profile and version, plus `policy_hash`. The hash is the SHA-256 of the compact, key-sorted UTF-8 JSON representation of the effective policy. A gate consumer must validate the returned subject, effective policy identity, and policy hash against its own trusted configuration; `verified` alone is not a sufficient authorization decision.

## Install and run

```sh
python3.11 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/python -m pytest -q
.venv/bin/python -m compileall -q src tests
RELEASE_PROOF_POLICY_FILE=/secure/config/release-policy.json \
RELEASE_PROOF_POLICY_PROFILE=production \
.venv/bin/release-proof-mcp
```

The server uses newline-delimited JSON-RPC 2.0 on stdio. It supports MCP `initialize`, `ping`, `tools/list`, and `tools/call`. Configure it as an MCP stdio server in a client; do not put credentials in tool arguments or the policy file.

Credentials come from the server environment and existing client configuration:

- GitHub token: read repository contents, pull requests, Actions, and attestations; GHCR package pull access.
- Registry: existing Docker/crane credentials for GHCR.
- Kubernetes: `get/list` on the named Deployment and ReplicaSets/Pods in the namespace. The input must name an explicit kube context; the current default context is never silently selected.

## Tool input

```json
{
  "repo": "acme/shop",
  "expected_commit": "0123456789abcdef0123456789abcdef01234567",
  "artifact": "ghcr.io/acme/shop:v1.4.0",
  "workflow": ".github/workflows/release.yml",
  "source_ref": "refs/heads/main",
  "signer_workflow": "acme/shop/.github/workflows/release.yml",
  "signer_digest": "89abcdef0123456789abcdef0123456789abcdef",
  "kube_context": "production",
  "namespace": "production",
  "deployment": "shop-api",
  "container": "api",
  "expected_run": {"id": 123456789, "attempt": 1}
}
```

Important rules:

- GitHub.com and GHCR are the only supported services in this MVP.
- `expected_commit` and `signer_digest` are full 40-character lowercase commit SHAs. `source_ref` matching is exact and case-sensitive.
- `artifact` must be `ghcr.io/...:tag` or `ghcr.io/...@sha256:...`. Verification always uses the resolved digest, never a tag. For digest-form input, `crane digest` must return that exact digest; it cannot move the subject.
- `signer_workflow` defaults to `${repo}/${workflow}`. For reusable workflows it must identify the called reusable workflow, not the caller, and must equal the trusted profile. `signer_digest` is mandatory whenever the signer repository differs from `repo`.
- A digest-pinned reusable signer may use its own exact branch/tag ref or the pinned SHA in its certificate; it need not equal the caller's `source_ref`. `buildSignerDigest` must still equal the trusted `signer_digest`.
- `container` is mandatory. The verifier never falls back to `containers[0]`.
- Reviewer and approver identities in trusted policy are immutable positive numeric GitHub user IDs, not login names.
- `expected_run` optionally pins the run ID and attempt. Otherwise the accepted certificate's `runInvocationURI` selects the run. Only attempt 1 is accepted.
- `review`, `release`, `require_cosign_signature`, and `policy_profile` are rejected as tool arguments. Policy comes only from server configuration.

### Review modes

- `exact_head`: `expected_commit == pr.head.sha`, and current approvals must cover that exact head.
- `merged_pr`: the PR is merged, `pr.merge_commit_sha == expected_commit`, and approvals cover the final PR head. This does not prove that reviewers directly approved the merge or squash commit.

The verifier paginates reviews, considers each reviewer's latest decision-bearing state, ignores `COMMENTED` and `PENDING` as decision changes, rejects a latest `CHANGES_REQUESTED`, handles `DISMISSED`, and counts distinct current approvals only. It does not reconstruct historical branch rulesets. When `require_non_author` is enabled, a missing, null, malformed, or non-positive PR author ID produces `unknown / REVIEW_AUTHOR_EVIDENCE_UNAVAILABLE`, never a pass.

### Release approval model and rerun limitation

The supported process uses one initial run for build/attestation and protected-environment release approval. The run attempt must match the certificate, expected commit, caller workflow, event, successful conclusion, and optional `expected_run`. At least one historical approval must name the exact environment, come from an allowed numeric user ID, and satisfy `prevent_self_approval` against both run actor and triggering actor.

GitHub's [workflow-run approval history API](https://docs.github.com/en/rest/actions/workflow-runs#get-the-review-history-for-a-workflow-run) exposes approvals at run level, without an attempt field. This MCP therefore does **not** claim that such an approval is bound to a rerun. A certified `runInvocationURI` with an attempt greater than 1 fails with `RUN_ATTEMPT_UNSUPPORTED`, and approval lookup is not used to authorize that rerun. `expected_run.attempt > 1` is rejected before verification. Attempt-aware validation can be enabled only after GitHub supplies and this project validates a safe binding.

When `prevent_self_approval` is enabled, both `actor.id` and `triggering_actor.id` must be valid positive numeric IDs. Missing or malformed evidence produces `unknown / RUN_ACTOR_EVIDENCE_UNAVAILABLE`.

Separate build and deployment runs are out of scope because this MVP has no standard cryptographic binding from a separate deployment approval to the image digest. Today's environment settings are not treated as proof of historical enforcement.

## Verification chain

| Link | Evidence and policy |
| --- | --- |
| Repository to commit | Repo-scoped GitHub commit lookup with full SHA equality. |
| Commit to reviewed change | PR base/head/merge records and paginated review decisions under the server-side policy. |
| Workflow run to build identity | Sigstore certificate fields populated from GitHub OIDC, including issuer, exact signer identity/digest, source repository/SHA/ref, GitHub-hosted runner, and run invocation. Immutable repository/owner IDs are cross-checked when available. |
| Attestation to artifact | `gh attestation verify` validates the Sigstore bundle, DSSE statement, SLSA v1 predicate, and exact in-toto subject digest. One fully acceptable result is sufficient. |
| Registry tag to digest | `crane digest`, then `crane manifest` by digest. The returned manifest bytes are independently hashed and compared with the resolved digest. |
| OCI index to platform image | A runtime digest passes only by direct equality or exact descriptor containment in a recognized OCI image index or Docker manifest list. An image manifest with a forged `manifests` field, unknown media type, or contradictory structure is rejected. |
| Kubernetes to running bytes | UID-based Deployment to ReplicaSet to Pod ownership, named container status, `imageID`, running state, readiness, rollout counts, and a second stability snapshot. Labels alone never establish ownership. |
| Run to release approval | Historical run-approval records for attempt 1 only, exact environment, numeric approver allowlist, and self-approval policy. Approval comments are not copied into receipts. |
| Optional Cosign signature | An additional independent signature check when required by trusted policy; GitHub artifact attestation already provides signature/provenance verification. |

Security decisions use certificate and verified-timestamp evidence, not workflow-controlled predicate fields such as `resolvedDependencies` or predicate invocation IDs. Raw custom predicates are not copied into reports. `bundle_sha256` identifies the canonical JSON representation of the returned `attestation.bundle`, not a retained raw bundle file.

### Registry and runtime edge cases

A moved tag produces `TAG_MOVED`; a digest-input/runtime mismatch produces `RUNTIME_DIGEST_MISMATCH`. A crane-induced digest-input substitution fails registry resolution with `REGISTRY_DIGEST_MISMATCH`. A child absent from the attested OCI index fails. A bare local/config ID or unrecognized `imageID` produces `IMAGE_ID_NOT_REGISTRY_COMPARABLE` and status `unknown`, not a fabricated digest mismatch. A conclusive running-digest mismatch fails even if a rollout is also incomplete.

Kubernetes is read before and after verification. Changes to target Pod UIDs, container IDs, image IDs, rollout revision, or readiness produce `RUNTIME_CHANGED_DURING_VERIFICATION` and status `unknown`. When the Deployment has a valid nonempty `spec.selector.matchLabels`, ReplicaSet and Pod list calls use that selector server-side; UID ownership checks still run locally. Invalid or absent selectors fall back to unfiltered namespace reads.

## Producer contract

The supported release workflow must check out and build the certified source commit, push the image to GHCR, capture the digest emitted by the push/build step, and attest that exact digest. The attestation subject name must not include a tag.

```yaml
permissions:
  id-token: write
  attestations: write
  contents: read
  packages: write
  # Optional when supported and needed: artifact-metadata: write

steps:
  - uses: actions/checkout@v4
    with:
      ref: ${{ github.sha }}

  # Build and push with a step that emits the exact pushed manifest/index digest.
  - id: push
    run: |
      ./ci/build-and-push.sh
      # This script must set steps.push.outputs.digest to the exact pushed digest.

  - uses: actions/attest@v4
    with:
      subject-name: ghcr.io/ORG/IMAGE
      subject-digest: ${{ steps.push.outputs.digest }}
      push-to-registry: true
```

Use a protected reusable workflow pinned in the server-side policy by `signer_digest` for stronger builder isolation. GitHub artifact attestations alone provide SLSA v1 Build L2; Build L3 requires a suitable isolated builder design. This tool does not infer Build L3 merely because a reusable workflow was used.

References:

- [GitHub build provenance](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds)
- [actions/attest](https://github.com/actions/attest)
- [gh attestation verify](https://cli.github.com/manual/gh_attestation_verify)
- [GitHub SLSA guidance](https://docs.github.com/en/enterprise-cloud@latest/actions/how-tos/secure-your-work/use-artifact-attestations/increase-security-rating)

## Output and failure semantics

Reports use schema `release-deployment-proof/v1`. Each check is independently marked `verified`, `failed`, or `unknown`, with structured reasons and evidence references. Top-level `missing_coverage` lists every unknown check. Aggregation is strict:

1. Any failed check makes the report `failed`.
2. Otherwise any unknown check makes it `unknown`.
3. Only all required checks verified makes the report `verified`.

Examples of honest degradation:

- Authoritative absence of attestation: `failed / ATTESTATION_MISSING`.
- Only SBOM/custom evidence: `failed / PROVENANCE_MISSING`.
- Empty or malformed successful verifier JSON: `unknown / VERIFIER_OUTPUT_INVALID`.
- Search reached 100 results without an acceptable result: `unknown / ATTESTATION_SEARCH_TRUNCATED`.
- Wrong identity, source SHA/ref, signer digest, trusted signer selection, or self-hosted runner: failed policy reasons.
- Opaque verifier rejection: `failed / ATTESTATION_VERIFICATION_FAILED`.
- Timeout, DNS, rate limit, trust-root fetch failure, or RBAC denial: unknown coverage, not absence.
- Overall deadline or cancellation: `unknown / VERIFICATION_DEADLINE_EXCEEDED` or `VERIFICATION_CANCELLED`.
- Expired short-lived certificate with valid verified signing-time evidence remains valid; later expiration alone is not a failure.
- Required Cosign signature absent: `failed / SIGNATURE_MISSING`.

The receipt contains evidence links where available, selected allowlisted certificate/attestation fields, sanitized runtime observations, tool versions, effective policy/hash, and explicit limitations. Approval comments are always omitted. Environment credentials, common token forms, Bearer values, authorization-header values, and known GitHub token formats are redacted from retained diagnostics and every tool's version output. Receipt evidence arrays retain at most 100 entries and disclose omitted counts in `evidence_truncation`; a serialized receipt over 512 KiB is rejected with an RPC error rather than returned as an evidence claim. Review reports before sharing because names, commit IDs, and user IDs can still be sensitive.

For operational control, requests carrying `_meta.progressToken` receive `notifications/progress` stage updates. `notifications/cancelled` cooperatively terminates the active process group and marks remaining coverage unknown. Stdio tool calls run separately so cancellation and ping requests can be processed during verification. The overall deadline and all cleanup waits are bounded.

## What this does not prove

Even a verified receipt does not prove:

- absence of vulnerabilities, malware, or reviewer mistakes;
- reproducible builds, complete dependency capture, or that the artifact is mathematically derived from source;
- that the workflow was benign or correctly implemented;
- historical branch-protection or environment-rule enforcement;
- attempt-bound approval on a workflow rerun;
- uncompromised signers, runners, GitHub, Sigstore, registry, Kubernetes API, kubelet, or nodes;
- integrity of a mutable container filesystem after startup;
- future tag stability, registry availability, or that future restarts will pull the same bytes;
- coverage of a separate deployment run or unrelated tags/registries.

This is an observation-window receipt, complementary to admission controllers. Continue to use digest-pinned deployment, admission enforcement, isolated builders, vulnerability scanning, and operational monitoring.

## Tests and live verification

The deterministic suite mocks external network services through one argv-based fake adapter and also launches real local Python subprocesses for timeout, process-tree cleanup, output-limit, cancellation, redaction, and `shell=False` coverage. It covers pass/fail/unknown behavior across every chain link, exact identity and trusted-policy matching, OCI structure validation, output bounds, schema stability, and injection rejection. No test invokes production mutation commands.

```sh
.venv/bin/python -m pytest -q
.venv/bin/python -m compileall -q src tests
```

An optional live smoke test is skipped by default. Run it only against a dedicated repository, GHCR image, and test cluster, with the operator policy configured:

```sh
RELEASE_PROOF_LIVE_SMOKE=1 \
RELEASE_PROOF_POLICY_FILE=/secure/config/release-policy.json \
RELEASE_PROOF_POLICY_PROFILE=production \
RELEASE_PROOF_LIVE_INPUT='{"repo":"acme/shop", ...}' \
.venv/bin/python -m pytest -q -m live tests/test_live_smoke.py
```

The live path remains environment-dependent and is not claimed as verified by the mocked/local CI result. Live compatibility still needs to cover real GitHub approval/rerun behavior, `gh` JSON contracts, GHCR manifest/index races, Kubernetes distributions and container runtimes, Cosign trust, and actual MCP clients.
