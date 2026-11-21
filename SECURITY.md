# Security Policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use this repository's private GitHub vulnerability reporting channel, or contact the repository maintainers privately if that channel is unavailable. Include the affected version, a minimal reproduction, the verification check involved, and whether any credential or production evidence was exposed. Do not include live tokens, kubeconfig contents, private registry credentials, or sensitive cluster records in a report.

## Security boundary

This MVP is a read-only evidence verifier. It does not deploy, mutate, remediate, or enforce admission. A `verified` report means only that the specified evidence links and server-side trusted policy passed during the observation window. It does not mean that signed software is safe.

The producer emits `release-deployment-proof/v2` receipts with a UUID4 receipt ID, optional base64url consumer nonce, full subject, verifier identity, policy descriptor, effective policy, and policy hash. Receipts are unsigned by default for local use. Failed and unknown receipts may be signed for audit, but the independent consumer denies them.

The verifier trusts the configured GitHub, Sigstore, GHCR, and Kubernetes services to return accurate evidence, while independently checking the documented relationships between that evidence. It does not defend against a compromised GitHub/Sigstore trust path, registry, Kubernetes API, kubelet, node, or signer. Predicate fields controlled by the originating workflow are not used as trusted identity policy.

Review/release rules, signer workflow/digest, and the Cosign requirement come from the operator's policy file, never MCP policy arguments. The active profile is selected by server configuration and supplies omitted `signer_workflow` and `signer_digest` fields. Any caller-supplied signer value must match the profile exactly; a difference fails with `SIGNER_POLICY_MISMATCH`. Approval comments are omitted because they are unnecessary, untrusted content and may contain credentials.

GitHub environment approval history is run-level, not demonstrably attempt-bound. Only certified run attempt 1 is accepted, and the current run attempt must still be 1 when release approval is evaluated. Certified or current rerun attempts fail with `RUN_ATTEMPT_UNSUPPORTED`.

## Signed receipts and consumer trust

Optional signing uses a standard in-toto Statement, DSSE pre-authentication encoding, and Ed25519. The signed predicate includes `proof_metadata` for issuer, key ID, algorithm, and signing time. `policy_hash` only identifies effective-policy content; it is not a receipt signature. Signing requires fail-closed schema, semantic, and retained-evidence validation before and after proof creation, with no unsigned fallback after a signing failure.

`release-proof-verify` requires an exact full subject and full verifier expectation, policy hash, issuer, trusted key ID and Ed25519 public key, consumer nonce, and maximum age. It validates the signature, v2 schema and semantics, retained-evidence invariants, policy consistency, observation window, and freshness. Only a `verified` receipt with complete applicable checks and no evidence truncation can allow; a truncated receipt is denied with `EVIDENCE_TRUNCATED`. The v2 consumer rejects v1 receipts.

The consumer runs locally without AI/MCP or provider credentials. It does not requery GitHub, GHCR, or Kubernetes, or rerun Sigstore cryptographic verification. It trusts the producer for live observations and data not retained in the receipt, including desired replica counts. A receipt alone omits the complete OCI index child list; package verification checks index-child membership against the retained exact OCI bytes. Signature and retained-evidence validation do not prove software safety or provide admission enforcement.

Consumer nonce equality and consumer-side maximum age provide freshness, not a one-time replay cache. Generate a fresh base64url challenge for each evaluation and add caller-side replay tracking when one-time use is required.

## Credential handling

Provide provider credentials only through server configuration and existing gh, crane, Docker, and kubectl credential stores. Never place them in MCP arguments or the trusted policy file. Use least privilege:

- GitHub read access for contents, pull requests, Actions, and attestations, plus GHCR package pull.
- Kubernetes `get/list` only for the named Deployment and namespace ReplicaSets/Pods.
- No write, deployment, or auto-remediation permissions are needed.

Programmatic signing requires direct injection of the private key, issuer, and key ID together. The stdio server's file-key path requires `RELEASE_PROOF_SIGNING_KEY_FILE`, `RELEASE_PROOF_SIGNING_ISSUER`, `RELEASE_PROOF_SIGNING_KEY_ID`, and `RELEASE_PROOF_ALLOW_FILE_SIGNING_KEY=1` together. The unencrypted Ed25519 PEM key is limited to 16 KiB. On POSIX, use mode 600; group or other permission bits are rejected. This file-key path is for development/testing only.

The OpenBao Transit backend signs exact raw DSSE PAE with a pinned numeric key version and verifies the returned signature with a pinned public key. Production requires HTTPS with hostname verification; redirects are disabled and response sizes, end-to-end deadlines, cancellation, and authentication-lock waits are bounded. Connection establishment and request sending are separately checked so no request bytes are sent after cancellation; a still-shutting-down worker rejects new requests until it exits. DNS resolution itself remains dependent on the runtime and egress environment. Use a short-lived sign-only credential or Kubernetes service-account role; runtime needs no private-key export permission. Full PAE and retained evidence are sent to OpenBao, so its endpoint and audit path are part of the trust boundary. Local development-mode integration does not validate production TLS, sealing, HA, audit behavior, HSM backing, or managed-cloud KMS.

Optional `RELEASE_PROOF_VERIFIER_INSTANCE_ID` and `RELEASE_PROOF_BUILD_DIGEST` values populate verifier metadata and are covered by the proof when signing is enabled. The build digest is an operator-supplied assertion, not a measured binary identity or verified build provenance.

The process runner does not invoke a shell, applies per-command and overall deadlines, terminates the process group on timeout/cancellation, and bounds output and reader cleanup. On POSIX, each output reader owns a detached raw descriptor and closes it after EOF or a bounded stop request; the coordinator never closes that descriptor on the reader's behalf. Windows retains separate job-contained stream cleanup. Common credential forms are redacted from command stderr and tool-version values used internally. Raw command stderr is not retained in receipts or operator logs; stable reason codes are returned instead. Reports intentionally omit raw authorization data, kubeconfig, registry credentials, approval comments, and custom predicates. Review reports before sharing because resource names, commit IDs, user IDs, and effective policy may still be operationally sensitive.

## Verification requirements

Use `gh` 2.102.0 or newer. Do not weaken the version floor, replace exact signer matching with prefixes or regular expressions, compare source refs case-insensitively, accept empty successful verifier output, or enable insecure Cosign/registry options. External reusable builders require a full signer commit digest, and the requested signer must match the trusted profile. `GH_VERSION_UNSUPPORTED` is an `unknown` outcome.

An expired short-lived Sigstore certificate is not inherently a failure when verified signing-time evidence proves that signing occurred during its validity window. Missing or unverifiable signing-time evidence must not be treated as equivalent; `SIGNING_TIME_UNVERIFIED` is an `unknown` outcome.

Both `failed` and `unknown` are not verified. A deployment gate must fail closed on either state and on malformed, oversized, cancelled, timed-out, stale, mismatched, or incomplete reports. The consumer CLI returns 0 for allow, 1 for deny, and 2 for input/usage errors; every nonzero result is a denial.

Consumer receipt, expectation, and public-key inputs are each limited to 2 MiB. Strict bounded UTF-8 JSON rejects duplicate object keys, nonfinite numbers, and excessive nesting. Denial output is bounded and does not echo input or evidence contents. The MCP serialized-receipt limit remains 512 KiB after optional signing.

The optional `RELEASE_PROOF_EVIDENCE_PACKAGE_ROOT` is operator-only configuration and requires signing. Local export writes exactly five files under `root/<receipt_id>`, using owner-only POSIX directories/files, platform-native access controls elsewhere, staged no-overwrite publication, and failure cleanup. Only verified, non-truncated evidence is exported. Package consumers use no-follow directory descriptors on POSIX and `lstat` plus `st_dev`/`st_ino` identity revalidation on Windows, reject extra or nonregular entries, enforce per-file and total bounds, and never trust package-supplied keys. The package contains the effective policy, accepted Sigstore bundle, and exact OCI bytes, so it must be protected and reviewed as sensitive evidence.

## Operational recommendations

Use protected, isolated reusable builders pinned by digest; digest-pinned deployments; admission-time signature/policy enforcement; current dependency and image scanning; and continuous runtime monitoring. Protect policy, expectation, key, and evidence-package files with operating-system permissions and audit changes. This receipt and consumer complement those controls rather than replacing them.

Stdout writes and flushes remain blocking under `_write_lock`, so a stalled client pipe can impede responsiveness and delay other output. Use `serve()` for supported stdio concurrency; direct concurrent in-process `handle()` calls are not a supported substitute. Nonblocking output, high availability, authenticated isolated remote cells, and remote evidence-package distribution remain unimplemented. OpenBao development-mode signing is validated, but production TLS, HSM/key custody, rotation/revocation operations, audit reliability, sealing, HA, and managed-cloud KMS remain unvalidated.
