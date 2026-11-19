# Changelog

## Unreleased

### Added

- Add the emitted `release-deployment-proof/v2` receipt with UUID4 `receipt_id`, optional base64url `consumer_nonce`, complete subject including run/ref/workflow and repository IDs, verifier identity, policy descriptor, and effective policy.
- Add standard in-toto Statement and DSSE PAE Ed25519 proofs with signed issuer, key ID, algorithm, and signing-time metadata. Support direct key injection or explicitly opted-in development/test file keys while retaining unsigned local receipts by default.
- Add version-pinned OpenBao Transit signing with raw-PAE Ed25519, pinned-public-key self-verification, TLS/redirect controls, bounded strict responses, cancellable end-to-end network deadlines, static-token and Kubernetes authentication, and no unsigned fallback.
- Record a single-operator live vertical slice across reviewed GitHub evidence, approved initial Actions run, GHCR, kind, OpenBao, and independent consumer allow/deny; document its limits in `docs/live-validation-2026-11-18.md`.
- Add optional verifier instance and operator-supplied build-digest metadata; the build digest is not measured or verified provenance.
- Add the independent offline `release-proof-verify` consumer with exact full-subject and full-verifier expectations, policy hash, issuer, trusted public key, nonce, consumer-side maximum age, and 0/1/2 allow/deny/input exit codes.

### Changed

- Break receipt v1 consumer compatibility: v2 requires the new metadata and full subject, renames `merge_commit_directly_reviewed` to `expected_commit_directly_reviewed`, and rejects v1 rather than relabeling it.
- Pin runtime dependencies to `cryptography==50.0.2` and `jsonschema==4.26.0`.
- Correct OCI image manifest recognition from `application/vnd.oci.image.manifest.v2+json` to the standard `application/vnd.oci.image.manifest.v1+json`, as exercised by the live GHCR fixture.
- Define independent package, MCP, policy, receipt, and reason-code compatibility contracts. The package remains 0.1.0 and these changes remain Unreleased.

### Security

- Add fail-closed validation of v2 schema, semantics, policy integrity, check aggregation, and retained evidence during signing and independent consumption.
- Bind the complete canonical receipt predicate and proof metadata to the DSSE signature; deny payload substitution, metadata relabeling, untrusted keys, expectation mismatches, stale/future observations, and invalid observation windows.
- Deny signed failed/unknown audit receipts and require all applicable checks to be verified before allowing.
- Reject duplicate JSON keys, invalid UTF-8, and nonfinite numbers; bound each consumer input/key file to 2 MiB and suppress input/evidence content in denial output.
- Enforce the 512 KiB MCP receipt bound after optional signing and never silently return unsigned output after a configured signing failure.
- Harden MCP JSON-RPC framing, lifecycle, input validation, bounded responses, cancellation, concurrency, and worker cleanup.
- Strengthen fail-closed release verification with operator-controlled policy profiles, exact signer/ref matching, current-attempt approval checks, complete runtime evidence, and provenance checks.

### Remaining work

- Expand the recorded single-operator live fixture into a provider/runtime and independent-adoption matrix.
- Validate production TLS, HSM/key custody, rotation/revocation, audit, sealing, HA, and managed-cloud KMS operations; implement evidence-package distribution, authenticated isolated remote cells, and nonblocking output. No broad enterprise-readiness claim is made.
