# Compatibility

## Independent version contracts

- Package: `release-proof-mcp` uses Semantic Versioning (SemVer). The current release is `0.1.1` and the development version is `0.1.2`. `release_proof_mcp.__version__`, package metadata, and MCP `serverInfo.version` share the package version.
- MCP protocol: `2025-06-18`, versioned independently of the package and evidence contracts.
- Policy: `release-proof-policy/v1`, versioned independently.
- Receipt: `release-deployment-proof/v2`, implemented and emitted. Unsigned local receipts are the default; configured MCP signing adds an in-toto Statement and DSSE Ed25519 proof. The [v2 JSON Schema](src/release_proof_mcp/schemas/receipt-v2.json) defines the concrete shape, and the [sanitized golden receipt](tests/fixtures/receipt-v2.golden.json) illustrates it.
- Evidence package manifest: `release-proof-evidence-package/v1`, versioned independently. Its optional v2 receipt descriptor is additive; ordinary v2 receipts are unchanged. A descriptor-bearing receipt requires the exact five-file package during consumer verification.

## Receipt v2 breaking changes

The v2 consumer rejects v1 receipts with `SCHEMA_VERSION_UNSUPPORTED`; changing only the version string is not a migration.

Producers must add required UUID4 `receipt_id`, nullable `consumer_nonce`, complete `verifier` metadata, `policy_descriptor`, and the full subject. In addition to the original artifact and workload identities, the subject requires `source_ref`, `workflow`, `expected_run`, `source_repository_id`, and `source_repository_owner_id`, using explicit nulls where allowed. `evidence.pull_request.merge_commit_directly_reviewed` is renamed `expected_commit_directly_reviewed`.

Signed receipts require signed `proof_metadata` for `issuer`, `keyid`, `algorithm`, and `signed_at`. The standard in-toto/DSSE payload must match the canonical receipt predicate; outer metadata relabeling and payload substitution are denied.

Consumers must provide exact full-subject and full-verifier objects with no missing or extra keys, plus the expected policy hash, issuer, trusted key ID/public key, nonce, and consumer-side maximum age. Matching only an artifact digest or a verifier subset is not compatible with the v2 consumer contract.

## Version policy

Package, MCP, policy, receipt, and evidence-package manifest versions move independently. Adding required receipt fields, removing or renaming fields, or changing field/proof semantics is breaking and requires a new receipt contract version. Consumers must not reinterpret an unknown receipt or package version as a supported one.

The consumer's freshness contract combines nonce equality with consumer-side time and maximum-age checks. It has no one-time replay cache. Failed and unknown receipts may use the same signed audit format but are always denied by the gate.

`release-proof-verify` returns 0 for allow, 1 for deny, and 2 for input/usage errors. Receipt, expectation, and public-key inputs are each limited to 2 MiB; strict JSON rejects duplicate keys, nonfinite numbers, and excessive nesting. Packages use the documented per-file and total bounds and exact five-file set. These behaviors are part of the consumer interface.

## Reason codes

Adding a reason code is additive and may occur within an existing policy or receipt contract version. Removing or renaming a code, or changing its meaning, is breaking and requires a new contract version. Consumers must handle unrecognized codes without treating them as success.

## Python and dependencies

Supported Python is `>=3.11`.

The exact `cryptography==50.0.2` and `jsonschema==4.26.0` pins are interim until hash-locked release artifacts are available. They do not make builds reproducible or hermetic: transitive dependencies and build inputs are not hash-locked.

## Provider and enterprise status

Two single-operator live records are available. `docs/live-validation-2026-11-18.md` covers the provider path and standalone signed receipt; `docs/live-validation-2026-11-20.md` adds a real private-GHCR, kind, stdio MCP, OpenBao five-file package export and independent consumer allow/deny run. These are not a provider/runtime matrix, independent organizational adoption, production key custody, or broad enterprise-readiness claim. Remote package distribution, authenticated isolated remote cells, nonblocking output, and high availability remain separate unimplemented work. Production TLS, HSM/key custody, audit, sealing, and managed-cloud KMS remain unvalidated.
