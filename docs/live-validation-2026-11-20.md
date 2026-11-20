# Local live evidence-package validation, 2026-11-20

## Scope

A dedicated local validation run exercised the development `0.1.1` source through a real stdio MCP server, private GHCR, an existing reviewed and approved initial GitHub Actions run, a new local kind Deployment, real OpenBao Transit signing, and the independent offline consumer.

This extends the 2026-11-18 standalone-receipt fixture with a real five-file evidence-package export. It is still a single-operator development validation, not production certification or independent organizational adoption.

## Source and runtime identities

- Repository: `okanyildiz/release-proof-live-fixture`, private during this observation.
- Pull request: #1, authored by `github-actions[bot]` and approved by `okanyildiz` (`21282605`).
- Reviewed merge commit: `8730053e8b161b9ae49144eec6eafad3150a475e`.
- Source ref: `refs/heads/release/8730053e8b161b9ae49144eec6eafad3150a475e`.
- Existing successful release run: `44390632747`, `workflow_dispatch`, attempt 1, production approval by `okanyildiz`.
- GHCR package: private during this observation.
- OCI digest: `sha256:75512113ef9a0a590fd99e3d1998e163f10eb9cc8e96fe1fa91d928544b07962`.
- OCI media type: `application/vnd.oci.image.manifest.v1+json`.
- Kubernetes: new kind cluster `kind-release-proof-local`, Kubernetes 1.37.0, namespace `production`, Deployment `shop-api`, container `api`, two ready Pods with exact direct digest matches.
- Observation window: `2026-11-20T11:45:38Z` through `2026-11-20T11:45:48Z`.
- Signer: OpenBao 2.7.2 Transit on loopback, key version 1, non-exportable Ed25519 key.
- Consumer verifier version: `0.1.1`, instance `local-live-01`.

The run reused the reviewed source and approved initial run from the earlier fixture while performing a fresh registry resolution, attestation verification, two-Pod rollout observation, package export, signature, and consumer evaluation. No release rerun was used.

## Receipt and package identities

- Receipt ID: `e9f6258b-046a-4b1e-8812-180f91be85b6`.
- Overall status: `verified`; `missing_coverage`, `reasons`, and `evidence_truncation` were empty.
- Policy hash: `sha256:78f6b302ea524b61a5b25d4a4afd73b936e10cca480e762b2fbf60909aa9406d`.
- Signed package manifest: `sha256:f3547281eb6ce48ca760886620b463cb9a117aeba199d8a82a0fc7a6306d1c3c`.
- Effective policy: 458 bytes, hash equal to the policy hash above.
- Sigstore bundle: 12,670 bytes, `sha256:a0e0de5acdebab3fb376dec838f553bdb204483d8af15b1abca2a46658cd85ac`.
- OCI manifest: 668 bytes, hash equal to the pinned OCI digest above.

The package contained exactly `receipt.json`, `manifest.json`, `effective-policy.json`, `sigstore-bundle.json`, and `oci-manifest.json`. The MCP response contained a DSSE proof and package descriptor.

## Outcomes

| Scenario | Result |
| --- | --- |
| Real private GHCR digest resolution and manifest retrieval | Passed |
| Real `gh attestation verify` against the existing provenance | One accepted result |
| Real stdio MCP verification and OpenBao Transit signing | `verified`, signed receipt |
| Five-file local package export | Exact expected file set |
| Independent consumer with provider credentials removed and `PATH` empty | Exit 0, `allow=true`, `OK` |
| Effective-policy attachment tampering | Exit 1, `ATTACHMENT_METADATA_MISMATCH` |
| Wrong consumer nonce | Exit 1, `NONCE_MISMATCH` |
| Descriptor-bearing receipt without package directory | Exit 1, `PACKAGE_REQUIRED` |
| Consumer usage error | Exit 2, `USAGE_ERROR` |
| Opt-in live provider smoke test | `1 passed` |
| Opt-in real OpenBao integration test | `1 passed` |

## Local test matrix

| Environment | Result |
| --- | --- |
| macOS Python 3.11 | `775 passed, 2 skipped` before the two opt-in tests were run separately |
| macOS Python 3.12 | `775 passed, 2 skipped` before the two opt-in tests were run separately |
| Docker Linux Python 3.11 | `775 passed, 2 skipped` |
| Docker Linux Python 3.12 | `775 passed, 2 skipped` after the strict MCP JSON fix |
| Docker Linux Python 3.13 | `775 passed, 2 skipped` after the strict MCP JSON and stream cleanup fixes |

Python 3.12 and 3.13 exposed a decoder-dependent deeply nested JSON result. The MCP server now applies the common strict JSON parser and depth bound consistently. Python 3.13 also exposed an unstarted-reader stream cleanup defect; subprocess stream objects are now closed explicitly and their closed state is asserted. The complete macOS and Linux suites passed after these fixes.

## Tool versions and integrity

- GitHub CLI 2.105.0, crane 0.20.7, kubectl and kind Kubernetes 1.37.0, kind 0.33.0, OpenBao 2.7.2, Docker 24.0.6.
- Downloaded gh, kind, OpenBao, and kubectl binaries were checked against official release digest or checksum metadata before use.
- Temporary GHCR credentials, package evidence, local signing material, and cluster configuration remained outside the tracked source tree. The GHCR credential file and kubeconfig were deleted after validation, and the dedicated kind cluster and OpenBao development server were stopped.

## Remaining limits

- This is not a native Windows result. Windows process cleanup still requires a real Windows runner.
- GitHub-hosted CI and build-provenance attestation for release artifacts remain blocked by the account billing restriction. No hosted CI or attested-release success is claimed.
- OpenBao used insecure loopback development mode and a local test credential. Production TLS, Kubernetes workload authentication, sealing, HA, audit reliability, backup/restore, HSM custody, and managed KMS remain unvalidated.
- The local kind observation used a development kubeconfig. It does not add new production RBAC evidence.
- No Cosign result, managed Kubernetes distribution, production cluster, provider matrix, or independent organizational adoption result is claimed.
- The package retains the effective policy, Sigstore predicate, resource identities, and OCI metadata and must be handled as sensitive evidence.
