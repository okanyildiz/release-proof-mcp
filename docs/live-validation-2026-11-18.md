# Live interoperability evidence: 2026-11-18

## Scope

A dedicated fixture produced a genuine `release-deployment-proof/v2` receipt with `status=verified`, an OpenBao Transit Ed25519 signature, and an independent consumer allow decision. This is a single-operator interoperability result, not enterprise separation of duties or production-readiness evidence.

## Recorded identities and artifacts

- Private fixture repository: `okanyildiz/release-proof-live-fixture` (changed from public to private after the recorded run).
- Pull request: #1, authored by `github-actions[bot]` (`41898282`) and approved by `okanyildiz` (`21282605`).
- Final PR head reviewed: `ee607bc3921bc80994a9bce188f0509c12d12c8d`.
- Merge commit: `8730053e8b161b9ae49144eec6eafad3150a475e`. The merge commit itself was not directly reviewed.
- Source ref: `refs/heads/release/8730053e8b161b9ae49144eec6eafad3150a475e`.
- Release run: `44390632747`, `workflow_dispatch`, attempt 1, successful. Actor and triggering actor were `github-actions[bot]`.
- Production approval: human `okanyildiz`; the environment required review and prevented self-review.
- GHCR artifact: `ghcr.io/okanyildiz/release-proof-live-fixture@sha256:75512113ef9a0a590fd99e3d1998e163f10eb9cc8e96fe1fa91d928544b07962`.
- Actual registry media type: `application/vnd.oci.image.manifest.v1+json`. This exposed and fixed the verifier's previous incorrect `v2+json` expectation.
- Runtime: a fresh kind cluster, Kubernetes 1.37.0, two ready Pods, exact direct `imageID` digest match, stable sequential observations, explicit `kind-release-proof-live` context, and a separate read-only ServiceAccount.
- Signer: OpenBao 2.7.2 Transit, key version 1, `release-proof/transit/release-proof/v1`.
- Receipt ID: `79efff12-0b4d-4b0c-9309-6e870d39288a`.
- Canonical receipt digest: `sha256:d09d005ae510581f8a72e2213b2cbd2fdd85d3f820ed4474a563bd751279ebf8`.
- Policy hash: `sha256:64eefdad8063a74928e0f93b21f8dcb2ef05865b1e552914b7dd8aa185e21c32`.

## Outcomes

| Scenario | Result |
| --- | --- |
| Real GitHub review/run/approval -> GHCR -> kind verifier | `verified` |
| Real MCP call with OpenBao Transit signing | `verified`, DSSE Ed25519 proof |
| Independent consumer without provider credentials | exit 0, `allow=true`, `OK` |
| Receipt subject tampering | exit 1, `RECEIPT_INVALID` |
| Wrong consumer nonce | exit 1, `NONCE_MISMATCH` |
| Wrong target container name | `failed`, `CONTAINER_NOT_FOUND` |
| Real OpenBao integration after network-deadline changes | passed |
| Offline deterministic suite | 651 passed, 2 opt-in tests skipped |

Tool versions included GitHub CLI 2.105.0, crane 0.20.7, kubectl 1.37.0, Docker 24.0.6, kind 0.33.0, and OpenBao 2.7.2.

## Required qualifications

- One operator controlled both automation and the human account. This does not demonstrate independent organizational review or release duties.
- The automatic PR-close dispatcher initially failed because it expected a checkout. A corrected dispatcher was manually run at a later infrastructure commit, which created the release ref and dispatched the successful release. The artifact itself remains bound to the reviewed merge SHA, but the entire automation chain was not reviewed through the fixture PR.
- The release ref is not `main`; historical branch protection is not reconstructed.
- The attestation was retrieved through the GitHub API, not GHCR referrer storage. Cosign was not required for this run.
- The kind result proves the tested containerd/GHCR path only, not managed Kubernetes distributions, other runtimes, HA, admission control, node integrity, or production scale.
- OpenBao ran in explicitly insecure loopback development mode with a narrowly scoped test token. This validates the real Transit API and signature path, not production TLS, workload-auth operations, sealing, HA, audit reliability, backup/restore, HSM backing, or production key custody.
- The receipt issuer was `https://issuer.example`; this is test metadata. The build digest is operator-supplied wheel metadata, not a measured running-binary identity.
- The fixture repository and GHCR package are now private. The recorded release ran while the repository and package were public. Any future private-repository attestation/environment run and private-package pull must be re-evaluated against the account's GitHub plan and access rules.

No production readiness, compliance certification, SLSA-level claim, or general zero-vulnerability claim follows from this fixture.
