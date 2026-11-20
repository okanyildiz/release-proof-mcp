# Release Proof MCP

[![CI](https://github.com/okanyildiz/release-proof-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/okanyildiz/release-proof-mcp/actions/workflows/ci.yml)

Release Proof MCP is a read-only evidence producer and independent receipt verifier for release promotion decisions. It connects approved change records, their associated GitHub commit, and an approved initial build to the OCI image digest Kubernetes reports running, then lets a separate consumer verify a signed receipt without provider credentials.

The important distinction is trust separation: a pipeline or AI agent can request evidence, but an independent consumer, not that caller, decides whether the producer's signed statement is authentic, fresh, and allowed by operator policy. The consumer does not re-query GitHub, GHCR, or Kubernetes, or repeat upstream Sigstore verification. The producer therefore remains part of the observation trust boundary.

## Why teams need it

A green build alone does not prove that the bytes running in a cluster are the bytes produced by the reviewed and approved change. Release Proof MCP makes that relationship explicit during one observation window.

It fits teams already using GitHub Actions, GHCR, and Kubernetes Deployments with digest-pinned images and an initial-run approval process. It is a post-rollout promotion and audit-evidence tool, not a general deployment platform.

## See the model in about a minute

No GitHub, registry, cluster, or OpenBao is needed for the simulated demo:

```sh
release-proof demo
```

```text
[SIMULATED] Verified signed receipt: id=cc880909-0b2c-4c3a-a733-447c807ca260
[SIMULATED] Independent consumer: allow=True, reason=OK
[SIMULATED] One-byte tamper: allow=False, reason=RECEIPT_INVALID
[SIMULATED] Digest mismatch: status=failed, reason=TAG_MOVED
[SIMULATED] Registry unavailable: status=unknown, reason=REGISTRY_UNAVAILABLE
[SIMULATED] No network, provider, cluster, or external signing service was used
```

The demo uses packaged simulated responses and an ephemeral in-memory key. The signature and independent consumer checks are real. It does not write a key or evidence package to disk and is not a live integration result.

## How it works

<p align="center">
  <img src="assets/architecture.svg" alt="Source, review, build identity, attestation, registry, runtime, and receipt chain" width="100%">
</p>

1. The operator supplies a server-side policy and a reviewed source, run, artifact, and workload target.
2. `release-proof capture`, or the MCP tool, checks source and review records, the initial Actions identity, Sigstore provenance, GHCR digests, approvals, and the named container's `imageID`.
3. The producer emits a `release-deployment-proof/v2` receipt with complete subject, verifier, policy hash, reasons, and missing coverage.
4. Optional OpenBao Transit or development-key signing produces an in-toto/DSSE Ed25519 proof and an optional five-file evidence package.
5. The independent `release-proof-verify` consumer checks the signature and exact expectations offline and returns `0` allow, `1` deny, or `2` input error.

`failed` and `unknown` always deny. Missing evidence is never treated as success, and no configured signing failure silently falls back to an unsigned receipt.

## Status and evidence, plainly stated

This is alpha software with a narrow supported topology: GitHub.com, Actions, GHCR, a Kubernetes Deployment, and one named container. Only certified run attempt 1 is accepted. It is not an admission controller, vulnerability scanner, continuous enforcement agent, or software-safety guarantee.

Current validation includes:

- 861 deterministic tests passed locally on macOS with three skips. Windows CI includes additional platform- or capability-specific skips; two skips on each host are opt-in live tests.
- Real single-operator live runs covering GitHub, GHCR, kind, OpenBao Transit, a signed standalone receipt, and a five-file package with independent offline allow/deny behavior.
- [GitHub Actions CI](https://github.com/okanyildiz/release-proof-mcp/actions/workflows/ci.yml) runs the Linux, macOS, and Windows matrix on Python 3.11, 3.12, and 3.13. The current result must pass before release.
- `v0.1.0` and `v0.1.1` artifacts were built locally and are unattested. `v0.1.2` is prepared for workflow-built, attested artifacts, but no such release is claimed here.

These runs do not establish independent organizational adoption, production key custody, production TLS/HA, Cosign interoperability, or a managed-Kubernetes/provider matrix.

## Where it fits, and where it does not

- [GitHub artifact attestations](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds) establish build provenance. Release Proof MCP adds independent observation of the running digest and applies review and approval policy to produce a portable promotion receipt.
- [GitHub's linked artifacts page](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/establish-provenance-and-integrity/view-linked-artifacts) shows build history, deployment records, and storage details. This project gives an offline consumer a signed artifact of its own to evaluate rather than relying only on a hosted view.
- [Kubernetes admission controllers](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/) can accept or reject API requests before objects are persisted. Release Proof MCP does not mutate workloads or enforce admission; it observes after rollout and leaves any promotion action to a separate system.
- Continuous change-recording and deployment platforms preserve ongoing history. Release Proof MCP provides a point-in-time signed observation and does not replace deployment logs, monitoring, or continuous enforcement.
- Other registries, source providers, workload kinds, reruns, and separate deployment workflows are outside the current contract. In `merged_pr` mode, the reviewed PR head and its associated merge or squash commit are distinct; the latter is not necessarily directly reviewed.

## Install and capture real evidence

Python 3.11 or newer is required, with `gh>=2.102.0`, `crane`, and `kubectl`. OpenBao is the built-in non-development CLI signing backend. Cosign is needed only when policy requires it. Programmatic capture also accepts an injected `ReceiptSigner`.

This pre-release preview pins the reviewed commit containing the producer CLI. It is not a signed or attested release. Before the public release, replace this with the release instructions:

```sh
git clone https://github.com/okanyildiz/release-proof-mcp.git
cd release-proof-mcp
git checkout 1fad405a7c86a21e92ba84af05d518bb0ad7b097
python3.11 -m venv .venv
. .venv/bin/activate
pip install .
release-proof capture --request capture-request.json --nonce-file consumer-nonce.txt --out current-receipt.json
```

Use a dedicated environment and follow the exact policy, reviewer/approver IDs, signing, runtime, and trust-distribution instructions. Do not put credentials in request JSON, policy files, MCP arguments, or chat.

For workflow-produced releases starting with `v0.1.2`, verify downloaded project distributions with GitHub's build-provenance command, then check the release checksums. This is separate from the producer's OCI attestation checks and the consumer's offline DSSE receipt verification:

```sh
gh attestation verify release_proof_mcp-0.1.2-py3-none-any.whl --repo okanyildiz/release-proof-mcp
gh attestation verify release_proof_mcp-0.1.2.tar.gz --repo okanyildiz/release-proof-mcp
sha256sum -c SHA256SUMS.txt
```

Earlier unattested releases support checksum verification only. No PyPI publication is claimed.

## Read next

- [Complete operating guide](GUIDE.md): policy, OpenBao, CLI and MCP capture, package export, consumer, CI gates, privacy, and failure playbooks.
- [Detailed project reference](docs/reference.md): verification chain, configuration, receipt examples, integration, security model, limitations, roadmap, and FAQ.
- [Raw stdio MCP appendix](docs/mcp-capture.md) for advanced protocol integrations.
- [Compatibility contracts](COMPATIBILITY.md) for policy, receipt, package, protocol, and exit-code semantics.
- [Security policy](SECURITY.md) for trust boundaries and private vulnerability reporting.
- Live evidence: [2026-11-18](docs/live-validation-2026-11-18.md) and [2026-11-20](docs/live-validation-2026-11-20.md), including their limits.
- [Contributing](CONTRIBUTING.md) and [code of conduct](CODE_OF_CONDUCT.md).

Issues are the current support path. Do not disclose suspected vulnerabilities in a public issue and do not attach live tokens, kubeconfig data, registry credentials, approval comments, or sensitive production evidence.
