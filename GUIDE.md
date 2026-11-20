# Release Proof MCP: v0.1.1 usage guide

This guide applies to the `v0.1.1` release, receipt schema `release-deployment-proof/v2`, and evidence-package schema `release-proof-evidence-package/v1`. Replace every example identity and absolute placeholder path with reviewed values for a dedicated environment. Examples contain no credentials.

## 1. Honest fit and a typical company workflow

Use this project for **post-rollout candidate-to-promotion decisions and audit evidence**. It observes an already-deployed Kubernetes workload and links the running image digest to GitHub source/review records, an approved initial Actions run, Sigstore provenance, and GHCR. A separate consumer can allow or deny a promotion decision from signed evidence.

A typical integration is:

1. An author opens a PR and an allowed reviewer approves the relevant head commit.
2. The initial release workflow builds the reviewed commit, pushes and attests the GHCR digest, receives protected-environment approval, and deploys the candidate.
3. After rollout, the producer calls `verify_release_deployment` against the named Deployment and container.
4. A consumer verifies the signed receipt or evidence package against independently supplied trust settings and exact expectations. Its existing promotion system, not this project, acts on an allow decision.
5. An auditor retains the evidence and decision. Signed `failed` and `unknown` receipts remain useful audit records, but never allow promotion.

This fits teams already using **GitHub.com, GitHub Actions, GHCR, and a Kubernetes Deployment**, with digest-pinned images and an initial-run approval process. It is useful when a security or release team needs portable evidence that a consumer can check without provider credentials.

Do not use it as:

- an admission controller, deployment mechanism, or continuous enforcement agent;
- a vulnerability, malware, reproducibility, node-integrity, or software-safety scanner;
- proof of future tag pulls, later restarts, or post-start filesystem state;
- a provider-general solution for other source services, registries, workload kinds, or separate deployment workflows;
- a way to make Actions reruns trustworthy.

Only certified run **attempt 1** is supported, and the current run attempt must still be 1. Never rerun a release to repair evidence in this model. A retry below means a new read-only observation with a fresh nonce against an unchanged eligible initial run. A genuinely new candidate must go through its own review, approval, build, attestation, and initial run.

The current policy contains `review.pull_request`. Therefore a new PR normally creates a new effective policy and a new `policy_hash`; distribute that new hash independently for every release. The offline consumer still trusts the producer's live observations. It does not requery GitHub, GHCR, Sigstore, or Kubernetes.

## 2. Personas and separation of duties

| Persona | Responsibility | Must not do |
| --- | --- | --- |
| Author | Prepare the PR and release candidate. | Be the sole reviewer when `require_non_author=true`, or self-approve when prevented. |
| Reviewer | Provide the required current, allowed, non-author review of the PR head. | Assume `merged_pr` means the merge commit itself was directly reviewed. |
| Approver | Approve the exact protected environment in the initial run under the approver policy. | Treat run-level approval history as attempt-bound or approve a rerun. |
| Operator | Own the server, trusted policy, read-only provider credentials, signing configuration, and package root. | Let the MCP caller select policy, approvers, or signer settings. |
| Consumer or promotion service | Generate a fresh nonce; own exact subject/verifier expectations, trusted policy hash, issuer, key ID/public key, and age limit; deny every nonzero result. | Copy expected values from the receipt or package being verified. |
| Auditor | Retain signed receipts, packages, decisions, policy/key lineage, and exceptions. | Interpret signed `failed` or `unknown` evidence as approval. |

For organizational separation, these roles need appropriately independent identities and change control. The [recorded live fixture](docs/live-validation-2026-11-18.md) was **single-operator only**: one operator controlled automation and the human account. It does not demonstrate independent organizational review or enterprise separation of duties.

## 3. Prerequisites, versions, and permissions

### Versions

| Component | Current requirement | Recorded live fixture, not a general compatibility claim |
| --- | --- | --- |
| Python | 3.11 or newer; examples invoke `python3.11` | No Python version was recorded |
| Runtime dependencies | `cryptography==50.0.2`, `jsonschema==4.26.0` | Not separately recorded |
| GitHub CLI | `gh>=2.102.0`; the producer enforces this floor | `gh 2.105.0` |
| `crane` | Required; no minimum is enforced by this branch | `0.20.7` |
| `kubectl` | Required; no minimum is enforced by this branch | Client and kind Kubernetes `1.37.0` |
| `cosign` | Required only when `require_cosign_signature=true`; no floor is enforced | No live Cosign result |
| OpenBao | Optional signing backend; use an organization-approved, patched release | OpenBao `2.7.2`, insecure loopback development only |
| MCP protocol | `2025-06-18`, strict newline-delimited JSON-RPC 2.0 over stdio | Real MCP call completed |

Docker `24.0.6` and kind `0.33.0` were fixture tools, not normal producer prerequisites. The dependency pins do not make the installation hermetic or reproducible. Production OpenBao TLS, workload-auth operations, sealing, HA, audit reliability, HSM backing, and managed KMS remain unvalidated by this project.

### Check out and install v0.1.1

Clone the repository and check out the exact release tag rather than a moving branch:

```sh
git clone https://github.com/okanyildiz/release-proof-mcp.git /absolute/path/release-proof-mcp
git -C /absolute/path/release-proof-mcp switch --detach v0.1.1
test "$(git -C /absolute/path/release-proof-mcp describe --tags --exact-match HEAD)" = v0.1.1
git -C /absolute/path/release-proof-mcp rev-parse HEAD
python3.11 -m venv /absolute/path/release-proof-mcp/.venv
/absolute/path/release-proof-mcp/.venv/bin/python -m pip install /absolute/path/release-proof-mcp
/absolute/path/release-proof-mcp/.venv/bin/python -c 'import release_proof_mcp; print(release_proof_mcp.__version__)'
gh --version
crane version
kubectl version --client -o json
```

Create owner-only working locations as the appropriate service owner. On separate producer and consumer hosts, use the equivalent protected paths on each host:

```sh
install -d -m 700 /secure/config /secure/keys /secure/openbao
install -d -m 700 /secure/evidence/packages /secure/receipts /secure/work
install -d -m 700 /secure/consumer/config /secure/consumer/trust
```

### Least-privilege credentials

Configure credentials in existing credential stores, never in MCP arguments, policy JSON, chat, or shell history:

- GitHub: read repository contents, PRs/reviews, Actions runs and approvals, and attestations. Private-repository attestation and environment behavior must be rechecked against the account's plan.
- GHCR: package pull using the existing `crane`/Docker credential store. Package visibility is separate from repository visibility.
- Kubernetes: an explicit context with `get` on the named Deployment and `get`/`list` on ReplicaSets and Pods in its namespace. No create, update, patch, delete, deploy, or remediation permission is needed.

A minimal Role ruleset for the example namespace is:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: release-proof-reader
  namespace: production
rules:
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get"]
  - apiGroups: ["apps"]
    resources: ["replicasets"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"]
```

Bind it only to the verifier's dedicated ServiceAccount. Kubernetes list permissions are namespace-scoped and are not restricted to one resource name by `resourceNames`.

The independent consumer needs the installed package and its Python dependencies, but **no GitHub, GHCR, Kubernetes, Sigstore, OpenBao, or other provider credentials and no network access**. It does need its independently distributed public key, policy hash, expectations, and nonce.

## 4. Configure and distribute a release-specific trusted policy

Save this as `/secure/config/release-policy.json` after replacing all sanitized values. Numeric reviewer and approver IDs are GitHub user IDs, not login names. This file is policy, not a credential store:

```json
{
  "schema_version": "release-proof-policy/v1",
  "profiles": {
    "production": {
      "version": "pr-123.1",
      "signer_workflow": "acme/shop/.github/workflows/release.yml",
      "signer_digest": null,
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

`signer_digest=null` is valid only for this same-repository signer pinned by exact `source_ref`. An external reusable signer requires its full 40-character commit digest. The schema is closed. If multiple profiles exist, `RELEASE_PROOF_POLICY_PROFILE` is mandatory; the MCP caller cannot supply `review`, `release`, `policy_profile`, or `require_cosign_signature`.

```sh
chmod 600 /secure/config/release-policy.json
export RELEASE_PROOF_POLICY_FILE=/secure/config/release-policy.json
export RELEASE_PROOF_POLICY_PROFILE=production
```

Derive the trusted hash from the reviewed policy, not from any receipt:

```sh
(umask 077
/absolute/path/release-proof-mcp/.venv/bin/python - \
  /secure/config/release-policy.json production \
  > /secure/config/production-policy-hash.txt <<'PY'
import sys
from release_proof_mcp.policy import PolicyStore

policy = PolicyStore.from_file(sys.argv[1]).select(sys.argv[2])
print(policy.sha256)
PY
)
```

The value is `sha256:` plus SHA-256 of the compact, key-sorted UTF-8 JSON for the **effective** profile. It includes the profile name, version, normalized reviewer/approver lists, and the PR number; it is not a hash of the raw policy file and is not a signature.

Have the policy reviewer independently recompute and approve the value. Distribute the policy hash through an authenticated, change-controlled channel to `/secure/consumer/config/production-policy-hash.txt`, with mode `0600`. Never take `--policy-hash`, the effective policy, or any other expectation from `receipt.json` or the package being checked. When the PR or policy changes, repeat review, derivation, and independent distribution; an old hash must deny the new release.

## 5. Configure OpenBao signing

Local receipts are unsigned by default and cannot allow the independent consumer. Package export requires signing. File-based private keys and insecure loopback are development/test paths, not a production key-custody design.

### Production configuration baseline, not production validation

Have an OpenBao administrator use an existing protected administrative session. Enable the default Transit mount once and create a non-exportable, non-derivation Ed25519 key:

```sh
bao secrets enable transit
bao write transit/keys/release-proof \
  type=ed25519 derived=false exportable=false allow_plaintext_backup=false
```

Do not enable key export or plaintext backup later. Pin version `1` in this example; rotation to another version requires a new reviewed key ID/public-key distribution and server configuration, not automatic consumer trust in `latest`.

Save this sign-only ACL as `/secure/config/openbao-release-proof-sign.hcl`:

```hcl
path "transit/sign/release-proof" {
  capabilities = ["update"]
}
```

Grant the workload no key-read, key-write, export, backup, verify, or administrative endpoint. Enable the default Kubernetes auth mount and bind exactly one dedicated ServiceAccount and namespace to the policy:

```sh
bao policy write release-proof-sign /secure/config/openbao-release-proof-sign.hcl
bao auth enable kubernetes
bao write auth/kubernetes/role/release-proof-signer \
  bound_service_account_names=release-proof-mcp \
  bound_service_account_namespaces=release-proof-system \
  policies=release-proof-sign \
  ttl=10m
```

Configure `auth/kubernetes/config` using the [official OpenBao short-lived-token guidance](https://openbao.org/docs/auth/kubernetes/) for the actual cluster and OpenBao placement. That choice is environment-specific; do not put a reviewer JWT in commands, files in this repository, chat, or logs. The adapter logs in only at `/v1/auth/kubernetes/login` and reads the producer ServiceAccount token from `/var/run/secrets/kubernetes.io/serviceaccount/token`.

Read the version-1 public key through the administrator session and convert the documented Ed25519 raw public-key value to PEM. This command reads key metadata, not private-key material, and refuses to overwrite an existing trust file:

```sh
(umask 077
/absolute/path/release-proof-mcp/.venv/bin/python - <<'PY'
import base64
import hashlib
import json
import os
import subprocess

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

result = subprocess.run(
    ["bao", "read", "-format=json", "transit/keys/release-proof"],
    check=True,
    capture_output=True,
    text=True,
)
data = json.loads(result.stdout)["data"]
if data["type"] != "ed25519" or data["exportable"] is not False:
    raise ValueError("Unexpected Transit key type or exportability")
if data.get("allow_plaintext_backup") is not False:
    raise ValueError("Plaintext backup must be disabled")
entry = data["keys"]["1"]
raw = base64.b64decode(entry["public_key"].encode("ascii"), validate=True)
key = Ed25519PublicKey.from_public_bytes(raw)
pem = key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
fd = os.open("/secure/keys/release-proof-v1-public.pem", flags, 0o600)
with os.fdopen(fd, "wb") as output:
    output.write(pem)
print("Public key SHA-256:", hashlib.sha256(raw).hexdigest())
PY
)
```

The public key is not a secret, but its authenticity and immutability are security-critical. Compare the fingerprint with the key administrator's independent record, then distribute the exact PEM and key ID through a separate authenticated channel to `/secure/consumer/trust/release-proof-v1-public.pem` with mode `0600`. Do not accept a key supplied by a receipt or package. See the [OpenBao Transit API](https://openbao.org/docs/api/secret/transit/) for key metadata and versioning.

Use HTTPS with a certificate whose hostname matches the configured origin. This example uses a private CA bundle; omit `RELEASE_PROOF_OPENBAO_CA_FILE` only when the system trust store is intended:

```sh
export RELEASE_PROOF_OPENBAO_ADDRESS=https://openbao.example:8200
export RELEASE_PROOF_OPENBAO_TRANSIT_MOUNT=transit
export RELEASE_PROOF_OPENBAO_KEY_NAME=release-proof
export RELEASE_PROOF_OPENBAO_KEY_VERSION=1
export RELEASE_PROOF_OPENBAO_PUBLIC_KEY_FILE=/secure/keys/release-proof-v1-public.pem
export RELEASE_PROOF_OPENBAO_KUBERNETES_ROLE=release-proof-signer
export RELEASE_PROOF_OPENBAO_CA_FILE=/secure/openbao/openbao-ca.pem
export RELEASE_PROOF_OPENBAO_TIMEOUT_SECONDS=10
export RELEASE_PROOF_SIGNING_ISSUER=https://release-proof.example.com/producer
export RELEASE_PROOF_SIGNING_KEY_ID=release-proof/transit/release-proof/v1
export RELEASE_PROOF_VERIFIER_INSTANCE_ID=producer-01
export RELEASE_PROOF_EVIDENCE_PACKAGE_ROOT=/secure/evidence/packages
unset RELEASE_PROOF_OPENBAO_TOKEN RELEASE_PROOF_OPENBAO_ALLOW_INSECURE_LOOPBACK
unset RELEASE_PROOF_SIGNING_KEY_FILE RELEASE_PROOF_ALLOW_FILE_SIGNING_KEY
unset RELEASE_PROOF_BUILD_DIGEST
```

The key ID must end in `/v1` to match the pinned numeric version. Exactly one of static token or Kubernetes role authentication is allowed. The adapter signs the exact raw DSSE pre-authentication encoding with `hash_algorithm=none` and `prehashed=false`, then verifies the returned signature with this pinned public key. It sends the full PAE and retained evidence to OpenBao, so the endpoint and its audit path are inside the privacy and trust boundary. There is no unsigned fallback after a signing failure.

For development only, plain HTTP requires both a loopback address such as `http://127.0.0.1:8200` and `RELEASE_PROOF_OPENBAO_ALLOW_INSECURE_LOOPBACK=1`, plus exactly one test authentication method loaded through a protected local credential store. The recorded loopback test does not validate production TLS, workload auth, key custody, sealing, HA, audit operations, backup/restore, HSM backing, or managed KMS. Do not carry development settings into the production example above.

`RELEASE_PROOF_VERIFIER_INSTANCE_ID` and `RELEASE_PROOF_BUILD_DIGEST` become exact consumer expectations. This example leaves build digest null. A configured build digest is an operator-supplied assertion, not a measured running-binary identity.

## 6. Establish exact expectations and a fresh nonce

Before capture, the consumer or release coordinator creates `/secure/consumer/config/consumer-expectations.json` from the approved release request, digest-pinned deployment configuration, trusted repository metadata, and known verifier configuration. Do not generate this file from the returned receipt.

This sanitized example deliberately uses digest-form artifact input, so `artifact_input` and the independently expected `pinned_artifact` are identical:

```json
{
  "subject": {
    "repo": "acme/shop",
    "expected_commit": "0123456789abcdef0123456789abcdef01234567",
    "artifact_input": "ghcr.io/acme/shop@sha256:0c987afb70eaca35f5f47da7654ae92d10dc0103f9efd775d370e183301e12d7",
    "pinned_artifact": "ghcr.io/acme/shop@sha256:0c987afb70eaca35f5f47da7654ae92d10dc0103f9efd775d370e183301e12d7",
    "source_ref": "refs/heads/main",
    "workflow": ".github/workflows/release.yml",
    "expected_run": {
      "id": 123456789,
      "attempt": 1
    },
    "source_repository_id": "555",
    "source_repository_owner_id": null,
    "kube_context": "production",
    "namespace": "production",
    "deployment": "shop-api",
    "container": "api"
  },
  "verifier": {
    "name": "release-proof-mcp",
    "version": "0.1.0",
    "instance_id": "producer-01",
    "build_digest": null
  }
}
```

Both objects are closed and every key shown is required. Replace `null` repository-owner or build-digest values when the independently known value is non-null; explicit nulls are still part of exact matching. `expected_run` may be null only when that field was intentionally omitted at capture; this example pins the initial run. Keep the full 40-character lowercase commit, exact case-sensitive source ref, full OCI digest, and complete verifier metadata. Protect the file:

```sh
chmod 600 /secure/consumer/config/consumer-expectations.json /secure/consumer/config/production-policy-hash.txt
chmod 600 /secure/consumer/trust/release-proof-v1-public.pem
```

Generate a new nonce for each consumer evaluation and keep it available for both the MCP call and the subsequent consumer check:

```sh
(umask 077
/absolute/path/release-proof-mcp/.venv/bin/python - <<'PY'
import os
import secrets

path = "/secure/work/consumer-nonce.txt"
flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(path, flags, 0o600)
with os.fdopen(fd, "wb") as output:
    os.fchmod(output.fileno(), 0o600)
    output.write(secrets.token_urlsafe(24).encode("ascii"))
PY
)
```

`secrets.token_urlsafe(24)` produces a fresh 32-character base64url value using only `A-Z`, `a-z`, `0-9`, `_`, and `-`, within the allowed 22-128 characters. The capture example propagates this exact string as `consumer_nonce`; the consumer later passes it as `--nonce`. Do not print it into chat or routine logs, reuse it for another evaluation, or treat it as a provider credential. Use a unique evaluation workspace rather than these `current` files when running evaluations concurrently.

The producer input also requires a full lowercase commit, a GHCR tag or SHA-256 digest reference, an exact `refs/heads/...` or `refs/tags/...` source ref, an explicit context and container, and attempt 1 when `expected_run` is supplied. The example omits caller signer fields so they inherit the trusted policy. Tags are supported, but digest input makes independent pinned-artifact expectations straightforward.

## 7. Capture a receipt through executable stdio MCP

The following inline Python starts the real server, completes `initialize` and `notifications/initialized`, calls `verify_release_deployment`, and keeps stdin open until the matching tool response arrives. It handles JSON-RPC errors, skips notifications, serializes `result.structuredContent` without changing its fields, and writes owner-only files. Run it in the configured producer environment after replacing the sanitized expectations:

```sh
/absolute/path/release-proof-mcp/.venv/bin/python - <<'PY'
import json
import os
import select
import subprocess
import time
import uuid
from pathlib import Path

SERVER = "/absolute/path/release-proof-mcp/.venv/bin/release-proof-mcp"
EXPECTATIONS = "/secure/consumer/config/consumer-expectations.json"
NONCE = "/secure/work/consumer-nonce.txt"
RECEIPT_ROOT = "/secure/receipts"
PACKAGE_ROOT = "/secure/evidence/packages"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
RESPONSE_TIMEOUT = 150

with open(EXPECTATIONS, "r", encoding="utf-8") as source:
    expectation = json.load(source)
subject = expectation["subject"]
if subject["artifact_input"] != subject["pinned_artifact"]:
    raise ValueError("This capture example requires digest-form artifact input")
nonce = Path(NONCE).read_text(encoding="ascii")
arguments = {
    key: subject[key]
    for key in (
        "repo",
        "expected_commit",
        "workflow",
        "source_ref",
        "kube_context",
        "namespace",
        "deployment",
        "container",
    )
}
arguments["artifact"] = subject["artifact_input"]
arguments["consumer_nonce"] = nonce
if subject["expected_run"] is not None:
    arguments["expected_run"] = subject["expected_run"]

process = subprocess.Popen(
    [SERVER],
    cwd="/absolute/path/release-proof-mcp",
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    bufsize=0,
)
if process.stdin is None or process.stdout is None:
    raise RuntimeError("MCP pipes were not created")


def send(message):
    frame = json.dumps(
        message, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii") + b"\n"
    process.stdin.write(frame)
    process.stdin.flush()


def response_for(request_id):
    deadline = time.monotonic() + RESPONSE_TIMEOUT
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Timed out waiting for the MCP response")
        ready, _, _ = select.select([process.stdout], [], [], remaining)
        if not ready:
            raise TimeoutError("Timed out waiting for the MCP response")
        line = process.stdout.readline(MAX_RESPONSE_BYTES + 1)
        if not line:
            raise RuntimeError("MCP server closed stdout before responding")
        if len(line) > MAX_RESPONSE_BYTES:
            raise ValueError("MCP response exceeds the capture limit")
        message = json.loads(line.decode("utf-8"))
        if not isinstance(message, dict):
            raise ValueError("MCP response is not an object")
        if "id" not in message:
            continue
        if message.get("id") != request_id:
            raise ValueError("MCP response has an unexpected request ID")
        if "error" in message:
            error = message["error"]
            raise RuntimeError(
                f"MCP JSON-RPC error {error.get('code')}: {error.get('message')}"
            )
        result = message.get("result")
        if not isinstance(result, dict):
            raise ValueError("MCP response has no object result")
        return result


def write_private(path, data, overwrite):
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    flags |= os.O_TRUNC if overwrite else os.O_EXCL
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


try:
    send({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "release-proof-capture", "version": "1"},
        },
    })
    initialized = response_for(1)
    if initialized.get("protocolVersion") != "2025-06-18":
        raise ValueError("MCP protocol version mismatch")
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    send({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "verify_release_deployment",
            "arguments": arguments,
        },
    })
    result = response_for(2)
    if result.get("isError") is not False:
        raise RuntimeError("MCP tool returned an error result")
    receipt = result.get("structuredContent")
    if not isinstance(receipt, dict):
        raise ValueError("MCP tool result has no structuredContent receipt")
    receipt_id = receipt.get("receipt_id")
    parsed_id = uuid.UUID(receipt_id) if isinstance(receipt_id, str) else None
    if parsed_id is None or parsed_id.version != 4 or str(parsed_id) != receipt_id:
        raise ValueError("Receipt has no canonical UUID4 receipt_id")
    encoded = json.dumps(
        receipt, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")
    write_private(f"{RECEIPT_ROOT}/{receipt_id}.json", encoded, overwrite=False)
    write_private("/secure/work/current-receipt-id", receipt_id.encode("ascii"), overwrite=True)
    print(f"receipt_id={receipt_id}")
    print(f"receipt_file={RECEIPT_ROOT}/{receipt_id}.json")
    if "evidence_package" in receipt:
        print(f"package_directory={PACKAGE_ROOT}/{receipt_id}")
    else:
        print("package_directory=none; retain the signed audit receipt")
finally:
    try:
        process.stdin.close()
    except BrokenPipeError:
        pass
    try:
        process.wait(timeout=140)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    process.stdout.close()
PY
```

Do **not** treat `release-proof-mcp > /secure/receipts/receipt.json` as sufficient. Server stdout carries JSON-RPC envelopes and can carry multiple messages; it is not a bare receipt channel. The consumer requires the signed receipt object or package, not an initialization response or protocol transcript. A JSON-RPC error produces no evidence claim. A tool result with `status=failed` or `unknown` can still be a signed audit receipt and is saved, but the consumer will deny it.

### Package creation and location

With `RELEASE_PROOF_EVIDENCE_PACKAGE_ROOT=/secure/evidence/packages` and a working signing backend, a `verified` receipt with empty `evidence_truncation` is exported before the MCP response returns. The package is:

```text
/secure/evidence/packages/<receipt_id>/
    receipt.json
    manifest.json
    effective-policy.json
    sigstore-bundle.json
    oci-manifest.json
```

Use the printed `receipt_id`, or read the locator file written by the capture example:

```sh
RECEIPT_ID="$(cat /secure/work/current-receipt-id)"
printf '%s\n' "/secure/evidence/packages/$RECEIPT_ID"
```

The locator is only a path aid, not a source of consumer expectations. Export creates a real `<root>/<receipt_id>` directory with exactly those five regular files, using staged no-overwrite publication. On POSIX the directory is `0700` and files are `0600`. Signing is mandatory. `failed`, `unknown`, and truncated receipts are not packaged; failed and unknown results instead remain signed audit receipts with no `evidence_package` claim. Export/signing failures produce a JSON-RPC error rather than an unsigned fallback.

For receipt-only operation, unset `RELEASE_PROOF_EVIDENCE_PACKAGE_ROOT` while retaining signing. A verified receipt exported with a package descriptor cannot later be consumed as a standalone receipt.

## 8. Verify offline with exact trust inputs

`release-proof-verify` selects receipt-file or package-directory mode from the input path. All other arguments remain the same. `--max-age 300` is an example policy choice: a nonnegative integer number of seconds measured by the consumer from receipt `completed_at` to its current UTC time. Choose and approve a value that fits the actual capture-to-promotion flow. The CLI also denies future observation/signing times and inverted observation windows.

Set the locator from the capture step and load the independently distributed hash and exact nonce:

```sh
RECEIPT_ID="$(cat /secure/work/current-receipt-id)"
POLICY_HASH="$(cat /secure/consumer/config/production-policy-hash.txt)"
NONCE="$(cat /secure/work/consumer-nonce.txt)"
```

For a signed **standalone receipt captured without package export**, run:

```sh
/absolute/path/release-proof-mcp/.venv/bin/release-proof-verify \
  "/secure/receipts/$RECEIPT_ID.json" \
  --trusted-public-key /secure/consumer/trust/release-proof-v1-public.pem \
  --keyid release-proof/transit/release-proof/v1 \
  --expectations /secure/consumer/config/consumer-expectations.json \
  --issuer https://release-proof.example.com/producer \
  --policy-hash "$POLICY_HASH" \
  --nonce "$NONCE" \
  --max-age 300
```

For an **exported evidence package**, run:

```sh
/absolute/path/release-proof-mcp/.venv/bin/release-proof-verify \
  "/secure/evidence/packages/$RECEIPT_ID" \
  --trusted-public-key /secure/consumer/trust/release-proof-v1-public.pem \
  --keyid release-proof/transit/release-proof/v1 \
  --expectations /secure/consumer/config/consumer-expectations.json \
  --issuer https://release-proof.example.com/producer \
  --policy-hash "$POLICY_HASH" \
  --nonce "$NONCE" \
  --max-age 300
```

Do not verify only the `receipt.json` inside an exported package: a receipt containing `evidence_package` is denied with `PACKAGE_REQUIRED`. Supply the package directory so its attachments are checked too.

The command emits bounded decision JSON without raw receipt or package contents. Exit codes are:

| Exit | Meaning | Gate behavior |
| --- | --- | --- |
| `0` | `allow=true`, reason `OK`; signature, status, exact expectations, retained evidence, freshness, and any package attachments passed. | Allow the separate promotion action. |
| `1` | Deny, including `failed`/`unknown`, stale evidence, mismatches, invalid signatures, or invalid packages. | Deny. |
| `2` | Input or usage error, including unreadable/malformed inputs or invalid CLI use. | Deny; never treat it as a warning. |

A fail-closed `/bin/sh` CI wrapper can take the receipt file or package directory as its first argument. It intentionally maps **every** nonzero status to denial:

```sh
#!/bin/sh
set -eu
INPUT=${1:?usage: release-proof-gate.sh RECEIPT_OR_PACKAGE_PATH}
POLICY_HASH=$(cat /secure/consumer/config/production-policy-hash.txt)
NONCE=$(cat /secure/work/consumer-nonce.txt)
if /absolute/path/release-proof-mcp/.venv/bin/release-proof-verify "$INPUT" \
  --trusted-public-key /secure/consumer/trust/release-proof-v1-public.pem \
  --keyid release-proof/transit/release-proof/v1 \
  --expectations /secure/consumer/config/consumer-expectations.json \
  --issuer https://release-proof.example.com/producer \
  --policy-hash "$POLICY_HASH" \
  --nonce "$NONCE" \
  --max-age 300
then
  printf '%s\n' 'Release evidence allowed; the separate promotion step may proceed.'
else
  status=$?
  printf 'Release evidence denied (consumer exit %s); promotion blocked.\n' "$status" >&2
  exit 1
fi
```

The consumer verifies DSSE Ed25519, signed issuer/key metadata, exact full subject and verifier, policy hash and internal policy consistency, nonce, status, evidence invariants, and age. Package mode additionally verifies the exact file set, signed manifest, attachment sizes/hashes, canonical policy and Sigstore bundle, and exact OCI bytes. It does not rerun upstream provider or Sigstore verification.

Nonce equality and maximum age provide freshness, **not one-time replay prevention**. There is no replay cache. If one-time use is required, the consumer must generate and track challenges and mark them consumed in its own system.

## 9. Transport, retention, and privacy

The five package files have distinct roles:

- `receipt.json`: signed v2 receipt and package manifest descriptor;
- `manifest.json`: exact attachment paths, sizes, and SHA-256 hashes;
- `effective-policy.json`: canonical effective policy for audit and consistency checking, not an independent consumer expectation;
- `sigstore-bundle.json`: the canonical accepted Sigstore bundle, including its signed in-toto predicate and any custom predicate fields present;
- `oci-manifest.json`: exact bytes returned by `crane manifest`.

Workflow-controlled custom predicate fields are retained inside the Sigstore bundle but are not copied into the receipt or trusted for security decisions. The receipt intentionally omits approval comments, raw authorization data, kubeconfig contents, registry credentials, and raw custom predicates. Resource names, commit IDs, numeric user IDs, evidence links, effective policy, OCI metadata, and the full signed predicate can still be sensitive.

Transport the directory as exactly five files; there is no supported archive or extraction input. Authenticated remote package distribution is not implemented, so use an organization-approved authenticated channel and access-controlled storage outside this project. Preserve the exact bytes and names, reject extra entries, and retain owner-only `0700` directories and `0600` files on POSIX. The consumer separately rejects symlinks, nonregular files, oversized inputs, and extra files.

Define retention from legal, audit, incident-response, and data-minimization requirements rather than a universal duration. Restrict producer, consumer, auditor, backup, and log access accordingly. Never place live tokens, ServiceAccount JWTs, kubeconfig data, registry credentials, private keys, or sensitive production evidence in chat, tickets, or routine logs. Review even bounded decision logs for operationally sensitive identifiers.

## 10. Failure playbook

Always deny first and inspect the receipt's `reasons` and `missing_coverage`. `failed` is conclusive negative evidence; `unknown` is incomplete evidence. Neither is success. The table covers common codes, not an exhaustive allowlist; unrecognized codes also deny.

| Reason code(s) | Meaning and safe action | Retry or new run? |
| --- | --- | --- |
| `GITHUB_UNAVAILABLE`, `REGISTRY_UNAVAILABLE`, `RUNTIME_UNAVAILABLE`, `ATTESTATION_UNAVAILABLE`, `TRUST_ROOT_UNAVAILABLE`, `VERIFICATION_DEADLINE_EXCEEDED` | Transient service, network, trust-root, rate-limit, or deadline coverage gap. Fix the cause and observe again with a fresh nonce. | New read-only capture only; no release rerun. |
| `REPOSITORY_NOT_VISIBLE` | The repository is invisible to the credential or its metadata does not match the request. A later 404 cannot be conclusive in this state. | Restore repository visibility and capture again with a fresh nonce; do not reinterpret this as a missing commit or PR. |
| `GITHUB_ACCESS_DENIED`, `REGISTRY_ACCESS_DENIED`, `RUNTIME_ACCESS_DENIED`, `ATTESTATION_ACCESS_DENIED`, `COSIGN_ACCESS_DENIED` | Read or verification access was denied. Correct only the documented least-privilege access. | New capture after access repair; no release rerun. |
| `GH_VERSION_UNSUPPORTED`, `GH_VERSION_UNKNOWN`, `GH_UNAVAILABLE` | Install a working `gh>=2.102.0`; do not weaken exact signer/ref checks. | New capture after tool repair; no release rerun. |
| `ATTESTATION_MISSING`, `PROVENANCE_MISSING`, `ATTESTATION_VERIFICATION_FAILED`, `SIGNING_TIME_UNVERIFIED` | Provenance is absent, rejected, or lacks acceptable signing-time evidence. Do not infer safety or manufacture an attestation after the fact. | No blind retry. Correct the release process and create a newly reviewed candidate when required; never rerun the release. |
| `SIGNER_POLICY_MISMATCH`, `SIGNER_MISMATCH`, `SIGNER_DIGEST_MISMATCH`, `SOURCE_COMMIT_MISMATCH`, `SOURCE_REF_MISMATCH`, `REPOSITORY_ID_MISMATCH`, `RUN_IDENTITY_MISMATCH` | Trusted policy and certified identity disagree. Stop and reconcile independently reviewed inputs; never edit expectations to match the disputed receipt. | New capture only after a legitimate configuration correction; otherwise a new reviewed candidate. No rerun. |
| `REVIEW_POLICY_FAILED`, `REVIEW_EVIDENCE_INVALID`, `RELEASE_APPROVAL_MISSING`, `RELEASE_APPROVER_NOT_ALLOWED` | Required review or environment approval is absent, invalid, or not allowed. Use the normal independent review/approval process. | New capture may read legitimately updated records while the run remains attempt 1. Never bypass policy or rerun. |
| `RUN_ATTEMPT_UNSUPPORTED` | A certified or current rerun cannot inherit run-level approval evidence. | No retry or rerun can repair this. Start a genuinely new reviewed candidate and initial run. |
| `TAG_MOVED`, `REGISTRY_DIGEST_MISMATCH`, `ATTESTED_DIGEST_MISMATCH`, `RUNTIME_DIGEST_MISMATCH` | Artifact identities disagree. Stop promotion and investigate registry, attestation, and deployment state. | After a legitimate runtime correction, capture new evidence with a fresh nonce. Rebuild only as a new reviewed candidate; no rerun. |
| `CONTAINER_NOT_FOUND`, `NO_RUNNING_PODS`, `ROLLOUT_INCOMPLETE`, `CONTAINER_STATUS_MISSING`, `IMAGE_ID_NOT_REGISTRY_COMPARABLE` | Target or rollout evidence is wrong, incomplete, or not comparable. Correct the named target, finish/stabilize rollout, and use a runtime that reports a registry digest. | New observation after correction; no release rerun. |
| `RUNTIME_CHANGED_DURING_VERIFICATION`, `RUNTIME_OBSERVATION_INCOMPLETE`, `RUNTIME_EVIDENCE_INVALID` | A stable observation window was not established. | Retry observation after the rollout stabilizes; no release rerun. |
| `VERIFIER_OUTPUT_INVALID`, `ATTESTATION_SEARCH_TRUNCATED`, `ATTESTATION_EVIDENCE_INVALID`, `REGISTRY_RESPONSE_INVALID`, `CHECK_NOT_RUN` | Evidence is malformed, truncated, or incomplete. Preserve it for diagnosis and repair the producer/tool path. | New capture after repair; do not reinterpret as absence or success. |
| `PROOF_MISSING`, `PROOF_METADATA_MISSING`, `SIGNATURE_INVALID`, `PAYLOAD_MISMATCH`, `KEY_NOT_TRUSTED`, `KEYID_MISMATCH`, `ISSUER_MISMATCH` | Consumer authenticity or trust checks failed. Obtain an authentic signed input and independently trusted key/metadata. | Re-run the offline consumer after correcting inputs; never disable checks or accept unsigned output. |
| `SUBJECT_MISMATCH`, `VERIFIER_MISMATCH`, `POLICY_MISMATCH`, `NONCE_MISMATCH` | Exact expectations differ. Verify the approved release request, policy lineage, verifier configuration, and challenge propagation independently. | Correct trusted inputs only when they were genuinely wrong; otherwise capture the intended release with a fresh nonce. |
| `RECEIPT_STALE`, `OBSERVATION_TIME_FUTURE`, `PROOF_TIME_FUTURE`, `OBSERVATION_WINDOW_INVERTED` | Freshness or clock checks failed. Synchronize clocks and review the approved age limit. | Capture fresh evidence for promotion; do not increase max-age merely to force allowance. |
| `PACKAGE_REQUIRED`, `PACKAGE_FILE_SET_INVALID`, `PACKAGE_FILE_INVALID`, `MANIFEST_DIGEST_MISMATCH`, `ATTACHMENT_METADATA_MISMATCH`, `BUNDLE_ATTACHMENT_MISMATCH`, `OCI_MANIFEST_MISMATCH`, `OCI_CHILD_MISSING` | Package form or retained attachments are missing, changed, or inconsistent. | Re-run the consumer only on a complete authentic package; otherwise request new signed evidence. No release rerun. |
| `STATUS_NOT_VERIFIED`, `MISSING_COVERAGE`, `CHECKS_NOT_VERIFIED` | The signed audit receipt itself is not promotable. | Address the underlying producer reasons; signing never converts failure or unknown into approval. |
| `EVIDENCE_TRUNCATED` | The signed receipt omits evidence at a retention bound and is denied even when its retained checks are verified. | Preserve it as an audit record, but never allow promotion from partial evidence. Correct the evidence scope and capture a complete receipt with a fresh nonce. |
| `USAGE_ERROR`, `INPUT_ERROR` | CLI/input setup failed; exit 2 is still denial. | Fix the command or input path and rerun the offline consumer. No release rerun. |

## 11. Audit checklist and pilot measurements

### Evidence checklist

For each candidate, retain or link under access control:

- branch/revision and package version, MCP protocol version, producer `tools` versions, and exact verifier metadata;
- approved policy source, PR-specific effective policy, independently derived hash, policy change approval, and consumer distribution record;
- repository and owner IDs, full source commit/ref, PR head/merge relationship, unique review IDs and reviewer IDs, initial run ID/attempt, environment approval and approver IDs;
- artifact input, pinned GHCR digest, accepted attestation identity, OCI media type, runtime container/image IDs, observation window, and stable-rollout result;
- fresh-challenge lifecycle, consumer max-age and clock source, and any external one-time-use record without publishing the nonce;
- signing issuer, key ID/version, public-key fingerprint and distribution/rotation approval, plus relevant OpenBao authentication/signing audit records;
- signed receipt or exact five-file package, package transport/access record, and any `evidence_truncation`, `missing_coverage`, reasons, and limitations;
- bounded consumer decision JSON with decision ID, receipt ID/digest, policy hash, reason, evaluation time, and exit status;
- exceptions and remediation, preserving signed `failed` and `unknown` receipts rather than deleting unfavorable evidence.

`verifier.build_digest`, when present, remains an operator assertion. Neither a receipt nor a package reconstructs all provider state; package mode retains the exact OCI index bytes but still trusts the producer's live observations, including desired replica counts.

### Pilot measurements

Define acceptance criteria before the pilot and report observed values without claiming unmeasured improvement:

- count eligible candidates, captures, `verified`/`failed`/`unknown` outcomes, and each reason code;
- count consumer exit 0/1/2 decisions and verify in tests that every nonzero blocks the promotion job;
- measure capture latency, offline consumer latency, receipt age at decision, and evidence/package sizes; report the actual distribution and operational limits encountered;
- count package export failures, truncated receipts, transport rejects, attachment mismatches, RBAC denials, timeouts, and signing failures;
- exercise wrong nonce, stale receipt, tampered receipt, wrong key, missing attachment, and `failed`/`unknown` cases; record whether each was denied and retained;
- track fresh-nonce and exact-expectation coverage, per-release policy hash distribution, independent reviewer/approver/operator/consumer assignments, and every exception;
- test key-version rotation and revocation procedures, TLS failure behavior, workload token expiry, backup/restore, and audit delivery separately before any production claim;
- record promotion outcomes and later runtime drift separately, since this receipt provides no continuous enforcement.

A pilot is not complete merely because one happy path allows. Require fail-closed negative tests, usable audit reconstruction, sustainable per-release policy distribution, and an approved decision on the remaining producer and OpenBao trust boundaries.

## 12. What the recorded live result proves

See [docs/live-validation-2026-11-18.md](docs/live-validation-2026-11-18.md) for the exact identities, versions, outcomes, and qualifications. It narrowly records one dedicated GitHub.com/Actions/GHCR/kind path with a verified receipt, real OpenBao Transit development-mode signing, and independent consumer allow/deny behavior.

It does **not** establish independent organizational adoption, production key custody, production TLS or workload-auth operations, a provider/runtime matrix, a production cluster result, Cosign interoperability, HA, compliance certification, or enterprise readiness. Use it as reproduction evidence for a narrowly scoped vertical slice, not as a substitute for the pilot and production controls above.
