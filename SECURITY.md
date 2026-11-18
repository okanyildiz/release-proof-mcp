# Security Policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use this repository's private GitHub vulnerability reporting channel, or contact the repository maintainers privately if that channel is unavailable. Include the affected version, a minimal reproduction, the verification check involved, and whether any credential or production evidence was exposed. Do not include live tokens, kubeconfig contents, private registry credentials, or sensitive cluster records in a report.

## Security boundary

This MVP is a read-only evidence verifier. It does not deploy, mutate, remediate, or enforce admission. A `verified` report means only that the specified evidence links and server-side trusted policy passed during the observation window. It does not mean that signed software is safe.

The verifier trusts the configured GitHub, Sigstore, GHCR, and Kubernetes services to return accurate evidence, while independently checking the documented relationships between that evidence. It does not defend against a compromised GitHub/Sigstore trust path, registry, Kubernetes API, kubelet, node, or signer. Predicate fields controlled by the originating workflow are not used as trusted identity policy.

Review/release rules, signer workflow/digest, and the Cosign requirement come from the operator's policy file, never MCP policy arguments. The active profile is selected by server configuration. Gate consumers must independently validate the receipt subject, effective policy, and policy hash. Approval comments are omitted because they are unnecessary, untrusted content and may contain credentials.

GitHub environment approval history is run-level, not demonstrably attempt-bound. Only initial run attempt 1 is accepted; rerun attempts fail with `RUN_ATTEMPT_UNSUPPORTED`.

## Credential handling

Provide credentials only through server configuration and existing gh, crane, Docker, and kubectl credential stores. Never place them in MCP arguments or the trusted policy file. Use least privilege:

- GitHub read access for contents, pull requests, Actions, and attestations, plus GHCR package pull.
- Kubernetes `get/list` only for the named Deployment and namespace ReplicaSets/Pods.
- No write, deployment, or auto-remediation permissions are needed.

The process runner does not invoke a shell, applies per-command and overall deadlines, terminates the process group on timeout/cancellation, bounds output and reader cleanup, and redacts common credential forms from retained diagnostics. Reports intentionally omit raw authorization data, kubeconfig, registry credentials, approval comments, and custom predicates. Review reports before sharing because resource names, commit IDs, user IDs, and effective policy may still be operationally sensitive.

## Verification requirements

Use `gh` 2.102.0 or newer. Do not weaken the version floor, replace exact signer matching with prefixes or regular expressions, compare source refs case-insensitively, accept empty successful verifier output, or enable insecure Cosign/registry options. External reusable builders require a full signer commit digest, and the requested signer must match the trusted profile.

An expired short-lived Sigstore certificate is not inherently a failure when verified signing-time evidence proves that signing occurred during its validity window. Missing or unverifiable signing-time evidence must not be treated as equivalent.

Both `failed` and `unknown` are not verified. A deployment gate must fail closed on either state and on malformed, oversized, cancelled, timed-out, or incomplete reports.

## Operational recommendations

Use protected, isolated reusable builders pinned by digest; digest-pinned deployments; admission-time signature/policy enforcement; current dependency and image scanning; and continuous runtime monitoring. Protect the policy file with operating-system permissions and audit policy changes. This receipt complements those controls rather than replacing them.
