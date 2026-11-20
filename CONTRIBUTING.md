# Contributing

Thank you for improving `release-proof-mcp`. Changes to an evidence verifier need precise behavior, explicit failure semantics, and tests for both positive and negative cases.

## Start with the right scope

- Open a [GitHub issue](https://github.com/okanyildiz/release-proof-mcp/issues) before substantial design or provider work.
- Keep each pull request focused on one behavior, fix, or documentation change.
- Do not include live credentials, private cluster records, approval comments, or sensitive production evidence in code, tests, issues, or pull requests.
- Report suspected vulnerabilities privately through [SECURITY.md](SECURITY.md), not through a public issue or pull request.

## Development setup

Use Python 3.11 or newer:

```sh
git clone https://github.com/okanyildiz/release-proof-mcp.git
cd release-proof-mcp
python3.11 -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
```

The runtime pins `cryptography==50.0.2` and `jsonschema==4.26.0`; the `test` extra installs pytest. These direct pins do not make the build hermetic or reproducible because transitive and build inputs are not hash-locked.

## Pull request process

1. Create a topic branch from the current default branch. Use a fork when contributing without repository write access.
2. Keep the public contract stable unless the PR explicitly discusses a schema or policy change. The tool is `verify_release_deployment`, the independent consumer is `release-proof-verify`, and the receipt schema is `release-deployment-proof/v2`.
3. Add or update deterministic tests for behavior changes. Cover success, conclusive failure, and unavailable evidence where those states are meaningful.
4. Update `README.md`, `SECURITY.md`, `COMPATIBILITY.md`, `CHANGELOG.md`, and relevant diagrams when behavior, requirements, contracts, limitations, or the verification chain changes.
5. Run the complete local checks before requesting review:

   ```sh
   python -m pytest -q
   python -m compileall -q src tests
   git diff --check
   ```

6. Open a pull request with:
   - the problem and chosen behavior;
   - affected verification-chain links and receipt fields;
   - the exact test commands and results;
   - whether external services were mocked or exercised live;
   - security, privacy, compatibility, and documentation impacts;
   - any remaining unknown coverage or platform limitations.

7. Respond to review with focused changes. Keep discussion in the PR so evidence-policy decisions remain auditable.

Do not claim that a live integration was tested when only deterministic fixtures ran. The live smoke test is opt-in and must use a dedicated repository, GHCR image, and test cluster. Never weaken an assertion or hide a failure to make a live test pass.

## Evidence and security review checklist

Reviewers and contributors should check that changes preserve these invariants:

- The server and consumer remain read-only: no deployment, mutation, approval, remediation, or admission behavior.
- Trusted policy comes only from the operator's server-side file and selected profile, never caller-controlled policy arguments.
- `failed` and `unknown` both remain non-verified, and any failed check takes precedence during aggregation. Signing either state for audit must not make it allowable.
- Missing evidence is not presented as authoritative absence. Timeouts, network errors, rate limits, and access denials remain `unknown` unless the code has conclusive policy evidence.
- Full commit SHAs, exact case-sensitive refs, signer workflow/digest, OCI digests, numeric user IDs, explicit Kubernetes context, and named container matching are not weakened.
- v2 receipts retain UUID4 IDs, optional base64url nonces, full subject and verifier metadata, policy descriptor/effective-policy consistency, and the documented breaking field names.
- Signed receipts use the standard in-toto Statement and DSSE PAE Ed25519 path. `proof_metadata` is authenticated, and configured signing never silently falls back to unsigned output.
- Consumers require exact full-subject and full-verifier expectations, policy hash, issuer, trusted key, nonce, and consumer-side maximum age. Freshness is not described as a one-time replay cache.
- Schema, semantic, and retained-evidence validation remains fail-closed. Documentation must distinguish receipt-only trust in the omitted OCI index child list from package-mode membership checks against the retained exact OCI bytes, while retaining the producer trust boundary for live observations, desired replica counts, and other non-retained data.
- Default local receipts remain unsigned. File signing keys require explicit development/test opt-in, owner-only POSIX permissions, and documented size/format limits; production KMS/HSM is not claimed.
- `RELEASE_PROOF_BUILD_DIGEST` remains an operator-supplied assertion, not measured or verified build provenance.
- `gh` 2.102.0 remains the minimum for attestation verification. Do not replace exact signer matching with unsafe prefix or regular-expression checks.
- Only certified run attempt 1 is accepted, and the current attempt must remain 1 during release-approval evaluation.
- External commands use argument vectors with `shell=False`, bounded output, deadlines, cancellation, and process cleanup.
- Receipts omit secrets, authorization data, kubeconfig contents, approval comments, and untrusted custom predicate content. Strict JSON, input/receipt bounds, and bounded denial output remain enforced.
- Documentation distinguishes what each producer and consumer check proves from what it does not prove.

## Documentation and assets

Keep examples consistent with the actual request schema, trusted policy schema, receipt fields, and reason codes. Use realistic documentation-only identities rather than real user or infrastructure data. Keep SVG assets self-contained, valid XML, readable when scaled on GitHub, and free of scripts or external resources.

## Questions

Use [GitHub Issues](https://github.com/okanyildiz/release-proof-mcp/issues) for implementation questions and proposed changes. GitHub Discussions is not currently enabled for this private repository; an issue is the current support path for design discussion.
