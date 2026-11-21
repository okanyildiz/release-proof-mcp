## Summary

Describe the behavior change and why it is needed. Link the relevant issue when available.

## Verification evidence

Select every level that applies and describe the exact evidence in the PR comments or linked document:

- [ ] Fixtures only
- [ ] Recorded real output
- [ ] Live environment

Do not describe fixture-only or recorded output as live verification. Identify the actual environments and versions.

## Checks

- [ ] `python -m pytest -q` passes, with counts reported.
- [ ] `python -m compileall -q src tests` passes.
- [ ] `git diff --check` passes.
- [ ] New behavior has regression tests that were observed failing before the fix.
- [ ] Documentation and compatibility notes match the implementation.
- [ ] Secret scanning completed; no credentials, private keys, kubeconfig data, approval comments, or sensitive production evidence are included.

## Security invariants

Confirm all that apply:

- [ ] The producer and consumer remain read-only.
- [ ] `failed` and `unknown` still deny, and incomplete evidence never becomes `verified`.
- [ ] Trusted policy remains server-side and cannot be selected by the caller.
- [ ] Exact SHAs, refs, signer identities, digests, numeric IDs, kube context, and container matching remain strict.
- [ ] No unsigned fallback was introduced after a configured signing failure.
- [ ] External commands retain argument vectors, `shell=False`, bounded output, deadlines, cancellation, and process cleanup.
- [ ] Offline consumers remain credential-free and expectations never come from the receipt being checked.
- [ ] No new runtime dependency was added without explicit maintainer approval.

## Remaining limits and open questions

List unvalidated platforms, unavailable evidence, compatibility changes, and anything the reviewer must not infer from this PR.
