# Security policy

## Scope

This is a **synthetic demonstration** release candidate. It contains no production keys, no production records and no credentials. The only key is a public test key whose private half no one holds.

In scope for reports:

- a false MATCH, VALID or authorization result;
- a ProofRecord/AAR disagreement the cross-check misses;
- a verifier crash, hang or fail-open on crafted input;
- any error in `PROOFRECORD_SIGNATURE_SPEC.md` or `AAR_INTEROPERABILITY_CONTRACT.md`.

Out of scope: the known limitations in `KNOWN_LIMITATIONS.md` (for example T18 signing-key misuse and cross-bundle replay), and defects in AAR itself, which should go to the AAR project.

## Reporting

Open an issue on this repository with the exact files, command and output. If the report should not be public, request a private channel in the issue without including details.

## What a result means

See `SECURITY_MODEL.md`. In short, a MATCH means the AAR bundle as read agrees with a ProofRecord that is authentic under the key **you** pinned. It does not mean the decision was correct, that signing authority was separated, or that outcome evidence is independent.
