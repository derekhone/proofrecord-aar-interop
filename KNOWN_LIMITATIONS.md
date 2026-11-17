# Known limitations

1. **Same-author.** The format, the verifier, the fixtures, the tests and the mutation checks were all produced by the same system (Abacus AI for Remnant Fieldworks). **None of it is independent validation.**
2. **Not formal AAR conformance.** AAR pyref reports the citing bundles conformant. The ProofRecord citation uses an existing AAR field AAR does not interpret. AAR has not endorsed this mapping.
3. **Demonstration format.** RF-CJ-1 JSON + Ed25519, not COSE/JWS. Ed25519 is used where AAR uses ES256.
4. **Custody (T18).** The key was runtime-accessible at generation. Signing is not separated from decision or composition. NOT PREVENTED.
5. **Replay (T19).** Only multiple dispatches inside one bundle are detected (including, since rc.4, dispatches bound to non-eligible or absent attempts). Cross-bundle or cross-relying-party replay is NOT TESTED and needs a nonce registry.
6. **Outcome (T20).** The AAR outcome observer is a test key from the same generator, so independence is not established. `--require-outcome` checks presence and state only.
7. **Trust.** The key is pinned out-of-band. There is no PKI, no rotation and no revocation. `--at` is caller-supplied.
8. **Ed25519 via libsodium.** `epverify/ed25519_verify.py` calls libsodium through PyNaCl 1.6.2 (runtime dependency, not bundled) after its own canonical-encoding and S < L checks. Results with other PyNaCl/libsodium versions are untested. It is the only acceptance gate. The Node/OpenSSL checker shipped in earlier candidates was removed in rc.3 because OpenSSL accepted small-order-key forgeries that this verifier rejects.
9. **AAR ontology.** Only `camera.stream.view` is exercised positively. `camera.ptz.preset` appears only in negatives.
10. **Public testbeds are unchanged.** PR #35/#36 remain open and unmerged. This package does not modify or fix them.
11. **Runtime.** Tested only on CPython 3.11.17, Linux x86_64 (glibc 2.36), with the versions pinned in `requirements.txt`. Other versions and platforms are untested. Node.js is no longer needed.

## Known issues (v0.1.0-rc.5 candidate)

1. **Mixed licensing.** MIT covers RF-authored files only. AAR-derived fixtures remain Apache License 2.0. Two RFC 8032 Section 7.1 test vectors are used as test data in `tests/run_tests.py`, with attribution. See `THIRD_PARTY_NOTICES.md`.
2. **Legacy identifiers in source.** Source comments and the report `tool` field say `EP-AAR-001`, the internal project name of the candidate. They are unchanged so the verifier stays byte-identical to the tested candidate, except `epverify/ed25519_verify.py`, replaced in rc.2, `tests/run_tests.py`, whose OpenSSL rows were removed in rc.3 and which gained rows X33–X35 in rc.4, and `epverify/aar_xcheck.py`, which gained the rc.4 dispatch-binding checks. Some docstrings (for example in `verify_offline.py`, `epverify/proofrecord.py` and `tests/run_tests.py`) still say "standard library only"; since rc.2, Ed25519 verification needs PyNaCl.
3. **Withheld author-side tools.** Comments mention `tools/make_fixtures.py` and an AAR harness option hook. Neither is included. No test needs them, and the fixtures cannot be regenerated from this package: the demonstration private key no longer exists.
4. **16-bundle observation.** Reproducible here, but same-author. It is not an independently confirmed defect and not an AAR vulnerability claim.
5. **`--at` is caller-supplied.** Validity results depend on the caller's clock value. If `--at` is omitted, the ProofRecord-only check does not evaluate the validity window: an expired ALLOW record still reports VALID (exit 0). Pass `--at` whenever freshness matters.
6. **Missing key file.** If the `--key` path does not exist, the CLI exits 1 with a Python traceback and no JSON report. Exit 1 is also the MISMATCH code; treat any run without a JSON report as a failure.
7. **Cross-record single use is per bundle.** rc.4 rejects extra dispatches that are bound to a non-eligible attempt, to an attempt missing from the bundle, or to conflicting edges. It does not detect replay across separate bundles.
8. **AAR trust pin is exact-match only (rc.5).** `--aar-trust-policy` is passed to pyref's own `--trust-policy`, which must exactly match the bundle's trust inputs, including `expected_anchor_heads`. A relying party therefore needs a per-evaluation policy, not only a list of root keys. epverify adds no root-only pinning of its own.
9. **Test trust pins are circular (rc.5).** The files in `fixtures/aar_trust/` and `AAR_FIXTURE_TRUST_POLICY.json` are derived from the fixture bundles themselves. They show that the pinning mechanism works; they do not establish that the AAR keys are trustworthy.
10. **Single read is in-process (rc.5).** pyref receives a private read-only copy (0400, in a 0700 temporary directory) and its reported `bundle_digest` must equal the SHA-256 of the in-memory bytes. A process running as the same user can still interfere with that process; the digest comparison makes such interference fail closed, not impossible.
11. **Exit-code change (rc.5).** Callers that treated exit 0 as "MATCH of any kind" now see 7 or 8 for weaker MATCHes. `VALID/PROOFRECORD_ONLY` still exits 0 when no AAR bundle is given.
12. **pyref output parsing (rc.5).** The trust basis and bundle digest are read from pyref's human-readable report lines at the pinned commit. A different pyref version may change those lines; epverify then fails closed.
