# Security model and custody

## What a MATCH means
Under the relying party's pinned public key, a ProofRecord authorized exactly one action, and AAR records exactly that action dispatched once, within the validity window, by the delegated credential named in the ProofRecord.

The two halves of a MATCH can rest on different trust bases. Since rc.5 the outcome and exit code say which:

| Outcome | Exit | ProofRecord key | AAR signatures / trust | Bytes |
|---|---|---|---|---|
| `MATCH` | 0 | pinned out of band (`--key`) | checked by AAR pyref against the relying party's `--aar-trust-policy` (pyref `--trust-policy`); report field `aar_trust_basis` lists `root_kids`, trust-store digest and the policy file's SHA-256 | pyref's reported `bundle_digest` must equal the SHA-256 of the bytes the cross-check read (read once) |
| `MATCH_AAR_TRUST_UNPINNED` | 8 | pinned | checked by pyref, but only against the AAR keys the bundle itself declares (explicit `--aar-trust-producer-declared`) | same single read |
| `MATCH_CROSS_CHECK_ONLY` | 7 | pinned | **not checked** | single read |

`--aar-pyref` without a trust option is refused (USAGE/AAR_TRUST_POLICY_REQUIRED, exit 64). Before rc.5 every row above exited 0 and the report did not state the AAR trust basis (issues #1 and #3), and pyref and the cross-check read the bundle path separately (issue #2).

## What it does NOT mean
- **Not proof that the authorization decision was correct**, or that the policy was right.
- **Not proof of separated signing authority.** A signature proves possession of a key. Anyone holding the signing key can produce a VALID ProofRecord for any action (test P29, T18: NOT PREVENTED by any verifier).
- **Not independent outcome evidence.** The AAR observer key is a test key from the same generator.
- **Not production custody, not formal AAR conformance, not independent review.**

## Custody of the demonstration key
- Generated fresh by an author-side tool (not included in this package) with pyca/cryptography. The private key existed only in that process's memory. It was never written to disk, logged or printed, and it was discarded when the process exited. **Nobody holds it.** No further record can be signed under `PUBLIC_TEST_KEY.json`.
- Consequence: the key is authentic only to the extent the reviewer trusts the published key file. That is out-of-band pinning, with no PKI and no revocation.
- During generation the key was **runtime-accessible** to the same process that composed the records. This is the T18 condition: the policy decision, the record composition and the signing were not separated. A production design must separate policy decision authority, signing authority (HSM/KMS, non-exportable), and the enforcement point / executor, which must not hold the signing key.

## Threats addressed by the verifier (tested; same-author)
Parameter, target and action substitution; type confusion (3 / "3" / true / 3.0 / null); object-subclass serialization tricks; re-serialization; signature tampering and malleability (S+L); small-order and non-canonical keys; key replacement; version/alg downgrade; HOLD/DENY presented as authorization; expiry and not-yet-valid at dispatch; wrong actor credential; uncited, ambiguous or unknown citations; multiple dispatches in one bundle; missing or contradicted outcome (with `--require-outcome`).

## Not addressed
Cross-bundle replay (needs a relying-party nonce registry). Key compromise or revocation. Clock correctness of `--at`. Side channels (verification uses public data only). Correctness of AAR pyref itself.
