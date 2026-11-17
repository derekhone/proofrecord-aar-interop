# proofrecord-aar-interop: signed ProofRecord™ and Agent Action Receipts (AAR) interoperability demonstration

**Release candidate v0.1.0-rc.4. Synthetic data only. Not production. Not independently reviewed. Not formal AAR conformance. Not endorsed by AAR.**

This package lets anyone check, offline:

1. that a signed ExecutionProof ProofRecord™ is authentic under a pinned public test key;
2. that an Agent Action Receipts (AAR) bundle cites that exact ProofRecord; and
3. that the action AAR records as attempted and dispatched is the same action the ProofRecord authorized: action name, target, exact parameter bytes, actor credential, validity window and single use.

AAR is pinned to `oneshot2001/aar` @ `aab2feca93986f92f29f7672dff3464e05163cb5`.

## Quick start

```bash
python3 -m pip install --require-hashes -r requirements.txt   # PyNaCl 1.6.2 (libsodium); the only runtime dependency
# ProofRecord + cross-record check. No AAR checkout needed; AAR signatures are NOT checked.
python3 -B verify_offline.py --proofrecord SIGNED_PROOFRECORD_EXAMPLE.json --key PUBLIC_TEST_KEY.json \
  --aar-bundle AAR_FIXTURE_CITING_PROOFRECORD.cbor --require-outcome
# expect: MATCH / AUTHORIZED_ACTION_EQUALS_DISPATCHED_ACTION_CROSS_CHECK_ONLY, exit 0
```

Full reproduction, including AAR's own verifier and all 97 test rows: see **REPRODUCE.md**.

## Files

| Path | Purpose |
|---|---|
| `SIGNED_PROOFRECORD_EXAMPLE.json` | Signed synthetic ProofRecord, decision ALLOW |
| `PUBLIC_TEST_KEY.json` | Ed25519 public **test** key and kid. No one holds the private key |
| `AAR_FIXTURE_CITING_PROOFRECORD.cbor` | AAR v0.2 bundle from AAR's harness; its permit decision cites the ProofRecord |
| `PROOFRECORD_SIGNATURE_SPEC.md` | Exact signature input, covered and excluded fields, encodings, failure semantics |
| `AAR_INTEROPERABILITY_CONTRACT.md` | Citation mechanism, comparison rules, conformance vs cross-check distinction |
| `REPRODUCE.md` | Step-by-step reproduction |
| `EXPECTED_RESULTS.md` | Every test row with expected outcome and exit code |
| `verify_offline.py`, `epverify/` | Offline verifier. Python 3.11+, standard library plus PyNaCl (libsodium) for Ed25519, no network, no clock |
| `requirements.txt` | Hash-pinned runtime dependencies (PyNaCl 1.6.2, cffi 2.1.1, pycparser 3.12) |
| `tests/` | `run_tests.py` (positive, negative, boundary) and `conformant_disagreement_observation.py` |
| `fixtures/` | All ProofRecords, keys and AAR bundles the tests use |
| `evidence/` | Recorded same-author runs: positive binding report and the 16-bundle observation |
| `SECURITY.md`, `SECURITY_MODEL.md`, `KNOWN_LIMITATIONS.md` | Security reporting, what a MATCH does and does not mean, limitations and known issues |
| `LICENSE`, `THIRD_PARTY_NOTICES.md`, `LICENSES/` | MIT License for RF-authored files; license map and third-party notices |
| `CITATION.cff`, `AUTHORS.md`, `.zenodo.json`, `ZENODO_ABSTRACT.md` | Citation and archival metadata |
| `RELEASE_NOTES.md`, `SHA256SUMS.txt` | Release notes and integrity manifest |

## Supported environment

Tested only on CPython 3.11.17, Linux x86_64 (glibc 2.36), PyNaCl 1.6.2 / cffi 2.1.1 / pycparser 3.12 installed from `requirements.txt`. Other versions and platforms are untested. Installation needs network access once; after that, verification needs no network and reads no clock. Without PyNaCl the verifier exits non-zero and never reports VALID or MATCH.

**Single acceptance gate.** The only code that accepts a signature is `epverify/ed25519_verify.py` (libsodium via PyNaCl, plus canonical-encoding and S < L checks). No other checker is shipped. A result from any other Ed25519 implementation must never be used to authorize an action.

## Exit codes

`0` MATCH or VALID · `1` MISMATCH · `2` INVALID · `3` UNSUPPORTED · `4` NOT_AUTHORIZED (HOLD, DENY or outside validity) · `5` INSUFFICIENT_EVIDENCE · `6` AAR_NONCONFORMANT · `64` usage.

The JSON report separates `proofrecord`, `cross_record`, `aar_conformance` and outcome evidence. **No level implies any other.**

## Test-only key warning

`PUBLIC_TEST_KEY.json` is a synthetic demonstration key (`key_notice: SYNTHETIC-DEMONSTRATION-KEY-NOT-PRODUCTION`). Never trust it for anything real. A valid signature proves only possession of a key at signing time; it does not prove separated signing authority (see SECURITY_MODEL.md, T18).

## Findings welcome

If you find a false MATCH or a disagreement this verifier misses, report it with the exact files and command (see SECURITY.md). Historical results are preserved, not rewritten.

## License and scope

RF-authored files are released under the MIT License (`LICENSE`). Third-party material keeps its own license: AAR-derived fixtures are Apache License 2.0. No third-party code is bundled; Ed25519 verification uses the PyNaCl runtime dependency (Apache License 2.0; bundles libsodium, ISC License), which you install yourself. The per-file map is in `THIRD_PARTY_NOTICES.md`.

This release publishes only the interoperability contract needed to verify the example independently: the ProofRecord signature input and encoding (`PROOFRECORD_SIGNATURE_SPEC.md`) and the AAR citation and comparison rules (`AAR_INTEROPERABILITY_CONTRACT.md`). It does not license any other ExecutionProof software, specification, service, trademark or other intellectual property, and it makes no statement of patent clearance or freedom to operate.

ExecutionProof™ and ProofRecord™ are trademarks of Remnant Fieldworks Inc. (pending applications, not registrations).
