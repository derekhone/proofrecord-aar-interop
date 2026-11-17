# Release notes

## v0.1.0-rc.5 (candidate; unpublished; requires founder approval before any publication)

Remediates the three findings reported by Matthew Visher (with Claude, Anthropic) against the rc.4 release asset on 2026-11-17 (issues #1-#3). rc.4 remains unchanged at tag `v0.1.0-rc.4`.

### Fixed
- **#1 AAR trust basis not stated / not pinned.** New `--aar-trust-policy FILE`, passed unchanged to pyref's existing `--trust-policy` option at the pinned AAR commit. The report gains `aar_trust_basis` (mode, pinned `root_kids`, trust-store digest and snapshot, policy SHA-256). `--aar-pyref` without a trust option is refused (USAGE/AAR_TRUST_POLICY_REQUIRED, exit 64). Explicit `--aar-trust-producer-declared` gives `MATCH_AAR_TRUST_UNPINNED`, exit 8. epverify also requires pyref to print the trust line that matches the option used.
- **#2 Bundle read twice.** The bundle is read once. pyref gets a private read-only copy of those bytes, and its reported `bundle_digest` must equal their SHA-256; the cross-check uses the same in-memory bytes. The trust policy is also read once.
- **#3 Cross-check-only MATCH exited 0.** It is now `MATCH_CROSS_CHECK_ONLY`, exit 7.

### Tests (same-author)
- `tests/finding_tests.py`: the three findings as tests (N1, N1b, N2, N3). Against the rc.4 tree: 4/4 FAIL (reproduced; N2 executed, not only read). Against rc.5: 4/4 PASS.
- `tests/run_tests.py`: 109/109 with AAR at the pinned commit (rc.4: 97). Rows X01-X03 and X26 now expect `MATCH_CROSS_CHECK_ONLY`, exit 7 (rc.4 expected exit 0). New rows X36-X38, F13-F17, U20-U23. New fixture `fixtures/aar/MUT_RECEIPT_SIGNATURES_BROKEN.cbor` (AAR_POSITIVE with every receipt signature's last byte flipped; pyref: nonconformant at step 06) and test trust pins in `fixtures/aar_trust/`.
- `tests/conformant_disagreement_observation.py` now pins each bundle's test trust policy; result unchanged (21 pairs, 16 pyref-conformant but not MATCH).

### Not changed
ProofRecord format, keys, signature verification, cross-record rules, existing fixtures and recorded rc.4 evidence.


## v0.1.0-rc.4 (release candidate; unpublished; release date to be set at publication)

Cross-record single-use fix found in the final same-author red-team of rc.3. No change to the format, keys, signature verification, existing fixtures or recorded evidence.

### Fixed
- **Single-use check ignored some dispatches.** `epverify/aar_xcheck.py` counted only dispatches bound to *eligible* attempts. A bundle that also carried a dispatch bound to a `not_dispatched` attempt of the same authorization, or a dispatch naming an attempt absent from the bundle, still produced `MATCH` at the cross-record level (exit 0). AAR's own verifier rejects such bundles (`graph/dominator-missing`, by code reading), but the cross-record level advertises single use on its own. Such dispatches now give `MISMATCH/DISPATCH_NOT_ELIGIBLE`, `MISMATCH/UNBOUND_DISPATCH`, or (when a dispatch's `attempted_as` edge disagrees with its `attempt_id`) `MISMATCH/DISPATCH_EDGE_CONFLICT`, exit 1.
- New cross-record fixtures `fixtures/aar/MUT_DISPATCH_NOT_ELIGIBLE.cbor`, `MUT_DISPATCH_UNBOUND.cbor`, `MUT_DISPATCH_EDGE_CONFLICT.cbor` (derived from `AAR_POSITIVE.cbor`; their AAR signatures are not valid, like the other `MUT_*` fixtures) and test rows X33–X35.
- `REPRODUCE.md` step 1b: a virtual-environment fallback for systems whose Python has no pip or refuses system-wide installs (PEP 668).
- `KNOWN_LIMITATIONS.md`: documents that omitting `--at` skips the validity-window check, that a missing `--key` file exits 1 with a traceback and no JSON, and that single use is checked per bundle only.

### Verified (same-author)
- `tests/run_tests.py`: 97/97 with an AAR checkout at the pinned commit, 85/85 without, from a clean virtual environment installed only from `requirements.txt`, then run with networking disabled.

## v0.1.0-rc.3 (release candidate; unpublished; release date to be set at publication)

Single-acceptance-gate and dependency-pinning release. No change to the format, verifier logic, fixtures, keys or recorded evidence.

### Changed
- **Removed `verify_sig_openssl.mjs`** (Node/OpenSSL second signature check) and its four test rows O01–O04. In a same-author check, Node v22.23.4 / OpenSSL 3.5.9 accepted 79 of 256 small-order-key forgeries (S = 0) that the libsodium verifier rejects. A weaker checker must not be able to produce a positive result. `epverify/ed25519_verify.py` is now the only signature-acceptance path; only its docstring changed.
- Added `requirements.txt`: PyNaCl 1.6.2, cffi 2.1.1 and pycparser 3.12, pinned with PyPI SHA-256 hashes (`pip install --require-hashes`).
- Documented the supported environment (CPython 3.11.17, Linux x86_64, glibc 2.36; others untested), the one-time online install, and offline behavior after install. Node.js is no longer needed.
- Documentation updated: `README.md`, `REPRODUCE.md`, `PROOFRECORD_SIGNATURE_SPEC.md`, `AAR_INTEROPERABILITY_CONTRACT.md` (version line), `EXPECTED_RESULTS.md`, `KNOWN_LIMITATIONS.md`, `THIRD_PARTY_NOTICES.md`, `CITATION.cff`, `.zenodo.json`, `ZENODO_ABSTRACT.md`.

### Verified (same-author)
- `tests/run_tests.py`: 94/94 with an AAR checkout at the pinned commit, 82/82 without, from a clean virtual environment installed only from `requirements.txt`, then run with networking disabled.
- Recorded files in `evidence/` regenerate byte-identically.

## v0.1.0-rc.2 (release candidate; unpublished; release date to be set at publication)

Licensing-provenance fix. No change to the format, fixtures, keys, test rows or recorded evidence.

### Changed
- `epverify/ed25519_verify.py` replaced. The rc.1 file was adapted from the Python illustration in RFC 8032 Section 6. RFC 8032 is an IRTF-stream document, and permission to modify and redistribute that code outside the IETF process could not be established clearly, so the code was removed rather than relicensed. The new file is written by Remnant Fieldworks (MIT) and calls libsodium through PyNaCl 1.6.2. It keeps the same function, `verify(public_key, message, signature) -> bool`, and the same stricter checks: exact byte types and lengths, canonical public-key and R encodings (y < p), S < L, small-order public keys and R rejected (libsodium), cofactorless equation. Any error returns False.
- New runtime dependency: PyNaCl 1.6.2 (Apache License 2.0; bundles libsodium, ISC License). Not bundled. Without it, verification fails closed (non-zero exit).
- Documentation updated for the dependency and the licensing change: `README.md`, `REPRODUCE.md`, `PROOFRECORD_SIGNATURE_SPEC.md` (item 1), `AAR_INTEROPERABILITY_CONTRACT.md` (version line), `KNOWN_LIMITATIONS.md`, `THIRD_PARTY_NOTICES.md`, `CITATION.cff`, `.zenodo.json`, `ZENODO_ABSTRACT.md`.

### Verified (same-author)
- `tests/run_tests.py`: 98/98 with an AAR checkout at the pinned commit, 86/86 without.
- Recorded files in `evidence/` regenerate byte-identically.
- Differential check of the new verifier against the rc.1 verifier and OpenSSL over 10,733 cases (RFC 8032 vectors, random valid signatures, all fixture ProofRecords, bit flips, truncation, non-canonical encodings, S >= L, small-order keys and R): the new and rc.1 verifiers agreed on every case. This harness is not part of the package.

## v0.1.0-rc.1 (release candidate; unpublished; release date to be set at publication)

First public candidate of the ProofRecord™ / Agent Action Receipts (AAR) interoperability demonstration.

### Included
- Signed synthetic ProofRecord (Ed25519, RF-CJ-1 canonical JSON) and its public test key.
- AAR v0.2 bundle (AAR harness, pinned commit `aab2feca`) whose authorization cites the ProofRecord through the existing `decision.evaluated_inputs` field.
- Offline verifier (Python stdlib) reporting ProofRecord, cross-record, AAR-conformance and outcome levels separately; second signature check via Node/OpenSSL.
- 98 targeted test rows: positive, signature tampering, HOLD/DENY, authorized/dispatched mismatch, missing/ambiguous/unknown citation, validity window, replay within a bundle, outcome presence.
- Reproducible observation of 16 AAR-conformant bundles that disagree with the ProofRecord (same-author; not an AAR defect claim).

### Changes from the internal handoff candidate
- `AAR_HANDOFF_MAPPING.md` renamed to `AAR_INTEROPERABILITY_CONTRACT.md`, with a section separating AAR conformance from RF cross-receipt consistency.
- `NOTICE` replaced by `THIRD_PARTY_NOTICES.md`, adding the RFC 8032 attribution.
- Added `README.md` (rewritten), `REPRODUCE.md`, `SECURITY.md`, `LICENSE` (MIT, RF-authored files only), `CITATION.cff`, `AUTHORS.md`, `.zenodo.json`, `ZENODO_ABSTRACT.md`, `tests/conformant_disagreement_observation.py`, `evidence/`.
- Verifier source, fixtures and keys are byte-identical to the internal candidate.

### Licensing
- RF-authored files: MIT License.
- AAR-derived fixtures: Apache License 2.0 (unchanged); AAR specification references: CC BY 4.0 attribution.
- RFC 8032-derived portions of `epverify/ed25519_verify.py`: IETF Trust Legal Provisions (not relicensed). *Superseded in rc.2: that code was removed.*
- Per-file map in `THIRD_PARTY_NOTICES.md`. No other ExecutionProof intellectual property is licensed, and no patent clearance is stated.

### Known issues
See `KNOWN_LIMITATIONS.md`.
