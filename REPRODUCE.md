# Reproduce

Tested only on CPython 3.11.17, Linux x86_64 (glibc 2.36). Other versions and platforms are untested. Network access is needed only for step 1b (and optional step 2); after that the verifier uses no network and no system clock.

## 1. Check integrity

```bash
sha256sum -c SHA256SUMS.txt          # every line must end in OK
```

## 1b. Install the Ed25519 dependency

```bash
# If your system Python has no pip or refuses system-wide installs (PEP 668, e.g. Debian/Ubuntu), first run:
#   python3 -m venv .venv && . .venv/bin/activate      (Debian/Ubuntu may need: apt install python3-venv)
python3 -m pip install --require-hashes -r requirements.txt
# PyNaCl 1.6.2 (Apache-2.0, wraps libsodium, ISC) + cffi 2.1.1 (MIT-0) + pycparser 3.12 (BSD-3-Clause).
# Without PyNaCl the verifier exits non-zero; it never falls back to another implementation.
```

## 2. (Optional) Get AAR's reference verifier at the pinned commit

```bash
git clone https://github.com/oneshot2001/aar
(cd aar && git checkout aab2feca93986f92f29f7672dff3464e05163cb5)
```

Skip this to run only the ProofRecord and cross-record levels.

## 3. Positive verification

```bash
# ProofRecord only
python3 -B verify_offline.py --proofrecord SIGNED_PROOFRECORD_EXAMPLE.json --key PUBLIC_TEST_KEY.json
# expect VALID / PROOFRECORD_ONLY, exit 0

# Authorized action == dispatched action, with AAR's own verifier first
python3 -B verify_offline.py --proofrecord SIGNED_PROOFRECORD_EXAMPLE.json --key PUBLIC_TEST_KEY.json \
  --aar-bundle AAR_FIXTURE_CITING_PROOFRECORD.cbor --aar-pyref ./aar --at 1735689800 --require-outcome \
  --aar-trust-policy AAR_FIXTURE_TRUST_POLICY.json
# expect MATCH / AUTHORIZED_ACTION_EQUALS_DISPATCHED_ACTION, exit 0; the report's aar_trust_basis names the pinned root_kids
# AAR_FIXTURE_TRUST_POLICY.json is a TEST PIN derived from the fixture itself (tests/make_test_trust_policy.py).
# A real relying party obtains its AAR trust policy out of band.
# recorded run: evidence/BINDING_EVIDENCE_POSITIVE.json
```

Check the citation yourself: `sha256sum SIGNED_PROOFRECORD_EXAMPLE.json` must equal `aar.proofrecord_ref_sha256` in the report, which is the `executionproof.proofrecord.v1` entry in the AAR authorization's `decision.evaluated_inputs`.

## 4. Negative examples (one per class)

```bash
K=fixtures/keys/PUBLIC_TEST_KEY.json; P=fixtures/proofrecords; A=fixtures/aar
python3 -B verify_offline.py --proofrecord $P/TAMPER_SIG_BYTE.json --key $K                      # INVALID/SIG_INVALID, exit 2
python3 -B verify_offline.py --proofrecord $P/PR_HOLD.json --key $K                              # NOT_AUTHORIZED/DECISION_HOLD, exit 4
python3 -B verify_offline.py --proofrecord $P/PR_DENY.json --key $K                              # NOT_AUTHORIZED/DECISION_DENY, exit 4
python3 -B verify_offline.py --proofrecord $P/PR_ALLOW.json --key $K --aar-bundle $A/AAR_PARAMS_CHANGED.cbor   # MISMATCH/PARAMETERS_DIGEST, exit 1
python3 -B verify_offline.py --proofrecord $P/PR_ALLOW.json --key $K --aar-bundle $A/AAR_NO_CITATION.cbor      # INSUFFICIENT_EVIDENCE/NO_CITATION, exit 5
python3 -B verify_offline.py --proofrecord $P/PR_ALLOW.json --key $K --aar-bundle $A/AAR_CITES_TWICE.cbor      # MISMATCH/AMBIGUOUS_CITATION, exit 1
python3 -B verify_offline.py --proofrecord $P/PR_HOLD.json  --key $K --aar-bundle $A/AAR_CITES_HOLD.cbor       # MISMATCH/DISPATCH_WITHOUT_ALLOW, exit 1
```

## 5. Full test suite

```bash
AAR_DIR=./aar python3 -B tests/run_tests.py
# expect: TOTAL 109  PASS 109  FAIL 0   (92 without AAR_DIR)
AAR_DIR=./aar python3 -B tests/finding_tests.py --target . --mode rc5
# expect: TOTAL 4 PASS 4 (issues #1-#3; against the rc.4 tree with --mode rc4 all 4 FAIL)
```

Every row asserts outcome, code **and** exit status. The full list is in `EXPECTED_RESULTS.md`.

## 6. Conformant-but-disagreeing AAR bundles

```bash
AAR_DIR=./aar python3 -B tests/conformant_disagreement_observation.py
# expect: pairs_checked 21, pyref_conformant_but_rf_not_match 16
```

See `AAR_INTEROPERABILITY_CONTRACT.md` for what this observation does and does not mean.
