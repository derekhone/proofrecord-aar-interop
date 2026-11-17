# Expected results

Generated from `tests/run_tests.py`; the observed run is in the founder package (`evidence/test_run_full_with_pyref.log`, 98/98 PASS on Python 3.11.17 / Node v22.23.4, when four OpenSSL rows O01–O04 still existed; they were removed in v0.1.0-rc.3 together with the OpenSSL checker, so the rc.3 suite was 94 rows; rc.4 adds X33–X35, giving 97). Rows P* = ProofRecord-only, X* = cross-record (no AAR signature check), F* = with AAR pyref (`AAR_DIR`), U* = unit. T-column maps to the EP-AAR-001 adversarial case list (T01–T20).

| ID | T | Expected (outcome/code, exit) |
|---|---|---|
| P01 | T01 | VALID/PROOFRECORD_ONLY, exit 0 |
| P02 | T11 | NOT_AUTHORIZED/OUTSIDE_VALIDITY, exit 4 |
| P03 | T17 | NOT_AUTHORIZED/DECISION_HOLD, exit 4 |
| P04 | T17 | NOT_AUTHORIZED/DECISION_DENY, exit 4 |
| P05 | T07 | INVALID/ACTOR_SUBJECT_MISMATCH, exit 2 |
| P06 | T05 | INVALID/PARAMS_DIGEST_MISMATCH, exit 2 |
| P07 | T11 | INVALID/TIME_INCOHERENT, exit 2 |
| P08 | T13 | INVALID/SCHEMA, exit 2 |
| P09 | T14 | INVALID/KID_UNKNOWN, exit 2 |
| P10 | T14 | INVALID/KID_UNKNOWN, exit 2 |
| P11 | T14 | INVALID/KEYFILE_KID_MISMATCH, exit 2 |
| P12 | T14 | INVALID/KID_UNKNOWN, exit 2 |
| P13 | T14 | INVALID/SIG_INVALID, exit 2 |
| P14 | T02 | INVALID/SIG_INVALID, exit 2 |
| P15 | T11 | INVALID/SIG_INVALID, exit 2 |
| P16 | T07 | INVALID/SIG_INVALID, exit 2 |
| P17 | T13 | INVALID/SIG_INVALID, exit 2 |
| P18 | T13 | INVALID/SIG_INVALID, exit 2 |
| P19 | T13 | INVALID/SIG_FORMAT, exit 2 |
| P20 | T13 | UNSUPPORTED/VERSION, exit 3 |
| P21 | T13 | UNSUPPORTED/ALG, exit 3 |
| P22 | T03 | INVALID/NON_CANONICAL, exit 2 |
| P23 | T03 | INVALID/NON_CANONICAL, exit 2 |
| P24 | T04 | INVALID/PARSE, exit 2 |
| P25 | T04 | INVALID/PARSE, exit 2 |
| P26 | T04 | INVALID/PARSE, exit 2 |
| P27 | T04 | INVALID/NON_CANONICAL, exit 2 |
| P28 | T13 | INVALID/PARSE, exit 2 |
| P29 | T18 | VALID/PROOFRECORD_ONLY, exit 0 |
| P30 | T13 | INVALID/KID_UNKNOWN, exit 2 |
| X01 | T01 | MATCH_CROSS_CHECK_ONLY/AUTHORIZED_ACTION_EQUALS_DISPATCHED_ACTION_CROSS_CHECK_ONLY, exit 7 (rc.4: MATCH, exit 0) |
| X02 | T20 | MATCH_CROSS_CHECK_ONLY/AUTHORIZED_ACTION_EQUALS_DISPATCHED_ACTION_CROSS_CHECK_ONLY, exit 7 (rc.4: MATCH, exit 0) |
| X03 | T03 | MATCH_CROSS_CHECK_ONLY/AUTHORIZED_ACTION_EQUALS_DISPATCHED_ACTION_CROSS_CHECK_ONLY, exit 7 (rc.4: MATCH, exit 0) |
| X04 | T16 | INSUFFICIENT_EVIDENCE/NO_CITATION, exit 5 |
| X05 | T16 | INSUFFICIENT_EVIDENCE/REF_NOT_CITED, exit 5 |
| X06 | T16 | MISMATCH/AMBIGUOUS_CITATION, exit 1 |
| X07 | T02 | MISMATCH/PARAMETERS_DIGEST, exit 1 |
| X08 | T04 | MISMATCH/PARAMETERS_DIGEST, exit 1 |
| X09 | T05 | MISMATCH/PARAMETERS_DIGEST, exit 1 |
| X10 | T09 | MISMATCH/TARGET, exit 1 |
| X11 | T10 | MISMATCH/ACTION_NAME, exit 1 |
| X12 | T10 | MISMATCH/CANONICAL_COMMAND, exit 1 |
| X13 | T11 | MISMATCH/EXPIRED_AT_DISPATCH, exit 1 |
| X14 | T11 | MISMATCH/EXPIRED_AT_DISPATCH, exit 1 |
| X15 | T11 | MISMATCH/DISPATCH_BEFORE_VALIDITY, exit 1 |
| X16 | T17 | MISMATCH/DISPATCH_WITHOUT_ALLOW, exit 1 |
| X17 | T17 | MISMATCH/DISPATCH_WITHOUT_ALLOW, exit 1 |
| X18 | T07 | MISMATCH/ACTOR, exit 1 |
| X19 | T04 | MISMATCH/PARAMETERS_DIGEST, exit 1 |
| X20 | T04 | MISMATCH/PARAMETERS_DIGEST, exit 1 |
| X21 | T15 | MISMATCH/ACTION_NAME, exit 1 |
| X22 | T15 | MISMATCH/TARGET, exit 1 |
| X23 | T12 | INSUFFICIENT_EVIDENCE/REF_NOT_CITED, exit 5 |
| X24 | T12 | INSUFFICIENT_EVIDENCE/REF_NOT_CITED, exit 5 |
| X25 | T19 | MISMATCH/REPLAY, exit 1 |
| X26 | T20 | MATCH_CROSS_CHECK_ONLY/AUTHORIZED_ACTION_EQUALS_DISPATCHED_ACTION_CROSS_CHECK_ONLY, exit 7 (rc.4: MATCH, exit 0) |
| X27 | T20 | INSUFFICIENT_EVIDENCE/OUTCOME_ABSENT, exit 5 |
| X28 | T20 | MISMATCH/OUTCOME_NOT_CONSISTENT, exit 1 |
| X29 | T05 | MISMATCH/PARAMETERS_VALUE, exit 1 |
| X30 | T16 | INVALID/AAR_PARSE, exit 2 |
| X31 | T13 | INVALID/SIG_INVALID, exit 2 |
| X32 | - | USAGE/AT_REQUIRED, exit 64 |
| X33 | T19 | MISMATCH/DISPATCH_NOT_ELIGIBLE, exit 1 |
| X34 | T19 | MISMATCH/UNBOUND_DISPATCH, exit 1 |
| X35 | T19 | MISMATCH/DISPATCH_EDGE_CONFLICT, exit 1 |
| F01 | T01 | MATCH/AUTHORIZED_ACTION_EQUALS_DISPATCHED_ACTION, exit 0 |
| F02 | T02 | MISMATCH/PARAMETERS_DIGEST, exit 1 |
| F03 | T17 | MISMATCH/DISPATCH_WITHOUT_ALLOW, exit 1 |
| F04 | T07 | MISMATCH/ACTOR, exit 1 |
| F05 | T11 | MISMATCH/EXPIRED_AT_DISPATCH, exit 1 |
| F06 | T09 | AAR_NONCONFORMANT/PYREF, exit 6 |
| F07 | T10 | AAR_NONCONFORMANT/PYREF, exit 6 |
| F08 | T19 | AAR_NONCONFORMANT/PYREF, exit 6 |
| F09 | T20 | INSUFFICIENT_EVIDENCE/OUTCOME_ABSENT, exit 5 |
| F10 | T20 | AAR_NONCONFORMANT/PYREF, exit 6 |
| F11 | T16 | INSUFFICIENT_EVIDENCE/NO_CITATION, exit 5 |
| F12 | T15 | MISMATCH/ACTION_NAME, exit 1 |
| U01 | T13 | RFC 8032 s7.1 vectors 1-2 verify |
| U02 | T13 | RFC 8032 vector 2 with altered message rejected |
| U03 | T14 | small-order (identity) public key |
| U03b | T14 | order-4 public key (y=0) rejected |
| U04 | T13 | non-canonical y >= p public key rejected |
| U05 | T06 | bytearray (non-bytes) input rejected |
| U06 | T06 | RF-CJ-1 rejects str subclass value |
| U07 | T06 | RF-CJ-1 rejects int subclass with hostile __eq__ |
| U08 | T06 | RF-CJ-1 rejects dict subclass |
| U09 | T06 | RF-CJ-1 rejects str-subclass key |
| U10 | T06 | detCBOR rejects int subclass |
| U11 | T06 | params_digest rejects hostile int subclass |
| U12 | T06 | type-strict equality defeats __eq__ override, bool/int and str/int confusion |
| U13 | T04 | detCBOR rejects floats |
| U14 | T04 | detCBOR rejects unsorted map keys |
| U15 | T04 | detCBOR rejects non-shortest integer |
| U16 | T03 | detCBOR parameter bytes independent of insertion order |
| U17 | T04 | RF-CJ-1 rejects lone surrogate |
| U18 | T04 | ProofRecord text fields must be NFC (decomposed form rejected) |
| U19 | - | detCBOR round-trips the AAR bundle byte-identically |

Arguments for each row are in `tests/run_tests.py` (one line per row).

## Rows added in rc.5 (issues #1-#3)

| ID | Issue | Expected (outcome/code, exit) |
|---|---|---|
| X36 | #3 | MATCH_CROSS_CHECK_ONLY/AUTHORIZED_ACTION_EQUALS_DISPATCHED_ACTION_CROSS_CHECK_ONLY, exit 7 (broken AAR receipt signatures) |
| X37 | #1 | USAGE/TRUST_OPTION_WITHOUT_PYREF, exit 64 |
| X38 | #1 | USAGE/TRUST_OPTIONS_CONFLICT, exit 64 |
| F13 | #1 | USAGE/AAR_TRUST_POLICY_REQUIRED, exit 64 |
| F14 | #1 | MATCH_AAR_TRUST_UNPINNED/AUTHORIZED_ACTION_EQUALS_DISPATCHED_ACTION_AAR_TRUST_UNPINNED, exit 8 |
| F15 | #1 | AAR_NONCONFORMANT/PYREF, exit 6 (pinned root_kid differs) |
| F16 | #1 | AAR_NONCONFORMANT/PYREF, exit 6 (pin belongs to another bundle) |
| F17 | #3 | AAR_NONCONFORMANT/PYREF, exit 6 (broken AAR receipt signatures, pinned) |
| U20 | #2 | stub pyref reports other bytes: AAR_NONCONFORMANT/PYREF_BUNDLE_DIGEST_MISMATCH, exit 6 |
| U21 | #2 | stub pyref reports no digest: AAR_NONCONFORMANT/PYREF_BUNDLE_DIGEST_MISMATCH, exit 6 |
| U22 | #1 | pin supplied, pyref reports producer-declared: AAR_NONCONFORMANT/PYREF_TRUST_BASIS_UNEXPECTED, exit 6 |
| U23 | - | guard positive control with consistent stub: MATCH, exit 0 |

Since rc.5 every F row passes `--aar-trust-policy fixtures/aar_trust/<bundle>.trust-policy.json` (test pins). Finding tests N1, N1b, N2, N3 are in `tests/finding_tests.py`.
