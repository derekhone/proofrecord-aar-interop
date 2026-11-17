"""EP-AAR-001 targeted tests. Offline, Python 3 stdlib only.

  python3 tests/run_tests.py                      # cross-record + ProofRecord + unit tests
  AAR_DIR=/path/to/aar python3 tests/run_tests.py # additionally runs AAR pyref (full-conformance rows)

Each CLI row runs verify_offline.py as a subprocess and asserts outcome, code AND
exit status. Expected values were fixed from the specification
(PROOFRECORD_SIGNATURE_SPEC.md, AAR_HANDOFF_MAPPING.md) and are listed in
EXPECTED_RESULTS.md.
"""
import json, os, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from epverify import detcbor, rfcj, ed25519_verify as E, proofrecord as P, aar_xcheck as X  # noqa: E402

PR = lambda n: os.path.join(ROOT, "fixtures", "proofrecords", n + ".json")
KEY = lambda n="PUBLIC_TEST_KEY": os.path.join(ROOT, "fixtures", "keys", n + ".json")
AAR = lambda n: os.path.join(ROOT, "fixtures", "aar", n + ".cbor")
AT = "1735689800"
EXIT = {"MATCH": 0, "VALID": 0, "MISMATCH": 1, "INVALID": 2, "UNSUPPORTED": 3, "NOT_AUTHORIZED": 4,
        "INSUFFICIENT_EVIDENCE": 5, "AAR_NONCONFORMANT": 6, "USAGE": 64}
AAR_DIR = os.environ.get("AAR_DIR")
results = []


def cli(tid, tcase, args, outcome, code):
    p = subprocess.run([sys.executable, "-B", os.path.join(ROOT, "verify_offline.py")] + args,
                       capture_output=True, text=True, timeout=900)
    try:
        rep = json.loads(p.stdout)
    except ValueError:
        rep = {}
    ok = rep.get("outcome") == outcome and rep.get("code") == code and p.returncode == EXIT[outcome]
    results.append((tid, tcase, ok, "expect %s/%s rc%d; got %s/%s rc%d %s" % (
        outcome, code, EXIT[outcome], rep.get("outcome"), rep.get("code"), p.returncode, rep.get("detail", ""))))


def unit(tid, tcase, fn, desc):
    try:
        ok = bool(fn())
        msg = desc
    except Exception as e:  # a crash is a failure, never a pass
        ok, msg = False, "%s: raised %r" % (desc, e)
    results.append((tid, tcase, ok, msg))


def raises(fn, exc):
    try:
        fn()
    except exc:
        return True
    return False


def B(pr, key="PUBLIC_TEST_KEY"):
    return ["--proofrecord", PR(pr), "--key", KEY(key)]

XC = "AUTHORIZED_ACTION_EQUALS_DISPATCHED_ACTION_CROSS_CHECK_ONLY"

# ---- ProofRecord-only level -------------------------------------------------
cli("P01", "T01", B("PR_ALLOW"), "VALID", "PROOFRECORD_ONLY")
cli("P02", "T11", B("PR_ALLOW") + ["--at", "1735689900"], "NOT_AUTHORIZED", "OUTSIDE_VALIDITY")
cli("P03", "T17", B("PR_HOLD"), "NOT_AUTHORIZED", "DECISION_HOLD")
cli("P04", "T17", B("PR_DENY"), "NOT_AUTHORIZED", "DECISION_DENY")
cli("P05", "T07", B("BAD_ACTOR_SUBJECT_MISMATCH"), "INVALID", "ACTOR_SUBJECT_MISMATCH")
cli("P06", "T05", B("BAD_PARAMS_DIGEST"), "INVALID", "PARAMS_DIGEST_MISMATCH")
cli("P07", "T11", B("BAD_LIFETIME"), "INVALID", "TIME_INCOHERENT")
cli("P08", "T13", B("BAD_EXTRA_FIELD"), "INVALID", "SCHEMA")
cli("P09", "T14", B("BAD_UNTRUSTED_SIGNER"), "INVALID", "KID_UNKNOWN")
cli("P10", "T14", B("PR_ALLOW", "OTHER_UNTRUSTED_KEY"), "INVALID", "KID_UNKNOWN")
cli("P11", "T14", B("PR_ALLOW", "BAD_KID_KEY"), "INVALID", "KEYFILE_KID_MISMATCH")
cli("P12", "T14", B("BAD_KID_FIELD_OTHER"), "INVALID", "KID_UNKNOWN")
cli("P13", "T14", B("BAD_KID_FIELD_OTHER", "OTHER_UNTRUSTED_KEY"), "INVALID", "SIG_INVALID")
cli("P14", "T02", B("TAMPER_PARAMS_RESIGNED_DIGEST"), "INVALID", "SIG_INVALID")
cli("P15", "T11", B("TAMPER_EXPIRY"), "INVALID", "SIG_INVALID")
cli("P16", "T07", B("TAMPER_ACTOR"), "INVALID", "SIG_INVALID")
cli("P17", "T13", B("TAMPER_SIG_BYTE"), "INVALID", "SIG_INVALID")
cli("P18", "T13", B("TAMPER_SIG_S_PLUS_L"), "INVALID", "SIG_INVALID")
cli("P19", "T13", B("TAMPER_SIG_UPPERCASE"), "INVALID", "SIG_FORMAT")
cli("P20", "T13", B("TAMPER_VERSION_DOWNGRADE"), "UNSUPPORTED", "VERSION")
cli("P21", "T13", B("TAMPER_ALG_NONE"), "UNSUPPORTED", "ALG")
cli("P22", "T03", B("TAMPER_WHITESPACE"), "INVALID", "NON_CANONICAL")
cli("P23", "T03", B("TAMPER_KEY_ORDER"), "INVALID", "NON_CANONICAL")
cli("P24", "T04", B("TAMPER_DUPLICATE_KEY"), "INVALID", "PARSE")
cli("P25", "T04", B("TAMPER_FLOAT_PARAM"), "INVALID", "PARSE")
cli("P26", "T04", B("TAMPER_NULL_PARAM"), "INVALID", "PARSE")
cli("P27", "T04", B("TAMPER_UNICODE_ESCAPE"), "INVALID", "NON_CANONICAL")
cli("P28", "T13", B("TAMPER_TRUNCATED"), "INVALID", "PARSE")
cli("P29", "T18", B("PR_OTHER_ACTION"), "VALID", "PROOFRECORD_ONLY")  # key holder can sign anything: NOT PREVENTED
cli("P30", "T13", B("PR_ALLOW", "SMALL_ORDER_KEY"), "INVALID", "KID_UNKNOWN")

# ---- Cross-record level (AAR bundle read; AAR signatures NOT checked here) ---
def C(pr, bundle, *extra):
    return B(pr) + ["--aar-bundle", AAR(bundle)] + list(extra)

cli("X01", "T01", C("PR_ALLOW", "AAR_POSITIVE"), "MATCH", XC)
cli("X02", "T20", C("PR_ALLOW", "AAR_POSITIVE", "--require-outcome"), "MATCH", XC)
cli("X03", "T03", C("PR_ALLOW", "AAR_PARAMS_REORDERED"), "MATCH", XC)
cli("X04", "T16", C("PR_ALLOW", "AAR_NO_CITATION"), "INSUFFICIENT_EVIDENCE", "NO_CITATION")
cli("X05", "T16", C("PR_ALLOW", "AAR_CITES_UNKNOWN_DIGEST"), "INSUFFICIENT_EVIDENCE", "REF_NOT_CITED")
cli("X06", "T16", C("PR_ALLOW", "AAR_CITES_TWICE"), "MISMATCH", "AMBIGUOUS_CITATION")
cli("X07", "T02", C("PR_ALLOW", "AAR_PARAMS_CHANGED"), "MISMATCH", "PARAMETERS_DIGEST")
cli("X08", "T04", C("PR_ALLOW", "AAR_PARAMS_STRING"), "MISMATCH", "PARAMETERS_DIGEST")
cli("X09", "T05", C("PR_ALLOW", "AAR_PARAMS_EXTRA"), "MISMATCH", "PARAMETERS_DIGEST")
cli("X10", "T09", C("PR_ALLOW", "AAR_TARGET_CHANGED"), "MISMATCH", "TARGET")
cli("X11", "T10", C("PR_ALLOW", "AAR_ACTION_CHANGED"), "MISMATCH", "ACTION_NAME")
cli("X12", "T10", C("PR_ALLOW", "AAR_COMMAND_OPERATION_CHANGED"), "MISMATCH", "CANONICAL_COMMAND")
cli("X13", "T11", C("PR_ALLOW", "AAR_DISPATCH_LATE"), "MISMATCH", "EXPIRED_AT_DISPATCH")
cli("X14", "T11", C("PR_EXPIRED_AT_DISPATCH", "AAR_CITES_EXPIRED"), "MISMATCH", "EXPIRED_AT_DISPATCH")
cli("X15", "T11", C("PR_NOT_YET_VALID_AT_DISPATCH", "AAR_CITES_NOT_YET_VALID"), "MISMATCH", "DISPATCH_BEFORE_VALIDITY")
cli("X16", "T17", C("PR_HOLD", "AAR_CITES_HOLD"), "MISMATCH", "DISPATCH_WITHOUT_ALLOW")
cli("X17", "T17", C("PR_DENY", "AAR_CITES_DENY"), "MISMATCH", "DISPATCH_WITHOUT_ALLOW")
cli("X18", "T07", C("PR_WRONG_AAR_CREDENTIAL", "AAR_CITES_WRONG_CREDENTIAL"), "MISMATCH", "ACTOR")
cli("X19", "T04", C("PR_PARAM_STRING_TYPED", "AAR_CITES_STRING_PARAM_PR"), "MISMATCH", "PARAMETERS_DIGEST")
cli("X20", "T04", C("PR_PARAM_BOOL_TYPED", "AAR_CITES_BOOL_PARAM_PR"), "MISMATCH", "PARAMETERS_DIGEST")
cli("X21", "T15", C("PR_OTHER_ACTION", "AAR_CITES_OTHER_ACTION_PR"), "MISMATCH", "ACTION_NAME")
cli("X22", "T15", C("PR_OTHER_TARGET", "AAR_CITES_OTHER_TARGET_PR"), "MISMATCH", "TARGET")
cli("X23", "T12", C("PR_REPLAY_SECOND_COPY", "AAR_POSITIVE"), "INSUFFICIENT_EVIDENCE", "REF_NOT_CITED")
cli("X24", "T12", C("PR_HOLD", "AAR_POSITIVE"), "INSUFFICIENT_EVIDENCE", "REF_NOT_CITED")
cli("X25", "T19", C("PR_ALLOW", "MUT_DUPLICATE_DISPATCH"), "MISMATCH", "REPLAY")
cli("X26", "T20", C("PR_ALLOW", "MUT_OUTCOME_REMOVED"), "MATCH", XC)
cli("X27", "T20", C("PR_ALLOW", "MUT_OUTCOME_REMOVED", "--require-outcome"), "INSUFFICIENT_EVIDENCE", "OUTCOME_ABSENT")
cli("X28", "T20", C("PR_ALLOW", "MUT_OUTCOME_CONTRADICTED", "--require-outcome"), "MISMATCH", "OUTCOME_NOT_CONSISTENT")
cli("X29", "T05", C("PR_ALLOW", "MUT_PARAMS_BYTES_SWAPPED_KEEP_DIGEST"), "MISMATCH", "PARAMETERS_VALUE")
cli("X30", "T16", C("PR_ALLOW", "MUT_TRUNCATED"), "INVALID", "AAR_PARSE")
cli("X33", "T19", C("PR_ALLOW", "MUT_DISPATCH_NOT_ELIGIBLE"), "MISMATCH", "DISPATCH_NOT_ELIGIBLE")
cli("X34", "T19", C("PR_ALLOW", "MUT_DISPATCH_UNBOUND"), "MISMATCH", "UNBOUND_DISPATCH")
cli("X35", "T19", C("PR_ALLOW", "MUT_DISPATCH_EDGE_CONFLICT"), "MISMATCH", "DISPATCH_EDGE_CONFLICT")
cli("X31", "T13", C("TAMPER_PARAMS_RESIGNED_DIGEST", "AAR_POSITIVE"), "INVALID", "SIG_INVALID")
cli("X32", "-", B("PR_ALLOW") + ["--aar-bundle", AAR("AAR_POSITIVE"), "--aar-pyref", "/nonexistent"], "USAGE", "AT_REQUIRED")

# ---- Full AAR conformance level (only when AAR_DIR is supplied) --------------
if AAR_DIR:
    def F(pr, bundle, *extra):
        return C(pr, bundle, "--aar-pyref", AAR_DIR, "--at", AT, *extra)
    FULL = "AUTHORIZED_ACTION_EQUALS_DISPATCHED_ACTION"
    cli("F01", "T01", F("PR_ALLOW", "AAR_POSITIVE", "--require-outcome"), "MATCH", FULL)
    cli("F02", "T02", F("PR_ALLOW", "AAR_PARAMS_CHANGED"), "MISMATCH", "PARAMETERS_DIGEST")   # AAR-conformant, EP disagrees
    cli("F03", "T17", F("PR_HOLD", "AAR_CITES_HOLD"), "MISMATCH", "DISPATCH_WITHOUT_ALLOW")
    cli("F04", "T07", F("PR_WRONG_AAR_CREDENTIAL", "AAR_CITES_WRONG_CREDENTIAL"), "MISMATCH", "ACTOR")
    cli("F05", "T11", F("PR_EXPIRED_AT_DISPATCH", "AAR_CITES_EXPIRED"), "MISMATCH", "EXPIRED_AT_DISPATCH")
    cli("F06", "T09", F("PR_ALLOW", "AAR_TARGET_CHANGED"), "AAR_NONCONFORMANT", "PYREF")
    cli("F07", "T10", F("PR_ALLOW", "AAR_ACTION_CHANGED"), "AAR_NONCONFORMANT", "PYREF")
    cli("F08", "T19", F("PR_ALLOW", "MUT_DUPLICATE_DISPATCH"), "AAR_NONCONFORMANT", "PYREF")
    cli("F09", "T20", F("PR_ALLOW", "MUT_OUTCOME_REMOVED", "--require-outcome"), "INSUFFICIENT_EVIDENCE", "OUTCOME_ABSENT")
    cli("F10", "T20", F("PR_ALLOW", "MUT_OUTCOME_CONTRADICTED"), "AAR_NONCONFORMANT", "PYREF")
    cli("F11", "T16", F("PR_ALLOW", "AAR_NO_CITATION"), "INSUFFICIENT_EVIDENCE", "NO_CITATION")
    cli("F12", "T15", F("PR_OTHER_ACTION", "AAR_CITES_OTHER_ACTION_PR"), "MISMATCH", "ACTION_NAME")

# ---- Unit tests --------------------------------------------------------------
V1 = ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
V2 = ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")
h = bytes.fromhex
unit("U01", "T13", lambda: E.verify(h(V1[0]), h(V1[1]), h(V1[2])) and E.verify(h(V2[0]), h(V2[1]), h(V2[2])), "RFC 8032 s7.1 vectors 1-2 verify")
unit("U02", "T13", lambda: not E.verify(h(V2[0]), b"\x73", h(V2[2])), "RFC 8032 vector 2 with altered message rejected")
IDENT = b"\x01" + bytes(31)  # encoding of the identity point (small order 1)
unit("U03", "T14", lambda: not E.verify(IDENT, b"any message", IDENT + bytes(32)), "small-order (identity) public key: universal forgery R=identity,S=0 rejected")
unit("U03b", "T14", lambda: not E.verify(bytes(32), b"", IDENT + bytes(32)), "order-4 public key (y=0) rejected")
unit("U04", "T13", lambda: not E.verify((2**255 - 19 + 1).to_bytes(32, "little"), b"", h(V1[2])), "non-canonical y >= p public key rejected")
unit("U05", "T06", lambda: not E.verify(bytearray(h(V1[0])), b"", h(V1[2])), "bytearray (non-bytes) input rejected")
class S(str): pass
class I(int):
    def __eq__(self, o): return True
    __hash__ = int.__hash__
class D(dict): pass
unit("U06", "T06", lambda: raises(lambda: rfcj.cj({"a": S("x")}), rfcj.CJError), "RF-CJ-1 rejects str subclass value")
unit("U07", "T06", lambda: raises(lambda: rfcj.cj({"a": I(3)}), rfcj.CJError), "RF-CJ-1 rejects int subclass with hostile __eq__")
unit("U08", "T06", lambda: raises(lambda: rfcj.cj(D(a=1)), rfcj.CJError), "RF-CJ-1 rejects dict subclass")
unit("U09", "T06", lambda: raises(lambda: rfcj.cj({S("a"): 1}), rfcj.CJError), "RF-CJ-1 rejects str-subclass key")
unit("U10", "T06", lambda: raises(lambda: detcbor.encode({"a": I(3)}), Exception), "detCBOR rejects int subclass")
unit("U11", "T06", lambda: raises(lambda: P.params_digest({"preset": I(3)}), Exception), "params_digest rejects hostile int subclass")
unit("U12", "T06", lambda: not X._same(I(3), 4) and not X._same(True, 1) and not X._same("3", 3), "type-strict equality defeats __eq__ override, bool/int and str/int confusion")
unit("U13", "T04", lambda: raises(lambda: detcbor.encode(1.5), Exception), "detCBOR rejects floats")
unit("U14", "T04", lambda: raises(lambda: detcbor.decode(h("a2616201616101")), Exception), "detCBOR rejects unsorted map keys")
unit("U15", "T04", lambda: raises(lambda: detcbor.decode(h("1817")), Exception), "detCBOR rejects non-shortest integer")
unit("U16", "T03", lambda: detcbor.encode({"preset": 3, "dwell_seconds": 30}) == detcbor.encode({"dwell_seconds": 30, "preset": 3}), "detCBOR parameter bytes independent of insertion order")
unit("U17", "T04", lambda: raises(lambda: rfcj.parse(b'{"a":"\\ud800"}'), rfcj.CJError), "RF-CJ-1 rejects lone surrogate")
unit("U18", "T04", lambda: not P._str("e\u0301") and P._str("\u00e9"), "ProofRecord text fields must be NFC (decomposed form rejected)")
unit("U19", "-", lambda: detcbor.encode(detcbor.decode(open(AAR("AAR_POSITIVE"), "rb").read())) == open(AAR("AAR_POSITIVE"), "rb").read(), "detCBOR round-trips the AAR bundle byte-identically")

# ---- Report ------------------------------------------------------------------
fails = [r for r in results if not r[2]]
for tid, tc, ok, msg in results:
    print("%s %-4s %-4s %s" % ("PASS" if ok else "FAIL", tid, tc, msg))
print("\nTOTAL %d  PASS %d  FAIL %d  (full-conformance rows %s)" % (
    len(results), len(results) - len(fails), len(fails), "INCLUDED" if AAR_DIR else "SKIPPED: set AAR_DIR"))
sys.exit(1 if fails else 0)
