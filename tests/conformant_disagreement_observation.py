"""Reproduce the conformant-but-disagreeing AAR bundle observation.

For each harness-generated AAR_* bundle and the ProofRecord the test suite pairs
it with, this runs AAR's own reference verifier (pyref, unchanged, from your AAR
checkout) and then the RF cross-record check. It lists every bundle that pyref
reports conformant while the RF cross-check does NOT report MATCH.

  AAR_DIR=/path/to/aar python3 -B tests/conformant_disagreement_observation.py

This is a same-author observation. It is NOT a claim of an AAR defect or
vulnerability: AAR treats decision.evaluated_inputs as opaque by design, so a
conformant bundle can legitimately disagree with a ProofRecord AAR never reads.
Exit 0 when the run completes (whatever the count); 64 if AAR_DIR is missing.
"""
import json, os, subprocess, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from make_test_trust_policy import policy_for  # noqa: E402  (rc.5: test pins only)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AT = "1735689800"
# (bundle, ProofRecord) pairs exactly as used by tests/run_tests.py rows X01, X03-X22
PAIRS = [
    ("AAR_POSITIVE", "PR_ALLOW"), ("AAR_PARAMS_REORDERED", "PR_ALLOW"),
    ("AAR_NO_CITATION", "PR_ALLOW"), ("AAR_CITES_UNKNOWN_DIGEST", "PR_ALLOW"),
    ("AAR_CITES_TWICE", "PR_ALLOW"), ("AAR_PARAMS_CHANGED", "PR_ALLOW"),
    ("AAR_PARAMS_STRING", "PR_ALLOW"), ("AAR_PARAMS_EXTRA", "PR_ALLOW"),
    ("AAR_TARGET_CHANGED", "PR_ALLOW"), ("AAR_ACTION_CHANGED", "PR_ALLOW"),
    ("AAR_COMMAND_OPERATION_CHANGED", "PR_ALLOW"), ("AAR_DISPATCH_LATE", "PR_ALLOW"),
    ("AAR_CITES_EXPIRED", "PR_EXPIRED_AT_DISPATCH"),
    ("AAR_CITES_NOT_YET_VALID", "PR_NOT_YET_VALID_AT_DISPATCH"),
    ("AAR_CITES_HOLD", "PR_HOLD"), ("AAR_CITES_DENY", "PR_DENY"),
    ("AAR_CITES_WRONG_CREDENTIAL", "PR_WRONG_AAR_CREDENTIAL"),
    ("AAR_CITES_STRING_PARAM_PR", "PR_PARAM_STRING_TYPED"),
    ("AAR_CITES_BOOL_PARAM_PR", "PR_PARAM_BOOL_TYPED"),
    ("AAR_CITES_OTHER_ACTION_PR", "PR_OTHER_ACTION"),
    ("AAR_CITES_OTHER_TARGET_PR", "PR_OTHER_TARGET"),
]


def main():
    aar = os.environ.get("AAR_DIR")
    if not aar:
        print("AAR_DIR not set (needs an AAR checkout at aab2feca93986f92f29f7672dff3464e05163cb5)")
        return 64
    rows = []
    tmp = tempfile.mkdtemp(prefix="epobs-")
    for bundle, pr in PAIRS:
        bpath = os.path.join(ROOT, "fixtures", "aar", bundle + ".cbor")
        tpath = os.path.join(tmp, bundle + ".trust-policy.json")
        with open(bpath, "rb") as f, open(tpath, "w") as g:
            json.dump(policy_for(f.read()), g, sort_keys=True)
        p = subprocess.run([sys.executable, "-B", os.path.join(ROOT, "verify_offline.py"),
                            "--proofrecord", os.path.join(ROOT, "fixtures", "proofrecords", pr + ".json"),
                            "--key", os.path.join(ROOT, "fixtures", "keys", "PUBLIC_TEST_KEY.json"),
                            "--aar-bundle", os.path.join(ROOT, "fixtures", "aar", bundle + ".cbor"),
                            "--aar-pyref", aar, "--at", AT, "--aar-trust-policy", tpath], capture_output=True, text=True, timeout=900)
        rep = json.loads(p.stdout)
        conf = rep.get("levels", {}).get("aar_conformance")
        pyref = conf.get("pyref_result") if isinstance(conf, dict) else conf
        rows.append({"bundle": bundle + ".cbor", "proofrecord": pr + ".json", "aar_pyref": pyref,
                     "rf_outcome": rep.get("outcome"), "rf_code": rep.get("code"), "exit": p.returncode})
    disagree = [r for r in rows if r["aar_pyref"] == "Result: conformant" and r["rf_outcome"] != "MATCH"]
    print(json.dumps({"pairs_checked": len(rows), "pyref_conformant_but_rf_not_match": len(disagree),
                      "observation": disagree, "all_rows": rows,
                      "note": "same-author observation; not a claim of an AAR defect"}, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
