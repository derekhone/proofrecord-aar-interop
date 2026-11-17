"""verify_offline: ProofRecord verification and AAR cross-check. No network."""
import argparse
import json
import os
import subprocess
import sys

from .proofrecord import PRError, load_public_key, verify_proofrecord
from .aar_xcheck import XResult, cross_check

EXIT = {"MATCH": 0, "VALID": 0, "MISMATCH": 1, "INVALID": 2, "UNSUPPORTED": 3,
        "NOT_AUTHORIZED": 4, "INSUFFICIENT_EVIDENCE": 5, "AAR_NONCONFORMANT": 6, "USAGE": 64}


def _read(path):
    with open(path, "rb") as f:
        return f.read()


def _emit(rep):
    sys.stdout.write(json.dumps(rep, sort_keys=True, indent=1) + "\n")
    return EXIT[rep["outcome"]]


def run_pyref(aar_dir, bundle_path, at):
    """Run AAR's own offline verifier (unchanged, from the reviewer's AAR checkout)."""
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    p = subprocess.run([sys.executable, "-B", "-m", "pyref", "verify", os.path.abspath(bundle_path), "--at", str(at)],
                       cwd=aar_dir, env=env, capture_output=True, text=True, timeout=600)
    conformant = p.returncode == 0 and "Result: conformant" in p.stdout
    last = [l for l in p.stdout.splitlines() if l.startswith("Result:")]
    return conformant, p.returncode, (last[-1] if last else "")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="verify_offline", description=__doc__)
    ap.add_argument("--proofrecord", required=True)
    ap.add_argument("--key", required=True, help="relying-party-pinned public key file")
    ap.add_argument("--aar-bundle")
    ap.add_argument("--aar-pyref", metavar="AAR_REPO_DIR", help="run AAR pyref from this checkout first")
    ap.add_argument("--at", type=int, help="evaluation time (unix seconds); never read from a clock")
    ap.add_argument("--require-outcome", action="store_true")
    try:
        a = ap.parse_args(argv)
    except SystemExit:
        return EXIT["USAGE"]
    rep = {"tool": "epverify 1.0 (EP-AAR-001)", "levels": {}}
    try:
        pub, kid = load_public_key(_read(a.key))
        pr_bytes = _read(a.proofrecord)
        pr = verify_proofrecord(pr_bytes, pub, kid)
    except PRError as e:
        rep.update(outcome=e.outcome, code=e.code, detail=e.detail)
        rep["levels"]["proofrecord"] = e.outcome
        return _emit(rep)
    rep["levels"]["proofrecord"] = "VALID"
    rep["proofrecord"] = {"proofrecord_id": pr["proofrecord_id"], "authorization_id": pr["authorization_id"],
                          "decision": pr["decision"], "kid": pr["kid"], "action": pr["action"],
                          "actor_id": pr["actor"]["actor_id"], "not_before": pr["not_before"],
                          "expires_at": pr["expires_at"], "key_notice": pr["key_notice"]}
    if not a.aar_bundle:
        if pr["decision"] != "ALLOW":
            rep.update(outcome="NOT_AUTHORIZED", code="DECISION_" + pr["decision"])
        elif a.at is not None and not (pr["not_before"] <= a.at < pr["expires_at"]):
            rep.update(outcome="NOT_AUTHORIZED", code="OUTSIDE_VALIDITY", detail="--at outside [not_before, expires_at)")
        else:
            rep.update(outcome="VALID", code="PROOFRECORD_ONLY",
                       detail="signature and schema valid; no dispatch evidence compared")
        return _emit(rep)
    if a.aar_pyref:
        if a.at is None:
            rep.update(outcome="USAGE", code="AT_REQUIRED", detail="--aar-pyref needs --at")
            return _emit(rep)
        ok, rc, line = run_pyref(a.aar_pyref, a.aar_bundle, a.at)
        rep["levels"]["aar_conformance"] = {"pyref_rc": rc, "pyref_result": line}
        if not ok:
            rep.update(outcome="AAR_NONCONFORMANT", code="PYREF", detail=line)
            return _emit(rep)
    else:
        rep["levels"]["aar_conformance"] = "NOT CHECKED (run with --aar-pyref, or run AAR pyref yourself)"
    try:
        x = cross_check(_read(a.aar_bundle), pr_bytes, pr, a.require_outcome)
    except XResult as e:
        rep.update(outcome=e.outcome, code=e.code, detail=e.detail)
        rep["levels"]["cross_record"] = e.outcome
        return _emit(rep)
    except (KeyError, TypeError, IndexError, AttributeError) as e:
        rep.update(outcome="INVALID", code="AAR_SHAPE", detail=repr(e)[:200])
        rep["levels"]["cross_record"] = "INVALID"
        return _emit(rep)
    rep["levels"]["cross_record"] = "MATCH"
    rep["aar"] = x
    code = "AUTHORIZED_ACTION_EQUALS_DISPATCHED_ACTION"
    if not a.aar_pyref:
        code += "_CROSS_CHECK_ONLY"
    rep.update(outcome="MATCH", code=code)
    return _emit(rep)
