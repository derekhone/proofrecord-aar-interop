"""verify_offline: ProofRecord verification and AAR cross-check. No network."""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

from .proofrecord import PRError, load_public_key, verify_proofrecord
from .aar_xcheck import XResult, cross_check

# rc.5: exit 0 for a MATCH means the AAR bundle was checked by AAR pyref against a
# relying-party-pinned trust policy, over the same bytes the cross-check read.
# Every weaker MATCH has its own non-zero exit (issues #1 and #3).
EXIT = {"MATCH": 0, "VALID": 0, "MISMATCH": 1, "INVALID": 2, "UNSUPPORTED": 3,
        "NOT_AUTHORIZED": 4, "INSUFFICIENT_EVIDENCE": 5, "AAR_NONCONFORMANT": 6,
        "MATCH_CROSS_CHECK_ONLY": 7, "MATCH_AAR_TRUST_UNPINNED": 8, "USAGE": 64}
_DIGEST_LINE = re.compile(r"^\s*bundle_digest: ([0-9a-f]{64})\s*$")


def _read(path):
    with open(path, "rb") as f:
        return f.read()


def _emit(rep):
    sys.stdout.write(json.dumps(rep, sort_keys=True, indent=1) + "\n")
    return EXIT[rep["outcome"]]


def run_pyref(aar_dir, bundle_bytes, at, trust_policy_bytes=None):
    """Run AAR's own offline verifier (unchanged, from the reviewer's AAR checkout).

    rc.5 (issue #2): pyref is given a private, read-only copy of the exact bytes
    already held in memory, never the caller's path, and its reported
    bundle_digest must equal sha256 of those bytes. rc.5 (issue #1): when a trust
    policy is supplied it is passed through pyref's own --trust-policy option.
    """
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    work = tempfile.mkdtemp(prefix="epverify-")  # mode 0700
    try:
        bpath = os.path.join(work, "bundle.cbor")
        with open(bpath, "xb") as f:
            f.write(bundle_bytes)
        os.chmod(bpath, 0o400)
        cmd = [sys.executable, "-B", "-m", "pyref", "verify", bpath, "--at", str(at)]
        if trust_policy_bytes is not None:
            tpath = os.path.join(work, "trust-policy.json")
            with open(tpath, "xb") as f:
                f.write(trust_policy_bytes)
            os.chmod(tpath, 0o400)
            cmd += ["--trust-policy", tpath]
        p = subprocess.run(cmd, cwd=aar_dir, env=env, capture_output=True, text=True, timeout=600)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    lines = p.stdout.splitlines()
    conformant = p.returncode == 0 and "Result: conformant" in lines
    last = [l for l in lines if l.startswith("Result:")]
    trust = [l for l in lines if l.startswith("Trust policy:")]
    digests = sorted({m.group(1) for m in (_DIGEST_LINE.match(l) for l in lines) if m})
    return {"conformant": conformant, "rc": p.returncode, "result": last[-1] if last else "",
            "trust_line": trust[-1] if trust else "", "bundle_digests": digests}


def _trust_summary(policy_bytes):
    """Report what the relying party pinned. Raises ValueError on an unreadable policy."""
    pol = json.loads(policy_bytes.decode("utf-8"))
    store = pol["trust_store"]
    return {"mode": "RELYING_PARTY_PINNED",
            "trust_policy_sha256": hashlib.sha256(policy_bytes).hexdigest(),
            "trust_store_digest": store["digest"], "trust_store_snapshot_id": store["snapshot_id"],
            "root_kids": [r["root_kid"] for r in store["roots"]],
            "expected_anchor_heads": len(pol["expected_anchor_heads"])}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="verify_offline", description=__doc__)
    ap.add_argument("--proofrecord", required=True)
    ap.add_argument("--key", required=True, help="relying-party-pinned public key file")
    ap.add_argument("--aar-bundle")
    ap.add_argument("--aar-pyref", metavar="AAR_REPO_DIR", help="run AAR pyref from this checkout first")
    ap.add_argument("--aar-trust-policy", metavar="FILE",
                    help="relying-party AAR trust pin, passed to pyref --trust-policy (required for exit-0 MATCH)")
    ap.add_argument("--aar-trust-producer-declared", action="store_true",
                    help="explicitly accept the bundle's own declared AAR trust; MATCH then exits 8, never 0")
    ap.add_argument("--at", type=int, help="evaluation time (unix seconds); never read from a clock")
    ap.add_argument("--require-outcome", action="store_true")
    try:
        a = ap.parse_args(argv)
    except SystemExit:
        return EXIT["USAGE"]
    rep = {"tool": "epverify 1.1 (EP-AAR-001, v0.1.0-rc.5 candidate)", "levels": {}}
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
    if (a.aar_trust_policy or a.aar_trust_producer_declared) and not a.aar_pyref:
        rep.update(outcome="USAGE", code="TRUST_OPTION_WITHOUT_PYREF",
                   detail="--aar-trust-policy / --aar-trust-producer-declared need --aar-pyref")
        return _emit(rep)
    if a.aar_trust_policy and a.aar_trust_producer_declared:
        rep.update(outcome="USAGE", code="TRUST_OPTIONS_CONFLICT",
                   detail="use either --aar-trust-policy or --aar-trust-producer-declared")
        return _emit(rep)
    # issue #2: the bundle is read exactly once; pyref and the cross-check both use these bytes.
    bundle_bytes = _read(a.aar_bundle)
    bundle_sha = hashlib.sha256(bundle_bytes).hexdigest()
    rep["aar_bundle_sha256"] = bundle_sha
    if a.aar_pyref:
        if a.at is None:
            rep.update(outcome="USAGE", code="AT_REQUIRED", detail="--aar-pyref needs --at")
            return _emit(rep)
        policy_bytes = None
        if a.aar_trust_policy:
            policy_bytes = _read(a.aar_trust_policy)
            try:
                rep["aar_trust_basis"] = _trust_summary(policy_bytes)
            except (ValueError, KeyError, TypeError) as e:
                rep.update(outcome="USAGE", code="TRUST_POLICY_UNREADABLE", detail=repr(e)[:200])
                return _emit(rep)
        elif a.aar_trust_producer_declared:
            rep["aar_trust_basis"] = {"mode": "PRODUCER_DECLARED_ONLY",
                                      "detail": "AAR issuer keys are the ones the bundle declares; "
                                                "the relying party pinned no AAR trust roots"}
        else:
            # issue #1: fail closed when no AAR trust basis was chosen.
            rep.update(outcome="USAGE", code="AAR_TRUST_POLICY_REQUIRED",
                       detail="--aar-pyref needs --aar-trust-policy FILE (or explicit --aar-trust-producer-declared)")
            return _emit(rep)
        r = run_pyref(a.aar_pyref, bundle_bytes, a.at, policy_bytes)
        rep["levels"]["aar_conformance"] = {"pyref_rc": r["rc"], "pyref_result": r["result"],
                                            "pyref_trust": r["trust_line"], "pyref_bundle_digests": r["bundle_digests"]}
        if not r["conformant"]:
            rep.update(outcome="AAR_NONCONFORMANT", code="PYREF", detail=r["result"])
            return _emit(rep)
        if r["bundle_digests"] != [bundle_sha]:
            rep.update(outcome="AAR_NONCONFORMANT", code="PYREF_BUNDLE_DIGEST_MISMATCH",
                       detail="pyref did not report exactly the bytes being cross-checked")
            return _emit(rep)
        want = "Trust policy: externally pinned" if policy_bytes is not None else "Trust policy: producer-declared only"
        if r["trust_line"] != want:
            rep.update(outcome="AAR_NONCONFORMANT", code="PYREF_TRUST_BASIS_UNEXPECTED", detail=r["trust_line"])
            return _emit(rep)
    else:
        rep["levels"]["aar_conformance"] = "NOT CHECKED (run with --aar-pyref, or run AAR pyref yourself)"
        rep["aar_trust_basis"] = {"mode": "NOT_CHECKED", "detail": "AAR signatures and trust were not evaluated"}
    try:
        x = cross_check(bundle_bytes, pr_bytes, pr, a.require_outcome)
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
        rep.update(outcome="MATCH_CROSS_CHECK_ONLY", code=code + "_CROSS_CHECK_ONLY")
    elif a.aar_trust_producer_declared:
        rep.update(outcome="MATCH_AAR_TRUST_UNPINNED", code=code + "_AAR_TRUST_UNPINNED")
    else:
        rep.update(outcome="MATCH", code=code)
    return _emit(rep)
