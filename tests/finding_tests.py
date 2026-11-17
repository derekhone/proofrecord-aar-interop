"""Targeted tests for the three independently reported findings (Matthew Visher,
proofrecord-aar-interop issues #1-#3, 2026-11-17).

Runs the verifier IN THE TREE GIVEN AS --target, using fixtures from this tree, so
the same tests can freeze the rc.4 behaviour and check the rc.5 candidate:

  AAR_DIR=/path/to/aar python3 tests/finding_tests.py --target /path/to/rc4 --mode rc4
  AAR_DIR=/path/to/aar python3 tests/finding_tests.py --target .            --mode rc5

--mode only chooses the documented full-check command of that release (rc.4 has
no trust-policy option). Each test PASSES only when the required property holds.
A test whose adversarial step did not actually happen is reported INVALID, never PASS.
"""
import argparse, contextlib, hashlib, importlib, io, json, os, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = lambda *p: os.path.join(HERE, *p)
AT = "1735689800"


def load_cli(target):
    for m in [m for m in sys.modules if m == "epverify" or m.startswith("epverify.")]:
        del sys.modules[m]
    sys.path.insert(0, target)
    try:
        return importlib.import_module("epverify.cli")
    finally:
        sys.path.pop(0)


def run_cli(cli, argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = cli.main(argv)
    try:
        rep = json.loads(out.getvalue())
    except ValueError:
        rep = {}
    return rc, rep


def base(pr="PR_ALLOW"):
    return ["--proofrecord", FIX("fixtures", "proofrecords", pr + ".json"),
            "--key", FIX("fixtures", "keys", "PUBLIC_TEST_KEY.json")]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--mode", choices=["rc4", "rc5"], required=True)
    a = ap.parse_args()
    aar = os.environ.get("AAR_DIR")
    if not aar:
        print("AAR_DIR is required"); return 2
    target = os.path.abspath(a.target)
    res = []

    # ---- Issue #1: the README full-check report must state the AAR trust basis ----
    cli = load_cli(target)
    argv = ["--proofrecord", FIX("SIGNED_PROOFRECORD_EXAMPLE.json"), "--key", FIX("PUBLIC_TEST_KEY.json"),
            "--aar-bundle", FIX("AAR_FIXTURE_CITING_PROOFRECORD.cbor"), "--aar-pyref", aar, "--at", AT,
            "--require-outcome"]
    if a.mode == "rc5":
        argv += ["--aar-trust-policy", FIX("AAR_FIXTURE_TRUST_POLICY.json")]
    rc, rep = run_cli(cli, argv)
    basis = rep.get("aar_trust_basis") or {}
    ok = rc == 0 and rep.get("outcome") == "MATCH" and basis.get("mode") == "RELYING_PARTY_PINNED" \
        and len(basis.get("root_kids") or []) >= 1
    res.append(("N1", "issue #1", ok, "full check rc=%s outcome=%s trust_basis=%s" % (
        rc, rep.get("outcome"), json.dumps(basis, sort_keys=True) if basis else "ABSENT")))
    # same release's command WITHOUT any trust choice must not yield exit 0 with an unstated basis
    argv_nt = [x for x in argv if x not in ("--aar-trust-policy", FIX("AAR_FIXTURE_TRUST_POLICY.json"))]
    rc2, rep2 = run_cli(cli, argv_nt)
    ok2 = not (rc2 == 0 and not rep2.get("aar_trust_basis"))
    res.append(("N1b", "issue #1", ok2, "no trust option: rc=%s outcome=%s/%s trust_basis=%s" % (
        rc2, rep2.get("outcome"), rep2.get("code"), "present" if rep2.get("aar_trust_basis") else "ABSENT")))

    # ---- Issue #2: replace the bundle file after pyref returns, before the cross-check ----
    cli = load_cli(target)
    work = tempfile.mkdtemp(prefix="toctou-")
    path_a = os.path.join(work, "bundle.cbor")
    shutil.copyfile(FIX("fixtures", "aar", "AAR_PARAMS_CHANGED.cbor"), path_a)   # pyref-conformant, EP MISMATCH
    bytes_b = open(FIX("fixtures", "aar", "MUT_RECEIPT_SIGNATURES_BROKEN.cbor"), "rb").read()  # pyref-NONconformant, EP MATCH
    real = cli.subprocess.run
    state = {"swapped": False, "pyref_calls": 0}

    def swapping_run(cmd, *k, **kw):
        p = real(cmd, *k, **kw)
        if "pyref" in cmd:
            state["pyref_calls"] += 1
            with open(path_a + ".new", "wb") as f:
                f.write(bytes_b)
            os.replace(path_a + ".new", path_a)
            state["swapped"] = True
        return p
    cli.subprocess.run = swapping_run
    argv = base() + ["--aar-bundle", path_a, "--aar-pyref", aar, "--at", AT]
    if a.mode == "rc5":
        argv += ["--aar-trust-policy", FIX("fixtures", "aar_trust", "AAR_PARAMS_CHANGED.trust-policy.json")]
    try:
        rc, rep = run_cli(cli, argv)
    finally:
        cli.subprocess.run = real
    if not state["swapped"]:
        res.append(("N2", "issue #2", None, "INVALID: swap never happened (rc=%s %s/%s)" % (rc, rep.get("outcome"), rep.get("code"))))
    else:
        res.append(("N2", "issue #2", rc != 0, "file replaced after pyref: rc=%s outcome=%s/%s" % (
            rc, rep.get("outcome"), rep.get("code"))))
    shutil.rmtree(work, ignore_errors=True)

    # ---- Issue #3: broken-AAR-signature bundle, run without --aar-pyref ----
    mut = FIX("fixtures", "aar", "MUT_RECEIPT_SIGNATURES_BROKEN.cbor")
    pre = subprocess.run([sys.executable, "-B", "-m", "pyref", "verify", mut, "--at", AT],
                         cwd=aar, capture_output=True, text=True, timeout=600)
    precondition = pre.returncode != 0 and "Result: nonconformant" in pre.stdout.splitlines()
    cli = load_cli(target)
    rc, rep = run_cli(cli, base() + ["--aar-bundle", mut])
    agrees = (rep.get("levels") or {}).get("cross_record") == "MATCH"
    if not (precondition and agrees):
        res.append(("N3", "issue #3", None, "INVALID: precondition pyref_nonconformant=%s cross_record_match=%s" % (precondition, agrees)))
    else:
        res.append(("N3", "issue #3", rc != 0, "broken AAR signatures, no pyref: rc=%s outcome=%s/%s" % (
            rc, rep.get("outcome"), rep.get("code"))))

    print("target=%s mode=%s fixture=%s sha256=%s" % (target, a.mode, os.path.basename(mut),
                                                     hashlib.sha256(open(mut, "rb").read()).hexdigest()))
    for tid, issue, ok, msg in res:
        print("%-7s %-4s %-9s %s" % ("INVALID" if ok is None else ("PASS" if ok else "FAIL"), tid, issue, msg))
    bad = [r for r in res if r[2] is not True]
    print("TOTAL %d PASS %d NOT-PASS %d" % (len(res), len(res) - len(bad), len(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
