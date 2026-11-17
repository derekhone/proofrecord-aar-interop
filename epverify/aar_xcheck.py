"""Cross-record check: does an AAR bundle cite this ProofRecord, and does the
action AAR records as attempted/dispatched agree with the action the
ProofRecord authorized?

This module READS AAR v0.2 bundles (deterministic CBOR). It does NOT verify
AAR signatures, credentials, Merkle proofs or epochs: that is AAR conformance,
decided by AAR's own offline verifier (pyref). verify_offline.py can run pyref
first (--aar-pyref) and refuses to report MATCH unless pyref says conformant.
"""
from . import detcbor
from .proofrecord import AAR_INPUT_NAME, proofrecord_ref


class XResult(Exception):
    def __init__(self, outcome, code, detail=""):
        super().__init__("%s/%s %s" % (outcome, code, detail))
        self.outcome, self.code, self.detail = outcome, code, detail


def _receipts(bundle_bytes):
    try:
        b = detcbor.decode(bundle_bytes)
        envs = b["artifacts"]["receipts"]
        out = []
        for env in envs:
            if type(env) is not list or len(env) != 2 or type(env[0]) is not bytes:
                raise XResult("INVALID", "AAR_SHAPE", "receipt envelope")
            out.append(detcbor.decode(env[0]))
        return out
    except detcbor.CBORError as e:
        raise XResult("INVALID", "AAR_PARSE", str(e))
    except (KeyError, TypeError) as e:
        raise XResult("INVALID", "AAR_SHAPE", repr(e))


def _same(a, b):
    """Type-strict equality (True != 1, '3' != 3)."""
    if type(a) is not type(b):
        return False
    if type(a) is dict:
        return set(a) == set(b) and all(_same(a[k], b[k]) for k in a)
    if type(a) is list:
        return len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b))
    return a == b


def cross_check(bundle_bytes, pr_bytes, pr, require_outcome=False):
    """Return a report dict on MATCH; raise XResult otherwise."""
    ref = proofrecord_ref(pr_bytes)
    rs = _receipts(bundle_bytes)
    rep = {"proofrecord_ref_sha256": ref.hex()}

    # 1. citation
    cites, all_ep_inputs = [], 0
    for r in rs:
        if r.get("kind") != "authorization":
            continue
        ev = r["body"]["decision"]["evaluated_inputs"]
        ep = [e for e in ev if e.get("name") == AAR_INPUT_NAME]
        all_ep_inputs += len(ep)
        if len(ep) > 1:
            raise XResult("MISMATCH", "AMBIGUOUS_CITATION", "authorization cites >1 ProofRecord")
        if ep and ep[0]["value_digest"] == ref:
            cites.append(r)
    if not all_ep_inputs:
        raise XResult("INSUFFICIENT_EVIDENCE", "NO_CITATION", "no AAR authorization cites any ProofRecord")
    if not cites:
        raise XResult("INSUFFICIENT_EVIDENCE", "REF_NOT_CITED",
                      "AAR cites a ProofRecord digest that is not this ProofRecord")
    if len(cites) > 1:
        raise XResult("MISMATCH", "AMBIGUOUS_CITATION", "more than one AAR authorization cites this ProofRecord")
    auth = cites[0]
    dec = auth["body"]["decision"]
    rep["aar_authorization_id"] = auth["receipt_id"].hex()
    rep["aar_decision"] = dec["decision"]

    # 2. actor (delegation subject credential)
    deleg = detcbor.decode(auth["body"]["delegation"][0])
    rep["aar_delegation_subject_credential_id"] = deleg["subject_credential_id"].hex()
    if deleg["subject_credential_id"].hex() != pr["actor"]["aar_subject_credential_id"]:
        raise XResult("MISMATCH", "ACTOR", "AAR delegation subject != ProofRecord actor credential")

    # 3. attempts and dispatches bound to that authorization
    attempts = [r for r in rs if r.get("kind") == "action_attempt" and r["body"]["authorization_id"] == auth["receipt_id"]]
    eligible = [a for a in attempts if a["body"]["disposition"] == "eligible_for_dispatch"]
    rep["aar_attempts_total"] = len(attempts)
    rep["aar_attempts_eligible"] = len(eligible)
    dispatches = []
    for a in eligible:
        dispatches += [d for d in rs if d.get("kind") == "dispatch" and d["body"]["attempt_id"] == a["receipt_id"]]
    # rc.4: every dispatch in the bundle must resolve to an attempt, its attempted_as edge must name the
    # same attempt, and no dispatch may be bound to a non-eligible attempt of this authorization.
    # (Before rc.4 such dispatches were ignored, so the single-use check could report MATCH.)
    all_attempt_ids = {r["receipt_id"] for r in rs if r.get("kind") == "action_attempt"}
    this_attempt_ids = {a["receipt_id"] for a in attempts}
    eligible_ids = {a["receipt_id"] for a in eligible}
    for d in (r for r in rs if r.get("kind") == "dispatch"):
        aid = d["body"]["attempt_id"]
        edges = [e.get("parent_id") for e in d.get("parents", []) if type(e) is dict and e.get("edge_type") == "attempted_as"]
        if aid not in all_attempt_ids:
            raise XResult("MISMATCH", "UNBOUND_DISPATCH", "AAR dispatch names an attempt not present in the bundle")
        if edges != [aid] and (aid in this_attempt_ids or any(e in this_attempt_ids for e in edges)):
            raise XResult("MISMATCH", "DISPATCH_EDGE_CONFLICT", "dispatch attempt_id and attempted_as edge disagree")
        if aid in this_attempt_ids and aid not in eligible_ids:
            raise XResult("MISMATCH", "DISPATCH_NOT_ELIGIBLE", "AAR dispatch bound to a non-eligible attempt of this authorization")

    if pr["decision"] != "ALLOW":
        if dispatches:
            raise XResult("MISMATCH", "DISPATCH_WITHOUT_ALLOW",
                          "AAR records a dispatch under a ProofRecord whose decision is %s" % pr["decision"])
        raise XResult("NOT_AUTHORIZED", "DECISION_" + pr["decision"], "ProofRecord does not authorize execution")
    if dec["decision"] not in ("permit", "permit_with_approval"):
        raise XResult("MISMATCH", "AAR_DECISION", "AAR decision %s vs ProofRecord ALLOW" % dec["decision"])

    x = pr["action"]
    for a in eligible:
        act, cmd = a["body"]["action"], a["body"]["command"]
        if act["action_name"] != x["action_name"] or cmd["action_name"] != x["action_name"]:
            raise XResult("MISMATCH", "ACTION_NAME", "%s vs %s" % (act["action_name"], x["action_name"]))
        if act["target_id"].hex() != x["target_id"] or cmd["target_id"].hex() != x["target_id"]:
            raise XResult("MISMATCH", "TARGET", "%s vs %s" % (act["target_id"].hex(), x["target_id"]))
        if act["parameters_digest"].hex() != x["parameters_digest"]:
            raise XResult("MISMATCH", "PARAMETERS_DIGEST", "AAR %s vs ProofRecord %s" % (act["parameters_digest"].hex(), x["parameters_digest"]))
        try:
            aar_params = detcbor.decode(act["parameters_cbor"])
            canon = detcbor.decode(cmd["canonical_command"])
        except detcbor.CBORError as e:
            raise XResult("INVALID", "AAR_PARSE", str(e))
        if not _same(aar_params, x["parameters"]):
            raise XResult("MISMATCH", "PARAMETERS_VALUE", "decoded AAR parameters differ from ProofRecord parameters")
        if canon.get("operation") != x["action_name"] or type(canon.get("target")) is not bytes \
                or canon["target"].hex() != x["target_id"] or type(canon.get("parameters_digest")) is not bytes \
                or canon["parameters_digest"].hex() != x["parameters_digest"]:
            raise XResult("MISMATCH", "CANONICAL_COMMAND", "AAR canonical_command disagrees with ProofRecord action")
        if "parameters" in canon and not _same(canon["parameters"], x["parameters"]):
            raise XResult("MISMATCH", "CANONICAL_COMMAND", "canonical_command.parameters differ")

    if not dispatches:
        raise XResult("INSUFFICIENT_EVIDENCE", "NO_DISPATCH", "no AAR dispatch bound to this authorization")
    if len(dispatches) > 1:
        raise XResult("MISMATCH", "REPLAY", "single-use ProofRecord bound to %d dispatches" % len(dispatches))
    d = dispatches[0]
    att = [a for a in eligible if a["receipt_id"] == d["body"]["attempt_id"]][0]
    if d["body"]["command_id"] != att["body"]["command"]["command_id"]:
        raise XResult("MISMATCH", "COMMAND_ID", "dispatch command_id != attempt command_id")
    t = d["body"]["dispatched_at"]
    rep["aar_dispatch_id"] = d["receipt_id"].hex()
    rep["aar_dispatched_at"] = t
    if t < pr["not_before"]:
        raise XResult("MISMATCH", "DISPATCH_BEFORE_VALIDITY", "dispatched_at %d < not_before %d" % (t, pr["not_before"]))
    if t >= pr["expires_at"]:
        raise XResult("MISMATCH", "EXPIRED_AT_DISPATCH", "dispatched_at %d >= expires_at %d" % (t, pr["expires_at"]))

    # 4. outcome evidence (reported; independence NOT established)
    outs = [o for o in rs if o.get("kind") == "outcome_observation" and o["body"]["subject_id"] == d["receipt_id"]]
    rep["aar_outcome_states"] = sorted(o["body"]["state"] for o in outs)
    rep["outcome_evidence_note"] = ("AAR outcome observation present; observer key is an AAR test key, not an "
                                    "independently trusted observer" if outs else "no AAR outcome observation for this dispatch")
    if require_outcome:
        if not outs:
            raise XResult("INSUFFICIENT_EVIDENCE", "OUTCOME_ABSENT", "--require-outcome: no outcome observation")
        if any(o["body"]["state"] != "consistent" for o in outs):
            raise XResult("MISMATCH", "OUTCOME_NOT_CONSISTENT", ",".join(rep["aar_outcome_states"]))
    return rep
