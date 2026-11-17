"""EP-PR-1 demonstration ProofRecord: format constants, schema and verification.

Normative description: PROOFRECORD_SIGNATURE_SPEC.md. Offline, stdlib only.
"""
import hashlib
import re
import unicodedata

from . import detcbor, ed25519_verify, rfcj

VERSION = "ep-proofrecord/1"
ALG = "Ed25519"
SIG_DOMAIN = b"EP-PROOFRECORD-v1"
KID_DOMAIN = b"EP-PROOFRECORD-KID-v1"
PARAMS_ENCODING = "rfc8949-deterministic-cbor"
KEY_NOTICE = "SYNTHETIC-DEMONSTRATION-KEY-NOT-PRODUCTION"
AAR_INPUT_NAME = "executionproof.proofrecord.v1"
DECISIONS = ("ALLOW", "HOLD", "DENY")
MAX_LIFETIME = 300

HEX32 = re.compile(r"[0-9a-f]{32}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
SIGHEX = re.compile(r"[0-9a-f]{128}\Z")


class PRError(Exception):
    """Verification failure. outcome is INVALID or UNSUPPORTED; code is specific."""

    def __init__(self, outcome, code, detail=""):
        super().__init__("%s/%s %s" % (outcome, code, detail))
        self.outcome, self.code, self.detail = outcome, code, detail


def kid_of(pub: bytes) -> str:
    return hashlib.sha256(KID_DOMAIN + b"\x00" + pub).hexdigest()


def sig_input(body) -> bytes:
    return SIG_DOMAIN + b"\x00" + rfcj.cj(body)


def params_digest(params) -> str:
    return hashlib.sha256(detcbor.encode(params)).hexdigest()


def _str(v, maxlen=128):
    return type(v) is str and 0 < len(v) <= maxlen and unicodedata.is_normalized("NFC", v)


def _uint(v):
    return type(v) is int and 0 <= v <= 2 ** 53 - 1


def _closed(obj, keys, where):
    if type(obj) is not dict:
        raise PRError("INVALID", "SCHEMA", where + " not an object")
    if set(obj) != set(keys):
        raise PRError("INVALID", "SCHEMA", "%s members %s != %s" % (where, sorted(obj), sorted(keys)))


BODY_KEYS = ("v", "alg", "kid", "proofrecord_id", "authorization_id", "decision", "actor", "action",
             "enforcement_point_id", "policy", "issuer", "issued_at", "not_before", "expires_at",
             "nonce", "use", "key_notice")
ACTOR_KEYS = ("actor_id", "identity_basis", "token_issuer", "token_subject", "aar_subject_credential_id")
ACTION_KEYS = ("action_name", "target_id", "parameters", "parameters_encoding", "parameters_digest")
POLICY_KEYS = ("policy_id", "policy_version")


def load_public_key(key_bytes: bytes):
    """Public key file: RF-CJ-1 object {alg, kid, public_key_hex, notice}."""
    try:
        k = rfcj.parse(key_bytes)
    except rfcj.CJError as e:
        raise PRError("INVALID", "KEYFILE_PARSE", e.code)
    _closed(k, ("alg", "kid", "public_key_hex", "notice"), "keyfile")
    if k["alg"] != ALG or type(k["public_key_hex"]) is not str or not HEX64.match(k["public_key_hex"]):
        raise PRError("INVALID", "KEYFILE_SCHEMA")
    pub = bytes.fromhex(k["public_key_hex"])
    if k["kid"] != kid_of(pub):
        raise PRError("INVALID", "KEYFILE_KID_MISMATCH", "kid does not match public key")
    return pub, k["kid"]


def verify_proofrecord(pr_bytes: bytes, pub: bytes, kid: str):
    """Return the verified body (dict) or raise PRError. Order follows the spec s6."""
    if type(pr_bytes) is not bytes:
        raise PRError("INVALID", "INPUT")
    try:
        env = rfcj.parse(pr_bytes)
    except rfcj.CJError as e:
        raise PRError("INVALID", "PARSE", e.code)
    try:
        canonical = rfcj.cj(env)
    except rfcj.CJError as e:
        raise PRError("INVALID", "PARSE", e.code)
    if canonical != pr_bytes:
        raise PRError("INVALID", "NON_CANONICAL", "file bytes must equal RF-CJ-1(envelope)")
    _closed(env, ("body", "sig"), "envelope")
    body, sig = env["body"], env["sig"]
    if type(body) is not dict:
        raise PRError("INVALID", "SCHEMA", "body")
    # version / algorithm before signature: no negotiation, no fallback
    if body.get("v") != VERSION:
        raise PRError("UNSUPPORTED", "VERSION", repr(body.get("v")))
    if body.get("alg") != ALG:
        raise PRError("UNSUPPORTED", "ALG", repr(body.get("alg")))
    if type(sig) is not str or not SIGHEX.match(sig):
        raise PRError("INVALID", "SIG_FORMAT")
    if body.get("kid") != kid:
        raise PRError("INVALID", "KID_UNKNOWN", "record kid is not the pinned key")
    if not ed25519_verify.verify(pub, sig_input(body), bytes.fromhex(sig)):
        raise PRError("INVALID", "SIG_INVALID")
    _check_body(body)
    return body


def _check_body(b):
    _closed(b, BODY_KEYS, "body")
    for f in ("proofrecord_id", "authorization_id", "nonce"):
        if type(b[f]) is not str or not HEX32.match(b[f]):
            raise PRError("INVALID", "SCHEMA", f)
    if b["decision"] not in DECISIONS:
        raise PRError("INVALID", "SCHEMA", "decision")
    for f in ("enforcement_point_id", "issuer"):
        if not _str(b[f]):
            raise PRError("INVALID", "SCHEMA", f)
    if b["use"] != "single" or b["key_notice"] != KEY_NOTICE:
        raise PRError("INVALID", "SCHEMA", "use/key_notice")
    _closed(b["actor"], ACTOR_KEYS, "actor")
    a = b["actor"]
    if a["identity_basis"] != "oidc" or not all(_str(a[f]) for f in ("actor_id", "token_issuer", "token_subject")):
        raise PRError("INVALID", "SCHEMA", "actor")
    if type(a["aar_subject_credential_id"]) is not str or not HEX64.match(a["aar_subject_credential_id"]):
        raise PRError("INVALID", "SCHEMA", "actor.aar_subject_credential_id")
    if a["actor_id"] != "agent:" + a["token_subject"]:
        raise PRError("INVALID", "ACTOR_SUBJECT_MISMATCH", "actor_id must equal 'agent:' + token_subject")
    _closed(b["policy"], POLICY_KEYS, "policy")
    if not all(_str(b["policy"][f]) for f in POLICY_KEYS):
        raise PRError("INVALID", "SCHEMA", "policy")
    _closed(b["action"], ACTION_KEYS, "action")
    x = b["action"]
    if not _str(x["action_name"]) or type(x["target_id"]) is not str or not HEX32.match(x["target_id"]):
        raise PRError("INVALID", "SCHEMA", "action")
    if x["parameters_encoding"] != PARAMS_ENCODING:
        raise PRError("UNSUPPORTED", "PARAMS_ENCODING")
    p = x["parameters"]
    if type(p) is not dict or not p:
        raise PRError("INVALID", "SCHEMA", "parameters")
    for k, v in p.items():
        if type(v) not in (str, int, bool):
            raise PRError("INVALID", "SCHEMA", "parameter %s type" % k)
    if type(x["parameters_digest"]) is not str or x["parameters_digest"] != params_digest(p):
        raise PRError("INVALID", "PARAMS_DIGEST_MISMATCH", "parameters_digest != SHA-256(detCBOR(parameters))")
    if not all(_uint(b[f]) for f in ("issued_at", "not_before", "expires_at")):
        raise PRError("INVALID", "SCHEMA", "times")
    if not (b["issued_at"] <= b["not_before"] < b["expires_at"] and b["expires_at"] - b["not_before"] <= MAX_LIFETIME):
        raise PRError("INVALID", "TIME_INCOHERENT")


def proofrecord_ref(pr_bytes: bytes) -> bytes:
    """Digest an AAR decision record cites: SHA-256 of the exact ProofRecord file bytes."""
    return hashlib.sha256(pr_bytes).digest()
