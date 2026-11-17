"""Write a pyref --trust-policy JSON file from an AAR fixture bundle's trust_inputs.

TEST PINS ONLY. A pin derived from the bundle being verified is circular: it shows
that the pinning mechanism works, not that the AAR keys are trustworthy. A real
relying party obtains its trust policy out of band and must not derive it from
the bundle it is about to verify.

  python3 tests/make_test_trust_policy.py BUNDLE.cbor OUT.json
"""
import json, os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from epverify import detcbor  # noqa: E402


def hexify(x):
    if type(x) is bytes:
        return x.hex()
    if type(x) is dict:
        return {k: hexify(v) for k, v in x.items()}
    if type(x) is list:
        return [hexify(v) for v in x]
    return x


def policy_for(bundle_bytes):
    t = dict(detcbor.decode(bundle_bytes)["trust_inputs"])
    t.pop("evaluation_time", None)  # pyref takes evaluation time only from --at
    return hexify(t)


if __name__ == "__main__":
    with open(sys.argv[1], "rb") as f:
        pol = policy_for(f.read())
    with open(sys.argv[2], "w") as f:
        json.dump(pol, f, sort_keys=True, indent=1)
        f.write("\n")
