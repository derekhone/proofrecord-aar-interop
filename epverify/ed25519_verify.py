"""Ed25519 signature verification for ProofRecords (verification only).

Copyright (c) 2026 Remnant Fieldworks Inc. MIT License (see LICENSE).

The Ed25519 arithmetic is delegated to libsodium through PyNaCl
(https://github.com/pyca/pynacl; PyNaCl: Apache License 2.0; libsodium: ISC
License). PyNaCl is a runtime dependency; it is NOT bundled in this package.
No elliptic-curve code is included in this file.

Checks made here before calling libsodium (all on public data):
  * exact `bytes` types; 32-byte public key; 64-byte signature;
  * public key and signature R must use canonical encodings (y < 2^255 - 19);
  * S must be below the group order L.
libsodium (crypto_sign_verify_detached) additionally rejects small-order
public keys and small-order R. Any library error is treated as "not valid".
This is the only signature-acceptance path in the package. Since v0.1.0-rc.3
no secondary (OpenSSL) checker is shipped.
"""
try:
    from nacl.signing import VerifyKey as _VerifyKey
    from nacl.exceptions import BadSignatureError as _BadSignatureError
except ImportError as exc:  # fail closed: no backend, no verification
    raise ImportError(
        "PyNaCl is required for Ed25519 verification: python3 -m pip install --require-hashes -r requirements.txt"
    ) from exc

_FIELD_P = 2 ** 255 - 19
_ORDER_L = 2 ** 252 + 27742317777372353535851937790883648493


def _canonical_point_encoding(b: bytes) -> bool:
    return (int.from_bytes(b, "little") & ((1 << 255) - 1)) < _FIELD_P


def verify(public: bytes, msg: bytes, signature: bytes) -> bool:
    if type(public) is not bytes or type(msg) is not bytes or type(signature) is not bytes:
        return False
    if len(public) != 32 or len(signature) != 64:
        return False
    if not _canonical_point_encoding(public) or not _canonical_point_encoding(signature[:32]):
        return False
    if int.from_bytes(signature[32:], "little") >= _ORDER_L:
        return False
    try:
        _VerifyKey(public).verify(msg, signature)
    except _BadSignatureError:
        return False
    except Exception:
        return False
    return True
