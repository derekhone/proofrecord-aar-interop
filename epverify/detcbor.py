"""Minimal strict deterministic-CBOR (RFC 8949 s4.2.1) codec, stdlib only.

Scope: the subset AAR v0.2 uses (uint/nint, bstr, tstr, array, map, false,
true, null). Floats, tags, indefinite lengths, non-shortest integers,
unsorted or duplicate map keys and invalid UTF-8 are rejected.
This is a reader for cross-checking; AAR conformance is decided by AAR's own
verifier (pyref), not by this module.
"""


class CBORError(ValueError):
    pass


def _head(major, n):
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 0x100:
        return bytes([(major << 5) | 24, n])
    if n < 0x10000:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    if n < 0x100000000:
        return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")
    if n < 0x10000000000000000:
        return bytes([(major << 5) | 27]) + n.to_bytes(8, "big")
    raise CBORError("integer out of range")


def encode(v):
    # exact built-in types only (subclasses rejected: see T06)
    t = type(v)
    if t is bool:
        return b"\xf5" if v else b"\xf4"
    if v is None:
        return b"\xf6"
    if t is int:
        return _head(0, v) if v >= 0 else _head(1, -1 - v)
    if t is bytes:
        return _head(2, len(v)) + v
    if t is str:
        b = v.encode("utf-8")
        return _head(3, len(b)) + b
    if t is list:
        return _head(4, len(v)) + b"".join(encode(x) for x in v)
    if t is dict:
        items = sorted(((encode(k), encode(x)) for k, x in v.items()), key=lambda kv: kv[0])
        for i in range(1, len(items)):
            if items[i][0] == items[i - 1][0]:
                raise CBORError("duplicate key")
        return _head(5, len(items)) + b"".join(k + x for k, x in items)
    raise CBORError("unsupported type %s" % t.__name__)


def decode(data):
    if type(data) is not bytes:
        raise CBORError("input must be bytes")
    v, i = _dec(data, 0, 0)
    if i != len(data):
        raise CBORError("trailing bytes")
    return v


def _arg(data, i, info):
    if info < 24:
        return info, i
    size = {24: 1, 25: 2, 26: 4, 27: 8}.get(info)
    if size is None:
        raise CBORError("indefinite/reserved length")
    if i + size > len(data):
        raise CBORError("truncated")
    n = int.from_bytes(data[i:i + size], "big")
    if (size == 1 and n < 24) or (size > 1 and n < (1 << (8 * size // 2))):
        raise CBORError("non-shortest integer")
    return n, i + size


def _dec(data, i, depth):
    if depth > 64:
        raise CBORError("nesting too deep")
    if i >= len(data):
        raise CBORError("truncated")
    ib = data[i]
    major, info = ib >> 5, ib & 31
    i += 1
    if major == 7:
        if info == 20:
            return False, i
        if info == 21:
            return True, i
        if info == 22:
            return None, i
        raise CBORError("forbidden simple/float")
    if major == 6:
        raise CBORError("tags forbidden")
    n, i = _arg(data, i, info)
    if major == 0:
        return n, i
    if major == 1:
        return -1 - n, i
    if major in (2, 3):
        if i + n > len(data):
            raise CBORError("truncated")
        raw = data[i:i + n]
        if major == 2:
            return bytes(raw), i + n
        try:
            return raw.decode("utf-8"), i + n
        except UnicodeDecodeError:
            raise CBORError("invalid UTF-8")
    if major == 4:
        out = []
        for _ in range(n):
            v, i = _dec(data, i, depth + 1)
            out.append(v)
        return out, i
    if major == 5:
        out = {}
        prev = None
        for _ in range(n):
            ks = i
            k, i = _dec(data, i, depth + 1)
            kb = data[ks:i]
            if prev is not None and kb <= prev:
                raise CBORError("map keys not strictly sorted")
            prev = kb
            if type(k) not in (str, int):
                raise CBORError("unsupported map key type")
            v, i = _dec(data, i, depth + 1)
            out[k] = v
        return out, i
    raise CBORError("unreachable")
