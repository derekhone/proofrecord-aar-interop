"""RF-CJ-1 strict JSON parser and canonical serializer (spec section 1).
Reused from RF-EP-AAR-SYNTH v1 src/rfcj.py (sha256 8e318774...47ee).
EP-AAR-001 change: the serializer accepts exact built-in types only.
Standard library only. Does NOT use the json module (so duplicate keys, -0,
floats and lone surrogates cannot be silently accepted)."""
import re
import unicodedata

MAX_BYTES = 65536
MAX_DEPTH = 16
MAX_INT = 2 ** 53 - 1
KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}\Z")  # \Z not $ (defect D1, found by A/B fuzz F01 run 1)


class CJError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class _P:
    def __init__(self, s):
        self.s = s
        self.i = 0

    def ws(self):
        s, n = self.s, len(self.s)
        while self.i < n and s[self.i] in " \t\n\r":
            self.i += 1

    def value(self, depth):
        if depth > MAX_DEPTH:
            raise CJError("DEPTH")
        self.ws()
        if self.i >= len(self.s):
            raise CJError("SYNTAX")
        c = self.s[self.i]
        if c == "{":
            return self.obj(depth)
        if c == "[":
            return self.arr(depth)
        if c == '"':
            return self.string()
        if c == "-" or c in "0123456789":  # ASCII only (defect D2)
            return self.number()
        for lit, val in (("true", True), ("false", False)):
            if self.s.startswith(lit, self.i):
                self.i += len(lit)
                return val
        if self.s.startswith("null", self.i):
            raise CJError("NULL_FORBIDDEN")
        raise CJError("SYNTAX")

    def obj(self, depth):
        self.i += 1
        out = {}
        self.ws()
        if self.i < len(self.s) and self.s[self.i] == "}":
            self.i += 1
            return out
        while True:
            self.ws()
            if self.i >= len(self.s) or self.s[self.i] != '"':
                raise CJError("SYNTAX")
            k = self.string()
            if not KEY_RE.match(k):
                raise CJError("BAD_KEY")
            if k in out:
                raise CJError("DUPLICATE_KEY")
            self.ws()
            if self.i >= len(self.s) or self.s[self.i] != ":":
                raise CJError("SYNTAX")
            self.i += 1
            out[k] = self.value(depth + 1)
            self.ws()
            if self.i < len(self.s) and self.s[self.i] == ",":
                self.i += 1
                continue
            if self.i < len(self.s) and self.s[self.i] == "}":
                self.i += 1
                return out
            raise CJError("SYNTAX")

    def arr(self, depth):
        self.i += 1
        out = []
        self.ws()
        if self.i < len(self.s) and self.s[self.i] == "]":
            self.i += 1
            return out
        while True:
            out.append(self.value(depth + 1))
            self.ws()
            if self.i < len(self.s) and self.s[self.i] == ",":
                self.i += 1
                continue
            if self.i < len(self.s) and self.s[self.i] == "]":
                self.i += 1
                return out
            raise CJError("SYNTAX")

    def number(self):
        m = re.compile(r"-?(0|[1-9][0-9]*)").match(self.s, self.i)
        if not m:
            raise CJError("SYNTAX")
        txt = m.group(0)
        j = m.end()
        if j < len(self.s) and self.s[j] in ".eE":
            raise CJError("FLOAT_FORBIDDEN")
        if j < len(self.s) and self.s[j] in "0123456789":
            raise CJError("SYNTAX")
        if txt == "-0":
            raise CJError("NEGATIVE_ZERO")
        v = int(txt)
        if abs(v) > MAX_INT:
            raise CJError("INT_RANGE")
        self.i = j
        return v

    def string(self):
        s = self.s
        self.i += 1
        buf = []
        while True:
            if self.i >= len(s):
                raise CJError("SYNTAX")
            c = s[self.i]
            if c == '"':
                self.i += 1
                break
            if ord(c) < 0x20:
                raise CJError("RAW_CONTROL")
            if c == "\\":
                self.i += 1
                if self.i >= len(s):
                    raise CJError("SYNTAX")
                e = s[self.i]
                simple = {'"': '"', "\\": "\\", "/": "/", "b": "\b",
                          "f": "\f", "n": "\n", "r": "\r", "t": "\t"}
                if e in simple:
                    buf.append(simple[e])
                    self.i += 1
                elif e == "u":
                    cp = self._hex4(self.i + 1)
                    self.i += 5
                    if 0xD800 <= cp <= 0xDBFF:
                        if s.startswith("\\u", self.i):
                            lo = self._hex4(self.i + 2)
                            if 0xDC00 <= lo <= 0xDFFF:
                                self.i += 6
                                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
                            else:
                                raise CJError("LONE_SURROGATE")
                        else:
                            raise CJError("LONE_SURROGATE")
                    elif 0xDC00 <= cp <= 0xDFFF:
                        raise CJError("LONE_SURROGATE")
                    buf.append(chr(cp))
                else:
                    raise CJError("SYNTAX")
            else:
                buf.append(c)
                self.i += 1
        out = "".join(buf)
        if not unicodedata.is_normalized("NFC", out):
            raise CJError("NOT_NFC")
        return out

    def _hex4(self, j):
        h = self.s[j:j + 4]
        if len(h) != 4 or not all(ch in "0123456789abcdefABCDEF" for ch in h):
            raise CJError("SYNTAX")
        return int(h, 16)


def parse(data: bytes):
    """Strictly parse UTF-8 bytes. Raises CJError(code)."""
    if not isinstance(data, (bytes, bytearray)):
        raise CJError("SYNTAX")
    if len(data) > MAX_BYTES:
        raise CJError("SIZE")
    try:
        text = bytes(data).decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise CJError("BAD_UTF8")
    if text.startswith("\ufeff"):
        raise CJError("SYNTAX")
    p = _P(text)
    v = p.value(1)
    p.ws()
    if p.i != len(text):
        raise CJError("TRAILING_DATA")
    return v


def _esc(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _ser(v, depth):
    if depth > MAX_DEPTH:
        raise CJError("DEPTH")
    t = type(v)  # EP-AAR-001: exact built-in types only (subclasses rejected; cf. RT6/RT7, T06)
    if v is True:
        return "true"
    if v is False:
        return "false"
    if v is None:
        raise CJError("NULL_FORBIDDEN")
    if t is int:
        if abs(v) > MAX_INT:
            raise CJError("INT_RANGE")
        return str(v)
    if t is float:
        raise CJError("FLOAT_FORBIDDEN")
    if t is str:
        if not unicodedata.is_normalized("NFC", v):
            raise CJError("NOT_NFC")
        return _esc(v)
    if t is list:
        return "[" + ",".join(_ser(x, depth + 1) for x in v) + "]"
    if t is dict:
        for k in v:
            if type(k) is not str or not KEY_RE.match(k):
                raise CJError("BAD_KEY")
        return "{" + ",".join(_esc(k) + ":" + _ser(v[k], depth + 1)
                              for k in sorted(v)) + "}"
    raise CJError("SYNTAX")


def cj(v) -> bytes:
    """Canonical serialization CJ(v) as UTF-8 bytes."""
    return _ser(v, 1).encode("utf-8")
