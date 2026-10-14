"""RFC 8785 JSON Canonicalization Scheme (JCS) — zero-dependency.

Byte-exact requirements (draft -13 Section 5):
  * object member names sorted in ascending UTF-16 code unit order, at every
    nesting level;
  * no insignificant whitespace;
  * shortest-round-trip number form (ECMAScript Number::toString);
  * RFC 8785 string escaping (JSON.stringify semantics);
  * UTF-8 encoded output bytes.
"""
from __future__ import annotations

from decimal import Decimal
from typing import Any

__all__ = ["canonicalize"]

_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _utf16_order(key: str) -> bytes:
    # Big-endian UTF-16 code units compare exactly in UTF-16 code unit order
    # (surrogate pairs of astral characters sort before U+E000..U+FFFF).
    return key.encode("utf-16-be")


def _encode_string(s: str) -> str:
    out = ['"']
    for ch in s:
        esc = _ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        else:
            cp = ord(ch)
            if cp < 0x20 or ch in ("\u2028", "\u2029"):
                out.append("\\u%04x" % cp)
            else:
                out.append(ch)
    out.append('"')
    return "".join(out)


def _encode_number(n: float | int) -> str:
    if isinstance(n, bool):  # bool is an int subclass; guarded by caller too
        raise TypeError("bool must not reach _encode_number")
    if isinstance(n, int):
        return str(n)
    f = float(n)
    if f != f or f in (float("inf"), float("-inf")):
        raise ValueError("JCS forbids NaN and Infinity")
    if f == 0:
        return "0"  # also normalizes -0.0
    if f.is_integer() and abs(f) < 1e21:
        return str(int(f))
    r = repr(f)
    if "e" in r:
        mant, exp = r.split("e")
        e = int(exp)
        if -6 <= e < 21:
            # ECMAScript uses fixed notation in this range.
            return format(Decimal(r), "f")
        return mant + "e" + ("+" if e > 0 else "") + str(e)
    return r


def _encode(obj: Any) -> str:
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, str):
        return _encode_string(obj)
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, float):
        return _encode_number(obj)
    if isinstance(obj, dict):
        parts = []
        for key in sorted(obj.keys(), key=_utf16_order):
            if not isinstance(key, str):
                raise TypeError("JCS object keys must be strings")
            parts.append(_encode_string(key) + ":" + _encode(obj[key]))
        return "{" + ",".join(parts) + "}"
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(_encode(v) for v in obj) + "]"
    raise TypeError("JCS cannot encode %s" % type(obj).__name__)


def canonicalize(obj: Any) -> bytes:
    """Return the RFC 8785 canonical form of *obj* as UTF-8 bytes."""
    return _encode(obj).encode("utf-8")
