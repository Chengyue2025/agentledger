"""纯 Python Ed25519（RFC 8032 参考实现风格）。

为什么自己实现而不是引入 cryptography 库：
  本项目承诺零运行时依赖 —— 合规工具自己不能有供应链尾巴。
  收据签名是低频操作（每份授权签一次），纯 Python 实现的
  性能（单次签名/验签约几十毫秒）完全够用。

诚实声明（对齐本工具"机器不装好人"的原则）：
  本实现不追求恒定时间运算，不防微架构侧信道。它适合
  "授权时刻签一次、验证可离线"的收据场景，不适合守护
  高并发在线签名端点。生产级在线签名请走 KMS/HSM。
"""

from __future__ import annotations

import hashlib

# 曲线参数（RFC 8032 §5.1）
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
I_SQRT = pow(2, (P - 1) // 4, P)  # sqrt(-1) mod P

_Point = tuple[int, int, int, int]  # 扩展坐标 (X, Y, Z, T): x=X/Z, y=Y/Z, xy=T/Z


def _x_recover(y: int) -> int:
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = x * I_SQRT % P
    if (x * x - xx) % P != 0:
        raise ValueError("point not on curve")
    if x % 2 != 0:
        x = P - x
    return x


_BY = 4 * pow(5, P - 2, P) % P
_BX = _x_recover(_BY)
B: _Point = (_BX, _BY, 1, _BX * _BY % P)  # 基点


def _edwards_add(p1: _Point, p2: _Point) -> _Point:
    (x1, y1, z1, t1) = p1
    (x2, y2, z2, t2) = p2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * t2 * D % P
    dd = 2 * z1 * z2 % P
    e = b - a
    f = dd - c
    g = dd + c
    h = b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _scalarmult(pt: _Point, e: int) -> _Point:
    q: _Point = (0, 1, 1, 0)  # 单位元
    while e > 0:
        if e & 1:
            q = _edwards_add(q, pt)
        pt = _edwards_add(pt, pt)
        e >>= 1
    return q


def _point_equal(p1: _Point, p2: _Point) -> bool:
    (x1, y1, z1, _) = p1
    (x2, y2, z2, _) = p2
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


def _isoncurve(pt: _Point) -> bool:
    x, y, z, t = pt
    return (
        z % P != 0
        and (x * y - z * t) % P == 0
        and (y * y - x * x - z * z - D * t * t) % P == 0
    )


def _encodepoint(pt: _Point) -> bytes:
    x, y, z, _ = pt
    zi = pow(z, P - 2, P)
    x = x * zi % P
    y = y * zi % P
    bits = [(y >> i) & 1 for i in range(255)] + [x & 1]
    out = bytearray(32)
    for i, bit in enumerate(bits):
        if bit:
            out[i // 8] |= 1 << (i % 8)
    return bytes(out)


def _decodepoint(s: bytes) -> _Point:
    if len(s) != 32:
        raise ValueError("bad point length")
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _x_recover(y)
    if x & 1 != sign:
        x = P - x
    pt: _Point = (x, y, 1, x * y % P)
    if not _isoncurve(pt):
        raise ValueError("point not on curve")
    return pt


# --------------------------------------------------------------------------
# 密钥与签名 API（对外只暴露这几个函数）
# --------------------------------------------------------------------------
def generate_seed() -> bytes:
    """32 字节私钥种子。"""
    import secrets

    return secrets.token_bytes(32)


def _expand_seed(seed: bytes) -> tuple[int, bytes]:
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(seed: bytes) -> bytes:
    a, _ = _expand_seed(seed)
    return _encodepoint(_scalarmult(B, a))


def sign(seed: bytes, msg: bytes) -> bytes:
    a, prefix = _expand_seed(seed)
    pub = _encodepoint(_scalarmult(B, a))
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % L
    r_pt = _encodepoint(_scalarmult(B, r))
    h = int.from_bytes(hashlib.sha512(r_pt + pub + msg).digest(), "little") % L
    s = (r + h * a) % L
    return r_pt + s.to_bytes(32, "little")


def verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    if len(pub) != 32 or len(sig) != 64:
        return False
    try:
        pt_a = _decodepoint(pub)
        pt_r = _decodepoint(sig[:32])
    except ValueError:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= L:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % L
    lhs = _scalarmult(B, s)
    rhs = _edwards_add(pt_r, _scalarmult(pt_a, h))
    return _point_equal(lhs, rhs)
