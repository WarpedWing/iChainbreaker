#!/usr/bin/env python

# A simple implementation of PBKDF2 using stock python modules. See RFC2898
# for details. Basically, it derives a key from a password and salt.

# (c) 2004 Matt Johnston <matt @ ucc asn au>
# This code may be freely used, distributed, relicensed, and modified for any
# purpose.

import hashlib
import hmac
from collections.abc import Callable
from struct import pack


def _ensure_bytes(b_or_s) -> bytes:
    if isinstance(b_or_s, bytes):
        return b_or_s
    return str(b_or_s).encode("utf-8")


def pbkdf2(password, salt, itercount: int, keylen: int, hashfn: Callable = hashlib.sha1) -> bytes:
    """Derive a key using PBKDF2 (HMAC-based).

    password and salt may be str or bytes; they are treated as UTF-8 strings if not bytes.
    """
    password_b = _ensure_bytes(password)
    salt_b = _ensure_bytes(salt)

    digest_size = hashfn().digest_size

    # number of output blocks to produce
    n_blocks = (keylen + digest_size - 1) // digest_size

    base_hmac = hmac.new(password_b, b"", hashfn)

    T = b""
    for i in range(1, n_blocks + 1):
        T += _pbkdf2_F(base_hmac, salt_b, itercount, i)

    return T[0:keylen]


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xorstr(): lengths differ")
    return bytes(x ^ y for x, y in zip(a, b, strict=False))


def _prf(h: hmac.HMAC, data: bytes) -> bytes:
    hm = h.copy()
    hm.update(data)
    return hm.digest()


def _pbkdf2_F(h: hmac.HMAC, salt: bytes, itercount: int, blocknum: int) -> bytes:
    U = _prf(h, salt + pack('>i', blocknum))
    T = U

    for _ in range(2, itercount + 1):
        U = _prf(h, U)
        T = _xor_bytes(T, U)

    return T
