"""Statically verified custom NVGT AES profiles from verified PE loaders.

The embedded seed pairs identify code, not filenames or version strings. Each
profile is selected only when both seeds occur inside the PE stub; decrypted
streams still require complete zlib and AngelScript validation.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct


@dataclass(frozen=True)
class Profile:
    name: str
    size_xor: int
    header: int
    seed_a: bytes
    seed_b: bytes
    key_xor: int
    iv_rotate: int
    iv_key_offset: int
    iv_start: int
    iv_step: int
    mix_shift: int
    mix_multiplier: int
    mix_add: int
    mask_length: int


PROFILES = (
    Profile("custom_aes_128_header", 31436, 128,
            bytes.fromhex("41e6a581c4762dec41038541e8b804b5c762c8e1346c0d7fafdc0964db"),
            bytes.fromhex("01b3e4f0d56b877fac33cfdd637d2684bf7d9f7f09986a0d5d5b86bedf72833273ba96"),
            0x41ABB9BD, 1, 11, 0xF3, 11, 6, 0x6B, -0x7C, 19),
    Profile("custom_aes_112_header", 96413, 112,
            bytes.fromhex("0dbf0a53aace45863a21e76a2db8d095f3ff4a305d881bcebcb0"),
            bytes.fromhex("9d79821ceabcde4d5ae612bedcfba02d147e0c800619d470cc5f47a08927265fb488e8b556b978a8d807c1"),
            0xAB5D469C, 3, 7, 0x4E, 4, 3, 0x3D, 0x46, 56),
    Profile("custom_aes_96_header", 95244, 96,
            bytes.fromhex("a4e469624622467e95f86da0555986935e963f7b7c4dfa332ccf47"),
            bytes.fromhex("b01534346cb8ce28d4412c6387764c383865d3355a0347bf64c809ab7a27a5bfb28c21ffe934b9"),
            0xAA5EACCF, 5, 4, 0xD4, 15, 6, 0x3B, -0x50, 34),
)


def match(executable: bytes) -> Profile | None:
    if executable[:2] != b"MZ":
        return None
    from extract import payload_offset
    stub = executable[:payload_offset(executable)]
    found = [p for p in PROFILES if p.seed_a in stub and p.seed_b in stub]
    if len(found) > 1:
        raise ValueError("ambiguous custom NVGT encryption profile")
    return found[0] if found else None


def decrypt(payload: bytes, profile: Profile) -> bytes:
    """Undo AES-CBC and the two byte-mixing passes verified in the PE code."""
    from Crypto.Cipher import AES
    from extract import _inflate, _unpad

    if len(payload) <= profile.header + profile.mask_length or (len(payload) - profile.header) % 16:
        raise ValueError("invalid custom NVGT payload length")
    n = len(payload) - profile.header
    key = hashlib.sha256(profile.seed_a + struct.pack("<I", n ^ profile.key_xor)
                         + profile.seed_b).digest()
    rotation = profile.iv_rotate
    iv = bytes(((((key[2*i] << rotation) | (key[2*i] >> (8-rotation))) & 255)
                ^ key[i + profile.iv_key_offset]
                ^ ((profile.iv_start + profile.iv_step*i) & 255)) for i in range(16))
    data = bytearray(payload)
    data[profile.header:] = AES.new(key, AES.MODE_CBC, iv).decrypt(payload[profile.header:])
    for i in range(n):
        data[profile.header + i] ^= ((n >> profile.mix_shift)
                                     - (i & 255)*profile.mix_multiplier + profile.mix_add) & 255
    start = profile.header + profile.mask_length
    for i in range(len(data) - start):
        data[start + i] ^= data[profile.header + i % profile.mask_length]
    return _inflate(_unpad(bytes(data[start:])))
