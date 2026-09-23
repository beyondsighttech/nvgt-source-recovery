"""Static recovery for a custom footer-framed AngelScript package.

The loader stores its AES key as eight adjacent 32-bit stack constants, with a
one-byte XOR applied before use. Discover those constants in the supplied PE;
no input-specific key or filename is stored in this project. Validate the
entire decompressed AngelScript module before accepting a candidate.
"""
from __future__ import annotations

import struct
import zlib

from Crypto.Cipher import AES

FOOTER_MAGIC = bytes.fromhex("45 4b 52 55 54 4b 4f 47")
FOOTER_SIZE = 16
PREFIX_SIZE = 8
PROFILE = "custom_footer_aes_cbc"


def matches(data: bytes) -> bool:
    return data[:2] == b"MZ" and len(data) >= FOOTER_SIZE and data[-16:-8] == FOOTER_MAGIC


def payload(data: bytes) -> bytes:
    """Return IV plus ciphertext after validating the PE overlay framing."""
    if not matches(data):
        raise ValueError("custom footer not found")
    from extract import payload_offset

    size, version = struct.unpack_from("<II", data, len(data) - 8)
    overlay = payload_offset(data)
    if version != 1:
        raise ValueError("unsupported custom footer version")
    if size < 32 or (size - 16) % 16 or overlay + PREFIX_SIZE + size + FOOTER_SIZE != len(data):
        raise ValueError("invalid custom footer payload size")
    start = overlay + PREFIX_SIZE
    return data[start:start + size]


def _seed_candidates(stub: bytes):
    """Find eight consecutive x64 stack constants; try their XOR variants."""
    pos = 0
    while True:
        pos = stub.find(b"\xc7\x45\xc8", pos)
        if pos < 0:
            return
        if pos + 56 <= len(stub) and all(
            stub[pos + i * 7:pos + i * 7 + 3] == bytes((0xC7, 0x45, 0xC8 + 4*i))
            for i in range(8)
        ):
            yield b"".join(stub[pos + i*7 + 3:pos + i*7 + 7] for i in range(8))
        pos += 1


def decrypt(data: bytes) -> bytes:
    """Recover a complete module; never accept only valid AES padding."""
    from asreader import read_module
    from extract import _inflate, _unpad, payload_offset

    encrypted = payload(data)
    iv, ciphertext = encrypted[:16], encrypted[16:]
    for seed in _seed_candidates(data[:payload_offset(data)]):
        for mask in range(256):
            key = bytes(value ^ mask for value in seed)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            first = cipher.decrypt(ciphertext[:16])
            if len(first) < 2 or first[0] & 15 != 8 or ((first[0] << 8) | first[1]) % 31:
                continue
            try:
                plain = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
                module = _inflate(_unpad(plain))
                read_module(module)
            except (ValueError, zlib.error):
                continue
            return module
    raise ValueError("unsupported custom footer AES key or bytecode")
