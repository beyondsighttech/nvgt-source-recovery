"""Synthetic custom-footer fixtures without private binaries or names."""
import struct
import unittest
import zlib

from Crypto.Cipher import AES

import extract
import footer_crypto
from asreader import read_module


def owned_module():
    return (b"\x01\x01\x08Mode" + (1 << 26).to_bytes(4, "big") +
            b"\x04\x00\x02\x06off\x00\x00\x00\x00\x04on\x00\x00\x00\x01" +
            b"\x00" * 13)


def owned_executable(module, mask=0xA7):
    stub = bytearray(1024)
    stub[:2] = b"MZ"
    struct.pack_into("<I", stub, 60, 128)
    stub[128:132] = b"PE\x00\x00"
    struct.pack_into("<H", stub, 134, 1)
    struct.pack_into("<H", stub, 148, 240)
    struct.pack_into("<H", stub, 152, 0x20B)
    struct.pack_into("<8sIIII", stub, 392, b".text\x00\x00\x00", 512, 4096, 512, 512)
    seed = bytes(range(32))
    for i in range(8):
        stub[600 + 7*i:607 + 7*i] = bytes((0xC7, 0x45, 0xC8 + 4*i)) + bytes(
            value ^ mask for value in seed[4*i:4*i+4])
    iv = bytes(range(16))
    compressed = zlib.compress(module)
    pad = 16 - len(compressed) % 16
    encrypted = iv + AES.new(seed, AES.MODE_CBC, iv).encrypt(
        compressed + bytes([pad]) * pad)
    return (bytes(stub) + b"HDRBYTES" + encrypted + footer_crypto.FOOTER_MAGIC +
            struct.pack("<II", len(encrypted), 1))


class FooterCryptoTests(unittest.TestCase):
    def test_portable_owned_module_roundtrip(self):
        module = owned_module()
        self.assertEqual(len(read_module(module).enums), 1)
        for mask in (0, 0xA7, 0xFF):
            with self.subTest(mask=mask):
                packaged = owned_executable(module, mask)
                self.assertTrue(footer_crypto.matches(packaged))
                self.assertEqual(extract.get_payload(packaged), footer_crypto.payload(packaged))
                info, stream = extract.extract_data(packaged)
                self.assertEqual(stream, module)
                self.assertEqual(info.bytecode, module)
                self.assertEqual(info.packaging_profile, footer_crypto.PROFILE)
                self.assertEqual(info.preamble_profile, "raw_angelscript")

    def test_rejects_bad_frame_and_ciphertext(self):
        packaged = bytearray(owned_executable(owned_module()))
        for version in (0, 2):
            changed = bytearray(packaged)
            struct.pack_into("<I", changed, len(changed) - 4, version)
            with self.assertRaisesRegex(ValueError, "version"):
                extract.extract_data(bytes(changed))
        changed = bytearray(packaged)
        struct.pack_into("<I", changed, len(changed) - 8, 1)
        with self.assertRaisesRegex(ValueError, "size"):
            extract.extract_data(bytes(changed))
        changed = bytearray(packaged)
        changed[-32] ^= 1
        with self.assertRaises(ValueError):
            extract.extract_data(bytes(changed))
        changed = bytearray(packaged)
        changed[600] = 0
        with self.assertRaisesRegex(ValueError, "unsupported"):
            extract.extract_data(bytes(changed))
