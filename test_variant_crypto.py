"""Portable regression checks for extraction profiles and preambles."""
import hashlib
import struct
import unittest
import zlib

from Crypto.Cipher import AES

import extract
import variant_crypto
from asreader import read_module


class VariantCryptoTests(unittest.TestCase):
    def test_profiles_have_distinct_seed_pairs(self):
        pairs = [(p.seed_a, p.seed_b) for p in variant_crypto.PROFILES]
        self.assertEqual(len(pairs), len(set(pairs)))

    def test_portable_profile_decrypt_roundtrip(self):
        stream = b"owned bytecode fixture" * 13
        compressed = zlib.compress(stream)
        for profile in variant_crypto.PROFILES:
            with self.subTest(profile=profile.name):
                pad = (-(profile.mask_length + len(compressed))) % 16 or 16
                body = bytearray(bytes([0x5A]) * profile.mask_length +
                                 compressed + bytes([pad]) * pad)
                n = len(body)
                start = profile.mask_length
                for i in range(len(body) - start):
                    body[start + i] ^= body[i % profile.mask_length]
                for i in range(n):
                    body[i] ^= ((n >> profile.mix_shift) -
                                (i & 255) * profile.mix_multiplier +
                                profile.mix_add) & 255
                key = hashlib.sha256(profile.seed_a +
                                     struct.pack("<I", n ^ profile.key_xor) +
                                     profile.seed_b).digest()
                rotation = profile.iv_rotate
                iv = bytes((((key[2*i] << rotation) |
                             (key[2*i] >> (8-rotation))) & 255) ^
                           key[i + profile.iv_key_offset] ^
                           ((profile.iv_start + profile.iv_step*i) & 255)
                           for i in range(16))
                encrypted = AES.new(key, AES.MODE_CBC, iv).encrypt(bytes(body))
                payload = bytes(profile.header) + encrypted
                self.assertEqual(variant_crypto.decrypt(payload, profile), stream)
                with self.assertRaises(ValueError):
                    variant_crypto.decrypt(payload[:-1], profile)

    def test_config_extension_uses_complete_module_validation(self):
        module = (b"\x01\x01\x08Mode" + (1 << 26).to_bytes(4, "big") +
                  b"\x04\x00\x02\x06off\x00\x00\x00\x00\x04on\x00\x00\x00\x01" + b"\x00" * 13)
        self.assertEqual(len(read_module(module).enums), 1)
        prefix = bytes(2) + bytes(4) + bytes(41) + struct.pack("<qB", 123, 0)
        plain = extract.split_stream(prefix + module)
        self.assertEqual(plain.bytecode, module)
        self.assertEqual(plain.preamble_profile, "namespaces_41_properties")
        config = (struct.pack("<i", 1) + b"\x0dlogging.level" + b"\x07warning")
        extended = extract.split_stream(prefix + config + module)
        self.assertEqual(extended.bytecode, module)
        self.assertEqual(extended.config_overrides, [("logging.level", "warning")])
        self.assertEqual(extended.preamble_profile, "namespaces_41_properties_config")
