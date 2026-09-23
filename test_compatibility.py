"""Owned format-drift fixtures for NVGT metadata and PE overlays."""
import struct
import unittest

import extract
from asreader import read_module
from test_support import owned_pe_stub


def encoded64(value):
    out = bytearray()
    while value >= 128:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def owned_stream(property_count, namespaces=True):
    module = b"\x01" + bytes(14)
    assert read_module(module)
    values = list(range(1, property_count + 1))
    values[5] = (1 << 40) + 7
    prefix = bytes(2)
    if namespaces:
        prefix += struct.pack("<i", 0)
    prefix += b"".join(encoded64(value) for value in values)
    prefix += struct.pack("<q", 1750000000000000)
    if namespaces:
        prefix += b"\x00"
    return prefix + module, values


class FormatDriftTests(unittest.TestCase):
    def test_property_count_and_64bit_values_are_discovered(self):
        for count in (12, 37, 41, 42, 60):
            with self.subTest(count=count):
                stream, values = owned_stream(count)
                info = extract.split_stream(stream)
                self.assertEqual(info.engine_properties, values)
                self.assertEqual(info.bytecode, b"\x01" + bytes(14))
                self.assertEqual(info.preamble_profile, f"namespaces_{count}_properties")
        stream, values = owned_stream(39, namespaces=False)
        info = extract.split_stream(stream)
        self.assertEqual(info.engine_properties, values)
        self.assertEqual(info.preamble_profile, "plugins_39_properties")

    def test_varint64_bounds(self):
        value = (1 << 64) - 1
        self.assertEqual(extract.Reader(encoded64(value)).varint64(), value)
        for invalid in (b"\x80" * 10, b"\xff" * 9 + b"\x02"):
            with self.assertRaises(ValueError):
                extract.Reader(invalid).varint64()

    def test_unknown_size_mask_is_accepted_only_with_valid_module(self):
        stream, _ = owned_stream(42)
        encrypted = extract.encrypt_official(stream)
        mask = 0x375AC3
        stub = owned_pe_stub()
        package = (stub + extract.Reader.varint_bytes(0) +
                   extract.Reader.varint_bytes(len(encrypted) ^ mask) + encrypted)
        info, recovered = extract.extract_data(package)
        self.assertEqual(recovered, stream)
        self.assertEqual(info.packaging_profile, "inferred_size_xor")
        self.assertEqual(info.preamble_profile, "namespaces_42_properties")
        damaged = bytearray(package)
        damaged[-1] ^= 1
        with self.assertRaises(ValueError):
            extract.extract_data(bytes(damaged))

    def test_signed_pe_candidate_excludes_certificate(self):
        stream, _ = owned_stream(41)
        encrypted = extract.encrypt_official(stream)
        stub = bytearray(owned_pe_stub())
        body = (extract.Reader.varint_bytes(0) +
                extract.Reader.varint_bytes(len(encrypted) ^ 0x375AC3) + encrypted)
        cert = bytes(range(32))
        struct.pack_into("<II", stub, 128 + 24 + 144, len(stub) + len(body), len(cert))
        package = bytes(stub) + body + cert
        info, recovered = extract.extract_data(package)
        self.assertEqual(recovered, stream)
        self.assertEqual(info.packaging_profile, "inferred_size_xor")
        padding = bytes(5)
        struct.pack_into("<II", stub, 128 + 24 + 144,
                         len(stub) + len(body) + len(padding), len(cert))
        padded_package = bytes(stub) + body + padding + cert
        info, recovered = extract.extract_data(padded_package)
        self.assertEqual(recovered, stream)
        self.assertEqual(info.packaging_profile, "inferred_size_xor")
