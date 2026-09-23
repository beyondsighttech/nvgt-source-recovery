"""Portable, identifier-free compatibility reports."""
import json
import unittest

import diagnose
import extract
from test_support import owned_pe_stub


class DiagnosisTests(unittest.TestCase):
    def test_supported_and_corrupt_owned_packages(self):
        module = b"\x01" + bytes(14)
        stream = (bytes(6) + bytes(41) + bytes(8) + b"\x00" + module)
        payload = extract.encrypt_stream(stream)
        package = (owned_pe_stub() + extract.Reader.varint_bytes(0) +
                   extract.Reader.varint_bytes(len(payload) ^ extract.NVGT_BYTECODE_NUMBER_XOR_REPO) +
                   payload)
        report = diagnose.diagnose_bytes(package)
        self.assertEqual(report["status"], "supported")
        self.assertEqual(report["stage"], "ready")
        self.assertNotIn("path", json.dumps(report).lower())
        damaged = bytearray(package)
        damaged[-1] ^= 1
        report = diagnose.diagnose_bytes(bytes(damaged))
        self.assertEqual(report["status"], "unsupported")
        self.assertIn(report["stage"], ("crypto", "metadata"))
        self.assertNotIn("path", json.dumps(report).lower())

    def test_invalid_container_has_stable_code(self):
        report = diagnose.diagnose_bytes(b"MZ")
        self.assertEqual(report["code"], "INVALID_CONTAINER")
