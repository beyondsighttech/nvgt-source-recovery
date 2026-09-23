"""Library reuse must reject changed code rather than match names alone."""
import os
from pathlib import Path
import unittest
import tempfile

from library_recovery import compile_reference, normalized_function
from asreader import DataType, Function, Instr

ROOT = Path(__file__).resolve().parent
PROBE = Path(os.environ["NVGT_LIBRARY_PROBE"]) if os.environ.get("NVGT_LIBRARY_PROBE") else None
COMPILER = Path(os.environ["NVGT_COMPILER"]) if os.environ.get("NVGT_COMPILER") else None
INCLUDES = Path(os.environ["NVGT_INCLUDE"]) if os.environ.get("NVGT_INCLUDE") else None


class ReferenceMetadataTests(unittest.TestCase):
    def test_type_id_indices_normalize_to_datatypes(self):
        def program(index, token):
            instruction = Instr(0, 0, "TYPEID", "asBCTYPE_DW_ARG", 2, dw_arg=index,
                                data_type=DataType(token_type=token))
            return Function(name="probe", bytecode=[instruction])
        self.assertEqual(normalized_function(program(1, 67)), normalized_function(program(9, 67)))
        self.assertNotEqual(normalized_function(program(1, 67)), normalized_function(program(1, 70)))

    @unittest.skipUnless(COMPILER and INCLUDES and COMPILER.exists() and INCLUDES.is_dir(),
                         "set NVGT_COMPILER and NVGT_INCLUDE for optional compiler checks")
    def test_owned_reference_exports_raw_debug_bytecode(self):
        with tempfile.TemporaryDirectory() as directory:
            module, hashes, harness = compile_reference(str(COMPILER), ["size.nvgt"],
                str(INCLUDES), directory, reference_mode="runtime")
            self.assertTrue(module.debug_info)
            self.assertTrue(module.entry_point().bytecode)
            self.assertTrue(hashes)
            self.assertGreater(harness.with_suffix(".bin").stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
