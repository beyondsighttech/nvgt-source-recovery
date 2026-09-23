"""Privacy-safe compatibility report. Reads an input without running it.

The report contains no filename, source text, hashes, strings, or local paths.
python diagnose.py path/to/program.exe [--output report.json]
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct
import zlib

import extract


def diagnose_bytes(data: bytes) -> dict:
    report = {"schema": 1, "status": "unsupported", "stage": "container",
              "container": "pe" if data[:2] == b"MZ" else "other"}
    try:
        offset = extract.payload_offset(data)
    except (ValueError, struct.error):
        report["code"] = "INVALID_CONTAINER"
        return report
    report["overlay_present"] = offset < len(data)
    if not report["overlay_present"]:
        report.update(stage="framing", code="NO_OVERLAY")
        return report
    if data[:2] == b"MZ":
        region = extract._pe_certificate_region(data)
        report["signed_pe_trailer"] = bool(region and region[0] + region[1] == len(data))
    try:
        info, _stream = extract.extract_data(data)
    except (ValueError, zlib.error, struct.error, IndexError):
        pass
    else:
        from asreader import read_module
        try:
            module = read_module(info.bytecode)
        except ValueError:
            report.update(stage="bytecode", code="UNSUPPORTED_BYTECODE")
            return report
        report.update(status="supported", stage="ready",
                      packaging_profile=getattr(info, "packaging_profile", "standard"),
                      preamble_profile=getattr(info, "preamble_profile", None),
                      bytecode_profile=getattr(module, "bytecode_profile", None),
                      class_count=len(module.classes),
                      function_count=len(module.script_functions),
                      global_count=len(module.globals))
        return report

    import custom_crypto
    import footer_crypto
    import variant_crypto
    try:
        known_custom = (footer_crypto.matches(data) or custom_crypto.matches(data)
                        or variant_crypto.match(data) is not None)
    except (ValueError, struct.error):
        known_custom = False
    if known_custom:
        report.update(stage="custom_profile", code="CUSTOM_PROFILE_REJECTED")
        return report
    try:
        payload = extract.get_payload(data)
    except (ValueError, struct.error, IndexError):
        candidates = list(extract._inferred_overlay_payloads(data))
        report.update(stage="crypto" if candidates else "framing",
                      code="NO_VALIDATED_PAYLOAD" if candidates else "UNSUPPORTED_FRAMING")
        return report
    try:
        stream = extract.decrypt(payload)
    except (ValueError, zlib.error):
        report.update(stage="crypto", code="UNSUPPORTED_CRYPTO")
        return report
    try:
        extract.split_stream(stream)
    except ValueError:
        report.update(stage="metadata", code="UNSUPPORTED_METADATA_OR_BYTECODE")
        return report
    report.update(stage="bytecode", code="UNSUPPORTED_BYTECODE")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        report = diagnose_bytes(args.input.read_bytes())
    except OSError:
        report = {"schema": 1, "status": "unsupported", "stage": "input",
                  "code": "INPUT_READ_ERROR"}
    result = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(result, encoding="utf-8")
    else:
        print(result, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
