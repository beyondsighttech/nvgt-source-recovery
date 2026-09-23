# Recovery-tool review

The review covered extraction and decryption, bytecode parsing, VM and control-flow recovery, signature rendering, project exports, include reuse, diagnostics, and packaging.

## Improvements

- Preserved namespaces across declarations and references, and suppressed duplicate function declarations from serialized tables.
- Added bounds checks for PE structures, compressed data, integers, and bytecode headers.
- Added support for historical package layouts, signed-PE trailers, serialized configuration, and verified custom AES profiles. A footer-framed custom fork derives its AES key from loader constants and validates a complete AngelScript module.
- Matched current NVGT serialization of AngelScript engine properties as 64-bit varints and discovered version-varying property counts by complete module parsing. Added validated PE overlay inference for changed size XOR masks and a privacy-safe diagnostic report with stable failure stages.
- Corrected embedded-pack framing, several VM and control-flow cases, and reference-returning chained assignments.
- Indexed control-flow lookups and cached module-wide type maps to improve large-module performance.
- Protected input and archive paths against replacement and collisions. Exported manifests distinguish reconstruction, compilation, and behavior checks.
- Added portable synthetic fixtures and opt-in compile checks. The CLI package excludes supplied binaries, recovered source, local archives, and machine-specific metadata.

## Validation and limits

Portable tests cover parsing, crypto integrity, source rendering, archive handling, and owned compile/run regressions. Optional integration checks require explicit local environment variables. A compile check runs in a disposable directory and records diagnostics without launching the supplied program.

Bytecode generally lacks comments, stripped names, and exact original include boundaries. Debug section names are retained when present; otherwise include layout is inferred. Custom engine builds can require additional verified extraction profiles and matching native APIs or plugins. Successful compilation alone does not establish behavioral equivalence.

Remaining work includes extending owned regressions for unresolved VM/control-flow cases, building a pinned native test host in CI, and ensuring re-exported projects do not retain obsolete generated files.
