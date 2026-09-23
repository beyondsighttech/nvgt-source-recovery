# Recover a source project

Install Python 3.10+ and the required dependency:

```sh
python -m pip install -r requirements.txt
```

Run the CLI with a supported executable and a new output path:

```sh
python recover.py path/to/game.exe -o game-source.zip
```

A `.zip` output saves the finished archive and removes the temporary unpacked project. A directory output keeps both the project and its `source.zip`:

```sh
python recover.py path/to/game.exe -o recovered-game
```

To try compiling the reconstructed project with an installed NVGT compiler:

```sh
python recover.py path/to/game.exe -o game-source.zip --check-with path/to/nvgt.exe
```

The compiler runs with `-c` against a disposable copy of generated source. Any compiled package is discarded. The archive records `source_compilation` as `passed`, `failed` or `timeout`, plus `compile-report.txt`; without the option, it remains `not_checked`. A pass applies to that compiler build only and does not verify game behavior. The supplied executable is never launched by the recovery command.

The output contains:

- `main.nvgt`: entry file with the generated include list.
- `includes/`: reconstructed source files. Debug section filenames are retained when available; stripped builds use declaration-based names such as `audioform.nvgt`.
- `browse.html`: offline source browser with search and 500-line pages. Classes stay in one source file so their members remain in scope when compiled.
- `source_evidence.json`: bytecode facts such as saved names, coordinates, imports, calls, declaration order and scope markers. Missing debug facts are not guessed.
- `manifest.json`: hashes, packaging/preamble/bytecode profiles, diagnostics and explicit verification fields. Compilation is `not_checked` unless `--check-with` was requested.
- `compile-report.txt`: compiler output when a compile check was requested; temporary project paths are replaced before archiving.

The source layout is generated from bytecode. Original comments, formatting, macro definitions and exact include boundaries are generally unavailable. Available library source can be reused with `library_recovery.py` only after bytecode comparison verifies it. Re-exporting protects files you edited by hand; choose a fresh output folder if a conflict is reported.

Recovery reads the game without running it. Unsupported encryption or bytecode formats fail with an error. A successful export and zero decompiler diagnostics do not prove compilation or correct behavior. Native APIs and plugins may require the matching engine build; runtime assets are not copied into the archive. Review recovered content before sharing or executing it.

The extractor has verified profiles for selected bundled release/development formats, two older NVGT headers, three custom AES builds, and one PE-bound XChaCha20/AES/HMAC build. The PE-bound profile requires the complete executable because its keys depend on PE data; a bare encrypted payload is insufficient. Profile selection uses crypto seeds embedded in the stub, not game filenames or version strings. Some customized builds also add configuration pairs before AngelScript bytecode. Other custom builds may use different parameters even when version strings match.

For single-file output or disassembly:

```sh
python decompile.py path/to/game.exe -o game.nvgt
python decompile.py path/to/game.exe --disasm -o game.asm
```

`native_probe.py` is an experimental compile-only check for supported targets. It uses an owned harness in a separate copy of a verified engine stub and discards original game bytecode. See [REVIEW.md](REVIEW.md) for its prerequisites and limits.

Run the portable tests with:

```sh
python -B -m unittest discover -v
```

Optional compiler/game tests skip when their fixtures are absent. Archive export protects an existing destination and publishes a complete ZIP atomically where the filesystem supports hard links; otherwise it uses exclusive creation and removes an incomplete copy on failure.

Optional integration fixtures can be enabled with NVGT_COMPILER, NVGT_INCLUDE and
NVGT_LIBRARY_PROBE as applicable. Leave them unset for the portable suite.
