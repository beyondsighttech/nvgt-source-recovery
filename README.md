# NVGT Source Recovery

[![Tests](https://github.com/beyondsighttech/nvgt-source-recovery/actions/workflows/tests.yml/badge.svg)](https://github.com/beyondsighttech/nvgt-source-recovery/actions/workflows/tests.yml)

An experimental command-line tool for recovering readable AngelScript/NVGT projects from supported compiled NVGT games. It reads the input executable; normal recovery does not run it.

## Quick start

Requires Python 3.10 or newer. From a checkout of this repository:

```sh
python -m pip install -r requirements.txt
python recover.py path/to/game.exe -o game-source.zip
```

The `.zip` output keeps only the finished source archive. To keep an unpacked project too, use a directory as the output path:

```sh
python recover.py path/to/game.exe -o recovered-game
```

To check whether the reconstructed source compiles with a specific NVGT build, opt in with `--check-with`:

```sh
python recover.py path/to/game.exe -o game-source.zip --check-with path/to/nvgt.exe
```

This compiles generated source in a disposable folder and adds `compile-report.txt`; it does not run the supplied game. A compiler pass does not establish behavioral equivalence. If recovery fails, generate a shareable stage report:

```sh
python diagnose.py path/to/game.exe --output report.json
```

The report omits the input filename, path, hash, strings and recovered source. See [USAGE.md](USAGE.md) for more options. This is a CLI-only project; no GUI or game executable is distributed here.

## What the export contains

| File | Purpose |
| --- | --- |
| `main.nvgt` and `includes/` | Reconstructed source project with readable declaration-based filenames. |
| `browse.html` | Offline browser with search, function navigation and paged viewing for large files. |
| `source_evidence.json` | Names, source coordinates, imports, declaration order and lifetime markers actually retained in bytecode. |
| `manifest.json` | Input/source hashes, packaging identity, diagnostics and verification status. |
| `compile-report.txt` | Compiler output when `--check-with` is used. |

Debug builds may retain original source-section filenames and local names. Otherwise, include layout and stripped names are generated. The export keeps binary string bytes and available signatures, but it cannot generally recover original comments, formatting, macros or exact include boundaries. The generated source is **not** the original source text.

## Accuracy and safety

A successful export is not proof that the project compiles or behaves like the game. Recovered control flow can still be wrong, and compilation may require the matching NVGT build, native plugins and APIs. Runtime assets are separate. `manifest.json` marks compilation `not_checked` by default and records the result of an opt-in check; `working_game_verified` remains false. A check uses only the supplied compiler build; zero decompiler diagnostics means only that its known placeholder scan found none.

Use this tool on software you own or are authorized to analyze. Recovered strings, debug section paths and code may contain private information; review an archive before sharing it. The manifest records the input filename and hash, not its local directory. This project is independent of NVGT and AngelScript and provides no guarantee of complete recovery. Compiling or running exported code is a separate action and should be done only after inspection.

Supported profiles include selected release and development builds, historical AngelScript bytecode variants, executables with embedded packs, three verified custom AES builds, one footer-framed AES build, and one PE-bound custom profile. Engine property counts and 64-bit values are read from the serialized stream; a changed payload-size XOR can be inferred when decryption and complete bytecode parsing both succeed. Signed executables may place an Authenticode certificate after the NVGT payload. A matching version label does not guarantee compatibility with a customized build. Unsupported inputs and compressed bytecode over the 256 MiB limit fail with an error rather than an invented source project.

## Testing and development

```sh
python -B -m unittest discover -v
```

The portable suite runs in GitHub Actions on Windows and Linux with Python 3.10 and 3.14. Optional native/compiler checks skip when their local fixtures are unavailable. The repository contains tool source and owned test fixtures; supplied games, DLLs, recovered projects and generated ZIPs are excluded. [REVIEW.md](REVIEW.md) records specific validation results, unresolved cases and improvement priorities.

For owned compile/run regressions, the optional `tools/build_bcdump.bat` host needs a matching NVGT source checkout and its built AngelScript library. Set `NVGT_SOURCE` to that checkout and make MinGW `g++` available on `PATH` (or set `CXX` to its executable). [USAGE.md](USAGE.md) covers single-file decompilation and other advanced options.

Licensed under the [MIT License](LICENSE).
