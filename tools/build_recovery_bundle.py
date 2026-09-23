"""Build the portable Python recovery interface without game files/assets."""
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FILES = ("recover.py", "disasm.py", "requirements.txt", "LICENSE",
         "USAGE.md", "decompile.py", "asreader.py", "signatures.py", "opcodes.py",
         "extract.py", "custom_crypto.py", "source_evidence.py", "inspect_exe.py", "library_recovery.py", "native_probe.py")

if __name__ == "__main__":
    output = ROOT / "build/NVGT-Recovery-Tool.zip"
    output.parent.mkdir(exist_ok=True)
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for filename in FILES:
            archive.write(ROOT / filename, filename)
        archive.write(ROOT / "USAGE.md", "README.md")
    print(f"{output}: {output.stat().st_size:,} bytes")
