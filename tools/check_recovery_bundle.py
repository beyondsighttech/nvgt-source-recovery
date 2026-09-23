"""Smoke-check recovery from a fresh, isolated extraction of the tool ZIP."""
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]

if __name__ == "__main__":
    with tempfile.TemporaryDirectory(dir=ROOT / "build") as folder:
        folder = Path(folder).resolve()
        assert folder.is_relative_to((ROOT / "build").resolve())
        with zipfile.ZipFile(ROOT / "build/NVGT-Recovery-Tool.zip") as archive:
            assert "LICENSE" in archive.namelist()
            archive.extractall(folder)
        boot = folder / "owned_check.py"
        boot.write_text('''from pathlib import Path
import sys
root = Path(__file__).resolve().parent
sys.path.insert(0, str(root))
import recover
assert Path(recover.__file__).resolve().parent == root
recover.generate_project(sys.argv[1], root / "owned_output")
print("Portable tool export passed")
''', encoding="utf-8")
        result = subprocess.run([sys.executable, "-I", str(boot), str(ROOT / "build/test_real.strip.bin")],
                                cwd=folder, capture_output=True, text=True, timeout=30)
        print(result.stdout)
        if result.returncode:
            print(result.stderr)
        raise SystemExit(result.returncode)
