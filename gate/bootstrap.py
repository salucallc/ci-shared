"""Fetch the gate's pinned tools into ~/.cache/saluca-gate, checksum-verified.

gitleaks comes from its GitHub release and is checked against the SHA-256 published in the
release's checksums file (pinned here, the same pin CI uses). pip-audit is installed into a
dedicated venv under the cache, never into the global Python.
"""
from __future__ import annotations

import hashlib
import io
import platform
import subprocess
import sys
import tarfile
import urllib.request
import venv
import zipfile
from pathlib import Path

from .checks.secrets import GITLEAKS_VERSION

CACHE = Path.home() / ".cache" / "saluca-gate"
# From https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_checksums.txt
GITLEAKS_SHA256 = {
    "linux_x64.tar.gz": "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
    "linux_arm64.tar.gz": "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080",
    "darwin_x64.tar.gz": "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709",
    "darwin_arm64.tar.gz": "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5",
    "windows_x64.zip": "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e",
    "windows_arm64.zip": "b95f5e4f5c425cedca7ee203d9afd29597e692c4924a12ed42f970537c72cc0f",
}
PIP_AUDIT = "pip-audit==2.10.1"


def _asset() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = "arm64" if machine in ("arm64", "aarch64") else "x64"
    if system == "windows":
        return f"windows_{arch}.zip"
    if system == "darwin":
        return f"darwin_{arch}.tar.gz"
    return f"linux_{arch}.tar.gz"


def gitleaks() -> Path:
    asset = _asset()
    exe = "gitleaks.exe" if asset.startswith("windows") else "gitleaks"
    dest = CACHE / f"gitleaks-{GITLEAKS_VERSION}" / exe
    if dest.is_file():
        return dest
    url = f"https://github.com/gitleaks/gitleaks/releases/download/v{GITLEAKS_VERSION}/gitleaks_{GITLEAKS_VERSION}_{asset}"
    data = urllib.request.urlopen(url, timeout=120).read()  # nosec B310  (https URL from pinned constants)
    got = hashlib.sha256(data).hexdigest()
    if got != GITLEAKS_SHA256[asset]:
        raise SystemExit(f"gitleaks checksum mismatch for {asset}: got {got}, pinned {GITLEAKS_SHA256[asset]}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    if asset.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            dest.write_bytes(z.read(exe))
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
            member = t.getmember(exe)
            f = t.extractfile(member)
            assert f is not None
            dest.write_bytes(f.read())
        dest.chmod(0o755)
    return dest


def audit_venv() -> Path:
    vdir = CACHE / "venv"
    py = vdir / ("Scripts/python.exe" if platform.system() == "Windows" else "bin/python")
    if not py.is_file():
        venv.EnvBuilder(with_pip=True).create(vdir)
    subprocess.run([str(py), "-m", "pip", "install", "-q", PIP_AUDIT], check=True)
    return py


def main(args: list[str]) -> int:
    print(f"gitleaks: {gitleaks()}")
    if "--no-audit" not in args:
        print(f"pip-audit venv: {audit_venv()}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
