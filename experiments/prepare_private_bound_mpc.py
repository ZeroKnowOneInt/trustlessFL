"""Install the digest-pinned official Linux MP-SPDZ distribution locally.

No Flower/Hub settings are read or changed. Use only on Linux/WSL. Existing
installations are preserved; run verification succeeds only for our pinned
archive and an installed mascot-party.x.
"""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import tarfile
import urllib.request

VERSION = "0.4.3"
SHA256 = "4b5f4f7a79f31365288fe4498ba2b70afc314c028696929c8d259ef50ab2e759"
URL = f"https://github.com/data61/MP-SPDZ/releases/download/v{VERSION}/mp-spdz-{VERSION}.tar.xz"


def prepare(directory):
    if os.name != "posix":
        raise RuntimeError("run the MPC backend setup inside Linux/WSL")
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    archive = directory / f"mp-spdz-{VERSION}.tar.xz"
    if not archive.exists():
        request = urllib.request.Request(URL, headers={"User-Agent": "TrustlessFL-local-validation"})
        temporary = archive.with_suffix(".download")
        with urllib.request.urlopen(request, timeout=60) as response, temporary.open("xb") as output:
            while chunk := response.read(1024 * 1024):
                output.write(chunk)
        temporary.rename(archive)
    with archive.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    if actual != SHA256:
        raise RuntimeError("MP-SPDZ archive digest mismatch; do not extract or execute")
    installation = directory / f"mp-spdz-{VERSION}"
    if not installation.exists():
        with tarfile.open(archive, "r:xz") as distribution:
            distribution.extractall(directory, filter="data")
    if not (installation / "mascot-party.x").is_file():
        subprocess.run(["sh", "Scripts/tldr.sh"], cwd=installation, check=True)
    if not (installation / "mascot-party.x").is_file():
        raise RuntimeError("pinned distribution did not provide a usable MASCOT binary")
    return installation


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path(".cache/private-bound-mpc"))
    args = parser.parse_args()
    print(prepare(args.directory))


if __name__ == "__main__":
    main()
