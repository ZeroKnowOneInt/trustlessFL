"""Read-only author-source snapshot for experiment provenance.

These sources are a reference for differential tests, not executable Flower
workers. Recording their hashes is not a security or whole-program parity proof.
"""

import hashlib
from pathlib import Path

from .aion_original_hprf import _read_primitive
from .fmnist_artifact_mgf import SHPRG_P, SHPRG_Q

REFERENCE_FILES = ("shprg/shprg.py", "shprg/initialization_values",
                   "roles/aggregation_rules.py", "roles/client.py", "roles/trainer.py",
                   "image_helper.py")


def load_author_reference(directory):
    root = Path(directory)
    initialization = _read_primitive(root / "shprg/initialization_values")
    if (not isinstance(initialization, (list, tuple)) or len(initialization) != 4
            or any(type(value) is not int for value in initialization)
            or tuple(initialization) != (1, 8, SHPRG_P, SHPRG_Q)):
        raise ValueError("author SHPRG initialization differs from port parameters")
    files = {name: (root / name).read_bytes() for name in REFERENCE_FILES}
    record = {"scope": "author source reference snapshot; not executable worker code or global RNG parity",
              "initialization": list(initialization),
              "sha256": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}
    return files, record


def stage_author_reference(files, output):
    root = Path(output) / "author-reference"
    root.mkdir(exist_ok=False)
    for name in REFERENCE_FILES:
        destination = root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(files[name])


def verify_author_reference(output, record):
    if (not isinstance(record, dict) or not isinstance(record.get("sha256"), dict)
            or set(record["sha256"]) != set(REFERENCE_FILES)):
        raise ValueError("invalid author reference inventory")
    _, actual = load_author_reference(Path(output) / "author-reference")
    if actual != record:
        raise ValueError("staged author reference changed")
