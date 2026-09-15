"""Download pinned public training/preprocessing sources for inspection only."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
from urllib.request import Request, urlopen

COMMIT = "bf04ddfa010c3de5a003bd087497b9f9184e58e9"
REPOSITORY = "Cyber-Tracer/iot-feature-engineering"


def get(url, limit=2_000_000):
    with urlopen(Request(url, headers={"User-Agent": "trustlessfl-source-audit"}), timeout=40) as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Unexpectedly large source")
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    tree_data = get(f"https://api.github.com/repos/{REPOSITORY}/git/trees/{COMMIT}?recursive=1")
    tree = json.loads(tree_data)
    if tree.get("truncated") or tree["sha"] != COMMIT:
        raise ValueError("Incomplete source tree")
    (args.output / "tree.json").write_bytes(tree_data)
    selected = {"README.md", ".gitmodules", "top_32_features.txt", "py_dataset/sys_func.py",
                "training/mlp.py", "training/create_fedstallar_dataset.py", "training/training30.ipynb",
                "training/training300.ipynb", "fedstellar_integration/readme.md",
                "calculating_scores/DFL/FULL/8.ipynb", "calculating_scores/CFL/8nodes.ipynb"}
    manifest = []
    for item in tree["tree"]:
        name = item["path"]
        if item["type"] != "blob" or not (name in selected or
                (name.startswith("fedstellar_integration/malwares/") and name.endswith(".py"))):
            continue
        if ".." in PurePosixPath(name).parts or PurePosixPath(name).is_absolute():
            raise ValueError("Unsafe source path")
        url = f"https://raw.githubusercontent.com/{REPOSITORY}/{COMMIT}/{name}"
        content = get(url)
        blob = hashlib.sha1(f"blob {len(content)}\0".encode() + content).hexdigest()
        if blob != item["sha"]:
            raise ValueError("Source does not match pinned Git blob")
        path = args.output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        manifest.append({"path": name, "url": url, "git_blob": blob,
                         "sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content)})
        print(name, len(content), flush=True)
    (args.output / "manifest.json").write_text(json.dumps({"commit": COMMIT, "repository": REPOSITORY,
        "execution": "None; fetched as text for audit, never imported or executed", "files": manifest}, indent=2))


if __name__ == "__main__":
    main()
