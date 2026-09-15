"""Download the four official, checksum-pinned Fashion-MNIST IDX files."""

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import struct
import urllib.request

BASE = "https://raw.githubusercontent.com/zalandoresearch/fashion-mnist/master/data/fashion/"
# Published by Zalando and also pinned in torchvision 0.19.0.
RESOURCES = {
    "train-images-idx3-ubyte.gz": ("8d4fb7e6c68d591d4c3dfef9ec88bf0d", (2051, 60000, 28, 28)),
    "train-labels-idx1-ubyte.gz": ("25c81989df183df01b3e8a0aad5dffbe", (2049, 60000)),
    "t10k-images-idx3-ubyte.gz": ("bef4ecab320f06d8554ea6380940ec79", (2051, 10000, 28, 28)),
    "t10k-labels-idx1-ubyte.gz": ("bb300cfdad3c16e7a12a480ee83cd310", (2049, 10000)),
}


def validate_resource(content, md5, header):
    if hashlib.md5(content).hexdigest() != md5:
        raise ValueError("Fashion-MNIST compressed checksum mismatch")
    raw = gzip.decompress(content)
    size = 4 * len(header)
    payload_size = header[1] * (784 if len(header) == 4 else 1)
    if len(raw) != size + payload_size or struct.unpack(">" + "I" * len(header), raw[:size]) != header:
        raise ValueError("Fashion-MNIST IDX header/length mismatch")
    if len(header) == 2 and any(label > 9 for label in raw[size:]):
        raise ValueError("invalid Fashion-MNIST class")
    return raw


def prepare(root, download=False):
    raw_dir = root / "FashionMNIST" / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    records = []
    for name, (md5, header) in RESOURCES.items():
        path = raw_dir / name
        if not path.exists():
            if not download:
                raise FileNotFoundError(f"{path}; run with --download first")
            print(f"Downloading {name}", flush=True)
            with urllib.request.urlopen(BASE + name, timeout=60) as response:
                content = response.read(32_000_001)
            if len(content) > 32_000_000:
                raise ValueError("download exceeds expected bound")
            validate_resource(content, md5, header)
            with path.open("xb") as stream:
                stream.write(content)
        content = path.read_bytes()
        raw = validate_resource(content, md5, header)
        target = raw_dir / name.removesuffix(".gz")
        if target.exists():
            if target.read_bytes() != raw:
                raise ValueError(f"existing extracted dataset changed: {target}")
        else:
            with target.open("xb") as stream:
                stream.write(raw)
        records.append({"name": name, "url": BASE + name, "md5": md5,
                        "sha256": hashlib.sha256(content).hexdigest(),
                        "raw_sha256": hashlib.sha256(raw).hexdigest(),
                        "bytes": len(content), "raw_bytes": len(raw), "idx_header": list(header)})
    return {"dataset": "Fashion-MNIST", "source": "https://github.com/zalandoresearch/fashion-mnist",
            "train_examples": 60000, "test_examples": 10000, "files": records}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(".cache/fashion-mnist"))
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.output and args.output.exists():
        parser.error("output already exists")
    report = prepare(args.root, args.download)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
