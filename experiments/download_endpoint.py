"""Fetch only the eight public V2 feature CSVs (87,742,914 bytes), not malware/logs."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import urlopen

RECORD = "https://www.scidb.cn/en/detail?dataSetId=0151eff3132541e2852a10ed65e0991f"
FILES = [
    ("eba346f9f75e69660db65b0ffaee3ae6", 10492940, "bddfabd78c1f668ed5e976f5603b748e"),
    ("61455d52348a1804eb387253b6951b0a", 11303951, "195e05252c6ca950f30b7e600d591809"),
    ("b32152a965f5209f08f09be0364d57bd", 11686758, "f85d6fe60720df542e87d33063ca7004"),
    ("37bfce470267c39941fca0a8a9dfd39e", 11658168, "6d1f84a985f288c824f333542a23a8de"),
    ("40a36fb9d4d0c5f4ed208b5d78c951f3", 10886983, "0bf9119f76b66f8f97a7da39ddb39fc2"),
    ("8d3a7bc4f905e499db6ca5e8ca20f4ea", 10441528, "bdc90c76eff93378927744072f33d233"),
    ("e1acca7dcac5f817189babac119eff48", 10786483, "fcd5076d5bcfbc7f4097e1a2ca28f7a6"),
    ("d0cd463f27f4bdcdb6906f4d1a7b8ab5", 10486103, "e80277f8629017dc3120d12bd3bb28fb"),
]


def verify(path, size, md5):
    data = path.read_bytes()
    if len(data) != size or hashlib.md5(data).hexdigest() != md5:
        raise ValueError(f"Published size/MD5 mismatch: {path}")
    return hashlib.sha256(data).hexdigest()


def fetch(index, directory):
    fid, size, md5 = FILES[index]
    path = directory / f"{index}.csv"
    url = "https://download.scidb.cn/download?" + urlencode({
        "fileId": fid, "path": f"/V2/32d-feature data/device/{index}.csv",
        "fileName": path.name,
    })
    if not path.exists():
        partial = path.with_suffix(".csv.partial")
        # Exclusive create: preserve earlier failed downloads for inspection.
        with urlopen(url, timeout=60) as response, partial.open("xb") as target:
            count = 0
            while chunk := response.read(1024 * 1024):
                count += len(chunk)
                if count > size:
                    raise ValueError("Response exceeds pinned file size")
                target.write(chunk)
        verify(partial, size, md5)
        partial.rename(path)
    sha = verify(path, size, md5)
    print(f"Verified {path.name}: {size:,} bytes", flush=True)
    return {"file": path.name, "url": url, "bytes": size, "md5": md5, "sha256": sha}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(".cache/endpoint/v2"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    with ThreadPoolExecutor(max_workers=4) as pool:
        files = list(pool.map(lambda i: fetch(i, args.output), range(8)))
    manifest = {"record": RECORD, "doi": "10.57760/sciencedb.25380", "version": "V2",
                "license": "https://creativecommons.org/licenses/by/4.0/", "files": files,
                "scope": "Only released feature CSVs; source device mapping not yet verified"}
    destination = args.output / "download-manifest.json"
    if destination.exists():
        if json.loads(destination.read_text()) != manifest:
            raise ValueError("Existing download manifest differs")
    else:
        with destination.open("x") as stream:
            json.dump(manifest, stream, indent=2)


if __name__ == "__main__":
    main()
