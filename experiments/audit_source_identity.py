"""Compare ported author methods with the official v5 artifact, read-only.

Fetches selected ZIP members using verified HTTP byte ranges. Never imports
remote Python, unpickles remote data, extracts paths, or modifies the Aion tree.
"""

import argparse
import ast
import hashlib
import io
import json
from pathlib import Path
import urllib.request
import zipfile


METHODS = {
    "agent/Aion/SA_ClientAgent.py": ("SA_ClientAgent", (
        "sendVectors", "share_mask_seed", "vss_share", "sum_shares", "get_sum_shares")),
    "agent/Aion/SA_Aggregator.py": ("SA_AggregatorAgent", (
        "MMF", "report_process", "reconstruction_process")),
}


class RangeZip(io.RawIOBase):
    def __init__(self, url, size, *, opener=urllib.request.urlopen):
        self.url, self.size, self.position, self.opener = url, size, 0, opener
        self.cache = {}

    def seekable(self):
        return True

    def readable(self):
        return True

    def tell(self):
        return self.position

    def seek(self, offset, whence=0):
        position = offset if whence == 0 else self.position + offset if whence == 1 else self.size + offset
        if whence not in (0, 1, 2) or position < 0:
            raise ValueError("invalid remote ZIP seek")
        self.position = position
        return position

    def read(self, count=-1):
        count = min(self.size - self.position, self.size if count < 0 else count)
        if count <= 0:
            return b""
        if count > 8 * 1024 * 1024:
            raise ValueError("remote ZIP read exceeds audit limit")
        first, last = self.position, self.position + count - 1
        key = (first, last)
        if key not in self.cache:
            request = urllib.request.Request(self.url, headers={"Range": f"bytes={first}-{last}"})
            with self.opener(request, timeout=20) as reply:
                if (reply.status != 206 or reply.headers.get("Content-Range") != f"bytes {first}-{last}/{self.size}"):
                    raise ValueError("remote archive ignored or changed byte range")
                raw = reply.read(count + 1)
                if len(raw) != count:
                    raise ValueError("truncated remote ZIP range")
            self.cache[key] = raw
        self.position += count
        return self.cache[key]


def method_inventory(raw, class_name, names):
    tree = ast.parse(raw)
    role = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == class_name)
    result = {n.name: hashlib.sha256(ast.dump(n, include_attributes=False).encode()).hexdigest()
              for n in role.body if isinstance(n, ast.FunctionDef) and n.name in names}
    if set(result) != set(names):
        raise ValueError("ported author method missing")
    return result


def audit(source, inventory, remote):
    entries = {f["path"]: f for f in inventory["files"]}
    rows = {}
    with zipfile.ZipFile(remote) as archive:
        for name, (role, methods) in METHODS.items():
            path = "Aion/" + name
            raw = archive.read(path)
            expected = entries[path]
            official_hash = hashlib.sha256(raw).hexdigest()
            if official_hash != expected["sha256"] or len(raw) != expected["bytes"]:
                raise ValueError("official member differs from pinned artifact inventory")
            local = (Path(source) / name).read_bytes()
            official_methods = method_inventory(raw, role, methods)
            local_methods = method_inventory(local, role, methods)
            rows[name] = dict(official_sha256=official_hash, local_sha256=hashlib.sha256(local).hexdigest(),
                full_file_identical=raw == local, ported_method_ast_identical=official_methods == local_methods,
                official_method_ast_sha256=official_methods, local_method_ast_sha256=local_methods)
    return dict(record_id=inventory["record_id"], comparison=rows,
                scope="two ASR role files and ported method AST; not a complete artifact or privacy audit")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("../Aion"))
    parser.add_argument("--inventory", type=Path, default=Path("docs/reproduction/artifact-inventory.json"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    inventory = json.loads(args.inventory.read_text())
    if inventory["record_id"] != 15870338:
        raise ValueError("this audit is pinned to the official v5 record")
    url = "https://zenodo.org/records/15870338/files/Aion.zip?download=1"
    result = audit(args.source, inventory, RangeZip(url, inventory["archive"]["bytes"]))
    result.update(remote_url=url, inventory_sha256=hashlib.sha256(args.inventory.read_bytes()).hexdigest())
    with args.output.open("xb") as stream:
        stream.write(json.dumps(result, indent=2).encode())
    print(json.dumps({name: {k: row[k] for k in ("full_file_identical", "ported_method_ast_identical")}
                      for name, row in result["comparison"].items()}, indent=2))


if __name__ == "__main__":
    main()
