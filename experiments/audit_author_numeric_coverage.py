"""Hash-verified coverage of ALL Python members in the pinned author artifact.

Use local bytes if pinned SHA-256 matches, otherwise HTTP-range ZIP members.
No remote code is executed; original files are not replaced or extracted.
Absence of named DMC identifiers is scoped evidence, not a semantics proof.
"""

import argparse
import ast
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
import zipfile

from experiments.audit_source_identity import RangeZip

PRECISION = re.compile(r"\b(?:DMC|DMR|l_dp|l_ex|ldp|lex)\b|dynamic mask (?:coverage|removal)", re.I)


def analyze(raw):
    text = raw.decode("utf-8-sig")
    tree = ast.parse(text)
    named = [{"line": i, "text": line.strip()} for i, line in enumerate(text.splitlines(), 1)
             if PRECISION.search(line)]
    calls = []
    definitions = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and "sum_hprg" in node.name:
            definitions.append({"name": node.name, "line": node.lineno})
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and "sum_hprg" in node.func.attr:
            calls.append({"name": node.func.attr, "line": node.lineno})
    return dict(precision_identifier_matches=named, sum_hprg_definitions=definitions, sum_hprg_calls=calls)


def audit(source, inventory, remote):
    root = Path(source)
    entries = [f for f in inventory["files"] if f["path"].endswith(".py")]
    rows, counts = {}, {"local_pinned": 0, "remote_changed": 0, "remote_missing": 0}
    with zipfile.ZipFile(remote) as archive:
        members = {i.filename for i in archive.infolist() if i.filename.endswith(".py")}
        if members != {f["path"] for f in entries}:
            raise ValueError("official ZIP Python inventory coverage changed")
        for entry in entries:
            name = entry["path"]
            relative = PurePosixPath(name).relative_to("Aion")
            if ".." in relative.parts:
                raise ValueError("unsafe inventory path")
            path = root / relative
            local = path.read_bytes() if path.is_file() else None
            local_sha = hashlib.sha256(local).hexdigest() if local is not None else None
            kind = "local_pinned" if local_sha == entry["sha256"] else (
                "remote_changed" if local is not None else "remote_missing")
            raw = local if kind == "local_pinned" else archive.read(name)
            sha = hashlib.sha256(raw).hexdigest()
            if sha != entry["sha256"] or len(raw) != entry["bytes"]:
                raise ValueError(f"official Python member differs from pinned inventory: {name}")
            counts[kind] += 1
            rows[name] = dict(bytes=len(raw), sha256=sha, local_sha256=local_sha,
                              source=kind, **analyze(raw))
    return dict(record_id=inventory["record_id"], python_members=len(entries), coverage=counts,
                files=rows, scope="all pinned Python sources; no binaries, containers or semantic absence proof")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("../Aion"))
    parser.add_argument("--inventory", type=Path, default=Path("docs/reproduction/artifact-inventory.json"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    inventory = json.loads(args.inventory.read_bytes())
    if inventory["record_id"] != 15870338:
        raise ValueError("coverage audit is pinned to v5")
    url = "https://zenodo.org/records/15870338/files/Aion.zip?download=1"
    result = audit(args.source, inventory, RangeZip(url, inventory["archive"]["bytes"]))
    result.update(remote_url=url, inventory_sha256=hashlib.sha256(args.inventory.read_bytes()).hexdigest())
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2)
    print(json.dumps({key: result[key] for key in ("record_id", "python_members", "coverage")}, indent=2))
    print(json.dumps({name: {key: row[key] for key in
        ("precision_identifier_matches", "sum_hprg_definitions", "sum_hprg_calls")}
        for name, row in result["files"].items() if any(row[key] for key in
        ("precision_identifier_matches", "sum_hprg_definitions", "sum_hprg_calls"))}, indent=2))


if __name__ == "__main__":
    main()
