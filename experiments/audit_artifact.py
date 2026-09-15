"""Verify a pinned Zenodo archive and extract text for review, never execute it.

Uses only the standard library. Binary datasets, models, and pickle files stay
in the archive. The output directory must be new; extracted text is untrusted.
"""

import argparse
import hashlib
import json
import stat
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

TEXT_SUFFIXES = {".py", ".md", ".txt", ".json", ".toml", ".yaml", ".yml", ".sh", ".ini", ".cfg", ".csv"}
TEXT_NAMES = {"LICENSE", "LICENSE.txt", "Dockerfile", "Makefile", "requirements", "README"}


def safe_member(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if (not name or path.is_absolute() or ".." in path.parts or "\\" in name
            or any(":" in part for part in path.parts)):
        raise ValueError(f"unsafe archive member: {name!r}")
    return path


def hashes(path: Path) -> dict:
    algorithms = {"md5": hashlib.md5(usedforsecurity=False), "sha256": hashlib.sha256()}
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            for algorithm in algorithms.values():
                algorithm.update(chunk)
    return {name: algorithm.hexdigest() for name, algorithm in algorithms.items()}


def audit(archive: Path, record_path: Path, output: Path) -> dict:
    record = json.loads(record_path.read_text())
    if record["id"] != 15870338:
        raise ValueError("unexpected Zenodo record; this audit pins version 15870338")
    matching = [f for f in record["files"] if f["key"] == archive.name]
    if len(matching) != 1:
        raise ValueError("archive name is not uniquely listed in record")
    entry = matching[0]
    actual = hashes(archive)
    if archive.stat().st_size != entry["size"] or entry["checksum"] != f"md5:{actual['md5']}":
        raise ValueError("archive checksum/size mismatch; refusing extraction")
    inventory = []
    with zipfile.ZipFile(archive) as bundle:
        seen = set()
        for info in bundle.infolist():
            member = safe_member(info.filename)
            normalized = str(member)
            if normalized in seen or stat.S_ISLNK(info.external_attr >> 16):
                raise ValueError("duplicate name or symlink in archive")
            seen.add(normalized)
            if info.file_size > 2 * 1024**3 or info.flag_bits & 1:
                raise ValueError("oversized or encrypted archive member")
        if sum(i.file_size for i in bundle.infolist()) > 8 * 1024**3:
            raise ValueError("archive exceeds inspection size limit")
        bad = bundle.testzip()
        if bad is not None:
            raise ValueError(f"CRC mismatch: {bad}")
        output.mkdir(parents=True, exist_ok=False)
        text_root = output / "source"
        text_root.mkdir()
        for info in bundle.infolist():
            if info.is_dir():
                continue
            member = safe_member(info.filename)
            row = {"path": info.filename, "bytes": info.file_size,
                   "compressed_bytes": info.compress_size, "crc32": f"{info.CRC:08x}",
                   "text_extracted": False}
            if (member.suffix.lower() in TEXT_SUFFIXES or member.name in TEXT_NAMES) and info.file_size <= 8 * 1024**2:
                content = bundle.read(info)
                try:
                    content.decode("utf-8-sig")
                except UnicodeDecodeError:
                    row["text_skip_reason"] = "not UTF-8; inspect separately"
                else:
                    target = text_root.joinpath(*member.parts)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with target.open("xb") as stream:
                        stream.write(content)
                    row.update(text_extracted=True, sha256=hashlib.sha256(content).hexdigest())
            inventory.append(row)
    report = {"record_id": record["id"], "doi": record["doi"],
              "publication_date": record["metadata"]["publication_date"],
              "record_license": record["metadata"].get("license"),
              "archive": {"name": archive.name, "bytes": archive.stat().st_size, **actual},
              "checked_utc": datetime.now(timezone.utc).isoformat(),
              "record_sha256": hashes(record_path)["sha256"],
              "zip_crc_valid": True, "files": inventory,
              "execution": "none; no archive Python, shell, pickle, or model code executed"}
    (output / "inventory.json").write_text(json.dumps(report, indent=2) + "\n")
    (output / "record.json").write_bytes(record_path.read_bytes())
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, default=Path(".cache/aion-artifact/Aion.zip"))
    parser.add_argument("--record", type=Path, default=Path(".cache/aion-artifact/record-15870338.json"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.archive, args.record, args.output)
    print(json.dumps({k: v for k, v in result.items() if k != "files"}, indent=2))
    print(f"Indexed {len(result['files'])} files; extracted "
          f"{sum(f['text_extracted'] for f in result['files'])} text files for review.")


if __name__ == "__main__":
    main()
