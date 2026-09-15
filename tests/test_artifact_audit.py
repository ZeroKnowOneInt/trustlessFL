import hashlib
import json
import zipfile

import pytest

from experiments.audit_artifact import audit, safe_member


@pytest.mark.parametrize("name", ["../x", "/x", "A/../../x", "A\\x", "C:/x", ""])
def test_member_traversal_rejected(name):
    with pytest.raises(ValueError):
        safe_member(name)


def test_audit_checks_archive_and_never_extracts_binary(tmp_path):
    archive = tmp_path / "Aion.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("Aion/README.md", "fixture, not the real artifact")
        bundle.writestr("Aion/model.pkl", b"not a trusted pickle")
    record = tmp_path / "record.json"
    record.write_text(json.dumps({"id": 15870338, "doi": "test-fixture",
        "metadata": {"publication_date": "test"},
        "files": [{"key": "Aion.zip", "size": archive.stat().st_size,
                   "checksum": "md5:" + hashlib.md5(archive.read_bytes(), usedforsecurity=False).hexdigest()}]}))
    output = tmp_path / "inspection"
    report = audit(archive, record, output)
    assert report["zip_crc_valid"]
    assert (output / "source/Aion/README.md").is_file()
    assert not (output / "source/Aion/model.pkl").exists()
    with pytest.raises(FileExistsError):
        audit(archive, record, output)
    with archive.open("ab") as stream:
        stream.write(b"tampered")
    with pytest.raises(ValueError, match="checksum"):
        audit(archive, record, tmp_path / "other")
