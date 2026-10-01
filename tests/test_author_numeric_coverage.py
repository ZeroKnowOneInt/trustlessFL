import hashlib
import io
import zipfile

import pytest

from experiments.audit_author_numeric_coverage import analyze, audit


def fixture(root, *, extra=False):
    stream, files = io.BytesIO(), []
    with zipfile.ZipFile(stream, "w") as archive:
        for name in ("same", "changed", "missing"):
            raw = b"def DMC(x):\n return x / 10 ** (l_dp + l_ex)\n"
            archive.writestr(f"Aion/{name}.py", raw)
            files.append(dict(path=f"Aion/{name}.py", bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
            if name != "missing":
                (root / f"{name}.py").write_bytes(raw if name == "same" else b"raise RuntimeError('must not execute')\n")
        if extra:
            archive.writestr("Aion/extra.py", b"pass\n")
    return stream, dict(record_id=15870338, files=files)


def test_all_python_coverage_prefers_pinned_bytes_and_falls_back_for_changed_missing(tmp_path):
    stream, inventory = fixture(tmp_path)
    result = audit(tmp_path, inventory, stream)
    assert result["coverage"] == dict(local_pinned=1, remote_changed=1, remote_missing=1)
    assert result["python_members"] == 3
    assert all(row["precision_identifier_matches"] for row in result["files"].values())
    assert not (tmp_path / "missing.py").exists()
    assert (tmp_path / "changed.py").read_bytes().startswith(b"raise RuntimeError")


def test_corrupt_member_rejected(tmp_path):
    stream, inventory = fixture(tmp_path)
    inventory["files"][1]["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="differs from pinned"):
        audit(tmp_path, inventory, stream)


def test_incomplete_python_inventory_rejected(tmp_path):
    stream, inventory = fixture(tmp_path, extra=True)
    with pytest.raises(ValueError, match="coverage changed"):
        audit(tmp_path, inventory, stream)


def test_sum_mask_call_not_confused_with_sum_key_call_or_definition():
    result = analyze(b"def server_sum_hprg(self):\n pass\nx = shprg.client_sum_hprg(seeds, m, max_mask)\n")
    assert result["sum_hprg_calls"] == [dict(name="client_sum_hprg", line=3)]
    assert result["sum_hprg_definitions"] == [dict(name="server_sum_hprg", line=1)]
