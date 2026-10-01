"""Offline source identity audit tests; network is never needed by pytest."""

import hashlib
import io
import zipfile

import pytest

from experiments.audit_source_identity import METHODS, RangeZip, audit, method_inventory


def test_ast_comparison_ignores_formatting_but_detects_calculation_change():
    first = b"class C:\n def m(self, x):\n  return x + 1\n"
    formatted = b"# comment\nclass C:\n    def m(self,x):\n        return x+1\n"
    changed = formatted.replace(b"x+1", b"x+2")
    assert method_inventory(first, "C", ["m"]) == method_inventory(formatted, "C", ["m"])
    assert method_inventory(first, "C", ["m"]) != method_inventory(changed, "C", ["m"])


def test_role_constructor_change_is_not_turned_into_full_file_identity(tmp_path):
    stream, entries = io.BytesIO(), []
    with zipfile.ZipFile(stream, "w") as archive:
        for name, (role, methods) in METHODS.items():
            raw = (f"class {role}:\n def __init__(self, prime):\n  self.prime = prime\n" +
                   "".join(f" def {m}(self):\n  return 1\n" for m in methods)).encode()
            archive.writestr("Aion/" + name, raw)
            entries.append(dict(path="Aion/" + name, sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw)))
            local = tmp_path / name
            local.parent.mkdir(parents=True, exist_ok=True)
            local.write_bytes(raw.replace(b"self.prime = prime", b"self.prime = 7"))
    result = audit(tmp_path, dict(files=entries, record_id=15870338), stream)
    assert all(not r["full_file_identical"] and r["ported_method_ast_identical"]
               for r in result["comparison"].values())


@pytest.mark.parametrize("status,header,raw", [(200, "bytes 0-2/3", b"abc"),
    (206, "bytes 0-2/4", b"abc"), (206, "bytes 0-2/3", b"ab")])
def test_wrong_or_incomplete_http_range_rejected(status, header, raw):
    class Reply(io.BytesIO):
        headers = {"Content-Range": header}
    reply = Reply(raw)
    reply.status = status
    reader = RangeZip("https://example.invalid/file", 3, opener=lambda *a, **k: reply)
    with pytest.raises(ValueError):
        reader.read(3)


def test_seek_and_cached_ranges_do_not_duplicate_http_reads():
    calls = []
    class Reply(io.BytesIO):
        status = 206
        headers = {"Content-Range": "bytes 0-2/3"}
    def opener(request, **kwargs):
        calls.append(request)
        return Reply(b"abc")
    reader = RangeZip("https://example.invalid/file", 3, opener=opener)
    assert reader.read() == b"abc"
    assert reader.seek(-3, 2) == 0
    assert reader.read() == b"abc"
    assert reader.read() == b""
    assert len(calls) == 1
