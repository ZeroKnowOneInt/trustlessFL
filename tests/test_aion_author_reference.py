import json
import pickle
from pathlib import Path

import pytest

from trustlessfl.aion_author_reference import (REFERENCE_FILES, load_author_reference,
    stage_author_reference, verify_author_reference)
from trustlessfl.fmnist_artifact_mgf import SHPRG_P, SHPRG_Q
from trustlessfl.crypto import ProtocolError


@pytest.fixture
def reference(tmp_path):
    root = tmp_path / "original"
    for name in REFERENCE_FILES:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(pickle.dumps((1, 8, SHPRG_P, SHPRG_Q))
                         if name.endswith("initialization_values") else b"# author reference\n")
    return root


def test_snapshot_is_portable_and_does_not_modify_source(reference, tmp_path):
    before = {name: (reference / name).read_bytes() for name in REFERENCE_FILES}
    files, record = load_author_reference(reference)
    output = tmp_path / "output"
    output.mkdir()
    stage_author_reference(files, output)
    verify_author_reference(output, json.loads(json.dumps(record)))
    assert before == {name: (reference / name).read_bytes() for name in REFERENCE_FILES}
    assert set(record["sha256"]) == set(REFERENCE_FILES)


@pytest.mark.parametrize("name", REFERENCE_FILES)
def test_snapshot_changes_are_rejected(reference, tmp_path, name):
    files, record = load_author_reference(reference)
    output = tmp_path / "output"
    output.mkdir()
    stage_author_reference(files, output)
    path = output / "author-reference" / name
    path.write_bytes(pickle.dumps((1, 8, SHPRG_P + 1, SHPRG_Q))
                     if name.endswith("initialization_values") else path.read_bytes() + b"changed")
    with pytest.raises(ValueError, match="initialization|reference changed"):
        verify_author_reference(output, record)


def test_unknown_inventory_and_pickle_globals_are_rejected(reference, tmp_path):
    _, record = load_author_reference(reference)
    record["sha256"]["../outside"] = "0" * 64
    with pytest.raises(ValueError, match="inventory"):
        verify_author_reference(tmp_path, record)
    (reference / "shprg/initialization_values").write_bytes(b"cos\nsystem\n.")
    with pytest.raises(ProtocolError, match="primitive"):
        load_author_reference(reference)


def test_actual_author_initialization_matches_port():
    root = Path(__file__).resolve().parents[2] / "Aion/input_validation/FL_Backdoor_CV"
    if not root.is_dir():
        pytest.skip("author artifact required")
    _, record = load_author_reference(root)
    assert record["initialization"] == [1, 8, SHPRG_P, SHPRG_Q]
