import pickle

import numpy as np
import pytest

from experiments.probe_aion_checkpoint import CheckpointReader, checkpoint_arrays, rebuild_tensor


def test_checkpoint_hash_is_required():
    with pytest.raises(ValueError, match="unreviewed"):
        checkpoint_arrays(b"not the pinned model")


def test_unknown_pickle_global_is_rejected():
    reader = CheckpointReader(b"cos\nsystem\n.", None, "")
    with pytest.raises(pickle.UnpicklingError, match="global rejected"):
        reader.load()


def test_only_bounded_contiguous_tensor_metadata_is_accepted():
    storage = np.arange(6, dtype="<f4")
    np.testing.assert_array_equal(rebuild_tensor(storage, 0, (2, 3), (3, 1), False, {}), storage.reshape(2, 3))
    with pytest.raises(ValueError):
        rebuild_tensor(storage, 2, (2, 3), (3, 1), False, {})
    with pytest.raises(ValueError):
        rebuild_tensor(storage, 0, (2, 3), (1, 2), False, {})
    with pytest.raises(ValueError):
        rebuild_tensor(storage, 0, (-2, 3), (3, 1), False, {})


def test_storage_reference_is_allowlisted():
    reader = CheckpointReader(b"", None, "")
    with pytest.raises(pickle.UnpicklingError):
        reader.persistent_load(("storage", "float32-storage", "../escape", "cpu", 6))
