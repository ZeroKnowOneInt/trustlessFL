import importlib.util
from pathlib import Path

import pytest

from trustlessfl.aion_original_hprf import OriginalAionHPRF, _PrimitiveUnpickler
from trustlessfl.crypto import ProtocolError


SOURCE = Path(__file__).resolve().parents[2] / "Aion/agent/Aion/HPRF"


@pytest.fixture(scope="module")
def implementations():
    if not (SOURCE / "hprf.py").is_file():
        pytest.skip("author artifact is required for differential tests")
    spec = importlib.util.spec_from_file_location("author_hprf", SOURCE / "hprf.py")
    original = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(original)
    port = OriginalAionHPRF.from_directory(SOURCE)
    reference = original.HPRF(port.n, port.m, port.p, port.q, str(SOURCE / "matrix"))
    return reference, port


@pytest.mark.parametrize("key", [1, 100000, 2**260 + 17])
@pytest.mark.parametrize("round_id", [1, 4, 60])
def test_author_output_exactly_matches(implementations, key, round_id):
    reference, port = implementations
    for length in (0, 1, port.m - 1, port.m, port.m + 1, port.m * 3 + 7):
        assert port.hprf(key, round_id, length) == reference.hprf(key, round_id, length)


def test_preserves_original_rounding_boundary():
    port = OriginalAionHPRF(1, 2, 2, 11, [[10, 0]])
    assert port.hprf(1, 1, 2) == [2, 0]


@pytest.mark.parametrize("length", [10000, 61706])
def test_full_experiment_vector_matches(implementations, length):
    reference, port = implementations
    assert port.hprf(100000, 4, length) == reference.hprf(100000, 4, length)


def test_no_pickle_global_resolution():
    import io
    with pytest.raises(ProtocolError, match="primitive"):
        _PrimitiveUnpickler(io.BytesIO(b"cos\nsystem\n.")).load()


def test_invalid_matrix_rejected():
    with pytest.raises(ProtocolError):
        OriginalAionHPRF(1, 2, 10, 11, [[0, 11]])


def test_public_setup_roundtrip(implementations):
    _, port = implementations
    clone = OriginalAionHPRF.from_public_setup(port.public_setup())
    assert clone.hprf(10, 4, 10000) == port.hprf(10, 4, 10000)


def test_fixed_point_aggregate_uses_author_modulus(implementations):
    import numpy as np
    from trustlessfl.numeric import FixedPoint
    _, port = implementations
    codec = FixedPoint(max_clients=4, mask_backend="aion-original",
                       original_hprf_setup=port.public_setup())
    assert codec.output_modulus == port.p
    updates = [np.asarray([0.1234, -0.5678, 1.0]),
               np.asarray([-0.2345, 0.6789, -2.0]),
               np.asarray([0.3456, -0.7890, 3.0]),
               np.asarray([-0.4567, 0.8901, -4.0])]
    keys = [1, 25, 100000, 75321]
    for round_id in (1, 4, 10):
        masked = [codec.mask(u, k, "author-port", round_id) for u, k in zip(updates, keys)]
        total = [sum(v) % port.p for v in zip(*masked)]
        assert codec.unmask(total, sum(keys), "author-port", round_id, 4) == [
            sum(v) for v in zip(*(codec.encode(u) for u in updates))]


@pytest.mark.parametrize("hotstuff", [False, True])
def test_flower_process_grid_author_hprf_four_rounds(implementations, tmp_path, hotstuff):
    import json
    import numpy as np
    from flwr.app import Context, RecordDict
    from trustlessfl.demo import provision
    from trustlessfl.local_grid import ProcessGrid
    from trustlessfl.protocol import Parameters
    from trustlessfl.server_app import app
    from trustlessfl.task import local_delta
    _, port = implementations
    p = Parameters("author-port-flower", ("c0", "c1", "c2", "c3"),
                   ("a0", "a1", "a2", "a3"), mask_backend="aion-original",
                   original_hprf_setup=port.public_setup(), hotstuff=hotstuff)
    # JSON restart must retain immutable setup and the same configuration digest.
    from dataclasses import asdict
    clone = Parameters.from_dict(json.loads(json.dumps(asdict(p))))
    assert clone.config_digest == p.config_digest
    manifest, nodes = provision(tmp_path / "identities", p)
    ctx = Context(run_id=1, node_id=0, node_config={}, state=RecordDict(), run_config={
        "aion-manifest": str(manifest), "research-mode": True,
        "num-server-rounds": 4, "timeout": 45.0})
    with ProcessGrid(nodes) as grid:
        app(grid, ctx)
    history = json.loads(ctx.state["aion-result"]["history"])
    assert len(history) == 5
    model = np.asarray(history[0]["body"]["model"])
    for round_id in range(1, 5):
        integers = [p.codec.encode(local_delta(model, i, p.learning_rate)) for i in range(4)]
        model = model + np.sum(integers, axis=0) / (4 * p.codec.scale)
        assert np.array_equal(model, np.asarray(history[round_id]["body"]["model"]))


def test_original_setup_changes_config_and_supports_client_mgf(implementations):
    from trustlessfl.protocol import Parameters
    from dataclasses import replace
    _, port = implementations
    p = Parameters("author-port", ("c0", "c1"), ("a0", "a1", "a2", "a3"),
                   mask_backend="aion-original", original_hprf_setup=port.public_setup())
    modified = list(port.public_setup())
    modified[4] += 1
    assert replace(p, original_hprf_setup=tuple(modified)).config_digest != p.config_digest
    masked = replace(p, mgf_beta="0.1", mgf_initial_alpha="0.1",
                     mgf_initial_bound="1", mgf_initial_term="1")
    assert masked.mgf_codec.hprf_modulus == port.p


def test_original_hprf_oracle_aggregate_and_recipient_binding(implementations):
    import copy
    import numpy as np
    from trustlessfl.crypto import Identity
    from trustlessfl.protocol import Parameters, Party, certificate
    _, port = implementations
    p = Parameters("original-oracle-aggregate", ("c0", "c1"),
                   ("a0", "a1", "a2", "a3"), dimension=61706,
                   oracle_mgf=True, mask_backend="aion-original",
                   original_hprf_setup=port.public_setup())
    identities = {name: Identity.generate(name) for name in p.clients + p.aggregators}
    registry = {name: identity.public() for name, identity in identities.items()}
    def trainer(weights, partition, rate, round_id):
        return np.full(p.dimension, 0.001 * (partition + 1))
    parties = {name: Party(identity, p, registry, trainer=trainer)
               for name, identity in identities.items()}
    enrollments = [parties[c].enroll({}) for c in p.clients]
    assert all("secret" not in parties[c].state for c in p.clients)
    votes = [parties[a].initialize({"enrollments": enrollments}) for a in p.aggregators]
    model = certificate(votes[0]["body"], votes, p, registry)
    updates = [parties[c].train({"model": model}) for c in p.clients]
    bad = copy.deepcopy(updates[0]["body"])
    bad["oracle_key"]["packets"]["a0"] = bad["oracle_key"]["packets"]["a1"]
    with pytest.raises(ProtocolError):
        parties["a0"].prepare({"model": model, "updates": [identities["c0"].sign(bad), updates[1]]})
    votes = [parties[a].prepare({"model": model, "updates": updates}) for a in p.aggregators]
    roster = certificate(votes[0]["body"], votes, p, registry)
    shares = [parties[a].share({"roster": roster}) for a in p.aggregators]
    results = [parties[a].finalize({"roster": roster, "shares": shares}) for a in p.aggregators]
    for result in results:
        np.testing.assert_array_equal(result["body"]["model"], np.full(p.dimension, 0.0015))
