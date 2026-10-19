"""Client count generalization preserves the four-party Rep4 contract."""
import json
from pathlib import Path
from types import SimpleNamespace
import pytest
from examples.seed_mpc_custom.create_local_data import prepare as prepare_data
from trustlessfl.crypto import ProtocolError, canonical, digest
from trustlessfl.seed_mpc_client_app import provision
from trustlessfl.seed_mpc_model import load_model_config
from trustlessfl.seed_mpc_policy import SeedMPCPolicy
from trustlessfl.seed_mpc_compile import recipe
from trustlessfl.seed_mpc_user import prepare as prepare_session


@pytest.mark.parametrize('clients', [4, 8, 16])
def test_model_client_count_inferred_and_explicitly_bound(tmp_path, clients):
    path = prepare_data(tmp_path/'data', clients=clients)
    spec, vector, training, shards, test, policy = load_model_config(path, 42, expected_clients=clients)
    assert len(shards) == clients and len(vector) == 53
    assert spec['schema']['dimension'] == 53
    with pytest.raises(ProtocolError): load_model_config(path, 42, expected_clients=clients+1)
    if clients != 4:
        # Historical experiment harness remains a deliberately fixed four-client benchmark.
        with pytest.raises(ProtocolError): load_model_config(path, 42, expected_clients=4)


@pytest.mark.parametrize('clients', [0, True, -1, 3])
def test_explicit_client_count_mismatch_rejected_before_backend(tmp_path, clients, monkeypatch):
    from trustlessfl import seed_mpc_user as user
    path = prepare_data(tmp_path/'data', clients=4)
    monkeypatch.setattr(user, 'pin_backend', lambda _: pytest.fail('backend touched before roster validation'))
    with pytest.raises(ProtocolError): prepare_session(tmp_path/'session', tmp_path/'backend', path, clients=clients)
    assert not (tmp_path/'session').exists()


@pytest.mark.parametrize('fault', ['empty-roster', 'policy-roster', 'minimum', 'capacity'])
def test_invalid_roster_or_width_rejected_before_session_creation(tmp_path, fault, monkeypatch):
    from trustlessfl import seed_mpc_user as user
    path = prepare_data(tmp_path/'data', clients=8)
    body = json.loads(path.read_text())
    if fault == 'empty-roster': body['train_data'] = []
    if fault == 'policy-roster': body['policy']['max_clients'] = 4
    if fault == 'minimum': body['policy']['minimum_accepted'] = 9
    if fault == 'capacity': body['policy']['squared_threshold'] = 2**63
    path.write_text(json.dumps(body))
    monkeypatch.setattr(user, 'pin_backend', lambda _: pytest.fail('unsafe policy reached backend'))
    with pytest.raises(ProtocolError): prepare_session(tmp_path/'session', tmp_path/'backend', path)
    assert not (tmp_path/'session').exists()


def test_client_count_changes_public_circuit_cache_and_sum_width():
    policies = [SeedMPCPolicy(53, n, 20000, 2500000000) for n in (4, 8, 16)]
    assert [p.widths()['count'] for p in policies] == [5, 6, 7]
    assert [p.widths()['sum'] for p in policies] == [19, 20, 21]
    for p in policies: p.validate_ring(64)
    recipes = [recipe({'runtime_client_port': True, 'client_port': 24000, 'clients': p.max_clients,
                       'parties': 4, 'widths': p.widths()}, {}, 'fixed') for p in policies]
    assert len({digest(r) for r in recipes}) == 3
    assert all(r['config']['parties'] == 4 for r in recipes)


@pytest.mark.parametrize('slot,count', [(4,4), (-1,8), (True,8), (8,8), (0,0), (0,True)])
def test_client_provisioning_refuses_slot_outside_declared_roster(tmp_path, slot, count):
    with pytest.raises(ProtocolError): provision(tmp_path/'client', {'client_count': count}, slot)
    assert not (tmp_path/'client').exists()
