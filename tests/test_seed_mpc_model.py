"""Generic adapter contracts and deterministic user-model training."""
from copy import deepcopy
import json
from pathlib import Path
import numpy as np
import pytest
import torch
from trustlessfl.crypto import ProtocolError, digest
from trustlessfl.seed_mpc_model import (schema, flatten, make, load_model_config,
    train_custom, evaluate_custom, source_sha, model_contract, validate_spec)
from experiments.prepare_seed_mpc_custom_example import prepare


def test_custom_train_roundtrip_determinism_and_model_independent_dimensions(tmp_path):
    cfg = prepare(tmp_path/'data')
    spec, vector, training, shards, test, _ = load_model_config(cfg, 42)
    assert vector.shape == (53,) and vector.dtype == np.float64
    _, model, expected = make(spec, vector)
    assert np.array_equal(flatten(model, expected), vector)
    with np.load(shards[0]) as data:
        args = dict(slot=0, round_id=1, training=training)
        a, ma = train_custom(spec, vector, data['x'], data['y'], **args)
        b, mb = train_custom(spec, vector, data['x'], data['y'], **args)
        assert np.array_equal(a, b) and ma == mb and np.any(a)
        assert ma['optimizer_steps'] == 4
    with np.load(test) as data:
        assert np.isfinite(evaluate_custom(spec, vector+a, data['x'], data['y'])['loss'])
    assert 'plugin' not in model_contract(spec)


@pytest.mark.parametrize('fault', ['shape', 'order', 'dtype', 'buffer', 'hash', 'source', 'adapter'])
def test_adapter_refuses_contract_mismatch_before_update(fault, tmp_path):
    cfg = prepare(tmp_path/'data')
    spec, vector, *_ = load_model_config(cfg, 42)
    if fault == 'shape': spec['schema']['parameters'][0]['shape'].reverse()
    if fault == 'order': spec['schema']['parameters'].reverse()
    if fault == 'dtype': spec['schema']['parameters'][0]['dtype'] = 'torch.float64'
    if fault == 'buffer': spec['schema']['buffers'].append({'name':'unexpected'})
    if fault == 'hash': spec['schema_hash'] = '00'*32
    if fault == 'source': Path(spec['plugin']).write_text('raise RuntimeError("must not execute")')
    if fault == 'adapter': spec['adapter_sha256'] = '00'*32
    if fault in ('shape', 'order', 'dtype', 'buffer'): spec['schema_hash'] = digest(spec['schema'])
    with pytest.raises(ProtocolError): make(spec, vector)


def test_fixed_buffers_are_preserved_but_mutable_buffers_and_ties_rejected():
    model = torch.nn.Linear(3, 2)
    model.register_buffer('fixed', torch.tensor([3], dtype=torch.int64))
    expected = schema(model)
    flatten(model, expected)
    model.fixed.add_(1)
    with pytest.raises(ProtocolError): flatten(model, expected)
    tied = torch.nn.Module()
    tied.a = torch.nn.Parameter(torch.ones(2)); tied.b = tied.a
    with pytest.raises(ProtocolError): schema(tied)
    aliased = torch.nn.Module()
    aliased.a = torch.nn.Parameter(torch.ones(2)); aliased.b = torch.nn.Parameter(aliased.a.detach())
    with pytest.raises(ProtocolError): schema(aliased)


def test_batchnorm_training_rejected_instead_of_silently_discarding_buffers(tmp_path):
    cfg = prepare(tmp_path/'data')
    (cfg.parent/'classifier.py').write_text('import torch\ndef make_model(**kwargs):\n return torch.nn.Sequential(torch.nn.BatchNorm1d(6),torch.nn.Linear(6,3))\n')
    spec, vector, training, shards, *_ = load_model_config(cfg, 42)
    with np.load(shards[0]) as data:
        with pytest.raises(ProtocolError, match='buffers changed'):
            train_custom(spec, vector, data['x'], data['y'], slot=0, round_id=1, training=training)


def test_large_model_schema_has_no_lenet_dimension_ceiling(tmp_path):
    cfg = prepare(tmp_path/'data', hidden=7000)
    spec, vector, *_ = load_model_config(cfg, 42)
    assert len(vector) == 70003 > 61706
    assert spec['schema']['dimension'] == len(vector)


@pytest.mark.parametrize('field,value', [('epochs', True), ('batch_size', 0), ('learning_rate', 0), ('momentum', 'bad')])
def test_invalid_training_configuration_fails_at_preparation(tmp_path, field, value):
    cfg = prepare(tmp_path/'data'); body = json.loads(cfg.read_text())
    body['training'][field] = value; cfg.write_text(json.dumps(body))
    with pytest.raises(ProtocolError): load_model_config(cfg, 42)


@pytest.mark.parametrize('fault', ['cap-half-modulus', 'ring-overflow', 'dimension', 'clients', 'word-width', 'missing-policy', 'unknown-field'])
def test_static_policy_rejected_before_native_setup(tmp_path, fault):
    from experiments.run_seed_mpc_flower import stage
    cfg = prepare(tmp_path/'data'); body = json.loads(cfg.read_text())
    if fault == 'cap-half-modulus': body['policy']['coordinate_cap'] = 32768
    if fault == 'ring-overflow': body['policy']['squared_threshold'] = 2**63
    if fault == 'dimension': body['policy']['dimension'] = 54
    if fault == 'clients': body['policy']['max_clients'] = 5
    if fault == 'word-width': body['policy']['word_bits'] = 32
    if fault == 'missing-policy': del body['policy']
    if fault == 'unknown-field': body['policy']['dynamic_threshold'] = True
    cfg.write_text(json.dumps(body)); output = tmp_path/'run'
    with pytest.raises(ProtocolError):
        stage(output, tmp_path/'missing-backend', mode='custom-model', model_config=cfg, rounds=2)
    assert not output.exists()



def test_small_cnn_image_adapter_preserves_schema_vector_and_deterministic_training():
    from trustlessfl.seed_mpc_model import inputs
    source=Path(__file__).resolve().parents[1]/'examples/seed_mpc_custom/fmnist_small_cnn.py'
    spec={'plugin':str(source),'plugin_sha256':source_sha(source),'kwargs':{},'seed':42}
    module,model,expected=make(spec)
    assert expected['dimension']==666 and expected['buffers']==[]
    assert [p['shape'] for p in expected['parameters']]==[[4,1,3,3],[4],[8,4,3,3],[8],[10,32],[10]]
    vector=flatten(model,expected)
    spec.update(schema=expected,schema_hash=digest(expected))
    _,restored,_=make(spec,vector)
    assert np.array_equal(flatten(restored,expected),vector)
    rng=np.random.default_rng(42);x=rng.integers(0,256,size=(65,28,28),dtype=np.uint8)
    y=(np.arange(65)%10).astype(np.uint8)
    assert tuple(inputs(module,x).shape)==(65,1,28,28)
    training={'epochs':1,'batch_size':32,'learning_rate':.05,'momentum':0.,'weight_decay':0.}
    a,ma=train_custom(spec,vector,x,y,slot=0,round_id=1,training=training)
    b,mb=train_custom(spec,vector,x,y,slot=0,round_id=1,training=training)
    assert np.array_equal(a,b) and ma==mb and ma['optimizer_steps']==3 and np.any(a)
    assert np.isfinite(evaluate_custom(spec,vector+a,x,y)['loss'])
