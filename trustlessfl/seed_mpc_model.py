"""Pinned PyTorch classification adapter. Parameters are private updates; buffers are fixed public state."""
import hashlib
import json
import math
from pathlib import Path
from types import ModuleType

import numpy as np

from .crypto import ProtocolError, digest


def source_sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def validate_spec(spec):
    if ('adapter_sha256' in spec and source_sha(__file__) != spec['adapter_sha256']):
        raise ProtocolError('model adapter implementation changed')
    if source_sha(spec['plugin']) != spec['plugin_sha256']:
        raise ProtocolError('model plugin source changed')
    if 'schema' in spec and digest(spec['schema']) != spec['schema_hash']:
        raise ProtocolError('model schema hash differs')


def plugin(spec):
    validate_spec(spec)
    path = Path(spec['plugin'])
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != spec['plugin_sha256']:
        raise ProtocolError('model plugin source changed')
    # User-authorized local code, not a sandbox. Execute the checked bytes,
    # avoiding stale import/pyc caches and global module-name collisions.
    module = ModuleType('trustlessfl_user_model_' + spec['plugin_sha256'])
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    if not callable(getattr(module, 'make_model', None)):
        raise ProtocolError('model plugin must define make_model(**kwargs)')
    return module


def schema(model):
    import torch
    parameters = []
    # Shared/tied parameters need an explicit alias contract; reject for now.
    seen = set(); storage_seen = set()
    for name, value in model.named_parameters(remove_duplicate=False):
        storage = value.untyped_storage().data_ptr()
        if id(value) in seen or value.numel() and storage in storage_seen:
            raise ProtocolError('tied parameters are not supported by this adapter')
        seen.add(id(value))
        if value.numel(): storage_seen.add(storage)
        if (value.dtype not in (torch.float32, torch.float64) or value.layout != torch.strided
                or value.device.type != 'cpu' or not torch.isfinite(value).all()):
            raise ProtocolError('model parameters must be finite dense CPU float32/float64 tensors')
        parameters.append({'name': name, 'shape': list(value.shape), 'dtype': str(value.dtype),
                           'requires_grad': value.requires_grad, 'size': value.numel()})
    dimension = sum(item['size'] for item in parameters)
    if dimension < 1 or not any(item['requires_grad'] for item in parameters):
        raise ProtocolError('model needs nonempty trainable parameters')
    buffers = []
    for name, value in model.named_buffers(remove_duplicate=False):
        if value.layout != torch.strided or value.device.type != 'cpu':
            raise ProtocolError('model buffers must be dense CPU tensors')
        if value.is_floating_point() and not torch.isfinite(value).all():
            raise ProtocolError('nonfinite model buffer')
        raw = value.detach().contiguous().reshape(-1).view(torch.uint8).numpy().tobytes()
        buffers.append({'name': name, 'shape': list(value.shape), 'dtype': str(value.dtype),
                        'sha256': hashlib.sha256(raw).hexdigest()})
    return {'version': 'torch-parameters-fixed-buffers-v1', 'parameters': parameters,
            'buffers': buffers, 'dimension': dimension}


def flatten(model, expected):
    if schema(model) != expected:
        raise ProtocolError('model schema or fixed buffers changed')
    vector = np.concatenate([p.detach().numpy().reshape(-1).astype(np.float64)
                             for p in model.parameters()])
    if not np.isfinite(vector).all():
        raise ProtocolError('nonfinite model vector')
    return vector


def make(spec, vector=None):
    import torch
    torch.set_num_threads(1)
    torch.use_deterministic_algorithms(True)
    module = plugin(spec)
    with torch.random.fork_rng(devices=[]):
        torch.manual_seed(spec['seed'])
        model = module.make_model(**spec['kwargs'])
    if not isinstance(model, torch.nn.Module):
        raise ProtocolError('factory must return torch.nn.Module')
    actual = schema(model)
    if 'schema' in spec and (actual != spec['schema'] or digest(actual) != spec['schema_hash']):
        raise ProtocolError('model factory/schema differs from session contract')
    if vector is not None:
        vector = np.asarray(vector)
        if (vector.dtype != np.float64 or vector.shape != (actual['dimension'],)
                or not np.isfinite(vector).all()):
            raise ProtocolError('invalid custom model vector')
        offset = 0
        with torch.no_grad():
            for p in model.parameters():
                size = p.numel()
                p.copy_(torch.from_numpy(vector[offset:offset+size].copy()).reshape(p.shape))
                offset += size
    return module, model, actual


def validate_data(x, y):
    if (not isinstance(x, np.ndarray) or not isinstance(y, np.ndarray)
            or x.dtype.kind not in 'fiu' or y.dtype.kind not in 'iu'
            or x.ndim < 2 or y.ndim != 1 or len(x) != len(y) or len(y) < 1
            or not np.isfinite(x).all() or np.any(y < 0)):
        raise ProtocolError('classification data requires finite numeric x and nonnegative integer y')


def inputs(module, x):
    import torch
    value = (module.prepare_inputs(x.copy()) if callable(getattr(module, 'prepare_inputs', None))
             else torch.from_numpy(x.copy()).float())
    if (not isinstance(value, torch.Tensor) or value.device.type != 'cpu'
            or len(value) != len(x) or not torch.isfinite(value).all()):
        raise ProtocolError('prepare_inputs must return finite CPU tensor preserving rows')
    return value


def logits_for(model, features, labels):
    import torch
    logits = model(features)
    if (not isinstance(logits, torch.Tensor) or logits.ndim != 2 or logits.shape[0] != len(labels)
            or logits.shape[1] < 2 or not torch.isfinite(logits).all()
            or int(labels.max()) >= logits.shape[1]):
        raise ProtocolError('classification model must return finite [batch, classes] logits')
    return logits


def train_custom(spec, vector, x, y, *, slot, round_id, training):
    import torch
    validate_data(x, y)
    module, model, expected = make(spec, vector)
    stream_seed = int(np.random.SeedSequence([spec['seed'], slot, round_id]).generate_state(1)[0])
    with torch.random.fork_rng(devices=[]):
        torch.manual_seed(stream_seed)
        features = inputs(module, x)
        labels = torch.from_numpy(y.astype(np.int64))
        generator = torch.Generator().manual_seed(stream_seed)
        optimizer = torch.optim.SGD([p for p in model.parameters() if p.requires_grad],
            lr=training['learning_rate'], momentum=training['momentum'], weight_decay=training['weight_decay'])
        model.train()
        steps = 0
        for _ in range(training['epochs']):
            for indices in torch.randperm(len(y), generator=generator).split(training['batch_size']):
                optimizer.zero_grad(set_to_none=True)
                torch.nn.functional.cross_entropy(logits_for(model, features[indices], labels[indices]), labels[indices]).backward()
                optimizer.step()
                steps += 1
        after = flatten(model, expected)  # Reject mutable buffers (e.g., training BatchNorm).
    return after-vector, {'rows': len(y), 'optimizer_steps': steps, 'device': 'cpu',
        'epochs': training['epochs'], 'batch_size': training['batch_size'], 'parameter_count': expected['dimension']}


def evaluate_custom(spec, vector, x, y, batch_size=256):
    import torch
    validate_data(x, y)
    module, model, expected = make(spec, vector)
    model.eval()
    correct, loss = 0, 0.0
    with torch.no_grad():
        for start in range(0, len(y), batch_size):
            labels = torch.from_numpy(y[start:start+batch_size].astype(np.int64))
            logits = logits_for(model, inputs(module, x[start:start+batch_size]), labels)
            correct += int((logits.argmax(1) == labels).sum())
            loss += float(torch.nn.functional.cross_entropy(logits, labels, reduction='sum'))
    flatten(model, expected)
    accuracy = correct/len(y)
    return {'accuracy': accuracy, 'test_error_rate': 1-accuracy, 'loss': loss/len(y)}


def load_model_config(path, seed, *, expected_clients=None):
    path = Path(path).resolve()
    cfg = json.loads(path.read_text())
    allowed = {'plugin', 'kwargs', 'train_data', 'test_data', 'training', 'policy'}
    if not isinstance(cfg, dict) or set(cfg)-allowed or not {'plugin', 'train_data', 'test_data'} <= set(cfg):
        raise ProtocolError('invalid model configuration fields')
    resolve = lambda value: (path.parent/Path(value)).resolve()
    source = resolve(cfg['plugin'])
    if source.suffix != '.py' or not source.is_file() or not isinstance(cfg.get('kwargs', {}), dict):
        raise ProtocolError('model requires self-contained .py plugin and object kwargs')
    if (not isinstance(cfg['train_data'], list) or not cfg['train_data']
            or expected_clients is not None and (type(expected_clients) is not int or expected_clients < 1
                                                 or len(cfg['train_data']) != expected_clients)):
        raise ProtocolError('client NPZ shard count does not match the requested clients')
    data = [resolve(value) for value in cfg['train_data']]
    test = resolve(cfg['test_data'])
    for shard in [*data, test]:
        with np.load(shard, allow_pickle=False) as saved:
            if set(saved.files) != {'x', 'y'}:
                raise ProtocolError('NPZ data must contain exactly x and y')
            validate_data(saved['x'], saved['y'])
    training = {'epochs': 1, 'batch_size': 64, 'learning_rate': .05, 'momentum': 0.0, 'weight_decay': 0.0}
    supplied = cfg.get('training', {})
    if not isinstance(supplied, dict) or set(supplied)-set(training):
        raise ProtocolError('unsupported custom training options')
    training.update(supplied)
    if any(type(training[k]) is not int or training[k] < 1 for k in ('epochs', 'batch_size')):
        raise ProtocolError('invalid epochs/batch size')
    for key in ('learning_rate', 'momentum', 'weight_decay'):
        v = training[key]
        if type(v) not in (int, float) or not math.isfinite(v) or v < 0 or key == 'learning_rate' and v == 0:
            raise ProtocolError('invalid SGD option')
    spec = {'plugin': str(source), 'plugin_sha256': source_sha(source), 'kwargs': cfg.get('kwargs', {}), 'seed': seed, 'adapter_sha256': source_sha(__file__)}
    _, model, expected = make(spec)
    spec.update(schema=expected, schema_hash=digest(expected))
    return spec, flatten(model, expected), training, data, test, cfg.get('policy')


def model_contract(spec):
    # Paths are deployment locations; checked source bytes and schema define semantics.
    return {k: v for k, v in spec.items() if k != 'plugin'}
