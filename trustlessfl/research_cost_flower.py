"""Explicit trusted plaintext benchmark, never a private-protocol fallback.

This separate local research app reveals updates to the reference server. The
production seed-MPC app and user/deployment entry points do not invoke it.
"""
import json
from pathlib import Path
import time

import numpy as np
from flwr.app import ArrayRecord, ConfigRecord, Context, Message, RecordDict
from flwr.clientapp import ClientApp
from flwr.serverapp import Grid, ServerApp

from .crypto import ProtocolError, canonical, digest
from .seed_mpc_client_app import TrainingCalls, write_private
from .seed_mpc_meter import ApplicationMeter, MeteredGrid
from .seed_mpc_poisoning_fixture import attack
from .seed_mpc_policy import SeedMPCPolicy
from .seed_mpc_training import train_lenet, quantize, evaluate_lenet

client_app = ClientApp()
server_app = ServerApp()


def configuration(context):
    cfg = json.loads(Path(context.run_config['deployment-file']).read_text())
    if cfg.get('trusted-plaintext-cost-benchmark') is not True:
        raise ProtocolError('plaintext research app requires explicit benchmark configuration')
    if cfg['variant'] not in ('plain-mean', 'plain-bound'):
        raise ProtocolError('unknown plaintext reference variant')
    return cfg, SeedMPCPolicy(**cfg['policy'])


def slot(context):
    value = int(context.node_config['partition-id'])
    if int(context.node_config['num-partitions']) != 4 or value not in range(4):
        raise ProtocolError('cost reference requires four clients')
    return value


def aggregate_q(updates, variant, policy):
    if variant not in ('plain-mean', 'plain-bound') or len(updates) != policy.max_clients:
        raise ProtocolError('invalid reference aggregation')
    if any(q.shape != (policy.dimension,) or q.dtype != np.int16 for q in updates):
        raise ProtocolError('invalid signed16 reference input')
    if policy.dimension*(policy.modulus//2)**2 >= 2**63:
        raise ProtocolError('reference norm width insufficient')
    # Widen BEFORE abs/square: abs(int16(-32768)) and int16 squares overflow.
    values = np.stack(updates).astype(np.int64)
    keep = np.ones(len(updates), dtype=bool)
    if variant == 'plain-bound':
        keep = np.all(np.abs(values) <= policy.coordinate_cap, axis=1)
        keep &= np.sum(values*values, axis=1, dtype=np.int64) <= policy.squared_threshold
    count = int(keep.sum())
    if count < policy.minimum_accepted:
        return {'status': 'abort'}, keep.tolist()
    total = np.sum(values[keep], axis=0, dtype=np.int64)
    return {'status': 'ok', 'count': count, 'sum': total.tolist()}, keep.tolist()


@client_app.query('identity')
def identity(message: Message, context: Context):
    configuration(context)
    return Message(RecordDict({'meta': ConfigRecord({'slot': slot(context)})}), reply_to=message)


@client_app.train()
def train(message: Message, context: Context):
    cfg, policy = configuration(context)
    index = slot(context)
    directory = Path(cfg['client_root'])/f'C{index}'
    model = message.content['model'].to_numpy_ndarrays()[0]
    round_id = int(message.content['config']['round'])
    if model.dtype != np.float64 or model.shape != (policy.dimension,):
        raise ProtocolError('invalid reference model')
    if 'cost-state' not in context.state:
        context.state['cost-state'] = ConfigRecord({'round': 0, 'last-trained': 0,
                                                   'model-hash': digest(cfg['initial_model'])})
    state = context.state['cost-state']
    if round_id != state['round']+1 or digest(model.tolist()) != state['model-hash']:
        raise ProtocolError('reference model chain differs')
    context_hash = digest({'seed': cfg['seed'], 'slot': index, 'round': round_id,
                           'model': state['model-hash'], 'case': cfg['case']})
    calls = TrainingCalls(directory/'calls.sqlite')
    try:
        cached = calls.reserve(round_id, context_hash)
        if cached is None:
            tick = time.monotonic()
            with np.load(directory/'train.npz', allow_pickle=False) as data:
                delta, meta = train_lenet(model, data['x'], data['y'], seed=cfg['seed'],
                                          slot=index, round_id=round_id, **cfg['training'])
            update = quantize(delta, policy)
            if index == 0 and cfg['case'] != 'clean':
                update = attack(np.asarray(update, dtype=np.int64), cfg['case'], policy).tolist()
            if any(not -32768 <= v < 32768 for v in update):
                raise ProtocolError('unexpected reference wire alias')
            training_seconds = time.monotonic()-tick
            tick = time.monotonic()
            cached = {'update': update, 'model_hash': state['model-hash'], 'training': meta}
            write_private(directory/f'audit/round-{round_id}.json', cached)
            calls.cache(round_id, context_hash, cached)
            write_private(directory/f'timing-round-{round_id}.json', {
                'round': round_id, 'training_and_quantization_seconds': training_seconds,
                'audit_cache_seconds': time.monotonic()-tick})
        state['last-trained'] = round_id
    finally:
        calls.close()
    return Message(RecordDict({'update': ArrayRecord([np.asarray(cached['update'], dtype=np.int16)]),
                              'meta': ConfigRecord({'slot': index, 'round': round_id,
                                                    'model-hash': cached['model_hash']})}), reply_to=message)


@client_app.query('commit')
def commit(message: Message, context: Context):
    configuration(context)
    state = context.state['cost-state']
    r = int(message.content['config']['round'])
    model = message.content['model'].to_numpy_ndarrays()[0]
    if r != state['round']+1 or state['last-trained'] != r:
        raise ProtocolError('reference commit order differs')
    state['round'] = r; state['model-hash'] = digest(model.tolist())
    return Message(RecordDict({'meta': ConfigRecord({'slot': slot(context), 'round': r,
                                                    'model-hash': state['model-hash']})}), reply_to=message)


@server_app.main()
def main(grid: Grid, context: Context):
    cfg, policy = configuration(context)
    output = Path(context.run_config['output-dir'])/f'run-{context.run_id}'
    output.mkdir(parents=True, exist_ok=False)
    meter = ApplicationMeter(); grid = MeteredGrid(grid, meter)
    model = np.asarray(cfg['initial_model'], dtype=np.float64)
    started = time.monotonic()
    def exchange(content, kind, mapping):
        replies = list(grid.send_and_receive([Message(content, dst_node_id=node, message_type=kind)
                                              for node in mapping], timeout=1200))
        if len(replies) != 4 or any(r.has_error() for r in replies):
            raise ProtocolError('reference Flower client failed')
        result = {}
        for reply in replies:
            index = int(reply.content['meta']['slot'])
            if index in result or mapping[reply.metadata.src_node_id] != index:
                raise ProtocolError('duplicate/unmapped reference client')
            result[index] = reply
        if set(result) != set(range(4)):
            raise ProtocolError('incomplete reference cohort')
        return [result[i] for i in range(4)]
    nodes = list(grid.get_node_ids())
    if len(nodes) != 4: raise ProtocolError('reference node count differs')
    replies = list(grid.send_and_receive([Message(RecordDict(), dst_node_id=n, message_type='query.identity')
                                         for n in nodes], timeout=1200))
    mapping = {r.metadata.src_node_id: int(r.content['meta']['slot']) for r in replies if not r.has_error()}
    if set(mapping) != set(nodes) or set(mapping.values()) != set(range(4)):
        raise ProtocolError('reference identity mapping differs')
    setup_seconds = time.monotonic()-started
    with np.load(cfg['test_data'], allow_pickle=False) as data:
        test_x, test_y = data['x'], data['y']
    models = [model.tolist()]; metrics = [evaluate_lenet(model, test_x, test_y)]
    records = []; timings = []
    for r in range(1, cfg['rounds']+1):
        meter.scope = f'round-{r}'; timing = {'round': r}; tick = time.monotonic()
        content = RecordDict({'model': ArrayRecord([model]), 'config': ConfigRecord({'round': r})})
        received = exchange(content, 'train', mapping)
        updates = []
        for reply in received:
            meta = reply.content['meta']
            if meta['round'] != r or meta['model-hash'] != digest(model.tolist()):
                raise ProtocolError('reference input round/model differs')
            updates.append(reply.content['update'].to_numpy_ndarrays()[0])
        timing['collect_seconds'] = time.monotonic()-tick; tick = time.monotonic()
        result, selected = aggregate_q(updates, cfg['variant'], policy)
        timing['check_and_sum_seconds'] = time.monotonic()-tick; tick = time.monotonic()
        if result['status'] == 'ok':
            model = model+np.asarray(result['sum'], dtype=np.float64)/(policy.scale*result['count'])
        timing['apply_seconds'] = time.monotonic()-tick; tick = time.monotonic()
        commits = exchange(RecordDict({'model': ArrayRecord([model]), 'config': ConfigRecord({'round': r})}),
                           'query.commit', mapping)
        if any(reply.content['meta']['round'] != r or reply.content['meta']['model-hash'] != digest(model.tolist()) for reply in commits):
            raise ProtocolError('reference model commit differs')
        models.append(model.tolist()); metrics.append(evaluate_lenet(model, test_x, test_y))
        timing['commit_and_evaluation_seconds'] = time.monotonic()-tick
        records.append({'round': r, 'result': result, 'selected': selected}); timings.append(timing)
        print('COST_REFERENCE', cfg['variant'], cfg['case'], r, metrics[-1]['accuracy'], flush=True)
    wall_seconds = time.monotonic()-started
    (output/'results.json').write_bytes(canonical({'scope': 'explicit trusted plaintext research reference',
        'variant': cfg['variant'], 'case': cfg['case'], 'seed': cfg['seed'], 'models': models,
        'metrics': metrics, 'records': records, 'round_timings': timings,
        'setup_seconds': setup_seconds, 'wall_seconds': wall_seconds, 'communication': meter.report()}))
