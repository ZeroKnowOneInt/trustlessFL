"""Parse and archive four-party seed-MPC communication measurements.

Only public diagnostics are copied. Fixture inputs, credentials, and shares are
never copied. MB is decimal; native MPC counters exclude ExternalIO traffic.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil


def parse_run(result):
    workspace = Path(result['workspace'])
    phases = {'online_mb': 0.0, 'preprocessing_mb': 0.0}
    stages = {}
    parties = []
    for i in range(result['parties']):
        path = workspace / f'P{i}' / 'native.log'
        text = path.read_text()
        phase = re.search(r'Spent .*?\(([\d.]+) MB,.*?on the online phase and '
                          r'.*?\(([\d.]+) MB,.*?on the preprocessing/offline phase', text)
        if not phase:
            raise ValueError(f'phase statistics missing: {path}')
        online, offline = map(float, phase.groups())
        phases['online_mb'] += online
        phases['preprocessing_mb'] += offline
        data = re.search(r'Data sent = ([\d.]+) MB', text)
        if not data:
            raise ValueError(f'total statistics missing: {path}')
        parties.append({'party': i, 'total_mb': float(data[1]),
                        'online_mb': online, 'preprocessing_mb': offline})
        for timer, mb in re.findall(r'^Time(\d+) = .*?\(([\d.]+) MB,', text, re.M):
            stages[timer] = stages.get(timer, 0.0) + float(mb)
    total = result['global_data_sent_mb']
    if abs(sum(phases.values()) - total) > .1:
        raise ValueError('phase totals disagree beyond native print rounding')
    if stages and abs(sum(stages.values()) - total) > .1:
        raise ValueError('stage totals disagree beyond native print rounding')
    external = {}
    for client in result['external_client_communication']:
        for name, counters in client.items():
            bucket = external.setdefault(name, {key: 0 for key in counters})
            for key, value in counters.items():
                bucket[key] += value
    counts = {}
    for count, name in re.findall(r'^\s*(\d+) (integer triples|integer randoms|integer dabits|'
                                  r'integer simple multiplications|integer opens|bit opens|'
                                  r'integer bits|bit triples|virtual machine rounds)\s*$',
                                  (workspace / 'compile.log').read_text(), re.M):
        counts[name] = int(count)
    return {'global_mb': total, **phases, 'online_percent': phases['online_mb']/total*100,
            'preprocessing_percent': phases['preprocessing_mb']/total*100,
            'parties': parties, 'stage_mb': stages,
            'stage_percent': {key: value/total*100 for key,value in stages.items()},
            'external_all_clients': external, 'compiler_requirements': counts}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--profile', type=Path, required=True)
    parser.add_argument('--logs-directory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    results = {name: json.loads(path.read_text()) for name,path in
               [('baseline', args.baseline), ('profile', args.profile)]}
    baseline, profile = results['baseline'], results['profile']
    for name in ['case', 'parties', 'clients', 'dimension', 'rounds', 'output',
                 'wire_modulus', 'field_bits', 'application_bits', 'aes_circuit_sha256']:
        if baseline[name] != profile[name]:
            raise ValueError(f'different comparison fixture: {name}')
    analysis = {name: parse_run(result) for name,result in results.items()}
    for key,count in analysis['baseline']['compiler_requirements'].items():
        if key != 'virtual machine rounds' and analysis['profile']['compiler_requirements'].get(key) != count:
            raise ValueError(f'timer probe changes resource requirements: {key}')
    n, d, rounds = baseline['clients'], baseline['dimension'], baseline['rounds']
    word_bits = baseline['wire_modulus'].bit_length()-1
    blocks = n*rounds*((d+128//word_bits-1)//(128//word_bits))
    all_mask_bits, needed_mask_bits = blocks*128, n*rounds*d*word_bits
    analysis['logical_sizes'] = {'seeds_bytes': n*16,
        'public_masked_updates_bytes': n*rounds*d*word_bits//8,
        'public_updates_sent_in_fixture': False,
        'aes_blocks': blocks, 'seed_a2b_bits': n*128,
        'mask_b2a_bits': all_mask_bits, 'needed_mask_b2a_bits': needed_mask_bits,
        'unused_mask_b2a_bits': all_mask_bits-needed_mask_bits}
    if analysis['baseline']['compiler_requirements']['integer dabits'] != n*128+all_mask_bits:
        raise ValueError('daBit counts differ from expected conversions')
    analysis['notes'] = [
        'Native counters: sum of bytes sent by MPC parties, decimal MB, excludes external clients and TLS/TCP overhead.',
        'External counters: sent plus received application messages with four-byte framing; excludes TLS/TCP overhead.',
        'Timer barriers change batching. Profile and baseline have equal non-round resource counts and rounded total MB.',
        'On-demand preprocessing is charged where generated; the registration stage pre-generates shared daBit material used later.',
        'No full-model traffic extrapolation from this D=2 fixture. Public masked inputs are compiled constants.']
    analysis['archived_logs'] = {}
    for name, result in results.items():
        dest = args.logs_directory / name
        dest.mkdir(parents=True, exist_ok=False)
        paths = [Path(result['workspace'])/'compile.log'] + [
            Path(result['workspace'])/f'P{i}'/'native.log' for i in range(result['parties'])]
        for path in paths:
            target = dest/('compile.log' if path.name=='compile.log' else path.parent.name+'.log')
            shutil.copyfile(path, target)
            analysis['archived_logs'][str(target)] = hashlib.sha256(target.read_bytes()).hexdigest()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as out:
        json.dump(analysis, out, indent=2)
    print(json.dumps(analysis, indent=2))


if __name__ == '__main__':
    main()
