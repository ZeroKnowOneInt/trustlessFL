"""Create deterministic toy classification shards and an explicit static policy."""
import argparse
import json
from pathlib import Path
import shutil
import numpy as np

ROOT = Path(__file__).resolve().parents[1]


def prepare(output, hidden=5):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(ROOT/'examples/seed_mpc_custom/classifier.py', output/'classifier.py')
    rng = np.random.default_rng(42)
    teacher = rng.normal(size=(6, 3))
    for name in ['C0', 'C1', 'C2', 'C3', 'test']:
        x = rng.normal(size=(64 if name != 'test' else 96, 6)).astype(np.float32)
        y = (x@teacher).argmax(1).astype(np.int64)
        np.savez_compressed(output/(name+'.npz'), x=x, y=y)
    config = {'plugin': 'classifier.py', 'kwargs': {'hidden': hidden},
        'train_data': [f'C{i}.npz' for i in range(4)], 'test_data': 'test.npz',
        'training': {'epochs': 1, 'batch_size': 16, 'learning_rate': .05},
        'policy': {'coordinate_cap': 20000, 'squared_threshold': 2500000000,
                   'scale': 10000, 'minimum_accepted': 2}}
    (output/'model.json').write_text(json.dumps(config, indent=2)+'\n')
    return output/'model.json'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--hidden', type=int, default=5)
    args = parser.parse_args()
    print(prepare(args.output, args.hidden))
