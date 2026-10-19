"""Prepare small-CNN custom-model config from locally checksum-verified FMNIST."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import numpy as np
from experiments.prepare_fashion_mnist import prepare as verify_dataset
from experiments.run_fmnist_flower import read_dataset

ROOT=Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def prepare(output, rows=1024, test_rows=2048, seed=42):
    if (type(rows) is not int or not 32<=rows<=15000 or type(test_rows) is not int
            or not 32<=test_rows<=10000 or type(seed) is not int or seed<0):
        raise ValueError('invalid FMNIST subset size/seed')
    report=verify_dataset(ROOT/'.cache/fashion-mnist',download=False)
    data=read_dataset(ROOT/'.cache/fashion-mnist/FashionMNIST/raw')
    output=Path(output).resolve();output.mkdir(parents=True,exist_ok=False,mode=0o700)
    shutil.copyfile(ROOT/'examples/seed_mpc_custom/fmnist_small_cnn.py',output/'model.py')
    order=np.random.default_rng(seed).permutation(len(data['train_y']))
    records={}
    for i,partition in enumerate(np.array_split(order,4)):
        selected=partition[:rows];path=output/f'C{i}.npz'
        np.savez_compressed(path,x=data['train_x'][selected],y=data['train_y'][selected]);path.chmod(0o600)
        records[f'C{i}']={'rows':len(selected),'sha256':sha(path),
            'indices_sha256':hashlib.sha256(selected.astype('<i8').tobytes()).hexdigest(),
            'class_counts':np.bincount(data['train_y'][selected],minlength=10).tolist()}
    path=output/'test.npz';np.savez_compressed(path,x=data['test_x'][:test_rows],y=data['test_y'][:test_rows])
    records['test']={'rows':test_rows,'sha256':sha(path)}
    cfg={'plugin':'model.py','kwargs':{'channels':[4,8],'classes':10},
        'train_data':[f'C{i}.npz' for i in range(4)],'test_data':'test.npz',
        'training':{'epochs':1,'batch_size':64,'learning_rate':.05,'momentum':0.,'weight_decay':0.},
        'policy':{'coordinate_cap':20000,'squared_threshold':2500000000,'scale':10000,'minimum_accepted':2}}
    (output/'model.json').write_text(json.dumps(cfg,indent=2)+'\n')
    (output/'dataset-manifest.json').write_text(json.dumps({'source':report,'selection_seed':seed,
        'partition':'four disjoint IID random partitions, first rows-per-client entries', 'shards':records},indent=2)+'\n')
    return output/'model.json'


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--rows-per-client',type=int,default=1024)
    p.add_argument('--test-rows',type=int,default=2048)
    args=p.parse_args();print(prepare(args.output,args.rows_per_client,args.test_rows))
