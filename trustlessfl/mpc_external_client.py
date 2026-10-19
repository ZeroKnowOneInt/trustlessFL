"""Local MP-SPDZ external client; private input never enters Flower messages.

Only used by the local MPC fixture runner for now. TLS keys and the client's
update/key file must reside in that client's private directory. Import the
unmodified ExternalIO client supplied by the pinned MP-SPDZ distribution.
"""
import argparse
import json
import os
from pathlib import Path
import sys

from .aion_original_hprf import OriginalAionHPRF
from .private_bound import NoWrapPolicy, scale_canonical_mask


def prepare_bits(policy,key,hprf,seed,update,*,mutation=None):
    if type(key) is not int or not 0<=key<hprf.q:
        raise ValueError('invalid private key domain')
    h=hprf.hprf(key,seed,policy.dimension)
    masks=tuple(scale_canonical_mask(value%hprf.p,hprf.p,policy.mask_max) for value in h)
    offsets=list(policy.encode(update,masks))
    if mutation=='off-grid':
        if policy.spacing==1:
            raise ValueError('off-grid fixture needs spacing > 1')
        offsets[0]+=1
    elif mutation=='coordinate-large':
        offsets[0]=policy.spacing*(policy.coordinate_cap+1)+masks[0]+policy.spacing*policy.coordinate_cap
    elif mutation not in (None,'nonboolean'):
        raise ValueError('invalid fixture mutation')
    keybits=(hprf.q-1).bit_length(); wirebits=policy.widths()['offset_unsigned']
    if any(not 0<=v<1<<wirebits for v in offsets):
        raise ValueError('fixture exceeds canonical input bit width')
    bits=[(key>>i)&1 for i in range(keybits)]
    bits.extend((v>>i)&1 for v in offsets for i in range(wirebits))
    if mutation=='nonboolean':
        bits[-1]=2
    return bits


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mp-spdz-dir',type=Path,required=True)
    parser.add_argument('--private-input',type=Path,required=True)
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    config=json.loads(args.config.read_text())
    private=json.loads(args.private_input.read_text())
    policy=NoWrapPolicy(config['dimension'],config['clients'],config['coordinate_cap'],config['scale'],
                        config['spacing'],config['mask_max'],config['squared_bound'],config['minimum_accepted'])
    hprf=OriginalAionHPRF.from_public_setup(tuple(config['hprf']['setup']))
    bits=prepare_bits(policy,private['key'],hprf,config['seed'],private['update'],mutation=private.get('mutation'))
    sys.path.insert(0,str(args.mp_spdz_dir.resolve()/'ExternalIO'))
    from client import Client
    client=Client(['127.0.0.1']*config['parties'],config['client_port'],private['client_id'])
    try:
        if client.domain.modulus!=config['backend_prime']:
            raise ValueError('backend field differs from frozen public policy')
        client.send_private_inputs(bits)
        output=client.receive_outputs(policy.dimension+2)
        if output[0] not in (0,1):
            raise ValueError('invalid authenticated status')
        if output[0]:
            result={'status':'ok','count':output[1],'sum':output[2:]}
        else:
            if any(output[1:]):
                raise ValueError('abort disclosed intermediate output')
            result={'status':'abort'}
        # This is a PENDING authenticated output until all MPC parties exit successfully.
        descriptor=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(descriptor,'w') as stream:
            json.dump(result,stream)
    finally:
        for socket in client.sockets:
            socket.close()


if __name__=='__main__':
    main()
