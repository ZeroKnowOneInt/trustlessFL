"""Small FMNIST training workload for transport integration, not LeNet5."""
import numpy as np

from .crypto import ProtocolError

DIMENSION=170  # 16 pooled pixel features * 10 classes + 10 biases.


def tensors(x,y):
    import torch
    values=torch.from_numpy(x.copy()).float().reshape(-1,1,28,28)/255.0
    features=torch.nn.functional.avg_pool2d(values,7).reshape(-1,16)
    return features,torch.from_numpy(y.astype(np.int64))


def model_for(vector):
    import torch
    if vector.shape!=(DIMENSION,) or vector.dtype!=np.float64 or not np.isfinite(vector).all():
        raise ProtocolError('invalid tiny FMNIST model')
    torch.set_num_threads(1); torch.use_deterministic_algorithms(True)
    model=torch.nn.Linear(16,10)
    with torch.no_grad():
        model.weight.copy_(torch.from_numpy(vector[:160].reshape(10,16)))
        model.bias.copy_(torch.from_numpy(vector[160:]))
    return model


def train(vector,x,y,*,seed,slot,round_id,epochs,batch_size,learning_rate):
    import torch
    model=model_for(vector); features,labels=tensors(x,y)
    generator=torch.Generator().manual_seed(seed+1000*slot+round_id)
    optimizer=torch.optim.SGD(model.parameters(),lr=learning_rate)
    model.train()
    for _ in range(epochs):
        order=torch.randperm(len(y),generator=generator)
        for indices in order.split(batch_size):
            optimizer.zero_grad()
            loss=torch.nn.functional.cross_entropy(model(features[indices]),labels[indices])
            loss.backward(); optimizer.step()
    after=np.concatenate([model.weight.detach().numpy().reshape(-1).astype(np.float64),
                          model.bias.detach().numpy().astype(np.float64)])
    return after-vector


def evaluate(vector,x,y):
    import torch
    model=model_for(vector); features,labels=tensors(x,y); model.eval()
    with torch.no_grad():
        logits=model(features)
        return {'accuracy':float((logits.argmax(1)==labels).float().mean()),
                'loss':float(torch.nn.functional.cross_entropy(logits,labels))}


def quantize(delta,policy):
    if delta.shape!=(policy.dimension,) or delta.dtype!=np.float64 or not np.isfinite(delta).all():
        raise ProtocolError('invalid training delta')
    scaled=np.rint(delta*policy.scale)
    # Honest-client preprocessing. Malicious client effective inputs are still
    # verified independently inside MPC; this check provides no server trust.
    if np.any(np.abs(scaled)>policy.coordinate_cap): raise ProtocolError('honest delta exceeds coordinate cap')
    result=scaled.astype(np.int64).tolist(); policy.validate_update(result)
    return result


def fixture_update(slot,round_id,dimension):
    # Public synthetic regression: +80000, -40000, then count-insufficient abort.
    updates={1:[[20000,0]]*4,2:[[-20000,0],[-20000,0],[20001,0],[20000,20000]],
             3:[[20000,0],[20001,0],[20001,0],[20000,20000]]}
    if round_id not in updates or dimension<2: raise ProtocolError('invalid fixture round')
    return updates[round_id][slot]+[0]*(dimension-2)


def scale_fixture_update(slot,round_id,dimension):
    """Dense public input with last-coordinate and cross-chunk violations.

    Threshold is 2.5e9. Seven B-sized coordinates in separate 32-word chunks
    exceed that threshold although each chunk alone passes. Honest inputs
    exercise wide sums at both ends and nonzero interiors throughout.
    """
    if slot not in range(4) or round_id not in (1,2,3) or dimension<256:
        raise ProtocolError('invalid scale fixture')
    direction=1 if round_id==1 else -1
    values=[direction*(slot+1)*(-1 if j%3==0 else 1) for j in range(dimension)]
    values[0]=direction*20000; values[-1]=-direction*20000
    if round_id>=2 and slot==2 or round_id==3 and slot==1:
        values[-1]=20001
    if round_id>=2 and slot==3:
        values=[0]*dimension
        for j in range(7): values[j*32]=20000
    return values
