"""Deterministic local FMNIST workloads; only masked updates leave clients."""
import numpy as np

from .crypto import ProtocolError

DIMENSION=170  # 16 pooled pixel features * 10 classes + 10 biases.
LENET_DIMENSION=61706


def configure_lenet():
    import torch
    torch.set_num_threads(1); torch.use_deterministic_algorithms(True)


def initial_lenet(seed):
    import torch
    from .fmnist import make_model,parameter_vector
    configure_lenet()
    with torch.random.fork_rng(devices=[]):
        torch.manual_seed(seed)
        return parameter_vector(make_model())


def lenet_model(vector):
    from .fmnist import make_model,load_vector
    if vector.shape!=(LENET_DIMENSION,) or vector.dtype!=np.float64 or not np.isfinite(vector).all():
        raise ProtocolError('invalid LeNet5 model')
    configure_lenet(); model=make_model(); load_vector(model,vector)
    return model


def train_lenet(vector,x,y,*,seed,slot,round_id,epochs,batch_size,learning_rate,momentum,weight_decay):
    import torch
    from .fmnist import parameter_vector,tensor_images
    model=lenet_model(vector); before=parameter_vector(model)
    images=tensor_images(x,'cpu'); labels=torch.from_numpy(y.astype(np.int64))
    stream_seed=int(np.random.SeedSequence([seed,slot,round_id]).generate_state(1)[0])
    generator=torch.Generator().manual_seed(stream_seed)
    optimizer=torch.optim.SGD(model.parameters(),lr=learning_rate,momentum=momentum,weight_decay=weight_decay)
    model.train(); steps=0
    for _ in range(epochs):
        for indices in torch.randperm(len(y),generator=generator).split(batch_size):
            optimizer.zero_grad(set_to_none=True)
            torch.nn.functional.cross_entropy(model(images[indices]),labels[indices]).backward()
            optimizer.step(); steps+=1
    return parameter_vector(model)-before,{'rows':len(y),'optimizer_steps':steps,'device':'cpu',
        'epochs':epochs,'batch_size':batch_size,'parameter_count':LENET_DIMENSION}


def evaluate_lenet(vector,x,y,batch_size=256):
    import torch
    from .fmnist import tensor_images
    model=lenet_model(vector); model.eval(); correct=0; loss=0.0
    with torch.no_grad():
        for start in range(0,len(y),batch_size):
            logits=model(tensor_images(x[start:start+batch_size],'cpu'))
            labels=torch.from_numpy(y[start:start+batch_size].astype(np.int64))
            correct+=int((logits.argmax(1)==labels).sum())
            loss+=float(torch.nn.functional.cross_entropy(logits,labels,reduction='sum'))
    accuracy=correct/len(y)
    return {'accuracy':accuracy,'test_error_rate':1-accuracy,'loss':loss/len(y)}


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
