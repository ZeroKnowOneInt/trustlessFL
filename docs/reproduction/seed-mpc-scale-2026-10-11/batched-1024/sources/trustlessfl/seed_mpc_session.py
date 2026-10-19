"""Public deployment loading and loopback RPC; never contains client seeds."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .crypto import ProtocolError, canonical
from .seed_mpc_committee import SeedCommittee
from .seed_mpc_policy import SeedMPCPolicy


def load_deployment(path):
    body=json.loads(Path(path).read_text())
    if body.get('protocol')!='seed-mpc-local-deployment-v1': raise ProtocolError('invalid deployment')
    c=body['committee']
    committee=SeedCommittee(SeedMPCPolicy(**c['policy']),c['session_id'],c['epoch'],
        c['clients'],c['aggregators'],c['registry'],c['registrations'],c['execution_hash'],body['initial_model'])
    if len(body['services'])!=4: raise ProtocolError('four services required')
    return body,committee


def rpc(url,action,payload=None,*,timeout=180):
    if not url.startswith('http://127.0.0.1:'): raise ProtocolError('local-only service endpoint')
    request=Request(url+'/'+action,data=canonical(payload or {}),headers={'Content-Type':'application/json'},method='POST')
    try:
        with urlopen(request,timeout=timeout) as response:
            raw=response.read(16*1024*1024+1)
        if len(raw)>16*1024*1024: raise ProtocolError('oversized service response')
        body=json.loads(raw)
        if set(body)!= {'result'}: raise ProtocolError('invalid service response')
        return body['result']
    except (HTTPError,URLError,TimeoutError,json.JSONDecodeError) as exc:
        raise ProtocolError('aggregator RPC failed; no plaintext fallback') from exc


def committee_rpc(deployment,action,payload=None):
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures=[pool.submit(rpc,url,action,payload,timeout=deployment['timeout']) for url in deployment['services']]
        return [future.result() for future in futures]
