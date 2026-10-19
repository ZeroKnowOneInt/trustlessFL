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
    if body.get("distributed_session"):
        from .seed_mpc_distributed import validate_local_deployment
        validate_local_deployment(body)
    if body.get('protocol')!='seed-mpc-local-deployment-v1': raise ProtocolError('invalid deployment')
    if body.get('rpc_material','inline-v1') not in ('inline-v1','prepared-reference-v1'):
        raise ProtocolError('unsupported RPC material mode')
    if body.get('training',{}).get('mode')=='custom-model':
        from .seed_mpc_model import validate_spec
        validate_spec(body['model_adapter'])
        if body['model_adapter']['schema']['dimension']!=body['committee']['policy']['dimension']:
            raise ProtocolError('model adapter/policy dimension differs')
    c=body['committee']
    committee=SeedCommittee(SeedMPCPolicy(**c['policy']),c['session_id'],c['epoch'],
        c['clients'],c['aggregators'],c['registry'],c['registrations'],c['execution_hash'],body['initial_model'],
        snapshot_version=c.get('snapshot_version',1),collection_window_ms=c.get('collection_window_ms',60000))
    if len(body['services'])!=4: raise ProtocolError('four services required')
    return body,committee


def rpc(url,action,payload=None,*,timeout=180,meter=None,transport=None):
    if transport:
        from .seed_mpc_distributed import remote_rpc
        return remote_rpc(url,action,payload,timeout=timeout,meter=meter,transport=transport)
    if not url.startswith('http://127.0.0.1:'): raise ProtocolError('local-only service endpoint')
    data=canonical(payload or {})
    request=Request(url+'/'+action,data=data,headers={'Content-Type':'application/json'},method='POST')
    scope=meter.scope if meter else None
    if meter: meter.record('aggregator-rpc-json','sent',action,len(data),scope=scope)
    try:
        with urlopen(request,timeout=timeout) as response:
            raw=response.read(16*1024*1024+1)
        if meter: meter.record('aggregator-rpc-json','received',action,len(raw),scope=scope)
        if len(raw)>16*1024*1024: raise ProtocolError('oversized service response')
        body=json.loads(raw)
        if set(body)!= {'result'}: raise ProtocolError('invalid service response')
        return body['result']
    except HTTPError as exc:
        raw=exc.read(16*1024*1024+1)
        if meter: meter.record('aggregator-rpc-json','received',action,len(raw),scope=scope)
        raise ProtocolError('aggregator RPC failed; no plaintext fallback') from exc
    except (URLError,TimeoutError,json.JSONDecodeError) as exc:
        raise ProtocolError('aggregator RPC failed; no plaintext fallback') from exc


def committee_rpc(deployment,action,payload=None,*,meter=None,sequential=False):
    if sequential:
        return [rpc(url,action,payload,timeout=deployment['timeout'],
            **({'meter':meter} if meter else {}),
            **({'transport':deployment['rpc_transport']} if deployment.get('distributed_session') else {}))
            for url in deployment['services']]
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures=[pool.submit(rpc,url,action,payload,timeout=deployment['timeout'],**({'meter':meter} if meter else {}),**({'transport':deployment['rpc_transport']} if deployment.get('distributed_session') else {})) for url in deployment['services']]
        return [future.result() for future in futures]
