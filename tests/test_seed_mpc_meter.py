import json
from pathlib import Path
from http.server import BaseHTTPRequestHandler,HTTPServer
import threading

import numpy as np
import pytest
from flwr.app import ArrayRecord,ConfigRecord,Message,RecordDict

from trustlessfl.crypto import ProtocolError
from trustlessfl.seed_mpc_meter import ApplicationMeter,MeteredGrid,graph_size,native_partition,global_partition
from trustlessfl.seed_mpc_session import rpc,committee_rpc
from trustlessfl.seed_mpc_telemetry_patch import patched_source


def log():
    return '\n'.join(['SEED_MPC_COMM START 7 10','SEED_MPC_COMM STOP 7 30',
        'SEED_MPC_REG_CHECKED','SEED_MPC_COMM START 8 35','SEED_MPC_COMM STOP 8 100',
        'SEED_MPC_CHECKED 1 1 2 3 4','SEED_MPC_COMM START 8 100','SEED_MPC_COMM STOP 8 160',
        'SEED_MPC_CHECKED 2 1 2 3 4','SEED_MPC_COMM_FINAL 180','SEED_MPC_COMM_GLOBAL 720'])


def test_exact_partition_includes_between_and_shutdown():
    p=native_partition(log(),2); g=global_partition([p]*4)
    assert g['setup_sent_bytes']==120
    assert [r['sent_bytes'] for r in g['rounds']]==[280,240]
    assert g['rounds'][0]['between_boundary_sent_bytes']==20
    assert g['shutdown_sent_bytes']==80 and g['total_sent_bytes']==720 and g['reconciled']


@pytest.mark.parametrize('before,after',[
    ('START 7 10','START 7 -1'),('STOP 7 30','STOP 7 9'),
    ('STOP 7 30','START 7 30'),('START 8 35','START 8 29'),
    ('STOP 8 100','STOP 8 invalid'),('CHECKED 1','CHECKED 2'),
    ('REG_CHECKED','REG_CHECKED\nSEED_MPC_REG_CHECKED'),
    ('SEED_MPC_COMM_FINAL 180','SEED_MPC_COMM_FINAL 159'),
    ('SEED_MPC_COMM_GLOBAL 720','SEED_MPC_COMM_GLOBAL -1'),
    ('SEED_MPC_COMM_FINAL 180',''),('SEED_MPC_COMM STOP 8 160',''),
    ('SEED_MPC_COMM_FINAL 180','SEED_MPC_COMM_FINAL 180\nSEED_MPC_COMM_FINAL 180')])
def test_reject_malformed_counter_and_boundary(before,after):
    with pytest.raises(ProtocolError): native_partition(log().replace(before,after),2)


def test_reject_global_mismatch():
    with pytest.raises(ProtocolError): global_partition([native_partition(log().replace('GLOBAL 720','GLOBAL 721'),2)]*4)


def test_graph_includes_array_children_once():
    arr=ArrayRecord([np.arange(1024,dtype=np.float64)])
    msg=Message(RecordDict({'model':arr,'config':ConfigRecord({'round':1})}),dst_node_id=7,message_type='train')
    size,objects=graph_size(msg)
    assert size>8192+len(msg.deflate()) and objects>=5
    # Exact independent recursive traversal, deduplicated within one graph.
    all_objects={}
    def walk(x):
        all_objects[x.object_id]=x
        for child in (x.children or {}).values(): walk(child)
    walk(msg)
    assert size==sum(len(x.deflate()) for x in all_objects.values())
    assert objects==len(all_objects)


class FakeGrid:
    pull_interval=.001
    def __init__(self): self.messages={}; self.replies=[]
    def push_messages(self,messages):
        for m in messages:
            key=f'id-{len(self.messages)}'
            m.metadata.__dict__['_run_id']=123
            m.metadata.__dict__['_src_node_id']=1
            m.metadata.__dict__['_message_id']=key
            self.messages[key]=m
        return list(self.messages)[-len(messages):]
    def pull_messages(self,ids):
        result,self.replies=self.replies,[]
        return result


def test_late_reply_keeps_origin_round_and_duplicates_not_recounted():
    raw=FakeGrid(); meter=ApplicationMeter(); grid=MeteredGrid(raw,meter)
    meter.scope='round-1'
    m=Message(RecordDict({'config':ConfigRecord({'round':1})}),dst_node_id=7,message_type='train')
    ids=grid.push_messages([m]); reply=Message(RecordDict(),reply_to=m)
    reply.metadata.__dict__['_message_id']='reply-1'
    meter.scope='round-2'; raw.replies=[reply]; grid.pull_messages(ids)
    raw.replies=[reply]; grid.pull_messages(ids)
    assert len(meter.events)==2
    assert all(e['scope']=='round-1' for e in meter.events)
    assert meter.events[0]['bytes']==graph_size(m)[0]
    assert meter.events[1]['bytes']==graph_size(reply)[0]


@pytest.fixture
def service():
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length=int(self.headers['Content-Length']); self.rfile.read(length)
            data=b'{"result":true}' if self.path=='/ok' else b'{"error":"rejected"}'
            self.send_response(200 if self.path=='/ok' else 409)
            self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
        def log_message(self,*args): pass
    server=HTTPServer(('127.0.0.1',0),Handler)
    t=threading.Thread(target=server.serve_forever,daemon=True); t.start()
    yield f'http://127.0.0.1:{server.server_port}'
    server.shutdown(); server.server_close(); t.join()


def test_rpc_counts_success_error_and_all_four_senders(service):
    meter=ApplicationMeter()
    assert committee_rpc({'services':[service]*4,'timeout':2},'ok',{'x':1},meter=meter)==[True]*4
    assert sum(e['bytes'] for e in meter.events if e['direction']=='sent')==4*len(b'{"x":1}')
    assert sum(e['bytes'] for e in meter.events if e['direction']=='received')==4*len(b'{"result":true}')
    with pytest.raises(ProtocolError): rpc(service,'bad',meter=meter)
    assert meter.events[-1]['bytes']==len(b'{"error":"rejected"}')
    assert '"x":' not in json.dumps(meter.report())


def test_counter_patch_refuses_unknown_source():
    with pytest.raises(ValueError): patched_source('unrelated source')
