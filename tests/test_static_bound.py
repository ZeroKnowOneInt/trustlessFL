"""Static-policy validation and server-loop regressions, with no native MPC."""
import json
from types import SimpleNamespace

import numpy as np
import pytest

from trustlessfl.crypto import ProtocolError
from trustlessfl.static_bound import static_learning_policy


def config(**changes):
    return {"threshold-mode":"static","squared-threshold":2,"scale":1,
            "coordinate-cap":10,**changes}


@pytest.mark.parametrize("change", [
    {"threshold-mode":"dynamic"}, {"threshold-mode":None}, {"boot-bound":2},
    {"minimum-bound":1}, {"maximum-bound":200}, {"squared-threshold":True},
    {"squared-threshold":-1}, {"squared-threshold":201}, {"squared-threshold":2.5},
])
def test_static_profile_rejects_dynamic_or_unsafe_policy(change):
    with pytest.raises(ProtocolError):
        static_learning_policy(config(**change),dimension=2,clients=4)


@pytest.mark.parametrize("abort_middle", [False, True])
def test_server_keeps_threshold_despite_mean_changes_or_abort(tmp_path,monkeypatch,abort_middle):
    from trustlessfl import fmnist_no_wrap_app as app
    from flwr.app import ArrayRecord, ConfigRecord
    monkeypatch.setattr(app,"DIMENSION",2)
    monkeypatch.setattr(app,"configure_torch",lambda device:None)
    monkeypatch.setattr(app,"reference_vector",lambda path:np.zeros(2))
    monkeypatch.setattr(app,"evaluate",lambda *args,**kwargs:{"accuracy":0.0})
    np.savez(tmp_path/"test.npz",x=np.zeros((2,28,28),dtype=np.uint8),y=np.zeros(2,dtype=np.uint8))
    cfg=config(**{"device":"cpu","data-dir":str(tmp_path),"output-dir":str(tmp_path/"outputs"),
                  "timeout":1.,"rounds":3,"seed":42})

    class Grid:
        batches=0
        def get_node_ids(self): return [11,22,33,44]
        def send_and_receive(self,messages,timeout):
            messages=list(messages)
            identity=messages[0].metadata.message_type=="query.identity"
            if not identity:self.batches+=1
            replies=[]
            for i,message in enumerate(messages):
                content={"meta":ConfigRecord({"partition":i})}
                if not identity:
                    request=message.content["config"]
                    model=message.content["model"].to_numpy_ndarrays()[0]
                    r=int(request["round"])
                    value=(2 if abort_middle else 0) if r==2 else 1
                    delta=np.full(2,value,dtype=np.float64)
                    content={"delta":ArrayRecord([delta]),"meta":ConfigRecord({"partition":i,
                        "case":request["case"],"round":r,"calls":self.batches,
                        "input_model_sha256":app.vector_hash(model)})}
                replies.append(SimpleNamespace(content=content,
                    metadata=SimpleNamespace(src_node_id=message.metadata.dst_node_id),has_error=lambda:False))
            return replies

    app.main(Grid(),SimpleNamespace(run_config=cfg,run_id=42))
    result=json.loads((tmp_path/"outputs/run-42/results.json").read_text())
    assert [c["case"] for c in result["cases"]]==["fedavg","quantized","no-wrap-static"]
    rows=result["cases"][-1]["history"][1:]
    assert [r["squared_bound"] for r in rows]==[2,2,2]
    assert [r["applied_count"] for r in rows]==([4,0,4] if abort_middle else [4,4,4])
    assert [r["status"] for r in rows]==(["ok","abort","ok"] if abort_middle else ["ok"]*3)
    with np.load(tmp_path/"outputs/run-42/no-wrap-static-models.npz") as saved:
        assert np.array_equal(saved["models"],[[0,0],[1,1],[1,1],[2,2]])
