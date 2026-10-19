"""Regression for the actual synchronous actor leak and abort/workload confusion."""
from types import SimpleNamespace

import pytest

from trustlessfl.seed_mpc_flower_runtime import guarded_submit, learning_workload_completed


def serialization_failure():
    # Fault injection at the reviewed Ray pre-submission serialization frame.
    namespace={}
    exec(compile('def _serialize_to_pickle5():\n'
                 '    raise RuntimeError("dictionary changed size during iteration")\n',
                 '/test/ray/_private/serialization.py','exec'),namespace)
    namespace['_serialize_to_pickle5']()


def test_submit_failure_restores_actor_and_next_request_runs():
    actor=object(); pool=SimpleNamespace(pool=[actor], _future_to_actor={})
    def fail(*args): raise ValueError('serialization failed')
    with pytest.raises(ValueError): guarded_submit(pool,fail,(None,None,'0',None))
    assert pool.pool == [actor]
    future=object()
    assert guarded_submit(pool,lambda *args:future,(None,None,'0',None)) is future
    assert pool._future_to_actor == {future:actor} and not pool.pool


def test_transient_dictionary_serialization_failure_retries_before_submission(monkeypatch):
    monkeypatch.setattr('trustlessfl.seed_mpc_flower_runtime.time.sleep',lambda _:None)
    actor=object(); pool=SimpleNamespace(pool=[actor],_future_to_actor={}); calls=[];future=object()
    def submit(*args):
        calls.append(args)
        if len(calls)==1:serialization_failure()
        return future
    assert guarded_submit(pool,submit,(None,None,'0',None)) is future
    assert len(calls)==2 and calls[0]==calls[1]
    assert pool._future_to_actor == {future:actor}


def test_persistent_dictionary_failure_is_bounded_and_actor_is_preserved(monkeypatch):
    monkeypatch.setattr('trustlessfl.seed_mpc_flower_runtime.time.sleep',lambda _:None)
    actor=object();pool=SimpleNamespace(pool=[actor],_future_to_actor={});calls=[]
    def fail(*args):
        calls.append(1);serialization_failure()
    with pytest.raises(RuntimeError):guarded_submit(pool,fail,(None,None,'0',None))
    assert len(calls)==3 and pool.pool==[actor] and not pool._future_to_actor


@pytest.mark.parametrize('error',[RuntimeError('network uncertain'),
    RuntimeError('dictionary changed size during iteration'), KeyboardInterrupt()])
def test_other_failures_are_never_retried(error):
    actor=object();pool=SimpleNamespace(pool=[actor],_future_to_actor={});calls=[]
    def fail(*args):calls.append(1);raise error
    with pytest.raises(type(error)):guarded_submit(pool,fail,(None,None,'0',None))
    assert calls==[1] and pool.pool==[actor]


def test_correct_aborts_do_not_complete_all_present_learning_benchmark():
    clean=[{'presence':[1]*4,'status':'ok'}]*2
    assert learning_workload_completed(clean,4)
    assert not learning_workload_completed(clean+[{'presence':[0]*4,'status':'abort'}],4)
    assert not learning_workload_completed([{'presence':[1,1,1,0],'status':'ok'}],4)
    assert not learning_workload_completed([{'presence':[1]*4,'status':'abort'}],4)
    assert not learning_workload_completed([],4)


def test_export_rejects_old_abort_run_before_changing_public_artifacts(tmp_path):
    import json
    from experiments.export_seed_mpc_poisoning import export
    run=tmp_path/'native';result=run/'runtime-results/run-1';result.mkdir(parents=True)
    (result/'results.json').write_text(json.dumps({'records':[{'manifest':{'presence':[0]*4},
        'result_certificate':{'body':{'result':{'status':'abort'}}}}]}))
    output=tmp_path/'public';output.mkdir();sentinel=output/'results.json';sentinel.write_text('original')
    with pytest.raises(ValueError,match='incomplete all-present'):
        export(tmp_path/'missing-oracle',[run],output)
    assert sentinel.read_text()=='original'


def test_runtime_install_checks_pin_and_is_idempotent(monkeypatch):
    from flwr.simulation.ray_transport.ray_actor import BasicActorPool
    from trustlessfl.seed_mpc_flower_runtime import install
    original=BasicActorPool.submit
    # monkeypatch retains the original on test teardown after install mutates it.
    monkeypatch.setattr(BasicActorPool,'submit',original)
    install();install()
    assert BasicActorPool.submit is guarded_submit


def test_runtime_install_rejects_unreviewed_source(monkeypatch):
    from flwr.simulation.ray_transport.ray_actor import BasicActorPool
    from trustlessfl.seed_mpc_flower_runtime import install
    def other(*args):pass
    monkeypatch.setattr(BasicActorPool,'submit',other)
    with pytest.raises(RuntimeError,match='source differs'):install()


def test_runtime_guard_startup_evidence_is_required_and_hash_bound(tmp_path):
    import json
    from experiments.run_seed_mpc_flower import verify_runtime_guard
    from trustlessfl.crypto import ProtocolError
    with pytest.raises(ProtocolError,match='missing'):verify_runtime_guard(tmp_path,'hash')
    evidence=tmp_path/'attempt-1/runtime-bootstrap/guards';evidence.mkdir(parents=True)
    path=evidence/'1.json';path.write_text(json.dumps({'installed':True,'source_sha256':'hash'}))
    assert verify_runtime_guard(tmp_path,'hash')['startup_processes']==1
    with pytest.raises(ProtocolError,match='differs'):verify_runtime_guard(tmp_path,'changed')
